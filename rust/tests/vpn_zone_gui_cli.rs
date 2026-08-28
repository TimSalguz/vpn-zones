//! End-to-end checks of `vpn-zone-gui`.
//!
//! Same shape as `picker_cli.rs`: kdialog answers from a queue and records what
//! it was asked, `vpn-zone` and `notify-send` record their arguments, and the
//! state directory belongs to the test. What is being checked is the wiring —
//! which CLI verb a menu entry ends in, which text the user is shown, and that
//! nothing is done silently — because that is all these six shortcuts are.
//!
//! The `add` path is deliberately only exercised as far as its failure branch:
//! the successful one sleeps six seconds waiting for a handshake, and that
//! wait is the point of it (`docs/GOTCHAS.md` §4), not something to stub out.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_vpn-zone-gui");
const CANCEL: &str = "CANCEL";

struct Home {
    root: PathBuf,
}

impl Home {
    fn new(tag: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("vpn-zone-gui-cli-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for sub in [
            "state/.pinned",
            "state/.pinnedprofile",
            "state/.labels",
            "profiles",
            "sandboxes",
            "config",
            "bin",
        ] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let home = Self { root };
        home.script(
            "kdialog",
            r#"{ printf '%s\n' "$@"; echo '--END--'; } >> "$KDIALOG_LOG"
answer=''
rest=''
first=1
if [ -f "$KDIALOG_ANSWERS" ]; then
  while IFS= read -r line; do
    if [ "$first" = 1 ]; then answer=$line; first=0; else rest="$rest$line
"; fi
  done < "$KDIALOG_ANSWERS"
fi
printf '%s' "$rest" > "$KDIALOG_ANSWERS"
case "$answer" in
  ''|CANCEL) exit 1 ;;
  EMPTY) exit 0 ;;
  *) printf '%s\n' "$answer" ;;
esac"#,
        );
        home.script(
            "vpn-zone",
            r#"{ printf '%s\n' "$@"; echo '--END--'; } >> "$RUNNER_LOG"
exit "${RUNNER_EXIT:-0}""#,
        );
        home.script(
            "notify-send",
            r#"{ printf '%s\n' "$@"; echo '--END--'; } >> "$NOTIFY_LOG""#,
        );
        home.write_manifest();
        home
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn script(&self, name: &str, body: &str) {
        let path = self.root.join("bin").join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).unwrap();
    }

    fn write_manifest(&self) {
        let r = self.root.display();
        let bin = self.root.join("bin");
        let bin = bin.display();
        let mut json = String::from("{\n");
        for (key, value) in [
            ("home", format!("{r}")),
            ("state", format!("{r}/state")),
            ("profiles", format!("{r}/profiles")),
            ("sandboxes", format!("{r}/sandboxes")),
            ("config", format!("{r}/config")),
            ("runner", format!("{bin}/vpn-zone")),
            ("picker", format!("{bin}/vpn-zone-pick")),
            ("core", "/nonexistent/vpn-zone-core".to_owned()),
            ("systemctl", "/nonexistent/systemctl".to_owned()),
            ("systemd-run", "/nonexistent/systemd-run".to_owned()),
            ("nsenter", "/nonexistent/nsenter".to_owned()),
            ("unshare", "/nonexistent/unshare".to_owned()),
            ("ip", "/nonexistent/ip".to_owned()),
            ("kdialog", format!("{bin}/kdialog")),
            ("notify-send", format!("{bin}/notify-send")),
            ("bwrap", "/nonexistent/bwrap".to_owned()),
            ("dbus-proxy", "/nonexistent/xdg-dbus-proxy".to_owned()),
            ("xwayland", "/nonexistent/xwayland-satellite".to_owned()),
        ] {
            json.push_str(&format!("  \"{key}\": \"{value}\",\n"));
        }
        json.pop();
        json.pop();
        json.push_str("\n}\n");
        fs::write(self.root.join("tools.json"), json).unwrap();
    }

    fn zone(&self, name: &str) {
        let dir = self.path("state").join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("config.conf"), "[Interface]\n").unwrap();
    }

    fn write(&self, rel: &str, body: &str) {
        let path = self.path(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    fn answers(&self, answers: &[&str]) {
        let mut text = String::new();
        for answer in answers {
            text.push_str(answer);
            text.push('\n');
        }
        fs::write(self.path("answers"), text).unwrap();
    }

    fn log(&self, name: &str) -> Vec<Vec<String>> {
        let text = fs::read_to_string(self.path(name)).unwrap_or_default();
        let mut out = Vec::new();
        let mut current = Vec::new();
        for line in text.lines() {
            if line == "--END--" {
                out.push(std::mem::take(&mut current));
            } else {
                current.push(line.to_owned());
            }
        }
        out
    }

    fn asked(&self) -> Vec<Vec<String>> {
        self.log("kdialog.log")
    }

    fn ran(&self) -> Vec<Vec<String>> {
        self.log("runner.log")
    }

    fn notified(&self) -> Vec<Vec<String>> {
        self.log("notify.log")
    }

    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .env("VPN_ZONE_TOOLS", self.path("tools.json"))
            .env("KDIALOG_ANSWERS", self.path("answers"))
            .env("KDIALOG_LOG", self.path("kdialog.log"))
            .env("RUNNER_LOG", self.path("runner.log"))
            .env("NOTIFY_LOG", self.path("notify.log"));
        for (key, value) in env {
            cmd.env(key, value);
        }
        cmd.output().unwrap()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Is this text somewhere in the dialog's arguments?
fn said(dialog: &[String], needle: &str) -> bool {
    dialog.iter().any(|arg| arg.contains(needle))
}

#[test]
fn the_help_works_without_a_manifest() {
    let out = Command::new(BIN)
        .arg("--help")
        .env_remove("VPN_ZONE_TOOLS")
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    for verb in [
        "add",
        "remove",
        "profile-add",
        "profile-rm",
        "settings",
        "forget",
    ] {
        assert!(text.contains(&format!("vpn-zone-gui {verb}")), "{text}");
    }

    let out = Command::new(BIN)
        .arg("nonsense")
        .env_remove("VPN_ZONE_TOOLS")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
}

#[test]
fn removing_a_zone_asks_twice_and_then_calls_the_cli() {
    let home = Home::new("remove");
    home.zone("nl");
    home.zone("de");
    // The zone, then the confirmation (any non-cancel answer is "continue").
    home.answers(&["nl", "ok"]);

    let out = home.run(&["remove"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));

    let asked = home.asked();
    assert_eq!(asked.len(), 2, "{asked:?}");
    assert!(said(&asked[0], "Какую зону удалить?"));
    // Both zones are offered, and nothing else: `direct` and `offline` are not
    // zones and there is nothing to delete about them.
    assert!(asked[0].contains(&"nl".to_owned()) && asked[0].contains(&"de".to_owned()));
    assert!(!said(&asked[0], "direct"));
    // The second step warns about the private key that goes with the config.
    assert!(said(&asked[1], "приватный ключ"), "{:?}", asked[1]);
    assert_eq!(home.ran(), vec![vec!["rm".to_owned(), "nl".to_owned()]]);
    assert!(said(&home.notified()[0], "Зона «nl» удалена"));
}

#[test]
fn a_cancelled_confirmation_removes_nothing() {
    let home = Home::new("remove-cancel");
    home.zone("nl");
    home.answers(&["nl", CANCEL]);
    let out = home.run(&["remove"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(home.ran().is_empty(), "{:?}", home.ran());
    assert!(home.notified().is_empty());
}

#[test]
fn with_no_zones_the_removal_dialog_says_so_instead_of_showing_an_empty_menu() {
    let home = Home::new("remove-empty");
    let out = home.run(&["remove"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let asked = home.asked();
    assert_eq!(asked.len(), 1);
    assert!(said(&asked[0], "VPN-зон нет — удалять нечего"), "{asked:?}");
    assert!(home.ran().is_empty());
}

#[test]
fn creating_a_container_cleans_the_name_before_the_cli_sees_it() {
    let home = Home::new("profile-add");
    home.answers(&["-моё имя"]);
    let out = home.run(&["profile-add"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(home.ran(), vec![vec!["profile", "create", "моё_имя"]]);
    assert!(said(&home.notified()[0], "Контейнер «моё_имя» создан"));

    // A name that is nothing but leading dashes and dots is no name at all —
    // and a dash is what kdialog would have taken for an option anyway.
    let home = Home::new("profile-add-empty");
    home.answers(&["-.-"]);
    let out = home.run(&["profile-add"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(home.ran().is_empty());
}

#[test]
fn a_failed_creation_is_shown_with_its_reason() {
    let home = Home::new("profile-add-fail");
    home.answers(&["work"]);
    let out = home.run(&["profile-add"], &[("RUNNER_EXIT", "1")]);
    assert!(out.status.success(), "{}", stderr(&out));
    let asked = home.asked();
    assert!(said(&asked[1], "Не удалось создать"), "{asked:?}");
    assert!(home.notified().is_empty(), "провал не празднуют");
}

#[test]
fn removing_containers_offers_all_of_them_at_once_only_when_there_are_several() {
    let home = Home::new("profile-rm");
    fs::create_dir_all(home.path("profiles/work")).unwrap();
    fs::create_dir_all(home.path("profiles/личное")).unwrap();
    // Somebody is living in one of them right now, and the menu says so.
    home.write(
        "state/.running/work/firefox",
        &format!("{} nl\n", std::process::id()),
    );
    home.answers(&["__all__", "ok"]);

    let out = home.run(&["profile-rm"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let asked = home.asked();
    assert!(said(&asked[0], "сейчас открыт в сети nl"), "{:?}", asked[0]);
    assert!(
        said(&asked[0], "⚠ Удалить ВСЕ профили (2)"),
        "{:?}",
        asked[0]
    );
    assert!(
        said(&asked[1], "Удалить ВСЕ профили (2)?"),
        "{:?}",
        asked[1]
    );
    assert_eq!(
        home.ran(),
        vec![
            vec!["profile", "rm", "work"],
            vec!["profile", "rm", "личное"]
        ]
    );
    assert!(said(&home.notified()[0], "Профили удалены"));
}

#[test]
fn with_one_container_there_is_nothing_to_delete_all_of() {
    let home = Home::new("profile-rm-one");
    fs::create_dir_all(home.path("profiles/work")).unwrap();
    home.answers(&["work", "ok"]);
    let out = home.run(&["profile-rm"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!said(&home.asked()[0], "__all__"));
    assert_eq!(home.ran(), vec![vec!["profile", "rm", "work"]]);
}

#[test]
fn the_settings_show_the_current_values_and_write_through_the_cli() {
    let home = Home::new("settings");
    home.zone("nl");
    home.write("config/default", "direct");
    home.answers(&["net", "offline"]);

    let out = home.run(&["settings"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let asked = home.asked();
    // The first menu is the one that makes the settings discoverable at all.
    assert!(
        said(&asked[0], "Сеть по умолчанию — сейчас: direct"),
        "{:?}",
        asked[0]
    );
    assert!(said(&asked[0], "Контейнер по умолчанию — сейчас: ask"));
    assert!(said(&asked[0], "Ярлыки программ — сейчас: picker"));
    assert!(said(&asked[0], "Доступ к экрану и вводу — сейчас: on"));
    // The second one opens on the current value and lists the real zones.
    assert!(asked[1].contains(&"--default".to_owned()));
    assert!(asked[1].contains(&"VPN: nl".to_owned()));
    assert_eq!(home.ran(), vec![vec!["default", "offline"]]);
    assert!(said(&home.notified()[0], "Сеть по умолчанию"));
}

#[test]
fn the_lock_menu_names_the_state_it_will_switch_to() {
    let home = Home::new("locks");
    home.zone("nl");
    home.write("state/nl/no-escape", "");
    home.zone("de");
    home.answers(&["lock", "nl"]);

    let out = home.run(&["settings"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let asked = home.asked();
    assert!(
        said(&asked[1], "nl — ЗАПЕРТА (снять замок)"),
        "{:?}",
        asked[1]
    );
    assert!(said(&asked[1], "de — открыта (запереть)"), "{:?}", asked[1]);
    assert_eq!(home.ran(), vec![vec!["unlock", "nl"]]);
    assert!(said(&home.notified()[0], "замок снят"));
}

#[test]
fn the_reset_dialog_shows_program_names_and_not_shortcut_ids() {
    // The key is a shortcut id (com.ayugram.desktop) and tells the user
    // nothing; the label is what the picker wrote next to it.
    let home = Home::new("forget");
    home.write("state/.pinned/com.ayugram.desktop", "nl");
    home.write("state/.pinnedprofile/com.ayugram.desktop", "__main__");
    home.write("state/.labels/com.ayugram.desktop", "AyuGram Desktop");
    home.answers(&["com.ayugram.desktop"]);

    let out = home.run(&["forget"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        said(
            &home.asked()[0],
            "AyuGram Desktop — сеть: nl, контейнер: основной"
        ),
        "{:?}",
        home.asked()[0]
    );
    assert_eq!(home.ran(), vec![vec!["forget", "com.ayugram.desktop"]]);
    // And the notification names the program, not the key.
    assert!(
        said(&home.notified()[0], "Для «AyuGram Desktop»"),
        "{:?}",
        home.notified()[0]
    );
}

#[test]
fn resetting_everything_goes_through_one_cli_call() {
    let home = Home::new("forget-all");
    home.write("state/.pinned/firefox", "nl");
    home.answers(&["__all__"]);
    let out = home.run(&["forget"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(home.ran(), vec![vec!["forget", "--all"]]);
}

#[test]
fn with_nothing_pinned_the_reset_dialog_says_so() {
    let home = Home::new("forget-empty");
    let out = home.run(&["forget"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        said(&home.asked()[0], "Закреплённых программ нет"),
        "{:?}",
        home.asked()
    );
    assert!(home.ran().is_empty());
}

#[test]
fn adding_a_zone_suggests_a_name_and_reports_a_refusal() {
    let home = Home::new("add");
    let conf = home.path("Amnezia VPN.conf");
    fs::write(&conf, "[Interface]\n").unwrap();
    home.answers(&[conf.to_str().unwrap(), "nl"]);

    let out = home.run(&["add"], &[("RUNNER_EXIT", "1")]);
    // A zone that could not be created is the one failing exit code these
    // shortcuts have.
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let asked = home.asked();
    // The file dialog starts in $HOME and filters by extension.
    assert!(asked[0].contains(&"--getopenfilename".to_owned()));
    assert!(said(&asked[0], "*.conf|Конфигурация WireGuard/AmneziaWG"));
    // The suggested name comes from the file name, cleaned of what a zone name
    // may not contain.
    assert!(
        asked[1].contains(&"Amnezia-VPN".to_owned()),
        "{:?}",
        asked[1]
    );
    assert_eq!(
        home.ran(),
        vec![vec![
            "add".to_owned(),
            "nl".to_owned(),
            conf.to_string_lossy().into_owned()
        ]]
    );
    assert!(said(&asked[2], "Не удалось создать зону nl"), "{asked:?}");
    assert!(home.notified().is_empty());
}

#[test]
fn a_cancelled_file_dialog_creates_nothing() {
    let home = Home::new("add-cancel");
    home.answers(&[CANCEL]);
    let out = home.run(&["add"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(home.ran().is_empty());
    assert_eq!(home.asked().len(), 1);
}
