//! End-to-end checks of the `vpn-zone` command line.
//!
//! Everything here runs against a state directory of its own and a manifest
//! whose tool paths point nowhere: not one of these cases may start a tool, and
//! a test that suddenly does would be a test that touches the developer's real
//! zones. The paths that DO need `systemctl`, `nsenter` or `kdialog` are the
//! ones the smoke test covers on a runner (`tests/integration/smoke.sh`).
//!
//! `VPN_ZONE_CURRENT` is scrubbed for the same reason as the compositor
//! variables in `wl_sandbox_cli.rs`: the developer's shell may well be running
//! inside a zone, and then every launch would take the delegation path and the
//! result would differ from CI.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_vpn-zone");

/// A state directory, a profile directory and a manifest naming them, removed
/// on drop.
struct Home {
    root: PathBuf,
}

impl Home {
    fn new(tag: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("vpn-zone-cli-test-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for sub in ["state", "profiles", "sandboxes", "config"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let home = Self { root };
        home.write_manifest();
        home
    }

    /// The manifest the wrapper would normally hand over. Every tool points at
    /// a path that does not exist: if a test ever starts one, it fails loudly
    /// instead of poking the real system.
    fn write_manifest(&self) {
        let r = self.root.display();
        let mut json = String::from("{\n");
        for (key, value) in [
            ("home", format!("{r}")),
            ("state", format!("{r}/state")),
            ("profiles", format!("{r}/profiles")),
            ("sandboxes", format!("{r}/sandboxes")),
            ("config", format!("{r}/config")),
            ("runner", format!("{r}/bin/vpn-zone")),
            ("picker", format!("{r}/bin/vpn-zone-pick")),
            ("core", "/nonexistent/vpn-zone-core".to_owned()),
            ("systemctl", "/nonexistent/systemctl".to_owned()),
            ("systemd-run", "/nonexistent/systemd-run".to_owned()),
            ("nsenter", "/nonexistent/nsenter".to_owned()),
            ("unshare", "/nonexistent/unshare".to_owned()),
            ("ip", "/nonexistent/ip".to_owned()),
            ("kdialog", "/nonexistent/kdialog".to_owned()),
            ("bwrap", "/nonexistent/bwrap".to_owned()),
            ("dbus-proxy", "/nonexistent/xdg-dbus-proxy".to_owned()),
            ("xwayland", "/nonexistent/xwayland-satellite".to_owned()),
            ("notify-send", "/nonexistent/notify-send".to_owned()),
        ] {
            json.push_str(&format!("  \"{key}\": \"{value}\",\n"));
        }
        json.pop();
        json.pop();
        json.push_str("\n}\n");
        fs::write(self.manifest(), json).unwrap();
    }

    fn manifest(&self) -> PathBuf {
        self.root.join("tools.json")
    }

    fn state(&self) -> PathBuf {
        self.root.join("state")
    }

    /// Make a zone look like it is up: `zone.pid` naming a process that really
    /// exists (ourselves) is all `zone_pid` asks for.
    fn zone_is_up(&self, zone: &str) {
        let dir = self.state().join(zone);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("zone.pid"), format!("{}\n", std::process::id())).unwrap();
        fs::write(dir.join("ready"), "").unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with(args, &[])
    }

    fn run_with(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .env("VPN_ZONE_TOOLS", self.manifest())
            .env_remove("VPN_ZONE_CURRENT")
            .env_remove("VPN_ZONE_DELEGATED")
            .env_remove("VPN_ZONE_APPID")
            .env_remove("VPN_ZONE_DRYRUN")
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("DISPLAY");
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

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A synthetic config, in the Windows line endings Amnezia hands out.
fn crlf_config() -> String {
    [
        "[Interface]",
        "PrivateKey = QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg=",
        "Address = 10.99.0.2/32",
        "",
        "[Peer]",
        "PublicKey = MDEyMzQ1Njc4OUFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFk=",
        "AllowedIPs = 0.0.0.0/0",
        "Endpoint = 192.0.2.1:51820",
        "",
    ]
    .join("\r\n")
}

#[test]
fn the_help_works_without_a_manifest() {
    // Somebody who ran the binary without the wrapper has to be told what this
    // is, not what is missing.
    let out = Command::new(BIN)
        .arg("--help")
        .env_remove("VPN_ZONE_TOOLS")
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.starts_with("vpn-zone — сетевые зоны"), "{text}");
    for verb in ["vpn-zone run", "vpn-zone check", "vpn-zone gc"] {
        assert!(text.contains(verb), "в справке нет «{verb}»");
    }
}

#[test]
fn a_missing_or_broken_manifest_is_an_error_of_its_own() {
    let out = Command::new(BIN)
        .arg("list")
        .env_remove("VPN_ZONE_TOOLS")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("VPN_ZONE_TOOLS"), "{}", stderr(&out));

    let out = Command::new(BIN)
        .arg("list")
        .env("VPN_ZONE_TOOLS", "/nonexistent/tools.json")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));

    // An incomplete manifest names the key that is missing: that is what tells
    // the user the wrapper and the binary come from different generations.
    let home = Home::new("short-manifest");
    fs::write(home.manifest(), "{\"home\":\"/h\"}").unwrap();
    let out = home.run(&["list"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("state"), "{}", stderr(&out));
}

#[test]
fn add_copies_the_config_without_carriage_returns_and_at_mode_600() {
    let home = Home::new("add");
    let source = home.root.join("amnezia.conf");
    fs::write(&source, crlf_config()).unwrap();

    let out = home.run(&["add", "nl", source.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "зона nl создана");

    let copy = home.state().join("nl/config.conf");
    let text = fs::read_to_string(&copy).unwrap();
    assert!(!text.contains('\r'), "CRLF остался в копии конфига");
    assert!(text.contains("PrivateKey ="));
    let mode = fs::metadata(&copy).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "конфиг с приватным ключом не 0600: {mode:o}");

    // The original may go away afterwards — that is what the copy is for.
    fs::remove_file(&source).unwrap();
    assert!(copy.is_file());
}

#[test]
fn add_refuses_a_bad_name_and_a_file_that_is_not_a_config() {
    let home = Home::new("add-bad");
    let conf = home.root.join("ok.conf");
    fs::write(&conf, crlf_config()).unwrap();

    let out = home.run(&["add", "nl 2", conf.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("имя только из букв"),
        "{}",
        stderr(&out)
    );

    let out = home.run(&["add", "nl", "/nonexistent/x.conf"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("нет файла"), "{}", stderr(&out));

    let junk = home.root.join("junk.conf");
    fs::write(&junk, "это не конфиг\n").unwrap();
    let out = home.run(&["add", "nl", junk.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("не похож на конфиг"),
        "{}",
        stderr(&out)
    );
    assert!(!home.state().join("nl").exists(), "зона создана из мусора");
}

#[test]
fn list_and_check_answer_for_a_zone_that_is_down() {
    let home = Home::new("down");
    fs::create_dir_all(home.state().join("nl")).unwrap();

    let out = home.run(&["list"]);
    assert!(out.status.success());
    assert_eq!(stdout(&out).trim(), "nl — опущена");

    // 2 is "the zone is down", and it is a contract: this is grepped and
    // scripted against.
    let out = home.run(&["check", "nl"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(stdout(&out).trim(), "зона nl не поднята");
}

#[test]
fn check_answers_from_the_state_mirror() {
    let home = Home::new("check");
    home.zone_is_up("nl");
    let dir = home.state().join("nl");

    // No mirror at all: a zone brought up by an older version. Saying "dead"
    // here would be a lie, so it gets its own code.
    let out = home.run(&["check", "nl"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(
        stdout(&out).contains("состояние неизвестно"),
        "{}",
        stdout(&out)
    );

    fs::write(
        dir.join("status"),
        "interface: awg0\n  public key: k\n\npeer: p\n  endpoint: 192.0.2.1:51820\n  \
         latest handshake: 1 minute, 5 seconds ago\n  transfer: 1 KiB received\n",
    )
    .unwrap();
    let out = home.run(&["check", "nl"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        stdout(&out).contains("туннель живой (latest handshake: 1 minute, 5 seconds ago)"),
        "{}",
        stdout(&out)
    );

    fs::write(
        dir.join("status"),
        "interface: awg0\n\npeer: p\n  transfer: 0 B\n",
    )
    .unwrap();
    let out = home.run(&["check", "nl"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("рукопожатия нет"), "{}", stdout(&out));
}

#[test]
fn a_launch_is_wrapped_in_the_compositor_restriction_by_default() {
    // The default is ON, and with no setting file at all. Getting this wrong is
    // invisible from the outside — the program starts and works, only the
    // screen capture and the background clipboard reads are quietly back.
    let home = Home::new("wrap");
    home.zone_is_up("nl");

    let out = home.run_with(&["run", "nl", "--", "firefox"], &[("VPN_ZONE_DRYRUN", "1")]);
    assert!(out.status.success(), "{}", stderr(&out));
    let line = stdout(&out);
    assert!(line.contains("wl-sandbox firefox --"), "{line}");
    assert!(line.starts_with("зона nl, профиль основной:"), "{line}");

    // Turned off by the setting the CLI itself writes.
    let out = home.run(&["wayland-sandbox", "off"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = home.run_with(&["run", "nl", "--", "firefox"], &[("VPN_ZONE_DRYRUN", "1")]);
    assert_eq!(stdout(&out).trim(), "зона nl, профиль основной: firefox");
}

#[test]
fn a_sandboxed_launch_carries_the_tool_paths_of_the_manifest() {
    let home = Home::new("fs-flags");
    home.zone_is_up("nl");
    let out = home.run_with(
        &["run", "nl", "--sandbox", "work", "--", "telegram-desktop"],
        &[("VPN_ZONE_DRYRUN", "1"), ("VPN_ZONE_APPID", "telegram")],
    );
    let line = stdout(&out);
    for expected in [
        "fs-sandbox",
        "--bwrap /nonexistent/bwrap",
        "--dbus-proxy /nonexistent/xdg-dbus-proxy",
        "--kdialog /nonexistent/kdialog",
        "--xwayland /nonexistent/xwayland-satellite",
        "telegram --name work --",
    ] {
        assert!(line.contains(expected), "нет «{expected}» в: {line}");
    }
}

#[test]
fn a_missing_container_stops_the_launch_with_the_way_out() {
    let home = Home::new("no-profile");
    home.zone_is_up("nl");
    let out = home.run_with(
        &["run", "nl", "--profile", "work", "--", "firefox"],
        &[("VPN_ZONE_DRYRUN", "1")],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("профиля work нет — создай: vpn-zone profile create work"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_locked_zone_runs_the_command_where_it_already_is() {
    // No nsenter, no systemd-run: re-entering a namespace is impossible and
    // delegating out of a quarantine zone is forbidden, so the selection
    // arguments are dropped and the command runs on the spot.
    let home = Home::new("locked");
    let dir = home.state().join("nl");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("no-escape"), "").unwrap();

    let out = home.run_with(
        &[
            "run",
            "de",
            "--profile",
            "work",
            "--fs-sandbox",
            "--",
            "echo",
            "hi",
        ],
        &[("VPN_ZONE_CURRENT", "nl")],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "hi");
    assert!(stderr(&out).contains("зона nl заперта"), "{}", stderr(&out));

    // Nothing left after the flags are dropped: a message, not an attempt to
    // execute the flag itself.
    let out = home.run_with(&["run", "de"], &[("VPN_ZONE_CURRENT", "nl")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("нечего запускать"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn containers_and_sandboxes_are_created_listed_and_removed() {
    let home = Home::new("containers");

    assert_eq!(
        stdout(&home.run(&["profile", "list"])).trim(),
        "профилей нет. Создать: vpn-zone profile create <имя>"
    );
    assert!(home.run(&["profile", "create", "work"]).status.success());
    assert!(home.root.join("profiles/work").is_dir());
    assert!(stdout(&home.run(&["profile", "list"])).contains("work — свободен"));

    // A leading dash is refused: kdialog takes such an argument for an option
    // and closes without a word.
    let out = home.run(&["profile", "create", "-bad"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("в имени нельзя"), "{}", stderr(&out));
    // Cyrillic, on the other hand, is fine.
    assert!(home.run(&["sandbox", "create", "личное"]).status.success());
    assert!(home.root.join("sandboxes/личное/home").is_dir());

    assert!(home.run(&["profile", "rm", "work"]).status.success());
    assert!(!home.root.join("profiles/work").exists());
    let out = home.run(&["profile", "rm", "work"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn the_registry_keeps_its_three_field_shape() {
    let home = Home::new("registry");
    home.zone_is_up("nl");
    let reg = home.state().join(".running/__main__/firefox");
    fs::create_dir_all(reg.parent().unwrap()).unwrap();
    // One live record (ourselves) in another network and one dead one.
    fs::write(
        &reg,
        format!("{} de sb:work\n999999 de \n", std::process::id()),
    )
    .unwrap();

    // A dry run rewrites the registry but starts nothing, and without a
    // graphical session the conflict is a warning on stderr rather than a
    // dialog nobody could answer.
    let out = home.run_with(&["run", "nl", "--", "firefox"], &[("VPN_ZONE_DRYRUN", "1")]);
    assert!(out.status.success(), "{}", stderr(&out));
    let kept = fs::read_to_string(&reg).unwrap();
    assert_eq!(kept, format!("{} de sb:work\n", std::process::id()));
    assert!(Path::new(&home.state().join(".running/__main__/.lock")).is_file());
}
