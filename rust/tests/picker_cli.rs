//! End-to-end checks of `vpn-zone-pick`.
//!
//! The picker is a machine with three inputs — the memory on disk, the answer
//! to a dialog and the environment — and exactly two outcomes: it becomes
//! `vpn-zone run` (or the program itself), or it exits without starting
//! anything. That invariant is what these tests assert, scenario by scenario:
//! **every one of them ends either in a recorded exec or in an explicit
//! cancel**, and never in silence.
//!
//! Nothing real is started. kdialog is a script that prints the answers it is
//! handed, one per call, and records what it was asked; `vpn-zone` is a script
//! that records its arguments and exits — since the picker `exec`s it, that
//! recording IS the launch. The state directory and the manifest are the test's
//! own, so a run cannot touch the developer's zones.
//!
//! The compositor variables are set or removed deliberately in every case: the
//! developer's shell has them, a CI runner does not, and the picker behaves
//! differently on purpose.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_vpn-zone-pick");

/// The answer a stub gives for "the empty menu entry" — the main profile. An
/// empty line in the answer file cannot mean that: an exhausted file reads the
/// same way, and that has to be a cancel.
const EMPTY: &str = "EMPTY";
/// The answer that makes the stub exit non-zero, i.e. the user said no.
const CANCEL: &str = "CANCEL";

struct Home {
    root: PathBuf,
}

impl Home {
    fn new(tag: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("vpn-zone-pick-test-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for sub in [
            "state/.last",
            "state/.lastprofile",
            "state/.pinned",
            "state/.pinnedprofile",
            "state/.labels",
            "state/.running",
            "profiles",
            "sandboxes",
            "config",
            "bin",
        ] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let home = Self { root };
        home.write_stubs();
        home.write_manifest();
        home
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn script(&self, name: &str, body: &str) -> PathBuf {
        let path = self.root.join("bin").join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).unwrap();
        path
    }

    /// kdialog: record the question, answer the next line of the queue.
    /// Written in plain POSIX shell with builtins only — `/bin/sh` is all a
    /// NixOS `/bin` has, and the test must not depend on coreutils being in
    /// `PATH`.
    fn write_stubs(&self) {
        self.script(
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
  '') exit 1 ;;
  CANCEL) exit 1 ;;
  EMPTY) exit 0 ;;
  *) printf '%s\n' "$answer" ;;
esac"#,
        );
        // vpn-zone: record the command line, and make `profile create` /
        // `sandbox create` actually produce a directory, because the picker
        // checks for one before using the name it was given.
        self.script(
            "vpn-zone",
            r#"{ printf '%s\n' "$@"; echo '--END--'; } >> "$RUNNER_LOG"
code=${RUNNER_EXIT:-0}
if [ "$code" = 0 ]; then
  if [ "$1 $2" = "profile create" ]; then mkdir -p "$VPNZ_PROFILES/$3"; fi
  if [ "$1 $2" = "sandbox create" ]; then mkdir -p "$VPNZ_SANDBOXES/$3/home"; fi
fi
exit "$code""#,
        );
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
            // The runner and the picker are the PROFILE paths in production;
            // here the runner is the recording stub and the picker is only ever
            // used as a fallback for the re-exec, which finds itself through
            // /proc/self/exe.
            ("runner", format!("{bin}/vpn-zone")),
            ("picker", BIN.to_owned()),
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

    /// A zone the picker will accept: a directory with a config in it.
    fn zone(&self, name: &str) {
        let dir = self.path("state").join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("config.conf"), "[Interface]\n").unwrap();
    }

    fn profile(&self, name: &str) {
        fs::create_dir_all(self.path("profiles").join(name)).unwrap();
    }

    fn write(&self, rel: &str, body: &str) {
        let path = self.path(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    fn read(&self, rel: &str) -> Option<String> {
        fs::read_to_string(self.path(rel)).ok()
    }

    /// The answers the dialogs will be given, in order.
    fn answers(&self, answers: &[&str]) {
        let mut text = String::new();
        for answer in answers {
            text.push_str(answer);
            text.push('\n');
        }
        fs::write(self.path("answers"), text).unwrap();
    }

    /// What the picker `exec`ed, as one invocation per element.
    fn launched(&self) -> Vec<Vec<String>> {
        blocks(&self.read("runner.log").unwrap_or_default())
    }

    /// What was asked, as one dialog per element.
    fn asked(&self) -> Vec<Vec<String>> {
        blocks(&self.read("kdialog.log").unwrap_or_default())
    }

    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        self.spawn(args, env, true)
    }

    /// The same launch with no compositor in the environment — a terminal, a
    /// unit, a CI runner.
    fn run_headless(&self, args: &[&str]) -> Output {
        self.spawn(args, &[], false)
    }

    fn spawn(&self, args: &[&str], env: &[(&str, &str)], display: bool) -> Output {
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .env("VPN_ZONE_TOOLS", self.path("tools.json"))
            .env("KDIALOG_ANSWERS", self.path("answers"))
            .env("KDIALOG_LOG", self.path("kdialog.log"))
            .env("RUNNER_LOG", self.path("runner.log"))
            .env("VPNZ_PROFILES", self.path("profiles"))
            .env("VPNZ_SANDBOXES", self.path("sandboxes"))
            .env_remove("DISPLAY")
            .env_remove("VPN_ZONE_ASK")
            .env_remove("VPN_ZONE_PROFILE")
            .env_remove("VPN_ZONE_CURRENT")
            .env_remove("VPN_ZONE_APPID");
        // A graphical session for most cases: they are about what the dialog
        // does with an answer. Without one the picker takes a different branch
        // on purpose, and the developer's shell has the variable set.
        if display {
            cmd.env("WAYLAND_DISPLAY", "wayland-test");
        } else {
            cmd.env_remove("WAYLAND_DISPLAY");
        }
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

/// Split a stub's log into invocations.
fn blocks(text: &str) -> Vec<Vec<String>> {
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

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The command every scenario launches. `%u` is there on purpose: a field code
/// reaches the picker as an ordinary argument and must survive to the far end.
const CMD: [&str; 3] = ["--", "firefox", "%u"];

fn pick(id: &str) -> Vec<&str> {
    let mut args = vec!["--id", id];
    args.extend(CMD);
    args
}

#[test]
fn a_program_nobody_has_run_before_is_asked_about_and_started() {
    let home = Home::new("fresh");
    home.zone("nl");
    home.answers(&["nl"]);

    let out = home.run(
        &[
            "--label",
            "Огненный лис",
            "--id",
            "firefox",
            "--",
            "firefox",
            "%u",
        ],
        &[],
    );
    assert!(out.status.success(), "{}", stderr(&out));

    assert_eq!(
        home.launched(),
        vec![vec![
            "run".to_owned(),
            "nl".to_owned(),
            "--".to_owned(),
            "firefox".to_owned(),
            "%u".to_owned()
        ]]
    );
    // One dialog, and it names the program the way a human knows it.
    let asked = home.asked();
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert!(
        asked[0].contains(&"Куда пустить «Огненный лис»?".to_owned()),
        "{:?}",
        asked[0]
    );
    // Both memories are updated: the label for the next dialog, the choice for
    // the next launch.
    assert_eq!(
        home.read("state/.labels/firefox").as_deref(),
        Some("Огненный лис")
    );
    assert_eq!(home.read("state/.last/firefox").as_deref(), Some("nl"));
}

#[test]
fn choosing_always_writes_the_pin_the_next_launch_obeys() {
    let home = Home::new("pin");
    home.zone("nl");
    home.answers(&["pin:nl"]);
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(home.read("state/.pinned/firefox").as_deref(), Some("nl"));
    assert_eq!(home.launched()[0][1], "nl");
}

#[test]
fn a_pinned_network_with_a_free_container_asks_only_about_the_container() {
    // The "always this network, container chosen every time" case: the entry
    // that leads to the container lives in the network dialog, which is not
    // being shown, so the container gets a window of its own.
    let home = Home::new("asksolo");
    home.zone("nl");
    home.profile("work");
    home.write("state/.pinned/firefox", "nl");
    home.answers(&["work"]);

    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));

    let asked = home.asked();
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert!(
        asked[0].contains(&"Профиль для «firefox»".to_owned()),
        "{:?}",
        asked[0]
    );
    assert_eq!(
        home.launched()[0],
        ["run", "nl", "--profile", "work", "--", "firefox", "%u"]
    );
    assert_eq!(
        home.read("state/.lastprofile/firefox").as_deref(),
        Some("work")
    );
}

#[test]
fn a_pinned_container_is_not_asked_about_at_all() {
    let home = Home::new("bothpinned");
    home.zone("nl");
    home.write("state/.pinned/firefox", "nl");
    home.write("state/.pinnedprofile/firefox", "sb:work");
    // No answers at all: a dialog here would be a cancel and nothing would
    // start, which is exactly what must not happen.
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(home.asked().is_empty(), "{:?}", home.asked());
    assert_eq!(
        home.launched()[0],
        ["run", "nl", "--sandbox", "work", "--", "firefox", "%u"]
    );
    // And the pin survives: it used to be erased by the validation that looked
    // for a CONTAINER named `sb:work`.
    assert_eq!(
        home.read("state/.pinnedprofile/firefox").as_deref(),
        Some("sb:work")
    );
}

#[test]
fn changing_the_container_asks_again_through_a_re_exec() {
    // Three dialogs: the network one, the container one, and the network one
    // again in the second pass of the picker. The choice travels in the
    // environment, which is what makes a throwaway container survive the trip.
    let home = Home::new("reprofile");
    home.zone("nl");
    home.answers(&["__chooseprofile__", "__fs__", "offline"]);

    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));

    assert_eq!(home.asked().len(), 3, "{:?}", home.asked());
    assert_eq!(
        home.launched()[0],
        ["run", "offline", "--fs-sandbox", "--", "firefox", "%u"]
    );
    assert_eq!(
        home.read("state/.lastprofile/firefox").as_deref(),
        Some("__fs__")
    );
    // The zone with no network is created on demand.
    assert!(home.path("state/offline/offline").is_file());
}

#[test]
fn a_throwaway_container_survives_the_re_exec_although_it_is_never_remembered() {
    let home = Home::new("tmp-handover");
    home.zone("nl");
    home.answers(&["__chooseprofile__", "__tmp__", "nl"]);

    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        home.launched()[0],
        ["run", "nl", "--tmp-profile", "--", "firefox", "%u"]
    );
    // Remembering it would make a one-off container permanent.
    assert_eq!(home.read("state/.lastprofile/firefox"), None);
}

#[test]
fn asking_the_network_again_drops_the_pin_and_keeps_the_pinned_container() {
    let home = Home::new("unpin");
    home.zone("nl");
    home.write("state/.pinned/firefox", "nl");
    home.write("state/.pinnedprofile/firefox", "__main__");
    home.answers(&["unpin", "offline"]);

    // VPN_ZONE_ASK is how the dialog is reached for a pinned program at all —
    // and after "↺ Спрашивать сеть снова" the pinned CONTAINER must still be
    // honoured, which is the bug this covers.
    let out = home.run(&pick("firefox"), &[("VPN_ZONE_ASK", "1")]);
    assert!(out.status.success(), "{}", stderr(&out));

    assert!(!home.path("state/.pinned/firefox").exists());
    assert_eq!(
        home.read("state/.pinnedprofile/firefox").as_deref(),
        Some("__main__")
    );
    assert_eq!(
        home.launched()[0],
        ["run", "offline", "--", "firefox", "%u"]
    );
    // The unpin entry offered the way out by name.
    assert!(
        home.asked()[0]
            .iter()
            .any(|a| a == "↺ Спрашивать сеть снова (закреплено: nl)"),
        "{:?}",
        home.asked()[0]
    );
}

#[test]
fn a_running_program_is_started_where_it_already_runs_without_a_word() {
    // A click on a running program means "raise the window". The selector is
    // read back too: without it the program came back "bare", with its network
    // remembered and its sandbox lost.
    let home = Home::new("running");
    home.zone("nl");
    home.write(
        "state/.running/__main__/firefox",
        &format!("{} nl sb:work\n", std::process::id()),
    );
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(home.asked().is_empty(), "{:?}", home.asked());
    assert_eq!(
        home.launched()[0],
        ["run", "nl", "--sandbox", "work", "--", "firefox", "%u"]
    );
}

#[test]
fn a_dead_record_is_not_a_running_program() {
    let home = Home::new("dead");
    home.zone("nl");
    home.write("state/.running/__main__/firefox", "999999 de sb:work\n");
    home.answers(&["nl"]);
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(home.asked().len(), 1);
    assert_eq!(home.launched()[0], ["run", "nl", "--", "firefox", "%u"]);
}

#[test]
fn a_cancelled_dialog_starts_nothing_and_says_nothing() {
    let home = Home::new("cancel");
    home.zone("nl");
    for answers in [vec![CANCEL], vec![EMPTY], vec![]] {
        home.answers(&answers);
        let _ = fs::remove_file(home.path("runner.log"));
        let out = home.run(&pick("firefox"), &[]);
        // Exit 0: the user said no, and that is not a failure.
        assert!(out.status.success(), "{:?}: {}", answers, stderr(&out));
        assert!(
            home.launched().is_empty(),
            "{:?} всё-таки что-то запустило",
            answers
        );
        assert_eq!(home.read("state/.last/firefox"), None);
    }
}

#[test]
fn cancelling_the_container_dialog_stops_the_launch_too() {
    let home = Home::new("cancel-profile");
    home.zone("nl");
    home.write("state/.pinned/firefox", "nl");
    home.answers(&[CANCEL]);
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(home.launched().is_empty());
}

#[test]
fn without_a_graphical_session_the_remembered_choice_is_taken_and_said_out_loud() {
    // kdialog dies without a compositor, and treating that as a cancel turned a
    // launch from a terminal or a unit into silence.
    let home = Home::new("headless");
    home.zone("nl");
    home.write("state/.last/firefox", "nl");
    let out = home.run_headless(&pick("firefox"));

    assert!(out.status.success(), "{}", stderr(&out));
    assert!(home.asked().is_empty(), "диалог всё-таки показали");
    assert!(
        stderr(&out).contains("спросить негде (нет графики) — беру «nl»"),
        "{}",
        stderr(&out)
    );
    assert_eq!(home.launched()[0], ["run", "nl", "--", "firefox", "%u"]);
}

#[test]
fn the_direct_choice_becomes_the_program_itself() {
    // "Прямой интернет" is the absence of a zone: there is no `vpn-zone run` in
    // this path at all, the picker simply becomes the command.
    let home = Home::new("direct");
    home.answers(&["direct"]);
    let out = home.run(
        &["--id", "hello", "--", "/bin/sh", "-c", "echo ЗАПУЩЕНО"],
        &[],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "ЗАПУЩЕНО");
    assert!(home.launched().is_empty(), "vpn-zone run тут ни при чём");
}

#[test]
fn a_new_container_is_created_from_the_dialog_and_used() {
    let home = Home::new("new-profile");
    home.zone("nl");
    // "Новый профиль…", the name (with what has to be cleaned out of it), then
    // the network.
    home.answers(&["__chooseprofile__", "__new__", "-моё имя", "nl"]);
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));

    let launched = home.launched();
    // The creation goes through the CLI, and the launch uses the cleaned name.
    assert_eq!(launched[0], ["profile", "create", "моё_имя"]);
    assert_eq!(
        launched[1],
        ["run", "nl", "--profile", "моё_имя", "--", "firefox", "%u"]
    );
    assert!(home.path("profiles/моё_имя").is_dir());
}

#[test]
fn a_creation_that_fails_still_starts_the_program() {
    // Under `set -e` this used to kill the picker silently, AFTER every dialog
    // had been answered: the user answered the questions and nothing started.
    let home = Home::new("failed-create");
    home.zone("nl");
    home.answers(&["__chooseprofile__", "__newsb__", "новая", "nl"]);
    // Every CLI call fails here, the final `run` included — so the picker's own
    // exit code is the runner's. What matters is that it GOT there.
    let _ = home.run(&pick("firefox"), &[("RUNNER_EXIT", "1")]);
    let launched = home.launched();
    assert_eq!(launched[0], ["sandbox", "create", "новая"]);
    // No sandbox flag — the container could not be made — but a launch.
    assert_eq!(
        launched.last().unwrap(),
        &["run", "nl", "--", "firefox", "%u"]
    );
}

#[test]
fn a_pin_that_names_a_zone_that_is_gone_is_dropped_rather_than_obeyed() {
    let home = Home::new("stale-pin");
    home.zone("nl");
    home.write("state/.pinned/firefox", "de");
    home.write("state/.pinnedprofile/firefox", "gone");
    home.answers(&["nl", EMPTY]);

    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!home.path("state/.pinned/firefox").exists());
    assert!(!home.path("state/.pinnedprofile/firefox").exists());
    assert_eq!(home.launched()[0], ["run", "nl", "--", "firefox", "%u"]);
}

#[test]
fn the_old_shortcut_format_still_launches() {
    // Shortcuts and the picker are not updated atomically: during one rebuild
    // the new picker was handed shortcuts of the old shape and AyuGram stopped
    // starting at all.
    let home = Home::new("legacy");
    home.zone("nl");
    home.answers(&["nl"]);
    let out = home.run(
        &[
            "AyuGram Desktop",
            "--",
            "env",
            "DESKTOPINTEGRATION=1",
            "AyuGram",
        ],
        &[],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        home.launched()[0],
        ["run", "nl", "--", "env", "DESKTOPINTEGRATION=1", "AyuGram"]
    );
    // The key came from the command, walking past the wrapper and the
    // assignment, and the label from the first argument.
    assert_eq!(
        home.read("state/.labels/AyuGram").as_deref(),
        Some("AyuGram Desktop")
    );
    assert_eq!(home.read("state/.last/AyuGram").as_deref(), Some("nl"));
}

#[test]
fn nothing_to_run_is_a_message_and_not_a_dialog() {
    let out = Command::new(BIN)
        .args(["--id", "firefox"])
        .env_remove("VPN_ZONE_TOOLS")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("нечего запускать"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_missing_manifest_names_itself() {
    let out = Command::new(BIN)
        .args(["--id", "firefox", "--", "firefox"])
        .env_remove("VPN_ZONE_TOOLS")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("VPN_ZONE_TOOLS"), "{}", stderr(&out));
}

/// One row of the table below: a name, the memory to lay down, the answers to
/// give, and whether anything is expected to start.
type Case = (
    &'static str,
    &'static [(&'static str, &'static str)],
    &'static [&'static str],
    bool,
);

/// The invariant of the whole file, asserted once more over a table: whatever
/// the memory says, the picker either starts something or is told not to.
#[test]
fn every_shape_of_memory_ends_in_a_launch_or_in_a_cancel() {
    let cases: [Case; 6] = [
        ("empty", &[], &["nl"], true),
        ("last", &[("state/.last/firefox", "offline")], &["nl"], true),
        (
            "lastprofile",
            &[("state/.lastprofile/firefox", "sb:work")],
            &["nl"],
            true,
        ),
        (
            "pinned+lastprofile",
            &[
                ("state/.pinned/firefox", "nl"),
                ("state/.lastprofile/firefox", "__fs__"),
            ],
            &[EMPTY],
            true,
        ),
        ("cancelled", &[], &[CANCEL], false),
        (
            "default-profile own",
            &[("config/default-profile", "own")],
            &["nl"],
            true,
        ),
    ];
    for (tag, files, answers, launches) in cases {
        let home = Home::new(&format!("table-{}", tag.replace(' ', "-")));
        home.zone("nl");
        for (path, body) in files {
            home.write(path, body);
        }
        home.answers(answers);
        let out = home.run(&pick("firefox"), &[]);
        assert!(out.status.success(), "{tag}: {}", stderr(&out));
        assert_eq!(
            !home.launched().is_empty(),
            launches,
            "{tag}: {:?}",
            home.launched()
        );
    }
}
