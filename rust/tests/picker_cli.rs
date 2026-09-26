//! End-to-end checks of `vpn-zone-pick`.
//!
//! The picker is a machine with three inputs — the memory on disk, the answer
//! to a dialog and the environment — and exactly two outcomes: it becomes
//! `vpn-zone run` (for `direct` too — it never becomes the program itself), or
//! it exits without starting anything. That invariant is what these tests assert, scenario by scenario:
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
            ("openssl", "/nonexistent/openssl".to_owned()),
            ("certutil", "/nonexistent/certutil".to_owned()),
            ("opener", "/nonexistent/xdg-open".to_owned()),
            // Absent unless a test puts a fake one there with `window()`:
            // without it the picker asks with kdialog, as every other test
            // here expects.
            ("window", format!("{bin}/vpn-zone-window")),
            ("busctl", format!("{bin}/busctl")),
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

    /// The launch window: record what it was told, answer `reply`, exit with
    /// `code`.
    fn window(&self, reply: &str, code: i32) {
        let log = self.path("window.in");
        self.script(
            "vpn-zone-window",
            &format!(
                "while IFS= read -r line; do printf '%s\\n' \"$line\" >> '{}'; done\nprintf '%s' '{reply}'\nexit {code}",
                log.display()
            ),
        );
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
            // In a zone nothing of the layout is moved: the test's home is
            // the host's here, wherever it runs.
            .env_remove("VPN_ZONE_CURRENT")
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

/// "Always" in the main home: the network is a container's, never a
/// program's (docs/PERMISSIONS.md §11.8) — the program moves to the
/// container of the main home bound to that network, and the next launch
/// goes there without a question.
#[test]
fn choosing_always_in_the_main_home_moves_the_program_to_its_container() {
    let home = Home::new("pin");
    home.zone("nl");
    home.answers(&["pin:nl"]);
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let line = ["run", "nl", "--container", "main-nl", "--", "firefox", "%u"];
    assert_eq!(home.launched()[0], line);
    assert_eq!(
        home.read("state/.pinnedprofile/firefox").as_deref(),
        Some("main-nl")
    );
    let conf = home
        .read("config/containers/main-nl/container.conf")
        .unwrap_or_default();
    assert!(
        conf.contains("home = main") && conf.contains("network = nl"),
        "{conf}"
    );
    assert_eq!(home.read("state/.pinned/firefox"), None);

    let _ = fs::remove_file(home.path("runner.log"));
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(home.asked().len() == 1, "asked again: {:?}", home.asked());
    assert_eq!(home.launched()[0], line);
}

/// A container with no network yet has it asked; "always" makes the choice
/// the container's, and the next launch asks nothing. Without "always"
/// nothing is bound: a binding is not a side effect of one launch.
#[test]
fn a_container_with_no_network_is_bound_by_always_only() {
    let home = Home::new("first-network");
    home.zone("nl");
    home.profile("work");
    home.write("state/.pinnedprofile/firefox", "work");
    home.answers(&["nl"]);
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!home
        .read("config/containers/work/container.conf")
        .unwrap_or_default()
        .contains("network"));
    let _ = fs::remove_file(home.path("runner.log"));
    let _ = fs::remove_file(home.path("kdialog.log"));
    home.answers(&["pin:nl"]);

    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(home.asked().len(), 1, "{:?}", home.asked());
    let line = ["run", "nl", "--container", "work", "--", "firefox", "%u"];
    assert_eq!(home.launched()[0], line);
    assert!(home
        .read("config/containers/work/container.conf")
        .unwrap_or_default()
        .contains("network = nl"));

    let _ = fs::remove_file(home.path("runner.log"));
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(home.asked().len(), 1, "asked again: {:?}", home.asked());
    assert_eq!(home.launched()[0], line);
}

/// The global default container is every unassigned program's: "always"
/// from one of them does not bind it — every new program would go into that
/// network unasked.
#[test]
fn the_default_container_is_not_bound_from_one_program() {
    let home = Home::new("shared-default");
    home.zone("nl");
    home.profile("work");
    home.write("config/default-profile", "work");
    home.answers(&["pin:unconfined"]);
    let out = home.run(&pick("telegram"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        home.launched()[0],
        [
            "run",
            "unconfined",
            "--container",
            "work",
            "--",
            "firefox",
            "%u"
        ]
    );
    assert!(!home
        .read("config/containers/work/container.conf")
        .unwrap_or_default()
        .contains("network"));
    // A new program is still asked.
    let _ = fs::remove_file(home.path("runner.log"));
    let _ = fs::remove_file(home.path("kdialog.log"));
    home.answers(&["nl"]);
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!home.asked().is_empty());
}

/// A program's network pin from before the network was the container's
/// becomes the container's network at the first look (container::migrate_pins).
#[test]
fn a_network_pin_from_before_becomes_the_containers() {
    let home = Home::new("pins-moved");
    home.zone("nl");
    home.profile("work");
    home.write("state/.pinned/firefox", "nl");
    home.write("state/.pinnedprofile/firefox", "work");
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(home.asked().is_empty(), "{:?}", home.asked());
    assert_eq!(
        home.launched()[0],
        ["run", "nl", "--container", "work", "--", "firefox", "%u"]
    );
    assert_eq!(home.read("state/.pinned/firefox"), None);
    assert!(home
        .read("config/containers/work/container.conf")
        .unwrap_or_default()
        .contains("network = nl"));
}

#[test]
fn a_pinned_container_is_not_asked_about_at_all() {
    let home = Home::new("bothpinned");
    home.zone("nl");
    // A network pin from before becomes the sandbox's network.
    home.write("state/.pinned/firefox", "nl");
    // A sandbox as the layout before one name per container kept it, and a
    // pin as it was written then.
    fs::create_dir_all(home.path("sandboxes/work/home")).unwrap();
    home.write("state/.pinnedprofile/firefox", "sb:work");
    // No answers at all: a dialog here would be a cancel and nothing would
    // start, which is exactly what must not happen.
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(home.asked().is_empty(), "{:?}", home.asked());
    assert_eq!(
        home.launched()[0],
        ["run", "nl", "--container", "work", "--", "firefox", "%u"]
    );
    // And the pin survives, by the container's one name now: it used to be
    // erased by the validation that looked for a CONTAINER named `sb:work`.
    assert_eq!(
        home.read("state/.pinnedprofile/firefox").as_deref(),
        Some("work")
    );
    assert!(
        home.path("profiles/work/home").is_dir(),
        "the sandbox moved in"
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

/// "↺ Спрашивать снова" drops the program's container pin — the network is
/// the container's — and asks the container right away: never a pass that
/// falls back to the main home because nothing is remembered.
#[test]
fn asking_again_drops_the_container_pin_and_asks_the_container() {
    let home = Home::new("unpin");
    home.zone("nl");
    home.write(
        "config/containers/main-nl/container.conf",
        "home = main\nnetwork = nl\n",
    );
    home.write("state/.pinnedprofile/firefox", "main-nl");
    home.write("state/.lastprofile/firefox", "main-nl");
    home.answers(&["unpin", "__ownsb__", "offline"]);

    // VPN_ZONE_ASK is how the dialog is reached for a pinned program at all.
    let out = home.run(&pick("firefox"), &[("VPN_ZONE_ASK", "1")]);
    assert!(out.status.success(), "{}", stderr(&out));

    assert!(!home.path("state/.pinnedprofile/firefox").exists());
    assert_eq!(
        home.launched()[0],
        [
            "run",
            "offline",
            "--sandbox",
            "app-firefox",
            "--",
            "firefox",
            "%u"
        ]
    );
    let asked = home.asked();
    // The unpin entry offered the way out by name; then the container.
    assert!(
        asked[0]
            .iter()
            .any(|a| a == "↺ Спрашивать снова (программа закреплена за контейнером main-nl)"),
        "{:?}",
        asked[0]
    );
    assert!(
        asked[1].contains(&"Профиль для «firefox»".to_owned()),
        "{:?}",
        asked[1]
    );
}

/// The global default container, bound to a network, is no answer for a
/// program nobody pinned to it: the network is asked, the container's
/// preselected.
#[test]
fn a_bound_default_container_does_not_answer_for_an_unpinned_program() {
    let home = Home::new("bound-default");
    home.zone("nl");
    home.profile("work");
    home.write("config/containers/work/container.conf", "network = nl\n");
    home.write("config/default-profile", "work");
    home.answers(&["nl"]);
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(home.asked().len(), 1, "{:?}", home.asked());
    assert_eq!(
        home.launched()[0],
        ["run", "nl", "--container", "work", "--", "firefox", "%u"]
    );
    // Pinned to it: its network, no question.
    let _ = fs::remove_file(home.path("runner.log"));
    let _ = fs::remove_file(home.path("kdialog.log"));
    home.write("state/.pinnedprofile/firefox", "work");
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(home.asked().is_empty(), "{:?}", home.asked());
}

#[test]
fn a_running_program_that_hands_over_is_started_where_it_already_runs_without_a_word() {
    // A click on a running program that hands a launch over to the copy that
    // is up means "raise the window". The selector is read back too: without
    // it the program came back "bare", with its network remembered and its
    // sandbox lost.
    let home = Home::new("running");
    home.zone("nl");
    let me = std::process::id() as i32;
    home.write(
        "state/.running/__main__/firefox",
        &format!("{me} nl sb:work\n"),
    );
    vpn_zone::registry::note_start(&home.path("state/.running"), me, false).unwrap();
    home.write("state/.handover/firefox", "");
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(home.asked().is_empty(), "{:?}", home.asked());
    assert_eq!(
        home.launched()[0],
        ["run", "nl", "--sandbox", "work", "--", "firefox", "%u"]
    );
}

#[test]
fn a_running_program_is_asked_until_it_is_seen_handing_over() {
    // A terminal opened in a zone left every next one there with no question
    // (owner, 2026-09-25). Not known to hand over: asked, with the network it
    // runs in chosen. Started there and gone at once with success — the
    // stand-in runner does exactly that — it handed over, and is remembered.
    let home = Home::new("running-ask");
    home.zone("nl");
    home.zone("de");
    let me = std::process::id() as i32;
    home.write("state/.running/__main__/firefox", &format!("{me} nl\n"));
    vpn_zone::registry::note_start(&home.path("state/.running"), me, false).unwrap();
    home.write("state/.last/firefox", "de\n");
    home.answers(&["nl"]);
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(home.asked().len(), 1);
    let asked = &home.asked()[0];
    let default = asked.iter().position(|a| a == "--default").unwrap();
    assert_eq!(asked[default + 1], "nl", "{asked:?}");
    assert_eq!(home.launched()[0], ["run", "nl", "--", "firefox", "%u"]);
    assert!(home.path("state/.handover/firefox").is_file());

    // Into another network: not watched (`run` warns there, and its cancel
    // exits with success too).
    let other = Home::new("running-other");
    other.zone("nl");
    other.zone("de");
    other.write("state/.running/__main__/alacritty", &format!("{me} nl\n"));
    vpn_zone::registry::note_start(&other.path("state/.running"), me, false).unwrap();
    other.answers(&["de"]);
    let out = other.run(&pick("alacritty"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(other.launched()[0], ["run", "de", "--", "firefox", "%u"]);
    assert!(!other.path("state/.handover/alacritty").exists());

    // A launch that fails is no hand-over.
    let failed = Home::new("running-failed");
    failed.zone("nl");
    failed.write("state/.running/__main__/firefox", &format!("{me} nl\n"));
    vpn_zone::registry::note_start(&failed.path("state/.running"), me, false).unwrap();
    failed.answers(&["nl"]);
    let _ = failed.run(&pick("firefox"), &[("RUNNER_EXIT", "3")]);
    assert_eq!(failed.launched().len(), 1);
    assert!(!failed.path("state/.handover/firefox").exists());
}

#[test]
fn a_record_whose_number_went_to_another_process_does_not_skip_the_question() {
    // The registry outlives a reboot, and the numbers in it are soon other
    // processes'. A live pid is not a running program: without its start time
    // on record — or with another one — the picker asks, it does not start a
    // click into the old network without a word.
    let home = Home::new("reused");
    home.zone("nl");
    let me = std::process::id() as i32;
    home.write(
        "state/.running/__main__/firefox",
        &format!("{me} unconfined\n"),
    );
    home.write("state/.handover/firefox", "");
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(home.asked().len(), 1, "no start time: asked");
    home.write(&format!("state/.running/.started/{me}"), "1\n");
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(home.asked().len(), 2, "another start time: asked");
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
fn the_unconfined_choice_goes_through_run_like_any_other_network() {
    // "Прямой интернет" (now "Без ограничений") used to be the picker becoming
    // the command itself —
    // and everything `vpn-zone run` adds on the way (the container, the
    // compositor restriction, the registry record) was lost without a word.
    let home = Home::new("unconfined");
    home.answers(&["unconfined"]);
    let out = home.run(
        &["--id", "hello", "--", "/bin/sh", "-c", "echo ЗАПУЩЕНО"],
        &[],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let menu = &home.asked()[0];
    assert!(
        menu.iter()
            .any(|a| a == "Без ограничений — сеть хоста, без VPN и без изоляции зоны"),
        "{menu:?}"
    );
    assert!(!menu.iter().any(|a| a == "direct"), "{menu:?}");
    assert_eq!(
        home.launched(),
        vec![vec![
            "run",
            "unconfined",
            "--",
            "/bin/sh",
            "-c",
            "echo ЗАПУЩЕНО"
        ]]
    );
    assert!(stdout(&out).trim().is_empty(), "пикер сам стал командой");
}

#[test]
fn a_container_chosen_for_unconfined_is_not_dropped() {
    // The loss of isolation this used to be: a sandbox set as the default (or
    // pinned) plus "Прямой интернет" started the program with the whole home.
    let home = Home::new("unconfined-sandbox");
    home.write("config/default-profile", "own");
    home.answers(&["unconfined"]);
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        home.launched()[0],
        [
            "run",
            "unconfined",
            "--sandbox",
            "app-firefox",
            "--",
            "firefox",
            "%u"
        ]
    );

    // A pin written before the rename says `direct`: the same network.
    let home = Home::new("unconfined-profile");
    home.profile("work");
    home.write("state/.pinned/firefox", "direct");
    home.write("state/.pinnedprofile/firefox", "work");
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        home.asked().is_empty(),
        "всё закреплено — спрашивать нечего"
    );
    assert_eq!(
        home.launched()[0],
        [
            "run",
            "unconfined",
            "--container",
            "work",
            "--",
            "firefox",
            "%u"
        ]
    );
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
    // Made right here, a layer, and the launch uses the cleaned name.
    assert_eq!(
        launched[0],
        ["run", "nl", "--container", "моё_имя", "--", "firefox", "%u"]
    );
    assert!(home.path("profiles/моё_имя").is_dir());
    assert!(home
        .read("config/containers/моё_имя/container.conf")
        .unwrap_or_default()
        .contains("home = layer"));
}

#[test]
fn a_creation_that_fails_still_starts_the_program() {
    // Under `set -e` this used to kill the picker silently, AFTER every dialog
    // had been answered: the user answered the questions and nothing started.
    let home = Home::new("failed-create");
    home.zone("nl");
    home.answers(&["__chooseprofile__", "__newsb__", "новая", "nl"]);
    // Its settings cannot be written: a file where their directory goes.
    home.write("config/containers/новая", "not a directory");
    // The final `run` fails too — so the picker's own exit code is the
    // runner's. What matters is that it GOT there.
    let _ = home.run(&pick("firefox"), &[("RUNNER_EXIT", "1")]);
    let launched = home.launched();
    // The sandbox could not be made, but a sandbox was asked for: the
    // program's own, not the main profile with the whole home — and a launch.
    assert_eq!(
        launched.last().unwrap(),
        &[
            "run",
            "nl",
            "--sandbox",
            "app-firefox",
            "--",
            "firefox",
            "%u"
        ]
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
fn a_container_bound_to_a_network_starts_there_without_a_question() {
    let home = Home::new("bound");
    home.zone("nl");
    home.zone("de");
    home.profile("work");
    home.write("config/containers/work/container.conf", "network = nl\n");
    home.write("state/.pinnedprofile/firefox", "work");
    // A stale network pin elsewhere loses: the network is the container's.
    home.write("state/.pinned/firefox", "de");
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(home.asked().is_empty(), "{:?}", home.asked());
    assert_eq!(
        home.launched()[0],
        ["run", "nl", "--container", "work", "--", "firefox", "%u"]
    );
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
            "old pin+lastprofile",
            &[
                ("state/.pinned/firefox", "nl"),
                ("state/.lastprofile/firefox", "__fs__"),
            ],
            &["nl"],
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

#[test]
fn an_unassigned_autostart_starts_offline_in_its_own_home_without_a_dialog() {
    // docs/CONTAINERS.md §5.2, `autostart.unassigned = "offline"` — the closed
    // variant, the default until 2026-09-24.
    let home = Home::new("autostart-unassigned");
    home.write("config/autostart", "offline");
    home.zone("nl");
    // What a dialog would preselect is not a consent to go online unasked.
    home.write("state/.last/tg", "nl");
    home.write("config/default", "direct");
    home.script("notify-send", r#"printf '%s\n' "$@" >> "$NOTIFY_LOG""#);
    let log = home.path("notify.log");
    let out = home.run(
        &["--autostart", "--id", "tg", "--", "telegram", "-autostart"],
        &[("NOTIFY_LOG", log.to_str().unwrap())],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(home.asked().is_empty(), "{:?}", home.asked());
    assert_eq!(
        home.launched()[0],
        [
            "run",
            "offline",
            "--sandbox",
            "app-tg",
            "--",
            "telegram",
            "-autostart"
        ]
    );
    // The file access dialog of a new home is answered in advance: nothing.
    assert_eq!(
        home.read("config/containers/app-tg/perms").as_deref(),
        Some("")
    );
    // Nothing is remembered.
    assert_eq!(home.read("state/.last/tg").as_deref(), Some("nl"));
    assert_eq!(home.read("state/.lastprofile/tg"), None);
    assert_eq!(home.read("state/.pinned/tg"), None);
    let notified = home.read("notify.log").unwrap_or_default();
    assert!(notified.contains("Автозапуск"), "{notified}");
    assert!(notified.contains("без сети"), "{notified}");
}

/// The default since 2026-09-24 (the owner's word): at login, a program with
/// nothing chosen for it gets the picker's question, and its "always" is kept
/// like a click's.
#[test]
fn an_unassigned_autostart_asks_and_remembers_always() {
    let home = Home::new("autostart-asks");
    home.zone("nl");
    home.answers(&["pin:nl"]);
    let out = home.run(
        &["--autostart", "--id", "tg", "--", "telegram", "-autostart"],
        &[],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!home.asked().is_empty(), "the picker asked");
    // "Always" in the main home: the container of the main home in nl.
    assert_eq!(
        home.read("state/.pinnedprofile/tg").as_deref(),
        Some("main-nl")
    );
    assert_eq!(home.launched()[0][1], "nl");
}

/// With nothing to draw a dialog on (a login on a text console) the question
/// cannot be asked: the closed variant, as with `offline`.
#[test]
fn an_unassigned_autostart_without_a_screen_starts_offline() {
    let home = Home::new("autostart-headless");
    home.zone("nl");
    let out = home.run_headless(&["--autostart", "--id", "tg", "--", "telegram"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(home.asked().is_empty(), "{:?}", home.asked());
    assert_eq!(home.launched()[0][1], "offline");
}

#[test]
fn an_assigned_autostart_starts_where_it_was_put_and_says_nothing() {
    let home = Home::new("autostart-assigned");
    home.zone("nl");
    home.profile("work");
    home.write("state/.pinned/tg", "nl");
    home.write("state/.pinnedprofile/tg", "work");
    home.script("notify-send", r#"printf '%s\n' "$@" >> "$NOTIFY_LOG""#);
    let log = home.path("notify.log");
    let out = home.run(
        &["--autostart", "--id", "tg", "--", "telegram"],
        &[("NOTIFY_LOG", log.to_str().unwrap())],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(home.asked().is_empty(), "{:?}", home.asked());
    assert_eq!(
        home.launched()[0],
        ["run", "nl", "--container", "work", "--", "telegram"]
    );
    assert_eq!(home.read("notify.log"), None);

    // A container bound to a network takes it along, over the pin.
    home.write(
        "config/containers/work/container.conf",
        "network = direct\n",
    );
    let _ = fs::remove_file(home.path("runner.log"));
    let out = home.run(
        &["--autostart", "--id", "tg", "--", "telegram"],
        &[("NOTIFY_LOG", log.to_str().unwrap())],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        home.launched()[0],
        ["run", "unconfined", "--container", "work", "--", "telegram"]
    );
}

#[test]
fn the_launch_window_asks_both_questions_at_once() {
    let home = Home::new("window");
    home.zone("nl");
    home.window(
        "net\tnl\ncontainer\t__ownsb__\npin-net\t1\npin-container\t0\n",
        0,
    );
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
    // One window instead of the two menus: kdialog never asked.
    assert!(home.asked().is_empty(), "{:?}", home.asked());
    let told = home.read("window.in").unwrap();
    assert!(told.contains("title\tЗапуск: Огненный лис\n"), "{told}");
    assert!(told.contains("net\tnl\tVPN: nl\t"), "{told}");
    assert!(told.contains("container\t__ownsb__\t"), "{told}");
    assert!(
        told.contains("container\t__newsb__\tНовая песочница…\tnew\n"),
        "{told}"
    );
    // "Always" is a checkbox, not a second row per choice.
    assert!(!told.contains("pin:"), "{told}");
    let launched = home.launched();
    assert_eq!(launched.len(), 1, "{launched:?}");
    assert_eq!(launched[0][..2], ["run", "nl"]);
    assert!(
        launched[0]
            .windows(2)
            .any(|w| w == ["--sandbox", "app-firefox"]),
        "{launched:?}"
    );
    // The program's own container is made with the network chosen: the
    // network is the container's.
    assert!(home
        .read("config/containers/app-firefox/container.conf")
        .unwrap_or_default()
        .contains("network = nl"));
    assert_eq!(home.read("state/.pinned/firefox"), None);
    assert_eq!(home.read("state/.last/firefox").as_deref(), Some("nl"));
    assert_eq!(home.read("state/.pinnedprofile/firefox"), None);
}

#[test]
fn a_closed_launch_window_starts_nothing_and_asks_nothing_more() {
    let home = Home::new("window-closed");
    home.zone("nl");
    home.window("", 1);
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(home.launched().is_empty(), "{:?}", home.launched());
    assert!(home.asked().is_empty(), "{:?}", home.asked());
}

#[test]
fn the_launch_window_cannot_start_what_it_was_not_offered() {
    let home = Home::new("window-foreign");
    home.zone("nl");
    home.window("net\tsomewhere\ncontainer\t\n", 0);
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(home.launched().is_empty(), "{:?}", home.launched());
    assert!(
        stderr(&out).contains("чего не предлагали"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_new_sandbox_is_named_in_the_window_and_pinned_by_its_checkbox() {
    let home = Home::new("window-new");
    home.zone("nl");
    // The pinned network stays pinned only while its box stays ticked.
    home.write("state/.pinned/firefox", "nl");
    home.window(
        "net\tnl\ncontainer\t__newsb__\nname\tобщая\npin-net\t0\npin-container\t1\n",
        0,
    );
    let out = home.run(&pick("firefox"), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(home.asked().is_empty(), "no inputbox: {:?}", home.asked());
    let launched = home.launched();
    // Made right here, with a home of its own.
    assert!(home
        .read("config/containers/общая/container.conf")
        .unwrap_or_default()
        .contains("home = private"));
    let run = launched.iter().find(|l| l[0] == "run").unwrap();
    assert!(
        run.windows(2).any(|w| w == ["--container", "общая"]),
        "{run:?}"
    );
    assert_eq!(
        home.read("state/.pinnedprofile/firefox").as_deref(),
        Some("общая")
    );
    assert_eq!(
        home.read("state/.pinned/firefox"),
        None,
        "unticked: the pin is gone"
    );
}

// --- A CHOICE ASKED FOR FROM A ZONE (`broker::pick`) --------------------------

/// `sleep` from PATH, for a stand-in window that answers like a person — not
/// sooner than the guard. `None` where there is none: the scenario is then
/// not run (the guard's refusal of a quick answer is checked either way).
fn sleep_binary() -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join("sleep"))
        .find(|p| p.is_file())
}

/// The launch window a person answers after a while.
fn slow_window(home: &Home, reply: &str) -> bool {
    let Some(sleep) = sleep_binary() else {
        eprintln!("нет sleep в PATH — сценарий с окном из зоны пропущен");
        return false;
    };
    let log = home.path("window.in");
    home.script(
        "vpn-zone-window",
        &format!(
            "while IFS= read -r line; do printf '%s\\n' \"$line\" >> '{}'; done\n'{}' 1.7\nprintf '%s' '{reply}'",
            log.display(),
            sleep.display()
        ),
    );
    true
}

#[test]
fn a_choice_for_a_zone_is_the_window_only_and_comes_back_on_stdout() {
    // The broker asks the host's picker for a program in zone nl. The window
    // says who asks and what, the command in a block of its own; nothing
    // starts, nothing is remembered — a pin of the name the zone chose
    // starts nothing either: the window is shown on the asking zone, with no
    // "always".
    let home = Home::new("from-zone");
    home.zone("nl");
    home.zone("de");
    home.write("state/.last/firefox", "de\n");
    if !slow_window(&home, "net\tnl\ncontainer\t\n") {
        return;
    }
    let out = home.run(
        &[
            "--from-zone",
            "nl",
            "--id",
            "firefox",
            "--",
            "firefox",
            "https://example.org/a b",
        ],
        &[],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "nl\0--\0firefox\0https://example.org/a b\0");
    assert!(
        home.launched().is_empty(),
        "the picker started something itself"
    );
    assert!(home.asked().is_empty());
    let told = home.read("window.in").unwrap();
    assert!(told.contains("title\tЗапрос из зоны «nl»\n"), "{told}");
    // The command is its own block, not notes the window writes itself.
    assert!(
        told.contains("cmd\tfirefox\ncmd\thttps://example.org/a b\n"),
        "{told}"
    );
    assert!(!told.contains("note\t"), "{told}");
    assert!(told.contains("program\t"), "{told}");
    assert!(told.contains("asker\tnl\n"), "{told}");
    assert!(told.contains("net\tnl\tVPN: nl\tselected\n"), "{told}");
    assert!(
        told.contains("net\tde\tVPN: de\t\n"),
        "the memory chose: {told}"
    );
    // The host's network last, away from where a habit would click.
    let nets: Vec<&str> = told.lines().filter(|l| l.starts_with("net\t")).collect();
    assert!(
        nets.last().unwrap().starts_with("net\tunconfined\t"),
        "{nets:?}"
    );
    // No new container to name in a window that came up by itself.
    assert!(!told.contains("\tnew\n"), "{told}");
    assert!(
        told.contains("pin-net\t0\n") && told.contains("pins\t0\n"),
        "{told}"
    );
    assert!(told.contains("guard\t1500\n"), "{told}");
    assert_eq!(home.read("state/.last/firefox").as_deref(), Some("de\n"));
}

#[test]
fn a_locked_zone_is_offered_only_itself() {
    let home = Home::new("from-zone-locked");
    home.zone("nl");
    home.zone("de");
    if !slow_window(&home, "net\tnl\ncontainer\t\n") {
        return;
    }
    let out = home.run(
        &[
            "--from-zone",
            "nl",
            "--locked",
            "--id",
            "x",
            "--",
            "firefox",
        ],
        &[],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let told = home.read("window.in").unwrap();
    let nets: Vec<&str> = told.lines().filter(|l| l.starts_with("net\t")).collect();
    assert_eq!(nets, ["net\tnl\tVPN: nl\tselected"], "{told}");
}

#[test]
fn a_choice_for_a_zone_answered_at_once_starts_nothing() {
    // Answered sooner than a person could have read it: a key meant for
    // something else.
    let home = Home::new("from-zone-fast");
    home.zone("nl");
    home.window("net\tnl\ncontainer\t\n", 0);
    let out = home.run(
        &["--from-zone", "nl", "--id", "firefox", "--", "firefox"],
        &[],
    );
    assert!(!out.status.success());
    assert!(stdout(&out).is_empty(), "{}", stdout(&out));
}

#[test]
fn a_container_named_like_a_command_is_no_container() {
    // A program with the home can make `vpn-profiles/pinmain`; read as a
    // menu command it would pin the program to the main home. It is not
    // offered, and an answer naming it starts nothing.
    let home = Home::new("from-zone-reserved");
    home.zone("nl");
    for name in ["pinmain", "unpinprof", "pin:x", "sb:x", "__fs__", "work"] {
        fs::create_dir_all(home.path("profiles").join(name)).unwrap();
    }
    if !slow_window(&home, "net\tnl\ncontainer\tpinmain\n") {
        return;
    }
    let out = home.run(
        &["--from-zone", "nl", "--id", "firefox", "--", "firefox"],
        &[],
    );
    assert!(!out.status.success());
    assert!(stdout(&out).is_empty());
    let told = home.read("window.in").unwrap();
    let containers: Vec<&str> = told
        .lines()
        .filter(|l| l.starts_with("container\t"))
        .collect();
    assert!(
        containers
            .iter()
            .any(|l| l.starts_with("container\twork\t")),
        "{told}"
    );
    for name in ["pinmain", "unpinprof", "pin:x", "sb:x"] {
        assert!(
            !containers
                .iter()
                .any(|l| l.starts_with(&format!("container\t{name}\t"))),
            "{name} offered: {told}"
        );
    }
    assert_eq!(home.read("state/.pinnedprofile/firefox"), None);
}

#[test]
fn inside_a_zone_the_picker_asks_the_broker_and_shows_nothing_itself() {
    use std::io::{Read, Write};
    // A stand-in broker: takes the request, answers "ok".
    let home = Home::new("in-zone");
    home.zone("nl");
    let runtime = home.path("runtime");
    fs::create_dir_all(runtime.join("vpn-zones")).unwrap();
    let listener =
        std::os::unix::net::UnixListener::bind(runtime.join("vpn-zones/broker")).unwrap();
    let broker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        stream.write_all(b"ok\n").unwrap();
        request
    });
    let runtime_dir = runtime.to_string_lossy().into_owned();
    let out = home.run(
        &pick("firefox"),
        &[
            ("VPN_ZONE_CURRENT", "nl"),
            ("XDG_RUNTIME_DIR", runtime_dir.as_str()),
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(broker.join().unwrap(), b"VZP1\0firefox\0firefox\0%u\0");
    assert!(home.asked().is_empty() && home.launched().is_empty());

    // No broker to ask: the picker asks itself, as before.
    let empty = home.path("no-broker");
    fs::create_dir_all(&empty).unwrap();
    let empty = empty.to_string_lossy().into_owned();
    home.answers(&["nl"]);
    let out = home.run(
        &pick("firefox"),
        &[
            ("VPN_ZONE_CURRENT", "nl"),
            ("XDG_RUNTIME_DIR", empty.as_str()),
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(home.asked().len(), 1);

    // A container of the host's network is no zone to the broker.
    let _ = fs::remove_file(home.path("kdialog.log"));
    home.answers(&["nl"]);
    let out = home.run(
        &pick("firefox"),
        &[
            ("VPN_ZONE_CURRENT", "unconfined"),
            ("XDG_RUNTIME_DIR", runtime_dir.as_str()),
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(home.asked().len(), 1, "asked by the picker itself");
}
