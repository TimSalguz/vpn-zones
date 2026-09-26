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
            ("openssl", "/nonexistent/openssl".to_owned()),
            ("certutil", "/nonexistent/certutil".to_owned()),
            ("opener", "/nonexistent/xdg-open".to_owned()),
            ("window", "/nonexistent/vpn-zone-window".to_owned()),
            ("busctl", "/nonexistent/busctl".to_owned()),
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
    /// exists (ourselves), with its start noted as the holder notes its own.
    fn zone_is_up(&self, zone: &str) {
        let dir = self.state().join(zone);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("zone.pid"), format!("{}\n", std::process::id())).unwrap();
        let stamp = vpn_zone::sys::process_stamp(std::process::id() as i32).unwrap();
        fs::write(dir.join("zone.start"), format!("{stamp}\n")).unwrap();
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
    assert!(text.starts_with("cellward — сетевые зоны"), "{text}");
    for verb in ["cellward run", "cellward check", "cellward gc"] {
        assert!(text.contains(verb), "в справке нет «{verb}»");
    }
    // The short name and the old one are named in the header.
    let header = text.lines().take(2).collect::<Vec<_>>().join("\n");
    assert!(
        header.contains("cw") && header.contains("vpn-zone"),
        "{header}"
    );
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

    // The built-in choices of the picker are not names a zone can take: a
    // zone called "unconfined" (or "direct", its old name) would be shadowed
    // by the host's network in every launch, and "offline" is the directory
    // the picker creates by itself.
    for reserved in ["unconfined", "direct", "offline"] {
        let out = home.run(&["add", reserved, conf.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(1), "{reserved}");
        assert!(stderr(&out).contains("встроенный"), "{}", stderr(&out));
        assert!(
            !home.state().join(reserved).join("config.conf").exists(),
            "{reserved}"
        );
    }
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
    // Outermost, on the host, and named by the zone whose directory the
    // restricted socket goes into (LEAK-MODEL §13).
    assert!(
        line.starts_with("зона nl, профиль основной: /nonexistent/vpn-zone-core wl-sandbox firefox --zone nl --frame "),
        "{line}"
    );
    // With the zone's border (docs/WINDOW-FRAME.md §0а): its colour and
    // width, and where the switch that hides it is.
    assert!(line.contains(" --frame-switch "), "{line}");
    assert!(line.trim_end().ends_with(" -- firefox"), "{line}");

    // Turned off by the setting the CLI itself writes — for unconfined
    // launches only: a zone has no unrestricted socket to hand out.
    let out = home.run(&["wayland-sandbox", "off"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = home.run_with(&["run", "nl", "--", "firefox"], &[("VPN_ZONE_DRYRUN", "1")]);
    assert!(
        stdout(&out).contains("wl-sandbox firefox --zone nl --"),
        "{}",
        stdout(&out)
    );
    let out = home.run_with(
        &["run", "unconfined", "--", "firefox"],
        &[("VPN_ZONE_DRYRUN", "1")],
    );
    assert_eq!(
        stdout(&out).trim(),
        "зона unconfined, профиль основной: firefox"
    );
    // The allowlist likewise: obs is let through unconfined only.
    fs::create_dir_all(home.root.join("config")).unwrap();
    let out = home.run(&["wayland-sandbox", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = home.run_with(&["run", "nl", "--", "obs"], &[("VPN_ZONE_DRYRUN", "1")]);
    assert!(
        stdout(&out).contains("wl-sandbox obs --zone nl --"),
        "{}",
        stdout(&out)
    );
    let out = home.run_with(
        &["run", "unconfined", "--", "obs"],
        &[("VPN_ZONE_DRYRUN", "1")],
    );
    assert!(!stdout(&out).contains("wl-sandbox"), "{}", stdout(&out));
}

#[test]
fn an_unconfined_launch_starts_no_zone_and_loses_nothing_on_the_way() {
    // "unconfined" is the host's network: nothing to start and nothing to enter.
    // But the compositor restriction and the container still apply — the
    // picker used to become the command itself and dropped both.
    let home = Home::new("unconfined");
    let out = home.run_with(
        &["run", "unconfined", "--", "firefox"],
        &[("VPN_ZONE_DRYRUN", "1")],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    // A zone start would have named the manifest's systemctl in a message and
    // waited ten seconds for a zone that does not exist.
    assert!(!stderr(&out).contains("systemctl"), "{}", stderr(&out));
    let line = stdout(&out);
    assert!(
        line.starts_with("зона unconfined, профиль основной:"),
        "{line}"
    );
    assert!(
        line.contains("wl-sandbox firefox --zone unconfined --"),
        "{line}"
    );

    // The old name is the same network.
    fs::create_dir_all(home.root.join("profiles/work")).unwrap();
    let out = home.run_with(
        &["run", "direct", "--profile", "work", "--", "firefox"],
        &[("VPN_ZONE_DRYRUN", "1")],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).starts_with("зона unconfined, профиль work:"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn a_zone_left_with_the_name_unconfined_is_refused_not_left_behind() {
    // Before the name was taken it could be a VPN zone: a launch "into" it now
    // would be the host's network, its tunnel silently skipped.
    let home = Home::new("unconfined-zone");
    home.zone_is_up("unconfined");
    fs::write(home.state().join("unconfined/config.conf"), "[Interface]\n").unwrap();
    let dry = [("VPN_ZONE_DRYRUN", "1")];
    for name in ["unconfined", "direct"] {
        let out = home.run_with(&["run", name, "--", "firefox"], &dry);
        assert_eq!(out.status.code(), Some(1), "{name}");
        assert!(stderr(&out).contains("Переименуй"), "{}", stderr(&out));
        assert!(stdout(&out).is_empty(), "{}", stdout(&out));
    }
    let json = stdout(&home.run(&["status", "--json"]));
    assert_eq!(json.matches("\"name\":\"unconfined\"").count(), 1, "{json}");
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
        stderr(&out).contains("контейнера work нет — создай: cellward container create work"),
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
        "контейнеров вида «слой над домом» нет. Создать: cellward container create <имя> --home layer"
    );
    assert!(home.run(&["profile", "create", "work"]).status.success());
    assert!(home.root.join("profiles/work").is_dir());
    assert!(stdout(&home.run(&["profile", "list"])).contains("work — слой над домом"));

    // A leading dash is refused: kdialog takes such an argument for an option
    // and closes without a word.
    let out = home.run(&["profile", "create", "-bad"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("не может быть именем"),
        "{}",
        stderr(&out)
    );
    // Cyrillic, on the other hand, is fine — and one name is one container,
    // whatever its home: the data in one directory, the kind in its settings.
    assert!(home.run(&["sandbox", "create", "личное"]).status.success());
    assert!(home.root.join("profiles/личное/home").is_dir());
    let out = home.run(&["container", "create", "work", "--home", "private"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("уже есть"), "{}", stderr(&out));
    assert!(home
        .run(&["container", "create", "files", "--home", "main"])
        .status
        .success());
    let list = stdout(&home.run(&["container", "list"]));
    assert!(list.contains("основной дом"), "{list}");
    assert!(list.contains("свой дом"), "{list}");

    assert!(home.run(&["profile", "rm", "work"]).status.success());
    assert!(!home.root.join("profiles/work").exists());
    let out = home.run(&["profile", "rm", "work"]);
    assert_eq!(out.status.code(), Some(1));
    // The words from before are gone with a pointer to what does the job.
    let out = home.run(&["isolate", "off"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("больше нет"), "{}", stderr(&out));
}

#[test]
fn two_entries_for_one_binary_see_each_other() {
    // A Steam game's shortcut (id PEAK) and Steam itself, firefox and its
    // private-window entry: different ids, one single-instance binary. The
    // second launch hands its work to the process that is already up, in ITS
    // network — and the warning used to stay silent.
    //
    // Not a dry run: a dry run says nothing about conflicts on purpose. The
    // launch goes all the way to exec'ing the manifest's nsenter, which does
    // not exist — so it fails AFTER the warning, which is what is looked at.
    let home = Home::new("by-binary");
    home.zone_is_up("nl");
    let index = home.state().join(".running/__main__/.by-binary");
    fs::create_dir_all(&index).unwrap();
    fs::write(index.join("steam"), format!("{} de \n", std::process::id())).unwrap();

    let out = home.run_with(
        &["run", "nl", "--", "steam", "steam://rungameid/1"],
        &[("VPN_ZONE_APPID", "PEAK")],
    );
    // Without a graphical session the warning goes to stderr — and for a link
    // it says what really happens to a link.
    let err = stderr(&out);
    assert!(err.contains("уже запущена в сети «de»"), "{err}");
    assert!(err.contains("ссылку ты открываешь в «nl»"), "{err}");

    // A plain launch of another id of the same binary gets the ordinary text.
    fs::write(
        index.join("firefox"),
        format!("{} de \n", std::process::id()),
    )
    .unwrap();
    let out = home.run_with(
        &["run", "nl", "--", "firefox", "--private-window"],
        &[("VPN_ZONE_APPID", "firefox-private")],
    );
    let err = stderr(&out);
    assert!(err.contains("уже запущена в сети «de»"), "{err}");
    assert!(err.contains("окно ОТКРОЕТСЯ"), "{err}");

    // The same binary in the SAME network is no conflict at all.
    fs::write(
        index.join("firefox"),
        format!("{} nl \n", std::process::id()),
    )
    .unwrap();
    let out = home.run_with(
        &["run", "nl", "--", "firefox"],
        &[("VPN_ZONE_APPID", "firefox-private")],
    );
    assert!(!stderr(&out).contains("уже запущена"), "{}", stderr(&out));
    // …and the launch was filed under both keys on the way.
    let by_id = fs::read_to_string(home.state().join(".running/__main__/firefox-private")).unwrap();
    assert!(by_id.contains(" nl "), "{by_id}");
    let by_binary = fs::read_to_string(index.join("firefox")).unwrap();
    assert_eq!(by_binary.lines().count(), 2, "{by_binary}");
}

#[test]
fn a_launch_asked_for_from_a_zone_is_marked_and_its_id_is_a_file_name() {
    // The broker hands on what a program in a zone asked for — the app id
    // too. It is a file name in the registry, and the launch is marked as
    // not the user's own (the picker does not follow it without asking).
    let home = Home::new("from-zone");
    home.zone_is_up("nl");
    let _ = home.run_with(
        &["run", "nl", "--", "true"],
        &[
            ("VPN_ZONE_DELEGATED", "1"),
            ("VPN_ZONE_APPID", "/tmp/../x/firefox"),
        ],
    );
    let main = home.state().join(".running/__main__");
    assert!(main.join("_tmp_.._x_firefox").is_file());
    let started: Vec<String> = fs::read_dir(home.state().join(".running/.started"))
        .unwrap()
        .flatten()
        .map(|e| fs::read_to_string(e.path()).unwrap())
        .collect();
    assert!(
        started.iter().any(|s| s.lines().any(|l| l == "from-zone")),
        "{started:?}"
    );
}

#[test]
fn only_a_throwaway_container_of_ours_can_be_joined() {
    // Its layer is erased behind the last tenant: a directory named by a
    // request would go with it.
    let home = Home::new("join");
    home.zone_is_up("nl");
    let other = home.root.join("documents");
    fs::create_dir_all(&other).unwrap();
    let out = home.run_with(
        &[
            "run",
            "nl",
            "--tmp-profile",
            "--join",
            other.to_str().unwrap(),
            "--",
            "true",
        ],
        &[("VPN_ZONE_DRYRUN", "1")],
    );
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("не временный контейнер"),
        "{}",
        stderr(&out)
    );
    let ours = home.state().join(".throwaway/vpn-profile-abc12345");
    fs::create_dir_all(&ours).unwrap();
    let out = home.run_with(
        &[
            "run",
            "nl",
            "--tmp-profile",
            "--join",
            ours.to_str().unwrap(),
            "--",
            "true",
        ],
        &[("VPN_ZONE_DRYRUN", "1")],
    );
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn a_zone_whose_process_is_in_our_network_is_not_entered() {
    // `zone.pid` of a stopped zone stays behind, and its number comes round to
    // another process. Here it names this test itself — the host's network:
    // entering it would start the program on the host under the zone's name.
    let home = Home::new("zone-is-host");
    home.zone_is_up("nl");
    let out = home.run(&["run", "nl", "--", "true"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("указывает на процесс в сети хоста"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_trusted_certificate_needs_a_real_container_and_one_certificate() {
    let home = Home::new("trust-add");
    let pem = home.root.join("ca.pem");
    let one = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    fs::write(&pem, one).unwrap();

    let out = home.run(&["trust", "add", "nope", pem.to_str().unwrap(), "--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("контейнера nope нет"),
        "{}",
        stderr(&out)
    );

    // The main profile is the host's: a certificate there would be the host's.
    let out = home.run(&["trust", "add", "__main__", pem.to_str().unwrap(), "--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("не контейнер"), "{}", stderr(&out));

    let out = home.run(&["trust", "add", "sb:nope", pem.to_str().unwrap(), "--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("контейнера nope нет"),
        "{}",
        stderr(&out)
    );

    fs::create_dir_all(home.root.join("profiles/work")).unwrap();
    // A bundle is refused before anything is run.
    let bundle = home.root.join("bundle.pem");
    fs::write(&bundle, format!("{one}{one}")).unwrap();
    let out = home.run(&["trust", "add", "work", bundle.to_str().unwrap(), "--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("добавляй по одному"),
        "{}",
        stderr(&out)
    );

    // One certificate reaches openssl — here the manifest's, which is not there.
    let out = home.run(&["trust", "add", "work", pem.to_str().unwrap(), "--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("/nonexistent/openssl"),
        "{}",
        stderr(&out)
    );
    assert!(!home.root.join("config/containers/work/trust").exists());
}

#[test]
fn trusted_certificates_are_listed_and_removed_by_fingerprint() {
    let home = Home::new("trust-list");
    let out = home.run(&["trust", "list"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("нет ни у одного"), "{}", stdout(&out));

    // The container is its data directory; its certificates are with its
    // policy.
    fs::create_dir_all(home.root.join("profiles/work")).unwrap();
    let trust = home.root.join("config/containers/work/trust");
    fs::create_dir_all(&trust).unwrap();
    let a = format!("0f1e{}", "a".repeat(60));
    let b = format!("0f1f{}", "b".repeat(60));
    fs::write(trust.join(format!("{a}.pem")), "x").unwrap();
    fs::write(trust.join(format!("{b}.pem")), "x").unwrap();

    // openssl is not there, and the certificates are listed all the same: by
    // their fingerprints. Hiding one would hide that it is trusted.
    let out = home.run(&["trust", "list", "--json"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&out);
    assert!(json.starts_with("{\"schema_version\":1,"), "{json}");
    assert!(json.contains(&format!("\"sha256\":\"{a}\"")), "{json}");
    assert!(json.contains("\"container\":\"work\""), "{json}");

    let out = home.run(&["trust", "rm", "work", "0f1"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("подходит к 2"), "{}", stderr(&out));

    let out = home.run(&["trust", "rm", "work", "0F1E"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!trust.join(format!("{a}.pem")).exists());
    assert!(trust.join(format!("{b}.pem")).exists());
    // A data container's NSS databases are cleaned from inside the next launch,
    // which the (still existing) trust directory switches on.
    assert!(
        stdout(&out).contains("при следующем запуске"),
        "{}",
        stdout(&out)
    );

    let out = home.run(&["trust", "reset", "work"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(trust.is_dir());
    assert!(fs::read_dir(&trust).unwrap().next().is_none());
}

#[test]
fn a_container_bound_to_a_network_runs_there_only() {
    // docs/CONTAINERS.md I1: one identity, one network at a time, and a change
    // of network is an action of its own — never a side effect of a launch.
    let home = Home::new("bound");
    home.zone_is_up("nl");
    fs::write(home.state().join("nl/config.conf"), crlf_config()).unwrap();
    fs::create_dir_all(home.root.join("profiles/work")).unwrap();

    let out = home.run(&["container", "set", "work", "network", "nope"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("сети nope нет"), "{}", stderr(&out));

    let out = home.run(&["container", "set", "work", "network", "nl"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["container", "show", "work", "--json"]));
    assert!(json.starts_with("{\"schema_version\":1,"), "{json}");
    assert!(
        json.contains("\"network\":{\"value\":\"nl\",\"source\":\"local\"}"),
        "{json}"
    );

    let dry = [("VPN_ZONE_DRYRUN", "1")];
    let out = home.run_with(
        &["run", "direct", "--profile", "work", "--", "firefox"],
        &dry,
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("работает в сети «nl»"),
        "{}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("cellward container set work network unconfined"),
        "{}",
        stderr(&out)
    );
    let out = home.run_with(&["run", "nl", "--profile", "work", "--", "firefox"], &dry);
    assert!(out.status.success(), "{}", stderr(&out));

    // Unbinding brings the per-launch question back.
    let out = home.run(&["container", "set", "work", "network", "ask"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = home.run_with(
        &["run", "direct", "--profile", "work", "--", "firefox"],
        &dry,
    );
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn kill_refuses_what_is_not_a_zone_of_its_own() {
    let home = Home::new("kill");
    // The exit codes are a contract: 2 not up, 3 refused.
    for name in ["unconfined", "direct"] {
        let out = home.run(&["kill", name]);
        assert_eq!(out.status.code(), Some(3), "{name}");
        assert!(stderr(&out).contains("сеть хоста"), "{}", stderr(&out));
    }
    assert_eq!(home.run(&["kill"]).status.code(), Some(3));
    let out = home.run(&["kill", "nl"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("не поднята"), "{}", stderr(&out));
    // A zone whose pid is a process of the host's network: "everything in its
    // namespace" would be the whole session. Refused before anything is
    // touched — this very test process is in that namespace.
    home.zone_is_up("nl");
    let out = home.run(&["kill", "nl"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(stderr(&out).contains("отказываюсь"), "{}", stderr(&out));
    assert!(!home.state().join(".journal").exists());
}

#[test]
fn the_journal_reads_for_a_person_and_for_a_program() {
    let home = Home::new("journal");
    let out = home.run(&["journal"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("журнал пуст"), "{}", stdout(&out));
    fs::create_dir_all(home.state()).unwrap();
    fs::write(
        home.state().join(".journal"),
        "{\"time\":\"2026-09-17T13:05:09Z\",\"event\":\"launch-unconfined\",\"app\":\"firefox\",\"container\":\"sb:web\",\"program\":\"firefox\",\"pid\":\"42\"}\n\
         {\"time\":\"2026-09-17T13:06:00Z\",\"event\":\"broker\",\"origin\":\"nl\",\"target\":\"unconfined\",\"app\":\"tg\",\"decision\":\"refused\",\"why\":\"человек отказал\"}\n\
         {\"time\":\"cut sho\n",
    )
    .unwrap();
    let out = stdout(&home.run(&["journal"]));
    assert!(
        out.contains(
            "2026-09-17 13:05:09 UTC  без ограничений: firefox (firefox, контейнер sb:web), pid 42"
        ),
        "{out}"
    );
    assert!(
        out.contains("брокер: из зоны «nl» в «unconfined» — tg — отказано: человек отказал"),
        "{out}"
    );
    assert!(out.contains("(повреждённая строка)"), "{out}");
    let out = stdout(&home.run(&["journal", "--json", "2"]));
    assert!(
        out.starts_with("{\"schema_version\":1,\"events\":[{\"time\":\"2026-09-17T13:06:00Z\",\"event\":\"broker\""),
        "{out}"
    );
    assert!(out.trim_end().ends_with("}]}"), "{out}");
    assert_eq!(home.run(&["journal", "0"]).status.code(), Some(1));
}

#[test]
fn a_container_is_never_in_two_networks_at_once() {
    // docs/CONTAINERS.md I2: even an unbound container, while its programs run.
    let home = Home::new("two-networks");
    home.zone_is_up("nl");
    fs::create_dir_all(home.root.join("profiles/work")).unwrap();
    let reg = home.state().join(".running/work/firefox");
    fs::create_dir_all(reg.parent().unwrap()).unwrap();
    fs::write(&reg, format!("{} nl work\n", std::process::id())).unwrap();

    let dry = [("VPN_ZONE_DRYRUN", "1")];
    let out = home.run_with(&["run", "direct", "--profile", "work", "--", "tg"], &dry);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("двух сетях"), "{}", stderr(&out));
    let out = home.run_with(&["run", "nl", "--profile", "work", "--", "tg"], &dry);
    assert!(out.status.success(), "{}", stderr(&out));
    // And the binding cannot be moved under running programs either.
    let out = home.run(&["container", "set", "work", "network", "direct"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("сейчас работают в сети nl"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn what_nix_declares_is_shown_as_such_and_not_changed_here() {
    let home = Home::new("declared");
    let declared = home.root.join("config/declared/containers");
    fs::create_dir_all(&declared).unwrap();
    fs::write(
        declared.join("private-dev.conf"),
        "network = offline\napp = firefox\n",
    )
    .unwrap();
    fs::create_dir_all(home.root.join("profiles/work")).unwrap();

    let out = home.run(&["container", "set", "sb:dev", "network", "direct"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("задана в Nix"), "{}", stderr(&out));
    let out = home.run(&["container", "assign", "firefox", "work"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("в Nix"), "{}", stderr(&out));

    let out = home.run(&["status", "--json"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&out);
    assert!(json.starts_with("{\"schema_version\":1,"), "{json}");
    // One name per container: the old `sb:` of a sandbox is not written.
    assert!(json.contains("\"selector\":\"dev\""), "{json}");
    assert!(
        json.contains("\"network\":{\"value\":\"offline\",\"source\":\"nix\"}"),
        "{json}"
    );
    // Declared and not yet on disk: the home itself comes from Nix.
    assert!(
        json.contains("\"home\":{\"value\":\"private\",\"source\":\"nix\"}"),
        "{json}"
    );
    assert!(json.contains("\"id\":\"firefox\""), "{json}");
    assert!(json.contains("\"uplink_owner\":"), "{json}");
    assert!(
        json.contains("\"autostart_unassigned\":{\"value\":\"ask\",\"source\":\"default\"}"),
        "{json}"
    );
    assert!(
        json.contains("\"wayland_proxy\":{\"value\":true,\"source\":\"default\"}"),
        "{json}"
    );
    assert!(
        json.contains("\"container\":{\"value\":\"dev\",\"source\":\"nix\"}"),
        "{json}"
    );
    assert!(
        json.contains("\"name\":\"unconfined\",\"kind\":\"unconfined\",\"aliases\":[\"direct\"]"),
        "{json}"
    );
    // A local assignment of another program is local.
    let out = home.run(&["container", "assign", "tg", "work"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"container\":{\"value\":\"work\",\"source\":\"local\"}"),
        "{json}"
    );
}

#[test]
fn a_private_home_is_granted_directories_but_never_the_state() {
    // docs/CONTAINERS.md §3.5: a Wine prefix or a Steam library, not the keys.
    let home = Home::new("grant");
    home.zone_is_up("nl");
    fs::create_dir_all(home.root.join("sandboxes/dev/home")).unwrap();
    fs::create_dir_all(home.root.join("profiles/work")).unwrap();
    let r = home.root.display().to_string();

    let out = home.run(&["container", "grant", "sb:dev", "~/.wine"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("увидят программы вне контейнера"),
        "{}",
        stdout(&out)
    );
    let json = stdout(&home.run(&["container", "show", "sb:dev", "--json"]));
    assert!(
        json.contains(&format!(
            "\"paths\":[{{\"value\":\"{r}/.wine\",\"source\":\"local\",\"expires\":null}}]"
        )),
        "{json}"
    );

    for refused in [
        "~/.local/state/vpn-zones",
        "~/.local/state/vpn-zones/nl",
        "~/state/nl",
        "~/sandboxes/dev/home",
        "~/.local/state",
        "~",
        "~/.wine/../.config/vpn-zones",
        "/run/user/1000",
        "/tmp/.X11-unix",
        "/etc",
        "relative/path",
    ] {
        let out = home.run(&["container", "grant", "sb:dev", refused]);
        assert_eq!(out.status.code(), Some(1), "{refused}: {}", stdout(&out));
        assert!(
            stderr(&out).contains("выдать нельзя"),
            "{refused}: {}",
            stderr(&out)
        );
    }
    // A layer over the home: a grant is a path of the home it writes
    // through, into the real one; outside the home there is no layer.
    let out = home.run(&["container", "grant", "work", "~/.wine"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = home.run(&["container", "grant", "work", "/mnt/games"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("слой над домом"), "{}", stderr(&out));

    // The launch hands the grant to fs-sandbox, which checks it once more.
    let out = home.run_with(
        &["run", "nl", "--sandbox", "dev", "--", "wine"],
        &[("VPN_ZONE_DRYRUN", "1"), ("VPN_ZONE_APPID", "wine")],
    );
    assert!(
        stdout(&out).contains(&format!("--name dev --bind-path {r}/.wine --")),
        "{}",
        stdout(&out)
    );

    let out = home.run(&["container", "revoke", "sb:dev", "~/.wine"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["container", "show", "sb:dev", "--json"]));
    assert!(json.contains("\"paths\":[]"), "{json}");

    // With a term: written next to the path, shown, and on the record.
    let out = home.run(&["container", "grant", "sb:dev", "~/.wine", "--for", "2h"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains(" до 20"), "{}", stdout(&out));
    let line = fs::read_to_string(home.root.join("config/containers/dev/paths")).unwrap();
    assert!(
        line.starts_with("until=") && line.trim_end().ends_with(&format!(" {r}/.wine")),
        "{line}"
    );
    let json = stdout(&home.run(&["container", "show", "sb:dev", "--json"]));
    assert!(
        json.contains("\"source\":\"local\",\"expires\":\"20"),
        "{json}"
    );
    for bad in [&["--for", "2w"][..], &["--for"][..], &["--later", "2h"][..]] {
        let mut argv = vec!["container", "grant", "sb:dev", "~/.wine"];
        argv.extend(bad);
        assert_eq!(home.run(&argv).status.code(), Some(1), "{bad:?}");
    }
    // A term that is over is not granted to anything, before any cleanup.
    fs::write(
        home.root.join("config/containers/dev/paths"),
        format!("until=1 {r}/.wine\n{r}/games\n"),
    )
    .unwrap();
    let json = stdout(&home.run(&["container", "show", "sb:dev", "--json"]));
    assert!(!json.contains(".wine"), "{json}");
    let out = home.run_with(
        &["run", "nl", "--sandbox", "dev", "--", "wine"],
        &[("VPN_ZONE_DRYRUN", "1"), ("VPN_ZONE_APPID", "wine")],
    );
    assert!(!stdout(&out).contains(".wine"), "{}", stdout(&out));
    // `expire` takes it out of the file and says so.
    let out = home.run(&["container", "expire"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("истёк"), "{}", stdout(&out));
    assert_eq!(
        fs::read_to_string(home.root.join("config/containers/dev/paths")).unwrap(),
        format!("{r}/games\n")
    );
    let journal = stdout(&home.run(&["journal", "--json"]));
    for event in [
        "\"event\":\"grant\"",
        "\"event\":\"revoke\"",
        "\"event\":\"grant-expired\"",
    ] {
        assert!(journal.contains(event), "{event}: {journal}");
    }
}

#[test]
fn a_merge_keeps_what_the_target_has_and_moves_the_programs() {
    // docs/CONTAINERS.md §3.4.
    let home = Home::new("merge");
    let old = home.root.join("profiles/old");
    let work = home.root.join("profiles/work");
    fs::create_dir_all(old.join("config/upper/app")).unwrap();
    fs::create_dir_all(work.join("config/upper")).unwrap();
    fs::write(old.join("config/upper/app/settings"), "old").unwrap();
    fs::write(old.join("config/upper/shared"), "old").unwrap();
    fs::write(work.join("config/upper/shared"), "work").unwrap();
    // A slot only the source has is created in the target.
    fs::create_dir_all(old.join("local-share/upper")).unwrap();
    fs::write(old.join("local-share/upper/history"), "old").unwrap();
    // A name a program of the target planted: never written through.
    std::os::unix::fs::symlink(
        "/nonexistent-elsewhere",
        work.join("config/upper/.merged-from-old"),
    )
    .unwrap();
    let pins = home.state().join(".pinnedprofile");
    fs::create_dir_all(&pins).unwrap();
    fs::write(pins.join("firefox"), "old").unwrap();
    fs::write(pins.join("tg"), "sb:other").unwrap();
    let sha = "a".repeat(64);
    fs::create_dir_all(old.join("trust")).unwrap();
    fs::write(
        old.join("trust").join(format!("{sha}.pem")),
        "-----BEGIN CERTIFICATE-----\n",
    )
    .unwrap();
    fs::create_dir_all(home.root.join("sandboxes/dev/home")).unwrap();

    let out = home.run(&["container", "merge", "old", "sb:dev"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("разные виды дома"),
        "{}",
        stderr(&out)
    );

    // A certificate the target does not trust yet needs a word of consent.
    let out = home.run(&["container", "merge", "old", "work"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("--yes"), "{}", stderr(&out));
    assert!(
        !work.join("config/upper/app").exists(),
        "refused means untouched"
    );

    // Not while programs of either run.
    let reg = home.state().join(".running/work/firefox");
    fs::create_dir_all(reg.parent().unwrap()).unwrap();
    fs::write(&reg, format!("{} direct work\n", std::process::id())).unwrap();
    let out = home.run(&["container", "merge", "old", "work", "--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("работают"), "{}", stderr(&out));
    fs::remove_file(&reg).unwrap();

    let out = home.run(&["container", "merge", "old", "work", "--yes"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stderr(&out).contains("теперь доверяет"), "{}", stderr(&out));
    assert_eq!(
        fs::read_to_string(work.join("config/upper/app/settings")).unwrap(),
        "old"
    );
    assert_eq!(
        fs::read_to_string(work.join("config/upper/shared")).unwrap(),
        "work"
    );
    assert_eq!(
        fs::read_to_string(work.join("config/upper/.merged-from-old-2/shared")).unwrap(),
        "old"
    );
    assert!(
        fs::symlink_metadata(work.join("config/upper/.merged-from-old"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read_to_string(work.join("local-share/upper/history")).unwrap(),
        "old"
    );
    // With the container's policy, not next to its data (the certificate was
    // put there in the old layout, and moved with the first look).
    assert!(home
        .root
        .join("config/containers/work/trust")
        .join(format!("{sha}.pem"))
        .is_file());
    assert_eq!(fs::read_to_string(pins.join("firefox")).unwrap(), "work");
    assert_eq!(fs::read_to_string(pins.join("tg")).unwrap(), "sb:other");
    // The source stays until it is removed by hand.
    assert!(old.join("config/upper/app/settings").is_file());
    assert!(
        stdout(&out).contains("cellward container rm old"),
        "{}",
        stdout(&out)
    );

    // What Nix declares is merged in the configuration.
    let declared = home.root.join("config/declared/containers");
    fs::create_dir_all(&declared).unwrap();
    fs::write(declared.join("overlay-work.conf"), "network = direct\n").unwrap();
    let out = home.run(&["container", "merge", "old", "work", "--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("объявлен в Nix"), "{}", stderr(&out));
}

#[test]
fn launch_starts_an_entry_by_id_through_the_picker() {
    // docs/CONTAINERS.md §5.1: a key binding gets what a click gets.
    let home = Home::new("launch");
    let apps = home.root.join(".local/share/applications");
    fs::create_dir_all(&apps).unwrap();
    fs::write(
        apps.join("vpnztest-fox.desktop"),
        "[Desktop Entry]\nType=Application\nName=Test Fox\nExec=fox --new-window %U\n",
    )
    .unwrap();
    let r = home.root.display().to_string();
    let dry = [("VPN_ZONE_DRYRUN", "1")];

    let out = home.run_with(&["launch", "vpnztest-fox", "--", "https://a", "b c"], &dry);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        stdout(&out).trim_end(),
        format!(
            "{r}/bin/vpn-zone-pick --id vpnztest-fox --label Test Fox -- fox --new-window https://a b c"
        )
    );

    // Taken over in place: the original from the backup, never our rewrite.
    fs::write(
        apps.join("vpnztest-fox.desktop"),
        "[Desktop Entry]\nName=Test Fox\nExec=/x/vpn-zone-pick --id vpnztest-fox -- fox\nX-VPNZone=adopted\n",
    )
    .unwrap();
    let backups = home.state().join(".adopted");
    fs::create_dir_all(&backups).unwrap();
    fs::write(
        backups.join("vpnztest-fox.desktop"),
        "[Desktop Entry]\nName=Test Fox\nExec=fox --from-backup\n",
    )
    .unwrap();
    let out = home.run_with(&["launch", "vpnztest-fox"], &dry);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).ends_with("-- fox --from-backup\n"),
        "{}",
        stdout(&out)
    );

    // Arguments an entry does not take are not passed.
    let out = home.run_with(&["launch", "vpnztest-fox", "--", "x"], &dry);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("не принимает аргументов"),
        "{}",
        stderr(&out)
    );
    assert!(
        stdout(&out).ends_with("-- fox --from-backup\n"),
        "{}",
        stdout(&out)
    );

    for (args, message) in [
        (&["launch", "vpnztest-nope"][..], "нет ни в одном"),
        (&["launch", "vpn-zone-add"][..], "служебный"),
        (&["launch", "vpnztest-fox", "x"][..], "после --"),
        (&["launch"][..], "нужен id"),
    ] {
        let out = home.run_with(args, &dry);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(stderr(&out).contains(message), "{args:?}: {}", stderr(&out));
    }
}

#[test]
fn doctor_reports_as_json_and_fails_on_what_it_cannot_prove() {
    // Every tool in this manifest is missing, and the zone "nl" is up but
    // cannot be entered: both are failures, never silence.
    let home = Home::new("doctor");
    home.zone_is_up("nl");
    fs::write(home.state().join("nl/config.conf"), crlf_config()).unwrap();
    fs::create_dir_all(home.state().join("de")).unwrap();
    fs::write(home.state().join("de/config.conf"), crlf_config()).unwrap();
    let out = home.run(&["doctor", "--json"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let json = stdout(&out);
    assert!(
        json.starts_with("{\"schema_version\":1,\"worst\":\"fail\","),
        "{json}"
    );
    assert!(
        json.contains("{\"id\":\"tool-nsenter\",\"level\":\"fail\""),
        "{json}"
    );
    // A zone that is down is skipped, not failed.
    assert!(
        json.contains(
            "{\"name\":\"de\",\"up\":false,\"checks\":[{\"id\":\"up\",\"level\":\"skip\""
        ),
        "{json}"
    );
    assert!(json.contains("\"name\":\"nl\",\"up\":true"), "{json}");
    assert!(
        json.contains("{\"id\":\"probe\",\"level\":\"fail\""),
        "{json}"
    );

    let out = home.run(&["doctor", "nope"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("такой зоны нет"), "{}", stdout(&out));
}

#[test]
fn a_host_interface_zone_is_added_and_reported_as_such() {
    let home = Home::new("hostif");
    let conf = home.root.join("lan.conf");
    fs::write(
        &conf,
        "[HostInterface]\nInterface = vpnztest0\nDNS = 192.0.2.53\n",
    )
    .unwrap();
    let out = home.run(&["add", "lan", conf.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("не шифрует"), "{}", stdout(&out));
    // The interface is not there right now: said, not refused.
    assert!(stderr(&out).contains("сейчас нет"), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("{\"name\":\"lan\",\"kind\":\"host-interface\""),
        "{json}"
    );
    assert!(
        json.contains("\"interface\":\"vpnztest0\",\"x11\":{"),
        "{json}"
    );
    assert!(
        json.contains("\"name\":\"unconfined\",\"kind\":\"unconfined\"")
            && json.contains("\"interface\":null"),
        "{json}"
    );

    for bad in [
        "[HostInterface]\nInterface = lo\n",
        "[HostInterface]\nDNS = 192.0.2.53\n",
        "[HostInterface]\nInterface = eth0\nDNS = resolver.example\n",
    ] {
        fs::write(&conf, bad).unwrap();
        let out = home.run(&["add", "bad", conf.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(1), "{bad}");
        assert!(
            stderr(&out).contains("[HostInterface]"),
            "{bad}: {}",
            stderr(&out)
        );
    }
}

#[test]
fn watch_announces_a_dead_tunnel_once_and_its_recovery() {
    let home = Home::new("watch");
    home.zone_is_up("nl");
    let zone = home.state().join("nl");
    fs::write(zone.join("config.conf"), crlf_config()).unwrap();
    let mirror = |rx: &str, tx: &str| {
        fs::write(
            zone.join("status"),
            format!(
                "interface: awg0\n\npeer: x\n  latest handshake: 10 minutes, 2 seconds ago\n  \
                 transfer: {rx} received, {tx} sent\n"
            ),
        )
        .unwrap()
    };
    let look = || {
        let out = home.run(&["watch", "--json"]);
        assert!(out.status.success(), "{}", stderr(&out));
        stdout(&out)
    };
    mirror("1.00 KiB", "1.00 KiB");
    let out = look();
    assert!(out.starts_with("{\"schema_version\":1,"), "{out}");
    assert!(out.contains("\"verdict\":\"unknown\""), "{out}");
    assert!(out.contains("\"handshake_age_s\":602"), "{out}");
    // Sending into silence: suspect at the first look, dead at the second.
    mirror("1.00 KiB", "2.00 KiB");
    assert!(look().contains("\"verdict\":\"suspect\",\"handshake_age_s\":602,\"rx_bytes\":1024,\"tx_bytes\":2048,\"notified\":false"));
    mirror("1.00 KiB", "3.00 KiB");
    let out = look();
    assert!(out.contains("\"verdict\":\"dead\""), "{out}");
    assert!(out.contains("\"notified\":true"), "{out}");
    // Still dead: not announced again.
    mirror("1.00 KiB", "4.00 KiB");
    assert!(look().contains("\"notified\":false"));
    // Answers again: alive, and that is announced.
    mirror("5.00 KiB", "5.00 KiB");
    let out = look();
    assert!(out.contains("\"verdict\":\"alive\""), "{out}");
    assert!(out.contains("\"notified\":true"), "{out}");

    // The status bar line marks nothing dead now.
    let bar = stdout(&home.run(&["status", "--bar"]));
    assert_eq!(
        bar.trim(),
        "{\"text\":\"nl\",\"tooltip\":\"cellward: поднятые зоны\",\"class\":\"up\",\"unconfined\":0}"
    );

    // A program running unconfined is marked, dead records are not.
    let reg = home.state().join(".running/__main__/firefox");
    fs::create_dir_all(reg.parent().unwrap()).unwrap();
    fs::write(
        &reg,
        format!(
            "{} direct __main__\n999999999 unconfined __main__\n",
            std::process::id()
        ),
    )
    .unwrap();
    let bar = stdout(&home.run(&["status", "--bar"]));
    assert_eq!(
        bar.trim(),
        "{\"text\":\"nl ⚠1\",\"tooltip\":\"cellward: поднятые зоны\\nБез ограничений (⚠) сейчас: firefox\",\"class\":\"up\",\"unconfined\":1}"
    );
    fs::remove_file(&reg).unwrap();

    // status --json carries the counters too.
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"handshake_age_s\":602,\"rx_bytes\":5120,\"tx_bytes\":5120"),
        "{json}"
    );
}

#[test]
fn a_container_with_x11_gets_its_own_x_server_in_zones_only() {
    // docs/HERMETICITY.md §7, A.
    let home = Home::new("x11");
    home.zone_is_up("nl");
    fs::write(home.state().join("nl/config.conf"), crlf_config()).unwrap();
    fs::create_dir_all(home.root.join("profiles/work")).unwrap();
    fs::create_dir_all(home.root.join("sandboxes/dev/home")).unwrap();
    let dry = [("VPN_ZONE_DRYRUN", "1")];

    let out = home.run_with(&["run", "nl", "--profile", "work", "--", "steam"], &dry);
    assert!(!stdout(&out).contains("x11-run"), "{}", stdout(&out));

    let out = home.run(&["container", "set", "work", "x11", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["container", "show", "work", "--json"]));
    assert!(
        json.contains("\"x11\":{\"value\":true,\"source\":\"local\"}"),
        "{json}"
    );

    let out = home.run_with(&["run", "nl", "--profile", "work", "--", "steam"], &dry);
    assert!(
        stdout(&out).contains("x11-run --xwayland /nonexistent/xwayland-satellite -- steam"),
        "{}",
        stdout(&out)
    );
    // `direct` is the host's own session: nothing to add.
    let out = home.run_with(&["run", "direct", "--profile", "work", "--", "steam"], &dry);
    assert!(!stdout(&out).contains("x11-run"), "{}", stdout(&out));

    // A sandbox is told, and starts its own satellite.
    let out = home.run(&["container", "set", "sb:dev", "x11", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = home.run_with(
        &["run", "nl", "--sandbox", "dev", "--", "steam"],
        &[("VPN_ZONE_DRYRUN", "1"), ("VPN_ZONE_APPID", "steam")],
    );
    assert!(stdout(&out).contains("--x11 on --"), "{}", stdout(&out));

    let out = home.run(&["container", "set", "work", "x11", "maybe"]);
    assert_eq!(out.status.code(), Some(1));

    // Or the zone itself, without any container.
    let out = home.run_with(&["run", "nl", "--", "steam"], &dry);
    assert!(!stdout(&out).contains("x11-run"), "{}", stdout(&out));
    let out = home.run(&["x11", "nl", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = home.run_with(&["run", "nl", "--", "steam"], &dry);
    assert!(
        stdout(&out).contains("x11-run --xwayland"),
        "{}",
        stdout(&out)
    );
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"x11\":{\"value\":true,\"source\":\"local\"},\"hermetic\":"),
        "{json}"
    );
    // Hermetic (the prototype): a marker and its JSON.
    let out = home.run(&["hermetic", "nl", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("перезапуска"), "{}", stdout(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"hermetic\":{\"value\":true,\"source\":\"local\"},\"nix_daemon\":"),
        "{json}"
    );
    // What the zone is let besides: a marker each, and its JSON.
    let out = home.run(&["nix-daemon", "nl", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = home.run(&["host-files", "nl", "writable"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"nix_daemon\":{\"value\":true,\"source\":\"local\"},\"host_files_writable\":{\"value\":true,\"source\":\"local\"}"),
        "{json}"
    );
    assert!(!home.run(&["nix-daemon", "nl", "yes"]).status.success());
    assert!(home.run(&["nix-daemon", "nl", "default"]).status.success());
    assert!(home.run(&["host-files", "nl", "default"]).status.success());
    // The microphone: ask by default, the zone's marker, Nix over it; the
    // host's own network has none to set.
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"microphone\":{\"value\":\"ask\",\"source\":\"default\"}"),
        "{json}"
    );
    assert!(
        json.contains("\"camera\":null,\"microphone\":null,"),
        "{json}"
    );
    let out = home.run(&["microphone", "nl", "no"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("недоступен"), "{}", stdout(&out));
    // Said for what it is: the switch of pulse and of the zone's restricted
    // PipeWire; the zone is hermetic here and no audio manager, so nothing
    // goes around it — neither the raw pipewire-0 nor systemd --user.
    assert!(stdout(&out).contains("(pulse)"), "{}", stdout(&out));
    assert!(stdout(&out).contains("PipeWire зоны"), "{}", stdout(&out));
    assert!(!stdout(&out).contains("pipewire-0"), "{}", stdout(&out));
    assert!(!stdout(&out).contains("systemd --user"), "{}", stdout(&out));
    // An audio manager: the raw socket, said loudly, and named as what goes
    // around the microphone's switch; in status with its source.
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"audio_manager\":{\"value\":false,\"source\":\"default\"}"),
        "{json}"
    );
    assert!(
        json.contains("\"microphone\":null,\"screencast\":null,\"audio_manager\":null,"),
        "{json}"
    );
    let out = home.run(&["audio-manager", "nl", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("ВНИМАНИЕ"), "{}", stdout(&out));
    assert_eq!(
        fs::read_to_string(home.state().join("nl/audio-manager")).unwrap(),
        "on"
    );
    let out = home.run(&["microphone", "nl", "no"]);
    assert!(
        stdout(&out).contains("сырой pipewire-0"),
        "{}",
        stdout(&out)
    );
    assert!(
        stdout(&out).contains("audio-manager nl off"),
        "{}",
        stdout(&out)
    );
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"audio_manager\":{\"value\":true,\"source\":\"local\"}"),
        "{json}"
    );
    assert!(!home.run(&["audio-manager", "nl", "yes"]).status.success());
    fs::create_dir_all(home.root.join("config/declared")).unwrap();
    fs::write(home.root.join("config/declared/audio-manager"), "nl\n").unwrap();
    assert!(home
        .run(&["audio-manager", "nl", "default"])
        .status
        .success());
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"audio_manager\":{\"value\":true,\"source\":\"nix\"}"),
        "{json}"
    );
    fs::remove_file(home.root.join("config/declared/audio-manager")).unwrap();
    assert!(!home.state().join("nl/audio-manager").exists());
    assert_eq!(
        fs::read_to_string(home.state().join("nl/microphone")).unwrap(),
        "no"
    );
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"microphone\":{\"value\":\"no\",\"source\":\"local\"}"),
        "{json}"
    );
    assert!(!home.run(&["microphone", "nl", "maybe"]).status.success());
    assert!(!home.run(&["microphone", "nowhere", "yes"]).status.success());
    fs::create_dir_all(home.root.join("config/declared")).unwrap();
    fs::write(home.root.join("config/declared/microphone"), "nl yes\n").unwrap();
    let out = home.run(&["microphone", "nl", "ask"]);
    assert!(stdout(&out).contains("задано в Nix"), "{}", stdout(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"microphone\":{\"value\":\"yes\",\"source\":\"nix\"}"),
        "{json}"
    );
    fs::remove_file(home.root.join("config/declared/microphone")).unwrap();
    assert!(home.run(&["microphone", "nl", "default"]).status.success());
    assert!(!home.state().join("nl/microphone").exists());
    // The screen cast: ask by default, the zone's marker, Nix over it —
    // next to the microphone in status; the host's own network has none.
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains(
            "\"microphone\":{\"value\":\"ask\",\"source\":\"default\"},\
             \"screencast\":{\"value\":\"ask\",\"source\":\"default\"}"
        ),
        "{json}"
    );
    let out = home.run(&["screencast", "nl", "no"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("недоступна"), "{}", stdout(&out));
    assert_eq!(
        fs::read_to_string(home.state().join("nl/screencast")).unwrap(),
        "no"
    );
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"screencast\":{\"value\":\"no\",\"source\":\"local\"}"),
        "{json}"
    );
    // yes, in a hermetic zone: said to need the portal to know the zone,
    // and to be ask in a file sandbox.
    let out = home.run(&["screencast", "nl", "yes"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("запомнить"), "{}", stdout(&out));
    assert!(
        stdout(&out).contains("знает зону по имени"),
        "{}",
        stdout(&out)
    );
    assert!(!stdout(&out).contains("не герметична"), "{}", stdout(&out));
    assert!(!home.run(&["screencast", "nl", "maybe"]).status.success());
    assert!(!home.run(&["screencast", "nowhere", "yes"]).status.success());
    assert!(!home.run(&["screencast", "nl"]).status.success());
    fs::write(home.root.join("config/declared/screencast"), "nl ask\n").unwrap();
    let out = home.run(&["screencast", "nl", "no"]);
    assert!(stdout(&out).contains("задано в Nix"), "{}", stdout(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"screencast\":{\"value\":\"ask\",\"source\":\"nix\"}"),
        "{json}"
    );
    fs::remove_file(home.root.join("config/declared/screencast")).unwrap();
    assert!(home.run(&["screencast", "nl", "default"]).status.success());
    assert!(!home.state().join("nl/screencast").exists());
    // The pause after a refusal: a term within 30s…1d, Nix over it.
    let out = home.run(&["ask-again", "10m"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("через 10m"), "{}", stdout(&out));
    let out = home.run(&["ask-again", "600s"]);
    assert!(stdout(&out).contains("через 10m"), "{}", stdout(&out));
    for bad in ["5s", "2d", "0m", "soon"] {
        assert!(!home.run(&["ask-again", bad]).status.success(), "{bad}");
    }
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"ask_again\":{\"value\":\"10m\",\"source\":\"local\"}"),
        "{json}"
    );
    fs::write(home.root.join("config/declared/ask-again"), "1h").unwrap();
    let out = home.run(&["ask-again", "default"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("Nix"), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"ask_again\":{\"value\":\"1h\",\"source\":\"nix\"}"),
        "{json}"
    );
    fs::remove_file(home.root.join("config/declared/ask-again")).unwrap();
    assert!(home.run(&["ask-again", "default"]).status.success());
    assert!(!home.root.join("config/ask-again").exists());
    let out = home.run(&["hermetic", "nl", "off"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"hermetic\":{\"value\":false,\"source\":\"local\"},\"nix_daemon\":"),
        "{json}"
    );
    assert!(
        json.contains(
            "\"hermetic\":{\"value\":true,\"source\":\"default\"},\
             \"ask_again\":{\"value\":\"3m\",\"source\":\"default\"}}"
        ),
        "{json}"
    );
    // A zone that is not hermetic: its "no" is said to be no boundary
    // against systemd --user, which records on the host and writes the
    // setting.
    let out = home.run(&["microphone", "nl", "no"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("systemd --user"), "{}", stdout(&out));
    assert!(home.run(&["microphone", "nl", "default"]).status.success());
    // Nor is its screen cast switch: no filter reads it there.
    let out = home.run(&["screencast", "nl", "no"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("не герметична"), "{}", stdout(&out));
    assert!(home.run(&["screencast", "nl", "default"]).status.success());
    // A local default, and a zone that follows it again.
    let out = home.run(&["hermetic", "--default", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = home.run(&["hermetic", "nl", "default"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"user_entries\":{\"value\":\"take-over\",\"source\":\"default\"},\"hermetic\":{\"value\":true,\"source\":\"local\"},\"ask_again\":"),
        "{json}"
    );
    // Declared in Nix: the default refuses the CLI, and an exception inverts it.
    fs::create_dir_all(home.root.join("config/declared")).unwrap();
    fs::write(home.root.join("config/declared/hermetic-default"), "on").unwrap();
    fs::write(
        home.root.join("config/declared/hermetic-exceptions"),
        "nl\n",
    )
    .unwrap();
    let out = home.run(&["hermetic", "--default", "off"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("в Nix"), "{}", stderr(&out));
    let out = home.run(&["hermetic", "nl", "on"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("hermetic.exceptions"),
        "{}",
        stderr(&out)
    );
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"hermetic\":{\"value\":false,\"source\":\"nix\"},\"nix_daemon\":"),
        "{json}"
    );
    fs::remove_file(home.root.join("config/declared/hermetic-default")).unwrap();
    fs::remove_file(home.root.join("config/declared/hermetic-exceptions")).unwrap();
    // Declared in Nix: switched off there, not here.
    fs::create_dir_all(home.root.join("config/declared")).unwrap();
    fs::write(home.root.join("config/declared/zone-x11"), "nl\n").unwrap();
    let out = home.run(&["x11", "nl", "off"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("в Nix"), "{}", stderr(&out));
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

#[test]
fn a_zone_gets_its_border_colour_width_and_switch() {
    // docs/WINDOW-FRAME.md §0а, §11: the colour per zone and its width go to
    // the proxy with the launch, from Nix over the local setting over the
    // default; the switch is read by the supervisor, so only its directory.
    let home = Home::new("frame");
    home.zone_is_up("nl");
    fs::write(home.state().join("nl/config.conf"), crlf_config()).unwrap();
    let dry = [("VPN_ZONE_DRYRUN", "1")];
    let default = vpn_zone::frame::default_color("nl").hex();

    let line = stdout(&home.run_with(&["run", "nl", "--", "foot"], &dry));
    // The title strip: always by default, the zone and the container as the
    // launch knows it.
    assert!(
        line.contains(&format!(
            "wl-sandbox foot --zone nl --frame {}:4:always --frame-title nl · основной \
             --frame-switch {} -- foot",
            &default[1..],
            home.root.join("config").display()
        )),
        "{line}"
    );
    let line = stdout(&home.run_with(&["run", "nl", "--fs-sandbox", "--", "foot"], &dry));
    assert!(
        line.contains("--frame-title nl · разовая песочница "),
        "{line}"
    );
    // No border for the host's own session: it is no zone.
    let line = stdout(&home.run_with(&["run", "unconfined", "--", "foot"], &dry));
    assert!(!line.contains("--frame"), "{line}");

    let out = home.run(&["frame", "color", "nl", "#3366FF"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("#3366ff"), "{}", stdout(&out));
    let out = home.run(&["frame", "width", "6"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = home.run(&["frame", "title", "hover"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let line = stdout(&home.run_with(&["run", "nl", "--", "foot"], &dry));
    assert!(line.contains("--frame 3366ff:6:hover "), "{line}");
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"frame_title\":{\"value\":\"hover\",\"source\":\"local\"}"),
        "{json}"
    );
    assert!(
        json.contains("\"frame_color\":{\"value\":\"#3366ff\",\"source\":\"local\"}"),
        "{json}"
    );
    assert!(
        json.contains("\"frame_width\":{\"value\":6,\"source\":\"local\"}"),
        "{json}"
    );

    // Nix wins, and the command does not pretend to change what Nix set.
    let declared = home.root.join("config/declared");
    fs::create_dir_all(&declared).unwrap();
    fs::write(declared.join("frame-colors"), "nl #ff0000\n").unwrap();
    fs::write(declared.join("frame-width"), "3").unwrap();
    fs::write(declared.join("frame-title"), "off").unwrap();
    let line = stdout(&home.run_with(&["run", "nl", "--", "foot"], &dry));
    assert!(line.contains("--frame ff0000:3:off "), "{line}");
    for change in [&["frame", "width", "8"][..], &["frame", "title", "default"]] {
        let out = home.run(change);
        assert!(!out.status.success(), "{change:?}");
        assert!(stderr(&out).contains("Nix"), "{}", stderr(&out));
    }
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"frame_color\":{\"value\":\"#ff0000\",\"source\":\"nix\"}"),
        "{json}"
    );
    assert!(
        json.contains("\"frame_title\":{\"value\":\"off\",\"source\":\"nix\"}"),
        "{json}"
    );
    fs::remove_file(declared.join("frame-title")).unwrap();
    let out = home.run(&["frame", "title", "default"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"frame_title\":{\"value\":\"always\",\"source\":\"default\"}"),
        "{json}"
    );

    // Back to the name's colour.
    fs::remove_file(declared.join("frame-colors")).unwrap();
    let out = home.run(&["frame", "color", "nl", "default"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains(&default), "{}", stdout(&out));

    // The switch: a setting of its own, read when a program connects.
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"frames\":{\"value\":true,\"source\":\"default\"}"),
        "{json}"
    );
    let out = home.run(&["frame", "hide"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        fs::read_to_string(home.root.join("config/frames")).unwrap(),
        "hidden"
    );
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"frames\":{\"value\":false,\"source\":\"local\"}"),
        "{json}"
    );
    assert!(home.run(&["frame", "show"]).status.success());
    assert!(!vpn_zone::frame::hidden(&home.root.join("config")));

    // Nonsense is refused, and a zone that is not there too.
    for bad in [
        &["frame", "color", "nl", "blue"][..],
        &["frame", "color", "nope", "#000000"],
        &["frame", "width", "0"],
        &["frame", "width", "33"],
        &["frame", "title", "sometimes"],
        &["frame", "title"],
        &["frame", "sideways"],
    ] {
        assert!(!home.run(bad).status.success(), "{bad:?}");
    }
}
