//! End-to-end checks of `vpn-zone-core fs-sandbox`.
//!
//! Two kinds of test live here, and the split is not cosmetic.
//!
//! What runs everywhere is the part that needs no namespaces: argument
//! handling, the headless permission branch (no graphical session means "allow
//! nothing", written down without ever showing a dialog) and the soft
//! degradation of the D-Bus proxy. bwrap is stood in for by a shell script the
//! test writes, and `$HOME` is redirected into a temporary directory in every
//! one of them — these tests must never touch the permissions of the machine
//! they run on.
//!
//! What is `#[ignore]`d is everything that needs a REAL bwrap, i.e. an
//! unprivileged user namespace. CI runs `cargo test` in a job that does not
//! prepare one (the AppArmor restriction of ubuntu-24.04 is lifted only in the
//! integration job), so those would fail there for a reason that has nothing to
//! do with this code. The same ground is covered by
//! `tests/integration/smoke.sh`, which runs where the namespaces work — and
//! against the paths baked into the real `vpn-zone` script, which is the more
//! honest test anyway. Run them by hand with:
//!
//! ```sh
//! cargo test --test fs_sandbox_cli -- --ignored
//! ```

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_vpn-zone-core");

/// A throwaway `$HOME`, removed on drop. Nothing here may write into the real
/// one: the permission files are the user's, not the test's.
struct Home {
    dir: PathBuf,
}

impl Home {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("vpn-zone-fs-test-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join(".config")).unwrap();
        fs::create_dir_all(dir.join("run")).unwrap();
        Self { dir }
    }

    /// An executable stand-in for bwrap. Written rather than borrowed from the
    /// system, because neither `/bin/true` nor `/usr/bin/true` is a given: on
    /// NixOS `/bin` holds `sh` and nothing else.
    fn script(&self, name: &str, body: &str) -> String {
        let path = self.dir.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        fs::set_permissions(&path, perms).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn perms(&self, app: &str) -> PathBuf {
        self.dir.join(".config/vpn-zones/fs-perms").join(app)
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// `fs-sandbox` with no graphical session and no reachable session bus.
///
/// `--kdialog /nonexistent…` is an assertion in itself: the headless branch must
/// never reach for a dialog, and a run that did would say so on stderr instead
/// of hanging.
fn run(home: &Home, bwrap: &str, args: &[&str]) -> Output {
    Command::new(BIN)
        .arg("fs-sandbox")
        .args(["--bwrap", bwrap])
        .args(["--dbus-proxy", "/nonexistent/vpn-zone/xdg-dbus-proxy"])
        .args(["--kdialog", "/nonexistent/vpn-zone/kdialog"])
        .args(["--xwayland", "/nonexistent/vpn-zone/xwayland-satellite"])
        .args(args)
        .env("HOME", &home.dir)
        .env("XDG_RUNTIME_DIR", home.dir.join("run"))
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("DISPLAY")
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .output()
        .unwrap()
}

// --- WITHOUT NAMESPACES ------------------------------------------------------

#[test]
fn without_a_graphical_session_nothing_is_allowed_and_nothing_is_asked() {
    let home = Home::new("headless");
    let ok = home.script("bwrap-ok", "exit 0");
    let out = run(&home, &ok, &["testapp", "--", "prog"]);
    assert!(out.status.success(), "status {:?}", out.status.code());

    let perms = home.perms("testapp");
    let body = fs::read_to_string(&perms)
        .unwrap_or_else(|e| panic!("no permission file at {}: {e}", perms.display()));
    assert!(
        body.is_empty(),
        "a headless launch must allow nothing, got {body:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("kdialog"),
        "a dialog was attempted: {stderr}"
    );
}

#[test]
fn an_existing_permission_file_is_not_asked_about_again() {
    let home = Home::new("remembered");
    let ok = home.script("bwrap-ok", "exit 0");
    let dir = home.dir.join(".config/vpn-zones/fs-perms");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("testapp"), "pictures\n").unwrap();
    let out = run(&home, &ok, &["testapp", "--", "prog"]);
    assert!(out.status.success());
    // Untouched, byte for byte.
    assert_eq!(
        fs::read_to_string(home.perms("testapp")).unwrap(),
        "pictures\n"
    );
}

#[test]
fn a_named_sandbox_keeps_its_permissions_and_home_together() {
    let home = Home::new("named");
    let ok = home.script("bwrap-ok", "exit 0");
    let out = run(&home, &ok, &["testapp", "--name", "work", "--", "prog"]);
    assert!(out.status.success());
    let sb = home.dir.join(".local/state/vpn-sandboxes/work");
    assert!(sb.join("home").is_dir(), "the sandbox has no home");
    assert!(sb.join("perms").is_file(), "the permissions are not shared");
    // …and NOT under the per-application directory, or a second program in the
    // same sandbox would be asked about the very same home all over again.
    assert!(!home.perms("testapp").exists());
}

#[test]
fn a_dead_dbus_proxy_costs_the_bus_and_not_the_program() {
    let home = Home::new("nobus");
    // The bus socket must not be bound, or bwrap would fail on a source path
    // that does not exist — the regression this port fixes.
    let ok = home.script(
        "bwrap-check",
        // `unix:path=…/bus` is the ADDRESS and stays: it names a path inside the
        // runtime tmpfs, where there is nothing. Only a bind of the socket
        // itself would be the bug.
        "for a in \"$@\"; do\n\
         \x20 case $a in unix:path=*) continue ;; */bus) echo \"BOUND $a\"; exit 3 ;; esac\n\
         done\n\
         exit 0",
    );
    let out = run(&home, &ok, &["testapp", "--", "prog"]);
    assert!(
        out.status.success(),
        "a missing proxy must not stop the program: {:?}\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("session bus"),
        "the missing bus must be reported: {stderr}"
    );
}

#[test]
fn the_exit_code_is_the_sandboxs_own() {
    let home = Home::new("exit");
    let seven = home.script("bwrap-7", "exit 7");
    let out = run(&home, &seven, &["testapp", "--", "prog"]);
    assert_eq!(out.status.code(), Some(7));
}

#[test]
fn the_filter_reaches_bwrap_on_the_descriptor_it_names() {
    let home = Home::new("seccomp");
    // bwrap reads the program from a NUMBER, so the descriptor has to be open
    // and past FD_CLOEXEC in the child. Verified from the child itself.
    let check = home.script(
        "bwrap-fd",
        "n=\"\"; p=\"\"\n\
         for a in \"$@\"; do\n\
           if [ \"$p\" = --seccomp ]; then n=$a; fi\n\
           p=$a\n\
         done\n\
         [ -n \"$n\" ] || { echo NO-SECCOMP-ARG; exit 3; }\n\
         [ -e \"/proc/self/fd/$n\" ] || { echo \"FD $n MISSING\"; exit 4; }\n\
         exit 0",
    );
    let out = run(&home, &check, &["testapp", "--", "prog"]);
    assert!(
        out.status.success(),
        "{:?}: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn a_bwrap_that_cannot_be_started_gives_127() {
    let home = Home::new("nobwrap");
    let out = run(
        &home,
        "/nonexistent/vpn-zone/bwrap",
        &["testapp", "--", "prog"],
    );
    assert_eq!(out.status.code(), Some(127));
}

#[test]
fn bad_usage_is_reported() {
    let home = Home::new("usage");
    let ok = home.script("bwrap-ok", "exit 0");
    let cases: [&[&str]; 5] = [
        &[],
        &["testapp"],
        &["testapp", "prog"],
        &["testapp", "--"],
        &["--", "prog"],
    ];
    for args in cases {
        let out = run(&home, &ok, args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "expected a usage error for {args:?}"
        );
    }

    let help = Command::new(BIN).arg("--help").output().unwrap();
    assert!(help.status.success());
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(text.contains("fs-sandbox"));
    assert!(text.contains("fs-sandbox-x11"));
}

// --- WITH A REAL SANDBOX (needs an unprivileged user namespace) ---------------

/// A shell the sandbox can actually reach.
///
/// `/usr` and `/bin` are NOT passed into the sandbox, so whatever the host's
/// `PATH` says is unreachable in there; only `/nix/store` is. Resolving the
/// symlink is what turns `/bin/sh` into a store path on NixOS — and on a machine
/// where it does not, there is nothing to run these with.
fn store_sh() -> Option<String> {
    let real = fs::canonicalize("/bin/sh").ok()?;
    real.starts_with("/nix/store")
        .then(|| real.to_string_lossy().into_owned())
}

fn have_bwrap() -> bool {
    Command::new("bwrap")
        .args(["--ro-bind", "/", "/", "--", "/bin/sh", "-c", "exit 0"])
        .output()
        .is_ok_and(|o| o.status.success())
}

#[test]
#[ignore = "needs an unprivileged user namespace; covered by tests/integration/smoke.sh"]
fn the_home_inside_is_empty_and_the_real_one_is_invisible() {
    let (true, Some(sh)) = (have_bwrap(), store_sh()) else {
        eprintln!("no working bwrap or no /bin/sh in the store — skipping");
        return;
    };
    let home = Home::new("real");
    // A marker in the outer home: it must not be visible from inside.
    fs::write(home.dir.join("marker"), "secret").unwrap();

    let out = run(
        &home,
        "bwrap",
        &[
            "testapp",
            "--",
            &sh,
            "-c",
            "[ -d \"$HOME\" ] && echo HOME-OK; [ -e \"$HOME/marker\" ] && echo LEAK; \
             [ -d /nix/store ] && echo STORE-OK; exit 0",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "status {:?}, stderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("HOME-OK"), "no home inside: {stdout:?}");
    assert!(stdout.contains("STORE-OK"), "no store inside: {stdout:?}");
    assert!(
        !stdout.contains("LEAK"),
        "the real home is visible: {stdout:?}"
    );
    // And the marker is still there outside.
    assert!(home.dir.join("marker").is_file());
}

#[test]
#[ignore = "needs an unprivileged user namespace; covered by tests/integration/smoke.sh"]
fn the_program_exit_code_travels_out_of_the_sandbox() {
    let (true, Some(sh)) = (have_bwrap(), store_sh()) else {
        eprintln!("no working bwrap or no /bin/sh in the store — skipping");
        return;
    };
    let home = Home::new("realexit");
    let out = run(&home, "bwrap", &["testapp", "--", &sh, "-c", "exit 42"]);
    assert_eq!(out.status.code(), Some(42));
}
