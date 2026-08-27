//! End-to-end checks of `vpn-zone-core wl-sandbox`.
//!
//! What can be checked without a compositor is exactly the part that matters
//! most: the FALLBACKS. Losing the Wayland restriction is acceptable, losing
//! the program is not — every "it did not work out" path has to still start the
//! command and say so on stderr. The sandboxed path itself needs a compositor
//! with `wp_security_context_v1` and is verified by hand (niri, KWin).
//!
//! The environment is scrubbed on purpose in every case: the developer machine
//! running these tests normally *does* have a compositor, and without that the
//! result would differ between a laptop and CI.

use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_vpn-zone-core");

/// `vpn-zone-core wl-sandbox …` with no way to reach a compositor.
fn run(args: &[&str], runtime_dir: Option<&str>) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.arg("wl-sandbox")
        .args(args)
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("WAYLAND_SOCKET");
    match runtime_dir {
        Some(dir) => cmd.env("XDG_RUNTIME_DIR", dir),
        None => cmd.env_remove("XDG_RUNTIME_DIR"),
    };
    cmd.output().unwrap()
}

#[test]
fn without_a_runtime_dir_the_program_still_runs() {
    let out = run(&["test-app", "--", "echo", "hi"], None);
    assert!(out.status.success(), "status {:?}", out.status.code());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hi");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("XDG_RUNTIME_DIR"),
        "the weakened protection must be reported: {stderr}"
    );
}

#[test]
fn without_a_compositor_the_program_still_runs() {
    // A real runtime directory, but nothing listening in it.
    let out = run(&["test-app", "--", "echo", "hi"], Some("/tmp"));
    assert!(out.status.success(), "status {:?}", out.status.code());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hi");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("compositor"),
        "the weakened protection must be reported: {stderr}"
    );
}

#[test]
fn the_exit_code_is_the_programs_own() {
    let out = run(&["test-app", "--", "sh", "-c", "exit 42"], None);
    assert_eq!(out.status.code(), Some(42));
}

#[test]
fn a_program_that_cannot_be_started_gives_127() {
    let out = run(&["test-app", "--", "vpn-zone-no-such-program"], None);
    assert_eq!(out.status.code(), Some(127));
}

#[test]
fn bad_usage_is_reported() {
    // Notably the old, separator-less call shape of the C version: it must be
    // refused rather than start "app-id" as if it were the program.
    let cases: [&[&str]; 5] = [
        &[],
        &["test-app"],
        &["test-app", "echo", "hi"],
        &["test-app", "--"],
        &["--", "echo", "hi"],
    ];
    for args in cases {
        let out = run(args, None);
        assert_eq!(
            out.status.code(),
            Some(2),
            "expected a usage error for {args:?}"
        );
    }

    let help = Command::new(BIN).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("wl-sandbox <app-id> -- cmd..."));
}
