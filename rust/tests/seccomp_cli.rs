//! End-to-end checks of the `vpn-zone-seccomp` binary.
//!
//! `selftest` runs in a process of its own on purpose: loading a seccomp filter
//! is irreversible, and doing it inside the test harness would leave every
//! later test in this thread running under the filter. Unprivileged seccomp
//! needs nothing but NO_NEW_PRIVS, which libseccomp sets itself, so these are
//! not `#[ignore]`d — if they fail in CI, the filter really is broken.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_vpn-zone-seccomp");

#[test]
fn selftest_passes() {
    let out = Command::new(BIN).arg("selftest").output().unwrap();
    assert!(
        out.status.success(),
        "selftest failed: status {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn selftest_passes_with_denied_userns() {
    let out = Command::new(BIN)
        .args(["selftest", "--deny-userns"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "selftest --deny-userns failed: status {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn export_writes_a_bpf_program_to_stdout() {
    let out = Command::new(BIN).arg("export").output().unwrap();
    assert!(out.status.success(), "export failed");
    assert!(!out.stdout.is_empty(), "export produced nothing");
    // struct sock_filter is 8 bytes; a truncated program would be rejected by
    // the kernel when bwrap loads it.
    assert_eq!(out.stdout.len() % 8, 0);

    let strict = Command::new(BIN)
        .args(["export", "--deny-userns"])
        .output()
        .unwrap();
    assert!(strict.status.success());
    assert!(strict.stdout.len() > out.stdout.len());
}

#[test]
fn bad_usage_is_reported() {
    let cases: [&[&str]; 3] = [&[], &["frobnicate"], &["export", "--nope"]];
    for args in cases {
        let out = Command::new(BIN).args(args).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "expected a usage error for {args:?}"
        );
    }

    let help = Command::new(BIN).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--deny-userns"));
}
