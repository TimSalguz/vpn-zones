//! `vpn-zone-seccomp` — the seccomp filter of the fs sandbox, on the command
//! line.
//!
//! The sandbox itself does NOT go through this binary any more: `vpn-zone-core
//! fs-sandbox` builds the filter in its own process and hands bwrap an
//! inherited descriptor, which takes one fork and one temporary file off the
//! startup path of every sandboxed program. What is left here is the part a
//! person uses: `selftest`, which loads the filter into a process of its own
//! and checks that the kernel really does refuse what it claims to, and
//! `export`, which writes the compiled program to stdout for inspection or for
//! a hand-rolled `bwrap --seccomp`.
//!
//! Argument parsing is done by hand on purpose: two verbs and one flag do not
//! need a CLI framework.

use std::io::{self, Write};
use std::process::ExitCode;

use vpn_zone::seccomp::{selftest, Filter, FilterOptions};

const USAGE: &str = "\
vpn-zone-seccomp — seccomp-bpf filter for the vpn-zones filesystem sandbox

Usage:
  vpn-zone-seccomp export [--deny-userns]     write the compiled cBPF program to
                                              stdout (this is what bwrap's
                                              --seccomp FD reads)
  vpn-zone-seccomp selftest [--deny-userns]   load the filter into this process
                                              and check that it works
  vpn-zone-seccomp --help

Options:
  --deny-userns   also refuse nested user namespaces (clone/unshare with
                  CLONE_NEWUSER). Off by default: without zypak or a setuid
                  chrome-sandbox, Chromium and Electron applications build their
                  own nested user namespace and refuse to start without it
                  (\"No usable sandbox!\").

Exit codes:
  0  success
  1  a selftest check failed
  2  bad usage
  3  the filter could not be built, exported or loaded
";

/// A selftest check failed — the filter is not doing what it says.
const EXIT_CHECK_FAILED: u8 = 1;
/// Bad command line.
const EXIT_USAGE: u8 = 2;
/// libseccomp or I/O failure.
const EXIT_ERROR: u8 = 3;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let verb = match args.first().map(String::as_str) {
        Some("--help" | "-h" | "help") => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Some(verb) => verb,
        None => {
            eprint!("{USAGE}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    let mut options = FilterOptions::default();
    for arg in &args[1..] {
        match arg.as_str() {
            "--deny-userns" => options.deny_userns = true,
            other => {
                eprintln!("vpn-zone-seccomp: unknown option: {other}");
                return ExitCode::from(EXIT_USAGE);
            }
        }
    }

    match verb {
        "export" => export(options),
        "selftest" => run_selftest(options),
        other => {
            eprintln!("vpn-zone-seccomp: unknown command: {other}");
            eprint!("{USAGE}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

fn export(options: FilterOptions) -> ExitCode {
    let filter = match Filter::build(options) {
        Ok(filter) => filter,
        Err(e) => {
            eprintln!("vpn-zone-seccomp: cannot build the filter: {e}");
            return ExitCode::from(EXIT_ERROR);
        }
    };
    warn_about_unknown(&filter);

    let bpf = match filter.export_bpf() {
        Ok(bpf) if bpf.is_empty() => {
            // An empty program would be accepted by bwrap and would filter
            // nothing at all — refuse instead, the caller then starts the
            // sandbox without a filter and says so.
            eprintln!("vpn-zone-seccomp: libseccomp produced an empty program");
            return ExitCode::from(EXIT_ERROR);
        }
        Ok(bpf) => bpf,
        Err(e) => {
            eprintln!("vpn-zone-seccomp: cannot export the filter: {e}");
            return ExitCode::from(EXIT_ERROR);
        }
    };

    let mut stdout = io::stdout().lock();
    if let Err(e) = stdout.write_all(&bpf) {
        eprintln!("vpn-zone-seccomp: cannot write the program: {e}");
        return ExitCode::from(EXIT_ERROR);
    }
    if let Err(e) = stdout.flush() {
        eprintln!("vpn-zone-seccomp: cannot write the program: {e}");
        return ExitCode::from(EXIT_ERROR);
    }
    ExitCode::SUCCESS
}

fn run_selftest(options: FilterOptions) -> ExitCode {
    match Filter::build(options) {
        Ok(filter) => warn_about_unknown(&filter),
        Err(e) => {
            eprintln!("vpn-zone-seccomp: cannot build the filter: {e}");
            return ExitCode::from(EXIT_ERROR);
        }
    }

    let checks = match selftest(options) {
        Ok(checks) => checks,
        Err(e) => {
            eprintln!("vpn-zone-seccomp: cannot load the filter: {e}");
            return ExitCode::from(EXIT_ERROR);
        }
    };

    let mut failed = 0;
    for check in &checks {
        if check.ok {
            println!("ok   {} ({})", check.name, check.detail);
        } else {
            failed += 1;
            println!("FAIL {} ({})", check.name, check.detail);
        }
    }

    if failed > 0 {
        eprintln!(
            "vpn-zone-seccomp: {failed} of {} checks failed",
            checks.len()
        );
        return ExitCode::from(EXIT_CHECK_FAILED);
    }
    println!("all {} checks passed", checks.len());
    ExitCode::SUCCESS
}

/// A rule missing because this libseccomp does not know the syscall is worth a
/// word, but never a reason to fail: a partial filter still beats no filter.
fn warn_about_unknown(filter: &Filter) {
    let unknown = filter.unknown_syscalls();
    if !unknown.is_empty() {
        eprintln!("vpn-zone-seccomp: unknown to libseccomp, rules skipped: {unknown:?}");
    }
}
