//! `vpn-zone-core` — the helper commands the bash `vpn-zone` script delegates
//! to. Two of them used to be Python scripts in `module/` and one a C program
//! there; there is no Python and no C in this project any more.
//!
//! Argument parsing is done by hand, as in `vpn-zone-seccomp`: a handful of
//! verbs with fixed positional arguments do not need a CLI framework, and both
//! `profile-run` and `wl-sandbox` sit on the startup path of every program
//! launched into a zone.

use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

use vpn_zone::{desktop, profile, wl_sandbox, zone};

const USAGE: &str = "\
vpn-zone-core — helper commands of vpn-zones

Usage:
  vpn-zone-core zone-holder [--ip P] [--awg P] [--wg P] [--pasta P] <name>
        Bring the zone up and hold it: a user namespace with the double id
        mapping, a net+mount namespace with the tunnel in it, and pasta as the
        way out. Runs until killed, and the zone dies with it — that is the
        kill switch. This is the ExecStart of vpn-zone@<name>.service; the tool
        paths are substituted by Nix and default to a PATH lookup.

  vpn-zone-core profile-run <profiledir> <zone> <ephemeral 0|1> <regdir> -- cmd...
        Stack the container's overlay layers over the XDG directories, drop the
        ambient capabilities and run the command. Called from `vpn-zone run`,
        already inside the zone's namespaces. An empty <profiledir> means the
        main profile: no layers are stacked. With <ephemeral> = 1 the command
        is run as a child and the container is removed after the last program
        living in it is gone.

  vpn-zone-core sync <state_dir> <home> <runner> <picker>
        Regenerate the .desktop entries for the zones. <runner> and <picker>
        are the paths that end up in the generated Exec lines.

  vpn-zone-core wl-sandbox <app-id> -- cmd...
        Run the command on a Wayland socket of its own, registered with the
        compositor as a sandbox (wp_security_context_v1): no screen capture,
        no background clipboard reads, no input emulation, no list of other
        windows. Without the protocol — an older compositor, an X11 session —
        the command is run as it is, with a warning on stderr.

  vpn-zone-core --help

Exit codes:
  0    success
  1    the pass failed
  2    bad usage
  127  the program could not be started (profile-run, wl-sandbox)
  *    otherwise profile-run and wl-sandbox report the exit code of the
       program itself (128 + N if it was killed by signal N)
";

/// Bad command line.
const EXIT_USAGE: u8 = 2;

fn main() -> ExitCode {
    // `args_os`, not `args`: a launcher can hand a file name through a `%U`
    // field code, and file names are bytes. `std::env::args()` panics on
    // anything that is not UTF-8, which would turn "open this file" into a
    // crash.
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let verb = args.first().map(|a| a.to_string_lossy().into_owned());

    match verb.as_deref() {
        Some("--help" | "-h" | "help") => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some("zone-holder") => match zone::Args::parse(&args[1..]) {
            Ok(parsed) => ExitCode::from(zone::run(parsed)),
            Err(e) => {
                eprintln!("vpn-zone-core zone-holder: {e}");
                eprint!("{USAGE}");
                ExitCode::from(EXIT_USAGE)
            }
        },
        Some("profile-run") => match profile::Args::parse(&args[1..]) {
            Ok(parsed) => ExitCode::from(profile::run(parsed)),
            Err(e) => {
                eprintln!("vpn-zone-core profile-run: {e}");
                eprint!("{USAGE}");
                ExitCode::from(EXIT_USAGE)
            }
        },
        Some("wl-sandbox") => match wl_sandbox::Args::parse(&args[1..]) {
            Ok(parsed) => ExitCode::from(wl_sandbox::run(parsed)),
            Err(e) => {
                eprintln!("vpn-zone-core wl-sandbox: {e}");
                eprint!("{USAGE}");
                ExitCode::from(EXIT_USAGE)
            }
        },
        Some("sync") => {
            let rest = &args[1..];
            if rest.len() != 4 {
                eprintln!("vpn-zone-core sync: need <state_dir> <home> <runner> <picker>");
                eprint!("{USAGE}");
                return ExitCode::from(EXIT_USAGE);
            }
            ExitCode::from(desktop::sync(
                Path::new(&rest[0]),
                Path::new(&rest[1]),
                &rest[2].to_string_lossy(),
                &rest[3].to_string_lossy(),
            ))
        }
        Some(other) => {
            eprintln!("vpn-zone-core: unknown command: {other}");
            eprint!("{USAGE}");
            ExitCode::from(EXIT_USAGE)
        }
        None => {
            eprint!("{USAGE}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}
