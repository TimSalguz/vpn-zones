//! `vpn-zone-core` — the helper commands the bash `vpn-zone` script delegates
//! to. Both of them used to be Python scripts in `module/`; there is no Python
//! in this project any more.
//!
//! Argument parsing is done by hand, as in `vpn-zone-seccomp`: two verbs with
//! fixed positional arguments do not need a CLI framework, and `profile-run`
//! sits on the startup path of every program launched into a container.

use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

use vpn_zone::{desktop, profile};

const USAGE: &str = "\
vpn-zone-core — helper commands of vpn-zones

Usage:
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

  vpn-zone-core --help

Exit codes:
  0    success
  1    the pass failed
  2    bad usage
  127  the program could not be started (profile-run)
  *    otherwise profile-run reports the exit code of the program itself
       (128 + N if it was killed by signal N)
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
        Some("profile-run") => match profile::Args::parse(&args[1..]) {
            Ok(parsed) => ExitCode::from(profile::run(parsed)),
            Err(e) => {
                eprintln!("vpn-zone-core profile-run: {e}");
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
