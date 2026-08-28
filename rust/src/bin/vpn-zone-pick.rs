//! `vpn-zone-pick` — the "which network?" dialog an intercepted launcher entry
//! opens instead of the program.
//!
//! Everything is in [`vpn_zone::picker`]; this file exists so that the decision
//! machine behind it can be unit-tested as a library. Like the CLI it needs the
//! tool manifest: the two-line wrapper in `home.packages` points
//! `VPN_ZONE_TOOLS` at it and execs this (see [`vpn_zone::tools`]). The wrapper
//! is also what keeps the shortcuts stable — they name the PROFILE path, not the
//! store one (`docs/GOTCHAS.md` §10).

use std::process::ExitCode;

fn main() -> ExitCode {
    vpn_zone::picker::main()
}
