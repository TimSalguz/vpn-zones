//! `vpn-zone` — the command line the user (and the picker, and the GUI
//! wrappers, and the generated `.desktop` files) call.
//!
//! Everything is in [`vpn_zone::cli`]; this file exists so that the logic can be
//! unit-tested as a library. The one thing that has to be true before it runs is
//! the tool manifest: Nix writes the absolute paths into a small JSON file and
//! the two-line wrapper in `home.packages` points `VPN_ZONE_TOOLS` at it
//! (see [`vpn_zone::tools`]).

use std::process::ExitCode;

fn main() -> ExitCode {
    vpn_zone::cli::main()
}
