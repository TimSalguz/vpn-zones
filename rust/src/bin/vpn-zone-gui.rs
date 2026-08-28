//! `vpn-zone-gui <add|remove|profile-add|profile-rm|settings|forget>` — the six
//! launcher entries of the project.
//!
//! Everything is in [`vpn_zone::gui`]. There is no wrapper for this one: the
//! `.desktop` files home-manager writes name the store path directly and carry
//! the manifest themselves —
//! `Exec=env VPN_ZONE_TOOLS=… …/vpn-zone-gui add`. They are regenerated on
//! every switch, so a store path in them cannot go stale, and the binary stays
//! out of `PATH`, where nothing would ever call it.

use std::process::ExitCode;

fn main() -> ExitCode {
    vpn_zone::gui::main()
}
