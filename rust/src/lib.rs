//! Core of vpn-zones: rootless network zones with VPN, data containers and
//! sandboxes (see `ROADMAP.md`).
//!
//! The project used to be a Nix module full of shell; this crate is what it has
//! been replaced with, one piece at a time, and each piece stayed in shell until
//! parity was proven. What is left in `module/` is the packaging and three
//! two-line wrappers that point `VPN_ZONE_TOOLS` at the manifest. What is here:
//!
//! * [`cli`] — the `vpn-zone` command line itself: the zone verbs, the
//!   containers, the sandboxes, the settings and the garbage collection;
//! * [`picker`] — `vpn-zone-pick`, the dialog an intercepted launcher entry
//!   opens: which network, which container, and the three levels of memory
//!   behind both answers (`docs/GOTCHAS.md` §11);
//! * [`gui`] — `vpn-zone-gui`, the six launcher entries (add and remove a zone,
//!   create and remove a container, the settings, reset the pins), kdialog over
//!   the CLI;
//! * [`dialog`] — the shapes of `kdialog` and `notify-send` call those two make,
//!   and the traps of each;
//! * [`launch`] — `vpn-zone run`, from the delegation of a launch that comes
//!   from inside a zone to the `execvp` into `nsenter`
//!   (`docs/GOTCHAS.md` §1, §5, §7, §13);
//! * [`registry`] — the "who runs where" registry the launches keep under
//!   `flock`, read by the picker and by the throwaway containers
//!   (`docs/GOTCHAS.md` §5);
//! * [`tools`] — the manifest of absolute tool paths Nix hands the CLI in one
//!   environment variable (`docs/GOTCHAS.md` §12);
//! * [`zone`] — the life cycle of a zone: the user namespace with its double
//!   mapping, the net+mount namespace, pasta, the tunnel, DNS and the state
//!   mirror. This is what `vpn-zone@<name>.service` starts
//!   (`docs/GOTCHAS.md` §1–§4);
//! * [`config`] — WireGuard/AmneziaWG config parsing, the behaviour of the
//!   `sed`/`grep` pipeline the zones used to run, written down as code and
//!   tests (`docs/GOTCHAS.md` §4);
//! * [`fs_sandbox`] — the filesystem sandbox: bwrap, the permissions, the
//!   `/.flatpak-info` that switches toolkits over to the portals, the filtered
//!   session bus and the sandbox's own X server (`docs/GOTCHAS.md` §6, §8, §9);
//! * [`seccomp`] — the syscall filter [`fs_sandbox`] loads into that box, the
//!   one thing that could not be done from bash at all;
//! * [`profile`] — data containers: the overlayfs layers of a profile and the
//!   life cycle of a throwaway one (`docs/GOTCHAS.md` §5);
//! * [`desktop`] — the `.desktop` generator behind `vpn-zone sync`
//!   (`docs/GOTCHAS.md` §10);
//! * [`wl_sandbox`] — the restricted Wayland socket a program is put on
//!   (`wp_security_context_v1`, `docs/GOTCHAS.md` §7);
//! * [`sys`] — the handful of syscalls more than one of them needs.
//!
//! `profile` and `desktop` were Python scripts in `module/`, `wl_sandbox` was a
//! C program there, `fs_sandbox` a two-hundred-line shell script, `cli` the
//! seven-hundred-line `vpn-zone` one, and `picker` and `gui` the last shell in
//! the project: there is no Python, no C and no logic in shell left anywhere.
//! Five binaries drive all of it: `vpn-zone` (the CLI), `vpn-zone-pick` (the
//! picker), `vpn-zone-gui` (the launcher entries), `vpn-zone-core` (what the CLI
//! and the systemd unit delegate to) and `vpn-zone-seccomp` (the filter, and its
//! own selftest).

pub mod cli;
pub mod completion;
pub mod config;
pub mod desktop;
pub mod dialog;
pub mod fs_sandbox;
pub mod gui;
pub mod launch;
pub mod picker;
pub mod profile;
pub mod registry;
pub mod seccomp;
pub mod sys;
pub mod tools;
pub mod wl_sandbox;
pub mod zone;
