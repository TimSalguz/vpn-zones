//! Core of vpn-zones: rootless network zones with VPN, data containers and
//! sandboxes (see `ROADMAP.md`).
//!
//! The user-facing CLI is still the bash/Nix module in `module/`; this crate is
//! the Rust core it is being replaced with, one piece at a time, and the bash
//! version stays in charge of a piece until parity is proven. What is here:
//!
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
//! C program there and `fs_sandbox` was a two-hundred-line shell script; the
//! project has no Python and no C left. All of them are driven by the
//! `vpn-zone-core` binary, which the bash `vpn-zone` and the systemd unit call.

pub mod config;
pub mod desktop;
pub mod fs_sandbox;
pub mod profile;
pub mod seccomp;
pub mod sys;
pub mod wl_sandbox;
pub mod zone;
