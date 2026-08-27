//! Core of vpn-zones: rootless network zones with VPN, data containers and
//! sandboxes (see `ROADMAP.md`).
//!
//! The working implementation is still the bash/Nix module in `module/`; this
//! crate is the Rust core it is being replaced with, one piece at a time, and
//! the bash version stays in charge until parity is proven. Two pieces exist so
//! far:
//!
//! * [`config`] — WireGuard/AmneziaWG config parsing, the behaviour of the
//!   `sed`/`grep` pipeline in `zoneInit` written down as code and tests
//!   (`docs/GOTCHAS.md` §4);
//! * [`seccomp`] — the syscall filter for the bwrap sandbox, the one thing that
//!   could not be done from bash at all.

pub mod config;
pub mod seccomp;
