//! Core of vpn-zones: rootless network zones with VPN, data containers and
//! sandboxes (see `ROADMAP.md`).
//!
//! The working implementation is still the bash/Nix module in `module/`; this
//! crate is the Rust core it is being replaced with, one piece at a time, and
//! the bash version stays in charge until parity is proven. Four pieces exist
//! so far:
//!
//! * [`config`] — WireGuard/AmneziaWG config parsing, the behaviour of the
//!   `sed`/`grep` pipeline in `zoneInit` written down as code and tests
//!   (`docs/GOTCHAS.md` §4). Not used by the zones yet;
//! * [`seccomp`] — the syscall filter for the bwrap sandbox, the one thing that
//!   could not be done from bash at all;
//! * [`profile`] — data containers: the overlayfs layers of a profile and the
//!   life cycle of a throwaway one (`docs/GOTCHAS.md` §5);
//! * [`desktop`] — the `.desktop` generator behind `vpn-zone sync`
//!   (`docs/GOTCHAS.md` §10).
//!
//! The last two were Python scripts in `module/` until they moved here; the
//! project has no Python left. Both are driven by the `vpn-zone-core` binary,
//! which the bash `vpn-zone` calls.

pub mod config;
pub mod desktop;
pub mod profile;
pub mod seccomp;
