//! Core of cellward (formerly vpn-zones): rootless network zones with VPN, data
//! containers and sandboxes (see `ROADMAP.md`).
//!
//! The project used to be a Nix module full of shell; this crate is what it has
//! been replaced with, one piece at a time, and each piece stayed in shell until
//! parity was proven. What is left in `module/` is the packaging and three
//! two-line wrappers that point `VPN_ZONE_TOOLS` at the manifest. What is here:
//!
//! * [`cli`] — the `cellward` command line itself (`cw`, the old `vpn-zone`),
//!   the crate's `vpn-zone` binary: the zone verbs, the
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
//! * [`container`] — containers as identities: the network a data container or
//!   a named sandbox is bound to, the programs assigned to it, and where each
//!   of those settings comes from (`docs/CONTAINERS.md`);
//! * [`config`] — WireGuard/AmneziaWG config parsing, the behaviour of the
//!   `sed`/`grep` pipeline the zones used to run, written down as code and
//!   tests (`docs/GOTCHAS.md` §4);
//! * [`openconnect`] — the second kind of zone: a userspace client
//!   (Cisco AnyConnect/ocserv, and through `--protocol` GlobalProtect and
//!   Pulse) in the uplink namespace, whose tun moves down into the app
//!   namespace. The `[OpenConnect]` config section, the vpnc-script contract as
//!   a pure function, and `vpn-zone-core oc-script` (`docs/GOTCHAS.md` §2a);
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
//!   (`wp_security_context_v1`, `docs/GOTCHAS.md` §7), and [`wl_proxy`], the
//!   confined process that stands on that socket between the program and the
//!   compositor (`docs/WINDOW-FRAME.md` §8) and draws the zone's frame
//!   ([`wl_frame`], its title's text [`wl_title`]);
//! * [`trust`] — extra root certificates trusted by one container only: the
//!   bundle bind, the environment and the NSS databases (`docs/CERTIFICATES.md`);
//! * [`status`] — the machine-readable state (`vpn-zone status --json`), with
//!   the origin of every settable value;
//! * [`system`] — system zones (ROADMAP M10, `docs/SYSTEM.md`): the same zone
//!   held by systemd from boot, for services and NixOS containers —
//!   `vpn-zone-core system-zone`, one of the two parts of the crate that run
//!   as root;
//! * [`console`] — the TTY console: log in on a text console and there is a
//!   network, through a system zone, with one key for everything else;
//! * [`egress`] — the host without a network of its own (M10 stage 5): an
//!   nftables policy that lets a user's program out only through a zone;
//! * [`sysrun`] — the other: `vpn-zone-sys`, a user's console program in a
//!   system zone, entered by a per-launch service and run as the user
//!   (M10 stage 4);
//! * [`sockets`] — the unix sockets a zone can reach, walked from inside it by
//!   `vpn-zone doctor` and told apart: the zone's own, the system's, a helper
//!   outside (`docs/LEAK-MODEL.md` §15, §17);
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

pub mod broker;
pub mod build;
pub mod bus_filter;
pub mod cli;
pub mod completion;
pub mod config;
pub mod console;
pub mod container;
pub mod dbus_wire;
pub mod desktop;
pub mod device_guard;
pub mod devices;
pub mod dialog;
pub mod dnsfwd;
pub mod doctor;
pub mod egress;
pub mod focus;
pub mod frame;
pub mod fs_sandbox;
pub mod grants;
pub mod gui;
pub mod hermetic;
pub mod home_layer;
pub mod hostif;
pub mod journal;
pub mod json;
pub mod kill;
pub mod launch;
pub mod links;
pub mod microphone;
pub mod openconnect;
pub mod origin;
pub mod picker;
pub mod profile;
pub mod pulse_filter;
pub mod pw_context;
pub mod registry;
pub mod screencast;
pub mod seccomp;
pub mod sockets;
pub mod status;
pub mod sys;
pub mod sysrun;
pub mod system;
pub mod sysuplink;
pub mod timings;
pub mod tools;
pub mod trust;
pub mod watch;
pub mod window;
pub mod wl_frame;
pub mod wl_proxy;
pub mod wl_sandbox;
pub mod wl_title;
pub mod x11;
pub mod zone;
