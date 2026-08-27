# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Changed
- A zone is now **two** network namespaces instead of one, the gateway layout of
  `docs/LEAK-MODEL.md`. Connectivity lives in the uplink namespace — pasta
  attaches there, and the tunnel's UDP socket stays there — while programs run in
  an app namespace that has loopback and the tunnel and nothing else. The
  interface is created in the uplink (a WireGuard socket stays in the namespace
  the interface was *born* in, whatever namespace it is later moved to), handed
  down with `ip link set awg0 netns <pid>` and configured there, because netlink
  works on the current namespace. The contract towards the outside is unchanged:
  `zone.pid` still names the app namespace, which is what `vpn-zone run`/`status`
  `nsenter` into, and `ready`, `status`, `resolv.conf`, `config.conf` and the
  offline marker keep their meaning. New file in the zone directory:
  `uplink.pid`. `vpn-zone gc` needs no change — it recognises a stray pasta by
  the `/proc/<pid>/ns/net` in its command line, and that pid is now the uplink's.
  An offline zone is unaffected: still one namespace with loopback and no pasta.
- Endpoints are resolved before either namespace exists, and the text handed to
  `setconf` carries literal addresses. `wg setconf` resolves `Endpoint` itself
  and retries DNS for about ninety seconds before failing — in a namespace that
  has no network until the tunnel it is configuring is up, a hostname would hang
  the zone and then fail anyway. A name that cannot be resolved is now a loud
  error instead of a zone that comes up without a route. `WgConfig` grew
  `resolve_endpoints` for this (v6 gets brackets only when a port follows), with
  unit tests; the rest of the parser API is untouched.
- The life cycle of a zone is Rust now. The two shell scripts of
  `module/default.nix` — `zoneHolder` (the user namespace with its double id
  mapping, and pasta) and `zoneInit` (tunnel, routes, IPv6, DNS, the state
  mirror) — are gone; the unit starts `vpn-zone-core zone-holder <name>`
  instead, with the tool paths substituted by Nix
  (`--ip/--awg/--wg/--pasta`). Parity is deliberate and the architecture is
  unchanged: the same one-namespace model, the same pasta arguments, the same
  files in the zone directory (`zone.pid`, `ready`, `status`, `resolv.conf`),
  the same `KillMode=control-group` kill switch. What changed underneath is
  that the config is now read by the tested parser of `rust/src/config.rs`
  instead of a `sed`/`grep` pipeline, that `ip`/`awg`/`wg`/`pasta` are exec'd
  directly instead of being interpolated into a shell, that the id mapping is
  done with an explicit fork plus `newuidmap`/`newgidmap` instead of
  `unshare(1)`, and that the holder passes TERM/INT on to the zone so a zone
  cannot outlive its holder even without systemd. Two small deliberate
  differences: an empty `wg show latest-handshakes` is now reported as "no
  handshake" (the old `awk` pipeline reported success on empty input), and the
  stripped config handed to `setconf` is written with mode 0600 because it
  carries the private key. The bash `vpn-zone` CLI, the picker and the GUI
  wrappers are untouched.
- C is gone: `wl-sandbox` is now a subcommand of `vpn-zone-core`
  (`vpn-zone-core wl-sandbox <app-id> -- cmd...`) instead of a C program built
  from `module/wl-sandbox.c` with `wayland-scanner`. The behaviour it
  implements is unchanged — a socket of its own registered with the compositor
  through `wp_security_context_v1`, the close-fd switch held open for the
  lifetime of the program, `WAYLAND_SOCKET` unset so the inherited descriptor
  cannot override `WAYLAND_DISPLAY`, and a loud fallback to an unrestricted
  launch whenever any of that fails. Two deliberate differences: the command
  must now be separated by `--` (the C version took it without a separator,
  and `vpn-zone run` was updated accordingly), and a program killed by a
  signal is reported as `128 + signal` instead of a flat `1`, matching
  `profile-run`. No libwayland is linked in: the wire protocol is spoken from
  Rust, so the derivation needs no Wayland `buildInputs`.
- Python is gone: both helper scripts are now subcommands of the Rust
  `vpn-zone-core` binary — `profile-run` (the overlayfs layers of a data
  container, the ambient-capability drop and the life cycle of a throwaway
  one) and `sync` (the `.desktop` generator). Behaviour is unchanged, every
  quirk of `docs/GOTCHAS.md` §5 and §10 is now covered by unit tests, and the
  bash side keeps calling them with the same arguments. The project no longer
  depends on `python3` at all.

### Security
- A leak out of a zone is now impossible by construction rather than forbidden
  by a rule. The namespace programs run in has exactly two interfaces, loopback
  and the tunnel, so:
  - the host's LAN is not reachable from a zone at all — there is no interface
    to reach it through, and no rule to get wrong;
  - any protocol family is fail-closed for the same reason, including families
    nobody has invented yet. The IPv6 patch of M0 is gone with the hole it
    plugged: the family is no longer switched off through a sysctl, v6 either
    goes into the tunnel or is left without a default route;
  - the /32 (or /128) route to the VPN server has disappeared from the zone
    together with the interface it pointed through. The encrypted packets are
    born in the uplink namespace and leave by *its* default route, so the
    programs never see the endpoint, and the smoke test now asserts the opposite
    of what it used to: inside the zone, the route to the endpoint must go
    through the tunnel;
  - the kill switch is topology now. Programs keep the app namespace alive after
    the holder is gone, but nothing keeps the *uplink* namespace alive; the
    kernel destroys it, and WireGuard reacts to its creating namespace going
    away by turning the carrier off and closing the sockets. The interface stays
    and drops every packet.
  Unchanged, and worth repeating: this closes the network. Unix sockets of the
  compositor, the bus and X11 are not affected by topology and stay the business
  of the wl-sandbox / fs-sandbox / dbus-proxy layers, and the nsncd leak is still
  closed by hiding its socket under a tmpfs — a socket has no route to remove.
- IPv6 no longer bypasses the tunnel. Previously only the IPv4 default route
  went into the tunnel while pasta still provided the zone with full IPv6
  connectivity to the host — all IPv6 traffic of zone apps went around the
  VPN whenever the host had IPv6. Now: if the config has an IPv6 `Address`,
  the v6 default route goes through the tunnel too; if the endpoint itself is
  IPv6-only, the v6 default is replaced with `unreachable` (only the /128 to
  the server stays); otherwise IPv6 is disabled inside the zone entirely
  (per-netns sysctl, the host is untouched). Fail-closed in every branch.
- Configs without `DNS=` no longer silently keep the host resolv.conf, whose
  local resolver is unreachable through the tunnel (names just stopped
  resolving). The zone now gets public resolvers (1.1.1.1, 9.9.9.9) reached
  via the tunnel, with a note in the zone log.

### Added
- Seccomp filter in the filesystem sandbox. `vpn-fs-sandbox` now compiles a BPF
  program with libseccomp and hands it to `bwrap --seccomp`: terminal injection
  (`ioctl` `TIOCSTI`/`TIOCLINUX`), `ptrace`, the keyring calls, `syslog`,
  `perf_event_open`, `acct`, `quotactl`, `uselib`, the NUMA calls and any
  `personality` other than `PER_LINUX` are refused with `EPERM`, while the new
  mount API and `clone3` answer `ENOSYS` so that libc takes its older path.
  Nested user namespaces are deliberately *not* blocked: without zypak or a
  setuid `chrome-sandbox`, Chromium and Electron applications build their own
  and refuse to start otherwise (`vpn-zone-seccomp export --deny-userns` for
  programs that do not need theirs). If the filter cannot be built the sandbox
  starts without it and says so on stderr.
- A Rust crate in `rust/` — the first piece of the Rust core (ROADMAP M1/M2):
  the filter generator `vpn-zone-seccomp` (`export`, `selftest`) and a
  WireGuard/AmneziaWG config parser with unit tests for every quirk in
  `docs/GOTCHAS.md` §4 (CRLF, empty `I1`–`I5`, the three endpoint shapes,
  address families, `setconf` stripping) — the parser the zones now run on
  (see the zone life cycle above).
- Fallback to the in-tree `wireguard` kernel module and `wg(8)` when
  `amneziawg` is unavailable and the config has no obfuscation parameters
  (Jc/Jmin/Jmax/S1/S2/H1–H4/I1–I5). Configs *with* obfuscation fail loudly
  instead of silently degrading.
- IPv6 endpoints: `[addr]:port` literals and v6-only hostnames now work — the
  route to the server is added via the host's v6 default route. Previously the
  bracket form was mis-parsed on the last colon and hostname resolution was
  IPv4-only.
- All `Address` entries are now applied, both families — previously only the
  first one; a v6-only `Address` used to kill the zone on `ip -4 addr add`.

### Fixed
- The IPv6 fallback route was a syntax error and had never worked:
  `ip -6 route replace default unreachable` puts the route type after the
  prefix, which iproute2 rejects with "Command line is not complete" (exit 255).
  The type goes first — `replace unreachable default`. It went unnoticed because
  the `disable_ipv6` sysctl branch above it usually won; the sysctl is gone now
  and this is the branch that runs.
- Launch-registry updates are serialized with `flock`: two concurrent launches
  of the same app could lose each other's records (read → rewrite → rename
  without locking), and `gc` could erase a record of an app that had just
  started.
- Registry entries carrying a container/sandbox selector no longer confuse the
  "already running in another network" check, the profile list, and the
  pinned-list dialog: `read -r pid z` was gluing the selector onto the zone
  name, so "same zone + sandbox" looked like a different network.
- `gc` removes abandoned throwaway containers in `/tmp` by checking for live
  PIDs in the registry instead of the registry directory's existence — after a
  hard kill the directory stayed forever and so did the garbage.
- `vpn-zone-pick`: the `fsflag` array was used before initialization on the
  "join a running temporary container" path (it only worked thanks to
  bash ≥ 4.4 treating an empty `"${arr[@]}"` as non-fatal under `set -u`).
