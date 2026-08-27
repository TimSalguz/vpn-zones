# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Security
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
  address families, `setconf` stripping). Zones still run on the bash version.
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
