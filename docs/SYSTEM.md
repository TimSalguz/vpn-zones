# The system tier (M10): zones held by the system

Related: [ARCHITECTURE.md](ARCHITECTURE.md) §3, [LEAK-MODEL.md](LEAK-MODEL.md)

**Status, 2026-09-24.** Stages 1–5 are in `main`, green in CI: system zones, services and
NixOS containers in them (`tests/vm-system.nix`), a user's console program in a system zone
and the TTY console (§7, §7a), the host egress policy with `strict` and the host's own
services through a zone (§9, §9b, §9c — `tests/vm-host.nix`), a user zone through a system
zone (§7b — `tests/vm-bridge.nix`), a zone through one interface (§4a —
`tests/vm-uplink.nix`) and the off switch (§9a).

## 1. What it is

A system zone is the same zone as a user one — a namespace with `lo` and a tunnel, the
tunnel created outside and moved in — held by systemd from boot instead of by a session.
Its uplink is the host's network, so there is no pasta and no user namespace: root creates
the interface in the host's namespace and moves it into `/run/netns/vz-<name>`.

What joins it: system services (`NetworkNamespacePath=`) and NixOS containers
(`containers.<name>.networkNamespace`). A user's programs join it through `vpn-zone-sys`
(§7) or through a user zone of their own on top of it (§7b).

The module is `nixosModules.default`. Its single entry, `programs.cellward.enable` (README,
Installation), turns on what the user tier needs of the system — kernel modules, the
PipeWire policy, the home-manager module for every user — but not this tier:
`services.cellward.system.enable` does that, and stays an explicit choice. (The options were
`services.vpn-zones.*`; the old names still work, with a warning.)

Stages 1–3 carry WireGuard/AmneziaWG zones only. OpenConnect and host-interface configs are
refused with a message; they need the uplink to be a namespace of its own and come later.

### 1a. Plain zones

`zones.<name>.kind = "plain"`: the same namespace, no tunnel. pasta attaches to it and
carries its connections out through the host's own network — not encrypted by the zone, but
still a namespace of its own: `lo` and pasta's interface (named `awg0`, so the second echelon
applies unchanged), its own resolv.conf (the public resolvers, as for a config without
`DNS =`), and nothing of the host's — pasta's port forwarding in both directions and its
mapping of the gateway to the host's loopback are shut (`PASTA_CLOSED`, the same as user
zones). pasta runs as the system user `vpn-zones-plain`, not as root and not as its default
`nobody`: the host's egress policy (§9) lets system users out and knows this one by name. It
keeps exactly two capabilities, CAP_SYS_ADMIN and CAP_NET_ADMIN, as ambient ones set by the
holder before exec — what it needs to enter a namespace the host's user namespace owns and
configure its interface. Not `--runas`: pasta changes its uid first, which clears every
capability, and then cannot enter the namespace (the VM test's "Couldn't switch to pasta
namespaces").

What it is for: the TTY console's second step when the VPN cannot come up (ARCHITECTURE §4),
and the way a program goes out directly once the host has no network of its own —
`vpn-zone-sys <plain zone> -- <command>`.

## 2. Names and files

- Zone name: `[a-z0-9][a-z0-9-]{0,11}`, not `unconfined`, `direct` or `offline`. Twelve,
  because the host-side interface is `vz-<name>` and interface names stop at 15.
- Namespace: `vz-<name>`, i.e. `/run/netns/vz-<name>`. The prefix keeps the namespaces
  apart from anybody else's `ip netns add`.
- Interface: created as `vz-<name>` in the host's namespace (so it can't collide with an
  `awg0` somebody else is creating there at the same moment), renamed to `awg0` once inside.
  Inside, a system zone looks exactly like a user zone's app namespace, and the same
  ruleset and the same smoke assertion apply unchanged.

| Path | Mode | What |
|---|---|---|
| `/var/lib/vpn-zones/system/<name>/config.conf` | 0600 root, dir 0755 | the config, unless `configFile` points elsewhere |
| `/run/vpn-zones/system/<name>/` | 2750 root:vpn-zones | the zone's run directory |
| `…/setconf.conf` | 0600 root | the stripped config `setconf` reads (private key inside) |
| `…/ready` | 0640 | the zone is up |
| `…/status` | 0640 root:vpn-zones | `awg show awg0`, every 5 s; no private key in it |
| `/etc/netns/vz-<name>/resolv.conf` | 0644 | the zone's resolvers; rewritten **in place** because consumers bind it |
| `/etc/vpn-zones/system-zones` | from the module | declared zone names, one per line, for `status --json` |

Members of the group `vpn-zones` can read the status; that is what makes
`cellward status --json` report a system zone's tunnel without root.

## 2a. One VPN, added once

`vpn-zone-sys --add <name> <config.conf>` (or `--plain`): the config goes to the
system-zone service (§7) over its socket, as one datagram; root checks it — a parseable
WireGuard/AmneziaWG config, a free name or a zone of the asking user's — writes
`/var/lib/vpn-zones/system/<name>/config.conf` (0600), `kind` and `users` (the one who added
it), and starts the zone. No rebuild, no root for the user, nothing in the repository.

**One config is one tunnel.** The same private key in two tunnels makes the server see two
devices with one key, and they knock each other off. So before writing anything root compares
the key with every system zone's: a match answers `SAME <zone>` — "this VPN already is zone
X, run your programs in it" — and nothing is created. Everything that should use that VPN —
services, NixOS containers, the TTY console, a user's programs — goes into that one zone, at
the same time, through one tunnel.

`vpn-zone-sys --up <name>` starts a zone for one of its users; the TTY console uses it.

**Who may add** (review): `services.cellward.system.users` (the module writes them to
`/etc/vpn-zones/system-adders`), and nobody else — a zone's own `users` may use it, not add
zones. A declared zone that the host's own services go through (`host.*`, `services`,
`containers` — marked `carries`) never has its config replaced by a request: whoever sets its
tunnel answers for the host's names, clock and services. The socket takes at most 16
connections per user (`MaxConnectionsPerSource`), so a client that says nothing holds its own
user's share and not the others' — a count bounds it, not a clock (2026-09-26; a request had
to come within 5 s before, and a loaded machine could miss that). Not a wall against a
member of the group who means it: the count is per uid, and `newuidmap` gives a user several
(review 2026-09-24) — a way to keep the service busy, not a way into anything.

## 3. Units

- `vpn-zone-system-ns@<name>.service` — `vpn-zone-core system-zone ns-up <name>`:
  the namespace, `lo` up, the app ruleset (second echelon) loaded before anything else, an
  empty resolv.conf. `Type=oneshot`, `RemainAfterExit`, **`restartIfChanged = false`**: the
  namespace must survive switches, because every consumer bound to it would otherwise be cut
  off or restarted by every update of this package. `ExecStop` = `ns-down`.
- `vpn-zone-system@<name>.service` — `vpn-zone-core system-zone up <name>`, the holder.
  `Type=notify`, `BindsTo=` and `After=` the namespace unit, `After=network-online.target`;
  its start is bounded by systemd's `TimeoutStartSec` alone (`services.cellward.system.
  startTimeout`, systemd's default unless set; `infinity` — as long as it takes).
  Sets the zone up (§4), says `READY=1` — so whatever is ordered after it starts with the
  tunnel and the zone's resolv.conf in place — then mirrors the status until stopped. `ExecStopPost` = `down`: the tunnel
  interface is deleted, the namespace stays with `lo` alone. `Restart=on-failure` after
  10 s: at boot the endpoint may not resolve yet.

Both are **templates**, and a zone is an instance: a zone can be added on the spot
(`vpn-zone-sys --add`, §2a) with no rebuild, and a declared one differs only by its settings.
The holder reads those itself — `kind`, `config`, `users`, `system-bus` — from
`/etc/vpn-zones/system-zones.d/<name>/` for a declared zone (written by the module) and from
`/var/lib/vpn-zones/system/<name>/` for one added on the spot. Nix is stronger, as with user
zones: a declared zone takes nothing from the local directory but its `config.conf`. Declared
zones with `autoStart` are wanted by `multi-user.target`.

Consumers bind to the **namespace** unit and only order after the holder: a tunnel going
down leaves them running with no way out (fail-closed, and downloads resume later); the
namespace going away stops them, because a process in a deleted namespace is cut off for
good.

## 4. `up`, step by step

1. Read the config (`--config P`, else the state directory), drop `\r`, parse with the same
   `config.rs`. OpenConnect or host-interface → refuse. Empty keys dropped and named, as
   in a user zone.
2. Resolve every endpoint **here, in the host's network**, and write literal addresses into
   the stripped config (`setconf.conf`, 0600). Unresolvable → fail, and systemd retries.
3. Delete leftovers: `vz-<name>` in the host's namespace, `awg0` in the zone's.
4. `ip link add vz-<name> type amneziawg`, falling back to `wireguard` for a config without
   obfuscation (the same choice as a user zone's `create_tunnel`).
5. `ip link set vz-<name> netns vz-<name>`; inside: rename to `awg0`.
6. `ip netns exec vz-<name> awg setconf awg0 setconf.conf` — the UDP socket stays in the
   host's namespace, where the interface was created.
7. Addresses of both families, MTU, up; default route into `awg0`; IPv6 into the tunnel or
   an unreachable default (`v6_plan`, shared with user zones).
8. resolv.conf from `DNS =` (or the public resolvers through the tunnel, as a user zone
   does), written in place.
9. `ready` and `READY=1` to systemd; after 4 s the handshake is looked at and said in the
   journal; the status mirror runs until the unit stops.

## 4a. Through one interface of the host

`services.cellward.system.zones.<zone>.uplink = "enp4s0";` — two providers, a modem next to
the wired network: each zone goes out by the interface it is given, and by nothing else.

- **A tunnel zone gets an uplink of its own.** Without `uplink` the host's namespace is the
  uplink: the tunnel is created there and its encrypted socket leaves by the host's routes.
  With it, `vzu-<zone>` is made first, with pasta in front of it — as the plain zones'
  user with the two namespace capabilities, like a plain zone's pasta — bound to the
  interface (`--outbound-if4/-if6`, i.e. `SO_BINDTODEVICE`), with addresses of its own (a
  second interface often has no default route; the sockets are bound to it anyway). The
  tunnel is born in `vzu-<zone>`, so its socket stays there, behind pasta, and moves on into
  the zone as `awg0` as before. This is a user zone's shape, held by root.
- **The uplink's filter** is a user zone's: the tunnel's packets to the endpoints, and
  nothing else (`zone::uplink_ruleset`). The endpoints are resolved in the host's network
  first, as always.
- **Out by it or not at all.** The interface down, gone, or without a route to the endpoint:
  no handshake, the zone has lo and a silent `awg0` — never another route (the VM test gives
  a zone the wrong interface on purpose and checks the server never hears from it). pasta
  dying fails the unit, which is started again (`Restart=on-failure`); the unit stopping
  takes pasta and `vzu-<zone>` away, and with them the tunnel's socket.
- **A plain zone** with `uplink` has its own pasta bound to the interface in the same way.
- **IPv6** by the interface when it has a global address and a default route through it
  (`hostif::ipv6_usable`), otherwise none (`-4`), exactly as for a host-interface user zone.
- **The egress policy** sees pasta's sockets, owned by `vpn-zones-plain`: let out in
  `enforce` (a system user) and in `strict` (named in the allowances). The tunnel's mark
  (§9) plays no part here.
- `status --json` says it: `system_networks[].uplink`, the interface or `null`.

## 5. Services in a system zone (stage 2)

`services.cellward.system.services.<unit> = "<zone>";` attaches the unit to the zone. The
unit's own definition is left alone: a systemd generator (`vpn-zones-generator`, a few lines
of shell with absolute store paths, none of our binaries) links a drop-in
`<unit>.service.d/50-vpn-zones.conf` into `/run` at boot and at every `daemon-reload`. The
switch (§9a) sets a flag, reloads, and the drop-ins are not there: the unit is back on the
host's network with no rebuild. The drop-in sets:

- `NetworkNamespacePath=/run/netns/vz-<zone>`;
- `BindReadOnlyPaths=/etc/netns/vz-<zone>/resolv.conf:/etc/resolv.conf` — without the `-`:
  no resolv.conf, and the unit fails instead of resolving through the host;
- `InaccessiblePaths=-/run/nscd -/run/systemd/resolve/io.systemd.Resolve` — both are unix
  sockets and cross namespaces: glibc asks nscd first, nss-resolve asks resolved over
  varlink, and either would resolve names through the host around the tunnel. The `-`
  because a host may run neither;
- with `systemBus = false` (the default): `InaccessiblePaths=-/run/dbus/system_bus_socket` —
  resolved's `org.freedesktop.resolve1` answers name lookups over the system bus too;
- `BindReadOnlyPaths=/etc/netns/vz-<zone>/nsswitch.conf:/etc/nsswitch.conf` — the host's
  file with `hosts: files dns`, written by `ns-up`: no NSS module but the plain resolver is
  ever asked for a name, which is the insurance a user zone has too (`zone_nsswitch`);
- `InaccessiblePaths=-/run/avahi-daemon` as well: nss-mdns would put a `.local` name onto the
  host's LAN;
- `bindsTo`/`after` the namespace unit, `wants`/`after` the holder.

The unit is still the person's; only its network changes.

The generator runs before local file systems are mounted. With `/var` on a file system of
its own it cannot see the switch's flag at boot and attaches the units anyway; the zones
themselves check the flag once `/var` is there and stay down, so the attached units stay
down with them (`BindsTo` a unit skipped by its condition) — closed, never leaking — until
`systemctl daemon-reload` runs the generator again. NixOS containers stay attached statically
(`container@<c>` has its network set by its own module) and under the switch stay stopped
with their zones.

## 6. NixOS containers in a system zone (stage 3)

`services.cellward.system.containers.<container> = "<zone>";` sets on
`containers.<container>`:

- the network: **not** `containers.<container>.networkNamespace`. nspawn joins a network
  namespace from inside the container's new user namespace, and the zone's belongs to the
  host's — `Failed to join network namespace: Operation not permitted` under
  `privateUsers = "pick"` (found by `tests/vm-system.nix`). Instead systemd enters the zone
  before nspawn runs — `NetworkNamespacePath=/run/netns/vz-<zone>` on `container@<container>`
  — and nspawn, given no network flags, shares the network it was started in. An assertion
  keeps `privateNetwork`, `networkNamespace`, `interfaces`, `macvlans` and `extraVeths`
  unset;
- `privateUsers = mkDefault "pick"`: the container's root has no capability in the user
  namespace that owns the zone's network namespace (the host's), so it can't add a route or
  an interface. An assertion refuses `"no"` and `"identity"` for a container in a zone, and
  `enableTun` or `CAP_NET_ADMIN` in `additionalCapabilities`;
- `extraFlags`:
  - `--resolv-conf=off` and `--bind-ro=/etc/netns/vz-<zone>/resolv.conf:/etc/resolv.conf`:
    nixpkgs' start script copies the host's resolv.conf into every container root, and the
    zone's file goes over it. The container runs its own nscd in its own `/run`, so the
    host's sockets aren't there;
  - `--inaccessible=/nix/var/nix/daemon-socket`: nixpkgs binds the **host's** Nix daemon
    socket into every container (conditioned on the host's daemon, not the container's), and
    any user there can ask the daemon for a fixed-output derivation — a download from any
    URL, made by the host in the host's network. This is a channel of every NixOS container,
    not only ours;
- `systemd.services."container@<container>"`: `NetworkNamespacePath`, `bindsTo`/`after`
  the namespace unit, `wants`/`after` the holder.

## 7. A user's program in a system zone (stage 4)

`vpn-zone-sys <zone> [--] <command>`, for the users listed in
`services.cellward.system.zones.<zone>.users`. Console programs (the use the TTY console of
ARCHITECTURE §4 needs); graphical ones go through a user zone over the system zone (§7b),
which has the session sealing user zones have.

A system zone's namespace belongs to the host's user namespace; entering it takes
`CAP_SYS_ADMIN` there, which no program of a user has. So a small service does the entering
(`rust/src/sysrun.rs`):

- **The socket** `/run/vpn-zones/sysrun.sock`, `SOCK_SEQPACKET`, `0660 root:vpn-zones`,
  `Accept=yes`: **one unit per launch** (`vpn-zone-sysrun@…`), so every launch is visible in
  `systemctl`, stops with its unit, and nothing it leaves behind outlives it. The group gets
  the zones' users (`users.groups.vpn-zones.members`); the per-zone list is checked by the
  service itself.
- **Who asks** comes from the kernel (`SO_PEERCRED`), never from the request. Root is
  refused (it has `ip netns exec`, and root in the zone's namespace could route around the
  tunnel).
- **What root does:** enters the zone's network namespace, makes a mount namespace of its
  own — the host's resolvers hidden (the same list as a user zone: nscd, resolved, avahi),
  the zone's resolv.conf and nsswitch.conf bound in, the system bus hidden unless
  `systemBus`, an empty `/run/user/<uid>` over the session's sockets — then drops to the
  user's groups, gid and uid and sets `NO_NEW_PRIVS`: `sudo` inside would be root in the
  zone's namespace. Last, a user namespace of the command's own, the user mapped onto
  itself: from the host's one, `/proc/<pid>/root` of any process of the session would lead
  around the empty `/run/user/<uid>` to the sockets it hides (LEAK-MODEL §16).
- **What root does not do:** interpret the request. The command, its directory and its
  environment are applied after the privileges are gone, as the user; the zone's name is
  checked like any zone name before it becomes a path.
- **The terminal** is the client's: it makes a pty, sends only the slave, and relays. The
  command gets the slave as its controlling terminal, so Ctrl-C, job control and the window
  size work without a signal passing through root. Without a terminal, the client's 0, 1 and
  2 are passed. The client gone — the end of the stream or a reset, not a wait that timed
  out — the command gets SIGHUP and SIGTERM, and SIGKILL after `services.cellward.system.stopGrace`
  (5s unless set, 1s…1h). No other descriptor of the service reaches it.
- **What the command does not see**, beyond the zone's resolver and the session's sockets:
  `/run/vpn-zones` (this service's socket — a command in one zone asking for another, and
  the `vpn-zones` group is not among its groups either), the host's `/tmp`, `/var/tmp` and
  `/dev/shm` (it gets its own: X11, tmux and other listening sockets there take the user's
  uid for the user), and the Nix daemon's socket (it builds and fetches in the host's
  network).
- The request is one datagram: `VZS1\0`, zone, mode, cwd, argc, argv…, envc, env…, each
  NUL-ended, at most 64 KiB; the answer is `EXIT <code>` or `ERR <why>`.

## 7b. A user zone through a system zone

One VPN, one tunnel — for the host's services and for the user's programs, graphical ones
included. A system zone holds the tunnel; a **user zone** (the rootless tier, with everything
it has: the sealed runtime directory, the compositor restriction, the picker, containers,
hermeticity) takes its way out from it instead of dialling the VPN a second time. The same
key in two tunnels makes the server see two devices with one key, and they knock each other
off.

```ini
[SystemZone]
Name = nl
```

`cellward add <zone> --system nl` writes that, and `cellward add <zone> <file.conf>` writes it
by itself when the file's key is already a system zone's the user may use (`VZK1`, below); a
system zone they may not use is a refusal, never a second tunnel behind its back.

- **The shape.** The user zone is a user namespace with its app namespace in it, like any
  other, but with no tunnel and no uplink of its own. Its way out is pasta, as for a
  host-interface zone — only this pasta is started by the system-zone service **in the
  system zone's network namespace**, as the user, and attached to the app namespace, where
  it names its interface `awg0`. A packet from the user zone reaches pasta, pasta sends it
  on from the system zone, and the system zone has lo and its tunnel and nothing else.
- **Asking** (`VZP1`). The zone's holder runs `vpn-zone-core system-uplink <zone> <pid>`, a
  watcher that opens the app namespace's user and network namespaces (`/proc/<pid>/ns/*`,
  its own zone's) and sends them as descriptors. The service knows the asker from the
  kernel: the zone asks from inside its own user namespace as its uid 0, which on the host
  is the first uid of the user's `/etc/subuid` range — the owner the egress policy knows
  zones' ways out by. It checks that the user may use the system zone, that the user
  namespace is owned by the user (`NS_GET_OWNER_UID`) and that the network namespace belongs
  to that user namespace (`NS_GET_USERNS`) — the host's and the system zones' belong to the
  host's, owned by root, so neither can be passed off as a zone —, brings the system zone
  up, and starts pasta: `setns` into the system zone's network while root, then no groups,
  the user's uid, the group `vpn-zones-bridge`, `NO_NEW_PRIVS`. pasta closes every
  descriptor it inherits, so it is given `/proc/<pid>/ns/*` paths, and the child — already
  the user, who may open a process of their own zone's as its owner — checks that the paths
  are the namespaces that were checked (`st_dev`/`st_ino`); a pid reused in the moment
  after could only attach pasta, running as the user, to another namespace of the same
  user's. Each descriptor is checked for its kind first (`NS_GET_NSTYPE`). The service
  reads no `/proc` of another user's processes and needs no `CAP_SYS_PTRACE`.
- **Only a zone asks** (review): VZP1 from an account's own uid is refused — the zone's
  uid 0 (the subuid start) is what a zone asks as, and no program of the user's becomes
  it. `/run/vpn-zones` is hidden in every user zone (LEAK-MODEL §14), so its programs do
  not reach the service at all.
- **Through, not into.** pasta's group `vpn-zones-bridge`: the system zone's ruleset
  refuses that group's packets to the system zone's own addresses (`meta skgid … fib daddr
  type local reject`), so a service listening in the system zone is not the user zone's
  to reach.
- **Its life is the connection.** The watcher holds the connection for as long as it runs;
  the holder watches the watcher the way it watches pasta for the other kinds. The zone
  going down stops the watcher, the connection closes, the service kills pasta. pasta
  ending is said on the connection (`EXIT`), the watcher ends, and the zone goes down with
  it.
- **Names.** The service answers with the system zone's resolvers; the app namespace's
  resolv.conf is written from them — the tunnel's, reached through the tunnel.
- **Liveness.** pasta's interface up is the link; the tunnel behind it is the system zone's,
  whose holder mirrors `wg show` for the group `vpn-zones`: the user zone's status is that
  file, so `cellward check` and the picker read a handshake as for any WireGuard zone.
- **Where a packet can go.** From the app namespace only to pasta (`awg0` is its only
  interface besides lo, and its filter allows nothing else). From pasta only where the
  system zone routes — its tunnel; the system zone's filter drops anything else. The tunnel
  stopping leaves the system zone with lo and the user zone with nothing (the VM test checks
  both the tunnel's address and the host's own). pasta's sockets are in the system zone's
  namespace, so the host's egress policy never sees them — and does not have to.
- **The system zone made anew** — its namespace unit restarted, cellward off and on — would
  leave pasta in the old namespace, which has no tunnel. The service keeps the zone's two
  descriptors for as long as the connection lasts and looks every second: the system zone's
  namespace gone or another one, pasta is killed; a namespace there again with its way out
  up (`ready`), pasta is started in it. In between the user zone has no way out at all —
  closed, never open — and it comes back without a restart.
- **Not yet.** IPv6 through such a zone: pasta is started with `-4`, so the zone has no IPv6
  route and its programs fall back to IPv4 at once.

## 7a. The TTY console

`services.cellward.system.console = { enable = true; zone = "nl"; fallback = "direct"; }` —
ARCHITECTURE §4: fell into a text console, logged in, and there is a network already, with
nothing to type and nothing to know.

```
  cellward — консоль · alice
    сеть: nl — туннель жив (tunnel alive)
    [Enter] терминал с интернетом (zone nl)
    [n]     Настройки и откат                ← console.admin, if set
    [p]     напрямую, без VPN (zone direct)  ← only when nl has no live tunnel
    [k]     аварийный ключ …                 ← the egress policy's key (§9)
    [x]     выключить cellward целиком …     ← the off switch (§9a)
    [q]     обычная консоль, без сети
```

- **When it shows up.** The login shell runs `vpn-zone-core console --login` once per login
  (`environment.loginShellInit`), in interactive shells only — a display manager starts a
  session with `bash -l -c …`, often on a VT, and the console must not stand in front of the
  compositor. The program then decides: a virtual terminal (`/dev/ttyN`, not a pty, not a
  serial line), outside any zone, a user of the console's zone. Anybody else gets the
  ordinary login.
- **The network.** A zone that is down is started — through the helper (§7), which starts
  it for the zone's users — and a tunnel is waited for up to 15 s. Alive
  means a handshake within WireGuard's session limit, or for a plain zone its interface up.
- **The keys.** Enter: a login shell in the zone through `vpn-zone-sys`, and back to the menu
  when it ends; `p`: the same in the plain `fallback` zone, offered when the zone has no live
  tunnel; `n`: the admin tool on the host; `k`: the emergency key; `x`: the off switch;
  `q`: the ordinary shell of the host. With cellward off the console does not show itself. The shell runs as a process of its own, not inside the console: the client's
  relay would leave a thread blocked on the terminal that would take the next key meant for
  the menu.
- **It never locks anybody out.** Every failure ends in the host's ordinary shell, which under
  the egress policy has no network but has everything to repair with — and the key.

## 8. State for tools

`cellward status --json` gets a top-level `system_networks` array — additive, schema 1. A
separate array and not entries in `networks`: a tool that doesn't know the difference would
offer a system zone as a network for a program container, which can't use it.

```json
"system_networks": [
  {"name":"vpn1","netns":"/run/netns/vz-vpn1","kind":"wireguard","source":"nix",
   "up":true,"tunnel_alive":true,"handshake_age_s":12,"rx_bytes":1024,"tx_bytes":2048,
   "readable":true}
]
```

`readable: false` means the reader isn't in the group `vpn-zones`: the run directory is
closed to them, so `up`, `tunnel_alive` and the counters are `null`.

## 9. The host without a network of its own (stage 5)

`services.cellward.system.egress = { enable = true; mode = "audit" | "enforce" | "strict"; }` —
ARCHITECTURE §2, «страховка»: a user's program that runs outside every zone does not reach
the network, however it was started.

- **One table, one unit.** `inet vpnzones_egress`, an `output` chain at priority −160 (after
  conntrack, before a DPI bypass's mangle). Rolling back a generation removes it with
  everything else.
- **Our binary cannot open the host.** The restriction is printed when the system is built
  (`vpn-zone-core egress print`, the same function as everything else) and loaded by `nft`
  alone from that file, in one transaction (`destroy table` + the new one). Only then does our
  binary ADD the allowances that need the running system — the uplinks of user zones, the
  named users and groups — with `egress allow`, and that step may fail (`-` in the unit): the
  host is then more closed than meant, user zones lose their way out as with a dropped
  tunnel, and it is never open. The VM test loads the file alone and checks exactly that.
- **By the socket's owner, not by cgroup.** Out: root and system users (uid < 1000),
  systemd's dynamic users (61184–65519), the first uid and gid of every `/etc/subuid` and
  `/etc/subgid` range (the uplinks of user zones: pasta runs as uid 0 of the zone's user
  namespace), `allowUsers`, `allowGroups` (`nixbld` by default), established and related
  traffic, loopback, the kernel's neighbour discovery and IGMP. A system zone's tunnel is
  let out by its mark: its UDP socket is the kernel's own, has no file and so no owner, and
  the holder writes `FwMark = 0x767a` into what `setconf` gets (`system::TUNNEL_MARK`,
  replacing any the config had) — found by the VM test, where the first handshake was
  refused. Everything in a zone never passes this hook. Anybody else: a rate-limited
  `vpn-zones-egress: … UID=<uid>` line in the kernel log, and in `enforce` `reject with
  icmpx admin-prohibited` — the program fails at once instead of hanging.
  Cgroup sets (`NFTSet=`) were the other design: systemd fills them when a unit starts, and
  every flushing firewall reload empties them — a policy that silently stops recognising
  what it allows.
- **`audit` first.** The same rules, logged and let through: a machine is watched before it
  is locked.
- **A firewall that flushes.** With `networking.nftables.flushRuleset` the NixOS firewall
  deletes every table on start and reload; the policy's unit is then `PartOf` it and
  reloads with it (`ReloadPropagatedFrom`). Without flushing it is left alone.
- **The emergency key.** `vpn-zones-egress-open.service` deletes the table with `nft` itself
  — no binary of this project involved, so it works when ours is broken — for
  `emergency.minutes` (15), then puts the policy back — also when stopped earlier. And
  `vpnzones.egress=off` on the kernel command line keeps the policy from loading at all.
  `emergency.group` (`wheel`) may start it with a password — at the machine too (2026-09-25: a line a zone's program slips into the shell's startup would otherwise turn it at the next login) — and stop it without one at the machine itself (a process in a local, active login session's own scope) — through polkit,
  which the module therefore turns on (NixOS has it off by default; the VM test found the
  key refused without it). The TTY console of ARCHITECTURE §4 turns it with one key.
- **What it does not close.** Names: a blocked program still resolves them through the
  host's nscd or resolved, which are the system's and go out — the connection is refused,
  the question already left. `host.dns` (§9c) sends those questions through a zone. And
  root: root can unload anything; the policy is about programs that do not know, not about
  root. `strict` (§9b) takes the host's own services off the network as well.
- **Known gaps** (review, not closed yet):
  - *Every first subuid and subgid is let out*, not only zones' uplinks: whatever runs as
    the user's first subordinate id in the host's network goes out — the root of a rootless
    container started with the host's network (`distrobox`/`toolbox`, `--network host`), or
    a namespace the user maps on purpose with `newuidmap`. Narrowing it needs the zones'
    pasta under an owner no container uses (ROADMAP).
  - *Established flows stay.* `ct state established,related accept` comes first: a
    connection opened while cellward was off, during the emergency key's window or
    before the policy loaded keeps flowing afterwards, and so does the reply side of a
    connection someone opened to a user's listener.
- **Loaded on any nft and kernel.** The table is replaced with `add table` + `delete
  table` in the same transaction as the new one — not `destroy`, which needs nft 1.0.8 and
  Linux 6.3; a file that did not load would leave the host with no policy at all.

## 9a. Rescue paths

The system tier is what gives a broken machine its network, so each way it can break has a
way around it that does not need the broken part:

| Broken | What is left |
|---|---|
| The graphical session, the GPU driver | The TTY console (§7a): the kernel's console, no graphics |
| This package in a new generation | The console falls through to the ordinary shell; the previous generation in the boot menu |
| The VPN, or the amneziawg module for a new kernel | The in-tree `wireguard` for configs without obfuscation; the plain zone, which needs no module |
| The egress policy keeps the host offline, our binary broken | The emergency key deletes the table with `nft` alone and puts it back from the built file with `nft` alone; `vpnzones.egress=off` on the kernel command line (`e` in the boot menu) keeps the policy from loading, with no binary of ours involved. Our binary crashing never OPENS the host: it only adds allowances to a restriction `nft` loads by itself |
| cellward as a whole, with no network to rebuild without it | `vpn-zones-off` (below) |
| Nix, the daemon | Not used at run time by zones, the console or the policy |
| The store itself | The previous generation; nix_cm's rescue copy runs without `/nix/store` |

**Off entirely, with no rebuild.** Taking cellward out of the configuration needs a rebuild,
and a rebuild may need the network cellward is keeping from the host. `vpn-zones-off` turns
it all off in place instead: it sets `/var/lib/vpn-zones/off`, deletes the egress table,
reloads systemd (the generator no longer attaches services), restarts the attached services
on the host's network, and stops the zones. Every zone unit and the policy have
`ConditionPathExists=!/var/lib/vpn-zones/off`, so nothing comes up again, reboots included;
the console does not show itself, and the helper (§7) answers "cellward is off".
`vpn-zones-on` removes the flag, starts the policy and the `autoStart` zones, brings up the
zones of the attached services that are running, reloads systemd and restarts those services
into their zones. The order matters: after the reload a service is bound to its zone, and
systemd stops a service bound to a zone that is not up; `try-restart` would not bring the
zone up either, it pulls in no dependencies. Both are oneshot units run by systemd with
coreutils, `nft` and `systemctl` — none of our binaries; the commands are wrappers around
`systemctl start`, and polkit lets `services.cellward.system.switchGroup` (`wheel` by
default, `null` for root only) start exactly these two units: `off` with a password, at the machine too, `on` without one at the machine itself. The console
has it as `[x]`. On the kernel command line, `vpnzones=off` does the same for one boot
without touching the flag. The user tier has its own switch, `cellward mode off`; user zones
do not depend on the system tier and keep working.

A statically linked set of tools (`ip`, `awg`, `nft`, pasta) was weighed and left out: on
NixOS every package carries its own closure, "the linking broke" happens only with a
corrupted store, which breaks everything at once and is what the previous generation is for;
the static set would cost long local builds for next to nothing.

## 9b. `strict`: the host itself, too

`mode = "strict"` is `enforce` and one more restriction: root and the system's users —
uid < 1000 and systemd's dynamic range — keep the local network only. Whatever of the
system has to reach further goes through a zone, like everything else, and chooses which:

```nix
services.cellward.system = {
  zones.direct0.kind = "plain";   # "directly": the host's network, through pasta
  host.nix = "direct0";           # or a VPN zone: downloads through the tunnel
  host.time = "direct0";          # or a VPN zone: nobody sees who asks for the time
  egress = { enable = true; mode = "strict"; };
};
```

With `programs.cellward.enable = true` the first three lines are the default whenever
`egress.enable` is on and `host.nix` / `host.time` are unset: a `zones.direct0` of your own
wins, `host.time` is set only with timesyncd on, and `host.nix = null` keeps the daemon on the
host's network.

- **What "local" is.** `egress.localNetworks`: the private, link-local and multicast ranges
  of both families by default — the router, a printer, a resolver on the LAN, mDNS. They
  are in the file built with the system, as two interval sets; each prefix is checked by
  our binary at build time (a prefix `nft` refused at boot would leave the host with no
  policy at all) and its host bits cleared. A LAN on public addresses has to be added.
  DHCP is let out by port (68→67, 546→547) for the system's users only: a renewal goes to
  the server's own address, which need not be a private one, and a service that can bind
  port 68 is not thereby let out to anywhere (review).
- **The ways out that stay.** A system zone's tunnel (its mark), the uplinks of user zones
  (subuid), the pasta of plain zones — its owner, `vpn-zones-plain`, is a system user and
  is now named in the allowances (`egress allow --user vpn-zones-plain`; if that step fails,
  plain zones are closed, not the host open) — and `allowUsers`/`allowGroups`. `nixbld` is
  no longer in `allowGroups` by default: builds download in the daemon's network, which is
  `host.nix`'s zone.
- **`host.nix`.** The Nix daemon is attached to the zone like any service (§5): substitutes
  and the builds that fetch run in the daemon's network namespace. It is not ordered after
  the zone's way out, only after its namespace — the daemon starts at once, local builds
  never wait for a VPN, and the network appears in its namespace when the tunnel does.
  Whoever may use the daemon may make it download; it downloads through this zone. Root's
  own `nix` without the daemon (a local store) is the host's and refused — which is what
  the VM test checks it against.
- **`host.time`.** systemd-timesyncd, attached the same way, with the system bus (it does
  not start without it; it asks for names through the zone's NSS). It belongs to early
  boot (`Before=sysinit.target`), so the namespace unit has no default dependencies — only
  after the local file systems and `systemd-tmpfiles-setup.service`, which makes the
  `/var/run → /run` link `ip netns` keeps namespaces under (the VM test found the zone
  failing without it): ordered after anything later, timesyncd would close a cycle.
  So it starts before the zone has a way out, and it does not come back by itself: it
  judges the network by the host's, and after its first attempts fail it waits for an
  event that may never come (in CI it never tried again within two minutes). The zone's
  way out, once up, restarts it — `ExecStartPost=-systemctl --no-block try-restart`, a
  drop-in on `vpn-zone-system@<zone>` written by the same generator, so the switch takes
  it away with the rest.
- **NetworkManager.** Its connectivity check is root's and goes to the internet; refused, it
  would tell every program that asks that there is only limited connectivity, while the
  zones have the internet. Under `strict` the module turns the check off (`mkDefault`).
- **Left on the host**, and refused once strict: a DNS resolver pointed past the LAN, unless
  `host.dns` (§9c) takes it through a zone (a zone's endpoint name is resolved by the host),
  `nixos-upgrade` (its evaluation fetches as root: attach it with `services.<unit>` and
  `systemBus = true`), anything else of the system that phones out. The kernel log names
  each of them (`vpn-zones-egress: … UID=`), and `audit` shows them before `strict` refuses.
- **Refused at build time.** `strict` with `host.nix` unset does not build: the daemon
  could not download, and neither could the next rebuild that would fix it. With timesyncd
  on and `host.time` unset it is a warning (the clock drifts, the machine still works); both
  say the line to add.
- **The switch** (§9a) returns the host's services to the host's network with the rest.

## 9c. The host's names through a zone

`services.cellward.system.host.dns = "<zone>"`: every name the host itself asks — resolved,
nscd, a program reading `/etc/resolv.conf` — is asked through the zone.

- **Why not resolved in the zone.** A namespace has no way into another, and that is the
  point of a zone. resolved moved into one would listen on 127.0.0.53 in the zone, out of
  the host's reach; the links NetworkManager tells it about would be the host's, which it
  would not see. What can be in two namespaces at once is a process.
- **The forwarder.** `vpn-zones-dns.socket` — UDP and TCP on 127.0.0.60:53, opened by systemd
  in the host's network — hands its sockets to `vpn-zones-dns.service`, which the generator
  (§5) attaches to the zone. The queries arrive from the host, and every socket the service
  makes to ask them further is made in the zone (`vpn-zone-core dns-forward`,
  `rust/src/dnsfwd.rs`). It parses nothing but the ID, gives each query a socket of its own
  connected to the resolver (a fresh port from the kernel, nothing accepted from elsewhere),
  and asks the zone's resolv.conf — bound over `/etc/resolv.conf`, read again per query
  because the zone rewrites it in place when its tunnel comes up. A zone that is not up
  answers nothing: the query is dropped, never sent elsewhere. `DynamicUser`, no
  capabilities, `ProtectSystem=strict`.
- **The host's resolver points there and nowhere else.** With resolved: `DNS=127.0.0.60`,
  `FallbackDNS=` empty, `Domains=~.` — forced (`mkForce`), because a merged list would send
  part of the questions around the zone. Without it: `networking.nameservers`. What DHCP
  hands out never reaches the resolver, or the router would be asked directly:
  - NetworkManager: `dns = "default"`, `rc-manager = "unmanaged"`, `systemd-resolved =
    false`. Not `dns = "none"`: its `systemd-resolved` key (true by default) sends every
    connection's resolvers to resolved whatever `dns` says — found in the manual after this
    section first shipped with `none`, and checked by a NetworkManager host in the VM test.
    It still writes its own copy, `/run/NetworkManager/resolv.conf`: the router's resolvers,
    read by plain zones and by the forwarder when off;
  - dhcpcd: its `resolv.conf` hook skipped from `/etc/dhcpcd.enter-hook`, which it runs
    before its hooks on every interface. Not `nohook resolv.conf` in `extraConfig`:
    nixpkgs puts that after the `interface ethX` blocks it writes for static IPv6, and a
    block in dhcpcd.conf runs to the end of the file — the VM test found eth0 still handing
    resolved QEMU's resolver;
  - systemd-networkd hands resolved each `.network`'s resolvers itself, and networkd.conf
    has no global "don't": with resolved, every network has to say `UseDNS = false` (DHCPv4,
    DHCPv6, router advertisements) and have no `DNS=`, or the system does not build — the
    message names the networks, NixOS's generated `99-*-dhcp` ones included.
- **Whose resolvers** (the owner's rule): a VPN zone's are its config's `DNS =`, or the
  public ones when the VPN names none; a plain zone — "directly" — has the router's, as the
  host knows them (`dnsfwd::ROUTER_SOURCES`: NetworkManager's copy, resolved's upstreams,
  /etc/resolv.conf; loopback addresses are the host's own stub and are skipped), or the
  public ones when the host knows none, and follows them every five seconds (another Wi-Fi,
  another router). `zones.<z>.dns` overrides either: addresses only, checked when the system
  is built and again when the zone comes up (a line that is not an address would be an
  option in resolv.conf).
- **What the host's resolver itself does in the host's network.** resolved's LLMNR and
  mDNS are multicast to the local network, around the zone: `host.dns` turns them off
  (`mkDefault`, for whoever wants `.local` on purpose). Tools that hand resolved per-link
  resolvers over D-Bus as root — iwd with its own network configuration, wg-quick,
  openvpn and strongswan scripts, tailscale — are not stopped by this module, and their
  routing domains are a closer match than the global `~.`: those names go to their
  servers. A `resolved.conf.d` drop-in or `extraConfig` with `DNS=` is added to the forced
  list, not replaced by it; without resolved, another `resolvconf -a` source lands in
  `/etc/resolv.conf` after 127.0.0.60 and glibc falls back to it on a timeout.
- **The forwarder under load** (review): a UDP query waits at most 2 s per resolver in all
  (stray answers do not restart the wait), a TCP client's connection lives at most 30 s,
  128 queries per protocol are in flight at once, and no thread to be had drops the query
  rather than the listener. Any local user can still keep those 128 busy.
- **Local names** (`printer.lan`, the router's own names) are answered when the zone's
  resolvers know them: a plain zone's are the router, so they are; a VPN zone's are not.
  Sending chosen local domains to the router from a VPN zone is optional and not built yet
  (ROADMAP).
- **A VPN zone for the host's names** needs its endpoint as an address: the holder resolves
  an endpoint name through the host, which would ask through the zone that is not up yet.
  The module warns; a plain zone for `host.dns` has no such loop.
- **Off.** Without the attaching drop-in the unit's own `ExecStart` runs, from the host's
  network: the router's resolvers as the host knows them (`--host-resolvers`), else a plain
  zone's own `dns`, else the public ones (`--fallback`). A VPN zone's own resolvers are not
  used: they are inside its tunnel. Names keep working with cellward off; the resolver
  settings stay as they are.
- **A program outside the zones** still gets its names — through the zone now, not the
  host's network — and under `enforce`/`strict` still no connection.

## 10. Leak channels of the system tier

1. **Routes around the tunnel** — none: `lo` and `awg0` only; the second echelon is loaded
   into the namespace before the tunnel arrives.
2. **DNS** — the zone's resolv.conf bound over the consumer's; nscd, resolved's varlink
   socket and (by default) the system bus hidden from services; containers have their own
   `/run`.
3. **Degradation** — the holder stopping deletes `awg0`: `lo` alone. A holder killed
   without its `ExecStopPost` leaves a working tunnel — not a leak.
4. **The host's Nix daemon** — hidden from containers (§6) and from a user's command
   (§7). Services: a service running as a user may reach the daemon socket; hiding it is
   `InaccessiblePaths` too, offered but not forced (some services legitimately build).
5. **One zone is one network** — everything in a zone shares its `lo` and abstract unix
   sockets. Separation means separate zones.
6. **The endpoint** — resolved in the host's network, as for user zones (LEAK-MODEL §5).
7. **A user's program** (§7) gets the same hiding as a service plus the session's sockets:
   the bus and the compositor are how a program asks the host to open something, in the
   host's network. Hidden where they lie is not enough: a user namespace of its own keeps
   the command out of the session's processes' `/proc/<pid>/root` (LEAK-MODEL §16).
7a. **Fail closed on a broken setting** — an `uplink` that names no interface, or a missing
   `vpn-zones-bridge` group, stops the zone or the uplink instead of going wherever the host
   routes; a declared zone never uses a config somebody not among its users added on the
   spot under its name before it was declared; a config added on the spot gets no
   `ListenPort` (the socket is the host's). Parse errors show a line's key, never its value.
8. **The host side has no second echelon** — a system zone's uplink is the host's network
   itself, and a ruleset there would be the host's firewall. Filtering the host's egress is
   stage 5 (§9); a zone's tunnel passes it by its mark.

## 11. Tests

- **Rust** (`system.rs`, `status.rs`): the name check; the paths; the argument parser;
  refusing OpenConnect, host-interface and configs without `[Interface]`; the declared list
  trusting no name; the `system_networks` entry for a closed, a down and an up zone. The
  command sequence of `up` itself is covered by the VM test only — it is `ip` calls, and a
  fake `ip` would test the fake.
- **VM `tests/vm-system.nix`:** `machine` with the NixOS module and a zone `sz` whose config
  is written at run time; `server` a WireGuard peer with HTTP and DNS on its tunnel address;
  `machine` also serves HTTP on its LAN address, which must never be reached from the zone:
  1. `ip -n vz-sz -o link` shows exactly `lo` and `awg0`; the ruleset is there;
  2. a service attached to `sz` fetches the tunnel's HTTP and resolves a name only the
     tunnel's DNS knows; it can't reach the LAN HTTP;
  3. the same service, with nscd and resolved running on the host, gets the tunnel's answer
     for a name the host's resolver answers differently;
  4. a NixOS container attached to `sz`: the same two checks, `ip link add` refused inside,
     the daemon socket inaccessible;
  5. stopping the holder: `ip -n vz-sz -o link` is `lo` alone, the service and the container
     keep running and reach nothing; starting it: the HTTP answers again;
  6. restarting the namespace unit restarts the service and the container, and they are in
     the new namespace (checked by a per-namespace sysctl: inode numbers are reused);
  7. `vpn-zone-sys` as a listed user: the tunnel's network and names, the user's uid,
     `NoNewPrivs: 1` and no capabilities, `lo` and `awg0` only, `ip link add` refused, the
     zone's nsswitch, the command's exit code, a pty with a terminal, the launch in the
     journal; a socket in the session's runtime directory reached through `/proc/<pid>/root`
     from the host and not from the zone; a user of another zone and a user outside the
     group are refused;
  8. a plain zone: `lo` and `awg0`, pasta as `vpn-zones-plain`, the server sees the machine,
     the host's loopback unreachable by the gateway and by `127.0.0.1`, the resolvers the
     host knows (QEMU's, from resolved) and no loopback among them,
     `connected: yes` in the status, and alice out through it while the policy refuses her
     directly; stopping it leaves `lo` alone;
  9. the egress policy, enforced from boot under a firewall that flushes every table: root
     and a `DynamicUser` service reach the LAN, a user outside the zones is refused at once
     and named in the kernel log, the same user through her zone is not; `systemctl reload`
     and `restart nftables` leave the policy in place; the emergency key opens and closes
     the host for a member of `wheel` and is refused to anybody else. Everything before
     step 9 runs under the enforced policy too.
  10. the TTY console: alice logs in on tty1, the menu says the tunnel is alive, Enter gives
     a shell in `sz` that reaches the tunnel, `q` a host shell that does not reach the LAN;
     with the server's WireGuard down and the zone restarted, the menu says there is no
     tunnel and `p` gives a shell in the plain zone that reaches the LAN;
  11. the off switch, by a member of `wheel`: the flag is set, the policy's table is gone,
     `sz` is down, the attached service runs again in the host's namespace and alice reaches
     the LAN directly; `vpn-zone-sys` answers that cellward is off; a `daemon-reload` does
     not attach the service again; `vpn-zones-on` is refused to a user outside `wheel`, and
     for alice brings the policy, `sz` and the service in its namespace back;
- **VM `tests/vm-bridge.nix`:** a user zone through a system zone (§7b), both tiers on one
  machine (the NixOS module and alice's home-manager module), the egress policy enforced:
  `cellward add --system` writes a config with no key; the zone's program reaches the
  tunnel's service and the server sees the system zone's tunnel address; `lo` and `awg0`
  only; the tunnel's resolver; the machine's own LAN address unreachable; pasta in the system
  zone's namespace as alice, none as root; `cellward check` from the system zone's
  handshake; `cellward add` with the system zone's key makes a zone through it; the tunnel
  stopped, nothing reachable, started again, reachable; the system zone's namespace made
  anew (told by a sysctl marker) and the user zone reaching the tunnel again with one pasta
  of alice's in the new namespace; cellward off, nothing reachable, on, reachable; the zone
  down, nothing of alice's left in the system zone.
- **VM `tests/vm-uplink.nix`:** zones through one interface (§4a), two networks under the
  strict policy: a tunnel zone through eth2 whose server sees it come from the machine's
  second address, `lo` and `awg0` in it, its uplink's pasta run by `vpn-zones-plain` and the
  uplink letting nothing out but the tunnel; a tunnel zone through eth1 with its endpoint on
  the second network: closed, no handshake ever, not rerouted; a plain zone through eth2
  reaching the second network and not the first; the uplink namespace and its pasta gone
  with the zone and back with it.
- **VM `tests/vm-host.nix`:** the strict policy. `server` has a LAN address and one outside
  every private range (198.51.100.1) that stands for the internet, with a TCP responder, an
  HTTP file and an NTP server (chrony) there; `machine` runs `strict` with a plain zone `pl`
  and `host.nix = host.time = "pl"`:
  1. the loaded table has no blanket allowance for system users; root reaches the LAN and is
     refused beyond it, named in the kernel log; a user outside the zones reaches neither;
  2. through `vpn-zone-sys pl` the user reaches the internet address;
  3. the Nix daemon runs in `pl`'s namespace, and a user's build downloads a file from the
     internet address through it; root's own `nix-prefetch-url` (a local store) is refused;
  4. timesyncd runs in `pl`'s namespace and contacts the NTP server — after every boot,
     although it starts before the zone's way out (the routes are the machine's own, from
     boot, as on real hardware);
  5. `vpn-zones-off` puts timesyncd back into the host's namespace, `vpn-zones-on` into the
     zone, and root is refused again;
  6. no ordering cycle in the journal of the first boot or of any later one (systemd would
     break it by dropping a job — on a new configuration this is where it shows); a reboot
     brings the policy, the zone and both services in it back by themselves;
  7. off survives a reboot: no table, no zone, timesyncd and the daemon on the host's
     network, root out; on after it puts everything back;
  8. the host's names (§9c): `server` answers the same names differently from its
     "internet" resolver and from its LAN one (the "router", which also hands out addresses
     and itself as the resolver by DHCP); the host — through nscd and
     resolved, and directly at 127.0.0.60 over UDP and TCP — gets the "internet" answer, the
     forwarder runs in `pl`'s namespace, `resolvectl dns` shows the forwarder alone; off, and
     after a reboot off, names still resolve with the forwarder on the host's network; on,
     it is back in the zone;
  9. `nmhost`: NetworkManager takes its address and resolver from the router's DHCP;
     `/run/NetworkManager/resolv.conf` names the router, `resolvectl dns` names the forwarder
     alone, the plain zone `direct0` (no `dns` of its own) asks the router, and the host's
     names get the router's answer through it.
