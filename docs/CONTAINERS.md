# Containers by default (M8) — design

Russian: [CONTAINERS.ru.md](CONTAINERS.ru.md) · Related: [LAUNCHERS.md](LAUNCHERS.md)
(launcher entries), [CERTIFICATES.md](CERTIFICATES.md) (per-container trust),
[LEAK-MODEL.md](LEAK-MODEL.md), [GOTCHAS.md](GOTCHAS.md)

**Status: design accepted with the owner's decisions of 2026-09-17 (§12).**
Nothing described here as "new" exists yet unless it is marked as done.

## 1. Summary

Today a launch is three independent choices made on every click: a network
(zone, unconfined, offline), a data container (main, overlay profile, throwaway)
and a filesystem sandbox (none, per-app, named, throwaway). This design turns
the three into one thing, a **container**:

> A container is a named identity: a home, a set of permissions, a set of
> trusted certificates **and one network at a time**. A program instance runs
> in exactly one container. Programs are assigned to containers; networks are
> assigned to containers, and both assignments can be changed at any time —
> explicitly, never as a side effect of a click.

Consequences, in order of importance:

1. **An identity changes networks only when a person says so**
   ([LEAK-MODEL](LEAK-MODEL.md) "Open channels" §4). The per-click network
   question is what used to take one browser profile into two networks without
   anybody noticing; a network change is now an action of its own, shown as
   such.
2. **No layer is silently dropped.** Every launch takes the same road, whether
   the network is a zone, `direct` or `offline`. The `direct` bug fixed in
   `fix/launch-path` (the picker dropped the container, the sandbox and the
   compositor restriction) is the class of bug this removes by construction.
3. **Every program gets a home of its own by default**, and two containers can
   be merged into one (§3.4).
4. **Launches from outside the launcher end up in the right container**: D-Bus
   activation, autostart, compositor key bindings, links from other programs,
   entries programs write into the user directory (§5).
5. **Per-zone launcher clones are deprecated**; the per-container view replaces
   them ([LAUNCHERS.md](LAUNCHERS.md) §4).
6. **Everything is declarative** through home-manager module options, with a
   machine-readable state output that says where every value comes from (§8,
   §9).

## 2. What exists today

| concept | where it lives | what it isolates |
|---|---|---|
| zone | `~/.local/state/vpn-zones/<zone>/` + `vpn-zone@<zone>` | network (app-ns: `lo` + tunnel only); WireGuard, AmneziaWG or OpenConnect |
| `unconfined` | nothing | nothing (host network) |
| `offline` | a zone with a marker, created on demand | everything network, incl. host resolvers |
| layer container (`home = layer`, was "profile") | `~/.local/state/vpn-profiles/<name>/` (data), `~/.config/vpn-zones/containers/<name>/` (policy) | the whole home, under its layer (`<name>/home/upper`); a granted path (`container grant`) is written in the real home; mounts below the home read-only unless granted; other containers' storage not seen (`crate::home_layer`, 2026-09-26 — before, only `.config`, `.local/share`, `.cache`, `.mozilla`, `.pki` were layered, and the rest of the home was written through) |
| throwaway container | `~/.local/state/vpn-zones/.throwaway/vpn-profile-*` | same, erased after the last tenant |
| container of a home of its own (`home = private`, was "named sandbox") | `~/.local/state/vpn-profiles/<name>/home` (data — the one data directory of every container, 2026-09-26; before, `vpn-sandboxes/<name>`), `~/.config/vpn-zones/containers/<name>/` (policy: `perms`, `paths`, `container.conf`, `trust/`) | whole home, bus, runtime dir, seccomp, X11 |
| container of the main home (`home = main`) | its policy only | nothing of the home: a network, programs and permissions of its own under a name |
| per-app sandbox | a named sandbox called `app-<key>` | same |
| throwaway sandbox | tmpfs | same, erased on exit |
| compositor restriction | `wl-sandbox`, on by default | screen capture, input emulation, background clipboard |

What the picker remembers is per program: `.pinned`/`.last` (network) and
`.pinnedprofile`/`.lastprofile` (container). The two axes are independent,
which is exactly what lets one program's identity travel between networks.
**Since 2026-09-26 the network is the container's** ([PERMISSIONS.md](PERMISSIONS.md)
§11.8): `.pinned` is gone — moved into the containers' networks once —, a
container with no network has it asked and bound at its first launch, and
"always" in the main home moves the program to `main-<network>`, a container
of the main home bound to it. `.last` only says where a question starts.

## 3. The model

### 3.1 Container

```
container = {
  name        unique; the selector is what the registry already uses
  home        private | overlay | throwaway-private | throwaway-overlay
  network     one network (§3.3), or ask
  routes      extra named routes beside the network (LAN, …) — off by default
  permissions filesystem {downloads, documents, pictures, home, paths[]},
              x11, compositor {restricted | full}, (later) bus names, devices
  trust       extra CA certificates (CERTIFICATES.md)
  apps        programs assigned here (launcher ids)
  source      nix (read-only) | local (CLI/GUI)
}
```

- **`home`** maps one-to-one onto what exists: `private` is today's named
  sandbox (and the per-app `app-<key>` one), `overlay` is today's profile, the
  throwaway kinds are today's `--fs-sandbox` and `--tmp-profile`. Data
  directories stay where they are; they are part of the contract
  ([GOTCHAS](GOTCHAS.md) §5).
- **`permissions.paths`** grants a private home individual directories of the
  real one, bound at the same path: `~/.wine` for a Wine program, the Steam
  library for Steam. Without it the default "a home of its own" breaks exactly
  the programs that live off data in the shared home (§3.5).
- **`network = ask`** is the compatibility value: the network question is
  asked on every launch, exactly as now. Existing containers migrate to it.
- **The main home is not a container.** "No container" stays available (host
  tools, terminals that run `sudo`), is shown as such, and cannot hold trust.

> **Superseded (the owner, 2026-09-26; [PERMISSIONS.md](PERMISSIONS.md)
> §11.7).** The main home becomes a kind of home, `home = main`, of any named
> container, and "no container" the built-in container `main`; `home` is
> `private | layer | main` (`overlay` read as `layer`) — one name is one
> container, whatever its home, with one data directory
> (`~/.local/state/vpn-profiles/<name>/`) and one policy directory
> (`~/.config/vpn-zones/containers/<name>/`). The throwaway kinds are one-off
> launches, not containers. `network = ask` is only "not chosen yet" (§11.8
> there). A container of the main home still cannot hold trust.

### 3.2 Invariants

- **I1. One network at a time; a change is explicit.** A container is launched
  into its current network only. Changing it is an action of its own —
  «Сменить сеть контейнера…» in the picker and the GUI, `cellward container
  set <c> network <net>` on the command line, the option in Nix — and never a
  side effect of choosing where to run a program. `cellward run <other>
  --profile <c>` is a refusal naming the way out, not a silent launch.
- **I2. Running programs keep their network.** A process cannot be moved into
  another network (§7). While programs of a container run in network A, the
  container is not started in B; the network change offers to close and
  restart them instead.
- **I3. One container per program instance.** The registry records the
  selector; the conflict check also looks at the binary (done).
- **I4. Every layer on every road.** Network, home, permissions, trust and the
  compositor restriction are applied by one code path (`cellward run` →
  `entry_argv` → `profile-run`), for every kind of network (done for zones,
  `unconfined` and `offline`).
- **I5. Unknown means offline.** A program with no assignment starts with no
  network until one is given ([GOTCHAS](GOTCHAS.md) §2), in a home of its own
  (`defaults.container = own`).
- **I6. Fail closed.** A container whose network no longer exists does not
  start somewhere else; a trust layer that cannot be applied stops the launch
  ([CERTIFICATES.md](CERTIFICATES.md) §4).

### 3.3 What a network can be

| kind | how | root |
|---|---|---|
| zone: WireGuard/AmneziaWG | kernel tunnel created in the uplink, moved into the app namespace (done) | no |
| zone: OpenConnect | client in the uplink, its tun moved into the app namespace (done) | no |
| zone: another client (sing-box, OpenVPN, a GUI client) | same shape, M4 | no |
| through a host interface | **done**: no uplink — pasta attached to the app namespace itself, its interface named `awg0`, every socket bound to that host interface (`--outbound-if4/-if6`), no port forwarding; `[HostInterface]` config | no |
| `unconfined` | the host's network, no namespace (done) | no |
| `offline` | loopback only (done) | no |
| a host interface **itself** inside the container | moving a real link into another network namespace needs `CAP_NET_ADMIN` in the host's namespace | **yes**: a small system helper (NixOS module option), never the default |

**Extra routes** (`routes`) sit beside the one network — the typical one is the
LAN next to a tunnel. Each is a named, explicit exception: a rule in the
uplink plus a route in the app namespace for exactly that prefix, off by
default and shown in every view of the container. A second default route is
never possible: two ways out is a leak waiting for a routing mistake.

### 3.4 Merging two containers

`cellward container merge <from> <into> [--yes]` and the «Контейнеры cellward»
entry (`cellward-gui containers`) — **implemented**: for programs that turned out to belong together (a browser and
a password manager).

- only containers of one kind merge: two layers over the home (their overlay
  slots, `<slot>/upper`, are merged slot by slot) or two homes of their own;
- the programs of `<from>` are assigned to `<into>` (`.pinnedprofile`, and
  `.lastprofile` so the picker does not offer the emptied container first);
- the home of `<from>` is copied into `<into>` **only where `<into>` has no
  such path**; conflicting paths go to a fresh `.merged-from-<from>[-N]/`
  directory of `<into>` and are listed — merging two browser profiles is not
  something a tool can decide. Nothing is followed: symlinks are copied as
  symlinks, a symlink in `<into>` is a taken name, and the conflicts directory
  is never one that already exists (a program of `<into>` could have planted a
  link to `~/.ssh` under that name, and the merge runs outside the sandbox).
  Sockets, pipes and overlay whiteouts are skipped and counted;
- the network stays `<into>`'s; trust certificates are united, and one that is
  new to `<into>` needs `--yes` — the merge is refused without it, and prints
  the ⚠ warning of [CERTIFICATES.md](CERTIFICATES.md) with it; permissions and
  path grants of `<from>` are not copied: `<into>` keeps its own;
- `<from>` is kept, emptied of programs, until it is deleted by hand;
- refused while programs of either container are running (I2), and for a
  container declared in Nix (the module would restore it).

### 3.5 Homes of their own, and what they cost

`own` as the default means an unassigned program starts in an empty private
home. Programs that expect their data in the shared home do not find it:

| program | what it needs | how it gets it |
|---|---|---|
| Wine programs | the prefix (`~/.wine`, or the `WINEPREFIX` their entry sets) | the prefix is read from the entry's `Exec` and offered as `permissions.paths` on the first launch |
| Steam | `~/.local/share/Steam`, `~/.steam` | a known-program hint: offered on the first launch |
| programs a person already set up in the shared home | their config | the first-launch dialog offers "a home of its own", "a layer over your home" (overlay) and "no container" |

The hints are a list in the crate, each entry naming the program and the
paths; nothing is granted without the person's answer.

**Path grants — implemented** (the hints and the first-launch offer are left):
`cellward container grant|revoke <name> <dir>` and
`containers.<name>.permissions.paths` in Nix. The program sees the directory
at its own path, read-write. Rules:

- an **allow-list**, not a list of dangers: below the home, or below `/mnt`,
  `/media`, `/run/media`, `/srv`. Everywhere else are the walls of the
  sandbox — `/run/user` holds the D-Bus socket the proxy filters and the
  compositor's, `/tmp` the X11 sockets, `/etc` the resolver the zone replaces —
  and a list of those would be one socket short sooner or later;
- never the home itself or anything above it (that is the `home` permission,
  asked for in words), never the state of this project or anything containing
  it: `~/.local/state/vpn-zones` holds every zone's private key;
- checked as written **and as resolved**, when granted and again by
  `fs-sandbox` at every launch: bwrap follows symlinks, so `~/games` pointing
  into the state is refused, and the resolved directory is what gets bound. A
  refused path is skipped with a warning; the launch goes on without it;
- only for a home of its own: a layer over the home already sees the whole
  real home.

**Grants with a term — implemented.** `grant … --for 30m|2h|7d` (up to 366
days; the GUI offers an hour, a day, a week) writes
`until=<unix seconds> <path>` into the sandbox's `paths` — a line an older
version reads as a relative path and refuses. A grant whose term is over is
absent from every launch from that second on, whether or not anything has
cleaned it up. For the programs already running a transient user timer runs
`cellward container expire` at the end of the term, and `revoke` does the same
at once: the bind is detached (`umount2(MNT_DETACH)`) in every mount namespace
of the sandbox's running programs, entered with `setns` as the owner of their
user namespaces. A detach cannot take away what is already open — a file
descriptor, a working directory inside; `cellward kill` is the hard end. Every
grant, revoke and expiry is in the journal (`grant`, `revoke`,
`grant-expired`), and `permissions.paths[].expires` in `status --json` is the
end of the term (RFC 3339, `null` without one).

### 3.6 Per-launch runtime (the order is the specification)

```
vpn-zone-core wl-sandbox <program> --zone <zone> --     on the host: the restricted Wayland socket (LEAK-MODEL §13)
[nsenter -U -n -m -t <zone>]  or  [unshare -U --map-current-user --keep-caps]   (unconfined)
  └─ unshare --mount --propagation slave             into a zone: every container, the main home's too
                                                     (a slave of the zone's shared /run/user/<uid>)
      └─ vpn-zone-core profile-run --cwd <dir> …     (done)
           1. home layer: overlay slots, or binds for permissions.paths
           2. runtime hermeticity (§6, phase 4 — not done): tmpfs over
              /run/user/<uid>, sockets back by name; tmpfs over /tmp/.X11-unix.
              A cover here would hide what the zone binds into its runtime
              later (the shared mount a launch is a slave of): it has to
              carry that through, or not cover the runtime directory
           3. trust layer: bundle binds, NSS databases (CERTIFICATES.md)
           4. chdir <dir> → $HOME → /                (done)
           5. drop ambient capabilities
           6. exec: fs-sandbox (bwrap) → program
```

Every mount happens in the launch's own mount namespace, never in the zone's:
two containers in one zone must not see each other's layers or certificates.
bwrap binds recursively, so what steps 1–3 mounted is what the sandbox sees.

## 4. Choosing a container

Resolution order for a launch of program `P`:

1. a running instance of `P` (by launcher id) of a program seen handing a
   launch over to its running copy: the same container — clicking such a
   program means "raise the window" ([GOTCHAS](GOTCHAS.md) §11); any other
   running program is asked, with its network and container chosen;
2. an assignment from Nix (`programs.cellward.containers.<c>.apps`);
3. a local assignment (made in the picker);
4. `defaults.container`: `own` — a new private container named after the
   program, network `offline`, and one question: which network to give it
   (the same menu as today, remembered as the container's network).

The picker shows the container and its network, and never asks for a network
of an assigned program:

```
«Firefox» — container firefox · VPN nl · own home
  ▶ Start
  ⇄ Change the container's network…     (I1: explicit; running programs restart)
  ⧉ Another container…                  (lists containers with their networks)
  ⊕ Merge with another container…
  One-off: throwaway container, offline
```

For `ask` containers and for "no container" the network-first dialog of today
stays, so nothing a user relies on disappears.

## 5. Launches outside the launcher

Interception is **default routing, not a security boundary**. A process on the
host can always `exec` a store path directly; the host user is trusted. The
boundary is the container → outside direction (§6).

| path | today | design | phase |
|---|---|---|---|
| launcher entry (menus, fuzzel/rofi, KRunner, noctalia) | picker shadow entry in `~/.local/share/applications` | unchanged; container-first picker | 1 |
| hidden handlers (`NoDisplay=true` + `MimeType`) | **done**: intercepted under the id of the visible entry of the same program | — | 0 |
| child entries (`steam steam://rungameid/…`) | **done**: no clones, launched under the client's id | **done**: web apps of a browser (`--app-id=`, `--app=`) join them | 0/3 |
| entries programs write into the user directory (Steam games, `userapp-*`, web apps, Wine) | not intercepted: foreign files are never rewritten | **done**: taken over in place with a backup and re-taken when rewritten ([LAUNCHERS.md](LAUNCHERS.md) §3.2); the invariant changed in a commit of its own | 3 |
| `xdg-open`, `gio open`, `kde-open`, "open with" | resolve to a `.desktop` → the shadow entry | unchanged | — |
| D-Bus activation (`gapplication launch`, `DBusActivatable=true`) | the service file activates around the shadow | **done** (§5.3): shadow session service files in `$XDG_DATA_HOME/dbus-1/services/<id>.service` for intercepted ids only; never for portal or system names | 3 |
| XDG autostart | runs uncontained | **done** (§5.2): assigned programs start in their container; **unassigned ones get the picker at login** (`ask`, since 2026-09-24) — or, with `offline` or no screen, start offline in a home of their own with a notification | 3 |
| compositor key bindings | only if the binding calls `vpn-zone-pick` | **done** (§5.1): `cellward launch <launcher-id>` reads the entry's `Exec` and goes through the picker | 3 |
| shell | uncontained | **done**: opt-in PATH shims for assigned programs (`pathShims.enable`); never a boundary | 3 |
| portal `OpenURI` from a host program | portal → handler entry → shadow → picker | unchanged | — |
| portal `OpenURI` from a container | the origin is lost | broker (§6.2) | 4 |
| a link opened from inside a zone | delegated through `systemd --user` | the same door, guarded: broker | 4 |
| `systemd-run --user`, `systemctl --user` from inside a zone | reachable | runtime hermeticity (§6.1) | 4 |
| `flatpak-spawn --host` | escapes over the session bus | filtered for private homes today; overlays with §6.1 | 4 |
| programs started by other host programs | uncontained | out of scope (host is trusted); `doctor` names it | — |

### 5.1 The launch command for bindings

`cellward launch <launcher-id> [-- extra args]` — **implemented** — finds the
entry by id in the same source directories `sync` reads, takes its `Exec`
(field codes filled from the extra arguments), and becomes the picker for it:

```kdl
Mod+B { spawn "cellward" "launch" "firefox"; }
```

- the entry is the program's own: an entry taken over in place is read from
  its backup, and one of our picker entries is skipped for the original it
  shadows further down the list — so a binding never wraps the picker in the
  picker;
- field codes are filled the way a launcher fills them: `%u`/`%f` the first
  argument, `%U`/`%F` all, `%i` → `--icon <Icon>`, `%c` the name, `%k` the
  entry file, `%%` a percent sign, deprecated codes dropped. Arguments an entry
  has no code for are not passed, and it says so;
- our own `vpn-zone-*` entries are refused: they start the GUI, not a program;
- `VPN_ZONE_DRYRUN=1` prints the picker command instead of starting it, for
  checking a binding;
- the shells complete the ids the picker knows (`.labels`).

A binding that calls the program directly still starts it uncontained: the
compositor is a host program, and the host is trusted (§5). What changes is
that the contained way is one word longer, not a script.

### 5.2 Autostart

The user's `~/.config/autostart/*.desktop` are taken over in place by the same
pass and under the same rules as the user's launcher entries (regular files
only, original bytes kept in `~/.local/state/vpn-zones/.adopted-autostart/`
first, re-taken when the program rewrites its entry, given back by
`autostart.unassigned = "as-is"` or `cellward mode off`). The rewritten `Exec`
is `vpn-zone-pick --autostart --id <key> -- <original command>`.

- **The key** is the one the program's pins live under, not the file name:
  autostart files are named by whoever wrote them (`telegramdesktop.desktop`
  next to `org.telegram.desktop.desktop`). A copied picker entry gives its
  `--id`; otherwise a launcher entry of the same file name; otherwise one of
  the same program; otherwise the file name.
- **What was chosen starts without a question** with `--autostart`. Running
  already — where it runs. The container: the pinned or assigned one, else the
  global default when it is an answer (`main`, `own`, an existing container).
  The network: the one that container is bound to, else the pin.
- **What was not chosen** depends on `autostart.unassigned`. `ask` (the default
  since 2026-09-24, the owner's word): the same picker a click shows, with its
  "always" — so a program is asked about once, at the login it first starts at,
  and not started into an empty home of its own where it has no data (the
  owner's KeePassXC, 2026-09-24: no database, no theme). `offline` (the default
  2026-09-17…24), and `ask` with no screen to ask on: a home of its own and
  `offline`; the last choice and the global network default are NOT used —
  they are what a dialog preselects, not a consent to go online unasked;
  nothing is remembered, and a notification says what was guessed.
- **No file access dialog either**: a home of its own that has never been
  started gets an empty permission file — the answer given when there is no
  screen to ask on.
- **Left alone**: symlinks (home-manager's `xdg.autostart`); entries that start
  nothing (`Hidden=true`, `X-GNOME-Autostart-enabled=false`, no `Exec`); a
  copied per-zone clone (it names its network); `/etc/xdg/autostart` entirely —
  the desktop's own components, and an entry of the same name in the user's
  directory would override, i.e. disable, them. A copied picker entry is
  unwrapped, not wrapped twice.
- The path unit watches `~/.config/autostart`: a program that switches its
  autostart on is taken over at once, long before the next login.

### 5.3 D-Bus activation

A `DBusActivatable=true` program is started by the session bus whenever its
name is called — `gapplication launch`, a notification's action, a file
manager's "open with", another program — and the bus reads the program's
**service file**, not its launcher entry. `DBusActivatable=false` in our entries
only helps launchers that honour it. So `sync` writes, for every entry it
intercepts (a picker shadow or a take-over) that is `DBusActivatable=true`, a
shadow service with the same bus name in `~/.local/share/dbus-1/services/`:

```ini
# X-VPNZone=dbus
[D-BUS Service]
Name=org.example.Notes
Exec=<picker> --id org.example.Notes -- <the original service Exec>
```

- the session bus reads the user's directory first and ignores a later file
  for the same name; `SystemdService=` of the original is dropped, or the bus
  would start that unit instead of `Exec`;
- only names of intercepted entries, and only well-formed bus names: nothing is
  written for a portal, a system component or any name without a launcher
  entry. A service file of the user's own with that name is never overwritten;
  ours are removed when the entry stops being intercepted (`mode off`);
- dbus-broker does not watch its service directories: when a shadow changed,
  `sync` asks for `systemctl --user --no-block reload dbus.service`;
- a program already running owns its name, and the bus hands calls to it —
  in the network it was started in, like a click on a running program.

## 6. The outward boundary (phase 4)

These are M3 items; containers make them per-container defaults.

### 6.1 Runtime hermeticity

In the launch's mount namespace: tmpfs over `/run/user/<uid>` with only the
Wayland socket (already restricted), PipeWire, PulseAudio and the broker socket
bound back; tmpfs over `/tmp/.X11-unix` plus `unset DISPLAY`
([LEAK-MODEL](LEAK-MODEL.md) §7), with a container-own `xwayland-satellite` for
programs granted `x11`; optionally tmpfs over `/run/dbus`. Private homes
already get all of it through bwrap; overlay containers get it once the broker
exists.

### 6.2 Broker

One socket per container, bound into its runtime directory. One verb: "open
this" (a URI, a file handed over by fd, or a launcher id). The host side knows
the origin container:

- target assigned to the **same** container → start it there, no dialog;
- a locked container → only the same container;
- otherwise → the picker, with the origin in the question.

Entry points inside the container: `xdg-open`/`$BROWSER` resolve to the broker
client; the delegation in `launch.rs` step 1 goes to the broker; portals stop
getting `OpenURI`/`OpenFile` through the bus proxy (`--call` rules per portal
interface). GTK, Qt and Firefox under `/.flatpak-info` call the portal and do
not fall back to `xdg-open`, so a portal-compatible front for `OpenURI` is
needed first. **Open research item**, VM prototype before any promise.

## 7. Limits without root

- **No global interception of `exec`.** fanotify permission events, LSM and
  eBPF hooks need `CAP_SYS_ADMIN`/`CAP_BPF` in the initial user namespace.
  seccomp user notification would need `NO_NEW_PRIVS` on the whole session,
  which breaks every setuid helper (`sudo`, and `newuidmap`, which zones depend
  on), and still does not reach the children of `systemd --user`.
- **No per-process network policy on the host.** cgroup BPF and `net_cls`
  need root. A network is only ever a namespace.
- **A running process cannot be moved** into another network or container;
  `setns` acts on the caller (I2).
- **A host interface cannot be moved into a container** without
  `CAP_NET_ADMIN` in the host's network namespace (§3.3). Traffic *through* it
  is possible rootless; the interface *itself* inside needs a system helper.
- **Host files cannot change, only views of them**, and a mount point has to
  exist already: nothing can be created inside root-owned directories.
- **The host session bus cannot be filtered for host programs**, only for
  containers, through a proxy.
- **Kernel modules** (`amneziawg`, `nf_tables`) cannot be loaded from a user
  namespace, and `/etc/subuid` needs the administrator once.
- **Programs with compiled-in trust or their own runtime** (Flatpak, Steam's
  pressure-vessel, AppImages, `webpki-roots`) cannot be given a trust layer
  from outside ([CERTIFICATES.md](CERTIFICATES.md) §2).
- **Entries in the user's own applications directory** can only be taken over
  by rewriting them, and a program that rewrites its entry wins for the moment
  until it is taken over again ([LAUNCHERS.md](LAUNCHERS.md) §3.2).

## 8. Declarative configuration (home-manager module options)

The options belong to the **home-manager** module (`homeModules.default`) and
are set in the home configuration of the user they apply to; the NixOS module
has none of them (its `programs.cellward.enable` only adds the home-manager module to
every home-manager user, with `programs.cellward.enable` on by default). The options were
`programs.vpn-zones.*`; the old names still work, with a warning. Declared values are
written into `~/.config/vpn-zones/declared/` of that user (read-only store links) and take
precedence over local state; the CLI and the GUI show them as "set in Nix" and
refuse to change them.

```nix
programs.cellward = {
  enable = true;

  launcher.mode = "picker";              # picker | per-zone (deprecated) | both (deprecated) | off
  defaults = {
    network = "offline";                 # offline | unconfined | <zone>
    container = "own";                   # own | ask | main | <container>
  };
  compositorRestriction.enable = true;
  hermetic.default = true;               # and hermetic.exceptions = [ "<zone>" ]
  zoneX11 = [ ];                         # zones whose programs get an X server of their own

  containers.work = {
    home = "private";                    # private | overlay
    network = "nl";                      # <zone> | unconfined | offline | ask
    apps = [ "firefox" "org.telegram.desktop" ];
    permissions = {
      paths = [ ];                       # e.g. [ "~/.wine" ] — private homes only
      x11 = false;
    };
    trust = {                            # CERTIFICATES.md
      certificates = [ ./certs/some-root-ca.pem ];
      acknowledgeRisk = true;            # required when certificates is non-empty
    };
  };

  autostart.unassigned = "ask";          # ask (the default) | offline | as-is
  interception.userEntries = "take-over";  # take-over | leave — LAUNCHERS.md §3.2
  desktop = {                            # the window menu's key and our windows' rule
    windowMenu.key = null;               # e.g. "Mod+Shift+V", niri's notation
    niri.enable = false;
    sway.enable = false;
  };
};
```

A zone through an interface of the host is a zone like the others, made from a
`[HostInterface]` file with `cellward add` — not an option. Named extra routes
beside a network and filesystem presets (`downloads`, `documents`) are not
there; `permissions.paths` is what a private home is given.

- Zones themselves are not declared: a zone config is a private key and must
  never enter the Nix store. A declared container naming a network that does
  not exist is a launch-time refusal (I6), not an evaluation error; a value that
  cannot be a network name at all is one (the option's type).
- Declared values are written below `~/.config/vpn-zones/declared/` whatever
  `xdg.configHome` is: that is the path every reader reads.
- Assertions: `trust.certificates != []` requires `acknowledgeRisk`; one
  program in two containers' `apps` is an error; `permissions.paths` on an
  `overlay` home is an error (it does not apply), and so is a path that is
  neither absolute nor `~/…`.

## 9. Machine-readable state

`cellward status --json` prints everything; `cellward container list --json`
and `cellward container show <name> --json` print subsets of the same schema.

- **`schema_version`** is in every document. Within a version changes are
  additive only; removing a field or changing its meaning is a new version and
  a CHANGELOG entry.
- **Every settable value carries its origin**: `{"value": …, "source": "nix" |
  "local" | "default"}`. Runtime facts (`running`, `up`, `handshake_age_s`) are
  plain values.
- **`networks[].restart_needed`**: for a zone that is up, the names of the
  settings it takes when it comes up (`hermetic`, `nix_daemon`,
  `host_files_writable`, `audio_manager`) whose value now differs
  from the one it came up with — in force after `cellward down <zone> &&
  cellward up <zone>`; `[]` when all are in force; `null` when the zone is
  down, or was started by a build from before the note (`build: "previous"`).

```json
{
  "schema_version": 1,
  "defaults": {
    "network":   { "value": "offline", "source": "default" },
    "container": { "value": "own",     "source": "nix" },
    "launcher_mode": { "value": "picker", "source": "default" },
    "compositor_restriction": { "value": true, "source": "default" },
    "wayland_proxy": { "value": true, "source": "default" },
    "frames": { "value": true, "source": "default" },
    "frame_width": { "value": 4, "source": "default" },
    "frame_title": { "value": "always", "source": "default" },
    "autostart_unassigned": { "value": "ask", "source": "default" },
    "user_entries": { "value": "take-over", "source": "default" },
    "hermetic": { "value": true, "source": "default" }
  },
  "networks": [
    { "name": "unconfined", "kind": "unconfined", "aliases": ["direct"],
      "source": "default", "up": true, "locked": false, "tunnel_alive": null,
      "handshake_age_s": null, "rx_bytes": null, "tx_bytes": null,
      "interface": null },
    { "name": "nl", "kind": "wireguard", "aliases": [], "source": "local",
      "up": true, "locked": false, "tunnel_alive": true,
      "handshake_age_s": 42, "rx_bytes": 1048576, "tx_bytes": 524288,
      "interface": null,
      "hermetic":            { "value": true,  "source": "default" },
      "nix_daemon":          { "value": false, "source": "default" },
      "host_files_writable": { "value": false, "source": "default" },
      "microphone":          { "value": "ask", "source": "default" },
      "screencast":          { "value": "ask", "source": "default" },
      "audio_manager":       { "value": false, "source": "default" },
      "frame_color":         { "value": "#4cacd9", "source": "default" },
      "build": "current", "restart_needed": ["nix_daemon"] },
    { "name": "lan", "kind": "host-interface", "aliases": [], "source": "local",
      "up": false, "locked": false, "tunnel_alive": null,
      "handshake_age_s": null, "rx_bytes": null, "tx_bytes": null,
      "interface": "enp4s0" }
  ],
  "containers": [
    { "name": "work", "selector": "work",
      "home":    { "value": "private", "source": "nix" },
      "network": { "value": "nl",      "source": "local" },
      "routes":  { "value": [],        "source": "default" },
      "apps":    [ { "value": "firefox", "source": "nix" } ],
      "permissions": {
        "filesystem": { "value": ["downloads"], "source": "nix" },
        "paths":      [ { "value": "/home/u/.wine", "source": "nix" } ],
        "x11":        { "value": false,         "source": "default" },
        "compositor": { "value": "restricted",  "source": "default" }
      },
      "trust": [ { "sha256": "…", "subject": "CN=…",
                   "not_after": "2030-01-01T00:00:00Z", "source": "nix" } ],
      "running": [ { "app": "firefox", "pid": 1234, "network": "nl" } ],
      "x11": { "value": false, "source": "default" },
      "frame_color": { "value": null, "source": "default" },
      "microphone": { "value": null, "source": "default" },
      "screencast": { "value": null, "source": "default" },
      "camera": { "value": null, "source": "default" },
      "devices": [ { "value": "security-keys", "source": "local" } ],
      "links": [ { "scheme": "https", "program": "firefox", "source": "local" } ] }
  ]
}
```

Written by hand like the manifest is read by hand (no `serde`); a test pins
every key of version 1.

**Keys to join on — part of the version 1 contract:**

- a container is identified by its **`selector`**, never by `name`: a layer
  over the home and a home of its own could share a name (`work` and `sb:work`
  were two containers). Every reference to a container elsewhere in the
  document — `apps[].container.value` — is a selector, and
  `containers[].selector` is what it matches. Since one name per container
  (2026-09-26, [PERMISSIONS.md](PERMISSIONS.md) §11.7) the selector IS the
  name — `sb:` is not written any more — and `home` has the value `main` for a
  container of the real home (a layer is still `overlay`). **A reader must
  take a `home` value it does not know as "not isolated"**: `main` is the
  whole real home, and a tool that showed an unknown kind as a home of its
  own would show the real home as isolated;
- a network by `name`; `networks[].kind` is one of `unconfined`, `offline`,
  `wireguard`, `openconnect`, `host-interface`, `system-zone`, and `interface`
  is the host's interface for `host-interface` and `null` for every other kind
  — a `host-interface` network is NOT encrypted by this project; `system_zone`
  is the system zone whose tunnel a `system-zone` network goes out by
  (`docs/SYSTEM.md` §7b) and `null` for every other kind (added 2026-09, an
  additional key: version 1 is unchanged for readers that ignore unknown keys);
- `networks[].aliases` are the other names a network is read by. The only one
  is `direct` on `unconfined`, its name until 2026-09: it is accepted in the
  CLI, in Nix (`defaults.network`, `containers.<n>.network`), in pins and in
  settings written before the rename, and never appears as a value anywhere
  in the document — every `network.value` and `apps[].network.value` says
  `unconfined`;
- a program by its launcher key (`apps[].id`, `containers[].apps[].value`),
  the lossless key of `docs/LAUNCHERS.md` §3.4.

**`uplink_owner`** (`{uid, gid}` or `null`) is for a host egress policy: every
socket a zone's traffic leaves the host by — pasta's, the OpenConnect
client's — belongs to the zone's uid 0, the start of the user's subordinate
ranges, so `meta skuid <uid>` in the host's nftables lets the zones out and
nothing else of the user. Stable as long as `/etc/subuid` is; note that a
rootless container tool mapping its own uid 1 onto the same subordinate uid
would match too.

## 10. Where can a packet or a DNS query go around the tunnel now?

- **Changeable networks (I1, I2).** A change is explicit and shown; a
  container never runs in two networks at once. The identity channel of
  [LEAK-MODEL](LEAK-MODEL.md) §4 is narrowed to a deliberate act.
- **Networks through a host interface** (done). pasta in the app namespace
  binds every socket to one interface of the host; the app namespace is the
  same two-link namespace (`lo` and `awg0`) as for a tunnel, with the same
  filter, so nothing inside can pick another way out, and an interface that
  goes down means no network rather than another route. pasta forwards no
  ports. What this network does not do is encrypt: it is named as such
  everywhere it is shown (`host-interface`).
- **Extra routes.** Each is a hole by definition — explicit, per prefix, off by
  default, listed in every view and in `doctor`.
- **`unconfined` containers** (done). No network namespace — the host's network and
  resolvers, and the name says so. The user namespace grants nothing over the
  host's netns.
- **Per-launch mount namespace, path grants.** No network change. A granted
  directory is a data channel between the container and everything that sees
  the same directory — deliberate, listed in `container show` and the JSON.
  The allow-list keeps it from being a channel to a host service: no socket
  directory (`/run`, `/tmp`) can be granted, so neither the unfiltered D-Bus
  nor the host's X11 or resolver becomes reachable through a grant.
- **`cellward launch`, shims, autostart, D-Bus shadows, taken-over entries.**
  They only start the picker or `cellward run`; no new socket, no new route.
  D-Bus shadows (done) close a path: activating a program by its bus name
  started it in the host's network, uncontained.
  Autostart (done) closes a path: a program that switched its own autostart on
  used to start at login in the host's network, uncontained; now it starts
  where it was put, or offline.
- **Broker.** A guarded door replacing the unguarded `systemd --user` path.
- **JSON output.** Names zones and containers to processes of the user; inside
  a private home the state directory is not visible at all.
- **Trust layer.** A MITM channel with its own analysis:
  [CERTIFICATES.md](CERTIFICATES.md) §5.

## 11. Phases and tests

| phase | content | proof |
|---|---|---|
| 0 | **done**: `direct` keeps its layers, working directory, conflict by id and binary, hidden handlers, Steam children | smoke; unit and scenario tests |
| 1 | **done**: network binding with I1/I2 in `run` and the picker, `cellward container list/show/set/assign/unassign`, `status --json` (`schema_version`, sources), home-manager options with `declared/`, clones deprecated, path grants (`container grant/revoke`, `permissions.paths`), merge (`container merge`). **Left**: `own` by default, hints (Wine prefix, Steam), container-first picker, GUI entries | CLI/picker scenario tests; VM: a declared container with its declared CA, refused elsewhere, reported as Nix |
| 2 | trust layer ([CERTIFICATES.md](CERTIFICATES.md)) — **done** (GUI dialog left) | VM and smoke: synthetic CA trusted in one container only |
| 3 | **done**: user-dir take-over, autostart take-over (§5.2). `cellward launch` (§5.1), D-Bus shadows (§5.3). web apps as children, host-interface networks (§3.3). **Left**: PATH shims | VM: activation via `gdbus call` lands in the container; autostart of an unassigned program is offline |
| 4 | runtime hermeticity, broker, X11 closure, extra routes | VM "evil host": a `systemd --user` counting `StartTransientUnit`, a portal logging callers, an HTTP beacon |

## 12. The owner's decisions (2026-09-17)

1. **Networks and containers change independently**, and a container's network
   can be any interface, not only the zones of this project → I1/I2 (explicit
   change, no two networks at once), §3.3 (host interfaces rootless through
   pasta; an interface itself only with a system helper), extra routes as
   explicit holes.
2. **A home of its own for every program, with merging** →
   `defaults.container = own`, §3.4, §3.5.
3. **Everything in containers, including entries in the user directory** →
   take-over in place with a backup ([LAUNCHERS.md](LAUNCHERS.md) §3.2, with the
   cost and risk per kind of entry); the invariant changes in its own commit.
4. **Unassigned autostart: offline, no dialog, a notification** → §5. Changed
   2026-09-24: the picker asks (`ask`), the closed variant stays as `offline`.
5. **Per-zone clones deprecated now** → [LAUNCHERS.md](LAUNCHERS.md) §4.
6. **`feat/openconnect-backend` merged first** → done.
