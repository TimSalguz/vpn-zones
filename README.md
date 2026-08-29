# vpn-zones

Читать по-русски: [README.ru.md](README.ru.md) · Development plan: [ROADMAP.md](ROADMAP.md)

Launch programs with a choice of network, data container and sandbox — straight
from the app's launcher entry. Everything runs as your user: root is not needed
either to create a zone or to launch, and no system configuration changes are
required.

You click a launcher entry — it asks which network to run in (through which VPN,
without VPN, or with no network at all) and in which environment (shared with
the system, a separate data container, or a sandbox). The choice is remembered
and can be pinned.

## What it does

Three independent layers, each enabled on its own.

**Network.** A zone is a network namespace brought up as your user: kernel
WireGuard/AmneziaWG inside, `pasta` from passt facing outward. There can be any
number of zones, each with its own config. There are built-in "direct internet"
and "no network" options — the latter means the literal absence of a route, not
a firewall rule.

**Data.** Five modes:

| mode | program's home | what it sees |
|---|---|---|
| main | your real `$HOME` | everything as usual |
| container | overlayfs on top of the XDG directories | sees your settings, writes to a layer |
| per-app sandbox | persistent, this program only | nothing of yours |
| named sandbox | persistent, shared | programs launched in it |
| throwaway sandbox | tmpfs, wiped on exit | nothing of yours |

The container exists first and foremost to break up singletons: without it, a
browser launched a second time simply hands its window to the already running
process — and the traffic goes through the old network while looking perfectly
normal.

**Isolation.** The compositor can tell clients apart via
`wp_security_context_v1`: programs launched through the tagged socket are not
given screen capture, background clipboard reading, keyboard and mouse
emulation, or the list of other windows. Measured before and after — 47
protocols versus 33.

Separately there is a filesystem sandbox on `bwrap`: an empty directory instead
of `$HOME`, the bus through `xdg-dbus-proxy` (no Secret Service), and a
`/.flatpak-info` planted inside — GTK/Qt/Chromium use it to figure out they are
in a sandbox and start going through the portals for files and the camera on
their own. If a program needs X11, it gets its own `xwayland-satellite` so it
cannot see other windows.

## Requirements

- a compositor supporting `wp_security_context_v1` — tested on **niri** and
  **KWin**; Mutter (GNOME) does not have the protocol, so the compositor
  isolation layer will not work;
- unprivileged user namespaces (`kernel.unprivileged_userns_clone`);
- a range in `/etc/subuid` and `/etc/subgid` for your user — NixOS hands them
  out to regular users by default;
- `/dev/net/tun` with read and write access;
- for VPN zones — the `wireguard` or `amneziawg` kernel module;
- working XDG portals (for the filesystem sandbox).

Check readiness:

```sh
sysctl kernel.unprivileged_userns_clone   # 1
grep "^$USER:" /etc/subuid                 # range exists
ls -l /dev/net/tun                         # crw-rw-rw-
```

## Supported environments

Most of the project does not depend on the desktop at all: the zones and the
tunnel, DNS, the data containers, the filesystem sandbox with its seccomp
filter, the `.desktop` interception (a freedesktop standard) and the portals —
any backend will do. Two things do depend on it: the compositor layer and the
dialogs.

| environment | state |
|---|---|
| **Plasma 6, Wayland** | every layer, out of the box |
| **niri / sway / wlroots, Wayland** | every layer — the development platform |
| **GNOME, Wayland** | works, minus the compositor layer: Mutter has no `wp_security_context_v1`, so `wl-sandbox` starts the program unrestricted and says so on stderr. Mitigating: Mutter hands out no `wlr-screencopy`, `data-control`, `virtual-keyboard` or `foreign-toplevel` either — most of what that layer takes away does not exist there. Dialogs are Qt and look foreign |
| **any X11 session** | the network and the filesystem are isolated, the display is NOT: the host's X socket is reachable from inside a zone, and one client there sees every window, keystroke and clipboard on the machine. Not recommended |
| **not NixOS** | same logic, different packaging: nix plus standalone home-manager (a plain package is planned), unprivileged userns (on Ubuntu 24.04 also `sysctl kernel.apparmor_restrict_unprivileged_userns=0`), subuid/subgid, and `amneziawg` through DKMS — or the in-tree `wireguard`, which is supported as a fallback |

Check the compositor:

```sh
wayland-info | grep -i security_context   # the protocol is there
```

`kdialog` is installed by the module itself, so no KDE session is needed —
only the binary. A zenity/kdialog abstraction is on the roadmap (M6), and so is
naming the degraded layer in `vpn-zone doctor` instead of on stderr alone.

## Installation

```nix
{
  inputs.vpn-zones.url = "github:TimSalguz/vpn-zones";

  # in home-manager
  imports = [ inputs.vpn-zones.homeModules.default ];
  programs.vpn-zones.enable = true;
}
```

After a rebuild, the launcher gets the entries "Add VPN zone", "Remove VPN
zone", "Create container", "Remove profile", "VPN zone settings" and "Reset app
networks".

## How to use it

Create a zone: the **"Add VPN zone"** entry → pick a `.conf` → give it a name.
The system tells you whether the handshake went through — that is, whether the
config is alive.

Then just launch programs from the launcher. The same from the terminal:

```sh
vpn-zone list                                  # zones and their state
vpn-zone up <zone> / down <zone>
vpn-zone check <zone>                          # is the tunnel alive
vpn-zone run <zone> -- firefox                 # run in a zone
vpn-zone run <zone> --profile work -- firefox  # + data container
vpn-zone run <zone> --sandbox work -- firefox  # + named sandbox
vpn-zone run <zone> --fs-sandbox -- firefox    # + throwaway sandbox
vpn-zone run <zone> --tmp-profile -- firefox   # one-off container

vpn-zone profile create|list|rm <name>
vpn-zone sandbox create|list|rm <name>
vpn-zone perms list|reset <app|--all>          # granted file accesses
vpn-zone lock|unlock <zone>                    # forbid leaving for other networks
vpn-zone default-profile ask|main|own|<name>
vpn-zone mode picker|per-zone|both|off         # how launcher entries behave
```

## What this does not replace

Flatpak. Its syscall filter is what the one here is modelled on, and it also
has its own runtime and ready-made rules for thousands of applications.
Here packages come from nixpkgs (no duplication and no runtime),
but the rules for each program have to be worked out on your own — though you
can peek at the same program's manifest on Flathub, in the `finish-args`
section.

What is missing here and what you should know:

- the sandbox does carry a seccomp filter now, modelled on flatpak's base set
  (terminal injection via `TIOCSTI`, `ptrace`, keyrings, `perf_event_open`, the
  new mount API); nested user namespaces are left allowed on purpose, otherwise
  Chromium and Electron applications would not start;
- the filesystem sandbox is enabled explicitly and needs tuning for each
  specific program;
- a zone isolates the network, not the files: without a sandbox the program
  sees your entire `$HOME`;
- tested on one machine and one set of programs.

## How it works inside

The subtleties that took the most time are commented in detail in
`module/default.nix`. The least obvious ones:

- a zone is **two** network namespaces, not one: connectivity (pasta and the
  tunnel's UDP socket) lives in the uplink one, while the namespace programs run
  in has nothing but loopback and the tunnel — a leak of any protocol family is
  impossible there because no path exists (`docs/LEAK-MODEL.md`). The interface
  is created in the uplink and moved down, because a WireGuard socket stays in
  the namespace the interface was born in;
- on top of that topology, and only as insurance against a mistake of ours,
  both namespaces get an **nftables ruleset**: nothing leaves the app namespace
  except through the tunnel, and nothing leaves the uplink except the tunnel's
  own packets to the server. A kernel that will not have it costs a warning in
  the journal, not the zone — the topology is what carries the weight;
- the zone holder needs a **double uid mapping**: `0:<subuid>:1` (otherwise
  capabilities are lost on `execve` and the interface cannot be created) plus
  `<uid>:<uid>:1` (otherwise the program does not see its `$HOME`);
- an overlayfs `upperdir` cannot live on an overlayfs — hence the separate
  storage directories;
- `mount(8)` does not work as non-root even with `CAP_SYS_ADMIN`, so mounting
  is done by calling `libc.mount` directly;
- name resolution goes to a daemon over a **unix socket**, which no route and
  no packet filter can stop: NixOS runs `nsncd`, and with `systemd-resolved`
  enabled glibc asks it first of all (`resolve` stands before `dns` in
  `nsswitch.conf`). Both sockets are hidden inside a zone — without that,
  names resolve past the tunnel and a leak test names your real ISP;
- Amnezia configs come in CRLF, and recent ones also with empty `I1`–`I5`
  parameters, on which `awg setconf` rejects the whole file.

## License

MIT.
