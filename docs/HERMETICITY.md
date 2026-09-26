# Runtime hermeticity of a zone — design and decisions to take

Русская версия: [HERMETICITY.ru.md](HERMETICITY.ru.md) · Related:
[LEAK-MODEL.md](LEAK-MODEL.md) ("open channels"), [CONTAINERS.md](CONTAINERS.md)
§6, ROADMAP M3 (hermeticity, broker, X11).

**Status: decided (the owner, 2026-09-17), implementation in progress** — see
§7 for the decisions. `cellward doctor` reports every channel below as `warn`
until it is closed, and names by path every unix socket a program of the zone
can connect to that is not the zone's own (`docs/LEAK-MODEL.md` §18).

## 1. What is open today

A program started in a zone WITHOUT a sandbox (no `--sandbox`/`--fs-sandbox`)
sees, in the zone's mount namespace, what every host program sees:

| channel | what it gives a program in the zone | LEAK-MODEL |
|---|---|---|
| `/run/user/<uid>/bus` (session bus) | `org.freedesktop.systemd1` → `StartTransientUnit`: any process OUTSIDE the zone, in the host's network; portals (`OpenURI` opens a link on the host); Secret Service (every password in the keyring); every other program's D-Bus API | §1, §2 |
| `/run/user/<uid>/systemd/private` | the same `systemd --user`, without D-Bus | §1 |
| `/run/dbus/system_bus_socket` | NetworkManager (real interfaces, SSIDs, addresses), hostname1, resolve1, machined: de-anonymisation without a packet | §3 |
| `/tmp/.X11-unix/X*`, `DISPLAY` | the host's X server: keyboard, screen and clipboard of the whole machine | §7 |
| the rest of `/tmp`, `/var/tmp`, `/dev/shm` | the host's listening sockets — a tmux server (`run-shell` runs on the host), a VPN client's IPC to a root service, single-instance sockets —, JACK, other programs' shared memory; a hermetic zone gets all three of its own (tmpfs, as Flatpak) | §15 |

The network topology cannot close any of them: they are Unix sockets, not
interfaces. Only the mount namespace can, and the sandbox already does it for
sandboxed programs — the measured cost there is "portals, notifications, tray
only".

## 2. The shape of the fix

In the zone's mount namespace (once, at zone start, so that every program in
the zone gets it — not per launch):

1. **tmpfs over `/run/user/<uid>`** — since `docs/LEAK-MODEL.md` §13 in EVERY
   zone, with the compositor's own `wayland-*` socket and its IPC never bound
   back; the restricted Wayland socket is made per launch by `wl-sandbox` on
   the host, in the zone's `vpn-zones/wayland/<zone>/` (read-only in the zone:
   a program cannot take another launch's socket's place), and served there by
   its confined proxy (`docs/WINDOW-FRAME.md` §8), which passes on only the
   launch's own processes — the compositor's own sandbox socket is in
   `vpn-zones/wl-up/`, which no zone has. The same proxy draws the zone's
   coloured border around the program's windows (§8, «Этап 2, обводка»),
   with objects of its own the program cannot name, and shows the program no
   new global; its colour, width and the switch that hides it are in
   `~/.config/vpn-zones` and the zones' state, which a zone cannot write. A
   hermetic zone gets
   PipeWire as a restricted socket of its own (a security context the
   zone's helper hands to PipeWire, a WirePlumber policy of ours deciding
   what its clients see: their own streams, the outputs, the microphones
   only on `yes`, never a monitor or a link of their own — without the
   policy no PipeWire at all; the host's raw `pipewire-0` only for a zone
   declared an audio manager, `cellward audio-manager`; where WirePlumber
   and PipeWire load scripts and fragments from in the home —
   `~/.config/pipewire`, `~/.config/wireplumber`,
   `~/.local/share/wireplumber`, `~/.local/state/wireplumber` — read-only in
   the zone and made beforehand, or a program would replace the policy;
   `docs/LEAK-MODEL.md` §20), PulseAudio (the `pulse-filter` socket: an
   allow-list of commands, no recording of a monitor, the microphone only by
   the zone's permission — `yes`, `no` or `ask`, the default, a question on
   the host; `docs/LEAK-MODEL.md` §17),
   and two sockets of ours: a **filtered session bus** (`xdg-dbus-proxy`) and
   the **broker**. `systemd/private` is not bound back. The proxies and the
   sound filter run in the host's user namespace, not the zone's: a
   program of the zone cannot reach the host's file system — the unfiltered
   bus in it — through their `/proc/<pid>/root` (`docs/LEAK-MODEL.md` §16).
2. **tmpfs over `/tmp/.X11-unix`** and `DISPLAY` unset in the launch
   environment; a container granted `x11` gets its own `xwayland-satellite`
   (decision A).
3. **The system bus**: one of B1–B3 below.

## 3. Decision C — the session bus and the broker

A filter with the rules of the sandbox (the desktop and document portals by name, `Notifications`,
`StatusNotifierWatcher`) applied to EVERY program of a zone breaks, measured
by what those programs use the bus for:

| breaks | who notices |
|---|---|
| Secret Service / KWallet / GNOME Keyring | browsers fall back to an unencrypted password store or ask for a password; mail and chat clients lose saved logins |
| MPRIS (`org.mpris.MediaPlayer2.*` needs `--own`) | media keys and the shell's player widget do not see players in the zone |
| tray icons of Electron and Qt (they own `org.kde.StatusNotifierItem-<pid>-<n>` first) | no icon, and a program that closes to the tray cannot be brought back from it — allowed since 2026-09-24 by `--own=org.kde.StatusNotifierItem-*`, a rule of our patched proxy that owns and nothing more |
| IBus / fcitx5 input methods | typing in a second layout through an input method stops working in zone programs |
| KDE global shortcuts (`org.kde.kglobalaccel`) | shortcuts registered by zone programs do nothing |
| dconf / GSettings writes (`ca.desrt.dconf`) | GTK programs cannot save settings (they fall back to memory) |
| `systemd --user` | **by design** — including today's delegation of a launch out of a zone (`launch.rs` step 1), hence the broker |
| D-Bus activation of other programs | a zone program cannot start a host program by name — also by design |

Each row can be allowed back per container (`permissions.dbus`, like
Flatpak's `finish-args`) — except `systemd1`, which is the escape itself.

**The broker** replaces the delegation: one socket per zone (the target:
one per container launch, [PERMISSIONS.md](PERMISSIONS.md) §11.9), one verb —
"open this" (a URI, a file passed by descriptor, a launcher id). The host side
knows which zone asked, and answers:

- the target is assigned to the same container → start it there, no dialog;
- the zone is locked → only the same container;
- otherwise → the picker, with "asked by zone X" in the question.

**"Always" (2026-09).** The question has three answers: allow, *always*, refuse. "Always"
is remembered as zone → network → program in `~/.config/vpn-zones/broker-always`, one
`origin<TAB>target<TAB>program` per line, and the next such launch goes on without a
question. The program is the command's first word as the host resolves it — its directory's
links followed, its own name kept, since `touch` and `cat` are links to one coreutils — and
"always" is offered only when that path and the file it finally is are both in the store,
where nothing in a zone can write: a program in `~/.local/bin` could be replaced by a
program in the zone and would make "always" a standing door. The name a launch gives itself
(the app-id) is not trusted — the program that asks sends it.

**The choice from a zone (2026-09-25).** The picker a program in a zone starts (a link it
opens) sees none of the zones — the project's state is hidden from zones — and a window a
zone draws is one its programs could draw too. So it asks the broker (`VZP1`, the app-id and
the command), and the broker shows the launch window on the host (`vpn-zone-pick
--from-zone`): the asking zone in the title; the command in a block of its own, word by word
and numbered, with the program as the host finds it (flagged when it is not from the store);
the asking zone chosen and the host's network last; a locked zone offered only itself; no
"always" and no new container (the zone picks which launcher's name the window carries).
Nothing is decided without the window — a pin or a running copy only choose where it starts.
The window takes nothing — no key, no click, no choice — until the person has been still for
`dialog::TOO_FAST` with it focused: every key (a widget's too), every press and the focus
coming back start that again, and so does a changed choice. Enter starts only in the asking
zone; another network takes a click on the button that names it; digits choose nothing. The
answer comes back as `run`'s arguments; the broker checks it is the request's own command
word for word (and, from a locked zone, that zone), that it did not come sooner than a person
could read the window, and starts it. The window is the question: no second one. The program
is found once, by the broker, before the window: the window shows that absolute path, and it
is what runs — `run` looks nothing up again by PATH, where a link in the home could be
pointed elsewhere while the window is open; a shell or an interpreter is flagged as running
any command, a program outside the store as replaceable. A question not answered in two minutes is closed (`cellward question-timeout <term>|never`, Nix
`questionTimeout`; never: no limit). A zone that keeps asking is asked at most four times a minute and not at
all for 15 s after a "no"; a request is refused whole past 64 KiB or an app-id past 255
bytes; there is no time limit for it to arrive (2026-09-26, was 5 s), and a connection that says
nothing holds a slot of its own zone: one zone holds at most four requests at once (64 in
all), and puts at most 30 lines a minute into the journal, the record of crossings. (Review 2026-09-25, which also found the socket systemd passes the broker
inherited by every program it started: it is close-on-exec now.) A container of the host's network (`unconfined` in
`VPN_ZONE_CURRENT`) is no zone to the broker and keeps its own picker, as does a zone
without a broker to ask.

Inside the zone `xdg-open`/`$BROWSER` resolve to the broker client, and the
portal's `OpenURI`/`OpenFile` are filtered out of the bus proxy (`--call`
rules) so that GTK/Qt fall back to `xdg-open`. Firefox and GTK under
`/.flatpak-info` call the portal and do NOT fall back — a portal-compatible
front for `OpenURI` is needed first; that is the research part.

**Proposed order** (nix-cm-eb recommends it too): a prototype behind a
per-zone flag `hermetic = true`, OFF by default, proven in the VM by an "evil
host" — a `systemd --user` path that counts `StartTransientUnit` calls, a
portal that logs its callers, a beacon on the host's loopback — before it
becomes a default, with the table above as the list of what the owner accepts.

## 4. Decision B — the system bus

| option | how | cost |
|---|---|---|
| B1 | tmpfs over `/run/dbus` in the zone | UPower (battery), logind inhibitors (a player keeping the screen on), NetworkManager applets inside zones stop working |
| **B2 (recommended)** | `xdg-dbus-proxy` for the system bus: `login1` and `UPower` allowed, `NetworkManager`, `hostname1`, `resolve1`, `machined`, `timedate1` denied | one proxy process per zone, started and supervised by the zone holder like pasta |
| B3 | as is, `warn` in `doctor` | NetworkManager answers "which networks is this machine on" to any zone program |

## 5. Decision A — X11

| option | behaviour |
|---|---|
| **А (recommended)** | closed by default in zones; a container with the `x11` permission gets its own `xwayland-satellite`, like the sandbox |
| Б | closed by default; an explicit `x11 = "host"` hole per container |
| В | as is until А is implemented |

## 6. What is not in question

- The sandbox already has all of this and keeps it.
- Environment variables are not a boundary (`unset DBUS_SESSION_BUS_ADDRESS`
  changes nothing: socket paths are well known). Only the mount closes.
- None of it is a network change: no packet goes anywhere new; what changes is
  which host services a zone program can ask to act for it.

## 7. Decisions (the owner, 2026-09-17)

- **A — X11: option А — implemented.** Closed in zones by default: tmpfs over
  `/tmp/.X11-unix` in the zone's mount namespace and no `DISPLAY` in a launch.
  A container with the `x11` permission gets its own `xwayland-satellite`.
  There is no `x11 = "host"` hole. The same per zone, for zones without
  containers: `cellward x11 <zone> on` or `zoneX11 = [ "<zone>" ]`.
- **B — the system bus: B2, narrowed — implemented.** `xdg-dbus-proxy` per zone; `UPower`
  allowed; `login1` only `Inhibit` and reading properties — no session list,
  no power management; `NetworkManager`, `hostname1`, `resolve1`, `machined`,
  `timedate1` denied.
- **C — the session bus and the broker.** The prototype first, behind a
  per-zone flag `hermetic`, proven by an evil host in the VM — **the prototype
  is implemented** (`cellward hermetic <zone> on`); what follows is not yet.
  Then:
  1. `hermetic` becomes the default; switching it off is explicit and per
     zone (a zone whose programs legitimately drive `systemd --user`, such as
     one running agents that start VM checks with `systemd-run --user`).
     **Implemented, and the default flipped (2026-09):**
     `hermetic.default` and `hermetic.exceptions` in the module,
     `cellward hermetic --default on (default)|off` and
     `cellward hermetic <zone> default (as all zones)|on|off` locally. What wins: a zone in
     `hermetic.exceptions` (the opposite of `hermetic.default`, which the
     module requires with it), then the zone's own setting, then
     `hermetic.default`, then the local default, then on. Only `off` opens
     anything: the prototype's empty marker, an unreadable one and any other
     content mean on. The holder decides once, when the zone comes up;
     `status --json` shows `defaults.hermetic` and `networks[].hermetic`, each
     with its source;
  2. bus permissions come from the program's Flathub manifest
     (`finish-args`: `--talk-name`, `--own-name`, `--system-talk-name`) when
     it has one, so that the filter does not break known programs;
     `permissions.dbus` is for the rest;
  3. the Secret Service the way Flatpak's Secret portal does it: a key of the
     container's own, never the host's whole keyring;
  4. MPRIS and input methods (IBus, fcitx) allowed by default; dconf writes
     and KDE global shortcuts by a per-container permission.
- `own` for everything (decision №2 of CONTAINERS §12) is a sandbox, i.e.
  Flatpak-like isolation without `hermetic`; the flag closes the rest: overlay
  containers, the main profile, launches without a sandbox.
