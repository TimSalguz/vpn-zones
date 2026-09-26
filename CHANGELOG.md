# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- **The waits kept on purpose are settings** (the owner, 2026-09-27:
  adjustable in stillconf; `rust/src/timings.rs`). How long a question of
  the broker's waits for its answer — `cellward question-timeout
  <term>|never`, `programs.cellward.questionTimeout`, 2m unless set; never:
  as long as it takes, the next questions refused meanwhile — and how long
  the zone-adding dialog waits for the first handshake before it says
  whether the tunnel is alive — `cellward handshake-check <term>`,
  `programs.cellward.handshakeCheckAfter`, 6s unless set. Both in
  `status --json` (`settings.question_timeout`, `settings.handshake_check`,
  with their source). On the system side: the grace a `vpn-zone-sys`
  command gets after its client went, before SIGKILL
  (`services.cellward.system.stopGrace`, 5s unless set), and a system
  zone's start timeout (`services.cellward.system.startTimeout`, systemd's
  own unless set; `infinity`). The microphone question keeps its 25 s:
  libpulse gives up on a stream after 30, and a later "yes" would open the
  microphone for a request nobody waits on.
- **A container's windows have a frame colour of its own**
  (`programs.cellward.containers.<name>.frameColor`, `cellward container
  set <c> color default|<#rrggbb>`, `containers[].frame_color` in
  `status --json`; `docs/PERMISSIONS.md` §11.10 — the owner, 2026-09-26:
  the colour moves from zones to containers too). A container with none is
  framed in its network's colour, as before.
- **A container's microphone setting of its own** (`programs.cellward.
  containers.<name>.permissions.microphone`, `cellward container set <c>
  microphone default|yes|no|ask` — `default`, none of its own, is the
  zone's setting —, `containers[].microphone` in `status
  --json`; `docs/PERMISSIONS.md` §11.10). The sound filter now knows which
  container a program that connects is of — the same way the broker does,
  by the launch it descends from (`rust/src/origin.rs`) — and decides its
  record streams by that container's setting. Which word wins: Nix's for
  the container, Nix's for the zone, the container's local one, the zone's
  local one, `ask`; a local setting never overrides a declared one. The
  question names the container, and "always" writes `microphone = yes` into
  the container's settings, not the zone's; for a program with no container
  it is still the zone's. The restricted PipeWire of a hermetic zone decides
  by the container of each client too: its helper sees every client in the
  daemon's registry (the pid the daemon read from the kernel, and a serial
  no other client has), tells whose program it is the same way, and
  publishes a key per client (`vpn-zones.microphone.client.<serial>`,
  with `vpn-zones.microphone-by-client.<zone>` = the serial of the
  helper's own client); the WirePlumber policy decides by it while that
  client is there, holding a new client until its key comes — it asks
  (`vpn-zones.microphone.pending.<serial>` = the zone), and the helper
  answers every request of its zone, a client it cannot tell the
  container of by an unknown one's setting. No clock decides: the key lets
  a client go, and the helper's client gone lets the zone's key decide. The zone's key stays for a policy of before: the
  strictest of the zone and of every container launched into it since it
  came up. The
  nearest launch in a program's ancestry decides, a throwaway one too; a
  number two launches' records claim is nobody's.
- **A container of the main home takes a mount namespace of its own** in a
  zone, with nothing mounted in it (`launch::Entry::own_mounts`): the
  zone's own namespace is then only its programs with no container, and
  one that leaves a container's launch (a daemon that forked twice) is
  never taken for them — by the sound filter or the broker. Programs of a
  container of the main home started before this update still run in the
  zone's own namespace until they are started again.
- **What a zone binds into its runtime directory later reaches containers
  already running** (`zone::seal_runtime`, `launch::entry_argv`): the
  zone's `/run/user/<uid>` is a shared mount, and a container's launch takes
  a slave copy of the zone's mount namespace (`--propagation slave`, was
  `private`). A socket or directory the host creates after the zone came up
  — in an ordinary zone PipeWire and the session bus after the host
  restarts them — used to stay out of reach of programs of a container
  started before; nothing a container mounts goes back to the zone. (A
  mount the host makes later on such a directory, as the document portal's
  FUSE, still does not reach the zone at all.)

- **`networks[].restart_needed` in `status --json`**: for a zone that is
  up, the settings it takes when it comes up (`hermetic`, `nix_daemon`,
  `host_files_writable`, `audio_manager`) whose value changed
  since it came up — in force after a restart; `[]` when all are in force,
  `null` when down or not known. The holder notes what it came up with
  (`zone.settings`, `hermetic::APPLIED`) before the zone is up.

- **A container's screen cast setting of its own** (`programs.cellward.
  containers.<name>.permissions.screencast`, `cellward container set <c>
  screencast default|yes|no|ask`, `containers[].screencast` in `status
  --json`; `docs/PERMISSIONS.md` §11.10). The hermetic zone's bus filter
  knows the container of each connection — as the sound filter does, the
  zone's own mount namespace being its own, the registry and the settings
  read through descriptors held before the zone covers them — and judges
  every ScreenCast call by that container's switch, by the microphone's
  rule; a refusal names the container. A container's `yes` keeps no choice
  yet: the portal knows every connection of the zone by the zone's name,
  and a choice kept under it would be every container's. A process whose
  `/proc` is out of a helper's reach (a sandbox's own bus filter is not
  dumpable) is known by its launch alone (`origin::Peer::mnt` optional),
  never taken for one of the zone's own without its namespace read.

- **A container's camera setting of its own** (`programs.cellward.
  containers.<name>.permissions.camera`, `cellward container set <c> camera
  default|on|off`, `containers[].camera` in `status --json`;
  `docs/PERMISSIONS.md` §11.10). A zone now covers the host's cameras for
  all its programs, whatever its own setting; a launch the cameras are let —
  by its container's setting, the zone's for a launch with none — takes the
  covers off in its own mount namespace (`profile-run --camera`), and a
  sandbox binds the camera nodes into its own `/dev` (`fs-sandbox --camera
  on`). The zone's `/dev` is a shared mount, each launch a slave of it: a
  camera plugged in later is covered in every launch, a launch let the
  cameras included (restart the program for it): parting its `/dev` from
  the zone's would let a security key or a serial adapter plugged in later
  reach it uncovered. Not
  a wall between the programs of one zone: while such a launch runs,
  another program of the zone outside a sandbox reaches its `/dev` through
  `/proc/<pid>/root` (hidden processes per launch are to come). The
  zone's camera setting applies from the next launch on: no restart of the
  zone (and `camera` is no longer in `restart_needed`).

- **Links on behalf of a container** (`docs/PERMISSIONS.md` §11.13): a link a
  program of a hermetic zone (or of a sandbox) opens goes from the bus filter
  to the broker on the host, not to `xdg-open` in the zone. The program is
  the distribution's to offer: the portal backend's window of choice
  (`AppChooser`, called on the implementation, which starts nothing; the
  backend the portal configuration names for it, else GNOME, KDE, GTK, else a
  kdialog menu) with the programs that claim the scheme, the distribution's
  default first — no window where only one program does. The container and
  the network are CellWard's: the launch window, as for any launch a zone
  asks for; an entry CellWard does not take over (a symlink) runs in the
  asking zone at once, as before. "Always" is per container: a checkbox of
  its own in the launch window keeps a rule `link = <scheme> <id>`
  (Nix `containers.<name>.links`, `cellward container links <c> [set|rm]`,
  `containers[].links` in `status --json`) which skips the choice of the
  program only. The container is the zone's filter's word for the
  connection, believed from that filter alone (its parent is the zone's
  process); the host's default applications are never changed. The filter
  answers the portal call at once and hands the link over in a thread of
  its own: the program's bus goes on while the person chooses.
- **A `/dev` of the zone's own, and terminals of its own**
  (`docs/PERMISSIONS.md` §11.12, `docs/LEAK-MODEL.md` §19): the zone's
  `/dev` is a tmpfs with only the basics and the GPU bound in from the
  devtmpfs, which the zone keeps at `/dev/.cellward/devtmpfs` (a directory
  only its root enters). Covering nodes on the shared devtmpfs left a
  device plugged in later bare in a mount namespace a program made private
  (`unshare -Urm`); now it appears in none. `/dev/pts` is a devpts instance
  of the zone's: the host's showed every terminal of the host's to a
  program that is their owner — it could read what is typed into one or
  write a fake prompt. A program started into a zone from a host terminal
  keeps that terminal but has no name for it (`tty`: "not a tty"). A
  device given to a launch, and the cameras, are bound onto an empty
  stand-in in its own mount namespace; when the device goes the zone
  unlinks the stand-in, and the kernel takes every bind on it away.
- **A zone keeps only the basics and the GPU of `/dev`** — default-deny
  (`docs/PERMISSIONS.md` §11.12, `docs/LEAK-MODEL.md` §19): no other
  device node is in the zone's `/dev` (the entry above), by no list of
  names. A list of what to hide had missed what is open to everyone:
  `/dev/kvm`, `/dev/vhost-net`, `/dev/vhost-vsock`, `/dev/net/tun`,
  `/dev/vfio/vfio`, `/dev/kmsg`, `/dev/udmabuf`. Kept: `null`, `zero`,
  `full`, `random`, `urandom`, `tty`, `ptmx`, `fuse`, `ntsync`, `dri/*`
  and NVIDIA's `nvidia<N>`, `nvidiactl`, `nvidia-modeset`, `nvidia-uvm`,
  `nvidia-uvm-tools`. A program that needs another node is given it by a
  grant. The device set `vm` gives `kvm`, `vhost-net`, `vhost-vsock` and
  `net/tun` (Nix `permissions.devices`, `cellward container devices`).
- **Devices given to a container** (`docs/PERMISSIONS.md` §11.12):
  `programs.cellward.containers.<name>.permissions.devices`, `cellward
  container devices <c> [add|rm <device>]`, `containers[].devices` in
  `status --json`, and `cellward devices [--json]` — what is plugged in,
  each device once, with the name a grant gives it by and the sets it falls
  into. A grant is a set — `games` (gamepads, physical, and their raw HID
  nodes), `security-keys` (FIDO), `phone` (adb, MTP/PTP), `serial`
  (`ttyUSB*`, `ttyACM*`) — or one device, `usb:<vendor>:<product>[:<serial>]`.
  The zone now covers every node one by one, `/dev/input` and
  `/dev/bus/usb` included (was: those two under a tmpfs), a watcher those
  plugged in later. The launch lists the host's nodes by udev's word on
  them and hands the given ones to `profile-run --device`, which takes the
  zone's covers off them in the launch's own mount namespace — the device's
  own entry, never a bind — checking each once more by number, vendor,
  product and serial. A sandbox binds them into its own `/dev`; a bind
  outlives the device and would open whatever takes its number next, so the
  zone's holder, seeing a device go, takes the bind away and puts
  `/dev/null` in its place in every other mount namespace of the zone's
  programs; and when another device gets the number of one gone, it kills
  every program of the zone that still holds the old node — a descriptor
  (`O_PATH` too), a bind of its own — unless it is the same device back
  (the kernel's word in sysfs: a gamepad back after its battery died is
  not killed for). This runs in a thread of its own and no clock decides
  anything: a look into a namespace is started, not waited for (a thread
  that only reports waits for it, however long — a loaded machine, a FUSE
  mount a program put over its `/dev`), and only the next look for the
  same node ends one; the sweep decides by what is there when the number
  is given again. A launch with no container
  gets none; a device plugged in later is seen after the program restarts.
  `games` never gives a HID device that also types or points (a combo
  receiver), and takes Bluetooth gamepads through `uhid`. Dangerous: `serial`
  and `usb:` for a board a program can reflash.

### Changed
- **The microphone for a program whose container is not known** (a
  throwaway sandbox, a temporary container, a daemon that left its
  launch's tree) is asked about even where the zone says `yes`, and is
  never offered "always": a program that left its container's launch must
  not get the zone's "yes" its container may have been refused. With no
  graphical session that is a refusal. The journal's `microphone` events
  carry a `container` field: the name, `""` for none, `"?"` for not known.
- **The CLI says what the default is** (the owner, 2026-09-26). Where the
  default is one of the values, the value is marked and `default` is no
  longer shown or completed (still taken): `camera|nix-daemon|audio-manager
  <zone> off (по умолчанию)|on`, `host-files <zone> read-only (по
  умолчанию)|writable`, `microphone|screencast <zone> ask (по
  умолчанию)|yes|no`, `frame title always (по умолчанию)|hover|off`,
  `frame width <1–32> (по умолчанию 4)`, `ask-again <term> (по умолчанию
  3m)`. Where `default` follows something, it stays a word and says what:
  `hermetic <zone> default (как у всех зон)|on|off`, `frame color <zone>
  default (из имени зоны)|<#rrggbb>`, `container set <c> color default
  (цвет сети)|<#rrggbb>`, `container set <c> microphone default (как у
  зоны)|yes|no|ask`. Completion offers the default first.
- **Container settings are written through a temporary file**, one writer
  at a time (a lock file in the directory), and a settings file that is there
  but cannot be read is no longer rewritten with its other keys lost.
  `container rm` and the sound filter's "always" share a lock: an answer
  does not bring back a container removed meanwhile.
- **The broker knows which container asks** (`broker::container_of`;
  `docs/PERMISSIONS.md` §11.9). It knew the zone only, and passed without a
  question just the zone's own programs (no container) asking for none. Now
  a program of a container asking for a launch in that same container, in
  the same zone, goes on without a question too — a browser of a container
  opening a window of itself. The container is known by the launch the
  program descends from: the launcher in the registry, taken only with its
  start time on record and the same, and the chain of parents read with
  each held — a program cannot make itself another's. "Always" and the
  journal name the origin as `zone/container`; the question says which
  container asks. A daemon that left its launch's tree, a throwaway
  sandbox, a record of a launch from before one container per launch are
  not known: `zone/?`, asked about, with no "always" — never taken for the
  zone's own programs. A launch that goes on without a question takes no
  app-id from the request, and what a program's name relaxes (no Wayland
  proxy, no compositor restriction, by `wayland-no-proxy` and
  `wayland-allow`) is not relaxed for it: the requester chose the command,
  and so the name. `?` is no longer allowed in a container's name. A
  container of the main home — run in the zone's own mount namespace — is
  told by its launch, not taken for the zone's own programs.

### Fixed
- **A hand-over is told by the program's windows, not by five seconds**
  (the owner, 2026-09-26/27: no fixed waits a slow or busy machine
  breaks). A launch into the network a running program is in used to count
  as handed over to the running copy if it ended with success within 5 s;
  on a loaded machine a browser's hand-over took longer and was never
  learned. Now the picker hands the launch a pipe; `wl-sandbox` takes it
  (the program never inherits it) and the Wayland proxy says when the
  program opens its first window, framed or not. Ended with success
  without a window, however long that took: a hand-over, remembered. A
  window: the picker leaves. Nothing on the way to say it (the proxy off
  or dead before it spoke, a launch outside `wl-sandbox`, a launch
  cancelled or only shown): said so, and nothing is learned — programs
  launched without the Wayland proxy are asked on every click, as a program
  not seen handing over is.
- **The network of a zone is waited for until pasta says it is done**
  (the owner, 2026-09-26: no fixed waits a slow or busy machine breaks).
  Every pasta that configures a namespace — a zone through a host
  interface, a zone's uplink, a system zone and its uplink, a user zone
  through a system zone (`vpn-zone-sys`) — now writes a pid file (`-P`),
  which pasta does once its initialisation is done; that is waited for, as
  long as it takes, and what pasta did is then looked at once: no route or
  no interface is a failure at once, with the reason, not a wait for ever
  (was five seconds of looking, then the zone did not come up; 300 ms for
  the attach, and a slow pasta was taken for one that had attached).
  pasta ending first ends the wait; `vpn-zone-sys` also stops waiting (and
  pasta) when the zone that asked goes. An OpenConnect client is waited for
  until its plan is written or it exits (was two minutes). pasta that
  cannot be started for a zone's uplink now takes the zone down at once. A
  system zone's start is still bounded by its unit's start timeout,
  systemd's; none is added. The broker and the system-zone service read a
  request as long as it takes (was five seconds): a peer that says nothing
  holds a slot of its own origin (four per zone) or of its own user (16 of
  the service's 64 connections), which bounds it instead.
- **A zone comes up however long its setup takes, and its helpers too**
  (the owner, 2026-09-26: no fixed waits that a slow or busy machine
  breaks). The user zone's unit is now `Type=notify` with no start timeout:
  the holder says `READY=1` once the zone has written `ready`, so `cellward
  up` and a launch into a zone that is down return exactly when the zone is
  ready, or failed (was ten seconds of polling, then "не поднялась" of a
  zone that came up a moment later). The zone's helpers (the bus proxies,
  the sound filter, the PipeWire context, a hermetic zone's session bus
  filter), `x11-run`'s satellite and a file sandbox's bus proxy, bus filter
  and X server are waited for until their socket is there — an inotify
  watch on its directory — or until they end without it (their pidfd, or
  asked every 100 ms where none can be had; an error is never taken for
  their end); was five seconds, and one second for the sandbox's X server,
  then no bus, no sound or no X. `cellward up` and a launch into a zone that
  is down say that the zone is starting and how to stop it — the launch on
  the desktop too, once it takes a while —, and a start that hangs is ended
  by `cellward down`.
- **A loaded machine no longer changes what happens: seven fixed waits
  are gone** (the owner, 2026-09-26: "a slower or busy computer and it all
  breaks"). Each one decided an outcome when it ran out; now the thing
  itself says when it is done, or the person does:
  - the Wayland proxy is waited for until it says it is ready or its
    channel closes (was 5 s, then the launch failed);
  - the session bus filter holds a program's calls the portal may see
    (to the portal, or to a unique name) — and what the program sends after
    them — until the portal answers the zone's `Register`, or the bus
    answers for it: an error when the portal cannot be started, `NoReply`
    when it goes without answering (was 2 s for every message, then the
    connection went on without the zone's id: a portal started cold on a
    busy machine made the zone's remembered screen cast ask again). What
    the program sends the bus and other names before that goes on at once,
    so a portal that is stuck — or stopped by a program of some zone —
    holds nothing it would not hold anyway; a message with the serial of
    the zone's `Register` waits too, so that no answer to it can pass for
    the portal's; a program that goes while its call waits is let go, what
    it sent still delivered. The filter's own notices go one at a time, in
    a thread of their own;
  - the doctor's walk of the reachable sockets is bounded by what it reads,
    not by 2 s a place (which reported "not seen whole" on a slow disk), and
    the doctor waits for its probe to the end (was 30 s, then a failed
    check). It never says "fine" for a probe that did not answer: a stop of
    the probe is seen as it happens (`waitid(WSTOPPED)` on its pidfd) and
    fails the check; for a probe frozen or starved through the user's
    cgroups the doctor says after a few seconds what it waits for, and
    Ctrl-C gives up on the probe — the check failed, the report printed; a
    second Ctrl-C ends the doctor. The probe is a process group of its own,
    so the terminal's Ctrl-C and Ctrl-Z are the doctor's, and it dies with
    the doctor (`PR_SET_PDEATHSIG`); a pipe someone else holds open no
    longer keeps the doctor reading once the probe is gone;
  - `vpn-zone-sys` relays a command's output to the end (was 2 s after its
    exit, and the tail was cut); what the command left behind in its unit is
    killed by the service as soon as the command is over, so nothing holds
    the terminal after it (a `systemctl stop` still gives a running command
    its `SIGTERM`);
  - the window menu's "restart" waits for the program to close however
    long it takes — a program asking whether to save is closing too (was
    10 s, then the restart was cancelled). Past 2 s it asks: cancel the
    restart (Enter, the default — always safe), close now (killed; too
    quick a press is taken for a stray key and asked again) or wait (Esc);
    the program closing meanwhile answers it;
  - the TTY console no longer sleeps 300 ms for a terminal's late answers
    after a shell. Keys are read straight from the terminal a piece at a
    time: a piece with an ESC in it is a sequence — an answer to a query
    (`ESC [ 0 n` holds the admin tool's `n`), an arrow or F-key, a mouse
    report — and chooses nothing, however late it lands; ESC alone is the
    Esc key. Mouse reports a program turned on are turned off before the
    menu.
- **A zone no longer reaches the devices the session's ACL opens** (audit
  2026-09-26, from inside a zone; LEAK-MODEL §19): `/dev/uinput` — a
  program of a zone made a virtual keyboard and typed into any window of
  the host —, `/dev/rfkill` (the host's radios off), `/dev/i2c-*`, the
  consoles `/dev/tty<N>`, `/dev/hidraw*`, `/dev/ttyUSB*`, `/dev/ttyACM*`,
  optical drives (`/dev/sr*`, `/dev/sg*`), FireWire (`/dev/fw*`), video
  capture's other nodes (`v4l-subdev*`, `v4l-touch*`, `radio*`, `vbi*`,
  `swradio*` — given with the camera setting), TV tuners (`/dev/dvb`),
  `/dev/input`, `/dev/bus/usb` are out of every zone's reach — those
  plugged in later too (the zone's own `/dev`, above). Security keys
  (FIDO), gamepads, phones and serial adapters work in a zone only given
  to a container on purpose (device sets, above).
- **The bus filter records a portal's refusal of the zone's id before the
  held calls go on** (`bus_filter::Conn::answered`): it was set after the
  wake-up, a race the test `a_refused_registration_leaves_the_connection_as_it_was`
  lost now and then under load.

### Changed (read before updating)
- **The network is the container's, not the program's** (`rust/src/picker.rs`,
  `container::migrate_pins`, `focus::Pin`; `docs/PERMISSIONS.md` §11.8).
  A program pinned to a network (`.pinned/<program>`) while its container
  had another or none was one identity in two networks, or two containers'
  programs arguing over one. Now:
  - A container bound to a network starts there without a question; one with
    no network yet has it asked, and "always" binds it — without "always"
    nothing is bound (a binding is an action of its own, I1). The global
    default container is never bound from one program's launch: every new
    program would go into that network unasked. The launch window does not
    offer a container with a network other than its own. Removing a zone
    unbinds the containers bound to it here.
  - "Always" for the main home moves the program to the container of the
    main home bound to that network, `main-<network>`; the main home itself
    still asks at every launch.
  - **Moved once, at the first look:** a program's network pin becomes its
    container's network (the container it is pinned to, or its own), when
    the container has none, every program of it agrees and it does not run
    in another network now (else it stays asked, and is said); a program of
    the main home goes to `main-<network>`; a program whose container is
    asked every time, or is the global default, keeps the network as the
    last choice, where the question starts; a pin to a zone that is gone is
    dropped.
  - A program nobody pinned that reaches the global default container has
    its network asked even when that container is bound, at a click and at
    login (offline): its network is nobody's choice for it. Where the
    network asked is not the container's own, the launch is refused (I1) —
    pin the program to the container, or choose its network.
  - The window menu (`window-menu`) pins or unpins the container's network;
    "↺ Спрашивать снова" drops the program's container pin; `cellward pins`
    lists the programs' containers and their networks; `status --json` gives
    `apps[].network` as the container's.

- **One name is one container; the kind of its home is a property of it**
  (`rust/src/container.rs`, `launch::resolve_selection`; the owner's decision
  of 2026-09-26, `docs/PERMISSIONS.md` §11.7). A layer over the home
  ("profile", `work`) and a home of its own ("sandbox", `sb:work`) were two
  containers, with their own directories, settings and commands, and the
  main home was none at all. Now:
  - `home = private | layer | main` in Nix and in the container's settings
    (`overlay` is read as `layer`; `status --json` still says `overlay` —
    schema 1). `main` is the real home under a container's name: no data of
    its own, but a network, programs and — next — permissions of its own; one
    network at a time is not checked for it (one identity everywhere), and it
    holds no certificates. Changing the kind sets the old kind's data aside
    (`home.<kind>`) and brings them back when it is changed back —
    `cellward container set <c> home <kind>`.
  - One data directory for every container, `~/.local/state/vpn-profiles/<name>/`
    (a historical name: every zone covers it, the ones started before this
    version too), one policy directory, `~/.config/vpn-zones/containers/<name>/`,
    and a declared one in `declared/containers/<name>.conf`, with its `home`.
  - **Moved once, on the host, at the first look**: the named sandboxes' data
    from `vpn-sandboxes/` (a rename on one disk — running programs keep what
    they have), the policy of both earlier layouts; `sb:<name>` in the
    picker's memory and the default becomes the name. A sandbox with a
    layer's name becomes `<name>-sb` (said, and a stale `sb:<name>` still
    finds it); a name that cannot be one (a leading `-`) stays where it is,
    and is said.
  - `cellward container create <name> [--home private|layer|main]`,
    `container rm`; `sandbox` and `profile` are the same command with their
    kind as the default. `run --container <name>`; `--profile` names the same
    container, whatever its kind. `--sandbox` (and `sb:<name>` anywhere —
    a pin, Nix `defaults.container`, a record) asks for a home of its own
    and gets nothing else: a layer or the main home by that name is refused,
    a missing one is made, as before.
  - The move plans first and under a lock (the first pickers at a login
    start together), writes the renames before anything moves, and takes
    the kind of home from its plan, not from the files next to the data that
    programs could write; a name Nix declares keeps it. A container whose
    data could not be moved (another disk, a link among its old files) is
    not launched until they are — never with an empty home next to them.
  - Nothing is made or moved for a launch before its network is checked:
    a new sandbox is made, and the data of a changed kind set aside, only for
    a launch that goes — and not while programs of the container run.
  - The broker asks, and keeps "always", for the container a request will
    really be in, with its kind (`work@private`): `--sandbox work` and
    `--container work` are no longer one question. "Always" given before
    is asked once more.
  - `default-profile = main` is the main home even when the last choice was
    a sandbox (the default used to be laid over it: one launch of two
    containers). A pin to a container that is gone is dropped, and the launch
    goes on as with no pin; a pinned sandbox (`sb:`) is made again, as
    before.
  - **One launch, one container**: a layer and a sandbox at once (`--profile
    X --sandbox Y`, or with `--fs-sandbox`/`--tmp-profile`) is refused — the
    picker built it from a default container laid over the sandbox of the
    last choice; it now takes a default container whole, and a last choice
    that is gone is the program's own container, never the main home. Every
    container has its registry directory, `.running/<name>/`; records of
    sandboxes started before (`sb:<name>` under `__main__`) are read while
    they live.
  - `cellward isolate` and `cellward reset-profile` are gone: zones have had
    no layer of their own since the whole-home layer of a container; they did
    nothing.

### Security
- **A program of a container no longer crosses into another identity of its
  zone without a question** (`rust/src/broker.rs`; review 2026-09-26). The
  broker let any program of a zone launch into that same zone unasked — in
  the main home (out of a layer or a sandbox, into the real home) or in
  another container (its data). It now tells a program of the zone's own
  from one of a container by the mount namespace (a container's launch has
  its own, which a program there cannot leave): only a program with no
  container, asking for none, in the same zone, goes on without a question —
  a link opened by the zone's bus filter, a launch from a terminal of the
  zone. Everything else is asked, a locked zone included.
- **A zone no longer sees the containers' data** (`zone::hide_container_storage`,
  `profile-run --storage`; review 2026-09-26). Every program of a zone read
  and wrote every container's storage — a browser profile, a sandbox's home,
  code they run included. A zone now covers both storage directories, keeping
  the real ones inside its own hidden state, in a directory only the zone's
  root enters; a container launched into it gets its own directory back from
  there, in the launch's own mount namespace only, while `profile-run` still
  has the capabilities of its setup.
- **A layer container covers the whole home** (`rust/src/home_layer.rs`,
  `profile::mount_profile`; the owner, 2026-09-26, `docs/PERMISSIONS.md`
  §11.3). A data container ("profile") layered only `.config`,
  `.local/share`, `.cache`, `.mozilla` and `.pki`: everything else — a line
  in `~/.bashrc`, an autostart entry, a git hook, a project — its programs
  wrote into the real home, where the host runs it later. Now the whole home
  is under the container's layer (`vpn-profiles/<name>/home/upper`; the old
  slots move into it at the first launch, the data stays). Given back over
  it: what was mounted below the home (the zone's covers keep their flags;
  another disk, or a bind of `~/.ssh` from elsewhere, is read-only unless
  granted), and the paths granted to the container — `container grant` now
  works for a layer too (below the home: a path it writes through, into the
  real one), checked again at every launch as written and as resolved, with
  the places the host runs things from never grantable. The other
  containers' storage is covered: one container's layer is no window into
  another's data. A layer that cannot be set up does not start the program —
  it never falls back to the real home.
- **A container's policy is apart from its data** (review 2026-09-25, P1):
  `container.conf`, `paths`, `perms` and `trust/` moved from
  `~/.local/state/vpn-{profiles,sandboxes}/<name>/` to
  `~/.config/vpn-zones/containers/{profiles,sandboxes}/<name>/`. Container
  storage is the containers' data, which their programs write, and a program
  in a zone could bind a container to the host's network (`network =
  unconfined`) or grant it a directory, and the next launch from the menu
  obeyed; the config dir is read-only in zones. The files move once, on the host, at the first
  look after the update (`.migrated` marks it): a file put next to a
  container's data after that is nobody's. Removing a container removes its
  policy too. The move takes plain files only — a link, to anything, stays
  where it is — copies across filesystems, and is not marked done while
  anything failed; a container is its data, its policy or its declaration,
  so removing the data directory does not unbind its network.

### Fixed
- **The launch window opens faster, most of all under load**
  (`window/package.nix`, the owner, 2026-09-26: Firefox took long to open
  while the machine was busy). iced reads every font of the system at each
  start — over a thousand on a desktop, up to a second even when idle — and
  the window needs one: Fira Sans is built in. It now gets a list of its own
  (`FONTCONFIG_FILE`: DejaVu for signs, Noto Color Emoji for the icons),
  set by the window itself from a path built into it — no wrapper, which
  would have renamed the process.
- **A link opened from a program in a zone offered no zones** (the owner,
  2026-09-25): the picker it starts runs in the zone, which no longer sees
  the project's state, so the launch window listed only "Без ограничений"
  and "Без сети" — not even the zone itself. The picker in a zone now asks
  the broker (`VZP1`), and the broker shows the launch window on the host
  (`vpn-zone-pick --from-zone`, `rust/src/broker.rs` `handle_pick`): every
  zone, the asking one chosen, "Запрос из зоны «…»" in the title and the
  command in a block of its own, word by word, with the program as the host
  finds it (flagged when it is not from the store); a locked zone is offered
  only itself. The window is the question — no second one from the broker —
  and it is built not to be answered by accident (a review of it found three
  ways and they are closed): it takes nothing — no key, no click, no choice —
  until the person has been still for 1.5 s with it focused, and every key,
  press, returning focus or changed choice starts that again; Enter starts
  only in the asking zone, another network takes a click on the button that
  names it, digits choose nothing, the host's network is listed last; no
  "always", no new container, nothing decided without the window, pins
  included. A container directory named like a menu command (`pinmain`,
  `pin:x`…) is offered in no menu any more. The broker starts only the
  request's own command, word for word. A container of the host's network,
  and a zone without a broker, keep their own picker.

- **`ping` works in a zone** (`rust/src/zone.rs` `allow_ping`, the owner,
  2026-09-25: "missing cap_net_raw+p capability"). A new network namespace
  lets nobody open the kernel's ICMP echo sockets (`net.ipv4.ping_group_range`
  is `1 0`), so `ping` wanted raw sockets, which a program in a zone does not
  have and must not get. The holder now opens echo sockets to the user's own
  groups in the zone (the one line of the zone's `gid_map` mapped to
  itself: a range over the zone's root as well is empty to the kernel).
  Nothing new leaves by it: the kernel builds the echo requests, and they
  take the zone's routes — the tunnel, or nowhere in an offline zone. Applies to a zone started after the update.
- **A running terminal no longer takes every next one into its network**
  (`rust/src/picker.rs`, the owner, 2026-09-25). A click on a running
  program started it where it ran, with no question — right for a browser or
  a messenger, which hand the launch over to the copy that is up, and wrong
  for a terminal, whose every window is a process of its own: one Alacritty
  opened in a zone left each next one there. Now a running program is asked,
  with the network and container it runs in chosen (Enter keeps them) and a
  note of where it is open. A launch into that same network is watched for
  five seconds: a program that exits in them with success handed the launch
  over, and is remembered (`.handover/<id>` in the state) — from then on a
  click on it while it runs raises it with no question, as before. So a
  browser or a messenger is asked once more after this update, and never
  again; two copies of one program alive at once drop the mark.
- **A program with OpenAL sound hung in a hermetic zone without the WirePlumber
  policy** (`rust/src/pw_context.rs`, found on the owner's machine 2026-09-25:
  AyuGram never showed a window, and every new launch queued behind the hung
  one). The zone's `pipewire-0` took a connection and closed it at once while
  there was no policy; OpenAL Soft (Telegram Desktop and its forks, games)
  connects, then waits for its first reply forever when the connection closes
  under it. The socket now does not listen until it is first handed to the
  daemon: a program's `connect` is refused, and it takes the pulse path at
  once. Once the policy has been there, a connection that comes while it is
  gone (WirePlumber restarting) is still taken and closed — a socket cannot
  stop listening. Applies to a zone started after the update.
- **Nothing could be launched into a zone that an update left running**
  (`rust/src/cli.rs` `zone_pid`, found on the owner's machine 2026-09-25). An
  update keeps running zones (`X-SwitchMethod=keep-old`, below), but a holder
  from before `zone.start` has no note of its start time, and a zone without
  the note read as down — the frame stayed, and every launch into it failed
  until the zone was restarted. Such a holder is now taken when its process
  sits in the zone's own unit, `vpn-zone@<name>.service` (read from
  `/proc/<pid>/cgroup`, with the start time read before and after, so the
  look was at that very process), and the note is written for it. A number
  outside the unit is still not a zone.

### Security
- **The broker's listening socket reached the programs it started** (found
  in the review above): systemd passes it as fd 3, and it was not closed on
  `exec` — a program a zone started into itself (no question for that) could
  take other zones' requests, their commands and links, and answer them. It
  is close-on-exec now, and `LISTEN_*` leave the broker's environment.
- **The broker is harder to flood**: a zone is asked at most four times a
  minute and not for 15 s after a "no"; a question not answered in two
  minutes is closed (one left open kept every other zone's out); a request
  past 64 KiB or with an app-id past 255 bytes is refused whole (it was cut
  and read) and must arrive whole within 5 s; one zone holds at most four
  requests at once (64 in all), and writes at most 30 journal lines a minute —
  a stream of cheap requests no longer rotates the record of crossings away.
- **What the zone's window shows is what runs**: the broker finds the
  program once, before the window, and starts that absolute path; `run`
  looked it up again by PATH, where a link in the home could be repointed
  while the window was open. A shell or interpreter is flagged as running any
  command; an empty argument is shown as one.

### Changed
- **The single entry is `programs.cellward.enable`** (NixOS), the same name as
  in home-manager (the owner's call of 2026-09-25): in NixOS, `programs.*` is
  where a tool that also sets up the system lives (`programs.firejail`,
  `programs.wireshark`); `services.*` is for daemons — the system tier
  (`services.cellward.system.*`) and the PipeWire policy
  (`services.cellward.pipewirePolicy.enable`) stay there. The first name,
  `services.cellward.enable`, still works, with a warning (checked in
  `tests/harness.nix` `singleEntry`: the same machine, and the warning).

### Changed
- **An update no longer cuts running zones off the network**
  (`module/default.nix`, `module/nixos.nix`, `tests/harness.nix`
  `keepOnSwitch`). home-manager's sd-switch restarted a zone whose unit had
  changed — every cellward update did — and a restarted holder left the
  zone's programs in a namespace without its tunnel until they were started
  again. `vpn-zone@` and the broker's socket now say `X-SwitchMethod=keep-old`
  (the socket is carried into zones when they come up: a new one would not
  reach the running ones); a system zone's tunnel (`vpn-zone-system@`) is not
  restarted by `nixos-rebuild` either, like its namespace already was. sd-switch
  reads this from the NEW unit, so the first update to this version already
  leaves running zones alone. A zone takes the new build when it is restarted;
  the holder's own fixes apply from then.

### Changed (read before updating)
- **The project is cellward now** (formerly vpn-zones; the owner's decision
  of 2026-09-25). The flake is `github:TimSalguz/cellward`; the old URL
  redirects. Nothing has to change at once — every old name below keeps
  working — but the old ones warn, and they will go.
- **Commands.** The command is `cellward`, with the short name `cw`;
  `vpn-zone` stays as an alias for the transition — all three are one
  wrapper in the profile (`cellward` with `cw` and `vpn-zone` linked to it).
  The GUI command is `cellward-gui`, with `vpn-zone-gui` as its alias. Tab
  completion (zsh, bash) answers to all three names. The help text and every
  message that tells you to run something say `cellward …`; notifications
  come from the app "cellward"; the launcher entries "Настройки VPN-зон" and
  "Контейнеры VPN-зон" are "Настройки cellward" and "Контейнеры cellward".
  The launcher entries `sync` writes and the picker's launches go through
  `…/bin/cellward` (the manifest's `runner`) and are rewritten at the next
  sync, which activation runs. The broker never offers "always" for
  `cellward` or `cw`, as it never did for `vpn-zone` (they run any command),
  and a PATH shim never takes any of the three names.
- **Options.** Home-manager `programs.vpn-zones.*` is
  `programs.cellward.*`; NixOS `services.vpn-zones.system.*` is
  `services.cellward.system.*` and `services.vpn-zones.pipewirePolicy.enable`
  is `services.cellward.pipewirePolicy.enable`. Every old option still works
  through `lib.mkRenamedOptionModule`, one rename per option, with a warning
  on use; `tests/harness.nix` (`oldNames`, in the eval job) checks that the
  old names name every new option and give the same home and the same
  system. Messages that say where a value was set name the new options.
- **A single entry** (`module/entry.nix`): one import of
  `nixosModules.default` and `programs.cellward.enable = true;`. It loads at
  boot the kernel modules a zone cannot load from its unprivileged user
  namespace (`amneziawg` unless `services.cellward.system.amneziawg = false`,
  `wireguard`, `tun`, `nf_tables`); turns the PipeWire policy on by default
  when WirePlumber is on; with the home-manager NixOS module imported, adds
  the home-manager module for every home-manager user
  (`home-manager.sharedModules`) with `programs.cellward.enable` true by
  default; and with `system.enable` and `system.egress.enable`, unless
  `system.host.nix`/`host.time` are set, declares a plain zone `direct0` (a
  default) and sends the Nix daemon and systemd-timesyncd through it. It
  turns on neither the system tier nor the egress policy: those, their mode,
  `host.dns`, the console, the switch and the emergency key stay explicit.
  Checked by evaluation (`singleEntry`) and in the `vm-audio` VM test, which
  now runs on it. The package's `pname` is `cellward`.
- **What stays as it was**: the state and config directories
  (`~/.local/state/vpn-zones`, `~/.config/vpn-zones` and its `declared/`,
  `/etc/vpn-zones`, `/var/lib/vpn-zones`, `/run/vpn-zones`), the nftables
  tables `vpnzones_*` and the kernel log prefix `vpn-zones-egress:`, the
  systemd units (`vpn-zone@`, `vpn-zone-broker.socket`, `vpn-zone-system@`,
  `vpn-zones-on`/`-off`, `vpn-zones-egress` …) and the commands named after
  them (`vpn-zones-on`, `vpn-zones-off`, `vpn-zone-sys`, `vpn-zone-console`),
  the internal binaries (`vpn-zone-core`, `vpn-zone-pick`, `vpn-zone-seccomp`,
  `vpn-zone-window`, `vpn-zone-sync` …) and the crate's names, the
  `VPN_ZONE_*` variables, the groups, the PipeWire and WirePlumber names,
  the compositor snippets `vpn-zones.kdl`/`vpn-zones.conf`, the kernel
  command line `vpnzones=off`, the `status --json` schema and fields, and the
  section numbers of `docs/LEAK-MODEL.md`.

### Added
- **Which build a running zone is on** (`rust/src/build.rs`). An update leaves
  running zones alone, so a zone can run a previous build for a while — and
  the holder's newer fixes do not apply to it until it is restarted. The
  holder notes its build (`zone.build`, the store directory of the program,
  next to `zone.pid`); `status --json` has `"build": "current" | "previous"`
  for every running network (`null` when down), `cellward doctor` warns about
  a zone on a previous build, and the tunnel watch says it once per installed
  build, with the zones and how to restart them. A holder from before the
  note reads as the previous build.
- **A screen cast switch per zone** (`rust/src/screencast.rs`,
  `rust/src/bus_filter.rs` `screencast_verdict`, LEAK-MODEL §21,
  PERMISSIONS §3д): `cellward screencast <zone> yes|no|ask|default` (with
  completion), Nix `programs.cellward.screencast.<zone> = "yes"|"no"|"ask"`
  (renamed from `programs.vpn-zones.screencast` like every option, written
  to `declared/screencast`), and `"screencast":{"value","source"}` for every
  zone in `cellward status --json` (`null` for `unconfined`). The
  microphone's rules: the zone's marker, Nix over it, `ask` without either;
  a value that is none of the three, or a file that cannot be read, is `no`.
  A hermetic zone's session bus filter reads it for every call, so it
  applies at once, to running programs too — through descriptors of the
  zone's, config and state directories it opens before its socket appears,
  since the zone covers the project's state right after (the filter's new
  `--zone`, `--zone-dir`, `--config`). `ask`, the default, is what every
  zone had: the portal's dialog every time, `SelectSources` without
  `persist_mode` and `restore_token`. `no` refuses every call of
  `org.freedesktop.portal.ScreenCast` with the portal's own
  `org.freedesktop.portal.Error.NotAllowed` and "трансляция экрана выключена
  для зоны «…»", a line in the zone's unit journal each time and a
  `screencast` event in `cellward journal` at most once per 10 s. `yes`
  passes `persist_mode` and `restore_token` as well, so a remembered choice
  works — only on a connection the portal knows as the zone (the entry
  above), and only while the call goes to the portal that took the id: by
  its unique name, or by the well-known one while that portal still owns it
  (asked on a short connection of the filter's own). Anywhere else `yes` is
  `ask`: a choice is never kept for the nameless host application every
  zone shares, nor by a portal restarted since. Not in force where no zone
  filter reads it: a zone that is not hermetic talks to the portal
  directly, and in a file sandbox `yes` is `ask` (its own filter does not
  see the zone's state; a hermetic zone's filter behind it holds `no`) —
  `cellward screencast` says so.
- **The portal knows the zone** (`rust/src/bus_filter.rs` `register`,
  `rust/src/desktop.rs` `zone_app_id`, LEAK-MODEL §23). Each zone has an
  application id of its own, `cellward.zone.<id>` — the zone's name with
  every character but `[A-Za-z0-9_]` turned into `_` and a `_` before a
  leading digit, plus an FNV-1a hash when the name changed on the way, so
  that `work-vpn` and `work_vpn` never share one. The bus filter registers
  each program connection under it with the portal's host registry
  (`org.freedesktop.host.portal.Registry.Register`, xdg-desktop-portal
  1.19+): the program's Hello goes up as it is; once the bus has answered
  it, the filter sends its own `Register` on that connection, under a
  reserved serial below xdg-dbus-proxy's `MAX_CLIENT_SERIAL`, and holds
  everything the program sent after the Hello — in order, with its
  descriptors — until the portal answers, for 2 s at most. The answer never
  reaches the program, and the program's own `Register` stays refused. The
  portal's dialogs then name the zone ("cellward · <zone>") and what the
  portal remembers is kept under the zone, not under the nameless host
  application every zone shared. It only helps: nothing is let because of
  it. No answer or an error (an older portal, no entry) leaves the
  connection as it was, said once in the zone's unit journal. The zone's
  holder writes the entry the portal needs,
  `~/.local/share/applications/cellward.zone.<id>.desktop` (`NoDisplay`, a
  harmless `Exec` of `cellward status <zone>` by the profile's path — GLib
  takes an entry only when it finds its program — marked
  `X-VPNZone=portal`), as the zone comes up; sync keeps it while the zone
  exists, whatever the launcher mode, and `cellward rm` takes it. The
  holder has a new flag, `--runner`, which the unit passes. A hermetic
  zone's session bus filter registers every connection of the zone,
  sandboxed ones included; the filter of a file sandbox (`--fs-sandbox`)
  in a zone that is not hermetic registers its own — `fs-sandbox` is told
  the zone (`--zone`) by the launch, and `bus-filter` takes the id as
  `--portal-app`.
- **How long a refused zone is not asked again is a setting** (the owner's
  request of 2026-09-25): `vpn-zone ask-again <term>|default`, Nix
  `programs.vpn-zones.askAgainAfter`, `ask_again` in the defaults of
  `status --json`. A term from `30s` to `1d`, `3m` unless set; read when the
  person refuses, so it applies without restarting a zone. The shortest is
  longer than a question waits for its answer: a shorter pause would let a
  program that reconnects after every "no" keep a dialog up for a stray
  Enter. A file with a term out of bounds is passed over, never read as no
  pause. The microphone's question uses it now; the other permissions will
  (`docs/PERMISSIONS.md` §3е).
- **Audio managers**: a hermetic zone that runs a mixer or a patchbay
  (pavucontrol, qpwgraph, EasyEffects) can be given the host's raw
  `pipewire-0` instead of the restricted one — `vpn-zone audio-manager
  <zone> on|off|default`, `programs.vpn-zones.audioManager` (a list of zone
  names, written to `declared/audio-manager`), and
  `"audio_manager":{"value","source"}` for every zone in `vpn-zone status
  --json` (`null` for `unconfined`); from the zone's next start. Said
  loudly: by the CLI, in the unit's journal and as a `warn` of the doctor's
  `pipewire` check — the zone hears everything the host plays, records the
  microphone around its switch and moves other programs' streams.
- **The microphone by permission** (`rust/src/microphone.rs`,
  `rust/src/pulse_filter.rs`, LEAK-MODEL §17; the owner's decision of
  2026-09-25). A program in a zone records the microphone only as the zone's
  switch says, like an app on a phone: `yes`, `no`, or `ask` — the default.
  With `ask`, the first time a program of the zone records, the person on the
  host is asked (kdialog): allow once (that one stream), always — to the
  whole zone, and the button and the text say so (`Всегда — всей зоне «…»`),
  since the program's name there is only its own word; it writes `yes` into
  the zone's setting and is not offered when Nix set the zone's value — or
  deny, which stands for that connection, so the program's retries on it are
  not asked about again, and quiets the zone for 3 minutes: no program of it
  is asked meanwhile, so one that reconnects after every "no" cannot keep a
  dialog up for a stray Enter. The sound filter holds
  that one `CREATE_RECORD_STREAM` while it asks — the connection's other
  commands go on, the server answers the held one by its tag when it gets
  it — and then forwards it or answers it `ERROR`/`ACCESS`. One question at
  a time per zone: a request while one is open is refused, not queued, and
  the connection's deny is in place before the question closes. No
  graphical session (neither `WAYLAND_DISPLAY` nor `DISPLAY` in the filter's
  environment, i.e. the zone unit's) or no answer within 25 s — under
  libpulse's own 30 s wait for a reply, so a late "yes" never opens the
  microphone for a stream the program has given up on — is a refusal,
  said in the unit's journal and in `vpn-zone journal` (a new event,
  `microphone`; refusals nobody was asked about at most one line per 10 s).
  The question names the filter's own zone, never anything the program
  says, and the program by its own `application.name`, cleaned of control
  characters, markup and reordering marks. The filter reads the setting for
  every record stream, so a change applies at once, without restarting the
  zone; it lives outside the zone's own file system — the marker in the
  zone's state directory and `~/.config/vpn-zones/declared/microphone` —
  Nix over the marker, an unknown value or an unreadable file meaning `no`;
  the filter and its kdialog run in the host's user namespace (Security,
  below), out of the zone's reach through `/proc`. Monitors stay
  unrecordable whatever the switch says. Settings: `vpn-zone microphone
  <zone> yes|no|ask|default`, `programs.vpn-zones.microphone.<zone> =
  "yes"|"no"|"ask"`, and `"microphone":{"value","source"}` for every zone in
  `vpn-zone status --json` (`null` for `unconfined`). `pulse-filter` takes
  `--zone`, `--zone-dir`, `--config` and `--kdialog`, all required; the
  zone holder `--kdialog`. Tests: the setting's precedence, the verdict
  (no display, "always" only where the marker decides), the buttons,
  once/always/deny with a stand-in kdialog, the deadline (the dialog
  killed), one question at a time, the program's name cleaned, and the
  filter between a client and a stand-in server — the held stream reaching
  the server only after "once" while a later command got there first, a
  denied one answered `ERROR` and the connection not asked again. VM:
  `ask` with no display and `no` refuse a record stream on the default
  source, `yes` lets the microphone's sound through, all on a running zone;
  the monitor refusal still holds; a value declared in Nix wins over the
  zone's own, in the status and in the running filter (a record stream of
  the hermetic test zone refused with Nix's `no` over its own `yes`); from
  a zone, neither the marker by its path nor through `/proc/<pid>/root` of
  the filter, the proxies or the question's kdialog (held open on an X
  server that never answers) can be reached. The PulseAudio path, and the
  restricted PipeWire of a hermetic zone (below, Security: `yes` or not —
  `ask` refuses there): raw `pipewire-0` records around it in an ordinary
  zone and an audio manager, and in a zone that is not hermetic so does the
  host's `systemd --user` — which can also rewrite the setting; `vpn-zone
  microphone` says what goes around it when it sets `no` or `ask`.
- **The title strip: the zone's name on the window** (`rust/src/wl_title.rs`,
  `rust/src/wl_frame.rs`, `docs/WINDOW-FRAME.md` §8 «Этап 2, заголовок»;
  stage 2 of the window frame, its second part — no buttons yet). Under the
  border's top band the proxy draws a strip of the zone's colour, 20 logical
  pixels high, with `<zone> · <container>` on it — the container as the
  launch knows it (`основной`, a profile, `песочница <name>`, `разовая
  песочница`, `временный`), cleaned of control and bidi characters and
  bounded (40 characters a part, 480 logical pixels a line). It is a
  subsurface of the program's root like the border's strips, with the text a
  subsurface of it: no id in the program's table, input on it dropped, a new
  subsurface of the program put below it. Modes (§0а): `always` (the
  default) — inside the window, the program is told a size less the strip
  and every translation of the border takes it too; `hover` — no room taken,
  over the top of the content, out while the pointer is at the window's top
  edge or on the strip (seen on the program's own `wl_pointer`), in when it
  goes below; `off` — the border alone. In fullscreen the strip goes and so
  does its room: which state a commit is of is the configure the program
  acked last, kept by serial. Whether it shows is not the program's alone:
  it is hidden only while the compositor's latest configure says fullscreen
  too, so a program that acks the fullscreen configure and never the one
  ending it gets the strip back, over the top of its content, the moment
  the compositor takes it out of fullscreen. The text is rasterized at the scale the
  compositor prefers for it — `wp_fractional_scale_v1` where it is offered
  to the restricted client (bound on the proxy's own registry, never shown
  to the program), else `preferred_buffer_scale` — into a buffer of exactly
  `round(logical × scale)` pixels given its size by `wp_viewport`; a resize
  never redraws it, a narrow window shows its left part. A new scale and the
  hover strip show at once (`set_desync`, the strip's commit, `set_sync`).
  The font is DejaVu Sans from the Nix package by store path
  (`VPN_ZONE_FRAME_FONT`, built in by `package.nix`; no fontconfig), read by
  the supervisor before the proxy is forked; the rasterizer is `ab_glyph`,
  pinned `=0.2.32`, no default features. The pixels live in one memfd per
  launch, made and sealed before the proxy's filter, in four regions of one
  scale each, a region redrawn only when no buffer of it is held by the
  compositor; the filter gains `pwrite64` only, and only to the title's
  writer descriptor (not the border's colour memfd, not a file stdout or
  stderr goes to). A connection with more than 4096 framed windows is
  refused with `no_memory`: each makes ~20 objects of the proxy's own
  upstream, which the cap on the program's objects does not count. Without a font the strip goes
  without text. Settings: `programs.vpn-zones.frame.title =
  "always"|"hover"|"off"`, `vpn-zone frame title always|hover|off|default`;
  `vpn-zone status --json` shows `frame_title` in `defaults` with its
  source. `wl-sandbox` takes `--frame <rrggbb>:<width>:<mode>` and
  `--frame-title <text>`. Tests: the layout (the frame with and without the
  strip tiling the band, a configured window exactly the compositor's
  size), the text cut to a narrow strip, hover, fullscreen from a
  configure's states, the text's cleaning, the mode's sources, the
  rasterizer (ink on the colour at 1–2×, clean edge rows, an ellipsis, a
  readable contrast on every default colour), the memfd's regions; the
  proxy between a client and a fake compositor — room for the strip,
  strip and text laid before the program's commit, a new buffer at 1.5
  shown at once, fullscreen and back, out at once when fullscreen ends
  un-acked, input on the title and its text dropped, the title raised above
  a new subsurface of the program, too many windows refused, `pwrite64` to
  any other descriptor refused, hover out at the top edge and in
  below. VM (`tests/vm-window.nix`): the strip and its text on the
  screenshot above foot's content, gone in fullscreen, crisp at 1.5 (a fifth
  of its pixels or more at least three quarters ink: 41% drawn at 1.5, 6%
  if stretched from 1), and a hover window without it.
- **The zone's border around its programs' windows** (`rust/src/wl_frame.rs`,
  `docs/WINDOW-FRAME.md` §8 «Этап 2, обводка»; stage 2 of the window frame,
  its first part — no title bar or buttons yet). The Wayland proxy draws a
  band of the zone's colour around every toplevel of a program in a zone:
  four subsurfaces of the program's own root surface, each the middle pixel
  of a 3×3 buffer stretched by `wp_viewport` — crisp at any scale, fractional
  included, nothing redrawn on a resize. The band lies INSIDE the window
  geometry: the proxy grows `set_window_geometry` and the size limits by it
  and takes it off `configure`, `configure_bounds`, popups' positions and
  the window menu's, so sway (which clips every tiled window) and niri with
  `clip-to-geometry` show it, and the compositor gets exactly the size it
  asked for; a program with no geometry of its own is framed around its
  surface's size. Geometry and limits go up just before the program's own
  commit, together with the strips' new place — synchronized subsurfaces,
  applied by that one commit. Maximized, tiled and fullscreen windows keep
  it. The program cannot name the strips (they have no id in its table), a
  subsurface of its own is put back below them, and input on them —
  pointer, touch, tablet tool, gestures, a drag — is dropped, not passed to
  it. What the proxy draws with it binds on a registry of its own: the
  program is shown no new global. Without `wl_subcompositor`, `wl_shm` or
  `wp_viewporter`, windows go without the border and the proxy says so once
  — never worse than without it. The colour is one pixel in a sealed memfd
  made before the proxy's filter is loaded (the filter is unchanged: no
  `memfd_create`, no mapping of a descriptor). Settings: the colour per zone
  (`programs.vpn-zones.frame.colors.<zone> = "#rrggbb"`, `vpn-zone frame
  color <zone> #rrggbb|default`; otherwise one derived from the zone's name,
  the same on every machine), the width (`frame.width`, `vpn-zone frame width
  <1–32>|default`, 4 logical pixels by default), and a switch that hides
  every border for sharing the screen (`vpn-zone frame hide|show`, local
  only), which the supervisor reads for each new connection. `vpn-zone
  status --json` shows `frames` and `frame_width` in `defaults` and
  `frame_color` per zone, each with its source. `wl-sandbox` takes `--frame
  <rrggbb>:<width>` and `--frame-switch <dir>`. Tests: the arithmetic
  (configure in and out, geometry, limits, the strips tiling the band), the
  settings, and the proxy between a client and a fake compositor — the
  geometry grown, four strips laid and committed before the program's
  commit, a configure less the border, a pointer over a strip unseen by the
  program, a new subsurface put below the strips, the strips gone with the
  toplevel, nothing of it on a connection that is hidden nor with a
  compositor that has no `wl_subcompositor`. VM
  (`tests/vm-window.nix`, sway): foot in a zone, screenshots read pixel by
  pixel — the border in the declared colour and width at every edge of the
  window, foot's own pixels exactly inside it, in fullscreen too, at scale
  1.5 after the resize it brings, and a window opened after `vpn-zone frame
  hide` without it while the older one keeps it.
- **`vpn-zone doctor` names every unix socket a zone can reach**
  (`docs/LEAK-MODEL.md` §18, the invariant the third review round asked for).
  A socket by path is a helper outside that acts for whoever connects — an ssh
  master, a root daemon in `/run`, the Nix daemon, an editor's server — and the
  zone's own network namespace cuts none of them. The probe walks, from inside
  the zone, the runtime directory, `~/.ssh`, `/run`, `/var/lib`, `/nix/var`,
  the home, `/tmp`, `/var/tmp` and `/dev/shm` with a program's rights (the
  session's groups shed, no capabilities; the doctor now enters with
  `nsenter --keep-caps`, as a launch does), never through a link a program
  may have made, never opening a file, never into FUSE, network filesystems
  or automount points (told by the device before a directory is opened,
  whatever it is called, and named), bounded in depth, and each place and
  each directory on a budget of its own, so that a program filling `/tmp`
  costs `/tmp` and nothing else — what it did not see it says. The zone's own
  sockets (its bus and pulse filters, `pipewire-0`, the broker, its own
  Wayland directory, its sandboxes', anything on a filesystem only the zone
  has) and the journal's are counted in a `sockets` summary; every other one
  is a `socket` line with its path at `warn` (at most 200, the rest counted),
  and what the project promises closed — the compositor, another zone's
  Wayland sockets, the system tier, the Nix daemon of a zone not let, the
  host's session bus (or the bus proxy without its filter) in a hermetic
  zone, the unfiltered sound server, the host's X server, a resolver — at
  `fail`, by its path and, told by the doctor, by its identity: a hard link
  under another name is the same socket. A new system check, `hardlinks`,
  warns when `fs.protected_hardlinks` is off.
  `tmp-sockets` is now the part of it in the temporary directories. What it
  found at once: systemd's varlink services in `/run/systemd` (`hostnamed`,
  `networkd`) answer every zone past the system bus filter, and so does
  dhcpcd's unprivileged socket; sshd on `/run/ssh-unix-local/socket`. Both named, not closed yet. VM test: the evil
  host's sockets in the home and in `/run` are named, one only the session's
  group may open is not, a clean hermetic zone names nothing but systemd's
  and dhcpcd's services; in an ordinary zone a socket in a bound runtime
  entry is named, and the Nix daemon taken away without a restart fails.
- **`vpn-zone status --json`** says in `defaults` whether the Wayland proxy is
  on (`wayland_proxy`), with its source, as `compositor_restriction`.
- **The Wayland proxy can be switched off**, for every program (`vpn-zone
  wayland-proxy off`, `programs.vpn-zones.waylandProxy.enable = false`) or for
  one it breaks (`~/.config/vpn-zones/wayland-no-proxy`,
  `waylandProxy.exceptions`): the compositor then listens for the program
  itself, as before — still the restricted socket.
- **A Wayland proxy between a program and the compositor** (`wl-sandbox`,
  `rust/src/wl_proxy.rs`; `docs/WINDOW-FRAME.md` §8, stage 1 of the window
  frame — nothing is drawn yet). The compositor's sandbox socket
  (`wp_security_context_v1`) now lives in `$XDG_RUNTIME_DIR/vpn-zones/wl-up/`
  (0700, never bound into a zone), and a proxy process listens on the zone's
  socket, the same path as before: each connection of the program gets a
  connection of its own to the restricted socket, through the pinned crate
  `wl-proxy` (`=0.1.4`), which keeps the two id spaces apart. The program sees
  the same globals minus the hidden ones and nothing added: only the protocols
  compiled in pass (the list in `rust/Cargo.toml` is the policy) — not
  `wp_drm_lease_device_v1`, not what security-context exists to hide, not
  NVIDIA's EGLStream or anything else unknown — and a bind to a name the
  connection was never shown is refused. The proxy is confined: not dumpable,
  an allow-list seccomp filter (no open, socket, connect, exec, fork,
  executable memory; killed on anything else), `RLIMIT_NOFILE`/`RLIMIT_DATA`,
  caps on connections, objects and globals, and a client that does not read
  its events is not read either. It never connects anywhere itself: the
  supervisor connects to the restricted listener and hands the descriptor
  over — and only for a process of its own launch: the proxy hands it the
  client's socket, the supervisor asks the kernel who connected
  (`SO_PEERPIDFD`) and passes the connection on only when that process is
  below it, every step of its ancestry read while held by a pidfd. It lives
  while a connection is open (a terminal's child keeps its window), never
  longer than its supervisor (`PR_SET_PDEATHSIG`); after the program exits
  nothing new is accepted, as before; out of descriptors, it rests and accepts
  again. The fallback: a proxy that cannot start leaves the compositor
  listening on the zone's socket itself, as before, with a warning
  (`--no-proxy` asks for that), and if that cannot be registered the program
  is not started — never unrestricted once the compositor has shown it speaks
  the protocol; a proxy that dies takes the program's display, never the
  unrestricted socket. The supervisor makes every connection upstream, so the
  compositor gives every window of the launch the supervisor's pid — the pid
  of the launch's record; it goes by `vz-wl-sandbox` meanwhile, adopts the
  program's orphans, passes SIGTERM, SIGINT and SIGHUP on to the program and
  them (the window menu's "close" and "restart" signal that pid), and
  `vpn-zone focused` and `window-menu` take the network of such a window from
  the supervisor's children, as the kernel says — for a process that runs our
  own `vpn-zone-core` and is a launch on record, not for one that merely took
  the name. Tests: the proxy between a real client library and a fake
  compositor under its own filter; the supervised start in a process of its
  own, with a client of another process beside it refused; a SIGTERM to the
  supervisor ending the program and the orphan it left; a process's ancestry
  through pidfds; VM: through the proxy and straight on sway's restricted
  socket the same globals minus the policy's, the proxy confined and its
  listener out of the zone, a zone process that is not of the launch not
  passed on while a child of it is, a foot window whose pid is the
  supervisor's still named by its zone and program, and the window menu's
  "close" ending foot, then the supervisor, the proxy and the socket.
- **The window menu's key and our windows' rule, written by the module**
  (`programs.vpn-zones.desktop`): `windowMenu.key` in niri's notation,
  `floatWindows` (the launch window and the menu float, by the app id
  `vpn-zone-window`), `niri.enable` writes `~/.config/niri/vpn-zones.kdl` and
  `niri.includeInConfig` appends its `include` to a config.kdl home-manager
  writes as text; `sway.enable` writes `~/.config/sway/vpn-zones.conf`, which
  home-manager's sway module includes by itself. The key's type admits only
  modifier names, `+` and a keysym. CI validates both snippets with niri and
  sway themselves; the VM test presses the key on sway and gets the menu,
  floating.
- **Which zone is the focused window in** (`docs/WINDOW-FRAME.md` §7б, §7в, the
  frame's first step). `vpn-zone focused [--json|--bar|--watch]` asks the
  compositor (niri, sway) for the focused window and its pid, and finds its
  launch up the pid's parents in the registry — or, for a program that
  detached from its launch, its network by its network namespace. `--watch`
  prints a status bar line (waybar's JSON, a class per zone) every time the
  focus moves. `vpn-zone window-menu` is the menu of that window for a key
  binding: pin the program to its network or ask again, close it and start it
  again through the picker, close it, cut its zone off — the last three
  confirmed. It is the launch window in a menu mode (kdialog where the window
  is missing). Nothing is taken from the window's title. VM test: a program in
  a zone opens a window on sway, `focused` names its zone and program, the
  menu comes up and closes having done nothing.
  The window has an app id, `vpn-zone-window`, for a compositor's window rule
  (README: floating in niri).
- **The launch window** (`vpn-zone-window`, the crate `window/`): the picker
  asks about the network and the container in ONE window, side by side,
  instead of two kdialog menus in a row with every entry twice ("… —
  всегда"). "Always" is a checkbox per column. Keyboard: ←/→ or Tab switch the
  column, ↑/↓ or a digit choose, Space ticks "always", Enter starts, Esc
  closes. A container open in another network cannot be chosen with a
  different one; a new sandbox or profile is named in the window. Drawn in
  software (iced with tiny-skia, no GPU context to wait for), light or dark as
  the system is. The picker keeps every decision and takes only what it
  offered back (`rust/src/window.rs` is the contract); where the window is
  missing it asks with kdialog as before. Tests: the picker with a fake window,
  the window's own, and `tests/vm-window.nix` — on a real compositor, with
  screenshots.

### Changed
- **Autostart asks about a program nothing was chosen for**
  (`autostart.unassigned = "ask"`, the new default, the owner's word of
  2026-09-24): the same picker a click shows, with its "always", at the login
  the program first starts at — instead of starting it offline in an empty home
  of its own, where a password manager had no database and a messenger no
  login. What was chosen still starts without a question. `offline` keeps the
  closed variant, and so does a login with no screen to ask on.

### Security
- **A zone's program cannot name itself to the portal**
  (`rust/src/bus_filter.rs` `refused`, LEAK-MODEL §23). xdg-desktop-portal
  1.19+ has `org.freedesktop.host.portal.Registry`: an unsandboxed caller
  registers any application id, once, before its first portal call. The
  portal takes a zone's (and a sandbox's) program for such a caller, and the
  filter refused only the `org.freedesktop.portal.` tree, so the program
  could register as a host application: the portal's dialogs (file chooser,
  screen cast) and notifications would name that application, and the
  permissions the portal keeps for its id would apply. With a registered id
  the Background portal also writes an autostart entry with the caller's
  command on the host — closed already, the filter answers
  `RequestBackground` itself. The whole `org.freedesktop.host.` tree is now
  refused, by interface, so a unique name does not get round it either.
- **A "yes" sooner than a question can be read is a stray key**
  (`rust/src/dialog.rs` `TOO_FAST`, LEAK-MODEL §22). The questions a zone's
  program brings up — the microphone, a launch in another network through
  the broker — are kdialog boxes whose default button is the first, "allow",
  and the new dialog takes the focus: an Enter meant for a chat, at the
  moment the program chose, said yes. An allowing answer within 1.5 s of
  starting kdialog is now a refusal, said in the journal. Questions the
  person opens themselves are unchanged. Next: a dialog of our own with
  "deny" as its default (`docs/PERMISSIONS.md` §9).
- **A screen cast from a zone asks every time** (`rust/src/dbus_wire.rs`
  `sanitized_screencast_sources`, LEAK-MODEL §21). The screen cast portal
  lets a program ask for its choice to be remembered (`persist_mode`); the
  next cast with the token it got back starts WITHOUT the portal's dialog,
  and niri shows nothing while a cast runs. The portal took a zone's program
  for a host application, so the remembered choice was not even tied to the
  zone. The session bus filter now passes `SelectSources` on with the options
  of an allow-list only (`handle_token`, `types`, `multiple`, `cursor_mode`):
  no `persist_mode`, no `restore_token`, nothing a later portal adds. A
  selection it cannot read is refused. Like Android, which asks before every
  screen capture.
- **A hermetic zone's PipeWire is its own, restricted socket**
  (`rust/src/pw_context.rs`, `module/wireplumber/`, LEAK-MODEL §20; the
  owner's decision of 2026-09-25). Every zone got the host's raw
  `pipewire-0`, where `module-access` in its legacy mode makes a client that
  is not a Flatpak unrestricted: it recorded the monitor of any output,
  moved and killed other programs' streams, linked any port to any port —
  around the sound filter and the microphone's switch. A hermetic zone now
  gets only a security context (`PipeWire:Interface:SecurityContext`, v3):
  a helper on the host, as the user, started by the zone's unit beside the
  sound filter (`vpn-zone-core pipewire-context`, the native protocol spoken
  from Rust, no libpipewire), makes the zone's listening socket (0600) and
  hands it to PipeWire with `create(listen_fd, close_fd, props)` — every
  client of it carries `pipewire.sec.engine = "vpn-zone"`, the zone as
  `pipewire.sec.app-id`, the holder's pid as `pipewire.sec.instance-id` and
  `pipewire.access = "restricted"` (never a word of our own: a stock
  WirePlumber grants everything to an access it does not know), properties
  a client cannot change; a pipe's write end is the `close_fd`, so PipeWire
  stops listening when the zone goes. `seal_runtime` binds that socket as
  the zone's `pipewire-0`, and the runtime watcher never binds the host's
  over it, not when PipeWire restarts either — the helper keeps the socket
  and hands the same descriptor to the new daemon. The permissions are a
  WirePlumber policy (`module/wireplumber/policy.lua` and
  `90-vpn-zones.conf`), for WirePlumber 0.5.14 and 0.5.15+ alike: no default
  permission (an `access.rules` entry, and on 0.5.15+ a `select-access` step
  before the config's rules); the core last; its own stream nodes `rwx` and
  their ports `r`, the streams of the zone's other programs `r`, any other
  node of its own (a virtual sink, a filter, a link group) destroyed at once; the host's sinks `r`; capture sources `r`
  only while the zone's microphone is `yes` (the helper publishes the switch
  in the `vpn-zones` metadata every second; revoked, the script breaks the
  links); the `default` metadata `r`; the `client-node` factory `r` — no
  link factory, no adapter or device factory. Links: only WirePlumber's,
  only a zone's stream to a host's sink and a host's source to a zone's
  capture stream on `yes` — never a sink's monitor, never a zone's node with
  anybody else's — a guard in WirePlumber's linking chain and a watchdog on
  every link; a zone's node is never a default device. The script writes
  `vpn-zones.policy = "1"` into that metadata, and only when its access rule
  is in force; without the key the helper does not hand the socket out —
  what connects is closed at once, and the zone has the pulse path only.
  Ordinary zones keep the raw socket (they have `systemd --user`). `ask` is
  a refusal on this path for now: the question is asked on the pulse path.
  The policy: `services.vpn-zones.pipewirePolicy.enable` (NixOS, through
  `services.pipewire.wireplumber.extraScripts`, the fragment as a config
  package — `extraConfig` would quote the feature names, which WirePlumber
  0.5.14 reads with their quotes, and it would not start at all) or
  `programs.vpn-zones.pipewirePolicy` (home-manager without NixOS, the same
  files in `~/.config/wireplumber` and `~/.local/share/wireplumber`; both on
  do not duplicate). `doctor`: a `pipewire` check per hermetic zone (the
  policy in force, or why not), the restricted socket counted as the zone's
  own, the host's raw one a failure in a hermetic zone and a warning in an
  ordinary one or an audio manager — by path and by identity. Tests: the
  messages byte by byte, broken ones an error, the decision, the helper
  against a stand-in daemon (nothing handed out before the marker; the
  listening socket and the pipe after; the pipe broken when the metadata
  goes); VM (`tests/vm-audio.nix`, a new CI job): a real PipeWire and
  WirePlumber with the NixOS module's policy — from the offline zone its
  `pipewire-0` is the context's (after a PipeWire restart too), `pw-dump`
  shows its own streams and the sink but no host stream, no sink port, no
  link, no link factory; it plays; a sink's monitor records zero bytes; the
  microphone is absent on `no`, records on `yes`, and its link breaks on
  `no` mid-recording; a virtual sink it makes is destroyed and never the
  default.
- **The zones' PipeWire policy out of the zones' reach, and tighter**
  (review of the restricted socket, LEAK-MODEL §20). WirePlumber looks for
  scripts in `~/.local/share/wireplumber` before the system's and for
  fragments in `~/.config/wireplumber` first, and the policy the restricted
  socket depends on is such a script: a program in a hermetic zone could
  put its own `vpn-zones/policy.lua` there, marker and all, and at
  WirePlumber's next start every hermetic zone's socket would be handed out
  with everything granted (a `pw-module` component would load native code
  into the host's daemon). `~/.config/pipewire`, `~/.config/wireplumber`,
  `~/.local/share/wireplumber` and `~/.local/state/wireplumber` are now
  entry points of the session: made before a hermetic zone comes up when
  missing, and read-only in it; never granted to a sandbox either. The
  zone's microphone is published before the socket is handed out, on the
  same connection, so WirePlumber has this run's value before any client of
  the zone (the key outlives a helper: a zone brought up on `no` after a
  `yes` recorded until the next tick), right after the metadata is bound,
  and again whenever the metadata says otherwise. `Audio/Duplex` is no
  capture source (WirePlumber gives a duplex node monitor ports: recording
  it was recording the host's playback); the watchdog, deciding by the
  nodes' classes like the guard, refuses it too. A zone's stream that
  claims the graph
  (`node.exclusive`, a forced or locked quantum or rate, `node.driver`) is
  destroyed, when it appears and when its properties change; an exclusive
  or passthrough link of a zone's stream is refused. A zone has at most 128
  clients and 256 nodes. A link whose ends the watchdog does not know yet is
  looked at again when they come, never let through. Documented what
  closing the context does: PipeWire disconnects every client that came
  through it. Tests: the helper against the stand-in daemon (the value at
  once, a stale one put right, published before the context's bind); VM —
  a duplex device records nothing with the microphone on, an earlier run's
  `yes` records nothing in a zone brought up on `no`, and from a hermetic
  zone the four directories cannot be written, missing before or not.
- **The zone's helpers run in the host's user namespace, out of the zone's
  reach through `/proc`** (`rust/src/zone.rs` `Helpers`, LEAK-MODEL §16;
  review 2026-09-25). The holder started the system bus proxy, a hermetic
  zone's session bus proxy and the sound filter as the user — inside the
  zone's user namespace, with the zone programs' very uid and no
  capabilities, and dumpable again after `exec`. The kernel lets such a
  process be read by its peers (`PTRACE_MODE_READ`, which Yama does not
  limit), so a program of any zone (outside a sandbox) could open
  `/proc/<pid>/root` of a helper: the host's file system as the host sees
  it, none of the zone's covers — the unfiltered session bus (then
  `StartTransientUnit`: code on the host, in its network) even from a
  hermetic zone, `pulse/native` around the filter, the compositor's socket,
  the project's state. The unit's own process now starts them before the
  holder goes on, in the host's user namespace, where a zone's programs
  have no `CAP_SYS_PTRACE`; the holder
  no longer supervises them (the unit's process logs a helper's death and
  stops them with the zone). The sound filter also makes itself not dumpable
  first thing, as the bus filter does, and whatever it starts — the
  microphone question's kdialog — is in the host's namespace as well. They
  keep the unit's supplementary groups now (the zone's namespace dropped
  them), which the sound server and the buses do not judge a client by.
  VM: from a zone, `/proc/<pid>/root` of the sound filter, of both proxies
  and of an open question's kdialog is refused, from the host the proxy's
  and the kdialog's read; each is in the host's user namespace.
- **The sound filter passes an allow-list, and a zone no longer records what
  the host plays** (`rust/src/pulse_filter.rs`, LEAK-MODEL §17). It refused
  four commands and passed the rest: a zone could set the default output,
  move another program's stream, change a device's volume, a card's profile
  or port, suspend a device, reach the extensions — and record the monitor of
  any output. Now only what an ordinary program needs passes: the handshake
  (once, protocol 13 or newer, before anything else), playing and recording,
  the control of its own streams, reading about devices, events, the sample
  cache; the volume, mute and info of a stream by its index only for a
  stream the connection made (the filter pairs replies with requests by tag,
  so every tag has to be above the last, as libpulse counts them); anything
  else — a command added to the
  protocol later included — is answered `ERROR`/`ACCESS` and never reaches
  the server. Property lists keep only PulseAudio's descriptive keys
  (`application.*`, `window.*`, `event.*`, `media.name` and its kin):
  pipewire-pulse copies them into the node, where `target.object`,
  `stream.capture.sink` or `media.class` chose what a stream records.
  Recording a monitor — by its name, by an index or a name that reads as
  one (`"0x10"`), by `direct_on_input` — is refused before the server sees
  it; after that the server's own word decides: the reply to a new record
  stream and every move name the source it is linked to, and a monitor there
  (a default source that is one, a fallback, a restored target) ends the
  connection before the reply or any sound reaches the program. A microphone
  and the default source stay allowed. The filter reads a packet only for a
  command it may pass and only after the handshake, and gives up a packet of
  more than 4096 values (its own and its property lists' entries) as
  unreadable: a 16 MiB frame of one-byte values would otherwise have cost the
  host some 800 MiB per connection. VM test: a module load and a
  monitor's recording are answered by the filter and never reach the server,
  a playback stream reaches it without its target, a record stream the
  server links to a monitor loses the connection with nothing heard. Raw
  `pipewire-0` still records a monitor (ROADMAP §17).
- **`vpn-zone doctor`'s probe is no longer open to the zone it checks.**
  Without capabilities it was an ordinary, dumpable process of the zone: a
  program there could read its `/proc/<pid>/environ` — the environment of the
  terminal the doctor was run from — and open its `/proc/<pid>/fd/1`, the pipe
  to the doctor, to write lines of its own ahead of the probe's, or stop it
  and hang the doctor. The probe is now not dumpable before it drops its
  rights, gets no environment but `HOME`, and is waited for 30 s at most and
  read up to 4 MB; an answer that names a check twice is not taken. The text
  report writes out every control character (and bidirectional overrides):
  a file named with an escape sequence in the zone's runtime directory no
  longer reaches the owner's terminal — erasing the `✗` lines, or setting the
  clipboard with OSC 52. `--json` escapes DEL and C1 too.
- **The zone's Wayland directory is read-only in the zone**
  (`vpn-zones/wayland/<zone>`, `rust/src/zone.rs`). It holds the socket of
  every launch of the zone, and it was bound writable: a program of one launch
  could unlink another launch's `wl-sandbox-<pid>` and listen there itself,
  and that launch's next connection — a new window, a dialog — came to it,
  keys and clipboard with it. connect(2) still works; unlink and bind get
  EROFS. `wl-sandbox` makes its sockets through the host's path. VM: from the
  zone a launch's socket cannot be removed nor a file put beside it.
- **The broker holds a peer that has exited by nothing.** `SO_PEERPIDFD`
  answering ESRCH (the peer has gone) used to fall back to a pidfd opened by
  the peer's number — whoever had it by then. Only a kernel without the option
  (`ENOPROTOOPT`) falls back now; the helper is shared with the Wayland proxy
  (`sys::peer_pidfd`).
- **Third review round: a zone loses sight of the project's own state.** A
  program in a zone without a sandbox has the home, and the project's state
  lay in it: the raw xdg-dbus-proxy socket behind the zone's bus filter (a
  connection past the portal allow-list), `zone.pid`/`zone.start` (the broker
  took a namespace for whatever zone those files named — a launch in another
  zone, or on the host, without a question), the locks, the pins, and every
  zone's private key. The zone's mount namespace now covers
  `~/.local/state/vpn-zones` with a tmpfs and binds back only the throwaway
  containers' layers (writable) and the launch registry (read-only);
  `~/.config/vpn-zones` and `~/.local/share/vpn-zones` are read-only there.
  System-zone commands get the same cover. **Zones up before the update have
  to be restarted.**
- **The Nix daemon is out of a zone's reach, unless the zone is let**
  (`vpn-zone nix-daemon <zone> on`, or `programs.vpn-zones.nixDaemon`): it
  builds and fetches in the host's network, and a fixed-output derivation
  fetches any address a program names — from any zone, an offline one too.
  **A zone where `nix-shell` or `nix build` is used has to be let before it
  is restarted.**
- **`vpn-zone status --json`** names, for each zone, `nix_daemon` and
  `host_files_writable` with their source, as `hermetic` and `x11`.
- **In a hermetic zone, what the host runs from the home is read-only**
  (owner, 2026-09-25): autostart, user units, launcher entries, D-Bus
  services, the shells' and compositors' configs, `~/.ssh`, browsers'
  native-messaging hosts. The session's entry points are created when missing,
  so that there is something to cover. A zone that has to write there is let
  (`vpn-zone host-files <zone> writable`, `programs.vpn-zones.hostFilesWritable`).
  home-manager's links in the home itself cannot be covered by a mount — the
  sandbox is what protects those.
- **`vpn-zones-off` and turning the emergency key take a password at the
  machine too** (owner, 2026-09-25): a line a zone's program slips into the
  shell's startup would otherwise switch the protection off at the next login
  on the seat. Turning it back on, and the key back, need none there.
- **The bus filter reads the end of the authentication as the proxy does.**
  It took only an exact `BEGIN\r\n`; xdg-dbus-proxy (like dbus-daemon) also
  takes `BEGIN` followed by a blank and anything. After such a line the proxy
  applied its rules to messages the filter still passed on unread — OpenURI to
  the host's portal among them. Now the filter follows the proxy's own rules,
  refuses the lines the proxy would refuse and passes the end on as the plain
  `BEGIN`. VM test with a raw client.
- **Programs in a zone keep the user's own group only.** They kept the
  session's supplementary groups: `libvirtd` and `docker` start things in the
  host's network for their members, `input` reads every key pressed.
  `profile-run` sheds them in the zone's user namespace (`nsenter
  --keep-caps` for every zone launch now); the system tier's commands keep the
  account's own group too — an allow-list instead of a list of groups to drop.
- **Egress:** the system tunnel's mark lets out only UDP from a socket with no
  owner or root's (a program able to mark its own socket went anywhere);
  IGMP, MLD and router solicitations go to multicast only, neighbour
  discovery with hop limit 255; in `strict` a `forward` chain keeps routed
  guests (docker's and libvirt's bridges) to the local network.
- **A plain system zone does not reach the host itself**: a host table refuses
  its pasta the host's own addresses, which the kernel delivers over `lo`
  past every firewall.
- **An OpenConnect zone needs its uplink filter**: for a userspace client it
  is the only thing keeping it to its gateway, so the zone does not come up
  without it.
- **The broker**: never "the same zone" for the host's network by name;
  "always" is not offered for a command with options; the question shows every
  word on its own line, without text-reordering characters, and a command too
  long to show whole is refused rather than cut.
- **Sound and camera devices out of every zone's reach.** logind gives the
  session's user an ACL on `/dev/snd/*` and `/dev/video*`, and a program in a
  zone is that user: it opened the microphone's capture device directly, past
  PipeWire and any permission. `/dev/snd` is covered in every zone (sound goes
  through the pulse filter and PipeWire); cameras (`/dev/video*`,
  `/dev/media*`, `/dev/v4l`) are `/dev/null` there, including one plugged in
  later, unless the zone is let (`vpn-zone camera <zone> on`,
  `programs.vpn-zones.camera`; `camera` in `status --json`).
- **`/run/systemd` by an allow-list in every zone** (and for the system
  tier's commands): systemd's services answer over varlink there, open to
  everyone — `io.systemd.Hostname` the machine's name, model and id,
  `io.systemd.Network` its interfaces and addresses — past the system bus
  filter. A tmpfs over it, with the journal's sockets, `system/` and logind's
  state bound back. dhcpcd's unprivileged socket and sshd's unix socket
  (`/run/ssh-unix-local`, a login on the host for a key in `~/.ssh`) are
  hidden. Found by the doctor's socket inventory; a clean hermetic zone now
  names none.
- **Input methods by their portals only.** A zone's bus let programs talk
  to `org.fcitx.Fcitx5`, fcitx5's whole controller: `Configure` starts a
  program on the host, `OpenX11Connection("host:0")` has the host's fcitx5
  open a TCP connection anywhere, and `SetConfig` switches on cloud pinyin,
  which fetches from the host's network. IBus runs nothing for a client, but
  its private bus is a socket by path in `~/.cache/ibus`, past the bus rules.
  Now only `org.freedesktop.portal.IBus` and `org.freedesktop.portal.Fcitx`
  (sandboxes get them too), `~/.cache/ibus` and `~/.config/ibus` are hidden in
  a zone, and its programs get `IBUS_USE_PORTAL=1` — typing goes as in
  Flatpak.
- **Notifications from a zone reach the host's daemon without what points
  anywhere.** The daemon runs on the host: a link in the text is opened there,
  an icon or an image by URL may be fetched there, `desktop-entry` activates
  that application on a click — past the door OpenURI is. The bus filter
  rewrites `Notify`: only `b`, `i`, `u` stay in the text, an icon by URL is
  dropped, the hints keep an allow-list (urgency, category, image data, a
  local image path, sound name …); the portal's `AddNotification` loses
  `markup-body`. VM test with a daemon that records what it gets.
- **`vpn-zones-on` fails when the egress policy does not load** — zones come
  back all the same, but "on" without the policy is not said to be on.
- The passt edit checks where it lands (the flow's `connect()` right after,
  its reset close by, a `cancel:`), so a reshuffled release fails the build
  instead of resetting another branch.
- **The sound filter closes a connection whose server offers a shared ring
  buffer** (`ENABLE_SRBCHANNEL`): after it, commands would travel past the
  filter. pipewire-pulse never offers one; a PulseAudio server would, and then
  a zone gets no sound rather than an unfiltered one.
- **Smaller**: PipeWire's unrestricted `pipewire-0-manager` is never bound
  into a zone; io_uring and userfaultfd answer ENOSYS in the sandbox; the TTY
  console's `x` and `k` take the key twice; `vpn-zone gc` signals through a
  pidfd; the runtime watcher does not follow a link a program put in its way;
  a sandbox cannot be granted a shell's init file or direnv's, docker's or
  containers' configuration.
- **The TTY console drops keys pressed before its menu is up.** Keys typed
  while it waited for the tunnel, left over from the shell that just ended, or
  a terminal's answer to something a program printed were read as the menu's
  choice — `x` switches vpn-zones off, `k` turns the emergency key. The menu
  flushes the terminal's input before it shows itself. It also waits for the
  tunnel once per console: back from a shell, it says how things are at once.
- **pasta resets what it cannot bind to the zone's interface** (review of
  2026-09-25). Between an interface going away and the watcher killing pasta,
  pasta connected TCP unbound — by the host's routes, with the host's address
  (an ISP ending a PPPoE session, a VPN server dropping a system client is
  enough). The pasta both modules install is built with a small edit that
  resets such a flow instead; it is applied by meaning, not as a diff, so it
  fits passt releases that differ, and fails the build loudly where it does
  not.
- **Second review round, launcher entries and the picker:** an autostart entry
  with `X-GNOME-Autostart-enabled=false` is taken over (systemd's generator,
  which starts autostart under niri and sway, does not know the key and ran
  it around the picker), the key kept for GNOME; a menu editor's "deleted"
  stub under a system entry's name is taken over with its flags and given
  back as it was (xdg-open and GLib went past it to the system entry); a
  localised `Exec[ru]` is dropped from autostart entries too; the launch
  window starts on the pinned network when "always" is ticked for it; a new
  profile that cannot be made starts the program in its own sandbox; the
  window menu cuts more invisible characters from a window's own name and
  shows no markup through kdialog.
- **Second review round, the module and the uplink:** a certificate file with
  a private key in it is refused by the option's type, before it is copied to
  the store; container names the runtime reserves (`__…`, `main`, `own`,
  `ask`, `pinmain`) and bad `defaults.container` values are refused; custom
  `xdg.dataHome`/`configHome` are refused with a message (the interception
  lives in the default ones); `niri.includeInConfig` needs a config.kdl
  home-manager writes as text; the broker starts its own binary from the store,
  not the profile's `vpn-zone` (a link a program with the home could
  repoint); a sandbox is never granted browsers' native-messaging hosts,
  user tmpfiles, more compositors' and shells' configs, pipewire and
  wireplumber configs, git's, KDE service menus or file managers' scripts;
  the uplink namespace (where OpenConnect runs) sees neither the system bus,
  nor the session's runtime directory, nor the host's `/tmp`.
- **The sound server through a filter** (review of 2026-09-25). Every zone,
  the hermetic and `offline` ones too, got the host's `pulse/native` — where
  a client may `LOAD_MODULE` `module-tunnel-sink`, `module-rtp-send` or
  `module-native-protocol-tcp` and make the HOST's sound server connect out,
  or listen, in the host's network. The holder now starts `pulse-filter` on
  the host and binds its socket as the zone's `pulse/native`: the protocol's
  frames pass whole, with their descriptors, except `LOAD_MODULE`,
  `UNLOAD_MODULE` and `KILL_CLIENT`, answered `ERROR`/`ACCESS`. VM test with a
  stand-in server that sees what reaches it.
- **The zone's sockets are bound only as what they are.** The filters' and
  the system bus proxy's sockets live in the zone's directory, which is the
  user's: a symlink put there in time gave the zone the host's own system or
  session bus. They are bound through a descriptor opened without following
  links and checked to be the user's socket.
- **A container's roots stay the container's.** The trust layer compared the
  NSS databases' paths as written: a sandboxed program that made `.pki` or
  `.mozilla` a link to the host's own had the host's browsers trust the
  container's roots. Paths are compared resolved now.
- **Second review round, D-Bus:** the portal's network monitor and proxy
  resolver are answered by the filter (the zone's network up and direct):
  `CanReach` had the host look up and try any name in its own network; the
  trash is no longer among what passes; the link opener drops
  `NIXOS_XDG_OPEN_USE_PORTAL`, with which xdg-open handed a link to the
  portal over the session bus — the host's, in an ordinary zone.
- **Second review round, the system tier and configs:** a config's keys and
  section names are read the way wg reads them, whitespace dropped — `Listen
  Port` and `[Inter face]` passed our filters as something else and wg took
  them for `ListenPort` and `[Interface]`; polkit's "no password" also
  requires the asking process to be in a login session's own scope (a unit the
  user's manager starts was taken for the display session); an uplink is given
  only when the rule keeping user zones out of the system zone is in, for the
  bridge group; an empty `uplink` stops the zone and the option is typed; a
  declared user can take over a config somebody else added on the spot; a
  command that ignores SIGTERM after its client left is killed after 5 s; the
  service's descriptors are closed on kernels before 5.11 too; groups that open
  host daemons (docker, libvirtd, podman, lxd, incus-admin) are dropped from a
  system zone's command; a parse error shows a key only when it is a plain word.
- **Second review round (2026-09-25), the launch path:** the zone entered is
  checked from inside — `profile-run` compares its own network namespace with
  the one `vpn-zone run` checked, since `nsenter` finds the zone again by a
  number, later; a zone without the holder's start note is not up (zones up
  since before the update are restarted once); the start notes of finished
  launches stay while a record names them; the broker refuses a request that
  looks like the host's (the host never needs it), shows the chosen container
  in its question and keeps it in "always"; `vpn-zone rm` also drops the
  broker's "always" answers for the zone; the window menu names a program
  only from the user's own launches.
- **The portals are asked only for what they would ask the user about**
  (review of 2026-09-25). xdg-desktop-portal knows its caller by the process
  on the other end of its connection — our proxy, outside the sandbox and the
  zone's mounts — and finds no `/.flatpak-info` there: every program of a
  hermetic zone or a sandbox was a HOST application to it. A host application
  gets without a dialog what a Flatpak is asked about: the dynamic launcher
  installs a launcher of the caller's making and starts it on the host, in the
  host's network; location, camera, a non-interactive screenshot, the Secret
  portal's key come the same way. The bus filter now lets through only named
  portal interfaces (file chooser, file transfer, settings, notifications,
  inhibit, network and memory monitors, proxy resolver, print, trash,
  screencast, account — and OpenURI, Email, Background, which it answers
  itself) and answers the rest, a portal added later included, with
  AccessDenied; a call that names no interface is refused too. The sandbox's
  `vpnzone.app.<id>` never reached the portal for the same reason; giving
  sandboxes their identity with the portals (the proxy inside the sandbox, as
  Flatpak runs it) is the next step. VM test: the dynamic launcher refused
  from a hermetic zone.
- **Only a throwaway container of ours can be joined.** `--tmp-profile
  --join <dir>` took any existing directory for a throwaway layer — which is
  erased behind its last tenant; a directory named by a request through the
  broker, or by a slip, would have gone with it.
- **What says "alive" means it** (review of 2026-09-24): `check`,
  `status --json` and `doctor` took any handshake line for a live tunnel — an
  hours-old one of a dead tunnel too; now a tunnel `vpn-zone watch` found dead
  in this run of the zone is not alive. A zone through a system zone whose
  tunnel says nothing is "disconnected", not its own link's "connected"; the
  previous run's status is removed when a zone starts.
- **The uplink namespace does not see the host's resolvers**: OpenConnect runs
  there, and a name it looked up (a redirect, a gateway list) went to the
  host's resolved over its socket, in the host's network.
- **`DNS =` takes addresses only**: wg-quick's search domains became
  `nameserver` lines, and a list of domains only left no resolver at all.
- **Declared settings are applied whatever `xdg.configHome` is.** They were
  written below `xdg.configHome` and read from `~/.config`: with a custom one,
  the declared network bindings of containers silently did not apply.
  `containers.<n>.network` and `defaults.network` are typed to a network name.
- **A zone through an interface of the host goes down when the interface goes
  away** (review of 2026-09-24). pasta binds every socket to the interface —
  and when that fails because the interface is gone, it only notes it in its
  debug log and connects the TCP socket unbound: by the host's routes, with
  the host's address (passt's `tcp_bind_outbound`). The holder of such a zone,
  and a system zone's uplink, now watch the interface over rtnetlink and kill
  pasta the moment it is deleted or renamed; a zone whose interface cannot be
  watched does not come up. VM test: the interface deleted under a running
  zone, the zone down within seconds.
- **The system tier, from the review of 2026-09-24.** Nothing there let a user
  do more than their own, but:
  - **every `vpn-zone-sys` command was hung up after 5 s** — the request
    timeout stayed on the connection, and the watcher took it for the client
    leaving (the TTY console's shell included). Cleared once the request is
    in; only the end of the stream or a reset ends the command;
  - a command in a system zone **reached this service's socket** and could
    ask for another zone: `/run/vpn-zones` is covered and the `vpn-zones`
    group dropped from its groups;
  - it **saw the host's `/tmp`** (X11, tmux, singleton sockets that trust the
    user's uid) **and the Nix daemon** (fetches in the host's network): it gets
    its own `/tmp`, `/var/tmp`, `/dev/shm`, and no daemon socket;
  - the switch-off and emergency-key polkit rules asked nobody from anywhere:
    no password from the local active session, a password from elsewhere (ssh,
    cron, a zone's command with the system bus);
  - fail closed: an `uplink` that names no interface stops the zone instead of
    going out by the host's routes; no `vpn-zones-bridge` group — no uplink,
    rather than one into the system zone; a declared zone does not use a
    config added on the spot under its name by somebody not among its users;
  - a config added on the spot loses `ListenPort` (the socket is the host's —
    port 53 was possible); parse errors show a line's key, never its value, in
    root's journal; the command gets no descriptor of the service but 0–2.
- **What a zone asks for is a file name, and not the user's launch.** The app
  id the broker passes on from a zone was a path in the registry
  (`/run/user/…`, `../..` — a file rewritten on the host); it is a file name
  now. A launch asked for from inside a zone is marked, and the picker's
  "already running — start it there" follows only the user's own launches: a
  program in a zone could start something under the id `firefox` and have the
  next click on Firefox go to its network without a question.
- **The picker never falls back to the least safe row.** A remembered network
  that is no longer offered (a zone removed after `vpn-zone default` named it)
  used to leave the first row marked — the host's network; a remembered
  container that is gone left the main profile marked. They start on
  `offline` and on the program's own sandbox now; `vpn-zone default` refuses
  a zone that does not exist, `vpn-zone rm` clears a default that named it. A
  new sandbox that cannot be made starts the program in its own sandbox, not
  in the main profile, and says so. Container names the menus use as tags
  (`pinmain`, `__fs__`, anything with `:`) are refused.
- **Launcher entries: deleted ones, localised commands, deep folders.** A
  user entry "deleted" by a menu editor (`Hidden=true`) is still what
  xdg-open runs when `mimeapps.list` names it — it is taken over now; a
  localised `Exec[ru]=` was copied into our entries past the picker and is
  dropped like `Exec`; Wine's entries are found at any depth, not three
  folders down.
- **Small ones from the same review:** a window's own name is shown in quotes
  and without bidi characters; notify-send gets `--`; a zone name cannot
  start with a dash.
- **A link with no handler opens nothing, instead of a browser around the
  picker.** Links of sandboxes and hermetic zones are opened with xdg-open in
  the zone; for a scheme with no handler it ran `$BROWSER` or the first of
  its own list (firefox, chromium, …) by itself — past the picker, with the
  main profile, in the network the link came from. The opener now runs it
  with `BROWSER=false`.
- **The portals by name, the sandbox's app id in a namespace of our own, no
  background requests** (found by a review on 2026-09-24). The bus of a
  sandbox and of a hermetic zone let through `org.freedesktop.portal.*` — a
  subtree with `org.freedesktop.portal.Flatpak` in it, the portal that starts
  processes outside the caller's sandbox. Only the desktop and the document
  portals are let through now, by name. The portals know a program by the
  `name=` of its `/.flatpak-info` and keep what the user allowed under it; the
  name was the program's own id, which a program started into a zone can
  choose — `org.mozilla.firefox` would have inherited an installed Flatpak's
  camera, location, screencast or Secret grants. It is `vpnzone.app.<id>` now
  (grants given to sandboxed programs before are asked again once).
  `Background.RequestBackground`, with which the portal writes an autostart
  entry on the host, is refused by the filter.
- **The broker refuses what it cannot place** (found by a review on
  2026-09-24). The one door out of a hermetic zone learnt the asking zone from
  `/proc/<peer pid>/ns/net` after reading the request — and a peer it could not
  place was taken for the host and started without a question, `unconfined`
  included. A program that asked and exited before the broker looked (or asked
  from a namespace of its own) had its command run on the host, in the host's
  network. The peer is now pinned when the connection is taken — the kernel's
  pidfd of the very process that connected (`SO_PEERPIDFD`), a pidfd opened at
  once on older kernels —, its namespace read only while that process lives,
  and anything that is not the host, a zone or a system zone is refused. A
  system zone asking is a person's question, never "the same zone" as a user
  zone of its name.
- **The broker asks one question at a time, and never "always" for a shell.**
  "Always" was remembered per program, and any program of the store counted:
  one "always" for `sh`, `env` or `python3` let every command behind it
  through. Shells, interpreters and wrappers are never remembered now. A
  request that needs a question while one is open is refused, not queued —
  a stream of dialogs is how a "yes" is got by accident. The command in the
  question is shown on one line, without markup.
- **A zone is entered only when it is ready.** `zone.pid` appears as soon as
  the namespaces exist, before the host's resolvers are hidden, the system bus
  filtered, the runtime sealed and the zone's resolv.conf bound; a launch
  that came then (a second autostart, a double click) copied that half-built
  mount tree into its container or sandbox and kept the host's resolv.conf for
  good. `vpn-zone run` now waits for `ready` too.
- **A sandbox is never granted what the host runs by itself**: launcher
  entries, autostart, user units, D-Bus services, `~/.local/bin`, the PATH
  shims, the environment, the compositors' and shells' configs, `~/.ssh`,
  `~/.gnupg`, home-manager's and nix's state — nor anything above them. A
  file written there by a sandboxed program was code the session started for
  it, outside the sandbox and the zone.
- **`vpn-zone lock` says where it holds.** The lock is kept by the broker, the
  one door of a hermetic zone; a zone that is not hermetic has
  `systemd --user` in reach, and the lock there promised what it could not
  keep. Locking such a zone now warns and says how to make it hermetic.
- **Process marks carry the boot.** The start time counts from boot, and
  `zone.start` and the registry's marks outlive a reboot: a mark is now the
  start time with the boot's id, and one from before a reboot matches nothing.
- **A pid is not a process: the registry and the zones keep start times.** The
  launch registry is on disk, outlives a reboot and is swept lazily, so after
  a reboot (or once numbers come round in a long session) a record's pid
  belonged to somebody else — and the picker, taking the program for running,
  started a click into its old network WITHOUT asking, `unconfined` included.
  `vpn-zone run` now notes the start time of each launch
  (`.running/.started/<pid>`); what a record makes happen without a question
  (the picker's "already running — start it there", the zone of a window)
  needs it to match. `zone.pid` gets `zone.start` the same way: a stopped
  zone whose number went to another process is not "up" — `vpn-zone run`
  would have entered that process's namespaces, the host's network among
  them. And right before the `exec`, a zone whose process is in the host's own
  network namespace is refused. Records and zones from before the update
  count by their pid as before; a zone restarted after it gets the check.
- **The zone of a window is the kernel's word** (`vpn-zone focused`,
  `window-menu`, found in review on the day they were added). The network is
  the network namespace of the window's own process against the host's and the
  zones'; the registry only adds the container and the program, and only for
  a launch that is certainly still that process and in that network. A window
  in the host's namespace shows as the host's whatever a file says. The menu
  signals the program through a pidfd opened before it shows, not by a number
  that can change hands while it is open; the bar line escapes Pango markup,
  and a program's app id is shown cut clean of control characters.
- **A sandboxed program's links open in its zone, not through the host's
  portal** (`docs/LEAK-MODEL.md` §2). A program in a sandbox sees
  `/.flatpak-info`, so GTK, Qt, Firefox and `xdg-open` open a link with the
  portal's `OpenURI` — and the portal, on the host, handed it to the default
  browser in the host's network or wherever that browser already ran, with
  nobody asked. The sandbox's session bus now goes through `vpn-zone-core
  bus-filter` in front of `xdg-dbus-proxy`: it answers `OpenURI` itself, the
  way the portal would, and opens the link with `xdg-open` in the zone,
  outside the sandbox — from where it takes the door every link from a zone
  takes, the picker and, for another network, the broker's question. The call
  is recognised by method and interface, not by destination. `file:` links,
  `OpenFile`, `OpenDirectory` and `ComposeEmail` are answered as cancelled for
  now. The tools manifest gains `opener` (`xdg-utils`' `xdg-open`).
  A hermetic zone's own session bus gets the same filter, for programs that
  call the portal without a sandbox (libportal, GTK4 with portals): the zone's
  app namespace starts it as the user, the zone gets ITS socket as `bus` (no
  filter, no bus), and a link goes to the broker as "open it in this very
  zone", which the broker starts without a question. The zone holder takes
  `--opener`. Zones up before the update need a restart.
  A refusal is not silent: a file (`OpenFile`, a `file:` link) or a mail the
  filter did not open shows a notification saying why — at most one in 30
  seconds, so a program cannot flood the desktop with them.
- **A hermetic zone has `/tmp`, `/var/tmp` and `/dev/shm` of its own**
  (`docs/LEAK-MODEL.md` §15). The host's `/tmp` held listening sockets nobody
  meant for a zone — a tmux server, whose `run-shell` runs a command on the
  host in the host's network, a VPN client's IPC to a root service,
  single-instance sockets — and `/dev/shm` other programs' shared memory and
  JACK's sockets. Now each is an empty tmpfs in the zone, as Flatpak gives an
  app; a file the host puts into `/tmp` is not seen in there, and the zone's
  `/tmp` is memory, emptied when the zone goes down. Ordinary zones share the
  host's `/tmp` as before, like the rest of the session (§1).
- **A sandbox's bus filter is no longer in `/tmp`.** Its socket lived in the
  `/tmp` every zone without a sandbox shares with the host: a program there
  could connect to the filter of a sandbox in another network and talk on the
  bus as that program. It is now in `$XDG_RUNTIME_DIR/vpn-zones/sandbox/` — in
  a zone the zone's own runtime directory, which no other zone sees. Without
  such a directory the sandbox runs without a session bus rather than with a
  filter in `/tmp`. **Zones up before the update need a restart** (`vpn-zone
  down` / `up`): the directory is made when the zone starts, and until then
  their sandboxes run without a session bus.
- **Throwaway containers moved to `~/.local/state/vpn-zones/.throwaway/`** — on
  a disk, as before, but out of `/tmp`, which a hermetic zone no longer shares.
  `gc` and the picker still find the ones started before the update in `/tmp`.
- **`doctor`: `tmp-sockets`** — the sockets a zone sees in `/tmp`, `/var/tmp`
  and `/dev/shm`. VM test: the evil host's tmux server, a listening socket, an
  abstract one and shared memory, none of them reachable from a hermetic zone.
- **A console program in a system zone (`vpn-zone-sys`) could reach the
  session through `/proc`.** Its own tmpfs hid the session's sockets where they
  lie, but the command ran in the host's user namespace, and the kernel lets
  the same user walk into another process's file system view:
  `/proc/<pid>/root` of any process of the session led to the compositor's IPC
  (whose `spawn` runs on the host, around the tunnel) and the session bus. The
  command now gets a user namespace of its own, the user mapped onto itself —
  the wall user zones already stand behind (`docs/LEAK-MODEL.md` §16); files of
  other users, root included, are seen as `nobody` inside. VM tests for both
  tiers: a socket in the session's runtime directory is reached through
  `/proc` from the host and from neither kind of zone.

### Fixed
- **A flaky proxy test**: `when_the_compositor_goes_the_client_loses_its_display`
  wrote its request after the proxy may already have closed the client
  (EPIPE on a loaded runner). It only checks now that nothing comes back.
- **`vpn-zone watch` does not carry a verdict over a restart**: a zone
  restarted between two looks inherited "dead" and read so while idle.
- **A plain system zone with an uplink needs its own `dns`**: the default
  resolvers are the primary network's, and names meant for one network went
  out through the other.
- **`vpn-zone run offline -- …` works without the picker.** The zone with no
  network was created only by the picker, on demand; typed by hand before the
  picker had ever made it, the launch found no zone. `run` creates it the same
  way now.
- **A sandbox in a hermetic zone has a session bus again.** Its own
  `xdg-dbus-proxy` sat on top of the zone's, and xdg-dbus-proxy cannot be
  stacked: the inner one's own calls carry serials the outer one refuses
  ("Invalid client serial: Exceeds maximum value"), so every connection was
  dropped during authentication — no portals, notifications or tray icon for
  a sandboxed program in a hermetic zone. Found by the new VM test. In a
  hermetic zone the sandbox's bus filter now goes straight onto the zone's
  filtered bus (recognised from the mount table), and the zone's rules — a
  sandbox's plus input methods, media keys and the screensaver inhibitor —
  are the ones in force.
- **Entries in subdirectories are intercepted** (owner, 2026-09-24: Wine's
  programs started with no network dialog). Wine puts the entry of every
  program it installs at `~/.local/share/applications/wine/Programs/…`, and
  the interception read only the top of each directory: such a program ran in
  the host's network, around the picker (`docs/LEAK-MODEL.md` §11). Directories
  are now walked four levels deep, entries named by their desktop-file ID as
  the menu specification says (`wine/Programs/X.desktop` is
  `wine-Programs-X.desktop`): the user's are taken over where they lie and
  given back there, a system one is shadowed by that name from the top of the
  user's directory. Symlinked and hidden directories are not entered. The
  path unit also watches `wine/Programs`.
- **`vpn-zone-gui` is in `PATH`.** The windows were reachable only from their
  menu entries, by a store path; a configurator opening "VPN zone containers"
  by name (`vpn-zone-gui containers`) or a person in a terminal got
  `No such file or directory`. It now comes as a two-line wrapper, like
  `vpn-zone` and `vpn-zone-pick`.
- **A home of its own looks like the desktop.** A program in a private home —
  its own container, or started at login before anything was chosen for it —
  got the toolkit's light defaults: the colours, GTK's settings and the icon
  themes live in the real home (owner, 2026-09-24: KeePassXC started at login
  and Claude Desktop in its container were white while the desktop is dark).
  The sandbox now binds them read-only, as Flathub's KDE and GTK builds get
  `xdg-config/kdeglobals:ro`: `kdeglobals`, KDE's defaults, qt5ct/qt6ct,
  Kvantum, fontconfig, GTK's settings and style sheets (not its bookmarks),
  icon and cursor themes, fonts. A path that resolves into the state of this
  project is left out. A theme changed while the program runs reaches it at
  its next start: a file replaced on disk stays the old one under a bind.
- **Tray icons in hermetic zones and containers.** Electron (Claude Desktop,
  Discord) and Qt (Telegram and its forks) register their icon as
  `org.kde.StatusNotifierItem-<pid>-<n>` and show none when they may not own
  that name — and the filter did not let them: xdg-dbus-proxy has only
  `org.kde.*`-style wildcards, and owning all of `org.kde.*` would own
  KWallet's name too. The proxy now carries a small patch
  (`module/patches/xdg-dbus-proxy-own-prefix.patch`): `--own=NAME-*` lets a
  program take `NAME-<letters, digits, _ and ->` and nothing more — no seeing
  or talking to other programs' tray items. Checked in the VM test and by hand
  against a private bus: the icon's name taken, `org.kde.kwalletd6` refused,
  the tray host's calls reach the program.

### Changed (behaviour — read before updating)
- **Zones are hermetic by default** (`docs/HERMETICITY.md` §7 C): with no
  setting of its own a zone has no `systemd --user`, its session bus goes
  through the filter, and a launch in another network goes through the
  broker, which asks. The ordinary mode let any program in a zone have the
  host's session start a process outside it, around its tunnel; the kernel
  never let the zone's own processes out, but a helper outside did.
  The way back is explicit: `programs.vpn-zones.hermetic.default = false`,
  a zone in `hermetic.exceptions`, `vpn-zone hermetic --default off` or
  `vpn-zone hermetic <zone> off`. What a hermetic zone does not have yet:
  bus permissions from Flathub manifests and a Secret Service of its own —
  programs that keep their login in the keyring (Electron ones among them)
  do not reach it; give such a zone an exception until then.

### Fixed
- The broker is socket-activated (`vpn-zone-broker.socket`), and every zone
  wants its socket. It used to be a service wanted by `default.target`: when
  home-manager put its unit in place after the user manager had reached that
  target (a switch, or a first boot), it was not started until the next login
  — and a hermetic zone's one door out was missing (red in CI).

### Added
- The broker's question has a third answer, **always**: remembered as zone →
  network → program (`~/.config/vpn-zones/broker-always`), offered only for a
  program of the store — what a zone cannot replace. `docs/HERMETICITY.md`
  §3.

### Security (a review of the system tier, 2026-09-23)
- A program in any user zone, hermetic ones included, reached the system
  tier's service socket (`/run/vpn-zones/sysrun.sock`): it could add a plain
  zone and run itself there, or attach a system zone's way out to namespaces
  of its own — out around its zone's tunnel. `/run/vpn-zones` is now hidden in
  every user zone; a way out through a system zone is taken from a zone's
  uid 0 only; adding zones is for `services.vpn-zones.system.users` only
  (as documented), and a zone the host's own services go through never has
  its config replaced by a request. `docs/LEAK-MODEL.md` §14.
- A user zone through a system zone could reach services listening in the
  system zone: its pasta now runs with the group `vpn-zones-bridge`, whose
  packets to the system zone's own addresses are refused.
- The system-zone service: 16 connections per user, 5 s to send a request;
  the follow loop re-checks the user and the zone's kind before re-attaching;
  namespaces are checked for their kind (`NS_GET_NSTYPE`).
- `strict`: DHCP ports are let out for the system's users only.
- The egress table is replaced with `add` + `delete table` instead of
  `destroy` (nft 1.0.8 / Linux 6.3 only): a policy that did not load left the
  host open.
- `host.dns`: resolved's LLMNR and mDNS off by default; the DNS forwarder has
  an overall deadline per query and per TCP connection and does not panic
  when no thread can be had. Remaining channels are listed in
  `docs/SYSTEM.md` §9, §9c.

### Added (system tier)
- A system zone through one interface of the host:
  `zones.<zone>.uplink = "<interface>"`. A tunnel zone gets an uplink
  namespace of its own, `vzu-<zone>`, behind pasta bound to the interface,
  and its tunnel is born there; a plain zone's pasta is bound to it. Out by
  that interface or not at all. `system_networks[].uplink` in
  `status --json`. `docs/SYSTEM.md` §4a, `tests/vm-uplink.nix`.

### Fixed
- `tests/vm-bridge.nix` listed the system zone's processes with `ps` per pid
  under errexit, and one ending in between failed the test (red once on
  main).

### Changed (system tier)
- A user zone through a system zone follows the system zone being made anew
  (its namespace unit restarted, vpn-zones off and on): the service starts
  its pasta in the new namespace once the way out there is up, with no
  restart of the user zone; in between the zone has no way out at all.

### Added
- A user zone through a system zone (`docs/SYSTEM.md` §7b): `[SystemZone]
  Name = <zone>`, or `vpn-zone add <zone> --system <system zone>`. No tunnel
  of its own: the system-zone service starts pasta in the system zone's
  network, as the user, attached to the user zone — one VPN, one tunnel, for
  services and programs, graphical ones included, with everything a user
  zone has. `vpn-zone add` with a config whose key is a system zone's makes
  such a zone by itself instead of a second tunnel. `status --json`: kind
  `system-zone` and a new key `system_zone` on every network; the picker
  names the system zone. `tests/vm-bridge.nix`.

### Security
- `host.dns` with NetworkManager and resolved: NetworkManager's
  `systemd-resolved` key (true by default) still sent every connection's
  resolvers to resolved under `dns = "none"`, so part of the host's names
  could go to the router around the zone. Now `dns = "default"`,
  `rc-manager = "unmanaged"`, `systemd-resolved = false`; with networkd, a
  network that would hand resolved its resolvers does not build. dhcpcd's
  `nohook resolv.conf` landed inside an `interface` block and held for one
  interface only: the hook is now skipped from `/etc/dhcpcd.enter-hook`. A
  NetworkManager host in `tests/vm-host.nix` checks it, and no link of any
  test host may have a resolver of its own.

### Changed (system tier)
- A plain zone's resolvers are the router's, as the host knows them
  (NetworkManager's copy, resolved's upstreams, /etc/resolv.conf), followed
  as the network changes; the public ones only when the host knows none.
  The host's DNS forwarder does the same when vpn-zones are off.

### Added (system tier)
- The host's names through a zone: `host.dns = "<zone>"`. A forwarder
  (`vpn-zone-core dns-forward`) gets UDP and TCP sockets on 127.0.0.60:53
  from systemd in the host's network and asks from the zone's; resolved (or
  /etc/resolv.conf) points there alone, DHCP's resolvers are ignored. Off, it
  asks the same addresses from the host. `zones.<z>.dns`: a zone's own
  resolvers. `docs/SYSTEM.md` §9c.

### Added (system tier)
- `egress.mode = "strict"`: the host itself loses the internet too — root
  and the system's users keep the local network (`egress.localNetworks`,
  checked when the system is built) and DHCP. `host.nix` and `host.time` put
  the Nix daemon and systemd-timesyncd into a zone (a plain one is
  "directly", a VPN one hides them); the daemon does not wait for the tunnel.
  NetworkManager's connectivity check is turned off under `strict`; `nixbld`
  is no longer allowed by default there. Build warnings name what `strict`
  would cut off. `docs/SYSTEM.md` §9b, `tests/vm-host.nix`.

### Changed
- The namespace unit of a system zone (`vpn-zone-system-ns@`) has no default
  dependencies (after the local file systems and tmpfiles only), so early-boot services can be
  attached to a zone.

### Added (system tier)
- The off switch: `vpn-zones-off` turns vpn-zones off entirely with no
  rebuild and no network — the policy's table goes, attached services restart
  on the host's network, zones stop, and a flag in `/var/lib/vpn-zones` keeps
  it so across reboots; `vpn-zones-on` turns it back. Plain systemd units, no
  binary of ours; `services.vpn-zones.system.switchGroup` (`wheel`) may use
  them without a password; `[x]` in the TTY console; `vpnzones=off` on the
  kernel command line for one boot. `docs/SYSTEM.md` §9a.

### Changed
- Services are attached to system zones by a systemd generator (a drop-in in
  `/run`), not in their unit definitions, so the switch can detach them.

### Fixed
- The user-tier VM test waits for the broker instead of racing it.

### Security
- The host egress policy fails closed when this project's binary fails: its
  restriction is printed when the system is built and loaded by `nft` alone;
  `vpn-zone-core egress allow` only adds allowances afterwards, and its failure
  leaves the host more closed, never open. The emergency key closes the host
  again from the same file. New verbs `egress print` and `egress allow`.

### Added (system tier)
- One VPN, added once: `vpn-zone-sys --add <zone> <config.conf>` (or
  `--plain`) makes a system zone on the spot — no rebuild, no root for the
  user — and the same private key again answers which zone it already is
  instead of a second tunnel. `vpn-zone-sys --up <zone>`.
  `services.vpn-zones.system.users`: who may add zones.
- Rescue paths: the emergency key deletes the policy's table with `nft` alone;
  `vpnzones.egress=off` on the kernel command line keeps the policy from
  loading. `docs/SYSTEM.md` §9a.

### Changed
- System zones are instances of templates: `vpn-zone-system-ns@<zone>` and
  `vpn-zone-system@<zone>`; the holder reads a zone's settings itself.
- The TTY console brings a zone up through the system-zone service, not polkit.

### Added (system tier)
- The TTY console: `services.vpn-zones.system.console`. Logging in on a text
  console lands in a small menu with a network already — a terminal in the
  console's system zone with one key, the plain fallback zone when the VPN
  does not come up, an admin tool, the emergency key, the plain console. Shown
  in interactive login shells on a virtual terminal only, for the zone's users;
  every failure ends in the ordinary shell. The zones' users may start their
  zones (polkit). `rust/src/console.rs`, `docs/SYSTEM.md` §7a.

### Added (system tier)
- Plain system zones: `services.vpn-zones.system.zones.<name>.kind = "plain"` —
  a namespace of its own that goes out through the host's network by pasta
  (as the system user `vpn-zones-plain`), not encrypted, with the host's
  loopback and port forwarding shut. The way a program goes out directly once
  the host egress policy is enforced, and the TTY console's fallback when the
  VPN cannot come up. `system_networks[].kind` is `plain` for them.

### Added (system tier, ROADMAP M10 stage 5)
- The host without a network of its own: `services.vpn-zones.system.egress`
  (`audit` by default, `enforce`). An nftables table of its own lets out root,
  system and dynamic users, the uplinks of user zones (the first ids of
  `/etc/subuid`/`/etc/subgid`), system zones' tunnels (by a mark: their kernel
  socket has no owner) and the named users and groups; a user's program
  outside every zone is logged as `vpn-zones-egress: … UID=`, and refused under
  `enforce`. Survives a firewall that flushes every table. An emergency key,
  `vpn-zones-egress-open.service`, lifts it for 15 minutes; `wheel` may turn it
  (polkit, which the module turns on). `rust/src/egress.rs`, `docs/SYSTEM.md` §9.

### Changed
- A system zone's tunnel marks its encrypted packets with `FwMark = 0x767a`,
  replacing any `FwMark` of the config.

### Added (system tier, ROADMAP M10 stage 4)
- `vpn-zone-sys <zone> [--] <command>`: a user's console program in a system
  zone, for the users in `services.vpn-zones.system.zones.<zone>.users`. A
  socket-activated service (`vpn-zone-sysrun@`, one unit per launch) learns who
  asks from the kernel, enters the zone, hides the host's resolvers, the system
  bus and the session's sockets, drops to the user with `NO_NEW_PRIVS` and runs
  the command; the pty is the client's own. `rust/src/sysrun.rs`,
  `docs/SYSTEM.md` §7.

### Security (system tier)
- Services in a system zone get the zone's `nsswitch.conf` (`hosts: files dns`,
  written by `ns-up`) and no `/run/avahi-daemon`, as user zones have had: a
  `.local` name went to the host's LAN through nss-mdns.

### Added (system tier, ROADMAP M10 — not built or run yet)
- `nixosModules.default` (`module/nixos.nix`): system zones held by systemd
  from boot — `services.vpn-zones.system.zones.<name>` — and services and NixOS
  containers attached to them (`…system.services.<unit>.zone`,
  `…system.containers.<name>.zone`). Optional; without it everything stays
  rootless. Design: `docs/SYSTEM.md`; the target picture:
  `docs/ARCHITECTURE.md`.
- `vpn-zone-core system-zone ns-up|ns-down|up|down <name>` (`rust/src/system.rs`):
  the namespace `/run/netns/vz-<name>` with `lo` and the second echelon; the
  tunnel created in the host's namespace and moved in as `awg0`; the zone's
  resolv.conf written in place; `READY=1` to systemd; the status mirror in
  `/run/vpn-zones/system/<name>/` for the group `vpn-zones`.
- `vpn-zone status --json`: a top-level `system_networks` array (additive,
  schema 1).
- A service in a system zone gets `/run/nscd`, resolved's varlink socket and by
  default the system bus hidden; a NixOS container gets its own user namespace
  and no access to the host's Nix daemon socket, which nixpkgs binds into every
  container and through which the host downloads whatever it is asked to.
- `tests/vm-system.nix` and a `vm-system` CI job.

### Changed
- The crate's derivation moved to `package.nix`, shared by both modules. Same
  text, same store path.

### Security (compositor sockets, LEAK-MODEL §13)
- No zone gets the compositor's own `wayland-*` socket or the IPC of niri,
  sway, Hyprland or i3 any more — through them a program in a zone could have
  the compositor spawn a process on the host, or type into a host terminal
  with a virtual keyboard. Every zone's runtime directory is a tmpfs with
  entries bound back: a hermetic zone keeps pipewire, pulse and doc; an
  ordinary zone everything else, the session bus and `systemd --user`
  included. Entries the host creates later (a restarted pipewire or dbus) are
  bound in by a watcher; refused names stay refused.
- `wl-sandbox` wraps the whole launch and runs on the host; the restricted
  socket lives in `$XDG_RUNTIME_DIR/vpn-zones/wayland/<zone>/` and
  `WAYLAND_DISPLAY` points there. `fs-sandbox` now gets that socket instead of
  the compositor's own one.
- `vpn-zone doctor`: `wayland-raw` and `compositor-ipc` checks; `session-bus`
  is reported filtered only when the bound bus is the zone's proxy.

### Changed (compositor restriction in zones)
- In a zone the Wayland restriction always applies: the built-in allowlist,
  `~/.config/vpn-zones/wayland-allow` and `vpn-zone wayland-sandbox off` apply
  to `unconfined` launches only. A screenshot tool or a clipboard manager that
  needs the full protocols has to run unconfined. With a compositor without
  `wp_security_context_v1` a program in a zone gets no Wayland at all.
- `NIRI_SOCKET`, `SWAYSOCK`, `I3SOCK`, `HYPRLAND_INSTANCE_SIGNATURE` are
  dropped from launches into a zone. `wl-sandbox` takes `--zone <zone>`.

### Changed (kill exit codes)
- `vpn-zone kill` exit codes are a contract now: 0 cut off, 1 programs killed
  but the zone not down, 2 the zone is not up, 3 refused (nothing touched).
  "Not up" and "refused" were both 1.

### Added (grants with a term)
- `vpn-zone container grant sb:<name> <dir> --for 30m|2h|7d` and a term
  choice in the GUI. A grant past its term is absent from every launch; for
  programs already running a user timer runs `vpn-zone container expire`,
  which detaches the directory in their mount namespaces. `revoke` now does
  that at once too, instead of "from the next launch".
- Journal events `grant`, `revoke`, `grant-expired`; `status --json` and
  `container show --json`: `permissions.paths[]` gains `expires` (additive).

### Added (cut a zone off)
- `vpn-zone kill <zone>` and the «Оборвать VPN-зону» launcher entry
  (`vpn-zone-gui kill`): every program in the zone's network namespace is
  frozen, the zone goes down, the frozen programs are killed — for a
  remote-access session that has to end now. The zone's own processes are
  left to `systemctl stop`; signals go through pidfds; a "zone" whose
  namespace is the host's is refused. Recorded in the journal as `kill`.

### Added (unconfined in sight)
- A journal of what was let out of containment: every launch into
  `unconfined` (`launch-unconfined`: app, container, program, pid) and every
  decision of the broker (`broker`: origin zone, target, app, started or
  refused and why). JSON lines in `~/.local/state/vpn-zones/.journal` (0600,
  rotated at 1 MiB into `.journal.1`); `vpn-zone journal [--json] [<N>]`
  reads it (`{"schema_version": 1, "events": [...]}`).
- `status --bar`: programs running unconfined right now are marked in the text
  (`⚠N`) and named in the tooltip; the object gains `"unconfined": N`
  (additive; `class` is unchanged).

### Changed (breaking, with the old name kept)
- The built-in network `direct` is now `unconfined`: the name says that nothing
  of a zone is around the program — no VPN, the host's resolver, session bus,
  `systemd --user` and X server. `direct` stays an alias everywhere a network
  name is read — `vpn-zone run`, `vpn-zone default`, `container set … network`,
  `defaults.network` and `containers.<n>.network` in Nix, pins, `.last`,
  settings and registry records written before — and is never written again.
  The picker and the GUI call it «Без ограничений — сеть хоста, без VPN и без
  изоляции зоны».
- `status --json` (schema_version 1): the built-in entry of `networks[]` is
  `{"name": "unconfined", "kind": "unconfined", "aliases": ["direct"], …}`,
  every entry has `aliases` (additive), and `defaults.network.value`,
  `containers[].network.value`, `apps[].network.value` and the live launches'
  `network` say `unconfined` where they said `direct`. A consumer matching
  `direct` must accept `unconfined` (or read `aliases`).
- Migration: a zone the user had named `unconfined` is no longer entered — a
  launch into it is refused instead of silently using the host's network, the
  picker does not offer it and `vpn-zone doctor` fails on it. Rename its
  directory in `~/.local/state/vpn-zones/`. `vpn-zone add` refuses the name.

### Added (hermetic switches)
- `programs.vpn-zones.hermetic.default` and `hermetic.exceptions` (zones set
  opposite to the default; the default is required with them), and locally
  `vpn-zone hermetic --default on|off` and
  `vpn-zone hermetic <zone> on|off|default`. The default is still off.
- `status --json`: `defaults.hermetic` (additive); `networks[].hermetic` now
  names `nix` when the value comes from the module.

### Changed
- `vpn-zone hermetic <zone> off` writes `off` into the zone's marker instead of
  removing it, so that it holds against a default that is on; `default`
  removes it. A marker left by the prototype (empty) still means on.

### Added (egress marker)
- `status --json` carries `uplink_owner`: the host uid and gid every zone's way
  out runs under (the zone's uid 0, the start of the user's subordinate
  ranges), for a host egress policy matching `meta skuid` (additive).

### Added (hermetic zones — prototype, off by default)
- `vpn-zone hermetic <zone> on|off` (takes effect at the zone's next start):
  the zone's runtime directory is a tmpfs of its own with only the Wayland,
  PipeWire and PulseAudio sockets and the document portal bound back; the
  session bus is a filter (portals, notifications, tray, MPRIS, IBus/fcitx,
  the screensaver inhibitor — not `systemd1`, not the Secret Service);
  `systemd --user` is out of reach. A launch out of such a zone goes through
  the broker (`vpn-zone-broker` user service): into the same zone at once,
  into another network only after a person says yes, never from a locked
  zone. `status --json` networks carry `hermetic` as `{value, source}`;
  `doctor` reports the session bus as filtered. The owner's decision C, as the
  prototype that is proven before it becomes the default.

### Added (X11 per zone)
- `vpn-zone x11 <zone> on|off` and `programs.vpn-zones.zoneX11 = [ names ]`:
  every program launched into such a zone gets an X server of its own
  (`x11-run`), without any container — Steam in a zone for someone who runs
  zones only. The host's X server stays out of reach. `status --json`
  networks carry `x11` as `{value, source}` (`null` for `direct` and
  `offline`'s built-in entry; additive).

### Security (X11 closed in zones)
- A zone hides `/tmp/.X11-unix` behind a tmpfs of its own, and a launch into a
  zone carries no `DISPLAY` or `XAUTHORITY`: the host's X server — every
  client of which sees the windows, the keyboard and the clipboard of all the
  others — and the X servers of other zones are out of reach (the owner's
  decision A). A container with `x11` — `vpn-zone container set <c> x11 on` or
  `programs.vpn-zones.containers.<name>.permissions.x11` — gets an
  `xwayland-satellite` of its own in zones (`vpn-zone-core x11-run`, started
  inside `wl-sandbox` and taken down with the program); a sandbox is told the
  same and starts its own. `container show --json` carries `x11` as
  `{value, source}` (additive). **Behaviour change:** X11-only programs in a
  zone (Steam, some Electron builds) need a container with `x11`.

### Security (the system bus in zones is filtered)
- Every zone gets its own `xdg-dbus-proxy` in front of the system bus, bound
  over `/run/dbus/system_bus_socket` in the zone's mount namespace: UPower
  whole, login1 only `Inhibit` and reading properties; NetworkManager,
  hostname1, resolve1, machined and timedate1 are filtered out (the owner's
  decision B2). A zone whose proxy cannot start has no system bus at all
  (tmpfs over `/run/dbus`); a proxy that dies leaves the zone without one.
  `zone-holder` takes `--dbus-proxy`. `doctor` reports the system bus as
  filtered or closed. **Behaviour change:** NetworkManager applets and
  anything asking hostname1 inside a zone stop getting answers.

### Added (JSON)
- `status --json` networks carry `interface`: the host interface of a
  `host-interface` network, `null` for every other kind (additive, schema
  version 1). `docs/CONTAINERS.md` §9 now states the keys to join on:
  containers by `selector`, networks by `name`, programs by launcher key.

### Added (PATH shims, opt-in)
- `programs.vpn-zones.pathShims.enable` (off by default): for every program
  assigned to a container, `sync` writes `~/.local/share/vpn-zones/bin/<program>`,
  which goes through the picker like a click on the entry, and the directory is
  put on the session's PATH. The shim calls the real program found outside its
  own directory, never itself; a file of that name that is not a shim is left
  alone. A convenience, not a boundary.

### Changed (a machine-id of the sandbox's own)
- A sandbox no longer shows the host's `/etc/machine-id`, one identifier shared
  by every zone and sandbox of the machine: a named sandbox gets one of its own,
  kept in its directory, and a throwaway sandbox a new one at every launch.
  **Behaviour change:** programs that register a device by machine-id (some
  launchers and sync clients) see a new device once per named sandbox.

### Added (containers in the GUI)
- A «Контейнеры VPN-зон» launcher entry (`vpn-zone-gui containers`): pick a
  container, then change its network, merge it into another container of the
  same kind (asking again before foreign root certificates are accepted), or
  grant a home of its own a directory from a chooser and take one back. Every
  change goes through `vpn-zone container`, whose refusals are shown as they
  are.

### Added (tunnel watch)
- `vpn-zone watch [--json]`, run every minute by a user timer
  (`programs.vpn-zones.tunnelWatch.enable`, on by default): a tunnel that sends
  into silence — the transmitted counter grows, the received one does not, and
  the last handshake is older than 180 s or never happened — is dead after two
  looks in a row, and a notification says so once; another one says when it
  answers again. OpenConnect and host-interface zones are judged by their
  mirror's `connected`/`disconnected`.
- `status --json` networks carry `handshake_age_s`, `rx_bytes` and `tx_bytes`
  (additive, schema version 1).
- `vpn-zone status --bar`: one JSON line for a status bar (waybar's
  `return-type: json`): the zones that are up, a dead tunnel marked, and a
  class of `none`, `up` or `dead`. Reads only the mirrors and the watcher's
  memory, so a bar can poll it often.
- The picker's network menu says "— туннель не отвечает" next to a zone the
  watcher found dead, and names a host-interface network "Через интерфейс: …
  (без шифрования)" instead of calling it a VPN.

### Fixed (a granted directory that does not exist)
- A sandbox granted `~/Downloads`, `~/Documents` or `~/Pictures` that does not
  exist no longer fails to start: the directory is bound with `--bind-try`, and
  the launch says which one is missing. Nothing is created in the real home.

### Added (networks through an interface of the host)
- A zone whose config has a `[HostInterface]` section (`Interface =`, optional
  literal `DNS =`) goes out through that interface of the host and nothing
  else: no uplink, pasta attached to the app namespace with every socket bound
  to the interface (`--outbound-if4/-if6`), its interface named `awg0` so the
  zone's filter, `doctor` and `check` apply unchanged, no port forwarding, an
  address of its own (`10.255.255.253/30`). A missing interface is a zone that
  refuses to come up. Not encrypted by the zone: `status --json` reports the
  kind `host-interface` (the owner's decision of 2026-09-17).

### Security (pasta's port forwarding shut)
- The uplink's pasta is started with `-t none -u none -T none -U none
  --no-map-gw`. Its defaults bound every port of the uplink — the tunnel's own
  UDP socket — on every address of the host and forwarded it in, offered every
  port of the host's loopback on the uplink's loopback (which the uplink's
  filter accepts), and mapped the gateway address to the host's loopback. The
  tunnel's own flows need none of it.

### Changed (lossless launcher keys, with migration)
- **The memory key of a launcher entry no longer loses characters.** Two
  entries whose names differed only in characters outside `[A-Za-z0-9._-]`
  (`Игра` and `Мама`, `a b` and `a_b`) shared one key — one network pin, one
  container, one sandbox home — and the second program silently went where the
  first had been sent. Such a key now carries the FNV-1a hash of the name
  (`Zen_Browser-a5ffb3fa`); plain ASCII ids do not change. **State migration:**
  the first `sync` moves pins, last choices, labels, file permissions and the
  own sandbox of a key that belonged to one entry to its new key; memory of a
  key that several entries shared is dropped, and those programs ask again.
  Declared `containers.<name>.apps`, `container assign` and `launch` use the
  same keys (`docs/LAUNCHERS.md` §3.4).

### Changed (web apps are children of their browser)
- An entry that opens a web app of a Chromium-family browser (`--app-id=`,
  `--app=`) is launched under the id of that browser's entry, like a Steam game
  under Steam's: the running browser opens the window in its own network and
  profile, so a pin of the web app's own promised a choice nobody could honour.
  No clones and no label of its own; without a browser entry it stays a
  program of its own.

### Added (doctor)
- `vpn-zone doctor [<zone>…] [--json]`: system readiness (user namespaces,
  `newuidmap`, subordinate ids, `/dev/net/tun`, the tools of the manifest), the
  context it runs in (a zone, a sandbox), and a probe run INSIDE every zone that
  is up — only `lo` and `awg0`, default routes into the tunnel only, `hosts:
  files dns`, no host resolver socket in reach — plus the tunnel's liveness.
  The channels `docs/LEAK-MODEL.md` lists as open (session bus, `systemd
  --user`, system bus, X11) are reported as warnings every time. Exit code 1
  when a promised property does not hold; `--json` carries `schema_version`
  and a level per check.

### Changed (D-Bus activation goes through the picker)
- A `DBusActivatable=true` program intercepted by the picker now also gets a
  shadow session service in `~/.local/share/dbus-1/services/` with the same bus
  name, starting it through the picker: activation by name (`gapplication
  launch`, notification actions, "open with", other programs) started it in the
  host's network, uncontained. Only intercepted entries with well-formed names;
  a user's own service file is never overwritten; `mode off` removes ours.
  `vpn-zone-core sync` takes an optional fifth argument, `systemctl`, to reload
  the session bus when a shadow changed (`docs/CONTAINERS.md` §5.3).

### Added (launch by id)
- `vpn-zone launch <id> [-- <arguments>]`: a launcher entry started through the
  picker by its id, the way a click starts it — for compositor key bindings
  (`spawn "vpn-zone" "launch" "firefox"`) and scripts. The program's own entry
  is used (a taken-over one from its backup, our picker entries skipped), field
  codes are filled like a launcher fills them, `VPN_ZONE_DRYRUN=1` prints the
  command, and the shells complete the ids (`docs/CONTAINERS.md` §5.1).

### Changed (XDG autostart goes through the picker)
- **The user's `~/.config/autostart` entries are taken over in place**, like
  the user's launcher entries: a program that switched its own autostart on
  started at login in the host's network, uncontained. Now it starts where it
  was put — its pinned or assigned container, that container's network or its
  network pin — and what nobody chose is the closed variant: `offline`, a home
  of its own, no dialog of any kind, and a notification saying so. The last
  choice and the global network default are not used unasked. Originals are
  kept in `~/.local/state/vpn-zones/.adopted-autostart/`; `vpn-zone mode off`
  or the new option `programs.vpn-zones.autostart.unassigned = "as-is"` (local
  file `~/.config/vpn-zones/autostart`) gives them back byte for byte.
  Symlinks, disabled entries and `/etc/xdg/autostart` are not touched
  (`docs/CONTAINERS.md` §5.2, the owner's decision of 2026-09-17).

### Added (path grants and merging containers)
- `vpn-zone container grant|revoke sb:<sandbox> <dir>` and
  `programs.vpn-zones.containers.<name>.permissions.paths`: a directory of the
  real home or of a data disk (`/mnt`, `/media`, `/run/media`, `/srv`) seen
  read-write by the programs of a home of their own — a Wine prefix, a Steam
  library. An allow-list: sockets (`/run`, `/tmp`), `/etc`, the home itself and
  the state of vpn-zones (zone keys) are never granted, checked as written and
  as resolved, in the CLI and again by `fs-sandbox` at every launch.
  `container show --json` lists them under `permissions.paths` (additive,
  schema version 1).
- `vpn-zone container merge <from> <into> [--yes]`: containers of one kind are
  merged — what `<into>` has is kept, conflicting versions from `<from>` go to a
  fresh `.merged-from-<from>/`, programs are reassigned, certificates new to
  `<into>` need `--yes`, permissions are not copied, `<from>` is kept. Refused
  while either runs and for containers declared in Nix.

### Changed (invariant: foreign entries in the user's applications directory)
- **Entries programs write into `~/.local/share/applications` are now taken
  over in place** — Steam games, browser web apps, Wine entries and, above
  all, the `userapp-*` entries a browser or a messenger writes when it makes
  itself the default handler. `mimeapps.list` sends links to exactly those
  files, so until now every link opened from a host program started the
  browser uncontained, in the direct network, although the browser's own
  system entry was intercepted. The original bytes are kept in
  `~/.local/state/vpn-zones/.adopted/` before anything is written, the entry is
  rewritten like a picker shadow (`X-VPNZone=adopted`), a program that rewrites
  its entry has it taken over again, and `vpn-zone mode off` or
  `interception.userEntries = "leave"` gives every original back byte for
  byte. Symlinks (home-manager, Nix) are never touched. This changes the
  written invariant "foreign files there are never rewritten"
  (`docs/LAUNCHERS.md` §3.2, the owner's decision of 2026-09-17).
- Desktop sync passes run one at a time (a lock in the state directory) and
  write entries, backups and restored originals through a rename: the path
  unit starts a pass on the very write of another pass, and a pass that read a
  half-written entry kept the fragment as the original.

### Security (a zone's own nsswitch.conf)
- A zone binds its own `/etc/nsswitch.conf`, the host's with `hosts:` reduced
  to `files dns`. Hiding the host's resolver sockets was a list (nscd,
  systemd-resolved, avahi) that the next NSS module talking to a host daemon
  would not be on — `mymachines` already asks machined over the system bus.
  Now no module but the plain resolver is loaded for a name inside a zone, and
  it reads the zone's resolv.conf. Other databases stay as the host has them. A
  failure is a loud warning, like the nftables echelon: the sockets are still
  hidden. Checked in the smoke and VM tests.

### Added (containers as identities: network binding, Nix options, JSON state)
- **A container can be bound to one network**: `vpn-zone container set
  <container> network <network|ask>`. `vpn-zone run` then refuses a bound
  container in any other network (and names the way out), and refuses ANY
  container — bound or not — in a second network while its programs run in a
  first: one identity, one network at a time (`docs/CONTAINERS.md` I1, I2).
  The picker takes a bound container's network as the answer, above a network
  pin. **Behaviour change:** starting a program of a data container in network
  B while another program of the same container runs in A is now refused;
  before, only the same program warned.
- `vpn-zone container list|show|set|assign|unassign`: containers with their
  network, programs and trusted certificates, and where each value comes from.
- `vpn-zone status --json`: the whole state for configuration tools —
  `schema_version` and `{value, source: nix|local|default}` for every
  settable value, plus runtime facts (networks up and alive, running
  programs). `container list|show --json` print parts of it.
- **home-manager options** — `programs.vpn-zones.defaults.{network,container}`,
  `launcher.mode`, `compositorRestriction.enable` and
  `containers.<name>.{home, network, apps, trust.{certificates,
  acknowledgeRisk}}`. The module writes `~/.config/vpn-zones/declared/`; the
  runtime reads it first, and the CLI and the GUI refuse to change a value
  declared there instead of writing a file that would change nothing.
  Declared certificates are checked at BUILD time (exactly one certificate per
  file, `CA:TRUE`); assertions catch a certificate without `acknowledgeRisk`, a
  program assigned to two containers and an unusable container name. The
  activation creates the directories of declared containers.

### Added (extra root certificates per container)
- `vpn-zone trust add|list|rm|reset`: a root certificate — a national CA, a
  corporate inspection root, a test CA — trusted by the programs of ONE data
  container or named sandbox, and by nothing else: not the host, not the
  container next door (`docs/CERTIFICATES.md`). `add` takes exactly one
  certificate with `basicConstraints CA:TRUE`, shows subject, issuer, validity
  and fingerprint with a loud warning and asks for the container's name.
- At launch `profile-run` binds the host's bundle plus the container's roots
  over the file every bundle path resolves to (on NixOS one store file, which
  NSS also reads through p11-kit), points `SSL_CERT_FILE` and its relatives at
  the SYSTEM path so a leaked variable is harmless, and installs the roots into
  the container's own NSS databases with `certutil` — never into one it cannot
  prove to be the container's. A bundle that cannot be laid down stops the
  launch. The manifest gains `openssl` and `certutil`.
- Covered by the smoke test (Ubuntu layout) and the VM test (NixOS store
  layout, p11-kit, and an environment pushed into the user manager).

### Fixed
- `vpn-zone run <zone>` with no command started nothing after the working
  directory fix put `profile-run` between `nsenter` and the program; it starts
  a shell again.

### Deprecated
- **Per-zone launcher clones** (`vpn-zone mode per-zone` and `both`). A clone
  is "this program, in that network" on every click — exactly how one identity
  ends up in two networks — and clones grow as programs × zones. `vpn-zone
  mode`, `vpn-zone sync` in those modes and the GUI settings now say so;
  nothing is removed yet. The replacement is the single intercepted entry and,
  later, per-container entries (`docs/LAUNCHERS.md` §4).

### Changed (design)
- `docs/CONTAINERS.md` and `docs/LAUNCHERS.md` carry the owner's decisions of
  2026-09-17: a container's network changes explicitly and can be a host
  interface as well as a zone, every program gets a home of its own with a way
  to merge two containers, entries in the user's applications directory are
  taken over in place, unassigned autostart starts offline with a
  notification, and the JSON state carries `schema_version` and the origin of
  every value.

### Added (design proposals, not implemented)
- `docs/CONTAINERS.md` (+ `.ru.md`): "everything in containers by default" —
  a container as one identity with exactly one network, interception of
  launches outside the launcher, the limits of what is possible without root,
  module options and a `--json` state schema for configuration tools.
- `docs/LAUNCHERS.md` (+ `.ru.md`): how launcher entries are generated and
  launched, the problems found (including handlers hidden with `NoDisplay` and
  foreign entries in the user directory that bypass the picker), and a
  proposal for retiring per-zone clones.
- `docs/CERTIFICATES.md` (+ `.ru.md`): extra root certificates trusted by the
  chosen containers only — never by the host or another container.
- `docs/LEAK-MODEL.md`: launches around the picker and trusted roots as
  channels, with the invariants the implementation must hold.

### Fixed (launches around the picker through hidden handlers; Steam games)
- **Links and files opened through a hidden handler started the program
  around the picker.** Entries with `NoDisplay=true` were skipped as a whole,
  and those are exactly the ones URL and file associations go through
  (`okularApplication_pdf`, `codium-url-handler`, …): the program started
  without its container, in the host's network. Such entries are now
  intercepted — kept hidden, never cloned — under the id of the visible entry
  of the same program. A hidden system helper with no program of its own in
  the menu is left alone.
- **Steam game entries are no longer treated as programs.** An entry whose
  command hands a URL to a program that another visible entry starts and
  claims the scheme of (`Exec=steam steam://rungameid/…` next to
  `steam.desktop`) is a child: no per-zone clones (the menu no longer grows as
  games × zones), and in picker mode it launches under the client's id, so the
  click is routed by the running client and the conflict check sees one
  program. Stale clones of such entries are swept by the next sync.

### Fixed (`direct` dropped the container, the sandbox and the compositor restriction)
- **Choosing "Прямой интернет" in the picker silently threw away every layer
  but the network.** The picker became the command itself for `direct`, so
  what `vpn-zone run` adds on the way never happened: the container or
  filesystem sandbox that had just been chosen, pinned or set as the default
  (`default-profile own` included) was not applied — the program got the whole
  `$HOME` — the Wayland restriction was not applied although it is on by
  default, and no record reached the launch registry, so "already running in
  another network" never knew about programs in the direct network. From
  inside a LOCKED zone the picker's own `systemd-run` also went straight past
  the lock. `direct` now goes through `vpn-zone run direct` like every other
  network; only the namespace step differs. A container there gets a user and
  mount namespace of its own from `unshare --map-current-user --keep-caps
  --mount` (no network namespace — direct is the host's network), so a data
  container works with `direct` for the first time instead of being ignored.
  Covered by unit tests of the new `entry_argv`, the picker scenarios and a
  smoke step that checks the layer, the host netns and the private userns.
- A program opened through delegation (a link clicked in a zone) carried
  `VPN_ZONE_DELEGATED=1` for the rest of its life, so the NEXT link clicked in
  it skipped the delegation and died in `nsenter` with "reassociate to
  namespaces failed". The guard is now removed from the environment once it has
  been checked.
- `vpn-zone add` refuses the names `direct` and `offline`: they are the
  picker's built-in choices, and a zone called `direct` could never be entered.
- **A program started into a zone opened in `/` instead of where it was
  started from** — a terminal showed `/` in its prompt. `nsenter` does
  `chdir("/")` when it joins a mount namespace. Every launch that enters a
  namespace now ends in `vpn-zone-core profile-run --cwd <dir>` (with an empty
  layer directory for the main profile), which changes into the caller's
  directory AFTER stacking the container's layers — `nsenter --wd` would have
  pinned the program to the directory under the overlay — and falls back to
  `$HOME` and `/` when that directory does not exist in the zone's mount tree.
  `profile-run` accepts the new optional leading `--cwd`; older command lines
  parse as before.
- **Two launcher entries for one single-instance binary did not see each
  other** in the "already running in another network" check: a Steam game's
  shortcut and Steam, firefox and its private-window entry, two Telegram
  variants. The registry key is the launcher id, so the second launch handed
  its work to the process already up — in that process's network — without a
  word. Every record is now also filed under the binary name
  (`.running/<container>/.by-binary/<binary>`, swept by `gc`), and the warning
  checks both. Routing a click on a running program still goes by the id only.
  When what is handed over is a link (`steam://…`, `https://…`) the warning
  says so, instead of promising that "the window will open".

### Added (a second kind of zone: OpenConnect)
- **A zone can now be carried by the `openconnect` client instead of a kernel
  tunnel** — Cisco AnyConnect and ocserv by default, and through `Protocol =`
  also GlobalProtect, Pulse, F5, Fortinet and Array (ROADMAP M4). A config with
  an `[OpenConnect]` section makes such a zone; everything else about a zone is
  unchanged, which is the whole point: the corporate VPN lives inside it, an RDP
  client runs in it, and the host never sees the tunnel
  (`rust/src/openconnect.rs`, `rust/src/zone.rs`).
- **The wall stands where it stood.** The client runs in the uplink namespace,
  creates its tun there through `/dev/net/tun` and runs `vpn-zone-core
  oc-script` as its `--script`; the script moves that tun into the app
  namespace and writes down what the gateway said, and the app namespace
  configures it with the same code a WireGuard zone uses. The TLS session, the
  gateway's address and every packet still wrapped in it stay one namespace up.
  A tun device and the descriptor attached to it are separate things, so the
  client goes on working after the interface has left its namespace — the same
  property WireGuard's UDP socket has, reached from the other side.
- No root and no kernel module: `TUNSETIFF` asks for `CAP_NET_ADMIN` in the
  user namespace that OWNS the network namespace, and inside the zone's own
  user namespace we are uid 0. All the device node needs to be is `crw-rw-rw-`.
- **What such a zone deliberately does not do**, all of it for one reason — a
  zone routes everything into the tunnel and has no second interface to route
  anything else through: split tunnelling (`CISCO_SPLIT_INC_*` is ignored and
  counted in the journal), split DNS, IPv6 (not even requested:
  `--disable-ipv6`), and interactive 2FA/OTP (a zone has no terminal to ask on,
  so the client runs `--non-inter`). Each is written down in
  `docs/LEAK-MODEL.md` with the reasoning rather than left to be discovered.
- **There is no way to spell "trust anything".** `ServerCert =` is a fingerprint
  pin (`pin-sha256:`/`sha256:`/`sha1:`, checked for being one) and without it
  the system CA store decides — that is the whole set of options. `Args =` is
  an allowlist of flags in `--flag=value` shape only, and it contains neither
  `--no-system-trust` nor `--allow-insecure-crypto`; nor `--script`,
  `--csd-wrapper` or `--external-browser`, which would replace the thing that
  puts the tunnel behind the wall or run a program of the server's choosing.
- Two more things a config cannot spell. `ServerCert` takes `pin-sha256:` or
  `sha256:` but **not** `sha1:`, which `openconnect` itself accepts: a pin is the
  whole trust decision for a zone that has one, and SHA-1 has not been
  collision-resistant for years. And the client is started with an environment
  built from scratch rather than inherited — `openconnect` honours
  `https_proxy` and its relatives, and a zone should not be one stray session
  variable away from talking to a proxy instead of its gateway. Four variables
  survive, each for a written reason: `PATH`, `HOME` and
  `SSL_CERT_FILE`/`NIX_SSL_CERT_FILE`, which is where the system CA store is.
- `PasswordFile =` must be absolute, non-empty and readable by nobody else
  (0600, checked at `vpn-zone add` and again at start). It is read once, in the
  uplink, and handed to the client on stdin — never on a command line
  (`/proc/<pid>/cmdline` is world readable) and never in the environment.
- Fail-closed, point by point: the gateway is resolved in the host's network
  before any namespace exists and handed over with `--resolve`, so nothing looks
  a name up from a namespace that has no resolver; the uplink's nftables rule is
  `ip daddr <gateway> accept` and nothing else; the client is spawned with
  `PR_SET_PDEATHSIG` so it cannot outlive the namespace it holds; the uplink
  waits on the client instead of parking, so the client's exit takes the whole
  zone down; and `disconnect` tears nothing down because the device dies with
  the client's descriptor and takes the app namespace's only route with it.
- The CI smoke test now runs a real ocserv on the runner with a certificate and
  a password generated on the fly, puts an OpenConnect zone in front of it and
  asserts the same invariants as for a WireGuard zone — exactly two links in the
  app namespace, both routes into the tunnel, the gateway's resolvers and search
  domain, no tunnel left in the uplink — plus a TCP connection through the
  tunnel and "kill the client, the zone is gone".

### Fixed (DNS leak: the host's resolvers were reachable from inside a zone)
- **Every name looked up inside a zone could be resolved by the HOST's
  systemd-resolved, around the tunnel.** nss-resolve talks varlink over
  `/run/systemd/resolve/io.systemd.Resolve`, a unix socket that no route and
  no packet filter can stop, and NixOS puts `resolve` ahead of `dns` in
  `nsswitch.conf` — so with resolved enabled this was the path of every
  lookup, while the traffic itself correctly went through the tunnel. Measured
  on a live zone: a browser leak test named the user's real ISP as the
  resolver while `curl ifconfig.me` in the same zone showed the VPN's address.
  The zone now hides every directory holding a host resolver's socket behind
  an empty tmpfs of its own — nscd/nsncd (as before), systemd-resolved and
  avahi (nss-mdns) — and a failure to do so takes the zone down instead of
  bringing it up leaking (`rust/src/zone.rs`, `hide_host_resolvers`).
- The hiding now happens **before** the offline branch: an offline zone used
  to keep the host's resolver sockets, which is a way out of a zone whose
  entire point is that there is none — a name is a channel, and data can be
  spelled into one.
- The zone's `resolv.conf` bind mount follows the symlink chain by hand and
  creates the file it lands on when it is missing. On NixOS the target is
  `/run/systemd/resolve/stub-resolv.conf`, i.e. inside the tmpfs that has just
  hidden resolved: without this the mount would fail with a bare ENOENT and
  take the zone with it (`sys::link_target`).
- The filesystem sandbox passes in the resolv.conf **file** and no longer its
  directory: `--ro-bind-try /run/systemd/resolve` handed every sandboxed
  program the host resolver's socket. Names still resolve inside; the socket
  does not come with them (`rust/src/fs_sandbox.rs`).
- Regression coverage in the VM test: the machine now runs systemd-resolved
  with a resolver of its own answering `leaktest.internal` with an address the
  tunnel's resolver never returns, so one `getent` inside the zone says whose
  resolver answered. Asserted for a live tunnel and for an offline zone, plus
  "the host's own resolution is untouched".

### Added
- A NixOS VM test (`tests/vm.nix`): a qemu machine with a real systemd user
  session and the home-manager module, plus a second VM acting as a live
  WireGuard peer. Covers what the CI smoke cannot — `vpn-zone up/down` through
  the `vpn-zone@` unit, the unit autostart inside `vpn-zone run`, the picker's
  offline branch, a real handshake/`vpn-zone check`, DNS through the tunnel,
  and a tcpdump leak watch on the uplink. Pins are shared with the harness via
  `tests/pins.nix`.
- AmneziaWG coverage in the VM test: both VMs now load the out-of-tree
  `amneziawg` kernel module, so the zone holder takes its ordinary `ip link
  add … type amneziawg` branch instead of the wireguard fallback (which stays
  covered by the CI smoke, whose runner has no such module). Asserted on a
  plain config against a stock WireGuard peer (wire compatibility), and on a
  new zone with real obfuscation — Jc/Jmin/Jmax, S1/S2, H1–H4 — against a
  second server interface carrying the same parameters: handshake seen by
  `vpn-zone check`, TCP through the tunnel, and an empty leak capture.

### Added (shell completion)
- Tab completion for zsh and bash, installed by the module. Context-aware:
  zone names where a zone is expected, profile/sandbox names after
  `--profile`/`--sandbox`, subcommands, pinned programs for `forget`, file
  completion where a path belongs. The rules live in the crate as the hidden
  `vpn-zone _complete` verb (a pure, tested function); the shell scripts only
  ask and insert.

### Changed (dialogs name the program)
- The file-access dialog of the sandbox and the "already running in another
  network" warning now name the program with the human-readable label the
  picker remembered (`.labels/<key>`), falling back to the raw id — and the
  access dialog says the name in the question body, not only the window
  title: with two programs starting at once, two anonymous dialogs are how
  permissions get granted to the wrong one. New `--label` flag on
  `vpn-zone-core fs-sandbox`; old invocations without it behave as before.

### Fixed (zone readiness)
- `vpn-zone up` right after a `down` could report «поднята» before the tunnel
  existed, and the unit autostart inside `vpn-zone run` (and the picker) could
  fail instantly with «зона не поднимается»: readiness was judged by the bare
  `ready` file, which survives a stop until the NEXT holder start cleans it
  up. Readiness now requires the marker AND a live zone process. Found by the
  VM test on its first pass over the systemd path.

### Fixed (launch-flow audit of the picker and `run`)
- Pinned sandboxes ("… — always" with a named or per-app sandbox) were erased
  by pin validation on the very next launch.
- Choosing a throwaway container via "Change container…" was silently lost on
  the re-exec: the program opened in the previous persistent container.
- After "Ask for the network again", a separately pinned container was ignored
  for that launch.
- A locked (no-escape) zone dropped `--profile` but not the sandbox flags, so
  opening a link from inside such a zone failed silently.
- Launching through the picker with no graphical session silently did nothing;
  it now falls back to the remembered/default choice with a note on stderr.
- The conflict warning named the wrapper (`wl-sandbox`) instead of the program,
  shared one "don't ask again" key across all sandboxed apps, and the
  delegated launch from inside a zone lost `VPN_ZONE_APPID` (separate
  permission sets and registry entries for the same app).
- A failed `systemctl --user start` or a failed profile/sandbox creation
  killed the whole launch under `set -e` after all dialogs had been answered;
  both now degrade with a message instead.
- Cosmetics: "Change container (now: …)" showed the last choice instead of the
  pinned one; the reset dialog's notification showed the entry key instead of
  the program's name.

### Changed
- **The picker and the GUI are Rust now — THE END OF BASH.** The last two
  pieces of shell logic in the project are gone: the four-hundred-line
  `vpn-zone-pick` and the six `writeShellScriptBin` wrappers behind the launcher
  entries. What replaces them is two more binaries in the crate,
  `vpn-zone-pick` (`rust/src/picker.rs`) and `vpn-zone-gui`
  (`rust/src/gui.rs`), plus the `kdialog`/`notify-send` shapes they share
  (`rust/src/dialog.rs`). Parity is the point, again: the same three levels of
  memory in the same files under `~/.local/state/vpn-zones`, the same menu
  entries in the same order with the same Russian texts, the same
  `VPN_ZONE_ASK` / `VPN_ZONE_PROFILE` hand-over across the re-exec of "⚙
  Сменить контейнер", the same `.desktop` argument shapes (`--id`, `--label`,
  and the legacy leading label), and the same `vpn-zone run` command line at the
  end of it. `module/default.nix` went from 1279 lines to 520 and holds no logic
  at all any more — three two-line wrappers that point `VPN_ZONE_TOOLS` at the
  manifest and `exec` a binary.
  What changed underneath:
  - **the decision is a pure function now.** "Which network, which container"
    is computed from a snapshot of the memory (`Memory` → `net_step`,
    `container_without_dialog`, `Container::from_selector`), so every branch of
    the machine — including all ten fixed in the launch-flow audit above — is a
    test case instead of a click. The menus are pure functions too, asserted
    entry by entry, because their ORDER is what a person navigates by;
  - **end-to-end scenarios run in CI.** `rust/tests/picker_cli.rs` drives the
    real binary against a fake manifest, a `kdialog` that answers from a queue
    and a `vpn-zone` that records its arguments: a fresh program, a pinned
    network, "change container" through the re-exec, unpinning, a cancel, no
    graphical session, and a program that is already running. The invariant
    asserted every time is the one the audit was about — each scenario ends
    either in a recorded `exec` or in an explicit cancel, never in silence.
    `rust/tests/vpn_zone_gui_cli.rs` does the same for the six shortcuts;
  - **the six shortcuts are one binary with six verbs**, and their `.desktop`
    entries call it directly: `Exec=env VPN_ZONE_TOOLS=… …/vpn-zone-gui add`.
    Those entries are written by home-manager and rewritten on every switch, so
    a store path in them cannot go stale — unlike the entries our own `sync`
    generates, which keep the profile paths of `vpn-zone` and `vpn-zone-pick`
    for exactly that reason;
  - **`notify-send` joined the manifest** (`notify-send` key) — it is the one
    tool only the GUI runs.

  Three deliberate behaviour differences, all small:
  - the "занят сетью …" note in the container menu now actually appears. It was
    read out of a container's `inuse` file, which nothing has written for a long
    time; the launch registry — the same source `vpn-zone profile list` uses —
    answers it as well now, and the `inuse` file is still read first;
  - `vpn-zone-gui add` calls the CLI through the profile path like every other
    dialog, where the shell version of that one wrapper used the store path;
  - a memory file that cannot be written (a full disk, a permission) is a line
    on stderr instead of the end of the launch. Under `set -e` the shell died
    there, silently, after every dialog had been answered.
- **The `vpn-zone` command line is Rust now.** The seven-hundred-line
  `writeShellScriptBin vpn-zone` of `module/default.nix` is gone; the crate
  grew a third binary of the same name (`rust/src/cli.rs` for the verbs,
  `rust/src/launch.rs` for `run`, `rust/src/registry.rs` for the launch
  registry). Parity is the point: the same verbs and flags, the same Russian
  messages word for word, the same exit codes (`check` still answers 0 alive /
  1 no handshake / 2 zone down / 3 state unknown, and it is meant to be
  scripted against), the same files under `~/.local/state/vpn-zones`, and the
  same registry format `pid zone selector` written under the same `flock` on
  the same `.lock` file — so the picker and the GUI wrappers, which are still
  shell, keep working through the same profile path without a change.
  What changed underneath:
  - **tool paths arrive in a manifest instead of being interpolated.** String
    interpolation by Nix is the one thing a compiled binary cannot do, and
    absolute paths are mandatory (part of what is started runs inside a
    namespace where `PATH` can be anything). Nix now writes them into a small
    flat JSON in the store and a two-line `writeShellScriptBin` wrapper points
    `VPN_ZONE_TOOLS` at it and execs the binary. The parser is written out by
    hand — the format is ours and flat, and it is read on the startup path of
    every program launched into a zone — and a missing key is a loud error
    naming it, never a silent default;
  - **the CLI no longer depends on `PATH` at all.** The wrapper carries no
    `PATH` of its own, and `du`, `mktemp`, `pgrep`, `flock`, `sed`, `grep`,
    `awk` and `basename` are gone from the runtime: sizes, temporary
    directories, the process scan, the locking and the parsing are code now,
    with unit tests for the parts that used to be one-liners (the `run`
    argument grammar, the app-id extraction with all its traps, the registry
    rewrite and gc criteria, the manifest parser, the `check` handshake
    scan);
  - **packaging:** the crate's `bin/vpn-zone` would collide with the wrapper of
    the same name in `home.packages`, so the crate no longer goes into the
    profile whole — a small symlink farm (`vpn-zone-helpers`) puts
    `vpn-zone-core` and `vpn-zone-seccomp` there, and the CLI comes through the
    wrapper.

  Four deliberate behaviour differences, all small:
  - `vpn-zone add` validates the config with the crate's parser instead of
    grepping for `[Interface]`. A file that cannot be parsed (or is not UTF-8)
    is refused right there, with the reason, instead of producing a zone that
    fails to start later. Everything that parsed before still parses;
  - `vpn-zone status` exits 0 for a zone whose `status` mirror does not exist
    yet. The shell version exited 1 there by accident — a trailing
    `[ -f … ] && { … }` was the last command of the branch;
  - directory sizes in `profile list` and `sandbox list` come from our own
    tree walk rather than `du -sh`. Same accounting (512-byte blocks, hard
    links counted once, symlinks not followed) and the same round-up
    formatting, but the last digit may differ from `du` in odd cases;
  - a missing or broken manifest is a new failure mode of its own: exit code 2
    with a message naming the file. `vpn-zone --help` deliberately works
    without one.
- The filesystem sandbox is Rust now. The two-hundred-line `vpn-fs-sandbox`
  shell script of `module/default.nix` is gone; `vpn-zone run --fs-sandbox` (and
  `--sandbox <name>`) calls `vpn-zone-core fs-sandbox` instead, with the tool
  paths substituted by Nix (`--bwrap/--dbus-proxy/--kdialog/--xwayland`) exactly
  as the zone holder takes `--ip/--pasta`. Behaviour is deliberately unchanged:
  the same permission files in `~/.config/vpn-zones/fs-perms/<app-id>` (old
  space-separated ones included) and the same shared `perms` of a named sandbox,
  the same `kdialog` checklist with the same wording, the same bwrap operations
  in the same order, the same `/.flatpak-info`, the same filtered session bus,
  the same GPU nodes, the same `mimeapps.list` read-only bind, the same
  `xwayland-satellite` on a random `:100`–`:499`, and the same exit code
  (128 + N for a signalled program). What changed underneath: the bwrap argument
  list is now a pure function with unit tests asserting the ORDER of the
  operations (a tmpfs listed after the bind it should hide would silently undo
  it, and nothing about a launched program shows that); the permission files are
  parsed and written by tested code; and the sandbox's own X server is started
  by an internal `vpn-zone-core fs-sandbox-x11` subcommand instead of an inline
  `bash -c`, so there is no shell inside the sandbox any more. One cosmetic
  difference: an empty permission set is written as an empty file rather than a
  lone newline, which is what `vpn-zone perms list` renders as "nothing".
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
- **A second echelon: nftables in both namespaces of a zone** (ROADMAP M3,
  `docs/LEAK-MODEL.md`). The topology stays the load-bearing wall — a leak is
  impossible because the path does not exist — and the filter is what insures it
  against a mistake of ours:
  - in the app namespace, an `output` chain with `policy drop` and two accepts,
    `oifname "lo"` and `oifname "awg0"`. Today it has nothing to stop; the day a
    change puts a third interface there, the packets stop instead of leaving
    through it quietly. `oifname` and not `oif` on purpose: names are matched at
    run time, so the ruleset goes in before the tunnel has even arrived and
    keeps meaning what it says afterwards;
  - in the uplink, the same `policy drop` with loopback and *one rule per
    endpoint*: `ip daddr <server> udp dport <port> accept` (`ip6 daddr` for a v6
    endpoint). The uplink exists to carry the tunnel and nothing else, so that
    is all it may send — no DNS, no ICMP, no "quick check against the network".
    The addresses are the literals the holder resolved in the host's network
    before either namespace existed, so there is nothing to look up here. A v6
    endpoint additionally accepts ICMPv6 neighbour discovery, without which the
    kernel could not resolve pasta's `fe80::1` and the tunnel would never send
    its first packet; IPv4 needs no counterpart, because ARP is not in the
    `inet` family at all;
  - an offline zone gets no rules and needs none — loopback is the only
    interface it will ever have.
  Nothing about this is load-bearing, and it says so out loud: no `nft`, an old
  kernel or a kernel whose `nf_tables` module is not loaded (it cannot be
  autoloaded from inside an unprivileged user namespace) is a loud
  `second echelon is OFF` in the journal and a zone that comes up anyway. The
  path to `nft` arrives by flag, like `ip`/`awg`/`wg`/`pasta`
  (`--nft`, substituted into the unit's `ExecStart`), and the ruleset is
  generated by a pure function with unit tests. Programs inside a zone cannot
  read the rules, let alone flush them: nfnetlink wants CAP_NET_ADMIN even to
  list, and they enter under the ordinary uid with no capabilities at all.
- The seccomp filter of the filesystem sandbox is built **in process** instead
  of by a subprocess. The sandbox used to run `vpn-zone-seccomp export`, redirect
  its stdout into a file and open that file as descriptor 34 from the shell;
  now `crate::seccomp` is called as a library and the compiled program is handed
  to bwrap on an inherited descriptor (`dup2` in `pre_exec`, which clears
  `FD_CLOEXEC` as a side effect). One fork and one temporary file are gone from
  the startup path of every sandboxed program, and so is the window in which a
  half-written file could have been handed to `--seccomp`. The filter itself is
  unchanged, and a filter that cannot be built is still a warning on stderr and
  a sandbox without it.
- The bus proxy is now killed when the sandbox is **signalled**, not only when
  the program exits normally. In the shell version the `trap` lived in a
  subshell that a TERM could take out on its own, leaving `xdg-dbus-proxy`
  running with nobody to collect it. bwrap's `--die-with-parent` never covered
  it: the proxy is our process, not bwrap's.
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

### Removed
- The last `writeShellScriptBin`s that held any logic: `vpn-zone-pick` and the
  six GUI wrappers (`vpn-zone-add-gui`, `vpn-zone-remove-gui`,
  `vpn-zone-profile-add-gui`, `vpn-zone-profile-rm-gui`,
  `vpn-zone-settings-gui`, `vpn-zone-forget-gui`). What is left in
  `module/default.nix` is three wrappers of two lines each — `vpn-zone`,
  `vpn-zone-pick` (both of which must own their name in the profile, because
  the generated shortcuts point at those paths) and `vpn-zone-sync` — plus the
  packaging. With them went the last runtime uses of `grep`, `sed`, `basename`,
  `cat`, `ls`, `du` and `sleep`: the module no longer references coreutils,
  gnused or gnugrep for anything but the `env` in a `.desktop` line.

### Added
- Seccomp filter in the filesystem sandbox. It now compiles a BPF
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
- A D-Bus proxy that did not come up took the whole program down with it. The
  filesystem sandbox bound the proxy socket unconditionally, so when
  `xdg-dbus-proxy` failed to start or exited before creating it — no session bus
  at all, a tty login, a CI runner — bwrap failed with "Can't find source path"
  and nothing started. The intent was always soft degradation: no bus is a
  degradation, no program is a bug. The bind is now skipped and the missing bus
  reported on stderr, while `DBUS_SESSION_BUS_ADDRESS` keeps pointing inside the
  runtime tmpfs, where there is nothing — the program must not find the *real*
  bus in any outcome. The five-second wait for the socket now also ends as soon
  as the proxy is seen to have exited, instead of being paid on every launch.
- `/run/current-system` is bound with `--ro-bind-try`. It exists only on NixOS,
  and a missing source is a hard bwrap failure, so the sandbox could not run on
  a machine that has a nix store but no NixOS system profile — which is what the
  CI runner is, and what a nix-on-Debian install is.
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
