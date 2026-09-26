//! `cellward` — the user-facing command line. The profile has it as `cellward`,
//! `cw` and the old `vpn-zone`: one wrapper execing this crate's `vpn-zone`
//! binary.
//!
//! This was the last big shell script of the project (`module/default.nix`,
//! part 3). What it does has not changed and is not supposed to: the same verbs,
//! the same words in the same messages, the same exit codes — `check` in
//! particular answers with 0/1/2/3 and is meant to be scripted against — and the
//! same files under `~/.local/state/vpn-zones`. The picker and the GUI wrappers
//! are still shell and still call this binary by its profile path, so the two
//! sides have to keep agreeing about all of it.
//!
//! The messages stay in Russian on purpose. They are what the user reads in a
//! terminal, and translating them is a step of its own (ROADMAP M6, gettext with
//! English as the base language); doing it here would have meant a rewrite plus
//! a translation in one commit, with nothing left to compare against.
//!
//! Tool paths come from the manifest ([`crate::tools`]) rather than from `PATH`:
//! part of what is started here runs inside a namespace where `PATH` can be
//! anything at all. The two heavy verbs live next door — `run` in
//! [`crate::launch`], the launch registry in [`crate::registry`].

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use crate::config::WgConfig;
use crate::launch;
use crate::openconnect::{self, OcConfig};
use crate::profile::{exec_command, proc_is_alive, EXIT_NOT_STARTED};
use crate::registry;
use crate::tools::Tools;

/// The manifest is missing or does not match this binary. Not the same thing as
/// a command that failed, hence its own code — and the same "bad invocation"
/// number `vpn-zone-core` uses.
pub const EXIT_TOOLS: u8 = 2;

/// How long `up` and `run` wait for a zone to come up: a hundred tries, a tenth
/// of a second each.
const READY_TRIES: u32 = 100;
const READY_STEP: Duration = Duration::from_millis(100);

const USAGE: &str = "cellward — сетевые зоны с VPN, без root\n(коротко — cw; прежнее имя vpn-zone тоже работает)\n\n  cellward add <имя> <файл.conf>   создать зону из конфига AmneziaWG/WireGuard\n                                   или OpenConnect (секция [OpenConnect])\n  cellward add <имя> --system <з.> зона через туннель системной зоны <з.>:\n                                   своего туннеля нет, один VPN — одно\n                                   подключение (конфиг с ключом системной\n                                   зоны становится такой зоной сам)\n  cellward up <имя>                поднять\n  cellward down <имя>              опустить\n  cellward list                    список зон и их состояние\n  cellward status <имя>            подробности (адрес, handshake)\n  cellward status --json           всё состояние машиночитаемо: зоны, контейнеры,\n                                   программы, откуда взято каждое значение\n  cellward status --bar            одна строка JSON для статус-бара (waybar):\n                                   поднятые зоны и живы ли их туннели\n  cellward run <имя> -- <кмд>      запустить программу внутри зоны\n  cellward launch <id> [-- <арг.>] запустить ярлык по id через пикер, как\n                                   щелчок по нему, — для биндов композитора\n  cellward rm <имя>                удалить зону вместе с ярлыками\n  cellward sync                    пересобрать .desktop-ярлыки\n  cellward mode <режим>            как ярлыки работают:\n                                     picker   — один ярлык, спрашивает сеть\n                                                при запуске (по умолчанию)\n                                     per-zone — отдельный ярлык на каждую зону\n                                                (устарел, будет убран)\n                                     both     — и то, и другое (устарел)\n                                     off      — не трогать ярлыки вовсе\n  cellward default <вариант>       что предлагать в пикере для незнакомой\n                                   программы: offline (по умолчанию),\n                                   unconfined (без ограничений: сеть хоста,\n                                   без VPN и изоляции зоны; прежнее имя —\n                                   direct) или имя зоны\n  cellward gc                      убрать зависшие держатели зон, осиротевшую\n                                   обвязку и мёртвые записи\n  cellward perms list|reset <прог.|--all>\n                                   какие доступы к файлам выданы программам\n                                   в песочнице; reset — спросить заново\n  cellward container create <имя> [--home private|layer|main]\n                                   контейнер: свой дом (private, по умолчанию),\n                                   слой над настоящим домом (layer) или сам\n                                   настоящий дом (main) — со своими сетью,\n                                   программами и разрешениями\n  cellward container rm <имя>      удалить контейнер с его данными\n  cellward sandbox create|list|rm <имя>\n  cellward profile create|list|rm <имя>\n                                   прежние слова: контейнер со своим домом\n                                   (sandbox) или слоем (profile)\n  cellward run <имя> --container <к> -- <кмд>\n                                   запустить в контейнере (--sandbox и\n                                   --profile — прежние слова для того же)\n  cellward run <имя> --fs-sandbox -- <кмд>\n                                   запустить в песочнице файловой системы:\n                                   вместо $HOME — пустой каталог, наружу\n                                   видно только разрешённое, остальное — через\n                                   диалог выбора файла (порталы)\n  cellward run <имя> --tmp-profile -- <кмд>\n                                   запустить в одноразовом контейнере: слой\n                                   создаётся в /tmp и стирается по выходе\n  cellward default-profile <v>     контейнер по умолчанию для всех запусков:\n                                   ask (спрашивать), main (основной),\n                                   own (своя песочница у каждой программы)\n                                   или имя контейнера\n  cellward pins                    какие программы закреплены за сетями\n  cellward forget <прог.|--all>    снять закрепление (снова будет спрашивать)\n  cellward wayland-proxy on|off    посредник между программами и\n                                   композитором (по умолчанию on; исключения —\n                                   ~/.config/vpn-zones/wayland-no-proxy)\n  cellward wayland-sandbox on|off  отбирать ли у программ захват экрана,\n                                   чтение буфера в фоне и эмуляцию ввода\n                                   (по умолчанию on; исключения —\n                                   ~/.config/vpn-zones/wayland-allow)\n  cellward frame show|hide         рамка цвета зоны вокруг окон её программ;\n                                   hide — спрятать у окон, открытых после\n                                   этого (для показа экрана)\n  cellward frame width <1–32> (по умолчанию 4)\n                                   толщина рамки, логические пиксели\n  cellward frame color <зона> default (из имени зоны)|<#rrggbb>\n                                   цвет рамки зоны\n  cellward frame title always (по умолчанию)|hover|off\n                                   полоса заголовка «зона · контейнер» сверху:\n                                   всегда, при наведении (поверх окна, у\n                                   верхнего края) или нет\n  cellward check <имя>             прошло ли рукопожатие (жив ли конфиг)\n  cellward watch [--json]          живы ли туннели поднятых зон; при смерти и\n                                   возвращении — уведомление (зовёт таймер)\n  cellward kill <зона>             оборвать зону сейчас: заморозить все её\n                                   программы, опустить зону, убить программы\n                                   (для удалённого доступа, который надо\n                                   прекратить немедленно)\n  cellward journal [--json] [<N>]  последние события: запуски без ограничений\n                                   (unconfined) и решения брокера\n  cellward focused [--json|--bar|--watch]\n                                   в какой сети и контейнере программа окна в\n                                   фокусе (niri, sway); --bar — строка для\n                                   статус-бара, --watch — такая строка при\n                                   каждой смене фокуса\n  cellward window-menu             меню программы окна в фокусе — для бинда\n                                   композитора: закрепить сеть, перезапустить\n                                   с выбором сети, закрыть, оборвать зону\n  cellward doctor [<зона>…] [--json]\n                                   что на деле закрыто: готовность системы и\n                                   проверки изнутри каждой поднятой зоны\n                                   (выходы, маршруты, резолверы, открытые\n                                   каналы); код 1 — есть нарушения\n  cellward hermetic <зона> default (как у всех зон)|on|off\n                                   герметичная зона: без systemd --user,\n                                   сессионная шина через фильтр, запуск\n                                   наружу через брокер\n  cellward hermetic --default on (по умолчанию)|off\n                                   герметичны ли зоны без своей настройки\n                                   (on — с 2026-09)\n  cellward x11 <зона> on|off       свой X-сервер программам зоны (X хоста в\n                                   зонах недоступен всегда)\n  cellward nix-daemon <зона> off (по умолчанию)|on\n                                   виден ли программам зоны Nix-демон хоста\n                                   (off: он качает в сети хоста)\n  cellward camera <зона> off (по умолчанию)|on\n                                   видны ли программам зоны камеры хоста\n  cellward audio-manager <зона> off (по умолчанию)|on\n                                   PipeWire хоста без ограничений в\n                                   герметичной зоне — для микшера\n                                   (pavucontrol, qpwgraph); off — свои\n                                   потоки и выходы для звука\n  cellward microphone <зона> ask (по умолчанию)|yes|no\n                                   может ли программа зоны записывать\n                                   микрофон: ask — спросить\n                                   при первой записи: один раз, всегда,\n                                   отказать; действует сразу. Звук, который\n                                   играет хост, не записать никогда. Это\n                                   переключатель пути pulse: сырой\n                                   pipewire-0 и systemd --user\n                                   негерметичной зоны идут мимо\n  cellward screencast <зона> ask (по умолчанию)|yes|no\n                                   может ли программа зоны транслировать\n                                   экран через портал: ask —\n                                   портал спрашивает каждый раз; no — отказ;\n                                   yes — выбор можно запомнить, если портал\n                                   знает зону по имени. Действует сразу;\n                                   держит фильтр шины герметичной зоны\n  cellward ask-again <срок> (по умолчанию 3m)\n                                   через сколько после отказа снова спросить\n                                   о разрешении (микрофон): 30s…1d; до того\n                                   запросы зоны отказаны без вопроса\n  cellward host-files <зона> read-only (по умолчанию)|writable\n                                   может ли герметичная зона писать то, что\n                                   хост исполняет из дома\n  cellward lock|unlock <имя>       запретить/разрешить программам этой зоны\n                                   запускать что-либо в ДРУГИХ сетях\n                                   (по умолчанию разрешено; держится только\n                                   в герметичной зоне)\n  cellward trust add <контейнер> <сертификат> [--yes]\n                                   дополнительный корневой сертификат ТОЛЬКО\n                                   для программ этого контейнера: хост и\n                                   другие контейнеры\n                                   ему не доверяют. Его владелец сможет читать\n                                   TLS-трафик программ контейнера\n  cellward trust list [<контейнер>] [--json]\n  cellward trust rm <контейнер> <начало sha256>\n  cellward trust reset <контейнер> убрать все дополнительные сертификаты\n  cellward container list|show [<контейнер>] [--json]\n                                   контейнеры: их дом, сеть, программы,\n                                   сертификаты\n  cellward container set <контейнер> network <сеть|ask>\n                                   привязать контейнер к сети: запуск в\n                                   другой сети будет отказом\n  cellward container set <контейнер> x11 on|off\n                                   свой X-сервер в зонах (X хоста в зонах\n                                   недоступен всегда)\n  cellward container set <контейнер> color default (цвет сети)|<#rrggbb>\n                                   цвет рамки окон контейнера\n  cellward container set <контейнер> microphone default (как у зоны)|yes|no|ask\n                                   может ли программа контейнера записывать\n                                   микрофон (Nix зоны важнее местной\n                                   настройки)\n  cellward container set <контейнер> screencast default (как у зоны)|yes|no|ask\n                                   может ли программа контейнера транслировать\n                                   экран через портал (yes — пока как ask:\n                                   своего имени у портала у контейнера нет)\n  cellward container set <контейнер> camera default (как у зоны)|on|off\n                                   видны ли программам контейнера камеры хоста\n                                   (запущенным после этого)\n  cellward container set <контейнер> home private|layer|main\n                                   сменить вид дома; данные прежнего вида\n                                   откладываются рядом, ничего не стирается\n  cellward devices [--json]        что подключено из того, что можно выдать\n                                   контейнеру: имя для выдачи и наборы\n  cellward container devices <контейнер> [add|rm <устройство>]\n                                   выдать контейнеру устройства, закрытые в\n                                   зонах: наборы games, security-keys, phone,\n                                   serial, vm или одно\n                                   usb:<произв.>:<модель>[:<сер.>]\n  cellward container links <контейнер> [set <схема> <id> | rm <схема>]\n                                   в какой программе открывать ссылки схемы\n                                   (https, tg…) из этого контейнера без выбора\n                                   программы; окно сети и контейнера остаётся\n  cellward container assign <программа> <контейнер>\n  cellward container unassign <программа>\n  cellward container grant <контейнер> <каталог> [--for 2h]\n  cellward container revoke <контейнер> <каталог>\n                                   выдать контейнеру каталог настоящего дома\n                                   или диска (/mnt, /media, /run/media, /srv):\n                                   префикс Wine, библиотеку Steam; --for —\n                                   на срок (30s, 15m, 2h, 7d), по истечении\n                                   и при revoke каталог отмонтируется и у\n                                   уже запущенных программ\n  cellward container merge <из> <в> [--yes]\n                                   объединить два контейнера одного вида:\n                                   совпавшее остаётся у <в>, версии из <из>\n                                   кладутся рядом; --yes — согласие принять\n                                   чужие корневые сертификаты\n";

/// Entry point of the `vpn-zone` binary.
pub fn main() -> ExitCode {
    // `args_os`: a launcher can hand a file name through a `%U` field code, and
    // file names are bytes. Refusing to start a program because its argument is
    // not valid Unicode would be a regression against every other launcher.
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let verb = args.first().cloned().unwrap_or_default();
    let rest: &[OsString] = args.get(1..).unwrap_or(&[]);

    // Help does not need the manifest: somebody who ran the binary without the
    // wrapper needs to be told what this is, not what is missing.
    if matches!(verb.as_bytes(), b"" | b"-h" | b"--help" | b"help") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let tools = match Tools::from_env() {
        Ok(tools) => tools,
        Err(e) => {
            eprintln!("cellward: {e}");
            return ExitCode::from(EXIT_TOOLS);
        }
    };

    // The two directories everything else assumes exist.
    for dir in [&tools.state, &tools.profiles] {
        if let Err(e) = fs::create_dir_all(dir) {
            eprintln!("не создать {}: {e}", dir.display());
            return ExitCode::from(1);
        }
    }

    let code = match verb.as_bytes() {
        b"add" => add(&tools, rest),
        b"up" => up(&tools, rest),
        b"down" => down(&tools, rest),
        b"list" => list(&tools),
        b"status" => status(&tools, rest),
        b"lock" => set_lock(&tools, rest, true),
        b"x11" => zone_x11(&tools, rest),
        b"hermetic" => zone_hermetic(&tools, rest),
        b"nix-daemon" => zone_allowance(&tools, rest, &NIX_DAEMON_SWITCH),
        b"host-files" => zone_allowance(&tools, rest, &HOST_FILES_SWITCH),
        b"camera" => zone_allowance(&tools, rest, &CAMERA_SWITCH),
        b"microphone" => zone_microphone(&tools, rest),
        b"screencast" => zone_screencast(&tools, rest),
        b"ask-again" => ask_again(&tools, rest),
        b"audio-manager" => zone_allowance(&tools, rest, &AUDIO_MANAGER_SWITCH),
        // Hidden: the broker's user service runs it (rust/src/broker.rs).
        b"_broker" => crate::broker::serve(&tools),
        b"unlock" => set_lock(&tools, rest, false),
        b"check" => check(&tools, rest),
        b"run" => launch::run(&tools, rest),
        b"launch" => launch_entry(&tools, rest),
        b"gc" => gc(&tools),
        b"doctor" => crate::doctor::run(&tools, rest),
        b"watch" => crate::watch::run(&tools, rest),
        b"journal" => crate::journal::run(&tools, rest),
        b"focused" => crate::focus::run(&tools, rest),
        b"window-menu" => crate::focus::menu(&tools),
        b"kill" => crate::kill::run(&tools, rest),
        b"perms" => perms(&tools, rest),
        b"trust" => trust(&tools, rest),
        b"container" => container(&tools, rest),
        b"devices" => devices_list(rest),
        b"sandbox" => sandbox(&tools, rest),
        b"profile" => profile(&tools, rest),
        b"wayland-sandbox" => wayland_sandbox(&tools, rest),
        b"wayland-proxy" => wayland_proxy(&tools, rest),
        b"frame" => frame(&tools, rest),
        // Zones have had no layer of their own since the whole-home layer of
        // a container (`docs/PERMISSIONS.md` §11.7): the two did nothing.
        b"isolate" | b"reset-profile" => {
            eprintln!(
                "cellward {}: команды больше нет — слоёв у зон нет, слой есть у контейнера \
                 (cellward container create <имя> --home layer; очистить — cellward container rm)",
                verb.to_string_lossy()
            );
            1
        }
        b"rm" => remove(&tools, rest),
        b"sync" => exec_sync(&tools),
        b"mode" => mode(&tools, rest),
        b"default-profile" => default_profile(&tools, rest),
        b"default" => default_network(&tools, rest),
        b"pins" => pins(&tools),
        b"forget" => forget(&tools, rest),
        // Hidden: the tab-completion scripts call it (rust/src/completion.rs).
        // Not in USAGE — a protocol verb, not a command for humans.
        b"_complete" => crate::completion::run(&tools, rest),
        _ => {
            eprintln!("неизвестная команда: {}", verb.to_string_lossy());
            print!("{USAGE}");
            1
        }
    };
    ExitCode::from(code)
}

// --- SHARED PIECES -----------------------------------------------------------

/// The shell's `${1:?message}`: an argument that has to be there and non-empty.
fn required<'a>(args: &'a [OsString], idx: usize, message: &str) -> Option<&'a OsString> {
    match args.get(idx) {
        Some(value) if !value.is_empty() => Some(value),
        _ => {
            eprintln!("{message}");
            None
        }
    }
}

/// Pid of a zone's APP namespace, if it is up.
///
/// `zone.pid` names the namespace programs run in — the one `nsenter` targets.
/// A stale file (the holder was killed, or stopped and its number reused) is
/// not "up": the process has to exist, and be the one that wrote it.
pub fn zone_pid(state: &Path, name: &OsStr) -> Option<i32> {
    let dir = state.join(name);
    let text = fs::read_to_string(dir.join("zone.pid")).ok()?;
    let pid: i32 = text.trim().parse().ok()?;
    // The holder notes when it started: a stopped zone leaves its number
    // behind, and once that number is reused a live process is not the zone.
    // Entering it would put a program into somebody else's namespaces. No
    // note, no zone — unless the number is a holder from before the note,
    // still in its zone's unit; a bare number that may have outlived its zone
    // is not trusted (review 2026-09-25).
    let stamp = match read_setting(&dir.join("zone.start")) {
        Some(stamp) => stamp,
        None => adopt_old_holder(&dir, name, pid)?,
    };
    (crate::sys::process_stamp(pid).as_deref() == Some(stamp.trim())).then_some(pid)
}

/// A holder of a build from before `zone.start`, which an update left
/// running (`X-SwitchMethod=keep-old`, `module/default.nix`): without this it
/// read as down, and nothing could be launched into the zone until it was
/// restarted. Its number is taken only while the process sits in the zone's
/// own unit, `vpn-zone@<name>.service` — a unit's control group goes when
/// the unit stops, and only systemd, or the user from the host (who could
/// write the note as well), puts a process in it — and the start time is
/// read before and after that look, so the look was at this very process
/// and not at one that took the number meanwhile. Then the note is written
/// for it, as a holder of this build writes it itself.
fn adopt_old_holder(dir: &Path, name: &OsStr, pid: i32) -> Option<String> {
    let before = crate::sys::process_stamp(pid)?;
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    if !in_zone_unit(&cgroup, name.to_str()?) {
        return None;
    }
    let after = crate::sys::process_stamp(pid)?;
    if after != before {
        return None;
    }
    // Where it can be written: from inside a zone the state is out of reach,
    // and the next look from the host writes it.
    let tmp = dir.join("zone.start.tmp");
    let _ = fs::write(&tmp, format!("{before}\n"))
        .and_then(|()| fs::rename(&tmp, dir.join("zone.start")));
    Some(before)
}

/// Whether `/proc/<pid>/cgroup` puts the process in the unit of zone `name`
/// (its own control group, or one below it).
pub fn in_zone_unit(cgroup: &str, name: &str) -> bool {
    let unit = format!("/vpn-zone@{name}.service");
    cgroup
        .lines()
        .filter_map(|l| l.strip_prefix("0::"))
        .any(|path| path.ends_with(&unit) || path.contains(&format!("{unit}/")))
}

/// Wait for the zone to come up, ten seconds at most: the `ready` marker AND
/// a live zone process.
///
/// The bare file is not enough. Stale state (`ready`, `zone.pid`) survives a
/// stop: the holder removes leftovers, but only when the NEXT one starts, and
/// between `systemctl start` and that cleanup the old `ready` is still on
/// disk. Trusting it made `up` after a `down` report "поднята" before the
/// tunnel existed, and made the autostart inside `run` (and the picker) fail
/// instantly — stale `ready`, dead `zone.pid`, «зона не поднимается». Caught
/// by tests/vm.nix on the first run of the systemd path; the smoke test
/// cannot see it (no `systemctl --user` on the CI runner).
pub fn wait_ready(state: &Path, name: &OsStr) -> bool {
    for _ in 0..READY_TRIES {
        if zone_up(state, name).is_some() {
            return true;
        }
        std::thread::sleep(READY_STEP);
    }
    zone_up(state, name).is_some()
}

/// The pid of a zone that is up AND ready: its namespaces exist and its setup
/// is over. `zone.pid` appears as soon as the namespaces do — before the host's
/// resolvers are hidden, the system bus filtered, the runtime directory sealed,
/// the zone's resolv.conf bound. A launch that entered then took a copy of that
/// half-built mount tree into its own mount namespace (a container, a sandbox)
/// and kept the host's resolv.conf for its whole life.
pub fn zone_up(state: &Path, name: &OsStr) -> Option<i32> {
    state
        .join(name)
        .join("ready")
        .is_file()
        .then(|| zone_pid(state, name))
        .flatten()
}

/// `systemctl --user <verb> vpn-zone@<name>.service`, waited for.
///
/// Returns the exit code, or 127 if systemctl itself could not be started —
/// the number a shell reports for that.
pub fn systemctl(tools: &Tools, verb: &str, name: &OsStr) -> u8 {
    let mut unit = OsString::from("vpn-zone@");
    unit.push(name);
    unit.push(".service");
    match Command::new(&tools.systemctl)
        .arg("--user")
        .arg(verb)
        .arg(unit)
        .status()
    {
        Ok(status) => status.code().map_or(1, |c| c as u8),
        Err(e) => {
            eprintln!("не запустить {}: {e}", tools.systemctl.display());
            EXIT_NOT_STARTED
        }
    }
}

/// Read a one-line setting file, the way `$(cat file)` did: trailing newlines
/// dropped, everything else kept. `None` when there is no file.
pub fn read_setting(path: &Path) -> Option<String> {
    let mut text = fs::read_to_string(path).ok()?;
    while text.ends_with('\n') || text.ends_with('\r') {
        text.pop();
    }
    Some(text)
}

/// Where the home-manager module puts what is declared in Nix, below the
/// config directory: one file per setting, and `containers/`.
pub const DECLARED_DIR: &str = "declared";

/// A setting of `~/.config/vpn-zones` and where it comes from: the value
/// declared in Nix wins over the local one. `None` when neither is set.
pub fn setting(tools: &Tools, name: &str) -> Option<(String, crate::container::Source)> {
    if let Some(value) = read_setting(&tools.config.join(DECLARED_DIR).join(name)) {
        return Some((value, crate::container::Source::Nix));
    }
    read_setting(&tools.config.join(name)).map(|value| (value, crate::container::Source::Local))
}

/// Write a setting file with no trailing newline (`printf '%s'`), creating
/// `~/.config/vpn-zones` on the way.
///
/// A setting declared in Nix is refused rather than written: the local file
/// would change nothing (the declared one wins) and the command would look
/// like it worked.
fn write_setting(tools: &Tools, name: &str, value: &OsStr) -> Result<(), String> {
    if tools.config.join(DECLARED_DIR).join(name).exists() {
        return Err(format!(
            "«{name}» задано в Nix (programs.cellward) и меняется там"
        ));
    }
    fs::create_dir_all(&tools.config).map_err(|e| format!("{}: {e}", tools.config.display()))?;
    let path = tools.config.join(name);
    fs::write(&path, value.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))
}

/// A zone name, which is stricter still: it ends up in unit names and in
/// generated `.desktop` files.
fn safe_zone_name(name: &OsStr) -> bool {
    // Not from a dash: a zone name is an argument to kdialog and systemctl.
    !name.as_bytes().is_empty()
        && !name.as_bytes().starts_with(b"-")
        && name
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// Entries of a directory whose names do not start with a dot, sorted — the set
/// and the order of a shell glob.
///
/// Public because the picker and the GUI walk the same directories and have to
/// see them in the same order: a menu that lists the zones differently from
/// `vpn-zone list` would be a bug report waiting to happen.
pub fn visible_entries(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        if entry.file_name().as_encoded_bytes().starts_with(b".") {
            continue;
        }
        out.push(entry.path());
    }
    out.sort();
    out
}

/// Disk usage of a directory tree, in bytes, the way `du` counts it: allocated
/// blocks rather than apparent size, directories included, hard links counted
/// once, symlinks not followed.
///
/// Public for the container removal dialog, which shows the same sizes as
/// `vpn-zone profile list`.
pub fn tree_size(path: &Path) -> u64 {
    fn walk(path: &Path, seen: &mut Vec<(u64, u64)>, total: &mut u64) {
        let Ok(meta) = fs::symlink_metadata(path) else {
            return;
        };
        if meta.nlink() > 1 && !meta.is_dir() {
            let key = (meta.dev(), meta.ino());
            if seen.contains(&key) {
                return;
            }
            seen.push(key);
        }
        *total += meta.blocks() * 512;
        if !meta.is_dir() {
            return;
        }
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            walk(&entry.path(), seen, total);
        }
    }
    let mut seen = Vec::new();
    let mut total = 0;
    walk(path, &mut seen, &mut total);
    total
}

/// `du -h`: powers of 1024, one decimal below ten, rounded UP, no unit letter
/// below a kilobyte.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 7] = ["", "K", "M", "G", "T", "P", "E"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        return format!("{bytes}");
    }
    // Ceiling, like du: a byte over 1.0K has to read as 1.1K, never as 1.0K.
    let tenths = (value * 10.0).ceil();
    if tenths < 100.0 {
        format!("{:.1}{}", tenths / 10.0, UNITS[unit])
    } else {
        format!("{}{}", value.ceil(), UNITS[unit])
    }
}

/// Normalise line endings the way `sed 's/\r$//'` did: ONE carriage return at
/// the end of a line, no more.
///
/// Amnezia hands out `.conf` files in the Windows format — verified on a real
/// one, 21 lines with a `\r`. The `\r` ends up at the END OF THE VALUE and the
/// zone dies on its first command: `ip addr add 10.8.1.10/32<CR>` → "inet prefix
/// is expected rather than …". The error looks nonsensical, because a carriage
/// return is invisible in it. (`docs/GOTCHAS.md` §4)
pub fn strip_cr(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for (idx, line) in input.split(|b| *b == b'\n').enumerate() {
        if idx > 0 {
            out.push(b'\n');
        }
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        out.extend_from_slice(line);
    }
    out
}

// --- ZONES -------------------------------------------------------------------

fn add(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(name) = required(args, 0, "нужно имя зоны") else {
        return 1;
    };
    let Some(conf) = required(args, 1, "нужен путь к .conf") else {
        return 1;
    };
    // `vpn-zone add <имя> --system <зона>`: a zone through a system zone, with
    // no file to read — the config is two lines and holds no key.
    let system = if conf == "--system" {
        let Some(zone) = required(args, 2, "нужно имя системной зоны") else {
            return 1;
        };
        Some(zone.to_string_lossy().into_owned())
    } else {
        None
    };
    if !safe_zone_name(name) {
        eprintln!("имя только из букв, цифр, - и _");
        return 1;
    }
    // The picker's built-in choices, not zones: a zone called "unconfined" (or
    // "direct", its old name) would never be entered — `vpn-zone run
    // unconfined` is the host's network — and
    // "offline" is the directory the picker creates by itself for the empty
    // zone. (`docs/GOTCHAS.md` §2)
    if launch::is_unconfined_name(&name.to_string_lossy()) || name == launch::OFFLINE {
        eprintln!(
            "«{}» — встроенный вариант пикера, так зону назвать нельзя",
            name.to_string_lossy()
        );
        return 1;
    }
    let conf = Path::new(conf);
    let mut text = if let Some(zone) = &system {
        crate::sysuplink::SysUplinkConfig { zone: zone.clone() }
            .text()
            .into_bytes()
    } else {
        if !conf.is_file() {
            eprintln!("нет файла {}", conf.display());
            return 1;
        }
        match fs::read(conf) {
            Ok(raw) => strip_cr(&raw),
            Err(e) => {
                eprintln!("не читается {}: {e}", conf.display());
                return 1;
            }
        }
    };
    // The parser the zone itself will run on, rather than a `grep` for
    // `[Interface]`: a file that cannot be parsed cannot bring a zone up, and
    // being told so now beats a zone that refuses to start later. Which of the
    // two kinds of zone this is, is one question asked of the same parse — an
    // `[OpenConnect]` section makes it one, anything else is WireGuard.
    let ini = match WgConfig::parse(&text) {
        Ok(ini) => ini,
        Err(e) => {
            eprintln!(
                "{} не похож на конфиг WireGuard/AmneziaWG или OpenConnect: {e}",
                conf.display()
            );
            return 1;
        }
    };
    if openconnect::is_openconnect(&ini) {
        // Checked in full right here, the password file included: a zone that
        // is created now and refuses to come up in a week, with the reason in
        // the journal, is the worst way to learn about a typo.
        match OcConfig::from_ini(&ini).and_then(|cfg| cfg.check_password_file().map(|()| cfg)) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("{}: {e}", conf.display());
                return 1;
            }
        }
    } else if crate::hostif::is_host_interface(&ini) {
        match crate::hostif::HostIfConfig::from_ini(&ini) {
            Ok(host) => {
                // Only a warning: a VPN the system brings up later, a modem
                // plugged in tomorrow. The zone itself refuses to come up
                // without it.
                if !Path::new("/sys/class/net").join(&host.interface).exists() {
                    eprintln!(
                        "интерфейса {} сейчас нет: зона не поднимется, пока он не появится",
                        host.interface
                    );
                }
                println!(
                    "зона пойдёт наружу через интерфейс хоста {} — сама она трафик не шифрует",
                    host.interface
                );
            }
            Err(e) => {
                eprintln!("{}: {e}", conf.display());
                return 1;
            }
        }
    } else if crate::sysuplink::is_system_zone(&ini) {
        match crate::sysuplink::SysUplinkConfig::from_ini(&ini) {
            Ok(sys) => println!(
                "зона пойдёт наружу через туннель системной зоны {} — своего туннеля у неё нет",
                sys.zone
            ),
            Err(e) => {
                eprintln!("{}: {e}", conf.display());
                return 1;
            }
        }
    } else if ini.interface().is_none() {
        eprintln!(
            "{} не похож на конфиг WireGuard/AmneziaWG, OpenConnect, [HostInterface] или \
             [SystemZone]",
            conf.display()
        );
        return 1;
    } else if let Some(key) = ini.interface().and_then(|i| i.get("PrivateKey")) {
        // One VPN, one tunnel: the same key in a user zone next to a system
        // zone makes the server see two devices with one key, and they knock
        // each other off. When the system tier has this VPN already, the user
        // zone goes out through it instead of dialling it a second time.
        if Path::new(crate::sysrun::SOCKET).exists() {
            match crate::sysrun::request_key_owner(key.trim()) {
                Ok(Some(zone)) => {
                    println!(
                        "этот VPN уже поднят системой как зона {zone}: второе подключение \
                         выбивало бы первое, поэтому зона пойдёт наружу через её туннель"
                    );
                    text = crate::sysuplink::SysUplinkConfig { zone }
                        .text()
                        .into_bytes();
                }
                Ok(None) => {}
                // A zone of the system's this user may not use: refused, not
                // dialled a second time behind its back.
                Err(e) if e.contains("already the system zone") => {
                    eprintln!("{e}");
                    return 1;
                }
                Err(e) => eprintln!(
                    "не удалось спросить системный уровень, не поднят ли этот VPN уже там \
                     ({e}) — зона создаётся со своим туннелем"
                ),
            }
        }
    }

    let dir = tools.state.join(name);
    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("не создать {}: {e}", dir.display());
        return 1;
    }
    // A copy, not a link: a config with a private key has to survive the
    // original being moved or deleted. Mode 0600 from the start — never a
    // moment where the key is world-readable. (`docs/GOTCHAS.md` §4)
    let target = dir.join("config.conf");
    let _ = fs::remove_file(&target);
    let written = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&target)
        .and_then(|mut file| file.write_all(&text));
    if let Err(e) = written {
        eprintln!("не записать {}: {e}", target.display());
        return 1;
    }
    println!("зона {} создана", name.to_string_lossy());
    0
}

fn up(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(name) = required(args, 0, "нужно имя") else {
        return 1;
    };
    let code = systemctl(tools, "start", name);
    if code != 0 {
        return code;
    }
    let name_text = name.to_string_lossy();
    if wait_ready(&tools.state, name) {
        println!("зона {name_text} поднята");
        0
    } else {
        eprintln!("зона {name_text} не поднялась — journalctl --user -u vpn-zone@{name_text}");
        1
    }
}

fn down(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(name) = required(args, 0, "нужно имя") else {
        return 1;
    };
    let code = systemctl(tools, "stop", name);
    if code != 0 {
        return code;
    }
    println!("зона {} опущена", name.to_string_lossy());
    0
}

fn list(tools: &Tools) -> u8 {
    for dir in visible_entries(&tools.state) {
        if !dir.is_dir() {
            continue;
        }
        let Some(name) = dir.file_name() else {
            continue;
        };
        let state = if zone_pid(&tools.state, name).is_some() {
            "поднята"
        } else {
            "опущена"
        };
        println!("{} — {state}", name.to_string_lossy());
    }
    0
}

fn status(tools: &Tools, args: &[OsString]) -> u8 {
    // The whole state, for configuration tools (`docs/CONTAINERS.md` §9).
    if args.first().is_some_and(|a| a == "--json") {
        println!("{}", crate::status::document(tools));
        return 0;
    }
    // One line for a status bar (waybar's `return-type: json` and the like).
    if args.first().is_some_and(|a| a == "--bar") {
        println!("{}", crate::status::bar(tools));
        return 0;
    }
    let Some(name) = required(args, 0, "нужно имя") else {
        return 1;
    };
    let Some(pid) = zone_pid(&tools.state, name) else {
        println!("зона {} не поднята", name.to_string_lossy());
        return 1;
    };
    let code = match Command::new(&tools.nsenter)
        .args(["--preserve-credentials", "-U", "-n", "-m", "-t"])
        .arg(pid.to_string())
        .arg("--")
        .arg(&tools.ip)
        .args(["-br", "-4", "addr", "show"])
        .status()
    {
        Ok(status) => status.code().map_or(1, |c| c as u8),
        Err(e) => {
            eprintln!("не запустить {}: {e}", tools.nsenter.display());
            return EXIT_NOT_STARTED;
        }
    };
    if code != 0 {
        return code;
    }
    // The tunnel's state comes from the mirror the zone writes itself: from the
    // inside, under an ordinary uid, `awg show` has no privileges and says
    // nothing at all. (`docs/GOTCHAS.md` §4)
    if let Ok(mirror) = fs::read_to_string(tools.state.join(name).join("status")) {
        println!();
        print!("{mirror}");
    }
    0
}

fn set_lock(tools: &Tools, args: &[OsString], locked: bool) -> u8 {
    let Some(name) = required(args, 0, "нужно имя зоны") else {
        return 1;
    };
    let dir = tools.state.join(name);
    if !dir.is_dir() {
        eprintln!("зоны {} нет", name.to_string_lossy());
        return 1;
    }
    let marker = dir.join(launch::NO_ESCAPE);
    let name = name.to_string_lossy();
    if locked {
        if let Err(e) = fs::write(&marker, b"") {
            eprintln!("не записать {}: {e}", marker.display());
            return 1;
        }
        println!(
            "зона {name} заперта: программы из неё не смогут запускать что-либо в других сетях"
        );
        // The lock is kept by the broker, the only door of a hermetic zone. A
        // zone that is not hermetic has `systemd --user` in reach, and a
        // program there can start anything outside without asking vpn-zones.
        let (hermetic, _) = crate::hermetic::zone_setting(&dir, &tools.config, &name);
        if !hermetic {
            eprintln!(
                "⚠ зона {name} не герметична: замок держится только в герметичной зоне — \
                 отсюда программа может запустить что угодно снаружи через systemd --user \
                 (docs/LEAK-MODEL.md §1). Включи герметичность: cellward hermetic {name} on"
            );
        } else if zone_pid(&tools.state, OsStr::new(&*name)).is_some() {
            // The setting takes effect when the zone comes up: one up since
            // before it was switched on is not hermetic yet.
            eprintln!(
                "замок держится, если зона поднята уже герметичной; включали герметичность \
                 после её подъёма — перезапусти зону: cellward down {name}, cellward up {name}"
            );
        }
    } else {
        let _ = fs::remove_file(&marker);
        println!("зона {name} открыта: запуск из неё в другой сети снова разрешён");
    }
    0
}

/// `vpn-zone hermetic <zone> default|on|off` and
/// `vpn-zone hermetic --default on|off`: `docs/HERMETICITY.md` §7 C — the
/// runtime directory closed, the session bus filtered, the broker as the way
/// out. Takes effect when a zone next comes up; `crate::hermetic` has the
/// order in which the settings win.
fn zone_hermetic(tools: &Tools, args: &[OsString]) -> u8 {
    // `default` is a word of its own where it follows something — here all
    // the zones' setting —, and is said to (the owner, 2026-09-26); where it
    // is one of the values, the value is marked instead.
    const USAGE: &str = "cellward hermetic <зона> default (как у всех зон)|on|off\n\
                         cellward hermetic --default on (по умолчанию)|off";
    let (Some(name), Some(value)) = (args.first(), args.get(1)) else {
        eprintln!("{USAGE}");
        return 1;
    };
    if name == "--default" {
        let Some(on) = value.to_str().filter(|v| matches!(*v, "on" | "off")) else {
            eprintln!("{USAGE}");
            return 1;
        };
        if let Err(e) = write_setting(tools, crate::hermetic::DEFAULT_SETTING, OsStr::new(on)) {
            eprintln!("{e}");
            return 1;
        }
        println!(
            "зоны без своей настройки {}герметичны — подействует на зону при её следующем подъёме",
            if on == "on" { "" } else { "не " }
        );
        return 0;
    }
    let dir = tools.state.join(name);
    if !dir.is_dir() {
        eprintln!("зоны {} нет", name.to_string_lossy());
        return 1;
    }
    let name = name.to_string_lossy();
    let marker = dir.join(crate::hermetic::MARKER);
    if crate::hermetic::zone_setting(&dir, &tools.config, &name).1 == crate::container::Source::Nix
        && crate::hermetic::declared_exception(&tools.config, &name)
    {
        eprintln!("зона {name} — исключение в Nix (hermetic.exceptions) и меняется там");
        return 1;
    }
    let up = zone_pid(&tools.state, OsStr::new(&*name)).is_some();
    let restart = if up {
        format!(" — подействует после перезапуска зоны: cellward down {name} && cellward up {name}")
    } else {
        String::new()
    };
    let written = match value.to_str() {
        Some(v @ ("on" | "off")) => fs::write(&marker, v.as_bytes()),
        Some("default") => match fs::remove_file(&marker) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        },
        _ => {
            eprintln!("{USAGE}");
            return 1;
        }
    };
    if let Err(e) = written {
        eprintln!("не записать {}: {e}", marker.display());
        return 1;
    }
    let (on, source) = crate::hermetic::zone_setting(&dir, &tools.config, &name);
    let from = match source {
        crate::container::Source::Local => "",
        crate::container::Source::Nix => " (умолчание из Nix)",
        crate::container::Source::Default => " (умолчание)",
    };
    if on {
        println!(
            "зона {name} герметична{from}: без systemd --user, сессионная шина через фильтр, \
             запуск наружу — через брокер{restart}"
        );
    } else {
        println!("зона {name} не герметична{from}{restart}");
    }
    0
}

/// A per-zone allowance, off unless given (`hermetic::nix_daemon`,
/// `hermetic::host_files_writable`).
struct Switch {
    verb: &'static str,
    marker: &'static str,
    on: &'static str,
    off: &'static str,
    nix: &'static str,
    read: fn(&Path, &Path, &str) -> (bool, crate::container::Source),
    said_on: &'static str,
    said_off: &'static str,
    /// Taken when the zone comes up (a restart is said); else by each
    /// launch, from the next one on.
    at_start: bool,
}

const NIX_DAEMON_SWITCH: Switch = Switch {
    verb: "nix-daemon",
    marker: crate::hermetic::NIX_DAEMON,
    on: "on",
    off: "off",
    nix: "programs.cellward.nixDaemon",
    read: crate::hermetic::nix_daemon,
    said_on:
        "программам зоны виден Nix-демон хоста — он качает и собирает в сети хоста, мимо её VPN",
    said_off: "Nix-демон хоста программам зоны не виден",
    at_start: true,
};

const HOST_FILES_SWITCH: Switch = Switch {
    verb: "host-files",
    marker: crate::hermetic::HOST_FILES,
    on: "writable",
    off: "read-only",
    nix: "programs.cellward.hostFilesWritable",
    read: crate::hermetic::host_files_writable,
    said_on: "программы зоны могут писать туда, что хост потом исполняет (автозапуск, ярлыки, конфиги оболочек и композитора)",
    said_off: "в герметичной зоне то, что хост исполняет из дома, только для чтения",
    at_start: true,
};

const CAMERA_SWITCH: Switch = Switch {
    verb: "camera",
    marker: crate::hermetic::CAMERA,
    on: "on",
    off: "off",
    nix: "programs.cellward.camera",
    read: crate::hermetic::camera,
    said_on: "программам зоны без своей настройки камеры видны камеры хоста — снимать они могут \
              без вопроса (программам, запущенным после этого)",
    said_off: "камеры хоста не видны программам зоны без своей настройки камеры (запущенным \
               после этого)",
    at_start: false,
};

/// The raw PipeWire socket in a hermetic zone (`crate::pw_context`): said
/// loudly, it is the host's whole sound graph.
const AUDIO_MANAGER_SWITCH: Switch = Switch {
    verb: "audio-manager",
    marker: crate::hermetic::AUDIO_MANAGER,
    on: "on",
    off: "off",
    nix: "programs.cellward.audioManager",
    read: crate::hermetic::audio_manager,
    said_on: "ВНИМАНИЕ: зоне отдан PipeWire хоста без ограничений — её программы слышат всё, что играет хост, записывают микрофон мимо настройки microphone, двигают и глушат чужие потоки и меняют права других клиентов; только для доверенного микшера (pavucontrol, qpwgraph, EasyEffects)",
    said_off: "герметичная зона получает ограниченный PipeWire: свои потоки, выходы для звука, микрофон по настройке microphone",
    at_start: true,
};

/// `vpn-zone nix-daemon|host-files|camera|audio-manager <zone> <off>|<on>`:
/// `<off>` is the default; `default` (the zone's marker removed) is still
/// taken, and not shown.
fn zone_allowance(tools: &Tools, args: &[OsString], switch: &Switch) -> u8 {
    let usage = format!(
        "cellward {} <зона> {} (по умолчанию)|{}",
        switch.verb, switch.off, switch.on
    );
    let (Some(name), Some(value)) = (args.first(), args.get(1)) else {
        eprintln!("{usage}");
        return 1;
    };
    let dir = tools.state.join(name);
    if !safe_zone_name(name) || !dir.is_dir() {
        eprintln!("зоны {} нет", name.to_string_lossy());
        return 1;
    }
    let name = name.to_string_lossy();
    let marker = dir.join(switch.marker);
    let written = match value.to_str() {
        Some(v) if v == switch.on || v == switch.off => fs::write(&marker, v.as_bytes()),
        Some("default") => match fs::remove_file(&marker) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        },
        _ => {
            eprintln!("{usage}");
            return 1;
        }
    };
    if let Err(e) = written {
        eprintln!("не записать {}: {e}", marker.display());
        return 1;
    }
    let (on, source) = (switch.read)(&dir, &tools.config, &name);
    let from = match source {
        crate::container::Source::Local => String::new(),
        crate::container::Source::Nix => format!(" (задано в Nix: {})", switch.nix),
        crate::container::Source::Default => " (умолчание)".to_owned(),
    };
    let restart = if switch.at_start && zone_pid(&tools.state, OsStr::new(&*name)).is_some() {
        format!(" — подействует после перезапуска зоны: cellward down {name} && cellward up {name}")
    } else {
        String::new()
    };
    let said = if on { switch.said_on } else { switch.said_off };
    println!("зона {name}: {said}{from}{restart}");
    0
}

/// `vpn-zone ask-again <term>|default` (`crate::grants::ask_again`): how long
/// after a refusal no program of the zone is asked again. Read when the
/// person refuses, so it applies at once.
fn ask_again(tools: &Tools, args: &[OsString]) -> u8 {
    use crate::container::Source;
    use crate::grants::{ask_again_term, term_text, ASK_AGAIN_SETTING};
    const USAGE: &str = "cellward ask-again <срок> (30s…1d; по умолчанию 3m)";
    let show = |tools: &Tools| {
        let (secs, source) = crate::grants::ask_again(&tools.config);
        let from = match source {
            Source::Local => String::new(),
            Source::Nix => " (задано в Nix: programs.cellward.askAgainAfter)".to_owned(),
            Source::Default => " (умолчание)".to_owned(),
        };
        println!(
            "после отказа зону снова спросят через {}{from}",
            term_text(secs)
        );
    };
    let value = match args {
        [] => {
            show(tools);
            return 0;
        }
        [value] => value.to_str().unwrap_or(""),
        _ => {
            eprintln!("{USAGE}");
            return 1;
        }
    };
    let written = if value == "default" {
        if tools
            .config
            .join(DECLARED_DIR)
            .join(ASK_AGAIN_SETTING)
            .exists()
        {
            Err(format!(
                "«{ASK_AGAIN_SETTING}» задано в Nix (programs.cellward) и меняется там"
            ))
        } else {
            match fs::remove_file(tools.config.join(ASK_AGAIN_SETTING)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
                _ => Ok(()),
            }
        }
    } else {
        match ask_again_term(value) {
            Some(secs) => write_setting(tools, ASK_AGAIN_SETTING, OsStr::new(&term_text(secs))),
            None => {
                eprintln!("срок — число и единица, от 30s до 1d: 45s, 3m, 1h (или default)");
                return 1;
            }
        }
    };
    if let Err(e) = written {
        eprintln!("не записать {e}");
        return 1;
    }
    show(tools);
    0
}

/// `vpn-zone microphone <zone> ask|yes|no` (`crate::microphone`): the
/// zone's marker. The sound filter reads it for every record stream, so it
/// applies at once, to programs already running too.
fn zone_microphone(tools: &Tools, args: &[OsString]) -> u8 {
    use crate::container::Source;
    use crate::microphone::{Setting, MARKER};
    // `default` — the marker removed, i.e. `ask` — is still taken, and no
    // longer shown: the default is marked where it is one of the three.
    const USAGE: &str = "cellward microphone <зона> ask (по умолчанию)|yes|no";
    let (Some(name), Some(value)) = (args.first(), args.get(1)) else {
        eprintln!("{USAGE}");
        return 1;
    };
    let dir = tools.state.join(name);
    if !safe_zone_name(name) || !dir.is_dir() {
        eprintln!("зоны {} нет", name.to_string_lossy());
        return 1;
    }
    let name = name.to_string_lossy();
    let marker = dir.join(MARKER);
    let written = match value.to_str() {
        Some("default") => match fs::remove_file(&marker) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        },
        Some(v) => match Setting::parse(v) {
            Some(setting) => fs::write(&marker, setting.as_str()),
            None => {
                eprintln!("{USAGE}");
                return 1;
            }
        },
        None => {
            eprintln!("{USAGE}");
            return 1;
        }
    };
    if let Err(e) = written {
        eprintln!("не записать {}: {e}", marker.display());
        return 1;
    }
    let (setting, source) = crate::microphone::setting(&dir, &tools.config, &name);
    let (hermetic, _) = crate::hermetic::zone_setting(&dir, &tools.config, &name);
    let (audio_manager, _) = crate::hermetic::audio_manager(&dir, &tools.config, &name);
    // The PipeWire socket follows the switch only where it is the restricted
    // one (`pw_context`): a hermetic zone that is not an audio manager.
    let restricted = hermetic && !audio_manager;
    // Said for what it is: the switch of the sound filter and of the
    // restricted PipeWire. What goes around it is named beside it (review
    // 2026-09-25) — a "no" read as the zone's boundary would be a promise it
    // does not keep.
    let said = match (setting, restricted) {
        (Setting::Yes, _) => "программы зоны записывают микрофон без вопроса",
        (Setting::No, true) => {
            "микрофон программам зоны недоступен: ни через звуковой сервер (pulse), ни через \
             PipeWire зоны"
        }
        (Setting::No, false) => "через звуковой сервер (pulse) микрофон программам зоны недоступен",
        (Setting::Ask, true) => {
            "при записи с микрофона через звуковой сервер (pulse) программа зоны спросит: \
             один раз, всегда или отказать; через PipeWire зоны — отказ (там не спрашивают)"
        }
        (Setting::Ask, false) => {
            "при записи с микрофона через звуковой сервер (pulse) программа зоны спросит: \
             один раз, всегда или отказать"
        }
    };
    let from = match source {
        Source::Local => String::new(),
        Source::Nix => " (задано в Nix: programs.cellward.microphone — своя настройка зоны \
                        не действует, пока оно там)"
            .to_owned(),
        Source::Default => " (умолчание)".to_owned(),
    };
    println!(
        "зона {name}: {said}{from}. Действует сразу; звук, который играет хост, зоне не записать"
    );
    if setting != Setting::Yes {
        if !hermetic {
            println!(
                "  мимо этого переключателя: сырой pipewire-0 и systemd --user хоста — зона \
                 не герметична, её программа запишет микрофон или перепишет эту настройку \
                 сама (cellward hermetic {name} on)"
            );
        } else if audio_manager {
            println!(
                "  мимо этого переключателя: сырой pipewire-0 — зона объявлена менеджером \
                 звука (cellward audio-manager {name} off)"
            );
        }
    }
    0
}

/// `cellward screencast <zone> ask|yes|no` (`crate::screencast`): the
/// zone's marker. The zone's bus filter reads it for every call of the
/// screen cast portal, so it applies at once, to programs already running
/// too.
fn zone_screencast(tools: &Tools, args: &[OsString]) -> u8 {
    use crate::container::Source;
    use crate::screencast::{Setting, MARKER};
    // `default` is still taken, as for the microphone.
    const USAGE: &str = "cellward screencast <зона> ask (по умолчанию)|yes|no";
    let (Some(name), Some(value)) = (args.first(), args.get(1)) else {
        eprintln!("{USAGE}");
        return 1;
    };
    let dir = tools.state.join(name);
    if !safe_zone_name(name) || !dir.is_dir() {
        eprintln!("зоны {} нет", name.to_string_lossy());
        return 1;
    }
    let name = name.to_string_lossy();
    let marker = dir.join(MARKER);
    let written = match value.to_str() {
        Some("default") => match fs::remove_file(&marker) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        },
        Some(v) => match Setting::parse(v) {
            Some(setting) => fs::write(&marker, setting.as_str()),
            None => {
                eprintln!("{USAGE}");
                return 1;
            }
        },
        None => {
            eprintln!("{USAGE}");
            return 1;
        }
    };
    if let Err(e) = written {
        eprintln!("не записать {}: {e}", marker.display());
        return 1;
    }
    let (setting, source) = crate::screencast::setting(&dir, &tools.config, &name);
    let (hermetic, _) = crate::hermetic::zone_setting(&dir, &tools.config, &name);
    let said = match setting {
        Setting::Yes => {
            "программа зоны может попросить портал запомнить, что показывать: следующую \
             трансляцию он начнёт без вопроса"
        }
        Setting::No => "трансляция экрана программам зоны недоступна: портал её не начнёт",
        Setting::Ask => {
            "при каждой трансляции экрана портал спрашивает, что показать; запомнить выбор \
             нельзя"
        }
    };
    let from = match source {
        Source::Local => String::new(),
        Source::Nix => " (задано в Nix: programs.cellward.screencast — своя настройка зоны \
                        не действует, пока оно там)"
            .to_owned(),
        Source::Default => " (умолчание)".to_owned(),
    };
    println!("зона {name}: {said}{from}. Действует сразу, и для уже запущенных программ");
    if !hermetic {
        // Said for what it is: the switch of the zone's bus filter, which a
        // zone that is not hermetic does not have (review 2026-09-25).
        println!(
            "  мимо этого переключателя: зона не герметична — её программы говорят с порталом \
             напрямую (cellward hermetic {name} on)"
        );
    } else if setting == Setting::Yes {
        println!(
            "  запомненный выбор — только если портал знает зону по имени (xdg-desktop-portal \
             1.19+), и не в песочнице файлов (--fs-sandbox): там как ask"
        );
    }
    0
}

/// `vpn-zone x11 <zone> on|off`: an X server of their own for the programs of a
/// zone (`docs/HERMETICITY.md` §7, A). The host's stays out of reach either way.
fn zone_x11(tools: &Tools, args: &[OsString]) -> u8 {
    let (Some(name), Some(value)) = (args.first(), args.get(1)) else {
        eprintln!("cellward x11 <зона> on|off");
        return 1;
    };
    let dir = tools.state.join(name);
    if !dir.is_dir() {
        eprintln!("зоны {} нет", name.to_string_lossy());
        return 1;
    }
    let name = name.to_string_lossy();
    let marker = dir.join(crate::x11::ZONE_FLAG);
    match value.to_str() {
        Some("on") => {
            if let Err(e) = fs::write(&marker, b"") {
                eprintln!("не записать {}: {e}", marker.display());
                return 1;
            }
            println!(
                "у программ зоны {name} свой X-сервер (xwayland-satellite); X-сервер хоста по-прежнему недоступен"
            );
            0
        }
        Some("off") => {
            let _ = fs::remove_file(&marker);
            if crate::x11::zone_setting(&tools.state, &tools.config, &name).1
                == crate::container::Source::Nix
            {
                eprintln!("x11 зоны {name} задан в Nix (zoneX11) — выключается там");
                return 1;
            }
            println!("у программ зоны {name} X нет");
            0
        }
        _ => {
            eprintln!("cellward x11 <зона> on|off");
            1
        }
    }
}

/// "Is this config alive at all?" — the short answer, by the fact of a
/// handshake. The exit codes are part of the contract: 0 alive, 1 no handshake,
/// 2 zone down, 3 state unknown.
fn check(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(name) = required(args, 0, "нужно имя") else {
        return 1;
    };
    let name_text = name.to_string_lossy();
    if zone_pid(&tools.state, name).is_none() {
        println!("зона {name_text} не поднята");
        return 2;
    }
    // "No handshake" and "no data" are different answers: the mirror is written
    // by the zone itself, and a zone brought up by an older version simply has
    // no such file. Without this check `check` used to declare a live tunnel
    // dead. (`docs/GOTCHAS.md` §4)
    let Ok(mirror) = fs::read_to_string(tools.state.join(name).join("status")) else {
        println!("зона {name_text}: состояние неизвестно — она поднята старой версией,");
        println!("перезапусти её: cellward down {name_text} && cellward up {name_text}");
        return 3;
    };
    match alive_line(&tools.state.join(name), &mirror) {
        Some(line) => {
            println!("зона {name_text}: туннель живой ({line})");
            0
        }
        None => {
            println!("зона {name_text}: рукопожатия нет — конфиг мёртвый или сервер недоступен");
            1
        }
    }
}

/// [`liveness_line`], unless `vpn-zone watch` found this run of the zone's
/// tunnel dead at its last look.
///
/// A handshake line says only that there WAS one: an idle tunnel's is hours
/// old and fine, a dead one's is hours old too. `watch` tells them apart by
/// age and counters, a minute at a time; a verdict older than the zone's
/// current start is about a previous run and is not read (review 2026-09-24:
/// `check`, `status --json` and `doctor` said "alive" of a dead tunnel).
pub fn alive_line(zone_dir: &Path, mirror: &str) -> Option<String> {
    let line = liveness_line(mirror)?;
    let (Some(name), Some(state)) = (zone_dir.file_name(), zone_dir.parent()) else {
        return Some(line);
    };
    let memory = state.join(crate::watch::WATCH_DIR).join(name);
    let modified = |p: &Path| fs::metadata(p).and_then(|m| m.modified()).ok();
    let about_this_run = match (modified(&memory), modified(&zone_dir.join("zone.pid"))) {
        (Some(verdict), Some(started)) => verdict >= started,
        _ => false,
    };
    let dead = about_this_run
        && fs::read_to_string(&memory)
            .ok()
            .and_then(|t| crate::watch::parse_memory(&t))
            .is_some_and(|(_, v)| v == crate::watch::Verdict::Dead);
    (!dead).then_some(line)
}

/// The line of the status mirror that says the tunnel is alive, whichever
/// backend wrote it.
///
/// A WireGuard zone answers with a handshake; an OpenConnect one has no
/// handshake at all and writes `connected:` instead when its interface is there
/// and up (`crate::zone::oc_mirror`). Writing a fake handshake line into the
/// second kind of file would have kept `check` shorter and told the user
/// something untrue.
pub fn liveness_line(mirror: &str) -> Option<String> {
    handshake_line(mirror).or_else(|| {
        mirror
            .lines()
            .map(str::trim_start)
            .find(|line| line.starts_with("connected:"))
            .map(str::to_owned)
    })
}

/// The "latest handshake" line of a `wg show` mirror, leading spaces trimmed.
///
/// `grep -A20 peer | grep -i 'latest handshake' | head -1`, written down: the
/// line has to belong to a peer block, because the interface block has no
/// handshake in it and a future field named like one must not be read as an
/// answer.
pub fn handshake_line(mirror: &str) -> Option<String> {
    let mut window = 0;
    for line in mirror.lines() {
        if line.contains("peer") {
            window = 21;
        }
        if window == 0 {
            continue;
        }
        window -= 1;
        if line.to_lowercase().contains("latest handshake") {
            return Some(line.trim_start_matches(' ').to_owned());
        }
    }
    None
}

fn remove(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(name) = required(args, 0, "нужно имя") else {
        return 1;
    };
    let name_text = name.to_string_lossy();
    // `unconfined` and `offline` are built-in choices of the picker, not zones:
    // unconfined traffic is the absence of a zone, and the empty one is
    // recreated by the first launch that asks for it. (`docs/GOTCHAS.md` §2)
    // A directory left with the name `unconfined` from before it was taken is
    // a zone all the same, and removable.
    if name == launch::UNCONFINED_ALIAS
        || name == launch::OFFLINE
        || (name == launch::UNCONFINED && !tools.state.join(name).is_dir())
    {
        eprintln!("«{name_text}» — встроенный вариант, его нельзя удалить");
        return 1;
    }
    let dir = tools.state.join(name);
    if !dir.is_dir() {
        eprintln!("зоны {name_text} нет");
        return 1;
    }
    let _ = systemctl(tools, "stop", name);
    if let Err(e) = crate::sys::remove_tree(&dir) {
        eprintln!("не удалить {}: {e}", dir.display());
        return 1;
    }
    // Its entry for the portal (`desktop::zone_app_id`): a new zone of the
    // same name gets its own. Sync below would take it too; this does not
    // wait for sync to work.
    crate::desktop::remove_zone_entry(&tools.home, &name_text);
    // Pins that pointed at this zone go with it: otherwise the program stays
    // bound to a network that no longer exists and fails silently on every
    // launch. (`docs/GOTCHAS.md` §11)
    for sub in [".pinned", ".last"] {
        for file in visible_entries(&tools.state.join(sub)) {
            if read_setting(&file).as_deref() == Some(name_text.as_ref()) {
                let _ = fs::remove_file(&file);
            }
        }
    }
    // The containers bound to it here: a new zone of the same name (another
    // provider) must not take them in unasked. One declared in Nix stays as
    // declared, and does not start elsewhere (I6).
    for c in crate::container::load_all(tools) {
        let bound_here = c.network.source == crate::container::Source::Local
            && c.network.value == crate::container::Network::Named(name_text.to_string());
        if bound_here {
            match crate::container::set_network(tools, &c.name, &crate::container::Network::Ask) {
                Ok(()) => println!(
                    "контейнер {} больше не привязан к сети: {} удалена",
                    c.name, name_text
                ),
                Err(e) => eprintln!("контейнер {}: {e}", c.name),
            }
        }
    }
    // And the picker's default, if it was this zone, and the broker's
    // "always" answers from or into it: a new zone of the same name must not
    // inherit them.
    let default = tools.config.join("default");
    if read_setting(&default).as_deref() == Some(name_text.as_ref()) {
        let _ = fs::remove_file(&default);
    }
    let always = tools.config.join(crate::broker::ALWAYS);
    if let Ok(text) = fs::read_to_string(&always) {
        let kept: String = text
            .lines()
            .filter(|l| {
                let mut fields = l.split('\t');
                let origin = fields.next().unwrap_or("");
                let target = fields.next().unwrap_or("");
                origin != name_text && target != name_text
            })
            .map(|l| format!("{l}\n"))
            .collect();
        let _ = fs::write(&always, kept);
    }
    let code = run_sync(tools);
    if code != 0 {
        return code;
    }
    println!("зона {name_text} удалена");
    0
}

// --- GARBAGE COLLECTION ------------------------------------------------------

/// Sweep up the hung leftovers of zones that were killed rather than stopped.
///
/// The criteria are deliberately EXACT rather than "kill everything orphaned":
/// the first version of this command took a live zone down because it only
/// looked at `zone.pid`. So: processes under systemd (`vpn-zone@…`) are not
/// touched at all — the unit owns them; a pasta is killed only when the netns it
/// serves is dead, and its number is right there in its command line; other
/// people's sandboxes (bwrap) are left alone, there are programs in them.
/// (`docs/GOTCHAS.md` §2)
fn gc(tools: &Tools) -> u8 {
    let mut killed = 0;
    for pid in processes_named("pasta") {
        // Held from here on: every check below is of THIS process, and the
        // signal goes to it or to nobody — a number can change hands between
        // reading /proc and kill(2) (review 2026-09-25).
        let Some(pidfd) = crate::sys::pidfd_open(pid) else {
            continue;
        };
        let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
        if cgroup.contains("vpn-zone@") {
            continue;
        }
        let Ok(cmdline) = fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let Some(target) = netns_pid(&cmdline) else {
            continue;
        };
        if proc_is_alive(target) {
            continue;
        }
        // Still pasta, now that it is held: the number may have been a new
        // process's by the time the descriptor was opened.
        let still = fs::read(format!("/proc/{pid}/comm")).is_ok_and(|c| c.trim_ascii() == b"pasta");
        if still && crate::sys::pidfd_signal(&pidfd, libc::SIGTERM) {
            killed += 1;
        }
    }

    let running = tools.state.join(".running");
    let mut cleaned = registry::sweep_dead(&running, &|pid| registry::alive(&running, pid));
    registry::sweep_started(&running);

    // Abandoned throwaway containers. Their home is erased behind the last
    // tenant, but a hard kill leaves the directory. Judged by live PIDs in the
    // registry and not by the registry directory existing: after a hard kill
    // that directory stays around full of dead records, and the older check kept
    // the garbage in /tmp forever. (`docs/GOTCHAS.md` §5)
    // Below the state directory, and in /tmp, where they lived before
    // (`docs/LEAK-MODEL.md` §15).
    for base in crate::launch::throwaway_bases(&tools.state) {
        for dir in visible_entries(&base) {
            let Some(name) = dir.file_name() else {
                continue;
            };
            if !name.as_bytes().starts_with(b"vpn-profile-") || !dir.is_dir() {
                continue;
            }
            let regdir = running.join(name);
            if registry::any_live(&regdir, &|pid| registry::alive(&running, pid)) {
                continue;
            }
            let _ = crate::sys::remove_tree(&dir);
            let _ = crate::sys::remove_tree(&regdir);
            cleaned += 1;
        }
    }

    println!("остановлено зависших выходов в сеть: {killed}, подчищено записей: {cleaned}");
    0
}

/// Pids whose `comm` is exactly this — `pgrep -x`, without the process table
/// tool.
fn processes_named(name: &str) -> Vec<i32> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return out;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let Ok(comm) = fs::read_to_string(entry.path().join("comm")) else {
            continue;
        };
        if comm.trim_end_matches('\n') == name {
            out.push(pid);
        }
    }
    out.sort_unstable();
    out
}

/// The pid out of the first `/proc/<pid>/ns/net` in a command line.
///
/// That is how a stray pasta is recognised: it is attached to a namespace from
/// the outside, and in the gateway layout that namespace is the zone's UPLINK.
/// (`docs/GOTCHAS.md` §2)
pub fn netns_pid(cmdline: &[u8]) -> Option<i32> {
    const PREFIX: &[u8] = b"/proc/";
    const SUFFIX: &[u8] = b"/ns/net";
    for start in 0..cmdline.len() {
        if !cmdline[start..].starts_with(PREFIX) {
            continue;
        }
        let digits_at = start + PREFIX.len();
        let end = digits_at
            + cmdline[digits_at..]
                .iter()
                .take_while(|b| b.is_ascii_digit())
                .count();
        if end > digits_at && cmdline[end..].starts_with(SUFFIX) {
            return std::str::from_utf8(&cmdline[digits_at..end])
                .ok()
                .and_then(|digits| digits.parse().ok());
        }
    }
    None
}

// --- PERMISSIONS, SANDBOXES, CONTAINERS --------------------------------------

fn perms(tools: &Tools, args: &[OsString]) -> u8 {
    let dir = tools.config.join("fs-perms");
    let sub = args
        .first()
        .cloned()
        .unwrap_or_else(|| OsString::from("list"));
    let rest: &[OsString] = args.get(1..).unwrap_or(&[]);
    match sub.as_bytes() {
        b"list" => {
            let files: Vec<PathBuf> = visible_entries(&dir)
                .into_iter()
                .filter(|f| f.is_file())
                .collect();
            if files.is_empty() {
                println!("доступы никому не выдавались");
                return 0;
            }
            for file in files {
                let text = fs::read_to_string(&file)
                    .unwrap_or_default()
                    .replace('\n', " ");
                let shown = if text.is_empty() {
                    "ничего"
                } else {
                    &text
                };
                println!(
                    "{} → {shown}",
                    file.file_name().unwrap_or_default().to_string_lossy()
                );
            }
            0
        }
        b"reset" => {
            let Some(what) = required(rest, 0, "имя программы или --all") else {
                return 1;
            };
            if what == "--all" {
                let _ = crate::sys::remove_tree(&dir);
                println!("сброшено для всех — при следующем запуске спросит заново");
            } else {
                let _ = fs::remove_file(dir.join(what));
                println!("сброшено для {}", what.to_string_lossy());
            }
            0
        }
        _ => {
            eprintln!("cellward perms list|reset <программа|--all>");
            1
        }
    }
}

/// `sandbox create|list|rm`: the words from before one name per container
/// (`docs/PERMISSIONS.md` §11.7) — `container` with a home of its own.
fn sandbox(tools: &Tools, args: &[OsString]) -> u8 {
    container_kind_alias(tools, args, crate::container::Home::Private, "sandbox")
}

/// `profile create|list|rm`: `container` with a layer over the home.
fn profile(tools: &Tools, args: &[OsString]) -> u8 {
    container_kind_alias(tools, args, crate::container::Home::Layer, "profile")
}

fn container_kind_alias(
    tools: &Tools,
    args: &[OsString],
    home: crate::container::Home,
    word: &str,
) -> u8 {
    let sub = args
        .first()
        .cloned()
        .unwrap_or_else(|| OsString::from("list"));
    let rest: &[OsString] = args.get(1..).unwrap_or(&[]);
    match sub.as_bytes() {
        b"create" => {
            let Some(name) = required(rest, 0, "нужно имя контейнера") else {
                return 1;
            };
            container_create(tools, name, home)
        }
        b"list" => {
            let all = crate::container::load_all(tools);
            let of_kind: Vec<_> = all.iter().filter(|c| c.home == home).collect();
            if of_kind.is_empty() {
                println!(
                    "контейнеров вида «{}» нет. Создать: cellward container create <имя> --home {}",
                    home.label(),
                    home.setting()
                );
                return 0;
            }
            for c in of_kind {
                println!("{}", container_line(tools, c));
            }
            0
        }
        b"rm" => {
            let Some(name) = required(rest, 0, "нужно имя контейнера") else {
                return 1;
            };
            container_remove(tools, name)
        }
        _ => {
            eprintln!("cellward {word} create|list|rm <имя> (то же, что cellward container)");
            1
        }
    }
}

/// `container create <name> [--home private|layer|main]`.
fn container_create(tools: &Tools, name: &OsStr, home: crate::container::Home) -> u8 {
    let name = name.to_string_lossy();
    match crate::container::create(tools, &name, home) {
        Ok(c) => {
            let what = match c.home {
                crate::container::Home::Private => {
                    "свой пустой дом, доступ наружу спросится при запуске"
                }
                crate::container::Home::Layer => "пустой слой поверх твоего ~/",
                crate::container::Home::Main => {
                    "основной дом: настоящий, со своими сетью и разрешениями"
                }
            };
            println!("контейнер {name} создан ({what})");
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

/// `container rm <name>`: its data and its local policy. A declared one stays
/// declared — the module would make it again.
fn container_remove(tools: &Tools, name: &OsStr) -> u8 {
    let text = name.to_string_lossy();
    let Some(c) = crate::container::load(tools, &text) else {
        eprintln!("контейнера {text} нет");
        return 1;
    };
    if let Some(busy) = crate::container::running_network(tools, &c) {
        eprintln!(
            "программы контейнера {} работают (в сети {busy}) — закрой их",
            c.name
        );
        return 1;
    }
    // The data first — it may take a while —, then the policy under the lock
    // the sound filter writes "always" under (`microphone::Policy::
    // remember`): an answer does not bring back a container removed
    // meanwhile.
    if fs::symlink_metadata(&c.dir).is_ok() {
        if let Err(e) = crate::sys::remove_tree(&c.dir) {
            eprintln!("не удалить {}: {e}", c.dir.display());
            return 1;
        }
    }
    {
        let root = tools.config.join(crate::container::POLICY_DIR);
        let _lock = match crate::registry::lock(&root) {
            Ok(lock) => lock,
            Err(e) => {
                eprintln!(
                    "не занять {}: {e} — данные контейнера {} удалены, настройки не удалены: \
                     повтори cellward container rm {}",
                    root.display(),
                    c.name,
                    c.name
                );
                return 1;
            }
        };
        if fs::symlink_metadata(&c.policy).is_ok() {
            if let Err(e) = crate::sys::remove_tree(&c.policy) {
                eprintln!("не удалить {}: {e}", c.policy.display());
                return 1;
            }
        }
    }
    let declared = crate::container::load(tools, &c.name).is_some();
    if declared {
        println!(
            "данные и местные настройки контейнера {} удалены; он объявлен в Nix и останется",
            c.name
        );
    } else if c.home == crate::container::Home::Main {
        let aside = if fs::symlink_metadata(&c.dir).is_ok() {
            ", и данные, отложенные от прежнего вида его дома"
        } else {
            ""
        };
        println!(
            "контейнер {} удалён (настоящий дом не тронут{aside})",
            c.name
        );
    } else {
        println!("контейнер {} удалён вместе со своими данными", c.name);
    }
    0
}

/// One line of a list: the name, the kind of home, the size, where it runs.
fn container_line(tools: &Tools, c: &crate::container::Container) -> String {
    let size = if c.home == crate::container::Home::Main {
        String::new()
    } else {
        format!(", {}", human_size(tree_size(&c.dir)))
    };
    let own = c
        .name
        .strip_prefix("app-")
        .filter(|_| c.home == crate::container::Home::Private)
        .map(|app| format!(" программы {app}"))
        .unwrap_or_default();
    let busy = match crate::container::running_network(tools, c) {
        Some(zone) => format!(" — открыт в сети {zone}"),
        None => String::new(),
    };
    format!("{} — {}{own}{size}{busy}", c.name, c.home.label())
}

// --- TRUSTED CERTIFICATES ----------------------------------------------------

/// `vpn-zone trust …`: extra root certificates of ONE container
/// (`docs/CERTIFICATES.md`). The layer itself is laid down at launch time by
/// `profile-run` (`crate::trust`); this is the storage and the loud part.
fn trust(tools: &Tools, args: &[OsString]) -> u8 {
    let sub = args
        .first()
        .cloned()
        .unwrap_or_else(|| OsString::from("list"));
    let rest: &[OsString] = args.get(1..).unwrap_or(&[]);
    match sub.as_bytes() {
        b"add" => trust_add(tools, rest),
        b"list" => trust_list(tools, rest),
        b"rm" => trust_remove(tools, rest, false),
        b"reset" => trust_remove(tools, rest, true),
        _ => {
            eprintln!("cellward trust add|list|rm|reset <контейнер> …");
            1
        }
    }
}

/// A container a certificate can belong to.
struct TrustTarget {
    /// The container's name.
    shown: String,
    /// The container's policy directory (`container::policy_dir`); the
    /// certificates live in `trust/` there.
    policy: PathBuf,
    /// A named sandbox's home on disk: its NSS databases can be brought in line
    /// right away, from here. `None` for a data container, whose databases sit
    /// under an overlay and are only touched from inside a launch.
    home: Option<PathBuf>,
}

impl TrustTarget {
    fn trust_dir(&self) -> PathBuf {
        self.policy.join(crate::trust::DIR)
    }
}

/// A container by name (`sb:<name>` read as it was). Not the main home, and
/// no container of it: its NSS databases are the host's, and a certificate
/// there would be the host's too.
fn trust_target(tools: &Tools, name: &OsStr) -> Result<TrustTarget, String> {
    let text = name.to_string_lossy().into_owned();
    let Some(c) = crate::container::load(tools, &text) else {
        if text.is_empty() || text == registry::MAIN || crate::container::reserved_name(&text) {
            return Err(format!(
                "«{text}» — не контейнер: основной профиль общий с хостом, и сертификат в нём был бы сертификатом хоста"
            ));
        }
        let name = crate::container::canonical(tools, &text).unwrap_or(text);
        return Err(format!(
            "контейнера {name} нет — создай: cellward container create {name}"
        ));
    };
    if c.home == crate::container::Home::Main {
        return Err(format!(
            "{} — основной дом: его базы сертификатов — хоста, и сертификат в них был бы сертификатом хоста",
            c.name
        ));
    }
    Ok(TrustTarget {
        home: c.private_home(),
        policy: c.policy.clone(),
        shown: c.name,
    })
}

/// `openssl x509 … -noout -fingerprint -sha256 -subject -issuer -enddate -ext
/// basicConstraints` on a certificate file.
pub fn certificate_info(
    tools: &Tools,
    file: &Path,
    inform: &str,
) -> Result<crate::trust::CertInfo, String> {
    let out = Command::new(&tools.openssl)
        .args(["x509", "-inform", inform, "-in"])
        .arg(file)
        .args([
            "-noout",
            "-fingerprint",
            "-sha256",
            "-subject",
            "-issuer",
            "-enddate",
            "-ext",
            "basicConstraints",
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("не запустить {}: {e}", tools.openssl.display()))?;
    if !out.status.success() {
        return Err(format!(
            "{} не похож на сертификат X.509: {}",
            file.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    crate::trust::parse_x509_text(&String::from_utf8_lossy(&out.stdout))
        .ok_or_else(|| format!("openssl не назвал отпечаток {}", file.display()))
}

fn trust_add(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(container) = required(args, 0, "нужен контейнер: имя профиля или sb:<песочница>")
    else {
        return 1;
    };
    let Some(file) = required(args, 1, "нужен файл сертификата (PEM или DER)")
    else {
        return 1;
    };
    let yes = args.iter().skip(2).any(|a| a == "--yes");
    let target = match trust_target(tools, container) {
        Ok(target) => target,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let file = Path::new(file);
    let raw = match fs::read(file) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("не читается {}: {e}", file.display());
            return 1;
        }
    };
    // One certificate per file, checked before anything is run: a bundle added
    // "as a certificate" would smuggle in every root inside it.
    let pems = crate::trust::count_pem_certs(&raw);
    if pems > 1 {
        eprintln!(
            "в {} сертификатов: {pems} — добавляй по одному, иначе в контейнер уехал бы каждый корень из этого файла",
            file.display()
        );
        return 1;
    }
    let inform = if pems == 1 { "PEM" } else { "DER" };
    let info = match certificate_info(tools, file, inform) {
        Ok(info) => info,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    if !info.is_ca {
        eprintln!(
            "{} — не сертификат удостоверяющего центра (нет basicConstraints CA:TRUE): корнем доверия он быть не может",
            file.display()
        );
        return 1;
    }
    let pem = match Command::new(&tools.openssl)
        .args(["x509", "-inform", inform, "-in"])
        .arg(file)
        .args(["-outform", "PEM"])
        .stdin(Stdio::null())
        .output()
    {
        Ok(out) if out.status.success() && crate::trust::count_pem_certs(&out.stdout) == 1 => {
            out.stdout
        }
        Ok(out) => {
            eprintln!(
                "openssl не перевёл {} в PEM: {}",
                file.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return 1;
        }
        Err(e) => {
            eprintln!("не запустить {}: {e}", tools.openssl.display());
            return 1;
        }
    };

    println!("Сертификат:    {}", info.subject);
    println!("Издатель:      {}", info.issuer);
    println!("Действует до:  {}", info.not_after);
    println!("SHA-256:       {}", info.sha256);
    println!();
    println!(
        "ВНИМАНИЕ. Любой, у кого есть закрытый ключ этого сертификата, сможет читать и подменять \
         зашифрованный трафик программ контейнера «{}»: пароли, переписку, банковские сессии. На \
         хост и в другие контейнеры сертификат не попадёт.",
        target.shown
    );
    if !yes {
        // SAFETY: isatty(3) takes no pointers.
        if unsafe { libc::isatty(0) } != 1 {
            eprintln!("нужно подтверждение: запусти в терминале или добавь --yes");
            return 1;
        }
        print!("Чтобы добавить, введи имя контейнера ({}): ", target.shown);
        let _ = std::io::stdout().flush();
        let mut answer = String::new();
        if std::io::stdin().read_line(&mut answer).is_err() || answer.trim() != target.shown {
            println!("не подтверждено — ничего не добавлено");
            return 1;
        }
    }

    let dir = target.trust_dir();
    let path = dir.join(format!("{}.pem", info.sha256));
    if let Err(e) = fs::create_dir_all(&dir).and_then(|()| fs::write(&path, &pem)) {
        eprintln!("не записать {}: {e}", path.display());
        return 1;
    }
    println!(
        "сертификат {} добавлен в контейнер {}: программы, запущенные в нём с этой минуты, ему \
         доверяют; уже запущенные — нет",
        &info.sha256[..16],
        target.shown
    );
    0
}

fn trust_list(tools: &Tools, args: &[OsString]) -> u8 {
    let json = args.iter().any(|a| a == "--json");
    let named: Vec<&OsString> = args.iter().filter(|a| *a != "--json").collect();
    let targets: Vec<TrustTarget> = match named.first() {
        Some(name) => match trust_target(tools, name) {
            Ok(target) => vec![target],
            Err(e) => {
                eprintln!("{e}");
                return 1;
            }
        },
        None => crate::container::load_all(tools)
            .into_iter()
            .filter(|c| c.home != crate::container::Home::Main)
            .map(|c| TrustTarget {
                home: c.private_home(),
                policy: c.policy.clone(),
                shown: c.name,
            })
            .filter(|t| t.trust_dir().is_dir())
            .collect(),
    };

    let mut rows: Vec<(String, crate::trust::CertInfo)> = Vec::new();
    for target in &targets {
        for cert in crate::trust::stored(&target.trust_dir()) {
            // A certificate openssl cannot read any more is still listed, by its
            // fingerprint: hiding it would hide that it is trusted.
            let info =
                certificate_info(tools, &cert.path, "PEM").unwrap_or(crate::trust::CertInfo {
                    sha256: cert.sha256.clone(),
                    ..crate::trust::CertInfo::default()
                });
            rows.push((target.shown.clone(), info));
        }
    }

    if json {
        let items: Vec<String> = rows
            .iter()
            .map(|(container, info)| {
                format!(
                    "{{\"container\":{},\"sha256\":{},\"subject\":{},\"issuer\":{},\"not_after\":{},\"source\":\"local\"}}",
                    crate::status::string(container),
                    crate::status::string(&info.sha256),
                    crate::status::string(&info.subject),
                    crate::status::string(&info.issuer),
                    crate::status::string(&info.not_after)
                )
            })
            .collect();
        println!("{{\"schema_version\":1,\"trust\":[{}]}}", items.join(","));
        return 0;
    }
    if rows.is_empty() {
        println!("дополнительных корневых сертификатов нет ни у одного контейнера");
        return 0;
    }
    for (container, info) in rows {
        let subject = if info.subject.is_empty() {
            "(не читается)".to_owned()
        } else {
            info.subject
        };
        println!(
            "{container}: {} — {subject}, до {}",
            &info.sha256[..16],
            info.not_after
        );
    }
    0
}

/// `rm <container> <prefix>` and `reset <container>`.
fn trust_remove(tools: &Tools, args: &[OsString], all: bool) -> u8 {
    let Some(container) = required(args, 0, "нужен контейнер: имя профиля или sb:<песочница>")
    else {
        return 1;
    };
    let target = match trust_target(tools, container) {
        Ok(target) => target,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let stored = crate::trust::stored(&target.trust_dir());
    let doomed: Vec<&crate::trust::Stored> = if all {
        stored.iter().collect()
    } else {
        let Some(prefix) = required(
            args,
            1,
            "нужно начало отпечатка SHA-256 (cellward trust list)",
        ) else {
            return 1;
        };
        let prefix = prefix.to_string_lossy().to_ascii_lowercase();
        let matching: Vec<&crate::trust::Stored> = stored
            .iter()
            .filter(|c| c.sha256.starts_with(&prefix))
            .collect();
        match matching.len() {
            0 => {
                eprintln!("у контейнера {} нет сертификата {prefix}…", target.shown);
                return 1;
            }
            1 => matching,
            n => {
                eprintln!("«{prefix}» подходит к {n} сертификатам — укажи больше символов");
                return 1;
            }
        }
    };
    for cert in &doomed {
        if let Err(e) = fs::remove_file(&cert.path) {
            eprintln!("не удалить {}: {e}", cert.path.display());
            return 1;
        }
    }
    // A named sandbox's databases are its own directory on disk: bring them in
    // line now. A data container's sit under its overlay, and the next launch
    // does it from inside — the (possibly empty) trust directory is what makes
    // that launch lay the layer down.
    match &target.home {
        Some(home) => {
            for warning in crate::trust::sync_home(&tools.certutil, &target.trust_dir(), home) {
                eprintln!("{warning}");
            }
            println!(
                "у контейнера {} убрано сертификатов: {}",
                target.shown,
                doomed.len()
            );
        }
        None => println!(
            "у контейнера {} убрано сертификатов: {} — из его баз NSS они уйдут при следующем запуске программы в нём",
            target.shown,
            doomed.len()
        ),
    }
    0
}

// --- LAUNCH BY ID -------------------------------------------------------------

/// `vpn-zone launch <id> [-- <arguments>]`: a launcher entry started through the
/// picker by its id, the way a click on it would start — for compositor key
/// bindings and scripts, which otherwise start the program itself, uncontained
/// (`docs/CONTAINERS.md` §5.1).
fn launch_entry(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(id) = required(
        args,
        0,
        "нужен id ярлыка: имя .desktop-файла без расширения",
    ) else {
        return 1;
    };
    let id = id.to_string_lossy().into_owned();
    let extra: &[OsString] = match args.iter().position(|a| a == "--") {
        Some(at) => &args[at + 1..],
        None if args.len() > 1 => {
            eprintln!("аргументы программы — после --: cellward launch {id} -- <аргументы>");
            return 1;
        }
        None => &[],
    };
    if id.starts_with(crate::desktop::PREFIX) {
        eprintln!("{id} — служебный ярлык cellward: его запускают как есть, не через пикер");
        return 1;
    }
    let dirs = crate::desktop::source_dirs(&tools.home);
    let Some((file, groups)) = crate::desktop::find_entry(&dirs, &tools.home, &tools.state, &id)
    else {
        eprintln!("ярлыка {id} нет ни в одном каталоге приложений");
        return 1;
    };
    let Some(entry) = crate::desktop::desktop_entry(&groups) else {
        return 1;
    };
    let (cmd, used) = crate::desktop::expand_exec(entry, &file, extra);
    if cmd.is_empty() {
        eprintln!("у ярлыка {id} нет Exec — запускать нечего");
        return 1;
    }
    if !extra.is_empty() && !used {
        eprintln!("ярлык {id} не принимает аргументов (в Exec нет %u, %f…) — они не переданы");
    }
    let mut argv: Vec<OsString> = vec![
        tools.picker.clone().into(),
        "--id".into(),
        crate::desktop::stable_key(&id).into(),
    ];
    if let Some(name) = entry.get("Name").filter(|n| !n.is_empty()) {
        argv.push("--label".into());
        argv.push(name.into());
    }
    argv.push("--".into());
    argv.extend(cmd);
    if std::env::var_os(launch::ENV_DRYRUN).is_some_and(|v| !v.is_empty()) {
        let words: Vec<String> = argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        println!("{}", words.join(" "));
        return 0;
    }
    let e = exec_command(&argv);
    eprintln!("не удалось запустить {}: {e}", tools.picker.display());
    EXIT_NOT_STARTED
}

// --- CONTAINERS --------------------------------------------------------------

/// `vpn-zone container …`: containers as identities (`docs/CONTAINERS.md`).
fn container(tools: &Tools, args: &[OsString]) -> u8 {
    let sub = args
        .first()
        .cloned()
        .unwrap_or_else(|| OsString::from("list"));
    let rest: &[OsString] = args.get(1..).unwrap_or(&[]);
    let json = rest.iter().any(|a| a == "--json");
    let yes = rest.iter().any(|a| a == "--yes");
    let words: Vec<String> = rest
        .iter()
        .filter(|a| *a != "--json" && *a != "--yes")
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    match sub.as_bytes() {
        b"list" => container_list(tools, json),
        b"create" => {
            let Some(name) = words.first() else {
                eprintln!("cellward container create <имя> [--home private|layer|main]");
                return 1;
            };
            let home = match (words.get(1).map(String::as_str), words.get(2)) {
                (None, _) => crate::container::Home::Private,
                (Some("--home"), Some(kind)) if words.len() == 3 => {
                    match crate::container::Home::parse(kind) {
                        Some(home) => home,
                        None => {
                            eprintln!("--home: private, layer или main");
                            return 1;
                        }
                    }
                }
                _ => {
                    eprintln!("cellward container create <имя> [--home private|layer|main]");
                    return 1;
                }
            };
            container_create(tools, OsStr::new(name), home)
        }
        b"rm" => {
            let Some(name) = words.first() else {
                eprintln!("cellward container rm <имя>");
                return 1;
            };
            container_remove(tools, OsStr::new(name))
        }
        b"show" => {
            let Some(selector) = words.first() else {
                eprintln!("нужно имя контейнера");
                return 1;
            };
            let Some(c) = crate::container::load(tools, selector) else {
                eprintln!("контейнера {selector} нет");
                return 1;
            };
            if json {
                println!(
                    "{{\"schema_version\":{},\"container\":{}}}",
                    crate::status::SCHEMA_VERSION,
                    crate::status::container(tools, &c)
                );
            } else {
                print_container(tools, &c);
            }
            0
        }
        b"set" => {
            let (Some(selector), Some(key), Some(value)) =
                (words.first(), words.get(1), words.get(2))
            else {
                eprintln!(
                    "cellward container set <контейнер> network <сеть|ask> | x11 on|off | \
                     home private|layer|main | color default (цвет сети)|<#rrggbb> | \
                     microphone|screencast default (как у зоны)|yes|no|ask | \
                     camera default (как у зоны)|on|off"
                );
                return 1;
            };
            if key == "camera" {
                let on = match value.as_str() {
                    "default" => None,
                    "on" => Some(true),
                    "off" => Some(false),
                    _ => {
                        eprintln!("camera: default (как у зоны), on или off");
                        return 1;
                    }
                };
                return match crate::container::set_camera(tools, selector, on) {
                    Ok(()) => {
                        match on {
                            Some(true) => println!(
                                "программам контейнера {selector} видны камеры хоста — снимать \
                                 они могут без вопроса (программам, запущенным после этого)"
                            ),
                            // The zone in Nix's camera list lets them all:
                            // Nix over a local word (`container::camera_for`).
                            Some(false) => println!(
                                "камеры хоста программам контейнера {selector} не видны \
                                 (запущенным после этого; если зона в programs.cellward.camera \
                                 в Nix — видны: Nix зоны важнее)"
                            ),
                            None => println!("у контейнера {selector} снова камера как у его зоны"),
                        }
                        0
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        1
                    }
                };
            }
            if key == "microphone" || key == "screencast" {
                // `default`: none of its own — the zone's; a word of its
                // own, said what it follows (the owner, 2026-09-26). `zone`,
                // its first name, is still taken.
                let setting = match value.as_str() {
                    "default" | "zone" => None,
                    word => match crate::microphone::Setting::parse(word) {
                        Some(setting) => Some(setting),
                        None => {
                            eprintln!("{key}: default (как у зоны), yes, no или ask");
                            return 1;
                        }
                    },
                };
                type Set =
                    fn(&Tools, &str, Option<crate::microphone::Setting>) -> Result<(), String>;
                let set: Set = if key == "microphone" {
                    crate::container::set_microphone
                } else {
                    crate::container::set_screencast
                };
                let said = if key == "microphone" {
                    "микрофон"
                } else {
                    "трансляция экрана"
                };
                return match set(tools, selector, setting) {
                    Ok(()) => {
                        match setting {
                            Some(s) => println!(
                                "{said} контейнера {selector}: {} (действует сразу; Nix зоны \
                                 важнее)",
                                s.as_str()
                            ),
                            None => {
                                println!("у контейнера {selector} снова {said} как у его зоны")
                            }
                        }
                        0
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        1
                    }
                };
            }
            if key == "color" {
                let color = (value != "default").then_some(value.as_str());
                return match crate::container::set_frame_color(tools, selector, color) {
                    Ok(()) if color.is_some() => {
                        println!(
                            "рамка окон контейнера {selector} теперь {value} (у окон, открытых после \
                             этого)"
                        );
                        0
                    }
                    Ok(()) => {
                        println!("у контейнера {selector} снова цвет рамки его сети");
                        0
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        1
                    }
                };
            }
            if key == "home" {
                let Some(home) = crate::container::Home::parse(value) else {
                    eprintln!("home: private, layer или main");
                    return 1;
                };
                return match crate::container::set_home(tools, selector, home) {
                    Ok(()) => {
                        println!(
                            "у контейнера {selector} теперь {}; данные прежнего вида отложены рядом \
                             (home.<вид>) и вернутся, если вид сменить обратно",
                            home.label()
                        );
                        0
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        1
                    }
                };
            }
            if key == "x11" {
                let on = match value.as_str() {
                    "on" => true,
                    "off" => false,
                    _ => {
                        eprintln!("x11: on или off");
                        return 1;
                    }
                };
                return match crate::container::set_x11(tools, selector, on) {
                    Ok(()) if on => {
                        println!(
                            "у контейнера {selector} в зонах свой X-сервер (xwayland-satellite); \
                             X-сервер хоста по-прежнему недоступен"
                        );
                        0
                    }
                    Ok(()) => {
                        println!("у контейнера {selector} в зонах X нет");
                        0
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        1
                    }
                };
            }
            if key != "network" {
                eprintln!("у контейнера меняются network, x11, home и color");
                return 1;
            }
            let Some(network) = crate::container::Network::parse(value) else {
                eprintln!("«{value}» — не имя сети");
                return 1;
            };
            if let crate::container::Network::Named(name) = &network {
                if !network_exists(tools, name) {
                    eprintln!("сети {name} нет — есть unconfined, offline и зоны из cellward list");
                    return 1;
                }
            }
            match crate::container::set_network(tools, selector, &network) {
                Ok(()) => {
                    match &network {
                        crate::container::Network::Ask => {
                            println!("контейнер {selector} больше не привязан: сеть спрашивается при запуске")
                        }
                        crate::container::Network::Named(name) => println!(
                            "контейнер {selector} привязан к сети {name}: его программы запускаются только в ней"
                        ),
                    }
                    0
                }
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        b"devices" => {
            let Some(selector) = words.first() else {
                eprintln!("cellward container devices <контейнер> [add|rm <устройство>]");
                return 1;
            };
            match (words.get(1).map(String::as_str), words.get(2)) {
                (Some(verb @ ("add" | "rm")), Some(word)) => {
                    match crate::container::set_device(tools, selector, word, verb == "add") {
                        Ok(()) if verb == "add" => {
                            println!(
                                "контейнеру {selector} выдано {word} — программам, запущенным \
                                 после этого"
                            );
                            0
                        }
                        Ok(()) => {
                            println!("у контейнера {selector} больше нет {word} — у запущенных после этого");
                            0
                        }
                        Err(e) => {
                            eprintln!("{e}");
                            1
                        }
                    }
                }
                (None, _) if crate::launch::in_zone() => {
                    eprintln!(
                        "cellward container devices: в зоне все такие устройства закрыты — \
                         запустите на хосте"
                    );
                    1
                }
                (None, _) => {
                    let Some(c) = crate::container::load(tools, selector) else {
                        eprintln!("контейнера {selector} нет");
                        return 1;
                    };
                    if c.devices.is_empty() {
                        println!("контейнеру {selector} устройства не выданы");
                        return 0;
                    }
                    let nodes = crate::devices::host_nodes();
                    for d in &c.devices {
                        let now: Vec<String> = crate::devices::Grant::parse(&d.value)
                            .map(|g| {
                                crate::devices::granted(&nodes, &[g])
                                    .iter()
                                    .map(|n| n.path.display().to_string())
                                    .collect()
                            })
                            .unwrap_or_default();
                        let now = if now.is_empty() {
                            "сейчас не подключено".to_owned()
                        } else {
                            now.join(" ")
                        };
                        println!("{} ({}): {now}", d.value, source_word(d.source));
                    }
                    0
                }
                _ => {
                    eprintln!("cellward container devices <контейнер> [add|rm <устройство>]");
                    1
                }
            }
        }
        b"links" => {
            let usage =
                "cellward container links <контейнер> [set <схема> <id ярлыка> | rm <схема>]";
            let Some(selector) = words.first() else {
                eprintln!("{usage}");
                return 1;
            };
            match (words.get(1).map(String::as_str), words.get(2), words.get(3)) {
                (Some("set"), Some(scheme), Some(id)) => {
                    match crate::container::set_link(tools, selector, scheme, Some(id)) {
                        Ok(()) => {
                            println!(
                                "ссылки {scheme}: из контейнера {selector} открываются в {id} — \
                                 без выбора программы (окно сети и контейнера остаётся)"
                            );
                            0
                        }
                        Err(e) => {
                            eprintln!("{e}");
                            1
                        }
                    }
                }
                (Some("rm"), Some(scheme), None) => {
                    match crate::container::set_link(tools, selector, scheme, None) {
                        Ok(()) => {
                            println!("ссылки {scheme}: из контейнера {selector} — снова с выбором программы");
                            0
                        }
                        Err(e) => {
                            eprintln!("{e}");
                            1
                        }
                    }
                }
                (None, _, _) => {
                    let Some(c) = crate::container::load(tools, selector) else {
                        eprintln!("контейнера {selector} нет");
                        return 1;
                    };
                    if c.links.is_empty() {
                        println!("у контейнера {selector} правил для ссылок нет: программу выбирают каждый раз");
                        return 0;
                    }
                    for l in &c.links {
                        println!("{}: → {} ({})", l.value.0, l.value.1, source_word(l.source));
                    }
                    0
                }
                _ => {
                    eprintln!("{usage}");
                    1
                }
            }
        }
        b"assign" => {
            let (Some(app), Some(selector)) = (words.first(), words.get(1)) else {
                eprintln!("cellward container assign <программа> <контейнер>");
                return 1;
            };
            let Some(target) = crate::container::load(tools, selector) else {
                eprintln!("контейнера {selector} нет");
                return 1;
            };
            let selector = &target.name;
            if let Some(owner) = crate::container::declared_owner(tools, app) {
                if &owner != selector {
                    eprintln!("программа {app} назначена контейнеру {owner} в Nix — меняется там");
                    return 1;
                }
            }
            let dir = tools.state.join(".pinnedprofile");
            let path = dir.join(crate::desktop::stable_key(app));
            if let Err(e) = fs::create_dir_all(&dir).and_then(|()| fs::write(&path, selector)) {
                eprintln!("не записать {}: {e}", path.display());
                return 1;
            }
            println!("программа {app} назначена контейнеру {selector}");
            0
        }
        b"unassign" => {
            let Some(app) = words.first() else {
                eprintln!("cellward container unassign <программа>");
                return 1;
            };
            let _ = fs::remove_file(
                tools
                    .state
                    .join(".pinnedprofile")
                    .join(crate::desktop::stable_key(app)),
            );
            match crate::container::declared_owner(tools, app) {
                Some(owner) => println!(
                    "локальное назначение {app} снято, но в Nix программа назначена контейнеру {owner}"
                ),
                None => println!("программа {app} больше не назначена контейнеру"),
            }
            0
        }
        b"expire" => crate::grants::expire(tools),
        b"grant" | b"revoke" => {
            let grant = sub == "grant";
            const USAGE: &str =
                "cellward container grant <контейнер> <каталог> [--for 30m|2h|7d]\n\
                 cellward container revoke <контейнер> <каталог>";
            let (Some(selector), Some(path)) = (words.first(), words.get(1)) else {
                eprintln!("{USAGE}");
                return 1;
            };
            let term = match (words.get(2).map(String::as_str), words.get(3)) {
                (None, _) => None,
                (Some("--for"), Some(term)) if grant && words.len() == 4 => {
                    match crate::grants::parse_term(term) {
                        Some(secs) => Some(secs),
                        None => {
                            eprintln!("срок — число и единица: 30s, 15m, 2h, 7d (не больше 366d)");
                            return 1;
                        }
                    }
                }
                _ => {
                    eprintln!("{USAGE}");
                    return 1;
                }
            };
            let until = term.map(|secs| crate::container::now() + secs);
            match crate::container::set_path(tools, selector, path, grant, until) {
                Ok(path) if grant => {
                    let shown = path.to_string_lossy();
                    let until_text = until.map(crate::journal::utc).unwrap_or_default();
                    if let Err(e) = crate::journal::append(
                        &tools.state,
                        "grant",
                        &[
                            ("container", selector.as_str()),
                            ("path", &*shown),
                            ("until", until_text.as_str()),
                        ],
                    ) {
                        eprintln!("журнал: {e}");
                    }
                    let term_text = match term {
                        None => String::new(),
                        Some(secs) => {
                            let timer = if crate::grants::schedule_expiry(tools, secs) {
                                ""
                            } else {
                                " (таймер не поставить: уже запущенные программы сохранят \
                                 доступ до `cellward container expire`, новые его не получат)"
                            };
                            format!(
                                " до {} UTC{timer}",
                                until_text.replace(['T', 'Z'], " ").trim_end()
                            )
                        }
                    };
                    println!(
                        "{shown} выдан контейнеру {selector}{term_text}: его программы видят и \
                         меняют там всё, и то, что они туда положат, увидят программы вне контейнера"
                    );
                    0
                }
                Ok(path) => {
                    let shown = path.to_string_lossy();
                    let (detached, failed) = crate::grants::detach_live(tools, selector, &path);
                    if let Err(e) = crate::journal::append(
                        &tools.state,
                        "revoke",
                        &[
                            ("container", selector.as_str()),
                            ("path", &*shown),
                            ("detached", detached.to_string().as_str()),
                            ("failed", failed.join("; ").as_str()),
                        ],
                    ) {
                        eprintln!("журнал: {e}");
                    }
                    println!("{shown} больше не выдан контейнеру {selector}");
                    if detached > 0 {
                        println!("  у запущенных программ каталог отмонтирован ({detached})");
                    }
                    if failed.is_empty() {
                        0
                    } else {
                        eprintln!(
                            "  у части запущенных программ отмонтировать не удалось ({}) — \
                             завершите их или оборвите зону: cellward kill",
                            failed.join("; ")
                        );
                        1
                    }
                }
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        b"merge" => {
            let (Some(from), Some(into)) = (words.first(), words.get(1)) else {
                eprintln!("cellward container merge <из контейнера> <в контейнер> [--yes]");
                return 1;
            };
            match crate::container::merge(tools, from, into, yes) {
                Ok(report) => {
                    print_merge(tools, from, into, &report);
                    0
                }
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        _ => {
            eprintln!(
                "cellward container list|show|create|rm|set|assign|unassign|grant|revoke|merge …"
            );
            1
        }
    }
}

fn print_merge(tools: &Tools, from: &str, into: &str, report: &crate::container::MergeReport) {
    println!(
        "{from} объединён в {into}: перенесено {}, программ переназначено {}",
        report.copied, report.apps
    );
    if report.conflicts > 0 {
        println!(
            "  {} совпавших путей {into} оставил себе; версии из {from} лежат рядом:",
            report.conflicts
        );
        for dir in &report.conflicts_dirs {
            println!("    {}", dir.display());
        }
    }
    if report.skipped > 0 {
        println!(
            "  пропущено особых файлов (сокеты, каналы, пометки удаления слоя): {}",
            report.skipped
        );
    }
    if !report.new_certificates.is_empty() {
        eprintln!(
            "⚠ {into} теперь доверяет корневым сертификатам из {from} — их владельцы могут читать \
             TLS-трафик программ {into}:"
        );
        let dir = crate::container::load(tools, into).map(|c| c.trust_dir());
        for sha in &report.new_certificates {
            let subject = dir
                .as_ref()
                .and_then(|d| certificate_info(tools, &d.join(format!("{sha}.pem")), "PEM").ok())
                .map(|info| info.subject)
                .unwrap_or_default();
            eprintln!("    {} {subject}", &sha[..16.min(sha.len())]);
        }
        eprintln!("  убрать: cellward trust rm {into} <начало sha256>");
    }
    let remove = format!(
        "cellward container rm {}",
        crate::container::canonical(tools, from).unwrap_or_else(|| from.to_owned())
    );
    println!("  {from} остался (без программ); удалить, когда проверишь результат: {remove}");
}

/// Is there a network by this name: `unconfined` (or `direct`), `offline`, or
/// a zone?
fn network_exists(tools: &Tools, name: &str) -> bool {
    crate::container::network_exists(tools, name)
}

fn source_word(source: crate::container::Source) -> &'static str {
    match source {
        crate::container::Source::Nix => "задано в Nix",
        crate::container::Source::Local => "локально",
        crate::container::Source::Default => "по умолчанию",
    }
}

fn print_container(tools: &Tools, c: &crate::container::Container) {
    let home = format!("{} ({})", c.home.label(), source_word(c.home_source));
    let network = match &c.network.value {
        crate::container::Network::Ask => "спрашивать при запуске".to_owned(),
        crate::container::Network::Named(name) => name.clone(),
    };
    println!("{}", c.selector());
    println!("  дом:       {home}");
    println!("  сеть:      {network} ({})", source_word(c.network.source));
    if let Some(m) = &c.microphone {
        println!(
            "  микрофон:  {} ({})",
            m.value.as_str(),
            source_word(m.source)
        );
    }
    if let Some(m) = &c.camera {
        let on = if m.value { "on" } else { "off" };
        println!("  камера:    {on} ({})", source_word(m.source));
    }
    if let Some(m) = &c.screencast {
        println!(
            "  экран:     {} ({})",
            m.value.as_str(),
            source_word(m.source)
        );
    }
    if c.apps.is_empty() {
        println!("  программы: нет");
    } else {
        let apps: Vec<String> = c
            .apps
            .iter()
            .map(|a| format!("{} ({})", a.value, source_word(a.source)))
            .collect();
        println!("  программы: {}", apps.join(", "));
    }
    if !c.links.is_empty() {
        let links: Vec<String> = c
            .links
            .iter()
            .map(|l| format!("{}: → {} ({})", l.value.0, l.value.1, source_word(l.source)))
            .collect();
        println!("  ссылки:    {}", links.join(", "));
    }
    let certs = crate::trust::stored(&c.trust_dir()).len();
    if certs > 0 {
        println!(
            "  ⚠ дополнительных корневых сертификатов: {certs} (cellward trust list {})",
            c.selector()
        );
    }
    if let Some(busy) = crate::container::running_network(tools, c) {
        println!("  работает:  в сети {busy}");
    }
}

/// `cellward devices [--json]`: what is plugged in that a container can be
/// given (`crate::devices`), each device once — by the name a grant gives it
/// by (`usb:<vendor>:<product>[:<serial>]`), the sets it falls into, and its
/// nodes.
fn devices_list(args: &[OsString]) -> u8 {
    // In a zone every such node is covered: what it would list is the
    // zone's view, not the machine's.
    if crate::launch::in_zone() {
        eprintln!("cellward devices: в зоне все такие устройства закрыты — запустите на хосте");
        return 1;
    }
    let json = args.iter().any(|a| a == "--json");
    let nodes = crate::devices::host_nodes();
    let devices = crate::devices::connected(&nodes);
    if json {
        let items: Vec<String> = devices
            .iter()
            .map(|d| {
                let list = |v: &[String]| {
                    let parts: Vec<String> = v.iter().map(|x| crate::status::string(x)).collect();
                    format!("[{}]", parts.join(","))
                };
                format!(
                    "{{\"id\":{},\"name\":{},\"sets\":{},\"nodes\":{}}}",
                    d.id.as_deref()
                        .map_or("null".to_owned(), crate::status::string),
                    crate::status::string(&d.name),
                    list(&d.sets),
                    list(&d.nodes)
                )
            })
            .collect();
        println!(
            "{{\"schema_version\":{},\"devices\":[{}]}}",
            crate::status::SCHEMA_VERSION,
            items.join(",")
        );
        return 0;
    }
    if devices.is_empty() {
        println!("устройств, которые можно выдать контейнеру, не подключено");
        return 0;
    }
    for d in &devices {
        let sets = if d.sets.is_empty() {
            String::new()
        } else {
            format!(" [{}]", d.sets.join(", "))
        };
        println!(
            "{}{sets}\n  {}\n  {}",
            d.name,
            d.id.as_deref().unwrap_or("(без USB-имени)"),
            d.nodes.join(" ")
        );
    }
    0
}

fn container_list(tools: &Tools, json: bool) -> u8 {
    if json {
        println!(
            "{{\"schema_version\":{},\"containers\":{}}}",
            crate::status::SCHEMA_VERSION,
            crate::status::containers(tools)
        );
        return 0;
    }
    let all = crate::container::load_all(tools);
    if all.is_empty() {
        println!(
            "контейнеров нет. Создать: cellward container create <имя> [--home private|layer|main]"
        );
        return 0;
    }
    for c in &all {
        print_container(tools, c);
    }
    0
}

// --- SETTINGS ----------------------------------------------------------------

fn wayland_sandbox(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(value) = required(args, 0, "on или off") else {
        return 1;
    };
    if value != "on" && value != "off" {
        eprintln!("только on или off");
        return 1;
    }
    if let Err(e) = write_setting(tools, "wayland-sandbox", value) {
        eprintln!("не записать {e}");
        return 1;
    }
    if value == "on" {
        println!(
            "программы запускаются без доступа к захвату экрана, буферу в фоне и эмуляции ввода"
        );
    } else {
        println!("ограничение снято: программы снова получают полный набор протоколов композитора");
    }
    0
}

/// `vpn-zone wayland-proxy on|off`: the Wayland proxy between programs and
/// the compositor (`crate::wl_proxy`). A program it breaks can be left out
/// alone, in `~/.config/vpn-zones/wayland-no-proxy`.
fn wayland_proxy(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(value) = required(args, 0, "on или off") else {
        return 1;
    };
    if value != "on" && value != "off" {
        eprintln!("только on или off");
        return 1;
    }
    if let Err(e) = write_setting(tools, "wayland-proxy", value) {
        eprintln!("не записать {e}");
        return 1;
    }
    if value == "on" {
        println!("между программами и композитором — посредник: только свои окна, без скрытых протоколов");
    } else {
        println!(
            "посредник выключен: композитор слушает для программ сам, как раньше (ограничения \
             security-context остаются); для одной программы — строка в ~/.config/vpn-zones/wayland-no-proxy"
        );
    }
    0
}

/// `vpn-zone frame show|hide`, `vpn-zone frame width <px>` (4),
/// `vpn-zone frame title always|hover|off` (always),
/// `vpn-zone frame color <zone> default|<#rrggbb>` (`default`: from the
/// zone's name): the frame of the zone's
/// colour the Wayland proxy draws around its programs' windows, and its title
/// strip (`crate::frame`, `docs/WINDOW-FRAME.md` §0а). Each takes effect for
/// windows opened after it: the colour, the width and the title when a
/// program is launched, the switch when it connects.
fn frame(tools: &Tools, args: &[OsString]) -> u8 {
    use crate::container::Source;
    use crate::frame::{
        Rgb, TitleMode, COLOR_FILE, MAX_WIDTH, SWITCH_SETTING, TITLE_SETTING, WIDTH_SETTING,
    };
    const USAGE: &str = "cellward frame show|hide\ncellward frame width <1–32> (по умолчанию 4)\n\
                         cellward frame title always (по умолчанию)|hover|off\n\
                         cellward frame color <зона> default (из имени зоны)|<#rrggbb>";
    let title_words = |mode: TitleMode| match mode {
        TitleMode::Always => "всегда (always)",
        TitleMode::Hover => "при наведении (hover)",
        TitleMode::Off => "нет (off)",
    };
    let from = |source: Source, nix: &str| match source {
        Source::Local => String::new(),
        Source::Nix => format!(" (задано в Nix: {nix})"),
        Source::Default => " (умолчание)".to_owned(),
    };
    match args.first().and_then(|a| a.to_str()) {
        None => {
            let (width, source) = crate::frame::width(&tools.config);
            let shown = if crate::frame::hidden(&tools.config) {
                "спрятаны (cellward frame show — вернуть)"
            } else {
                "рисуются"
            };
            let (title, title_source) = crate::frame::title_mode(&tools.config);
            println!(
                "рамки зон: {shown}; толщина {width}{}; заголовок: {}{}",
                from(source, "programs.cellward.frame.width"),
                title_words(title),
                from(title_source, "programs.cellward.frame.title")
            );
            0
        }
        Some("title") => {
            let Some(value) = args.get(1).and_then(|v| v.to_str()) else {
                eprintln!("{USAGE}");
                return 1;
            };
            let written = if value == "default" {
                if tools.config.join(DECLARED_DIR).join(TITLE_SETTING).exists() {
                    Err(format!(
                        "«{TITLE_SETTING}» задано в Nix (programs.cellward) и меняется там"
                    ))
                } else {
                    match fs::remove_file(tools.config.join(TITLE_SETTING)) {
                        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
                        _ => Ok(()),
                    }
                }
            } else {
                match TitleMode::parse(value) {
                    Some(mode) => write_setting(tools, TITLE_SETTING, OsStr::new(mode.as_str())),
                    None => {
                        eprintln!("заголовок — always, hover, off или default");
                        return 1;
                    }
                }
            };
            if let Err(e) = written {
                eprintln!("не записать {e}");
                return 1;
            }
            let (title, source) = crate::frame::title_mode(&tools.config);
            println!(
                "заголовок рамки: {}{} — у программ, запущенных после этого",
                title_words(title),
                from(source, "programs.cellward.frame.title")
            );
            0
        }
        Some(verb @ ("show" | "hide")) => {
            let value = if verb == "hide" { "hidden" } else { "shown" };
            if let Err(e) = write_setting(tools, SWITCH_SETTING, OsStr::new(value)) {
                eprintln!("не записать {e}");
                return 1;
            }
            if verb == "hide" {
                println!(
                    "рамки зон спрятаны: окна, открытые после этого, — без рамки (уже открытые \
                     остаются с ней). Вернуть: cellward frame show"
                );
            } else {
                println!("рамки зон снова рисуются — у окон, открытых после этого");
            }
            0
        }
        Some("width") => {
            let Some(value) = args.get(1).and_then(|v| v.to_str()) else {
                eprintln!("{USAGE}");
                return 1;
            };
            let written = if value == "default" {
                if tools.config.join(DECLARED_DIR).join(WIDTH_SETTING).exists() {
                    Err(format!(
                        "«{WIDTH_SETTING}» задано в Nix (programs.cellward) и меняется там"
                    ))
                } else {
                    match fs::remove_file(tools.config.join(WIDTH_SETTING)) {
                        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
                        _ => Ok(()),
                    }
                }
            } else {
                match value.parse::<i32>() {
                    Ok(w) if (1..=MAX_WIDTH).contains(&w) => {
                        write_setting(tools, WIDTH_SETTING, OsStr::new(&w.to_string()))
                    }
                    _ => {
                        eprintln!("толщина — целое от 1 до {MAX_WIDTH} или default");
                        return 1;
                    }
                }
            };
            if let Err(e) = written {
                eprintln!("не записать {e}");
                return 1;
            }
            let (width, source) = crate::frame::width(&tools.config);
            println!(
                "толщина рамки: {width}{} — у программ, запущенных после этого",
                from(source, "programs.cellward.frame.width")
            );
            0
        }
        Some("color") => {
            let (Some(name), Some(value)) = (args.get(1), args.get(2).and_then(|v| v.to_str()))
            else {
                eprintln!("{USAGE}");
                return 1;
            };
            let dir = tools.state.join(name);
            if !safe_zone_name(name) || !dir.is_dir() {
                eprintln!("зоны {} нет", name.to_string_lossy());
                return 1;
            }
            let name = name.to_string_lossy();
            let file = dir.join(COLOR_FILE);
            let written = if value == "default" {
                match fs::remove_file(&file) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                    _ => Ok(()),
                }
            } else {
                let Some(color) = Rgb::parse(value) else {
                    eprintln!("цвет — #rrggbb (например, #3366ff) или default");
                    return 1;
                };
                fs::write(&file, color.hex())
            };
            if let Err(e) = written {
                eprintln!("не записать {}: {e}", file.display());
                return 1;
            }
            let (color, source) = crate::frame::zone_color(&tools.state, &tools.config, &name);
            println!(
                "зона {name}: рамка {}{} — у программ, запущенных после этого",
                color.hex(),
                from(source, "programs.cellward.frame.colors")
            );
            0
        }
        Some(_) => {
            eprintln!("{USAGE}");
            1
        }
    }
}

fn mode(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(value) = required(args, 0, "режим: picker | per-zone | both | off") else {
        return 1;
    };
    if !matches!(value.as_bytes(), b"picker" | b"per-zone" | b"both" | b"off") {
        eprintln!("неизвестный режим: {}", value.to_string_lossy());
        return 1;
    }
    if let Err(e) = write_setting(tools, "mode", value) {
        eprintln!("не записать {e}");
        return 1;
    }
    if let Some(note) = crate::desktop::Mode::parse(&value.to_string_lossy()).deprecation() {
        eprintln!("{note}");
    }
    run_sync(tools)
}

fn default_profile(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(value) = required(args, 0, "ask | main | own | <имя контейнера>") else {
        return 1;
    };
    // A container by its one name, whatever its home.
    let value = if matches!(value.as_bytes(), b"ask" | b"main" | b"own") {
        value.clone()
    } else {
        match crate::container::load(tools, &value.to_string_lossy()) {
            Some(c) => OsString::from(c.name),
            None => {
                eprintln!("контейнера {} нет", value.to_string_lossy());
                return 1;
            }
        }
    };
    let value = &value;
    if let Err(e) = write_setting(tools, "default-profile", value) {
        eprintln!("не записать {e}");
        return 1;
    }
    println!("контейнер по умолчанию: {}", value.to_string_lossy());
    0
}

fn default_network(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(value) = required(args, 0, "вариант: offline | unconfined | <имя зоны>")
    else {
        return 1;
    };
    // The old name is accepted and never written.
    let value = if value == launch::UNCONFINED_ALIAS {
        OsStr::new(launch::UNCONFINED)
    } else {
        value.as_os_str()
    };
    // A zone that is not there would be a row the picker does not offer.
    if value != "offline"
        && value != launch::UNCONFINED
        && !tools.state.join(value).join("config.conf").is_file()
    {
        eprintln!("зоны {} нет", value.to_string_lossy());
        return 1;
    }
    if let Err(e) = write_setting(tools, "default", value) {
        eprintln!("не записать {e}");
        return 1;
    }
    println!("по умолчанию в пикере: {}", value.to_string_lossy());
    0
}

// --- PINS --------------------------------------------------------------------

/// `pins`: which program runs in which container without a question, and
/// the network that container is bound to — a network is a container's, not
/// a program's (`docs/PERMISSIONS.md` §11.8).
fn pins(tools: &Tools) -> u8 {
    let mut found = false;
    for file in visible_entries(&tools.state.join(".pinnedprofile")) {
        if !file.is_file() {
            continue;
        }
        let key = file.file_name().unwrap_or_default();
        // The label, not the key: the key is a shortcut id
        // (com.ayugram.desktop) and tells the user nothing.
        // (`docs/GOTCHAS.md` §10)
        let label = read_setting(&tools.state.join(".labels").join(key))
            .unwrap_or_else(|| key.to_string_lossy().into_owned());
        let value = read_setting(&file).unwrap_or_default();
        let shown = match value.as_str() {
            "__main__" | "" => "основной, сеть спрашивается при запуске".to_owned(),
            "__fs__" => "разовая песочница, сеть спрашивается при запуске".to_owned(),
            selector => match crate::container::load(tools, selector) {
                Some(c) => match &c.network.value {
                    crate::container::Network::Named(n) => format!("{} (сеть {n})", c.name),
                    crate::container::Network::Ask => {
                        format!("{} (сеть не выбрана — спросится)", c.name)
                    }
                },
                None => format!("{selector} (его нет)"),
            },
        };
        println!("{label}: контейнер → {shown}");
        found = true;
    }
    if !found {
        println!("закреплённых программ нет — пикер спрашивает каждый раз");
    }
    0
}

fn forget(tools: &Tools, args: &[OsString]) -> u8 {
    // `.pinned` is where a program's network was pinned before it became its
    // container's: a stale one goes too.
    const SUBDIRS: [&str; 4] = [".pinned", ".last", ".lastprofile", ".pinnedprofile"];
    let Some(what) = required(args, 0, "имя программы или --all") else {
        return 1;
    };
    if what == "--all" {
        for sub in SUBDIRS {
            let _ = crate::sys::remove_tree(&tools.state.join(sub));
        }
        println!("сброшено для всех программ");
    } else {
        for sub in SUBDIRS {
            let _ = fs::remove_file(tools.state.join(sub).join(what));
        }
        println!("сброшено для {}", what.to_string_lossy());
    }
    0
}

// --- SHORTCUTS ---------------------------------------------------------------

/// The four arguments the `.desktop` generator takes. The runner and the picker
/// are PROFILE paths, not store ones: that is what breaks the dependency cycle
/// (`vpn-zone` calls sync, sync writes `vpn-zone` into the shortcuts) and keeps
/// the shortcuts from going stale after every rebuild. (`docs/GOTCHAS.md` §10)
fn sync_argv(tools: &Tools) -> Vec<OsString> {
    vec![
        tools.core.clone().into(),
        "sync".into(),
        tools.state.clone().into(),
        tools.home.clone().into(),
        tools.runner.clone().into(),
        tools.picker.clone().into(),
        tools.systemctl.clone().into(),
    ]
}

/// `vpn-zone sync` — become the generator, as the shell version's `exec` did.
fn exec_sync(tools: &Tools) -> u8 {
    let argv = sync_argv(tools);
    let e = exec_command(&argv);
    eprintln!("не удалось запустить {}: {e}", tools.core.display());
    EXIT_NOT_STARTED
}

/// The same, as a child: `mode` and `rm` have something to say afterwards.
fn run_sync(tools: &Tools) -> u8 {
    let argv = sync_argv(tools);
    match Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::null())
        .status()
    {
        Ok(status) => status.code().map_or(1, |c| c as u8),
        Err(e) => {
            eprintln!("не запустить {}: {e}", tools.core.display());
            EXIT_NOT_STARTED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An old holder is taken only in its own zone's unit.
    #[test]
    fn an_old_holder_is_known_by_its_zones_unit() {
        let own = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/\
                   app-vpn\\x2dzone.slice/vpn-zone@nix-zone-desktop.service\n";
        assert!(in_zone_unit(own, "nix-zone-desktop"));
        assert!(!in_zone_unit(own, "nix-zone"));
        assert!(!in_zone_unit(own, "desktop"));
        let below = "0::/user.slice/user@1000.service/app.slice/vpn-zone@nl.service/sub\n";
        assert!(in_zone_unit(below, "nl"));
        // Another unit, a terminal of the user's: not the zone.
        let other = "0::/user.slice/user@1000.service/app.slice/app-Alacritty@x.service\n";
        assert!(!in_zone_unit(other, "nl"));
        // A unit named after the zone by someone else is no zone of ours.
        let lookalike = "0::/user.slice/user@1000.service/app.slice/evil-vpn-zone@nl.service\n";
        assert!(!in_zone_unit(lookalike, "nl"));
        // cgroup v1 lines are not read.
        assert!(!in_zone_unit("1:name=systemd:/vpn-zone@nl.service\n", "nl"));
    }

    /// A handshake line is "alive" unless watch found THIS run of the tunnel
    /// dead; a verdict from before the zone's start is not read.
    #[test]
    fn a_tunnel_watch_found_dead_is_not_alive() {
        let state = std::env::temp_dir().join(format!("vz-alive-{}", std::process::id()));
        let dir = state.join("nl");
        fs::create_dir_all(state.join(crate::watch::WATCH_DIR)).unwrap();
        fs::create_dir_all(&dir).unwrap();
        let mirror = "peer: p\n  latest handshake: 3 hours ago\n";
        let memory = state.join(crate::watch::WATCH_DIR).join("nl");
        // A verdict from before this run...
        fs::write(&memory, "10 10 dead\n").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(dir.join("zone.pid"), "1\n").unwrap();
        assert!(alive_line(&dir, mirror).is_some());
        // ...and one about it.
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(&memory, "10 10 dead\n").unwrap();
        assert!(alive_line(&dir, mirror).is_none());
        fs::write(&memory, "10 10 alive\n").unwrap();
        assert!(alive_line(&dir, mirror).is_some());
        let _ = fs::remove_dir_all(&state);
    }

    /// `zone.pid` outlives a stopped zone; with the holder's start time beside
    /// it, a number that went to another process is not the zone.
    #[test]
    fn a_zone_is_up_only_while_its_own_holder_lives() {
        let state = std::env::temp_dir().join(format!("vz-zone-pid-{}", std::process::id()));
        let dir = state.join("nl");
        fs::create_dir_all(&dir).unwrap();
        let me = std::process::id() as i32;
        fs::write(dir.join("zone.pid"), format!("{me}\n")).unwrap();
        // No note of the holder's start, and the test runs in no zone's
        // unit: not a zone, and no note is written for it.
        assert_eq!(zone_pid(&state, OsStr::new("nl")), None);
        assert!(!dir.join("zone.start").exists());
        let stamp = crate::sys::process_stamp(me).unwrap();
        fs::write(dir.join("zone.start"), format!("{stamp}\n")).unwrap();
        assert_eq!(zone_pid(&state, OsStr::new("nl")), Some(me));
        fs::write(dir.join("zone.start"), "1\n").unwrap();
        assert_eq!(zone_pid(&state, OsStr::new("nl")), None);
        let _ = fs::remove_dir_all(&state);
    }

    #[test]
    fn carriage_returns_go_only_from_the_ends_of_lines() {
        assert_eq!(strip_cr(b"a\r\nb\r\n"), b"a\nb\n".to_vec());
        // Only ONE, and only at the end — a `\r` in the middle of a value is
        // somebody's data, not a line ending.
        assert_eq!(strip_cr(b"a\r\r\n"), b"a\r\n".to_vec());
        assert_eq!(strip_cr(b"a\rb\n"), b"a\rb\n".to_vec());
        // A file without a trailing newline keeps not having one.
        assert_eq!(strip_cr(b"a\r\nb"), b"a\nb".to_vec());
        assert_eq!(strip_cr(b""), b"".to_vec());
    }

    #[test]
    fn liveness_is_a_handshake_or_the_word_connected() {
        // A WireGuard zone, unchanged.
        let wg = "interface: awg0\n\npeer: p\n  latest handshake: now\n";
        assert_eq!(liveness_line(wg).as_deref(), Some("latest handshake: now"));

        // An OpenConnect one, whose mirror has no handshake in it at all.
        let oc =
            "interface: awg0\n  backend: openconnect\n  connected: yes\n  address: 10.5.0.7/32\n";
        assert_eq!(liveness_line(oc).as_deref(), Some("connected: yes"));

        // And the two dead shapes.
        let gone = "interface: awg0\n  backend: openconnect\n  disconnected: the tunnel interface is gone\n";
        assert_eq!(liveness_line(gone), None);
        assert_eq!(liveness_line("interface: awg0\n\npeer: p\n"), None);
        assert_eq!(liveness_line(""), None);
    }

    #[test]
    fn a_handshake_is_looked_for_inside_a_peer_block() {
        let mirror = "\
interface: awg0
  public key: k
  listening port: 51820

peer: p
  endpoint: 10.0.0.1:51820
  latest handshake: 1 minute, 5 seconds ago
  transfer: 1 KiB received
";
        assert_eq!(
            handshake_line(mirror).as_deref(),
            Some("latest handshake: 1 minute, 5 seconds ago")
        );
        // A peer that has never answered has no such line at all.
        assert_eq!(
            handshake_line("interface: awg0\n\npeer: p\n  transfer: 0 B\n"),
            None
        );
        assert_eq!(handshake_line(""), None);
        // Case-insensitive, as `grep -i` was.
        assert!(handshake_line("peer: p\n  Latest Handshake: now\n").is_some());
        // Too far from any peer line: the twenty-line window of `grep -A20`.
        let far = format!("peer: p\n{}  latest handshake: now\n", "  x\n".repeat(25));
        assert_eq!(handshake_line(&far), None);
    }

    #[test]
    fn a_stray_pasta_is_recognised_by_the_namespace_in_its_command_line() {
        assert_eq!(
            netns_pid(b"pasta\0--netns\0/proc/12345/ns/net\0-I\0hostif\0"),
            Some(12345)
        );
        // The first one wins, as `head -1` did.
        assert_eq!(netns_pid(b"pasta /proc/7/ns/net /proc/9/ns/net"), Some(7));
        for junk in [
            &b"pasta"[..],
            b"pasta --netns /proc//ns/net",
            b"pasta /proc/12/ns/mnt",
            b"pasta /proc/12x/ns/net",
            b"",
        ] {
            assert!(netns_pid(junk).is_none(), "{junk:?} приняли за netns");
        }
    }

    #[test]
    fn names_that_would_break_a_dialog_or_a_path_are_refused() {
        for good in ["work", "личное", "a.b", "a_b", "a-b"] {
            assert!(
                crate::container::valid_name(good),
                "«{good}» должно быть можно"
            );
        }
        for bad in ["", "a/b", "a b", "-a", ".a", "/"] {
            assert!(
                !crate::container::valid_name(bad),
                "«{bad}» должно быть нельзя"
            );
        }
        // Zone names end up in unit names: stricter still.
        for good in ["nl", "nl-2", "a_b"] {
            assert!(safe_zone_name(OsStr::new(good)));
        }
        for bad in ["", "nl 2", "nl.2", "личное", "nl/2"] {
            assert!(
                !safe_zone_name(OsStr::new(bad)),
                "«{bad}» должно быть нельзя"
            );
        }
    }

    #[test]
    fn sizes_read_like_du() {
        assert_eq!(human_size(0), "0");
        assert_eq!(human_size(512), "512");
        assert_eq!(human_size(4096), "4.0K");
        assert_eq!(human_size(1536), "1.5K");
        // Rounded up, never down: a byte over is a tenth more.
        assert_eq!(human_size(1024 * 1024 + 1), "1.1M");
        assert_eq!(human_size(10 * 1024), "10K");
        assert_eq!(human_size(11 * 1024 + 1), "12K");
        assert_eq!(human_size(1024 * 1024), "1.0M");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0G");
    }

    #[test]
    fn the_help_text_lists_every_verb_the_dispatcher_knows() {
        for verb in [
            "add",
            "up",
            "down",
            "list",
            "status",
            "run",
            "rm",
            "sync",
            "mode",
            "default",
            "gc",
            "perms",
            "sandbox",
            "profile",
            "default-profile",
            "pins",
            "forget",
            "wayland-sandbox",
            "check",
            "lock",
            "trust",
            "container",
        ] {
            assert!(
                USAGE.contains(&format!("cellward {verb}")),
                "в справке нет «{verb}»"
            );
        }
    }
}
