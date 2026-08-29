//! `vpn-zone` — the user-facing command line.
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

const USAGE: &str = "vpn-zone — сетевые зоны с VPN, без root\n\n  vpn-zone add <имя> <файл.conf>   создать зону из конфига AmneziaWG/WireGuard\n  vpn-zone up <имя>                поднять\n  vpn-zone down <имя>              опустить\n  vpn-zone list                    список зон и их состояние\n  vpn-zone status <имя>            подробности (адрес, handshake)\n  vpn-zone run <имя> -- <кмд>      запустить программу внутри зоны\n  vpn-zone rm <имя>                удалить зону вместе с ярлыками\n  vpn-zone sync                    пересобрать .desktop-ярлыки\n  vpn-zone mode <режим>            как ярлыки работают:\n                                     picker   — один ярлык, спрашивает сеть\n                                                при запуске (по умолчанию)\n                                     per-zone — отдельный ярлык на каждую зону\n                                     both     — и то, и другое\n                                     off      — не трогать ярлыки вовсе\n  vpn-zone default <вариант>       что предлагать в пикере для незнакомой\n                                   программы: offline (по умолчанию), direct\n                                   или имя зоны\n  vpn-zone gc                      убрать зависшие держатели зон, осиротевшую\n                                   обвязку и мёртвые записи\n  vpn-zone perms list|reset <прог.|--all>\n                                   какие доступы к файлам выданы программам\n                                   в песочнице; reset — спросить заново\n  vpn-zone sandbox create|list|rm <имя>\n                                   именованные песочницы: свой дом, общий для\n                                   всех программ, запущенных в этой песочнице\n  vpn-zone run <имя> --sandbox <п> -- <кмд>\n                                   запустить в именованной песочнице\n  vpn-zone run <имя> --fs-sandbox -- <кмд>\n                                   запустить в песочнице файловой системы:\n                                   вместо $HOME — пустой каталог, наружу\n                                   видно только разрешённое, остальное — через\n                                   диалог выбора файла (порталы)\n  vpn-zone run <имя> --tmp-profile -- <кмд>\n                                   запустить в одноразовом контейнере: слой\n                                   создаётся в /tmp и стирается по выходе\n  vpn-zone default-profile <v>     контейнер по умолчанию для всех запусков:\n                                   ask (спрашивать), main (основной),\n                                   own (своя песочница у каждой программы)\n                                   или имя контейнера\n  vpn-zone pins                    какие программы закреплены за сетями\n  vpn-zone forget <прог.|--all>    снять закрепление (снова будет спрашивать)\n  vpn-zone isolate <overlay|off>   свой слой профиля у зоны (overlay — по\n                                   умолчанию). Без него браузер откроет окно\n                                   в уже запущенном процессе, мимо VPN\n  vpn-zone reset-profile <имя>     очистить слой профиля зоны\n  vpn-zone wayland-sandbox on|off  отбирать ли у программ захват экрана,\n                                   чтение буфера в фоне и эмуляцию ввода\n                                   (по умолчанию on; исключения —\n                                   ~/.config/vpn-zones/wayland-allow)\n  vpn-zone check <имя>             прошло ли рукопожатие (жив ли конфиг)\n  vpn-zone lock|unlock <имя>       запретить/разрешить программам этой зоны\n                                   запускать что-либо в ДРУГИХ сетях\n                                   (по умолчанию разрешено)\n";

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
            eprintln!("vpn-zone: {e}");
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
        b"unlock" => set_lock(&tools, rest, false),
        b"check" => check(&tools, rest),
        b"run" => launch::run(&tools, rest),
        b"gc" => gc(&tools),
        b"perms" => perms(&tools, rest),
        b"sandbox" => sandbox(&tools, rest),
        b"profile" => profile(&tools, rest),
        b"wayland-sandbox" => wayland_sandbox(&tools, rest),
        b"isolate" => isolate(&tools, rest),
        b"reset-profile" => reset_profile(&tools, rest),
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
/// A stale file (the holder was killed) is not "up": the process has to exist.
pub fn zone_pid(state: &Path, name: &OsStr) -> Option<i32> {
    let text = fs::read_to_string(state.join(name).join("zone.pid")).ok()?;
    let pid: i32 = text.trim().parse().ok()?;
    proc_is_alive(pid).then_some(pid)
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
    let ready = state.join(name).join("ready");
    let up = || ready.is_file() && zone_pid(state, name).is_some();
    for _ in 0..READY_TRIES {
        if up() {
            return true;
        }
        std::thread::sleep(READY_STEP);
    }
    up()
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

/// Write a setting file with no trailing newline (`printf '%s'`), creating
/// `~/.config/vpn-zones` on the way.
fn write_setting(tools: &Tools, name: &str, value: &OsStr) -> Result<(), String> {
    fs::create_dir_all(&tools.config).map_err(|e| format!("{}: {e}", tools.config.display()))?;
    let path = tools.config.join(name);
    fs::write(&path, value.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))
}

/// A name that may become a directory next to other people's data.
///
/// Refuses exactly what is dangerous — a path separator, whitespace, a leading
/// dash or dot — and nothing else. Cyrillic stays Cyrillic: the earlier rule was
/// "latin only", the GUI sanitised a Russian name into a row of dashes, and
/// kdialog takes an argument starting with `-` for an option and closes without
/// a word. (`docs/GOTCHAS.md` §11)
fn safe_name(name: &OsStr) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && !bytes.contains(&b'/')
        && !bytes.contains(&b' ')
        && !bytes.starts_with(b"-")
        && !bytes.starts_with(b".")
}

/// A zone name, which is stricter still: it ends up in unit names and in
/// generated `.desktop` files.
fn safe_zone_name(name: &OsStr) -> bool {
    !name.as_bytes().is_empty()
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
    if !safe_zone_name(name) {
        eprintln!("имя только из букв, цифр, - и _");
        return 1;
    }
    let conf = Path::new(conf);
    if !conf.is_file() {
        eprintln!("нет файла {}", conf.display());
        return 1;
    }
    let raw = match fs::read(conf) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("не читается {}: {e}", conf.display());
            return 1;
        }
    };
    let text = strip_cr(&raw);
    // The parser the zone itself will run on, rather than a `grep` for
    // `[Interface]`: a file that cannot be parsed cannot bring a zone up, and
    // being told so now beats a zone that refuses to start later.
    match WgConfig::parse(&text) {
        Err(e) => {
            eprintln!(
                "{} не похож на конфиг WireGuard/AmneziaWG: {e}",
                conf.display()
            );
            return 1;
        }
        Ok(cfg) if cfg.interface().is_none() => {
            eprintln!("{} не похож на конфиг WireGuard/AmneziaWG", conf.display());
            return 1;
        }
        Ok(_) => {}
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
    } else {
        let _ = fs::remove_file(&marker);
        println!("зона {name} открыта: запуск из неё в другой сети снова разрешён");
    }
    0
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
        println!("перезапусти её: vpn-zone down {name_text} && vpn-zone up {name_text}");
        return 3;
    };
    match handshake_line(&mirror) {
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

fn reset_profile(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(name) = required(args, 0, "нужно имя зоны") else {
        return 1;
    };
    let dir = tools.state.join(name);
    if !dir.is_dir() {
        eprintln!("зоны {} нет", name.to_string_lossy());
        return 1;
    }
    if zone_pid(&tools.state, name).is_some() {
        eprintln!(
            "сначала опусти зону: vpn-zone down {}",
            name.to_string_lossy()
        );
        return 1;
    }
    let _ = crate::sys::remove_tree(&dir.join("overlay"));
    println!(
        "слой профиля зоны {} очищен (основной профиль не тронут)",
        name.to_string_lossy()
    );
    0
}

fn remove(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(name) = required(args, 0, "нужно имя") else {
        return 1;
    };
    let name_text = name.to_string_lossy();
    // `direct` and `offline` are built-in choices of the picker, not zones:
    // direct traffic is the absence of a zone, and the empty one is recreated by
    // the first launch that asks for it. (`docs/GOTCHAS.md` §2)
    if name == "direct" || name == "offline" {
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
        // SAFETY: kill(2) with a pid we read out of /proc and a plain signal
        // number; the worst a race can do is deliver TERM to nothing.
        if unsafe { libc::kill(pid, libc::SIGTERM) } == 0 {
            killed += 1;
        }
    }

    let running = tools.state.join(".running");
    let mut cleaned = registry::sweep_dead(&running, &proc_is_alive);

    // Abandoned throwaway containers. Their home is erased behind the last
    // tenant, but a hard kill leaves the directory. Judged by live PIDs in the
    // registry and not by the registry directory existing: after a hard kill
    // that directory stays around full of dead records, and the older check kept
    // the garbage in /tmp forever. (`docs/GOTCHAS.md` §5)
    for dir in visible_entries(Path::new("/tmp")) {
        let Some(name) = dir.file_name() else {
            continue;
        };
        if !name.as_bytes().starts_with(b"vpn-profile-") || !dir.is_dir() {
            continue;
        }
        let regdir = running.join(name);
        if registry::any_live(&regdir, &proc_is_alive) {
            continue;
        }
        let _ = crate::sys::remove_tree(&dir);
        let _ = crate::sys::remove_tree(&regdir);
        cleaned += 1;
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
            eprintln!("vpn-zone perms list|reset <программа|--all>");
            1
        }
    }
}

/// Named sandboxes. NOT containers: a container is a layer over your home (you
/// see everything, only the data is split), a sandbox has a home of its own and
/// it is empty. Hence the separate directory.
fn sandbox(tools: &Tools, args: &[OsString]) -> u8 {
    let sub = args
        .first()
        .cloned()
        .unwrap_or_else(|| OsString::from("list"));
    let rest: &[OsString] = args.get(1..).unwrap_or(&[]);
    match sub.as_bytes() {
        b"create" => {
            let Some(name) = required(rest, 0, "нужно имя песочницы") else {
                return 1;
            };
            if !safe_name(name) {
                eprintln!("в имени нельзя: / пробел, и оно не должно начинаться с - или .");
                return 1;
            }
            let home = tools.sandboxes.join(name).join("home");
            if let Err(e) = fs::create_dir_all(&home) {
                eprintln!("не создать {}: {e}", home.display());
                return 1;
            }
            println!(
                "песочница {} создана (свой пустой дом, доступ наружу спросится при запуске)",
                name.to_string_lossy()
            );
            0
        }
        b"list" => {
            let dirs: Vec<PathBuf> = visible_entries(&tools.sandboxes)
                .into_iter()
                .filter(|d| d.is_dir())
                .collect();
            if dirs.is_empty() {
                println!("песочниц нет. Создать: vpn-zone sandbox create <имя>");
                return 0;
            }
            for dir in dirs {
                let name = dir
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                let perms = fs::read_to_string(dir.join("perms"))
                    .unwrap_or_default()
                    .replace('\n', " ");
                let perms = if perms.is_empty() {
                    "ничего"
                } else {
                    &perms
                };
                let size = human_size(tree_size(&dir));
                match name.strip_prefix("app-") {
                    Some(app) => {
                        println!("{name} — своя песочница программы {app}, {size}, доступ: {perms}")
                    }
                    None => println!("{name} — {size}, доступ: {perms}"),
                }
            }
            0
        }
        b"rm" => {
            let Some(name) = required(rest, 0, "нужно имя песочницы") else {
                return 1;
            };
            let dir = tools.sandboxes.join(name);
            if !dir.is_dir() {
                eprintln!("песочницы {} нет", name.to_string_lossy());
                return 1;
            }
            if let Err(e) = crate::sys::remove_tree(&dir) {
                eprintln!("не удалить {}: {e}", dir.display());
                return 1;
            }
            println!(
                "песочница {} удалена вместе со своим домом",
                name.to_string_lossy()
            );
            0
        }
        _ => {
            eprintln!("vpn-zone sandbox create|list|rm <имя>");
            1
        }
    }
}

fn profile(tools: &Tools, args: &[OsString]) -> u8 {
    let sub = args
        .first()
        .cloned()
        .unwrap_or_else(|| OsString::from("list"));
    let rest: &[OsString] = args.get(1..).unwrap_or(&[]);
    match sub.as_bytes() {
        b"create" => {
            let Some(name) = required(rest, 0, "нужно имя профиля") else {
                return 1;
            };
            if !safe_name(name) {
                eprintln!("в имени нельзя: / пробел, и оно не должно начинаться с - или .");
                return 1;
            }
            let dir = tools.profiles.join(name);
            if let Err(e) = fs::create_dir_all(&dir) {
                eprintln!("не создать {}: {e}", dir.display());
                return 1;
            }
            println!(
                "профиль {} создан (пустой слой поверх твоего ~/)",
                name.to_string_lossy()
            );
            0
        }
        b"list" => {
            let dirs: Vec<PathBuf> = visible_entries(&tools.profiles)
                .into_iter()
                .filter(|d| d.is_dir())
                .collect();
            if dirs.is_empty() {
                println!("профилей нет. Создать: vpn-zone profile create <имя>");
                return 0;
            }
            let running = tools.state.join(".running");
            for dir in dirs {
                let name = dir
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                let size = human_size(tree_size(&dir));
                // Who has it open, from the shared launch registry — the same
                // one the network-conflict warning reads.
                match registry::live_zone(&running.join(&name), &proc_is_alive) {
                    Some(zone) => println!("{name} — открыт в сети {zone} ({size})"),
                    None => println!("{name} — свободен ({size})"),
                }
            }
            0
        }
        b"rm" => {
            let Some(name) = required(rest, 0, "нужно имя профиля") else {
                return 1;
            };
            let dir = tools.profiles.join(name);
            if !dir.is_dir() {
                eprintln!("профиля {} нет", name.to_string_lossy());
                return 1;
            }
            if let Err(e) = crate::sys::remove_tree(&dir) {
                eprintln!("не удалить {}: {e}", dir.display());
                return 1;
            }
            println!("профиль {} удалён", name.to_string_lossy());
            0
        }
        _ => {
            eprintln!("vpn-zone profile create|list|rm <имя>");
            1
        }
    }
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

fn isolate(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(value) = required(args, 0, "overlay или off") else {
        return 1;
    };
    if value != "overlay" && value != "off" {
        eprintln!("только overlay или off");
        return 1;
    }
    if let Err(e) = write_setting(tools, "isolate", value) {
        eprintln!("не записать {e}");
        return 1;
    }
    if value == "overlay" {
        println!("зоны накладывают свой слой на ~/.config, ~/.local/share, ~/.cache,");
        println!("~/.mozilla, ~/.pki — программа видит настройки, но пишет в слой зоны");
    } else {
        println!("зоны используют общий профиль. Учти: браузер тогда откроет окно");
        println!("в уже запущенном процессе, и трафик пойдёт мимо VPN");
    }
    println!("поднятые зоны надо перезапустить, чтобы это применилось");
    0
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
    run_sync(tools)
}

fn default_profile(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(value) = required(args, 0, "ask | main | own | <имя профиля>") else {
        return 1;
    };
    if !matches!(value.as_bytes(), b"ask" | b"main" | b"own")
        && !tools.profiles.join(value).is_dir()
    {
        eprintln!("профиля {} нет", value.to_string_lossy());
        return 1;
    }
    if let Err(e) = write_setting(tools, "default-profile", value) {
        eprintln!("не записать {e}");
        return 1;
    }
    println!("контейнер по умолчанию: {}", value.to_string_lossy());
    0
}

fn default_network(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(value) = required(args, 0, "вариант: offline | direct | <имя зоны>")
    else {
        return 1;
    };
    if let Err(e) = write_setting(tools, "default", value) {
        eprintln!("не записать {e}");
        return 1;
    }
    println!("по умолчанию в пикере: {}", value.to_string_lossy());
    0
}

// --- PINS --------------------------------------------------------------------

fn pins(tools: &Tools) -> u8 {
    let mut found = false;
    for (sub, network) in [(".pinned", true), (".pinnedprofile", false)] {
        for file in visible_entries(&tools.state.join(sub)) {
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
            if network {
                println!("{label}: сеть → {value}");
            } else {
                let value = if value == "__main__" {
                    "основной".to_owned()
                } else {
                    value
                };
                println!("{label}: контейнер → {value}");
            }
            found = true;
        }
    }
    if !found {
        println!("закреплённых программ нет — пикер спрашивает каждый раз");
    }
    0
}

fn forget(tools: &Tools, args: &[OsString]) -> u8 {
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
            assert!(safe_name(OsStr::new(good)), "«{good}» должно быть можно");
        }
        for bad in ["", "a/b", "a b", "-a", ".a", "/"] {
            assert!(!safe_name(OsStr::new(bad)), "«{bad}» должно быть нельзя");
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
            "default-profile",
            "pins",
            "forget",
            "isolate",
            "reset-profile",
            "wayland-sandbox",
            "check",
            "lock",
        ] {
            assert!(
                USAGE.contains(&format!("vpn-zone {verb}")),
                "в справке нет «{verb}»"
            );
        }
    }
}
