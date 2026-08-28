//! `vpn-zone-gui` — the six launcher entries, one subcommand each.
//!
//! These were six `writeShellScriptBin` wrappers in `module/default.nix`, one
//! per `.desktop` file: add a zone, remove a zone, create a container, remove a
//! container, the settings, and "forget the networks of programs". They are
//! kdialog over the CLI and nothing else — every one of them ends in a
//! `vpn-zone` verb — so they moved into one binary with a verb of their own
//! rather than six binaries in `home.packages`. The launcher entries name it
//! directly:
//!
//! ```text
//! Exec=env VPN_ZONE_TOOLS=/nix/store/…-vpn-zone-tools.json …/vpn-zone-gui add
//! ```
//!
//! The dialog and notification texts are carried over WORD FOR WORD, including
//! the ones where the shell passed a literal `\n` to kdialog (a Nix indented
//! string does not interpret backslash escapes, so those two characters reached
//! the dialog as they are). They stay in Russian for the same reason the CLI's
//! do: they are read by the user at his desktop, and translating them is a step
//! of its own (ROADMAP M6).
//!
//! Everything reachable from here is also reachable from the command line; this
//! is the half of the project for people who do not open a terminal, which is
//! why every branch ends in either a notification or an error dialog — a
//! shortcut that silently does nothing is indistinguishable from a broken one.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use crate::cli::{human_size, read_setting, tree_size, visible_entries, EXIT_TOOLS};
use crate::dialog;
use crate::picker::{sanitize_name, MAIN};
use crate::profile::proc_is_alive;
use crate::registry;
use crate::tools::Tools;

const USAGE: &str = "\
vpn-zone-gui — графические ярлыки vpn-zones (kdialog над vpn-zone)

  vpn-zone-gui add          выбрать .conf и создать зону
  vpn-zone-gui remove       остановить и удалить зону
  vpn-zone-gui profile-add  завести контейнер данных
  vpn-zone-gui profile-rm   удалить контейнер (или все)
  vpn-zone-gui settings     сеть/контейнер по умолчанию, ярлыки, замки
  vpn-zone-gui forget       забыть закреплённые сети программ

Эти же действия есть в CLI: vpn-zone add|rm|profile|default|mode|forget.
Пути инструментов приходят манифестом VPN_ZONE_TOOLS, как и у vpn-zone.
";

/// Entry point of the `vpn-zone-gui` binary.
pub fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let verb = args.first().cloned().unwrap_or_default();

    if matches!(verb.as_bytes(), b"" | b"-h" | b"--help" | b"help") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let tools = match Tools::from_env() {
        Ok(tools) => tools,
        Err(e) => {
            eprintln!("vpn-zone-gui: {e}");
            return ExitCode::from(EXIT_TOOLS);
        }
    };

    let code = match verb.as_bytes() {
        b"add" => add(&tools),
        b"remove" => remove(&tools),
        b"profile-add" => profile_add(&tools),
        b"profile-rm" => profile_rm(&tools),
        b"settings" => settings(&tools),
        b"forget" => forget(&tools),
        _ => {
            eprintln!("неизвестная команда: {}", verb.to_string_lossy());
            print!("{USAGE}");
            1
        }
    };
    ExitCode::from(code)
}

// --- SHARED PIECES -----------------------------------------------------------

/// `vpn-zone <args…>`: did it work, and what did it say?
///
/// Both streams together, the way the shell's `2>&1` collected them — the
/// dialogs that show a failure show the reason, and the reason is usually on
/// stderr. A CLI that could not be started at all is a failure whose text is
/// why.
fn cli(tools: &Tools, args: &[&str]) -> (bool, String) {
    match Command::new(&tools.runner)
        .args(args)
        .stdin(Stdio::null())
        .output()
    {
        Ok(out) => {
            let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            (out.status.success(), text.trim_end().to_owned())
        }
        Err(e) => (
            false,
            format!("не запустить {}: {e}", tools.runner.display()),
        ),
    }
}

/// `vpn-zone <args…>` with everything thrown away: the caller checks the state
/// on disk instead.
fn cli_quiet(tools: &Tools, args: &[&str]) -> bool {
    Command::new(&tools.runner)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// A menu: `--title T --menu TEXT tag1 text1 tag2 text2 …`, and what came back.
fn menu(tools: &Tools, title: &str, text: &str, rows: &[(String, String)]) -> Option<String> {
    menu_with_default(tools, title, None, text, rows)
}

/// The same, with an entry pre-selected (`--default`).
fn menu_with_default(
    tools: &Tools,
    title: &str,
    default: Option<&str>,
    text: &str,
    rows: &[(String, String)],
) -> Option<String> {
    let mut argv: Vec<OsString> = vec!["--title".into(), title.into()];
    if let Some(default) = default {
        argv.push("--default".into());
        argv.push(default.into());
    }
    argv.push("--menu".into());
    argv.push(text.into());
    for (tag, label) in rows {
        argv.push(tag.as_str().into());
        argv.push(label.as_str().into());
    }
    dialog::ask(&tools.kdialog, &argv).filter(|answer| !answer.is_empty())
}

fn row(tag: &str, text: impl Into<String>) -> (String, String) {
    (tag.to_owned(), text.into())
}

/// The zones a dialog may act on: a directory with a config in it.
///
/// "Прямой интернет" and "Без сети" are deliberately absent — the first is the
/// absence of a zone, the second an empty namespace recreated by the next
/// launch that asks for it. There is nothing to delete there, and an entry for
/// them would only confuse. (`docs/GOTCHAS.md` §2)
fn zones(state: &Path) -> Vec<PathBuf> {
    visible_entries(state)
        .into_iter()
        .filter(|dir| dir.join("config.conf").is_file())
        .filter(|dir| dir.file_name().is_some_and(|n| n != "offline"))
        .collect()
}

fn name_of(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// Is this zone up? The same test `vpn-zone list` makes: a `ready` file and a
/// holder that is still alive.
fn zone_is_up(dir: &Path) -> bool {
    if !dir.join("ready").is_file() {
        return false;
    }
    read_setting(&dir.join("zone.pid"))
        .and_then(|text| text.trim().parse::<i32>().ok())
        .is_some_and(proc_is_alive)
}

// --- ADD A ZONE --------------------------------------------------------------

fn add(tools: &Tools) -> u8 {
    let Some(conf) = dialog::ask(
        &tools.kdialog,
        [
            OsStr::new("--title"),
            OsStr::new("Конфиг VPN"),
            OsStr::new("--getopenfilename"),
            tools.home.as_os_str(),
            OsStr::new("*.conf|Конфигурация WireGuard/AmneziaWG (*.conf)"),
        ],
    ) else {
        return 0;
    };
    if conf.is_empty() {
        return 0;
    }

    let suggest = suggested_zone_name(Path::new(&conf));
    let question = format!("Как назвать зону? Это имя попадёт в ярлыки: Chromium ({suggest})");
    let Some(name) = dialog::ask(
        &tools.kdialog,
        [
            "--title",
            "Имя зоны",
            "--inputbox",
            question.as_str(),
            suggest.as_str(),
        ],
    ) else {
        return 0;
    };
    if name.is_empty() {
        return 0;
    }

    let (ok, _) = cli(tools, &["add", &name, &conf]);
    if !ok {
        dialog::message(
            &tools.kdialog,
            [
                "--error",
                format!("Не удалось создать зону {name}").as_str(),
            ],
        );
        return 1;
    }

    if !cli_quiet(tools, &["up", &name]) {
        dialog::notify(
            &tools.notify_send,
            Some("critical"),
            "8000",
            &format!("Зона «{name}» не поднялась"),
            &format!("Смотри: journalctl --user -u vpn-zone@{name}"),
        );
        return 0;
    }

    let _ = cli_quiet(tools, &["sync"]);
    // Give the zone a few seconds for its handshake and say straight away
    // whether the config is alive: that answer is what a zone is usually
    // created for ("which of my .conf files still works?").
    // (`docs/GOTCHAS.md` §4)
    std::thread::sleep(std::time::Duration::from_secs(6));
    if cli_quiet(tools, &["check", &name]) {
        dialog::notify(
            &tools.notify_send,
            None,
            "8000",
            &format!("Зона «{name}» готова"),
            "Рукопожатие прошло — конфиг рабочий. Запускай программы: они спросят сеть при старте.",
        );
    } else {
        dialog::notify(
            &tools.notify_send,
            Some("critical"),
            "10000",
            &format!("Зона «{name}» поднята, но туннель молчит"),
            "Рукопожатия нет: конфиг устарел или сервер недоступен. Зону можно удалить ярлыком «Удалить VPN-зону».",
        );
    }
    0
}

/// The name offered for a zone made out of this file: the base name without
/// `.conf`, with everything outside `[A-Za-z0-9_-]` turned into a dash.
///
/// A dash and not an underscore, and a dot is replaced too — that is what the
/// shell's `sed` did, and the name ends up in unit names and shortcuts, where
/// `vpn-zone add` only accepts those characters anyway.
pub fn suggested_zone_name(conf: &Path) -> String {
    let stem = conf
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let stem = stem.strip_suffix(".conf").unwrap_or(&stem);
    stem.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

// --- REMOVE A ZONE -----------------------------------------------------------

fn remove(tools: &Tools) -> u8 {
    let rows: Vec<(String, String)> = zones(&tools.state)
        .into_iter()
        .map(|dir| {
            let name = name_of(&dir);
            if zone_is_up(&dir) {
                row(&name, format!("{name} (сейчас поднята)"))
            } else {
                row(&name, name.clone())
            }
        })
        .collect();

    if rows.is_empty() {
        dialog::message(
            &tools.kdialog,
            [
                "--msgbox",
                "VPN-зон нет — удалять нечего.\\n\\nСоздать: «Добавить VPN-зону» в лаунчере.",
            ],
        );
        return 0;
    }

    let Some(zone) = menu(tools, "Удалить VPN-зону", "Какую зону удалить?", &rows)
    else {
        return 0;
    };

    // The second step is mandatory: the copy of the config goes with the zone,
    // and the private key in it cannot be recovered from anywhere.
    // (`docs/GOTCHAS.md` §4)
    //
    // The `\n` here are two characters, not a line break, and that is verbatim:
    // a Nix indented string interprets no backslash escapes, so this is exactly
    // what the shell version handed kdialog.
    let warning = format!(
        "Зона «{zone}» будет остановлена и удалена вместе с копией конфига (там приватный ключ).\\n\\nПрограммы, закреплённые за этой зоной, снова начнут спрашивать сеть."
    );
    if !dialog::confirm(
        &tools.kdialog,
        [
            "--title",
            "Точно удалить?",
            "--warningcontinuecancel",
            warning.as_str(),
        ],
    ) {
        return 0;
    }

    let (ok, out) = cli(tools, &["rm", &zone]);
    if ok {
        dialog::notify(
            &tools.notify_send,
            None,
            "6000",
            &format!("Зона «{zone}» удалена"),
            "Ярлыки пересобраны.",
        );
    } else {
        dialog::message(
            &tools.kdialog,
            [
                "--error",
                format!("Не удалось удалить зону «{zone}»:\\n{out}").as_str(),
            ],
        );
    }
    0
}

// --- CREATE A CONTAINER ------------------------------------------------------

fn profile_add(tools: &Tools) -> u8 {
    let Some(name) = dialog::ask(
        &tools.kdialog,
        [
            "--title",
            "Новый контейнер",
            "--inputbox",
            "Название контейнера (буквы, цифры, дефис). Контейнер хранит настройки и сессии отдельно, но видит текущие как исходные, пока сам их не изменит.",
            "",
        ],
    ) else {
        return 0;
    };
    let name = sanitize_name(&name);
    if name.is_empty() {
        return 0;
    }

    let (ok, out) = cli(tools, &["profile", "create", &name]);
    if ok {
        dialog::notify(
            &tools.notify_send,
            None,
            "6000",
            &format!("Контейнер «{name}» создан"),
            "Выбирай его во втором окне при запуске программы.",
        );
    } else {
        dialog::message(
            &tools.kdialog,
            ["--error", format!("Не удалось создать: {out}").as_str()],
        );
    }
    0
}

// --- REMOVE A CONTAINER ------------------------------------------------------

/// A container is a layer accumulated on top of your `~/`: browser cache,
/// cookies, sessions. It grows and goes stale, so there has to be a way to
/// throw it away without touching the main environment — which stays untouched
/// by construction, being the lower layer of the overlay.
fn profile_rm(tools: &Tools) -> u8 {
    let running = tools.state.join(".running");
    let dirs: Vec<PathBuf> = visible_entries(&tools.profiles)
        .into_iter()
        .filter(|dir| dir.is_dir())
        .collect();
    let total = dirs.len();

    let mut rows: Vec<(String, String)> = dirs
        .iter()
        .map(|dir| {
            let name = name_of(dir);
            let size = human_size(tree_size(dir));
            match registry::live_zone(&running.join(&name), &proc_is_alive) {
                Some(zone) => row(
                    &name,
                    format!("{name} — {size}, сейчас открыт в сети {zone}"),
                ),
                None => row(&name, format!("{name} — {size}")),
            }
        })
        .collect();

    if total == 0 {
        dialog::message(
            &tools.kdialog,
            [
                "--msgbox",
                "Профилей нет.\n\nПрофиль создаётся при запуске программы: выбери «➕ Новый профиль…» во втором окне выбора.",
            ],
        );
        return 0;
    }
    if total > 1 {
        rows.push(row("__all__", format!("⚠ Удалить ВСЕ профили ({total})")));
    }

    let Some(choice) = menu(
        tools,
        "Удалить профиль",
        "Какой контейнер данных удалить? Основное окружение не пострадает",
        &rows,
    ) else {
        return 0;
    };

    let warn = if choice == "__all__" {
        format!("Удалить ВСЕ профили ({total})?\n\nПропадут накопленные в них настройки, куки и сессии. Твоё основное окружение (~/.config и остальное) не тронется.")
    } else {
        format!("Удалить профиль «{choice}»?\n\nПропадут его настройки, куки и сессии. Основное окружение не тронется.")
    };
    if !dialog::confirm(
        &tools.kdialog,
        [
            "--title",
            "Точно удалить?",
            "--warningcontinuecancel",
            warn.as_str(),
        ],
    ) {
        return 0;
    }

    if choice == "__all__" {
        for dir in &dirs {
            let _ = cli_quiet(tools, &["profile", "rm", &name_of(dir)]);
        }
        dialog::notify(
            &tools.notify_send,
            None,
            "6000",
            "Профили удалены",
            &format!("Снесены все {total} контейнеров данных."),
        );
    } else if cli_quiet(tools, &["profile", "rm", &choice]) {
        dialog::notify(
            &tools.notify_send,
            None,
            "6000",
            "Профиль удалён",
            &format!("Контейнер «{choice}» снесён."),
        );
    } else {
        dialog::message(
            &tools.kdialog,
            [
                "--error",
                format!("Не удалось удалить профиль «{choice}»").as_str(),
            ],
        );
    }
    0
}

// --- SETTINGS ----------------------------------------------------------------

/// Everything that used to live in commands only: the default network and
/// container, the shortcut mode, the zone locks. The menu shows the CURRENT
/// values — without them a setting is impossible to remember and its state
/// impossible to guess.
fn settings(tools: &Tools) -> u8 {
    let _ = fs::create_dir_all(&tools.config);
    let setting = |name: &str, fallback: &str| {
        read_setting(&tools.config.join(name)).unwrap_or_else(|| fallback.to_owned())
    };
    let current_net = setting("default", "offline");
    let current_profile = setting("default-profile", "ask");
    let current_mode = setting("mode", "picker");
    let current_wayland = setting("wayland-sandbox", "on");

    let Some(what) = menu(
        tools,
        "Настройки VPN-зон",
        "Что настроить?",
        &[
            row("net", format!("Сеть по умолчанию — сейчас: {current_net}")),
            row(
                "prof",
                format!("Контейнер по умолчанию — сейчас: {current_profile}"),
            ),
            row("mode", format!("Ярлыки программ — сейчас: {current_mode}")),
            row(
                "wl",
                format!("Доступ к экрану и вводу — сейчас: {current_wayland}"),
            ),
            row("lock", "Замки зон (кому запрещено выходить в другие сети)"),
        ],
    ) else {
        return 0;
    };

    match what.as_str() {
        "net" => {
            let mut rows = vec![
                row(
                    "offline",
                    "Без сети (безопасный выбор для незнакомой программы)",
                ),
                row("direct", "Прямой интернет"),
            ];
            for dir in zones(&tools.state) {
                let name = name_of(&dir);
                rows.push(row(&name, format!("VPN: {name}")));
            }
            let Some(value) = menu_with_default(
                tools,
                "Сеть по умолчанию",
                Some(&current_net),
                "Что предлагать для программы, которую запускаешь впервые?",
                &rows,
            ) else {
                return 0;
            };
            apply(tools, &["default", &value], "Сеть по умолчанию", &value);
        }
        "prof" => {
            let mut rows = vec![
                row("ask", "Спрашивать каждый раз"),
                row("main", "Всегда основной (общий с системой)"),
                row("own", "У каждой программы своя постоянная песочница"),
            ];
            for dir in visible_entries(&tools.profiles) {
                if !dir.is_dir() {
                    continue;
                }
                let name = name_of(&dir);
                rows.push(row(&name, format!("Всегда «{name}»")));
            }
            let Some(value) = menu_with_default(
                tools,
                "Контейнер по умолчанию",
                Some(&current_profile),
                "Спрашивать ли контейнер при каждом запуске?",
                &rows,
            ) else {
                return 0;
            };
            apply(
                tools,
                &["default-profile", &value],
                "Контейнер по умолчанию",
                &value,
            );
        }
        "mode" => {
            let Some(value) = menu_with_default(
                tools,
                "Ярлыки программ",
                Some(&current_mode),
                "Как вести себя ярлыкам?",
                &[
                    row("picker", "Один ярлык, спрашивает сеть при запуске"),
                    row("per-zone", "Отдельный ярлык на каждую зону"),
                    row("both", "И то, и другое"),
                    row("off", "Не трогать ярлыки"),
                ],
            ) else {
                return 0;
            };
            apply(tools, &["mode", &value], "Режим ярлыков", &value);
        }
        "wl" => {
            let Some(value) = menu_with_default(
                tools,
                "Доступ к экрану и вводу",
                Some(&current_wayland),
                "Отбирать ли у программ захват экрана, чтение буфера в фоне и эмуляцию ввода? Исключения (скриншотилки, менеджер буфера) — в ~/.config/vpn-zones/wayland-allow",
                &[
                    row("on", "Отбирать — программа видит только свои окна"),
                    row("off", "Не отбирать — как было до этой настройки"),
                ],
            ) else {
                return 0;
            };
            apply(
                tools,
                &["wayland-sandbox", &value],
                "Доступ к экрану",
                &value,
            );
        }
        "lock" => return locks(tools),
        _ => {}
    }
    0
}

/// Run the CLI verb and say so in a notification — but only when it worked, as
/// the shell's `&&` did.
fn apply(tools: &Tools, args: &[&str], title: &str, value: &str) {
    if cli_quiet(tools, args) {
        dialog::notify(&tools.notify_send, None, "4000", title, value);
    }
}

/// A locked zone does not let its programs out into other networks — which is
/// what a quarantine zone is for, not a VPN one. (`docs/GOTCHAS.md` §1)
fn locks(tools: &Tools) -> u8 {
    // Every zone directory, `offline` included: a lock is about what may leave
    // the zone, and that question makes sense for the empty one too.
    let dirs: Vec<PathBuf> = visible_entries(&tools.state)
        .into_iter()
        .filter(|dir| dir.is_dir())
        .collect();
    let rows: Vec<(String, String)> = dirs
        .iter()
        .map(|dir| {
            let name = name_of(dir);
            if dir.join(crate::launch::NO_ESCAPE).is_file() {
                row(&name, format!("{name} — ЗАПЕРТА (снять замок)"))
            } else {
                row(&name, format!("{name} — открыта (запереть)"))
            }
        })
        .collect();

    if rows.is_empty() {
        dialog::message(&tools.kdialog, ["--msgbox", "Зон нет."]);
        return 0;
    }

    let Some(zone) = menu(
        tools,
        "Замки зон",
        "Запертая зона не выпускает свои программы в другие сети — это нужно карантинным, а не VPN",
        &rows,
    ) else {
        return 0;
    };

    if tools
        .state
        .join(&zone)
        .join(crate::launch::NO_ESCAPE)
        .is_file()
    {
        if cli_quiet(tools, &["unlock", &zone]) {
            dialog::notify(
                &tools.notify_send,
                None,
                "4000",
                &format!("Зона «{zone}»"),
                "замок снят",
            );
        }
    } else if cli_quiet(tools, &["lock", &zone]) {
        dialog::notify(
            &tools.notify_send,
            None,
            "4000",
            &format!("Зона «{zone}»"),
            "заперта",
        );
    }
    0
}

// --- FORGET THE PINS ---------------------------------------------------------

fn forget(tools: &Tools) -> u8 {
    let pins = tools.state.join(".pinned");
    let profile_pins = tools.state.join(".pinnedprofile");
    let keys = pinned_keys(&pins, &profile_pins);

    if keys.is_empty() {
        dialog::message(
            &tools.kdialog,
            [
                "--msgbox",
                "Закреплённых программ нет — сеть спрашивается при каждом запуске.",
            ],
        );
        return 0;
    }

    let mut rows = vec![row("__all__", "⟲ Сбросить у ВСЕХ программ")];
    for key in &keys {
        // The program's NAME, not the internal key: the key is a shortcut id
        // (com.ayugram.desktop) and tells nobody what it is about. The label is
        // written by the picker itself, in `.labels`. (`docs/GOTCHAS.md` §10)
        let label = label_of(&tools.state, key);
        let net = read_setting(&pins.join(key)).unwrap_or_else(|| "—".to_owned());
        let mut container = read_setting(&profile_pins.join(key)).unwrap_or_else(|| "—".to_owned());
        if container == MAIN {
            container = "основной".to_owned();
        }
        rows.push(row(
            key,
            format!("{label} — сеть: {net}, контейнер: {container}"),
        ));
    }

    let Some(choice) = menu(
        tools,
        "Сбросить сеть по умолчанию",
        "У какой программы забыть выбранную сеть?",
        &rows,
    ) else {
        return 0;
    };

    if choice == "__all__" {
        let _ = cli_quiet(tools, &["forget", "--all"]);
        dialog::notify(
            &tools.notify_send,
            None,
            "5000",
            "Сброшено",
            "Сеть снова спрашивается для всех программ.",
        );
    } else {
        let label = label_of(&tools.state, &choice);
        let _ = cli_quiet(tools, &["forget", &choice]);
        dialog::notify(
            &tools.notify_send,
            None,
            "5000",
            "Сброшено",
            &format!("Для «{label}» сеть снова будет спрашиваться."),
        );
    }
    0
}

/// Every program that has a pin of either kind, in the order the two shell
/// globs produced them: the networks first, then the containers, each
/// alphabetical, and nobody listed twice.
pub fn pinned_keys(pins: &Path, profile_pins: &Path) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    for dir in [pins, profile_pins] {
        for file in visible_entries(dir) {
            if !file.is_file() {
                continue;
            }
            let name = name_of(&file);
            if !keys.contains(&name) {
                keys.push(name);
            }
        }
    }
    keys
}

fn label_of(state: &Path, key: &str) -> String {
    read_setting(&state.join(".labels").join(key)).unwrap_or_else(|| key.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zone_name_is_suggested_from_the_file_name() {
        assert_eq!(
            suggested_zone_name(Path::new("/home/u/Downloads/nl.conf")),
            "nl"
        );
        // Everything outside the alphabet a zone name may use becomes a dash —
        // a dot included, which is what makes a suggestion out of a name like
        // "AmneziaVPN-2.conf".
        assert_eq!(
            suggested_zone_name(Path::new("/tmp/AmneziaVPN 2.1.conf")),
            "AmneziaVPN-2-1"
        );
        assert_eq!(suggested_zone_name(Path::new("/tmp/личное.conf")), "------");
        // Only the extension goes, and only from the end.
        assert_eq!(
            suggested_zone_name(Path::new("/tmp/conf.conf.conf")),
            "conf-conf"
        );
        assert_eq!(suggested_zone_name(Path::new("/tmp/plain")), "plain");
    }

    #[test]
    fn the_reset_list_names_every_pinned_program_once() {
        let dir = std::env::temp_dir().join(format!("vpn-zone-gui-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let pins = dir.join(".pinned");
        let profile_pins = dir.join(".pinnedprofile");
        fs::create_dir_all(&pins).unwrap();
        fs::create_dir_all(&profile_pins).unwrap();
        fs::write(pins.join("firefox"), "nl").unwrap();
        fs::write(pins.join("com.ayugram.desktop"), "de").unwrap();
        fs::write(profile_pins.join("firefox"), "__main__").unwrap();
        fs::write(profile_pins.join("dolphin"), "sb:work").unwrap();
        // A dot-file is not a pin, and neither is a directory.
        fs::write(pins.join(".hidden"), "x").unwrap();
        fs::create_dir_all(pins.join("subdir")).unwrap();

        assert_eq!(
            pinned_keys(&pins, &profile_pins),
            ["com.ayugram.desktop", "firefox", "dolphin"]
        );
        // Nothing pinned at all is the "нет закреплённых" branch.
        assert!(pinned_keys(&dir.join("gone"), &dir.join("also-gone")).is_empty());
        let _ = fs::remove_dir_all(&dir);
    }
}
