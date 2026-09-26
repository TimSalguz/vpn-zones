//! Links opened on behalf of a container (`docs/PERMISSIONS.md` §11.13).
//!
//! A link a program of a zone opens — a messenger's, a mail client's — reaches
//! the zone's bus filter (`crate::bus_filter`), and the filter hands it to the
//! broker on the host (`crate::broker`, a link request). Two choices are made
//! there, each by its owner (owner, 2026-09-26):
//!
//! * **the program** is the distribution's to offer: the portal backend's own
//!   window of choice (`org.freedesktop.impl.portal.AppChooser` — GNOME's,
//!   KDE's, as the portal configuration names it) with the programs that
//!   claim the link's scheme, the distribution's default first
//!   ([`programs_for`], [`distro_default`]). Called on the implementation, not
//!   on the portal: it answers with the choice and starts nothing;
//! * **the container and the network** are CellWard's: the launch window, as
//!   for any launch a zone asks for, with the asking zone in it.
//!
//! "Always" is CellWard's too, and per container: a rule "links of this
//! scheme from this container open in this program" ([`rule`], Nix
//! `containers.<c>.links`, `cellward container links`). It skips the choice
//! of the program only — the launch window still shows. The host's own
//! default (`mimeapps.list`) is never changed by CellWard; KDE's window has
//! a checkbox of its own that does, and that is the distribution's.
//!
//! A program's rule is taken only for a container the broker is sure of
//! (`crate::broker`): the zone's own programs and one not known choose every
//! time.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// A link's scheme, lowercased: `https` of `https://…`, `tg` of `tg:…`.
/// `None` for anything that is not one.
pub fn scheme_of(uri: &str) -> Option<String> {
    let (scheme, _) = uri.split_once(':')?;
    let mut chars = scheme.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c));
    valid.then(|| scheme.to_ascii_lowercase())
}

/// A program links of a scheme may open in: its launcher id (the
/// `.desktop` file's name without it) and its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    pub id: String,
    pub name: String,
}

/// The programs that claim `scheme` (`x-scheme-handler/<scheme>` in their
/// entry), each once, as the entries' programs wrote them
/// (`desktop::find_entry`: not CellWard's own taken-over copies), the
/// distribution's `default` first ([`distro_default`]), the rest by name.
/// Deleted entries (`Hidden=true`) are none.
pub fn programs_for(
    dirs: &[PathBuf],
    home: &Path,
    state: &Path,
    scheme: &str,
    default: Option<&str>,
) -> Vec<Program> {
    let mut ids: BTreeSet<String> = BTreeSet::new();
    for dir in dirs {
        for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(id) = name.strip_suffix(".desktop") {
                if !id.starts_with(crate::desktop::PREFIX) {
                    ids.insert(id.to_owned());
                }
            }
        }
    }
    let mut out: Vec<Program> = Vec::new();
    for id in ids {
        let Some((_, groups)) = crate::desktop::find_entry(dirs, home, state, &id) else {
            continue;
        };
        let Some(entry) = crate::desktop::desktop_entry(&groups) else {
            continue;
        };
        if entry.get("Hidden") == Some("true")
            || !crate::desktop::claimed_schemes(entry)
                .iter()
                .any(|s| s == scheme)
        {
            continue;
        }
        let name = entry
            .get("Name")
            .filter(|n| !n.is_empty())
            .unwrap_or(&id)
            .to_owned();
        out.push(Program { id, name });
    }
    out.sort_by(|a, b| {
        let first = |p: &Program| Some(p.id.as_str()) != default;
        (first(a), &a.name).cmp(&(first(b), &b.name))
    });
    out
}

/// The `mimeapps.list` files, in the order the specification reads them: the
/// user's configuration, the system's, then the data directories', each
/// desktop's own before the common one.
pub fn mimeapps_files(home: &Path) -> Vec<PathBuf> {
    let env_dirs = |var: &str, default: &str| -> Vec<PathBuf> {
        let value = std::env::var_os(var).filter(|v| !v.is_empty());
        std::env::split_paths(&value.unwrap_or_else(|| OsString::from(default)))
            .filter(|d| !d.as_os_str().is_empty())
            .collect()
    };
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map_or_else(|| home.join(".config"), PathBuf::from);
    let data_home = std::env::var_os("XDG_DATA_HOME")
        .filter(|v| !v.is_empty())
        .map_or_else(|| home.join(".local/share"), PathBuf::from);
    let desktops: Vec<String> = std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .split(':')
        .filter(|d| !d.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    let mut dirs = vec![config_home];
    dirs.extend(env_dirs("XDG_CONFIG_DIRS", "/etc/xdg"));
    dirs.push(data_home.join("applications"));
    dirs.extend(
        env_dirs("XDG_DATA_DIRS", "/usr/local/share:/usr/share")
            .into_iter()
            .map(|d| d.join("applications")),
    );
    let mut out = Vec::new();
    for dir in dirs {
        for desktop in &desktops {
            out.push(dir.join(format!("{desktop}-mimeapps.list")));
        }
        out.push(dir.join("mimeapps.list"));
    }
    out
}

/// The distribution's default program for links of `scheme`: the first
/// `x-scheme-handler/<scheme>` of `[Default Applications]` in `files`, as a
/// launcher id.
pub fn distro_default(files: &[PathBuf], scheme: &str) -> Option<String> {
    let key = format!("x-scheme-handler/{scheme}");
    for file in files {
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        let mut in_defaults = false;
        for line in text.lines().map(str::trim) {
            if line.starts_with('[') {
                in_defaults = line == "[Default Applications]";
                continue;
            }
            if !in_defaults {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            if k.trim() != key {
                continue;
            }
            let first = v
                .split(';')
                .map(str::trim)
                .find_map(|id| id.strip_suffix(".desktop").filter(|i| !i.is_empty()));
            if let Some(id) = first {
                return Some(id.to_owned());
            }
        }
    }
    None
}

/// A container's rule for `scheme`: the program its links open in.
pub fn rule(container: &crate::container::Container, scheme: &str) -> Option<String> {
    container
        .links
        .iter()
        .find(|l| l.value.0 == scheme)
        .map(|l| l.value.1.clone())
}

/// A rule's word as the container's settings keep it: `<scheme> <id>`.
pub fn rule_word(scheme: &str, id: &str) -> String {
    format!("{scheme} {id}")
}

/// A rule's word read back: the scheme, lowercased, and the program's id.
pub fn parse_rule(word: &str) -> Option<(String, String)> {
    let (scheme, id) = word.trim().split_once(char::is_whitespace)?;
    let id = bare_id(id.trim());
    let scheme = scheme_of(&format!("{scheme}:"))?;
    plausible_id(id).then(|| (scheme, id.to_owned()))
}

/// What the choice of a program came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    /// A program, by its launcher id.
    Chosen(String),
    /// The person closed the window: nothing opens.
    Cancelled,
    /// No window could be shown.
    Unavailable(String),
}

/// The portal backends that may show the window of choice, in order: the one
/// the portal configuration names for `AppChooser` (or its default), then
/// the usual ones — a backend that has none answers so, and the next is
/// asked.
pub fn backends() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let desktops: Vec<String> = std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .split(':')
        .filter(|d| !d.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
    let mut dirs: Vec<PathBuf> = config_home.into_iter().collect();
    for var in ["XDG_CONFIG_DIRS", "XDG_DATA_DIRS"] {
        if let Some(value) = std::env::var_os(var) {
            dirs.extend(std::env::split_paths(&value).filter(|d| !d.as_os_str().is_empty()));
        }
    }
    dirs.push(PathBuf::from("/etc/xdg"));
    let mut files: Vec<PathBuf> = Vec::new();
    for desktop in &desktops {
        for dir in &dirs {
            files.push(
                dir.join("xdg-desktop-portal")
                    .join(format!("{desktop}-portals.conf")),
            );
        }
    }
    for dir in &dirs {
        files.push(dir.join("xdg-desktop-portal").join("portals.conf"));
    }
    if let Some(text) = files.iter().find_map(|f| fs::read_to_string(f).ok()) {
        out = configured(&text);
        if out.iter().any(|b| b == "none") {
            return Vec::new();
        }
    }
    for usual in ["gnome", "kde", "gtk"] {
        if !out.iter().any(|b| b == usual) {
            out.push(usual.to_owned());
        }
    }
    out.retain(|b| b != "*");
    out
}

/// The backends a `portals.conf` names for `AppChooser`: its own key, else
/// `default`.
pub fn configured(text: &str) -> Vec<String> {
    let mut preferred = false;
    let (mut own, mut default) = (None, None);
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            preferred = line == "[preferred]";
            continue;
        }
        let Some((k, v)) = line.split_once('=').filter(|_| preferred) else {
            continue;
        };
        match k.trim() {
            "org.freedesktop.impl.portal.AppChooser" => own = Some(v.trim().to_owned()),
            "default" => default = Some(v.trim().to_owned()),
            _ => {}
        }
    }
    own.or(default)
        .unwrap_or_default()
        .split(';')
        .map(str::trim)
        .filter(|b| {
            !b.is_empty()
                && b.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'*')
        })
        .map(str::to_owned)
        .collect()
}

/// Ask the person which program opens `uri`: the portal backends' window of
/// choice ([`backends`]), through `busctl` on the session bus — waited for as
/// long as the person takes; `kdialog`'s menu where no backend has one.
pub fn choose(
    busctl: &Path,
    kdialog: &Path,
    scheme: &str,
    uri: &str,
    programs: &[Program],
) -> Choice {
    if programs.is_empty() {
        return Choice::Unavailable(format!("нет программы для ссылок {scheme}:"));
    }
    let mut why = String::from("ни у одного бэкенда портала нет окна выбора программы");
    for backend in backends() {
        match app_chooser(busctl, &backend, scheme, uri, programs) {
            Ok(choice) => return choice,
            Err(e) => why = e,
        }
    }
    eprintln!("links: {why} — kdialog");
    kdialog_menu(kdialog, uri, programs).unwrap_or(Choice::Unavailable(why))
}

/// One backend's `AppChooser.ChooseApplication`. `Err` for a backend that
/// has none (or is none).
fn app_chooser(
    busctl: &Path,
    backend: &str,
    scheme: &str,
    uri: &str,
    programs: &[Program],
) -> Result<Choice, String> {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let handle = format!(
        "/org/freedesktop/portal/desktop/request/cellward/link{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let mut args: Vec<OsString> = ["--user", "--json=short", "--timeout=infinity", "--", "call"]
        .iter()
        .map(OsString::from)
        .collect();
    args.push(format!("org.freedesktop.impl.portal.desktop.{backend}").into());
    args.push("/org/freedesktop/portal/desktop".into());
    args.push("org.freedesktop.impl.portal.AppChooser".into());
    args.push("ChooseApplication".into());
    args.push("ossasa{sv}".into());
    args.push(handle.into());
    args.push("".into());
    args.push("".into());
    args.push(programs.len().to_string().into());
    args.extend(programs.iter().map(|p| OsString::from(&p.id)));
    let content_type = format!("x-scheme-handler/{scheme}");
    let mut options: Vec<(&str, &str)> =
        vec![("content_type", content_type.as_str()), ("uri", uri)];
    if let Some(first) = programs.first() {
        options.push(("last_choice", first.id.as_str()));
    }
    args.push(options.len().to_string().into());
    for (key, value) in options {
        args.push(key.into());
        args.push("s".into());
        args.push(value.into());
    }
    let out = Command::new(busctl)
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("не запустить {}: {e}", busctl.display()))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        return Err(format!("{backend}: {err}"));
    }
    parse_answer(&String::from_utf8_lossy(&out.stdout))
        .ok_or_else(|| format!("{backend}: ответ не разобрать"))
}

/// `busctl --json=short`'s answer of `ChooseApplication` — `ua{sv}`: the
/// response (0 chosen, 1 cancelled, 2 otherwise) and the results, `choice`
/// among them. A choice need not be one of those offered — KDE's window
/// shows every program too, the way out of a list that missed one —, but it
/// must look like a launcher id; whether there is such an entry, and whether
/// it takes a link, the broker sees.
pub fn parse_answer(json: &str) -> Option<Choice> {
    let value = crate::json::parse(json.trim()).ok()?;
    let data = value.get("data")?.as_array()?;
    let response = data.first()?.as_i64()?;
    if response != 0 {
        return Some(Choice::Cancelled);
    }
    let choice = data.get(1)?.get("choice")?.get("data")?.as_str()?;
    let choice = choice.strip_suffix(".desktop").unwrap_or(choice);
    Some(if plausible_id(choice) {
        Choice::Chosen(choice.to_owned())
    } else {
        Choice::Cancelled
    })
}

/// A launcher id as a file name can carry it: no path, no space, and not
/// what a program would take for an option.
pub fn plausible_id(id: &str) -> bool {
    !id.is_empty()
        && !id.starts_with('-')
        && id != "."
        && id != ".."
        && !id.contains(['/', '\0'])
        && !id.contains(char::is_whitespace)
}

/// A launcher id as written: `firefox.desktop` is `firefox`.
pub fn bare_id(id: &str) -> &str {
    id.strip_suffix(".desktop").unwrap_or(id)
}

/// `kdialog`'s menu of `programs`, where no backend shows a window.
fn kdialog_menu(kdialog: &Path, uri: &str, programs: &[Program]) -> Option<Choice> {
    let shown = crate::bus_filter::loggable(uri);
    let mut args: Vec<OsString> = vec![
        "--title".into(),
        "Открыть ссылку".into(),
        "--menu".into(),
        format!("Какой программой открыть {shown}?").into(),
    ];
    for p in programs {
        args.push(p.id.clone().into());
        // Not taken for an option: a name is anybody's text.
        args.push(p.name.trim_start_matches('-').to_owned().into());
    }
    let out = Command::new(kdialog)
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return Some(Choice::Cancelled);
    }
    let id = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    Some(if programs.iter().any(|p| p.id == id) {
        Choice::Chosen(id)
    } else {
        Choice::Cancelled
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scheme_is_told_by_the_standard() {
        assert_eq!(scheme_of("HTTPS://example.org"), Some("https".into()));
        assert_eq!(scheme_of("tg:resolve?domain=x"), Some("tg".into()));
        assert_eq!(scheme_of("web+app://x"), Some("web+app".into()));
        assert_eq!(scheme_of("1http://x"), None);
        assert_eq!(scheme_of("no scheme"), None);
        assert_eq!(scheme_of("://x"), None);
    }

    #[test]
    fn a_rule_reads_as_it_is_written() {
        assert_eq!(
            parse_rule(&rule_word("https", "firefox")),
            Some(("https".into(), "firefox".into()))
        );
        assert_eq!(
            parse_rule("HTTPS  org.mozilla.firefox"),
            Some(("https".into(), "org.mozilla.firefox".into()))
        );
        assert_eq!(
            parse_rule("https firefox.desktop"),
            Some(("https".into(), "firefox".into()))
        );
        assert_eq!(parse_rule("https -x"), None);
        for bad in [
            "https",
            "https ../x",
            "https a/b",
            "1x firefox",
            " firefox",
            "https a b",
        ] {
            assert_eq!(parse_rule(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_default_is_the_first_file_that_names_one() {
        let dir = std::env::temp_dir().join(format!("vz-links-mime-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let user = dir.join("user.list");
        let system = dir.join("system.list");
        fs::write(
            &user,
            "[Added Associations]\nx-scheme-handler/https=chromium.desktop;\n\
             [Default Applications]\ntext/html=vlc.desktop\n",
        )
        .unwrap();
        fs::write(
            &system,
            "[Default Applications]\nx-scheme-handler/https=firefox.desktop;chromium.desktop;\n",
        )
        .unwrap();
        let files = vec![dir.join("missing.list"), user, system];
        assert_eq!(distro_default(&files, "https"), Some("firefox".into()));
        assert_eq!(distro_default(&files, "tg"), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_programs_that_claim_a_scheme_default_first() {
        let dir = std::env::temp_dir().join(format!("vz-links-apps-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let apps = dir.join("apps");
        fs::create_dir_all(&apps).unwrap();
        let entry = |id: &str, name: &str, mime: &str, extra: &str| {
            fs::write(
                apps.join(format!("{id}.desktop")),
                format!(
                    "[Desktop Entry]\nType=Application\nName={name}\nExec={id} %u\n\
                     MimeType={mime}\n{extra}"
                ),
            )
            .unwrap();
        };
        entry(
            "aaa",
            "Zeta Browser",
            "x-scheme-handler/https;x-scheme-handler/http;",
            "",
        );
        entry("bbb", "Alpha Browser", "x-scheme-handler/https;", "");
        entry("ccc", "Mail", "x-scheme-handler/mailto;", "");
        entry("ddd", "Gone", "x-scheme-handler/https;", "Hidden=true\n");
        entry("vpn-zone-x", "Ours", "x-scheme-handler/https;", "");
        let home = dir.join("home");
        let found = programs_for(
            std::slice::from_ref(&apps),
            &home,
            &dir.join("state"),
            "https",
            Some("aaa"),
        );
        let ids: Vec<&str> = found.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, ["aaa", "bbb"]);
        assert_eq!(found[0].name, "Zeta Browser");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_portal_configuration_names_the_backend() {
        let conf = "[preferred]\ndefault=gnome;gtk\norg.freedesktop.impl.portal.FileChooser=kde\n";
        assert_eq!(configured(conf), ["gnome", "gtk"]);
        let conf = "[preferred]\ndefault=gnome\norg.freedesktop.impl.portal.AppChooser=kde\n";
        assert_eq!(configured(conf), ["kde"]);
        assert!(configured("[other]\ndefault=gnome\n").is_empty());
        // Nothing that would make another bus name.
        assert_eq!(
            configured("[preferred]\ndefault=gnome;a.b;x y\n"),
            ["gnome"]
        );
    }

    #[test]
    fn the_answer_is_the_choice() {
        let gnome = r#"{"type":"ua{sv}","data":[0,{"choice":{"type":"s","data":"firefox"}}]}"#;
        assert_eq!(parse_answer(gnome), Some(Choice::Chosen("firefox".into())));
        let kde = r#"{"type":"ua{sv}","data":[0,{"activation_token":{"type":"s","data":"t"},"choice":{"type":"s","data":"chromium.desktop"}}]}"#;
        assert_eq!(parse_answer(kde), Some(Choice::Chosen("chromium".into())));
        let cancelled = r#"{"type":"ua{sv}","data":[1,{}]}"#;
        assert_eq!(parse_answer(cancelled), Some(Choice::Cancelled));
        // KDE's "show all": one not offered is a choice too.
        let other = r#"{"type":"ua{sv}","data":[0,{"choice":{"type":"s","data":"vlc"}}]}"#;
        assert_eq!(parse_answer(other), Some(Choice::Chosen("vlc".into())));
        // Not a launcher id: nothing opens.
        let odd = r#"{"type":"ua{sv}","data":[0,{"choice":{"type":"s","data":"../x"}}]}"#;
        assert_eq!(parse_answer(odd), Some(Choice::Cancelled));
        assert_eq!(parse_answer("nonsense"), None);
    }
}
