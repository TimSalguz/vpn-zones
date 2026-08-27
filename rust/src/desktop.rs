//! `.desktop` generation for VPN zones. Two modes, switched with
//! `vpn-zone mode`.
//!
//! **picker mode** (the default) is what this exists for. The application keeps
//! its single launcher entry, but that entry is intercepted: instead of the
//! program it starts the picker, which asks "which network?" and calls the
//! program itself. The launcher does not grow a row of duplicates, and the
//! network is chosen at the moment of starting. The interception is the plain
//! XDG trick — a file of the same name in `~/.local/share/applications`
//! shadows the system one. The originals in `/nix/store` are never touched;
//! undoing it is deleting our files (`vpn-zone mode off`).
//!
//! **per-zone mode** is the older behaviour: one entry per zone, "Firefox
//! (nl)". Useful for starting into a specific zone with one click and no
//! dialog. `both` does both.
//!
//! **Self-eating protection** (in both modes):
//!
//! * files carrying the `X-VPNZone` key are never taken as input;
//! * in per-zone mode clones are additionally filtered out by name prefix;
//! * foreign files in `~/.local/share/applications` (home-manager symlinks,
//!   hand-written entries) are NEVER overwritten — only our own, the ones
//!   carrying the marker. Without that the very first sync would have erased
//!   the entries Nix puts there.
//!
//! Why a parser and not `sed`: a `.desktop` file is an ini with localised keys
//! and escaping, and taking it apart line by line means one day producing an
//! entry with a mangled `Exec`. (`docs/GOTCHAS.md` §10)

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Prefix of every file this module writes itself, and of the module's own
/// menu entries. Files starting with it are never taken as input.
pub const PREFIX: &str = "vpn-zone-";
/// The marker that says "this file is ours". Present in the file we write and
/// checked before overwriting or deleting anything.
pub const MARK: &str = "X-VPNZone";

/// What gets carried into a per-zone clone.
///
/// `MimeType` is deliberately **not** here: otherwise the clones would start
/// claiming file associations, and one day "open this image" would silently
/// travel into a VPN zone. In picker mode it is the other way round — there is
/// only one entry and it MUST keep the associations, or the program stops
/// being a handler. (`docs/GOTCHAS.md` §10)
const CLONE_KEYS: [&str; 7] = [
    "Icon",
    "Terminal",
    "Categories",
    "Keywords",
    "StartupNotify",
    "StartupWMClass",
    "Path",
];

/// Keys that must never be copied into a picker entry: `Exec` is rewritten,
/// and the other two would let the launcher reach the program around it.
const PICKER_DROPPED_KEYS: [&str; 3] = ["Exec", "DBusActivatable", "TryExec"];

/// Localised label keys. `Name` is the only one a zone suffix is appended to.
const LABEL_KEYS: [&str; 3] = ["Name", "GenericName", "Comment"];

/// The `%f`, `%U`… field codes of the desktop entry specification.
const FIELD_CODES: &str = "fFuUdDnNickvm";

/// Our own menu entries. home-manager puts them there as symlinks, so `ours()`
/// would leave them alone anyway — they are listed to make the intent visible.
const OWN_ENTRIES: [&str; 3] = [
    "vpn-zone-add.desktop",
    "vpn-zone-remove.desktop",
    "vpn-zone-forget.desktop",
];

/// How the launcher entries are generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Picker,
    PerZone,
    Both,
    Off,
}

impl Mode {
    /// Anything unknown in the mode file means the default, never a failure:
    /// this runs from a path unit and a timer, where an error is invisible.
    pub fn parse(text: &str) -> Self {
        match text.trim() {
            "per-zone" => Self::PerZone,
            "both" => Self::Both,
            "off" => Self::Off,
            _ => Self::Picker,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Picker => "picker",
            Self::PerZone => "per-zone",
            Self::Both => "both",
            Self::Off => "off",
        }
    }

    fn intercepts(self) -> bool {
        matches!(self, Self::Picker | Self::Both)
    }

    fn clones(self) -> bool {
        matches!(self, Self::PerZone | Self::Both)
    }
}

/// One `[Group]` of a desktop file with its keys, in file order.
///
/// A `Vec` and not a map on purpose: the output has to keep the order of the
/// input, so that a rewritten entry stays diff-able against the original.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Group {
    pub name: String,
    entries: Vec<(String, String)>,
}

impl Group {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.0 == key)
            .map(|e| e.1.as_str())
    }

    /// Keys and values in file order.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Last value wins, first position wins — the same thing a Python dict did.
    fn set(&mut self, key: &str, value: &str) {
        match self.entries.iter_mut().find(|e| e.0 == key) {
            Some(e) => e.1 = value.to_string(),
            None => self.entries.push((key.to_string(), value.to_string())),
        }
    }

    /// Is `key` present, either plain or in any localised form (`Name[ru]`)?
    fn has(&self, key: &str) -> bool {
        self.entries
            .iter()
            .any(|(k, _)| k == key || k.starts_with(&format!("{key}[")))
    }
}

/// Read a whole desktop file: `[(group name, keys)]`.
///
/// Invalid UTF-8 is replaced rather than rejected (Python read these with
/// `errors="replace"`): a broken byte in some translated `Comment` must not
/// cost the user their launcher entry.
pub fn parse_desktop(text: &str) -> Vec<Group> {
    let mut groups: Vec<Group> = Vec::new();
    for raw in text.lines() {
        let s = raw.trim();
        if s.len() >= 2 && s.starts_with('[') && s.ends_with(']') {
            groups.push(Group {
                name: s[1..s.len() - 1].to_string(),
                entries: Vec::new(),
            });
            continue;
        }
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        let Some((key, value)) = s.split_once('=') else {
            continue;
        };
        // Keys before the first group header belong to nothing and are
        // dropped, as the specification says.
        let Some(current) = groups.last_mut() else {
            continue;
        };
        current.set(key.trim(), value.trim());
    }
    groups
}

/// Same, from a file. An unreadable file yields no groups, which makes it a
/// non-candidate — never an error.
pub fn parse_desktop_file(path: &Path) -> Vec<Group> {
    match fs::read(path) {
        Ok(bytes) => parse_desktop(&String::from_utf8_lossy(&bytes)),
        Err(_) => Vec::new(),
    }
}

/// The `[Desktop Entry]` group.
pub fn desktop_entry(groups: &[Group]) -> Option<&Group> {
    groups.iter().find(|g| g.name == "Desktop Entry")
}

/// Can this file be intercepted or cloned?
pub fn is_candidate(file_name: &str, entry: Option<&Group>) -> bool {
    if file_name.starts_with(PREFIX) {
        return false;
    }
    let Some(entry) = entry else {
        return false;
    };
    // Ours already — taking it as input is how a generator eats itself.
    if entry.has(MARK) {
        return false;
    }
    if entry.get("Type").unwrap_or("Application") != "Application" {
        return false;
    }
    for hidden in ["NoDisplay", "Hidden"] {
        if entry
            .get(hidden)
            .unwrap_or("false")
            .eq_ignore_ascii_case("true")
        {
            return false;
        }
    }
    entry.get("Exec").is_some_and(|e| !e.is_empty())
}

/// A key without spaces or quotes, so that `Exec` parses for anybody.
pub fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// `Name`, `Name[ru]`, `GenericName`, `Comment[de]` → the base key.
fn label_key(key: &str) -> Option<&'static str> {
    for base in LABEL_KEYS {
        let Some(rest) = key.strip_prefix(base) else {
            continue;
        };
        if rest.is_empty() {
            return Some(base);
        }
        // `[…]` with a non-empty locale and no nested bracket.
        if rest.len() > 2
            && rest.starts_with('[')
            && rest.ends_with(']')
            && !rest[1..rest.len() - 1].contains(']')
        {
            return Some(base);
        }
    }
    None
}

/// Drop `%U` and friends. Used for per-zone clones only: there the command
/// goes through `vpn-zone run`, which does not carry file arguments.
fn strip_field_codes(exec: &str) -> String {
    let mut out = String::with_capacity(exec.len());
    // A `%` is held back for one character: only `%` + a code is dropped, a
    // literal `%%` and a `%` before anything else stay as they are.
    let mut pending_percent = false;
    for c in exec.chars() {
        if pending_percent {
            pending_percent = false;
            if FIELD_CODES.contains(c) {
                continue;
            }
            out.push('%');
        }
        if c == '%' {
            pending_percent = true;
            continue;
        }
        out.push(c);
    }
    if pending_percent {
        out.push('%');
    }
    out
}

/// per-zone: "Firefox (nl)" — a separate entry per zone.
pub fn render_clone(entry: &Group, zone: &str, runner: &str) -> String {
    let exec_line = strip_field_codes(entry.get("Exec").unwrap_or(""))
        .trim()
        .to_string();
    let mut lines = vec![
        "[Desktop Entry]".to_string(),
        "Type=Application".to_string(),
    ];
    for (key, value) in entry.entries() {
        match label_key(key) {
            // Only the name gets the zone appended: a translated Comment with
            // "(nl)" glued to it reads like a mistake.
            Some("Name") => lines.push(format!("{key}={value} ({zone})")),
            Some(_) => lines.push(format!("{key}={value}")),
            None if CLONE_KEYS.contains(&key) => lines.push(format!("{key}={value}")),
            None => {}
        }
    }
    lines.push(format!("Exec={runner} run {zone} -- {exec_line}"));
    lines.push(format!("{MARK}={zone}"));
    lines.join("\n") + "\n"
}

/// picker: the same entry, with `Exec` leading into the network dialog.
///
/// `app_key` is the identifier of the entry (its file name without the
/// extension). It is handed to the picker as `--id` and is the memory key for
/// "which network and which container was chosen for this program". It used to
/// be derived from the first word of the command, and for entries shaped like
/// `Exec=env DESKTOPINTEGRATION=1 AyuGram` that produced "env" — so every such
/// program shared one memory slot, and the reset list showed a mysterious
/// "env".
///
/// **There must be NO QUOTES in `Exec`**, and that is not a matter of taste.
/// The program's display name ("Zen Browser") used to be passed here quoted,
/// by the letter of the desktop specification. But Telegram (and it is not
/// alone) splits `Exec` naively on spaces without removing quotes: the
/// argument fell apart into `Zen` and `Browser"`, the picker took the rubbish
/// for a command, and the launch died with «невозможно выполнить Browser"».
/// So the command line carries single words only, and the human-readable name
/// is taken by the picker from the label file written next to it.
/// (`docs/GOTCHAS.md` §10)
pub fn render_picker(groups: &[Group], picker: &str, app_key: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for group in groups {
        if group.name != "Desktop Entry" && !group.name.starts_with("Desktop Action ") {
            continue;
        }
        out.push(format!("[{}]", group.name));
        for (key, value) in group.entries() {
            if PICKER_DROPPED_KEYS.contains(&key) || key == MARK {
                continue;
            }
            out.push(format!("{key}={value}"));
        }
        if let Some(exec) = group.get("Exec").filter(|e| !e.is_empty()) {
            // Field codes (%U, %f) are KEPT: the entry stays a file handler,
            // and the path reaches the program through the picker as an
            // ordinary argument.
            out.push(format!(
                "Exec={picker} --id {} -- {exec}",
                sanitize(app_key)
            ));
        }
        // Without this the launcher activates the program over D-Bus, around
        // `Exec` — and the whole interception would be pointless.
        out.push("DBusActivatable=false".to_string());
        if group.name == "Desktop Entry" {
            out.push(format!("{MARK}=picker"));
        }
        out.push(String::new());
    }
    out.join("\n")
}

/// Is this file ours — may it be overwritten or deleted?
///
/// A symlink is never ours: home-manager and the user put those there.
pub fn ours(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_symlink() && meta.is_file() => {}
        _ => return false,
    }
    match fs::read(path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).contains(&format!("{MARK}=")),
        Err(_) => false,
    }
}

/// Is there anything at this path at all — INCLUDING a broken symlink?
///
/// A plain "does it exist" follows symlinks and answers `false` for one
/// pointing nowhere. Without this distinction sync would write THROUGH such a
/// symlink, into somebody else's target — with home-manager that is the
/// read-only `/nix/store`, and the whole pass died on the write. Observed
/// exactly like that. (`docs/GOTCHAS.md` §10)
pub fn occupied(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// Write only when the content changed; returns 1 if it did.
///
/// The comparison is mandatory: a path unit watches this directory, so without
/// it the unit would wake sync, sync would rewrite the files, and the loop
/// would never end. (`docs/GOTCHAS.md` §10)
///
/// The comparison is over bytes, not text: a file that is not valid UTF-8 is
/// simply "different", it does not abort the pass.
pub fn write_if_changed(target: &Path, content: &str) -> u32 {
    if fs::read(target).is_ok_and(|existing| existing == content.as_bytes()) {
        return 0;
    }
    match fs::write(target, content) {
        Ok(()) => 1,
        Err(e) => {
            eprintln!(
                "skipping {}: {e}",
                target
                    .file_name()
                    .unwrap_or(target.as_os_str())
                    .to_string_lossy()
            );
            0
        }
    }
}

/// The human-readable name next to the key: dialogs and reset lists show
/// "Zen Browser" while the command line carries the id only.
fn write_label(state_dir: &Path, key: &str, label: &str) {
    let dir = state_dir.join(".labels");
    if fs::create_dir_all(&dir).is_ok() {
        let _ = fs::write(dir.join(sanitize(key)), label);
    }
}

/// Where launcher entries are read from, in priority order and deduplicated.
///
/// The environment is read by the caller and passed in, so that a test can
/// describe a whole system of directories without touching the process
/// environment other threads are reading from.
pub fn source_dirs(home: &Path) -> Vec<PathBuf> {
    let user = std::env::var("USER").unwrap_or_default();
    let mut dirs = vec![
        home.join(".local/share/applications"),
        PathBuf::from(format!("/etc/profiles/per-user/{user}/share/applications")),
        PathBuf::from("/run/current-system/sw/share/applications"),
    ];
    if let Some(data_dirs) = std::env::var_os("XDG_DATA_DIRS") {
        for dir in std::env::split_paths(&data_dirs) {
            if !dir.as_os_str().is_empty() {
                dirs.push(dir.join("applications"));
            }
        }
    }
    let mut seen = BTreeSet::new();
    dirs.into_iter()
        .filter(|d| seen.insert(d.clone()) && d.is_dir())
        .collect()
}

/// One launcher entry found in the sources.
struct App {
    /// File name, e.g. `firefox.desktop`.
    name: String,
    groups: Vec<Group>,
    /// Found in our own output directory. Such files are never intercepted:
    /// they are either ours or the user's.
    own_dir: bool,
}

fn collect_apps(dirs: &[PathBuf], out_dir: &Path) -> Vec<App> {
    let resolved = |p: &Path| fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let out_resolved = resolved(out_dir);

    let mut apps: Vec<App> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for dir in dirs {
        let own_dir = resolved(dir) == out_resolved;
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        // Sorted, so that two runs over the same directory produce the same
        // result — the "first one found wins" rule below depends on it.
        let mut names: Vec<String> = entries
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(String::from))
            .filter(|n| n.ends_with(".desktop"))
            .collect();
        names.sort();
        for name in names {
            if seen.contains(&name) {
                continue;
            }
            let groups = parse_desktop_file(&dir.join(&name));
            if groups.is_empty() || !is_candidate(&name, desktop_entry(&groups)) {
                continue;
            }
            seen.insert(name.clone());
            apps.push(App {
                name,
                groups,
                own_dir,
            });
        }
    }
    apps
}

/// Names of the zones that have a config — the ones a per-zone clone can be
/// made for. An offline zone has no config and is a picker option, not a zone.
fn zone_names(state_dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(state_dir) else {
        return Vec::new();
    };
    let mut zones: Vec<String> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_str().map(String::from)?;
            if name.starts_with('.') || !e.path().join("config.conf").is_file() {
                return None;
            }
            Some(name)
        })
        .collect();
    zones.sort();
    zones
}

/// Remove our own files that are not wanted any more: the mode changed, a zone
/// was deleted, a program disappeared. Foreign files are left alone —
/// [`ours`] checks both the marker and that it is not a symlink.
pub fn cleanup(out_dir: &Path, wanted: &BTreeSet<String>) -> u32 {
    let Ok(entries) = fs::read_dir(out_dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(String::from) else {
            continue;
        };
        if !name.ends_with(".desktop")
            || OWN_ENTRIES.contains(&name.as_str())
            || wanted.contains(&name)
        {
            continue;
        }
        let path = entry.path();
        if ours(&path) && fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// The whole pass. Returns the process exit code.
pub fn sync(state_dir: &Path, home: &Path, runner: &str, picker: &str) -> u8 {
    sync_from(state_dir, home, runner, picker, &source_dirs(home))
}

/// [`sync`] over an explicit list of source directories.
fn sync_from(state_dir: &Path, home: &Path, runner: &str, picker: &str, dirs: &[PathBuf]) -> u8 {
    let out_dir = home.join(".local/share/applications");
    if let Err(e) = fs::create_dir_all(&out_dir) {
        eprintln!("cannot create {}: {e}", out_dir.display());
        return 1;
    }

    let mode = match fs::read_to_string(home.join(".config/vpn-zones/mode")) {
        Ok(text) => Mode::parse(&text),
        Err(_) => Mode::Picker,
    };
    let zones = zone_names(state_dir);
    let apps = if mode == Mode::Off {
        Vec::new()
    } else {
        collect_apps(dirs, &out_dir)
    };

    let mut wanted: BTreeSet<String> = BTreeSet::new();
    let mut written = 0u32;

    for app in &apps {
        let Some(entry) = desktop_entry(&app.groups) else {
            continue;
        };

        // The picker intercepts an entry under its own name, so only entries
        // that came from the system directories may be touched. Files already
        // sitting in ~/.local/share/applications (ours, or home-manager's) are
        // left as they are.
        if mode.intercepts() && !app.own_dir {
            let target = out_dir.join(&app.name);
            if !occupied(&target) || ours(&target) {
                wanted.insert(app.name.clone());
                let app_key = app.name.strip_suffix(".desktop").unwrap_or(&app.name);
                write_label(state_dir, app_key, entry.get("Name").unwrap_or(app_key));
                written += write_if_changed(&target, &render_picker(&app.groups, picker, app_key));
            }
        }

        if mode.clones() {
            for zone in &zones {
                let name = format!("{PREFIX}{zone}-{}", app.name);
                let target = out_dir.join(&name);
                if occupied(&target) && !ours(&target) {
                    continue;
                }
                wanted.insert(name);
                written += write_if_changed(&target, &render_clone(entry, zone, runner));
            }
        }
    }

    let removed = cleanup(&out_dir, &wanted);
    let zone_list = if zones.is_empty() {
        "none".to_string()
    } else {
        zones.join(", ")
    };
    println!(
        "mode {}: {} entries ({written} updated, {removed} removed); zones: {zone_list}",
        mode.as_str(),
        wanted.len()
    );
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// A directory under the system temp dir, removed on drop. No dependency
    /// for this: the crate's dependencies are libc and libseccomp, and a test
    /// helper is not a reason to add a third.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "vpn-zone-desktop-test-{}-{tag}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }

        fn write(&self, name: &str, body: &str) -> PathBuf {
            let p = self.join(name);
            fs::write(&p, body).unwrap();
            p
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    const FIREFOX: &str = "\
[Desktop Entry]
# a comment
Type=Application
Name=Firefox
Name[ru]=Огненный лис
GenericName=Web Browser
Comment=Browse the web
Exec=firefox %U
Icon=firefox
Terminal=false
MimeType=text/html;x-scheme-handler/https;
Categories=Network;WebBrowser;
StartupWMClass=firefox
DBusActivatable=true
TryExec=firefox

[Desktop Action new-private-window]
Name=New Private Window
Exec=firefox --private-window %U

[X-Something-Else]
Name=not carried over
";

    fn groups() -> Vec<Group> {
        parse_desktop(FIREFOX)
    }

    #[test]
    fn the_parser_keeps_order_and_drops_noise() {
        let g = groups();
        assert_eq!(g.len(), 3);
        assert_eq!(g[0].name, "Desktop Entry");
        assert_eq!(g[1].name, "Desktop Action new-private-window");
        assert_eq!(g[0].get("Exec"), Some("firefox %U"));
        assert_eq!(g[0].get("Name[ru]"), Some("Огненный лис"));
        assert_eq!(g[0].get("nothing"), None);
        // Comments, blank lines and lines without `=` are gone; order is kept.
        let keys: Vec<&str> = g[0].entries().map(|(k, _)| k).collect();
        assert_eq!(keys[0], "Type");
        assert_eq!(keys[1], "Name");
        assert!(!keys.contains(&"# a comment"));
    }

    #[test]
    fn the_parser_handles_the_awkward_lines() {
        let g = parse_desktop(
            "Stray=key before any group\n\
             [Desktop Entry]\n\
             \n\
             ; an ini comment style we do not know, and no key either\n\
             Exec = env FOO=bar app --flag=1 \n\
             Name=First\n\
             Name=Second\n\
             []\n\
             Empty=group name\n",
        );
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].get("Stray"), None);
        // Values keep their inner `=`, and both sides are trimmed.
        assert_eq!(g[0].get("Exec"), Some("env FOO=bar app --flag=1"));
        // Last value wins, first position wins.
        assert_eq!(g[0].get("Name"), Some("Second"));
        assert_eq!(g[0].entries().filter(|(k, _)| *k == "Name").count(), 1);
        assert_eq!(g[1].name, "");
    }

    #[test]
    fn candidates_are_visible_applications_that_are_not_ours() {
        let g = groups();
        assert!(is_candidate("firefox.desktop", desktop_entry(&g)));
        // Our own files, by name and by marker.
        assert!(!is_candidate("vpn-zone-add.desktop", desktop_entry(&g)));
        for marker in ["X-VPNZone=picker", "X-VPNZone[ru]=picker"] {
            let marked = parse_desktop(&format!("[Desktop Entry]\nExec=x\n{marker}\n"));
            assert!(
                !is_candidate("x.desktop", desktop_entry(&marked)),
                "{marker} must not be taken as input"
            );
        }
        for skip in [
            "Type=Link\nExec=x",
            "NoDisplay=true\nExec=x",
            "NoDisplay=TRUE\nExec=x",
            "Hidden=true\nExec=x",
            "Name=no exec line",
        ] {
            let g = parse_desktop(&format!("[Desktop Entry]\n{skip}\n"));
            assert!(!is_candidate("x.desktop", desktop_entry(&g)), "{skip}");
        }
        assert!(!is_candidate("x.desktop", None));
    }

    #[test]
    fn the_picker_entry_carries_no_quotes_and_keeps_the_field_codes() {
        let out = render_picker(
            &groups(),
            "/home/u/.nix-profile/bin/vpn-zone-pick",
            "firefox",
        );

        assert!(
            !out.contains('"'),
            "quotes in Exec break naive parsers:\n{out}"
        );
        assert!(
            !out.contains('\''),
            "quotes in Exec break naive parsers:\n{out}"
        );
        assert!(out
            .contains("Exec=/home/u/.nix-profile/bin/vpn-zone-pick --id firefox -- firefox %U\n"));
        // The entry must stay a file handler.
        assert!(out.contains("MimeType=text/html;x-scheme-handler/https;"));
        // D-Bus activation would go around Exec.
        assert_eq!(out.matches("DBusActivatable=false").count(), 2);
        assert!(!out.contains("DBusActivatable=true"));
        assert!(!out.contains("TryExec="));
        // The marker belongs to the main group only, or the actions would look
        // like entries of their own.
        assert_eq!(out.matches("X-VPNZone=picker").count(), 1);
        assert!(out.starts_with("[Desktop Entry]\n"));
        // Actions are carried over, foreign groups are not.
        assert!(out.contains("[Desktop Action new-private-window]"));
        assert!(out.contains(
            "Exec=/home/u/.nix-profile/bin/vpn-zone-pick --id firefox -- firefox --private-window %U"
        ));
        assert!(!out.contains("X-Something-Else"));
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn the_picker_id_is_sanitised_not_quoted() {
        let g = parse_desktop("[Desktop Entry]\nType=Application\nExec=AyuGram\n");
        let out = render_picker(&g, "pick", "com.ayugram.desktop with space");
        assert!(out.contains("Exec=pick --id com.ayugram.desktop_with_space -- AyuGram"));
        assert_eq!(sanitize("Zen Browser"), "Zen_Browser");
        assert_eq!(sanitize("Огненный"), "________");
        assert_eq!(sanitize("a-b_c.d"), "a-b_c.d");
    }

    #[test]
    fn a_clone_is_named_after_its_zone_and_claims_no_mime_types() {
        let g = groups();
        let out = render_clone(desktop_entry(&g).unwrap(), "nl", "/bin/vpn-zone");
        assert!(out.contains("Name=Firefox (nl)\n"));
        assert!(out.contains("Name[ru]=Огненный лис (nl)\n"));
        // Only the name gets the suffix.
        assert!(out.contains("GenericName=Web Browser\n"));
        assert!(out.contains("Comment=Browse the web\n"));
        // Associations must not be hijacked by a clone.
        assert!(!out.contains("MimeType"));
        // Field codes make no sense here: the file argument would be lost.
        assert!(out.contains("Exec=/bin/vpn-zone run nl -- firefox\n"));
        assert!(out.contains("X-VPNZone=nl\n"));
        assert!(!out.contains("TryExec"));
        assert!(!out.contains("DBusActivatable"));
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn field_codes_are_removed_one_by_one() {
        assert_eq!(strip_field_codes("app %U %f --x"), "app   --x");
        // A literal percent is not a field code.
        assert_eq!(strip_field_codes("app 50%% %i"), "app 50%% ");
        assert_eq!(strip_field_codes("app %Z"), "app %Z");
        // A `%` at the very end is kept, and `%%U` loses only the `%U`.
        assert_eq!(strip_field_codes("app %"), "app %");
        assert_eq!(strip_field_codes("%%U"), "%");
    }

    #[test]
    fn ours_and_occupied_tell_symlinks_apart() {
        let tmp = TempDir::new("ours");
        let mine = tmp.write("mine.desktop", "[Desktop Entry]\nX-VPNZone=picker\n");
        let theirs = tmp.write("theirs.desktop", "[Desktop Entry]\nExec=x\n");
        let link = tmp.join("link.desktop");
        symlink(&mine, &link).unwrap();
        let broken = tmp.join("broken.desktop");
        symlink(tmp.join("gone-for-good"), &broken).unwrap();

        assert!(ours(&mine));
        assert!(!ours(&theirs), "a file without the marker is not ours");
        assert!(!ours(&link), "a symlink is never ours, marker or not");
        assert!(!ours(&broken));
        assert!(!ours(&tmp.join("absent.desktop")));

        assert!(occupied(&mine));
        assert!(occupied(&link));
        // The whole point: a symlink pointing nowhere still occupies the path,
        // and writing to it would write into somebody else's target.
        assert!(occupied(&broken));
        assert!(!occupied(&tmp.join("absent.desktop")));
    }

    #[test]
    fn write_if_changed_is_idempotent() {
        let tmp = TempDir::new("write");
        let target = tmp.join("x.desktop");
        assert_eq!(write_if_changed(&target, "one\n"), 1);
        assert_eq!(write_if_changed(&target, "one\n"), 0);
        assert_eq!(write_if_changed(&target, "two\n"), 1);
        assert_eq!(fs::read_to_string(&target).unwrap(), "two\n");
        // Not valid UTF-8 on disk: still just "different", never a failure.
        fs::write(&target, b"\xff\xfe").unwrap();
        assert_eq!(write_if_changed(&target, "two\n"), 1);
    }

    #[test]
    fn cleanup_removes_only_our_own_leftovers() {
        let tmp = TempDir::new("cleanup");
        let stale = tmp.write(
            "vpn-zone-nl-firefox.desktop",
            "[Desktop Entry]\nX-VPNZone=nl\n",
        );
        let kept = tmp.write(
            "vpn-zone-de-firefox.desktop",
            "[Desktop Entry]\nX-VPNZone=de\n",
        );
        let foreign = tmp.write("handmade.desktop", "[Desktop Entry]\nExec=x\n");
        let own_menu = tmp.write("vpn-zone-add.desktop", "[Desktop Entry]\nX-VPNZone=menu\n");
        let target = tmp.write("target.desktop", "[Desktop Entry]\nX-VPNZone=picker\n");
        let link = tmp.join("linked.desktop");
        symlink(&target, &link).unwrap();
        let not_desktop = tmp.write("notes.txt", "X-VPNZone=\n");

        let wanted: BTreeSet<String> = ["vpn-zone-de-firefox.desktop", "target.desktop"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(cleanup(&tmp.path, &wanted), 1);

        assert!(!stale.exists(), "our stale clone must go");
        assert!(kept.exists());
        assert!(foreign.exists(), "a file without the marker is not ours");
        assert!(own_menu.exists(), "our own menu entries are never swept");
        assert!(
            fs::symlink_metadata(&link).is_ok(),
            "a symlink is never ours, even if its target carries the marker"
        );
        assert!(target.exists());
        assert!(not_desktop.exists());
    }

    #[test]
    fn modes_are_read_leniently() {
        assert_eq!(Mode::parse("per-zone\n"), Mode::PerZone);
        assert_eq!(Mode::parse(" both "), Mode::Both);
        assert_eq!(Mode::parse("off"), Mode::Off);
        assert_eq!(Mode::parse("picker"), Mode::Picker);
        assert_eq!(Mode::parse("nonsense"), Mode::Picker);
        assert_eq!(Mode::parse(""), Mode::Picker);
        assert!(Mode::Both.intercepts() && Mode::Both.clones());
        assert!(Mode::Picker.intercepts() && !Mode::Picker.clones());
        assert!(!Mode::PerZone.intercepts() && Mode::PerZone.clones());
        assert!(!Mode::Off.intercepts() && !Mode::Off.clones());
    }

    #[test]
    fn a_full_pass_writes_a_picker_entry_and_sweeps_the_old_one() {
        let tmp = TempDir::new("sync");
        let home = tmp.join("home");
        let state = tmp.join("state");
        let apps = home.join(".local/share/applications");
        let system = tmp.join("system/applications");
        fs::create_dir_all(&apps).unwrap();
        fs::create_dir_all(&system).unwrap();
        fs::create_dir_all(state.join("nl")).unwrap();
        fs::write(state.join("nl/config.conf"), "[Interface]\n").unwrap();
        fs::write(system.join("firefox.desktop"), FIREFOX).unwrap();
        // A leftover of a zone that no longer exists.
        fs::write(
            apps.join("vpn-zone-gone-firefox.desktop"),
            "[Desktop Entry]\nX-VPNZone=gone\n",
        )
        .unwrap();

        // The source list is passed in rather than taken from XDG_DATA_DIRS:
        // tests share one process, and rewriting the environment under the
        // other threads is not worth a fixture.
        let dirs = vec![apps.clone(), system.clone()];
        let run = || sync_from(&state, &home, "/bin/vpn-zone", "/bin/vpn-zone-pick", &dirs);
        assert_eq!(run(), 0);

        let written = fs::read_to_string(apps.join("firefox.desktop")).unwrap();
        assert!(written.contains("--id firefox --"));
        assert!(written.contains("X-VPNZone=picker"));
        assert!(!apps.join("vpn-zone-gone-firefox.desktop").exists());
        // The label file is what the dialogs show instead of the id.
        assert_eq!(
            fs::read_to_string(state.join(".labels/firefox")).unwrap(),
            "Firefox"
        );

        // Second pass changes nothing, and the entry we wrote ourselves is not
        // taken as input on the way (it now sits in the output directory).
        assert_eq!(run(), 0);
        assert_eq!(
            fs::read_to_string(apps.join("firefox.desktop")).unwrap(),
            written
        );
    }
}
