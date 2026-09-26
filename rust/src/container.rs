//! Containers as identities (`docs/CONTAINERS.md` §3, `docs/PERMISSIONS.md`
//! §11.7).
//!
//! A container is a home, its permissions, its trusted certificates and ONE
//! network at a time, under ONE name. The kind of its home is a property of
//! it, not a part of the name:
//!
//! * `private` — a home of its own (`<data>/home`), what a "sandbox" was;
//! * `layer` — a layer over the whole real home (`<data>/home/upper`), what a
//!   "profile" was; `overlay` is read as it;
//! * `main` — the real home itself: no data of its own, but a network,
//!   programs and permissions of its own.
//!
//! Its data live in `~/.local/state/vpn-profiles/<name>/` whatever the kind —
//! a historical name: every zone covers that directory, the ones started
//! before this layout too, which a new directory they would not — and its
//! policy in `~/.config/vpn-zones/containers/<name>/`, read-only in zones.
//!
//! **Where each value comes from is part of the value.** A setting can be
//! declared in Nix (home-manager writes it under
//! `~/.config/vpn-zones/declared/containers/`, read-only), set locally from the
//! CLI or the GUI (`container.conf` in the container's policy directory, the
//! picker's `.pinnedprofile`), or be the default. A declared value wins, and the
//! local tools refuse to change it instead of failing on a read-only file —
//! and a configuration tool reading `vpn-zone status --json` has to know which
//! values it would be fighting the module over.
//!
//! **The file format is ours and flat**: `key = value` lines, `#` comments,
//! repeated keys for lists. Nix writes it, the CLI writes it, a human can read
//! it, and there is no parser to pull in for it.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::cli::{read_setting, visible_entries};
use crate::registry;
use crate::tools::Tools;

/// The local settings of a container, in its policy directory
/// ([`policy_dir`]).
pub const FILE: &str = "container.conf";
/// Where a container's policy lives, below the config dir: its settings,
/// grants, file permissions and trusted certificates, `<name>/`. Not next to
/// its data: a program with the data in reach could otherwise bind its
/// container to the host's network or grant it a directory (review
/// 2026-09-25, P1). The config dir is read-only in zones.
pub const POLICY_DIR: &str = "containers";
/// The mark that this version's layout is in place ([`migrate`]): the
/// policy moved out of the data, the named sandboxes' data moved in with the
/// rest, one name per container. Its content is the layout's number.
pub const LAYOUT_MARK: &str = ".layout";
const LAYOUT: &str = "2";
/// The mark of the previous layout (policy per kind,
/// `containers/{profiles,sandboxes}/<name>`): after it, files next to a
/// container's data are nobody's policy.
const LAYOUT_1_MARK: &str = ".migrated";
/// Names the move to one name gave to what could not keep its own, one
/// `<old selector>\t<new name>` a line: a stale `sb:work` still finds the
/// sandbox that became `work-sb`.
pub const RENAMED: &str = ".renamed";
/// Where the containers' data live, below the home ([`Tools::profiles`]).
pub const PROFILES_SUBDIR: &str = ".local/state/vpn-profiles";
/// Where home-manager puts the declared containers, below the config dir.
pub const DECLARED: &str = "declared/containers";
/// The prefix a named sandbox's selector had while a layer and a home of its
/// own could share a name. Still read: in Nix, in stale memory, in the
/// records of programs started before the move.
pub const SANDBOX_PREFIX: &str = "sb:";
/// The directories granted to a private home, one per line: the path, or
/// `until=<unix seconds> <path>` for a grant with a term.
pub const PATHS_FILE: &str = "paths";
/// The prefix of a grant with a term. A granted path is absolute or `~/…`,
/// so it can never start like this — and a version that does not know the
/// prefix reads the line as a relative path, which fs-sandbox refuses.
pub const UNTIL_PREFIX: &str = "until=";
/// In a container's data directory: the kind of home its `home/` holds. A
/// change of kind sets the other kind's data aside (`home.<kind>`) instead
/// of reading one as the other ([`prepare_data`]).
pub const DATA_KIND: &str = ".home-kind";

/// Now, in seconds since the epoch.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// One line of a paths file: the path as written, and the end of its term.
/// A term that does not parse ended long ago: `Some(0)`.
pub fn grant_line(line: &str) -> (&str, Option<u64>) {
    match line.strip_prefix(UNTIL_PREFIX) {
        Some(rest) => match rest.split_once(' ') {
            Some((until, path)) => (path.trim(), Some(until.parse().unwrap_or(0))),
            None => ("", Some(0)),
        },
        None => (line, None),
    }
}

/// Where a value comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Declared in the home-manager module: read-only here.
    Nix,
    /// Set with the CLI, the GUI or the picker.
    Local,
    /// Nobody set it.
    Default,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nix => "nix",
            Self::Local => "local",
            Self::Default => "default",
        }
    }
}

/// A value and its origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sourced<T> {
    pub value: T,
    pub source: Source,
}

/// What kind of home a container has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Home {
    /// A home of its own: `<data>/home`.
    Private,
    /// A layer over the whole real home: `<data>/home/upper`.
    Layer,
    /// The real home itself.
    Main,
}

impl Home {
    /// As `status --json` says it (schema 1: a layer is `overlay` there).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Layer => "overlay",
            Self::Main => "main",
        }
    }

    /// As the settings and Nix write it: `layer`, and `overlay` for it.
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "private" => Some(Self::Private),
            "layer" | "overlay" => Some(Self::Layer),
            "main" => Some(Self::Main),
            _ => None,
        }
    }

    /// The word a setting is written with.
    pub fn setting(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Layer => "layer",
            Self::Main => "main",
        }
    }

    /// For people.
    pub fn label(self) -> &'static str {
        match self {
            Self::Private => "свой дом",
            Self::Layer => "слой над домом",
            Self::Main => "основной дом",
        }
    }
}

/// The network a container is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Network {
    /// Not bound: the network is asked on every launch, as before containers
    /// had one. What every existing container starts as.
    Ask,
    /// A network by name: a zone, `unconfined` or `offline` (`direct`, the old
    /// name of `unconfined`, is read as it).
    Named(String),
}

impl Network {
    /// `ask`, or a name that could be a network. Anything with a path
    /// separator or whitespace in it cannot be one.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.is_empty() || text.contains(['/', ' ', '\t', '\n']) || text.starts_with(['-', '.'])
        {
            return None;
        }
        Some(if text == "ask" {
            Self::Ask
        } else {
            Self::Named(crate::launch::network_name(text).to_owned())
        })
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Ask => "ask",
            Self::Named(name) => name,
        }
    }

    /// May a launch into `zone` use a container bound to this network?
    pub fn accepts(&self, zone: &str) -> bool {
        match self {
            Self::Ask => true,
            Self::Named(name) => name == zone,
        }
    }
}

/// One container, with the origin of every setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    pub name: String,
    pub home: Home,
    /// Where the kind of home was set.
    pub home_source: Source,
    pub network: Sourced<Network>,
    pub apps: Vec<Sourced<String>>,
    /// Directories of trusted certificates declared in Nix: built by the module
    /// (one `<sha256>.pem` each, checked for CA:TRUE at build time), read-only.
    pub declared_trust: Vec<PathBuf>,
    /// Directories of the real home granted to the container
    /// (`docs/CONTAINERS.md` §3.5): declared ones first. Only grants in force:
    /// one whose term is over is not here at all.
    pub paths: Vec<Sourced<PathBuf>>,
    /// The end of the term of those `paths` that have one, in unix seconds.
    pub expires: Vec<(PathBuf, u64)>,
    /// An X server of its own in a zone (`docs/HERMETICITY.md` §7, A): the
    /// host's is never reachable from a zone.
    pub x11: Sourced<bool>,
    /// The colour of its windows' frame (`#rrggbb`); none of its own is the
    /// zone's (`docs/PERMISSIONS.md` §11.10).
    pub frame_color: Option<Sourced<String>>,
    /// Whether its programs record the microphone (`crate::microphone`);
    /// none of its own is the zone's setting.
    pub microphone: Option<Sourced<crate::microphone::Setting>>,
    /// Whether its programs cast the screen through the portal
    /// (`crate::screencast`); none of its own is the zone's setting.
    pub screencast: Option<Sourced<crate::microphone::Setting>>,
    /// Whether its programs reach the host's cameras; none of its own is the
    /// zone's setting.
    pub camera: Option<Sourced<bool>>,
    /// The devices it is given (`crate::devices::Grant` words): declared
    /// ones first, then the local ones.
    pub devices: Vec<Sourced<String>>,
    /// Its rules for links (`crate::links`): `(scheme, program id)`, the
    /// program its links of that scheme open in without asking which;
    /// declared ones first, one per scheme.
    pub links: Vec<Sourced<(String, String)>>,
    /// The container's data directory ([`data_dir`]). May not exist yet — and
    /// a container of the main home has none it uses.
    pub dir: PathBuf,
    /// Its policy: settings, grants, permissions, certificates
    /// ([`policy_dir`]).
    pub policy: PathBuf,
}

impl Container {
    /// The selector the registry, the pins and `vpn-zone run` use: its name.
    pub fn selector(&self) -> String {
        self.name.clone()
    }

    pub fn trust_dir(&self) -> PathBuf {
        self.policy.join(crate::trust::DIR)
    }

    /// The home the programs see, on disk: a private home's. `None` for a
    /// layer (its home is an overlay, mounted per launch) and for the main
    /// home (the real one).
    pub fn private_home(&self) -> Option<PathBuf> {
        (self.home == Home::Private).then(|| self.dir.join("home"))
    }
}

/// The beginning of a temporary container's directory name (`--tmp-profile`):
/// its launches are recorded under it, and it is no container's name.
pub const TEMPORARY_PREFIX: &str = "vpn-profile-";

/// The names that are words of this project rather than containers: the
/// picker's menu commands and settings (`main`, `ask`, `own`, `pinmain`,
/// `unpinprof`, anything `__…`), the directories of the previous policy
/// layout, and the temporary containers' names.
pub fn reserved_name(name: &str) -> bool {
    name.starts_with("__")
        || name.starts_with(TEMPORARY_PREFIX)
        || matches!(
            name,
            "pinmain" | "unpinprof" | "main" | "ask" | "own" | "profiles" | "sandboxes"
        )
}

/// Can this be the name of a container? One file name, which no program can
/// take for an option or a hidden file, and no word of ours ([`reserved_name`]).
/// `:` is out: it separated the old sandbox prefix, and the picker's tags;
/// `?` too: the broker names an origin it does not know `zone/?`.
/// Any script otherwise — `Работа` is a name.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with(['-', '.'])
        && !name
            .chars()
            .any(|c| c == '/' || c == ':' || c == '?' || c.is_whitespace() || c.is_control())
        && !reserved_name(name)
}

/// A selector back into a container's name. `None` for everything that is not
/// a container: the main profile, a throwaway sandbox or container, an empty
/// string. `sb:<name>` is read as `<name>` — what it became unless the move
/// renamed it, which [`canonical`] knows.
pub fn parse_selector(selector: &str) -> Option<&str> {
    let name = selector.strip_prefix(SANDBOX_PREFIX).unwrap_or(selector);
    valid_name(name).then_some(name)
}

/// A selector as the container's name now, the move's renames included:
/// `sb:work` is `work-sb` when a layer took `work`.
pub fn canonical(tools: &Tools, selector: &str) -> Option<String> {
    canonical_in(&tools.config, selector)
}

/// [`canonical`], from the config dir alone.
pub fn canonical_in(config: &Path, selector: &str) -> Option<String> {
    let renamed = fs::read_to_string(config.join(POLICY_DIR).join(RENAMED)).unwrap_or_default();
    for line in renamed.lines() {
        if let Some((old, new)) = line.split_once('\t') {
            if old == selector && valid_name(new) {
                return Some(new.to_owned());
            }
        }
    }
    parse_selector(selector).map(str::to_owned)
}

/// The container a sandbox asked for by name (`--sandbox work`, `sb:work`)
/// is: a home of its own of that very name, when there is one; else what
/// the move renamed it to (`work-sb`, when a layer had the name); else the
/// name — once, never a rename of a rename.
pub fn sandbox_name(tools: &Tools, name: &str) -> Option<String> {
    let bare = name.strip_prefix(SANDBOX_PREFIX).unwrap_or(name);
    if load(tools, bare).is_some_and(|c| c.home == Home::Private) {
        return Some(bare.to_owned());
    }
    canonical(tools, &format!("{SANDBOX_PREFIX}{bare}"))
}

/// `key = value` lines, in order. Comments (`#`) and lines without `=` are
/// skipped; keys and values are trimmed; a key may repeat.
pub fn parse_conf(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

fn values<'a>(conf: &'a [(String, String)], key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    conf.iter()
        .filter(move |(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// The file a declared container lives in: `<name>.conf`, with its `home`.
pub fn declared_file(tools: &Tools, name: &str) -> PathBuf {
    declared_file_in(&tools.config, name)
}

/// [`declared_file`], from the config dir alone.
pub fn declared_file_in(config: &Path, name: &str) -> PathBuf {
    config.join(DECLARED).join(format!("{name}.conf"))
}

/// Settings as `key = value` pairs, in order.
type Conf = Vec<(String, String)>;

/// A declared container: its settings, and the kind of its home. The files
/// of the module before one name per container are read too:
/// `overlay-<name>.conf` and `private-<name>.conf`, with the kind in the
/// name and no `home` line — a file of the new kind always has one, which
/// is how the two are told apart.
fn read_declared(tools: &Tools, name: &str) -> Option<(Conf, Option<Home>)> {
    read_declared_in(&tools.config, name)
}

/// [`read_declared`], from the config dir alone.
fn read_declared_in(config: &Path, name: &str) -> Option<(Conf, Option<Home>)> {
    if let Ok(text) = fs::read_to_string(declared_file_in(config, name)) {
        let conf = parse_conf(&text);
        if let Some(home) = values(&conf, "home").last().and_then(Home::parse) {
            return Some((conf, Some(home)));
        }
    }
    for (prefix, home) in [("overlay-", Home::Layer), ("private-", Home::Private)] {
        let file = config.join(DECLARED).join(format!("{prefix}{name}.conf"));
        if let Ok(text) = fs::read_to_string(file) {
            let conf = parse_conf(&text);
            if values(&conf, "home").next().is_none() {
                return Some((conf, Some(home)));
            }
        }
    }
    None
}

/// Where the data of a container live, whatever its kind.
pub fn data_dir(tools: &Tools, name: &str) -> PathBuf {
    tools.profiles.join(name)
}

/// Where the policy of a container lives ([`POLICY_DIR`]).
pub fn policy_dir(tools: &Tools, name: &str) -> PathBuf {
    policy_dir_in(&tools.config, name)
}

/// [`policy_dir`], from the config dir alone.
pub fn policy_dir_in(config: &Path, name: &str) -> PathBuf {
    config.join(POLICY_DIR).join(name)
}

/// The files a container's policy is made of.
const POLICY_FILES: [&str; 4] = [FILE, PATHS_FILE, "perms", crate::trust::DIR];

/// What the move to this layout did, for the one who reads it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Moved {
    /// `(old selector, new name)` for every container whose name changed.
    pub renamed: Vec<(String, String)>,
    /// Directories that are no container's name and were left where they are.
    pub left: Vec<PathBuf>,
    /// What went wrong: the move is tried again at the next look.
    pub failed: Vec<String>,
}

/// Move everything into this version's layout — once, on the host, and
/// marked done ([`LAYOUT_MARK`]). Once, and not at every start: after the
/// move a file next to a container's data is nobody's business, and a
/// program with the data in reach could put one there, which a move at every
/// start would then take for its policy. In a zone nothing is moved: its
/// config is read-only there, and its state not the host's.
pub fn migrate(tools: &Tools) {
    if crate::launch::in_zone() {
        return;
    }
    let moved = migrate_in(
        &tools.config,
        &tools.profiles,
        &tools.sandboxes,
        &tools.state,
    );
    report_move(&moved);
    if layout_done(&tools.config) {
        for line in migrate_pins(tools) {
            eprintln!("cellward: {line}");
        }
    }
}

/// The mark that the programs' network pins became their containers'
/// networks ([`migrate_pins`]).
pub const PINS_MOVED: &str = ".pins-moved";

/// The container a program runs in without a question, as the pins and the
/// default say: a named one, the main home, a throwaway one, or none chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Owner {
    Named(String),
    Main,
    Throwaway,
    Free,
}

/// The name of the container of the main home a program pinned to `network`
/// in the main home goes to: `main-<network>`, a free name if that one is
/// something else.
fn main_container_name(tools: &Tools, network: &str) -> Option<String> {
    let base = format!("main-{network}");
    (1..100)
        .map(|n| {
            if n == 1 {
                base.clone()
            } else {
                format!("{base}-{n}")
            }
        })
        .filter(|name| valid_name(name))
        .find(|name| match load_quiet(tools, name) {
            None => true,
            Some(c) => {
                c.home == Home::Main && c.network.value == Network::Named(network.to_owned())
            }
        })
}

/// The container of the main home bound to `network`, made when there is
/// none (`main-<network>`): where a program of the main home goes when its
/// network is chosen "always" (`docs/PERMISSIONS.md` §11.8). Its settings are
/// written in one go: never a container of the main home with no network.
pub fn main_for_network(tools: &Tools, network: &str) -> Result<String, String> {
    let network = crate::launch::network_name(network);
    let name = main_container_name(tools, network)
        .ok_or_else(|| format!("нет имени для контейнера основного дома в сети {network}"))?;
    if load_quiet(tools, &name).is_none() {
        let file = policy_dir(tools, &name).join(FILE);
        let text = format!(
            "# Локальные настройки контейнера cellward (docs/CONTAINERS.md).\n\
             # Пишет `cellward container`; значения из Nix лежат в ~/.config/vpn-zones/declared.\n\
             home = {}\nnetwork = {network}\n",
            Home::Main.setting()
        );
        fs::create_dir_all(policy_dir(tools, &name))
            .and_then(|()| write_atomically(&file, &text))
            .map_err(|e| format!("не записать {}: {e}", file.display()))?;
    }
    Ok(name)
}

/// Is `network` one a launch can go to: `offline`, the host's, or a zone
/// that still has its config?
pub fn network_exists(tools: &Tools, network: &str) -> bool {
    network == crate::launch::OFFLINE
        || crate::launch::is_unconfined_name(network)
        || (!network.is_empty()
            && !network.contains('/')
            && tools.state.join(network).join("config.conf").is_file())
}

/// The network pinned to a program (`.pinned/<program>`) becomes the network
/// of the container the program runs in (`docs/PERMISSIONS.md` §11.8) —
/// once, on the host, after the layout is in place, and marked done
/// ([`PINS_MOVED`]).
///
/// * A named container the program is pinned to (or its own, `app-<key>`)
///   with no network yet takes it — when every program of the container
///   agrees: one without a pin was asked every time, and does not agree.
///   Where they do not, or the container runs in another network right now,
///   it stays "ask", and the pins are said.
/// * A container reached only through the global default is nobody's
///   choice for this program: binding it would send every new program into
///   that network unasked. It is left alone, as is one bound already or
///   declared in Nix.
/// * A program of the main home goes to a container of the main home bound
///   to that network, `main-<network>`.
/// * Otherwise the network is the last choice, where the question starts.
/// * A pin to a zone that is gone is dropped.
///
/// Each pin is taken away once handled; one that failed is tried again at
/// the next look. Returns what it did, for the one who reads it.
pub fn migrate_pins(tools: &Tools) -> Vec<String> {
    let root = tools.config.join(POLICY_DIR);
    let mark = root.join(PINS_MOVED);
    let pins_dir = tools.state.join(".pinned");
    if mark.exists() {
        return Vec::new();
    }
    let Ok(_guard) = registry::lock(&root) else {
        return Vec::new();
    };
    if mark.exists() {
        return Vec::new();
    }
    let mut said = Vec::new();
    let default = crate::cli::setting(tools, "default-profile")
        .map(|(v, _)| v)
        .unwrap_or_default();
    let all = load_all_quiet(tools);
    let owner_of = |key: &str| -> Owner {
        if let Some(c) = all.iter().find(|c| {
            c.apps
                .iter()
                .any(|a| a.value == key && a.source == Source::Nix)
        }) {
            return Owner::Named(c.name.clone());
        }
        let pinned =
            read_setting(&tools.state.join(".pinnedprofile").join(key)).unwrap_or_default();
        if !pinned.is_empty() {
            return match pinned.as_str() {
                "__main__" => Owner::Main,
                "__fs__" => Owner::Throwaway,
                other => canonical(tools, other).map_or(Owner::Free, Owner::Named),
            };
        }
        // Nothing pinned: the default says where it goes — but only `main`
        // and the program's own container are the program's; a named default
        // is shared, and nobody chose its network by pinning one program.
        match default.as_str() {
            "main" => Owner::Main,
            "own" => Owner::Named(format!("app-{key}")),
            _ => Owner::Free,
        }
    };

    let _ = fs::create_dir_all(tools.state.join(".last"));
    let _ = fs::create_dir_all(tools.state.join(".pinnedprofile"));
    let as_last = |key: &str, net: &str| {
        let _ = fs::write(tools.state.join(".last").join(key), net);
    };
    let mut proposals: std::collections::BTreeMap<String, Vec<(PathBuf, String, String)>> =
        std::collections::BTreeMap::new();
    let mut failed = false;
    let pins: Vec<PathBuf> = visible_entries(&pins_dir)
        .into_iter()
        .filter(|f| f.is_file())
        .collect();
    for file in &pins {
        let key = file
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let net = crate::launch::network_name(&read_setting(file).unwrap_or_default()).to_owned();
        if !network_exists(tools, &net) {
            said.push(format!("{key}: сети {net} больше нет — закрепление снято"));
            let _ = fs::remove_file(file);
            continue;
        }
        let owner = match owner_of(&key) {
            // A container that is gone is not made again for its pin — only
            // the program's own, which its first launch would have made.
            Owner::Named(name)
                if load_quiet(tools, &name).is_none() && !name.starts_with("app-") =>
            {
                Owner::Free
            }
            owner => owner,
        };
        match owner {
            Owner::Named(name) => proposals
                .entry(name)
                .or_default()
                .push((file.clone(), key, net)),
            Owner::Main => match main_for_network(tools, &net) {
                Ok(name) => match fs::write(tools.state.join(".pinnedprofile").join(&key), &name) {
                    Ok(()) => {
                        let _ = fs::remove_file(file);
                        said.push(format!(
                            "{key}: сеть {net} была закреплена за программой в основном \
                                 доме — теперь она в контейнере {name} (основной дом, сеть {net})"
                        ));
                    }
                    Err(e) => {
                        failed = true;
                        said.push(format!("{key}: не перенести закрепление сети {net}: {e}"));
                    }
                },
                Err(why) => {
                    failed = true;
                    said.push(format!("{key}: {why}"));
                }
            },
            Owner::Throwaway | Owner::Free => {
                as_last(&key, &net);
                let _ = fs::remove_file(file);
                said.push(format!(
                    "{key}: контейнер выбирается при запуске — сеть {net} больше не закреплена, \
                     окно начнёт с неё"
                ));
            }
        }
    }
    for (name, wanted) in &proposals {
        let container = load_quiet(tools, name);
        let settable = container
            .as_ref()
            .is_none_or(|c| c.network.source != Source::Nix && c.network.value == Network::Ask);
        let mut nets: Vec<&str> = wanted.iter().map(|(_, _, n)| n.as_str()).collect();
        nets.sort();
        nets.dedup();
        // Every program of the container has a say: one without a pin was
        // asked every time.
        let silent = container.as_ref().is_some_and(|c| {
            c.apps
                .iter()
                .any(|a| !wanted.iter().any(|(_, key, _)| *key == a.value))
        });
        let busy = container
            .as_ref()
            .and_then(|c| running_network(tools, c))
            .filter(|busy| nets.len() != 1 || busy != nets[0]);
        let bind = settable && nets.len() == 1 && !silent && busy.is_none();
        if !bind {
            for (file, key, net) in wanted {
                as_last(key, net);
                let _ = fs::remove_file(file);
            }
            if settable {
                let why = match busy {
                    Some(busy) => format!("его программы сейчас работают в сети {busy}"),
                    None if nets.len() > 1 => format!(
                        "его программы были закреплены за разными сетями ({})",
                        nets.join(", ")
                    ),
                    None => "не все его программы были закреплены за сетью".to_owned(),
                };
                said.push(format!(
                    "контейнер {name}: {why} — сеть контейнера не выбрана, спросится при запуске"
                ));
            }
            continue;
        }
        // The program's own container that was never launched: made now, a
        // home of its own, as its first launch would have made it.
        let file = policy_dir(tools, name).join(FILE);
        let made = match container {
            Some(_) => write_key(&file, "network", Some(nets[0]), true),
            None => write_key(&file, "home", Some(Home::Private.setting()), true)
                .and_then(|()| write_key(&file, "network", Some(nets[0]), true)),
        };
        match made {
            Ok(()) => {
                for (file, _, _) in wanted {
                    let _ = fs::remove_file(file);
                }
                said.push(format!("контейнер {name} теперь в сети {}", nets[0]));
            }
            Err(e) => {
                failed = true;
                said.push(format!("контейнер {name}: не записать сеть: {e}"));
            }
        }
    }
    if !failed {
        let _ = fs::write(&mark, "");
    }
    said
}

/// [`migrate`] for a home, where no manifest is at hand
/// (`fs_sandbox::settle_permissions`).
pub fn migrate_home(home: &Path) {
    if crate::launch::in_zone() {
        return;
    }
    let moved = migrate_in(
        &home.join(".config/vpn-zones"),
        &home.join(PROFILES_SUBDIR),
        &home.join(".local/state/vpn-sandboxes"),
        &home.join(".local/state/vpn-zones"),
    );
    report_move(&moved);
}

fn report_move(moved: &Moved) {
    for (old, new) in &moved.renamed {
        eprintln!("cellward: контейнер {old} теперь называется {new}");
    }
    for dir in &moved.left {
        eprintln!(
            "cellward: {} — не имя контейнера, оставлен на месте",
            dir.display()
        );
    }
    for why in &moved.failed {
        eprintln!("cellward: {why}");
    }
}

/// The plan of the move, written before anything moves and followed to the
/// end by every try: `<kind>\t<old name>\t<new name>` a line. A second look
/// that scanned again would take a sandbox already moved in for a layer.
const LAYOUT_PLAN: &str = ".layout-plan";

/// The kind of home Nix declares for a name, from the config dir alone: the
/// file of one name per container, or one of the files from before it.
fn declared_home_in(config: &Path, name: &str) -> Option<Home> {
    let dir = config.join(DECLARED);
    if let Ok(text) = fs::read_to_string(dir.join(format!("{name}.conf"))) {
        if let Some(home) = values(&parse_conf(&text), "home")
            .last()
            .and_then(Home::parse)
        {
            return Some(home);
        }
    }
    [("overlay-", Home::Layer), ("private-", Home::Private)]
        .into_iter()
        .find(|(prefix, _)| dir.join(format!("{prefix}{name}.conf")).is_file())
        .map(|(_, home)| home)
}

/// Every container of the layouts before, and the name each will have.
///
/// A layer (`profiles/<n>`) keeps its own name; a home of its own
/// (`sandboxes/<n>`) keeps it unless a layer has it or Nix declares it with
/// another kind of home — then `<n>-sb`; a name that became a word of ours
/// gets `-2`. What cannot be a name at all stays where it is, and is said.
/// An empty data directory with no policy, which home-manager makes for a
/// declared container before anything moves, takes nobody's name — unless
/// Nix declares it as that kind.
fn plan_move(
    config: &Path,
    profiles: &Path,
    sandboxes: &Path,
    moved: &mut Moved,
) -> Vec<(Home, String, String)> {
    let root = config.join(POLICY_DIR);
    let mut old: Vec<(Home, String)> = Vec::new();
    for (kind, data, sub) in [
        (Home::Layer, profiles, "profiles"),
        (Home::Private, sandboxes, "sandboxes"),
    ] {
        let mut names: Vec<String> = Vec::new();
        for dir in [data.to_path_buf(), root.join(sub)] {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                // A container's own directory, never a link to one.
                if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') || names.contains(&name) {
                    continue;
                }
                names.push(name);
            }
        }
        names.sort();
        old.extend(names.into_iter().map(|n| (kind, n)));
    }
    let hollow = |name: &str| {
        fs::read_dir(profiles.join(name)).is_ok_and(|mut d| d.next().is_none())
            && !root.join("profiles").join(name).exists()
            && declared_home_in(config, name).is_none_or(|home| home == Home::Private)
    };
    let privates: Vec<String> = old
        .iter()
        .filter(|(kind, _)| *kind == Home::Private)
        .map(|(_, n)| n.clone())
        .collect();
    old.retain(|(kind, name)| !(*kind == Home::Layer && privates.contains(name) && hollow(name)));

    // A layer gives its name to a sandbox that Nix declares under it: the
    // declaration is the sandbox's, and so are its network and trust.
    let yields = |kind: Home, name: &str| {
        kind == Home::Layer
            && privates.iter().any(|p| p == name)
            && declared_home_in(config, name) == Some(Home::Private)
    };
    // The names that stay: every layer that has a good one and does not give
    // it up, and every name Nix declares as something other than a home of
    // its own. Then the rest find a free one around them.
    let mut taken: Vec<String> = old
        .iter()
        .filter(|(kind, name)| *kind == Home::Layer && valid_name(name) && !yields(*kind, name))
        .map(|(_, name)| name.clone())
        .collect();
    let declared_other =
        |name: &str| declared_home_in(config, name).is_some_and(|h| h != Home::Private);
    // And every sandbox that can keep its own name keeps it: a rename never
    // lands on the name of a sandbox that stays — a stale `sb:<name>` then
    // means one container only.
    let keepers: Vec<String> = privates
        .iter()
        .filter(|name| {
            valid_name(name)
                && !taken.iter().any(|t| t == *name)
                && !declared_other(name)
                && (fs::symlink_metadata(profiles.join(name)).is_err()
                    || hollow(name)
                    || yields(Home::Layer, name))
        })
        .cloned()
        .collect();
    taken.extend(keepers.iter().cloned());
    let mut plan: Vec<(Home, String, String)> = Vec::new();
    for (kind, name) in &old {
        if *kind == Home::Private && keepers.contains(name) {
            plan.push((*kind, name.clone(), name.clone()));
            continue;
        }
        let data = match kind {
            Home::Private => sandboxes.join(name),
            _ => profiles.join(name),
        };
        if *kind == Home::Layer && valid_name(name) && !yields(*kind, name) {
            plan.push((*kind, name.clone(), name.clone()));
            continue;
        }
        let (base, suffix) = if yields(*kind, name) {
            (name.clone(), "-layer")
        } else if valid_name(name) {
            (name.clone(), "-sb")
        } else if reserved_name(name) && valid_name(&format!("{name}-2")) {
            // A word of ours now (`main`, `ask`…): the name with a number.
            // Not a reserved beginning (`vpn-profile-…`): no number makes
            // that a name.
            (name.clone(), "-")
        } else {
            if data.is_dir() {
                moved.left.push(data);
            }
            continue;
        };
        let hollow_target = |new: &str| *kind == Home::Private && hollow(new);
        let free = |new: &str| {
            valid_name(new)
                && !taken.iter().any(|t| t == new)
                && !declared_other(new)
                && (profiles.join(new) == data
                    || fs::symlink_metadata(profiles.join(new)).is_err()
                    || hollow_target(new)
                    // The layer that gives the name up moves out first.
                    || (*kind == Home::Private && new == name && yields(Home::Layer, new)))
        };
        let mut new = if suffix == "-layer" {
            format!("{base}-layer")
        } else {
            base.clone()
        };
        let mut n = 1;
        while !free(&new) {
            n += 1;
            if n > 1000 {
                break;
            }
            new = match (suffix, n) {
                ("-sb", 2) => format!("{base}-sb"),
                ("-sb", _) => format!("{base}-sb{}", n - 1),
                ("-layer", _) => format!("{base}-layer{n}"),
                _ => format!("{base}-{n}"),
            };
        }
        if !free(&new) {
            if data.is_dir() {
                moved.left.push(data);
            }
            continue;
        }
        taken.push(new.clone());
        plan.push((*kind, name.clone(), new));
    }
    plan
}

/// One container of the plan: its kind before, its old name, its new one,
/// and whether its move is done — a later try touches only what is not: a
/// container moved already may have been changed since.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Step {
    kind: Home,
    old: String,
    new: String,
    done: bool,
}

fn read_plan(file: &Path) -> Option<Vec<Step>> {
    let text = fs::read_to_string(file).ok()?;
    let mut plan = Vec::new();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let mut parts = line.split('\t');
        let (Some(kind), Some(old), Some(new), done, None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return None;
        };
        plan.push(Step {
            kind: Home::parse(kind)?,
            old: old.to_owned(),
            new: new.to_owned(),
            done: done == Some("done"),
        });
    }
    Some(plan)
}

fn write_plan(file: &Path, plan: &[Step]) -> io::Result<()> {
    let mut text = String::new();
    for step in plan {
        text.push_str(&format!(
            "{}\t{}\t{}{}\n",
            step.kind.setting(),
            step.old,
            step.new,
            if step.done { "\tdone" } else { "" }
        ));
    }
    write_atomically(file, &text)
}

/// Is this version's layout in place ([`LAYOUT_MARK`])?
pub fn layout_done(config: &Path) -> bool {
    fs::read_to_string(config.join(POLICY_DIR).join(LAYOUT_MARK)).is_ok_and(|t| t.trim() == LAYOUT)
}

fn write_atomically(file: &Path, text: &str) -> io::Result<()> {
    let tmp = file.with_extension("tmp");
    fs::write(&tmp, text)?;
    fs::rename(&tmp, file)
}

/// The names whose move has not finished: their data are still where the
/// layout before kept them. A launch of one is refused rather than started
/// with an empty home next to its data ([`migrate`]).
pub fn move_pending(tools: &Tools, name: &str) -> bool {
    move_pending_in(&tools.config, &tools.sandboxes, name)
}

/// [`move_pending`], from the directories alone.
pub fn move_pending_in(config: &Path, sandboxes: &Path, name: &str) -> bool {
    if layout_done(config) {
        return false;
    }
    match read_plan(&config.join(POLICY_DIR).join(LAYOUT_PLAN)) {
        // Any container not moved yet: its data may be where the launch would
        // not look, or its policy — its network among it — not in place.
        Some(plan) => plan.iter().any(|step| step.new == name && !step.done),
        None => fs::symlink_metadata(sandboxes.join(name)).is_ok_and(|m| m.is_dir()),
    }
}

/// [`migrate`], from the directories alone, wherever it runs. Under a lock:
/// the first pickers at a login after an update start together.
///
/// 1. The plan ([`plan_move`]), written first ([`LAYOUT_PLAN`]), and the
///    renames with it ([`RENAMED`]): a stale `sb:<name>` finds the new name
///    even while the move is not done.
/// 2. The policy into `containers/<name>/`: from the previous layout's
///    `containers/{profiles,sandboxes}/<n>/`, or — only when that one never
///    ran — from next to the data. Plain files only: a link stays where it
///    is. A file already in place is kept. The kind of home is the plan's,
///    written over whatever a moved file said: the files next to the data
///    were in reach of programs.
/// 3. The data of a home of its own into the one data directory: a rename,
///    on one disk — a running program keeps what it has open. Across disks
///    nothing is copied: the move stops, and says so.
/// 4. The picker's memory and the default follow a renamed container.
pub fn migrate_in(config: &Path, profiles: &Path, sandboxes: &Path, state: &Path) -> Moved {
    let root = config.join(POLICY_DIR);
    let mut moved = Moved::default();
    if layout_done(config) {
        return moved;
    }
    let _guard = match registry::lock(&root) {
        Ok(guard) => guard,
        Err(e) => {
            moved
                .failed
                .push(format!("не взять замок {}: {e}", root.display()));
            return moved;
        }
    };
    if layout_done(config) {
        return moved;
    }
    let policy_moved_before = root.join(LAYOUT_1_MARK).exists();

    let plan_file = root.join(LAYOUT_PLAN);
    let mut plan = match read_plan(&plan_file) {
        Some(plan) => plan,
        None => {
            let plan: Vec<Step> = plan_move(config, profiles, sandboxes, &mut moved)
                .into_iter()
                .map(|(kind, old, new)| Step {
                    kind,
                    old,
                    new,
                    done: false,
                })
                .collect();
            let mut renamed = fs::read_to_string(root.join(RENAMED)).unwrap_or_default();
            for step in &plan {
                if step.kind == Home::Private && step.old != step.new {
                    renamed.push_str(&format!("{SANDBOX_PREFIX}{}\t{}\n", step.old, step.new));
                }
            }
            let written = write_atomically(&root.join(RENAMED), &renamed)
                .and_then(|()| write_plan(&plan_file, &plan));
            if let Err(e) = written {
                moved.failed.push(format!(
                    "не записать план переноса в {}: {e}",
                    root.display()
                ));
                return moved;
            }
            plan
        }
    };

    for index in 0..plan.len() {
        if plan[index].done {
            continue;
        }
        let step = plan[index].clone();
        let (kind, name, new) = (&step.kind, &step.old, &step.new);
        let (data, sub) = match kind {
            Home::Private => (sandboxes.join(name), "sandboxes"),
            _ => (profiles.join(name), "profiles"),
        };
        let target = policy_dir_in(config, new);
        let sources: Vec<PathBuf> = if policy_moved_before {
            vec![root.join(sub).join(name)]
        } else {
            vec![root.join(sub).join(name), data.clone()]
        };
        // A layer that changes its name waits for its programs: their records
        // are under the old name, and while they live the new one would not
        // see them run (one network at a time, `container rm`).
        if *kind == Home::Layer && name != new {
            let running = state.join(".running");
            if registry::any_live(&running.join(name), &|pid| registry::alive(&running, pid)) {
                moved.failed.push(format!(
                    "программы контейнера {name} работают — он станет {new}, когда они закроются"
                ));
                continue;
            }
        }
        let failed_before = moved.failed.len();
        for source in &sources {
            for file in POLICY_FILES {
                let from = source.join(file);
                let to = target.join(file);
                if fs::symlink_metadata(&to).is_ok() {
                    continue;
                }
                if let Err(e) = move_policy_file(&from, &to) {
                    moved.failed.push(format!(
                        "не перенести {} в {}: {e}",
                        from.display(),
                        to.display()
                    ));
                }
            }
        }
        // Its data stay where they are until its policy is in place, and its
        // kind is not written either: the next try must find the container as
        // it was, the file that did not move still to be moved.
        if moved.failed.len() > failed_before {
            continue;
        }
        // The kind, the plan's: the shape of the data is no proof of it, and
        // a moved file no word on it.
        if let Err(e) = write_key(&target.join(FILE), "home", Some(kind.setting()), true) {
            moved.failed.push(e);
            continue;
        }
        let _ = fs::remove_dir(root.join(sub).join(name));

        let into = profiles.join(new);
        let data_is_dir = fs::symlink_metadata(&data).is_ok_and(|m| m.is_dir());
        if data != into && data_is_dir {
            // The empty directory home-manager made for the name before the
            // move: nobody's.
            let empty = fs::read_dir(&into).is_ok_and(|mut d| d.next().is_none());
            if empty {
                let _ = fs::remove_dir(&into);
            }
            if fs::symlink_metadata(&into).is_ok() {
                moved.failed.push(format!(
                    "{} уже есть — данные {} остались на месте; разберись с ними вручную",
                    into.display(),
                    data.display()
                ));
                continue;
            }
            let renamed = fs::create_dir_all(profiles).and_then(|()| fs::rename(&data, &into));
            if let Err(e) = renamed {
                let why = if e.raw_os_error() == Some(libc::EXDEV) {
                    "они на другом диске — перенеси каталог вручную".to_owned()
                } else {
                    e.to_string()
                };
                moved.failed.push(format!(
                    "не перенести {} в {}: {why}; запуски контейнера {new} до того отказаны",
                    data.display(),
                    into.display()
                ));
                continue;
            }
        }
        if fs::symlink_metadata(&into).is_ok_and(|m| m.is_dir()) {
            let _ = fs::write(into.join(DATA_KIND), kind.setting());
        }
        let old_selector = match kind {
            Home::Private => format!("{SANDBOX_PREFIX}{name}"),
            _ => name.clone(),
        };
        if *name != *new && !moved.renamed.iter().any(|(o, _)| *o == old_selector) {
            moved.renamed.push((old_selector.clone(), new.clone()));
        }
        if old_selector != *new {
            follow_rename(config, state, &old_selector, new);
        }
        plan[index].done = true;
        if let Err(e) = write_plan(&plan_file, &plan) {
            moved.failed.push(format!("не записать план переноса: {e}"));
        }
    }
    for sub in ["profiles", "sandboxes"] {
        let _ = fs::remove_dir(root.join(sub));
    }

    // Done only when everything went: a move that failed is tried again at
    // the next look, rather than a binding or a trust left behind in silence.
    if moved.failed.is_empty() {
        match fs::write(root.join(LAYOUT_MARK), LAYOUT) {
            Ok(()) => {
                let _ = fs::remove_file(&plan_file);
            }
            Err(e) => moved
                .failed
                .push(format!("не записать {}: {e}", root.display())),
        }
    }
    moved
}

/// A container renamed by the move: the picker's memory and the local
/// default say its new name. A word of ours that was a name (`main`) is not
/// followed in the default: as a word it means itself.
fn follow_rename(config: &Path, state: &Path, old: &str, new: &str) {
    for sub in [".pinnedprofile", ".lastprofile"] {
        for file in visible_entries(&state.join(sub)) {
            if read_setting(&file).as_deref() == Some(old) {
                let _ = fs::write(&file, new);
            }
        }
    }
    if !reserved_name(old) {
        let default = config.join("default-profile");
        if read_setting(&default).as_deref() == Some(old) {
            let _ = fs::write(&default, new);
        }
    }
}

/// Move one policy file of the old layout, if it is one: a regular file, or
/// `trust/` as a real directory of regular files. A link — to anything — is
/// left where it is: moved, it would stay a link into wherever it points, and
/// the policy would be read and written through it. Across filesystems (the
/// config and the state on separate mounts) a copy, then the original gone.
fn move_policy_file(old: &Path, new: &Path) -> io::Result<()> {
    let Ok(meta) = fs::symlink_metadata(old) else {
        return Ok(());
    };
    let files: Vec<PathBuf> = if meta.is_file() {
        Vec::new()
    } else if meta.is_dir() {
        let mut files = Vec::new();
        for entry in fs::read_dir(old)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                return Err(io::Error::other(format!(
                    "{} is not a plain file — left where it is",
                    entry.path().display()
                )));
            }
            files.push(entry.path());
        }
        files
    } else {
        return Err(io::Error::other("neither a plain file nor a directory"));
    };
    if let Some(parent) = new.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::rename(old, new) {
        Ok(()) => return Ok(()),
        Err(e) if e.raw_os_error() != Some(libc::EXDEV) => return Err(e),
        Err(_) => {}
    }
    if meta.is_file() {
        fs::copy(old, new)?;
        return fs::remove_file(old);
    }
    fs::create_dir_all(new)?;
    for file in &files {
        if let Some(name) = file.file_name() {
            fs::copy(file, new.join(name))?;
        }
    }
    fs::remove_dir_all(old)
}

/// Set (`Some`) or drop (`None`) one key of a settings file, keeping the rest.
/// With `replace` false an existing key is left as it is.
pub fn write_key(path: &Path, key: &str, value: Option<&str>, replace: bool) -> Result<(), String> {
    edit_conf(path, |conf| {
        if !replace && conf.iter().any(|(k, _)| k == key) {
            return false;
        }
        conf.retain(|(k, _)| k != key);
        if let Some(value) = value {
            conf.push((key.to_owned(), value.to_owned()));
        }
        true
    })
}

/// Every value of `key` in a settings file set to `values` (one line each,
/// in order), the rest kept — a list, as `device`.
pub fn write_values(path: &Path, key: &str, values: &[String]) -> Result<(), String> {
    edit_conf(path, |conf| {
        conf.retain(|(k, _)| k != key);
        conf.extend(values.iter().map(|v| (key.to_owned(), v.clone())));
        true
    })
}

/// A settings file read, changed by `change` (`false`: nothing to write),
/// and written back — one writer at a time, through a temporary.
fn edit_conf(path: &Path, change: impl FnOnce(&mut Conf) -> bool) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{}: не файл в каталоге", path.display()))?;
    fs::create_dir_all(parent).map_err(|e| format!("не создать {}: {e}", parent.display()))?;
    // One writer at a time: the directory's lock held while its file is
    // read, changed and replaced — the command line and the sound filter's
    // "always" write the same file, and one must not drop the other's key.
    // A lock file, not the directory: `flock` of a directory opened for
    // reading fails on NFS.
    let lock =
        registry::lock(parent).map_err(|e| format!("не занять {}: {e}", parent.display()))?;
    // A file that is there and cannot be read is not rewritten: its other
    // settings would be lost with it.
    let mut conf: Conf = match fs::read_to_string(path) {
        Ok(text) => parse_conf(&text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(format!("не прочитать {}: {e}", path.display())),
    };
    if !change(&mut conf) {
        return Ok(());
    }
    let mut text = String::from(
        "# Локальные настройки контейнера cellward (docs/CONTAINERS.md).\n\
         # Пишет `cellward container`; значения из Nix лежат в ~/.config/vpn-zones/declared.\n",
    );
    for (k, v) in &conf {
        text.push_str(&format!("{k} = {v}\n"));
    }
    // Through a temporary: the zone's helpers read these files while the
    // command line and the sound filter's "always" write them, and half a
    // file is a setting nobody made.
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}.new", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let written = fs::write(&tmp, text)
        .and_then(|()| fs::rename(&tmp, path))
        .map_err(|e| {
            let _ = fs::remove_file(&tmp);
            format!("не записать {}: {e}", path.display())
        });
    drop(lock);
    written
}

/// The kind of home the data of a container are in, when nothing says it:
/// a layer has `home/upper`, a home of its own `home/`. A directory with
/// neither — a layer never launched since the whole-home layer, with its old
/// slots — is a layer; nothing at all is a home of its own, the standard.
fn kind_of_data(dir: &Path) -> Home {
    let mark = dir.join(DATA_KIND);
    if let Some(kind) = fs::symlink_metadata(&mark)
        .is_ok_and(|m| m.is_file())
        .then(|| fs::read_to_string(&mark).ok())
        .flatten()
        .and_then(|t| Home::parse(&t))
    {
        return kind;
    }
    if dir.join("home/upper").is_dir() {
        Home::Layer
    } else if dir.join("home").is_dir() || !dir.is_dir() {
        Home::Private
    } else {
        Home::Layer
    }
}

/// Is the data directory a real directory, or not there at all? A link in
/// its place, or in the place of its `home`, is refused: bwrap binds `home`,
/// and a link would lead it anywhere.
fn no_link(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(format!(
            "{} — ссылка, а не каталог: запуск остановлен",
            path.display()
        )),
        _ => Ok(()),
    }
}

fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

/// Are a container's data the kind its settings say — nothing to set aside
/// or bring back ([`prepare_data`])?
pub fn data_ready(container: &Container) -> bool {
    let dir = &container.dir;
    if !is_real_dir(dir) {
        return true;
    }
    let has = kind_of_data(dir);
    has == container.home
        || (!is_real_dir(&dir.join("home"))
            && !is_real_dir(&dir.join(format!("home.{}", container.home.setting()))))
}

/// Make a container's data the kind its settings say, before a launch: when
/// the kind changed, the data of the old one go aside (`home.<old kind>`) and
/// those of the new one, if they were set aside before, come back. The main
/// home has no data of its own: what an earlier kind left goes aside too.
/// Nothing is erased; what cannot be moved stops the launch.
pub fn prepare_data(container: &Container) -> Result<(), String> {
    let dir = &container.dir;
    no_link(dir)?;
    if container.home == Home::Main && fs::symlink_metadata(dir).is_err() {
        return Ok(());
    }
    fs::create_dir_all(dir).map_err(|e| format!("не создать {}: {e}", dir.display()))?;
    let home = dir.join("home");
    no_link(&home)?;
    let has = kind_of_data(dir);
    if has != container.home && fs::symlink_metadata(&home).is_ok() {
        let aside = dir.join(format!("home.{}", has.setting()));
        if fs::symlink_metadata(&aside).is_ok() {
            return Err(format!(
                "у контейнера {} сменился вид дома, а {} уже занят — разберись с ним вручную",
                container.name,
                aside.display()
            ));
        }
        fs::rename(&home, &aside).map_err(|e| format!("не отложить {}: {e}", home.display()))?;
    }
    if has != container.home {
        let back = dir.join(format!("home.{}", container.home.setting()));
        if is_real_dir(&back) && fs::symlink_metadata(&home).is_err() {
            fs::rename(&back, &home).map_err(|e| format!("не вернуть {}: {e}", back.display()))?;
        }
    }
    // A home of its own is its `home/`, there from the start.
    if container.home == Home::Private {
        fs::create_dir_all(&home).map_err(|e| format!("не создать {}: {e}", home.display()))?;
    }
    fs::write(dir.join(DATA_KIND), container.home.setting())
        .map_err(|e| format!("не записать {}: {e}", dir.join(DATA_KIND).display()))
}

/// Whether the container `name` is one: its data, its policy or its
/// declaration is there ([`load`]'s rule) — from the directories alone, for
/// the zone's helpers, which have no manifest. No move, no renames: `name`
/// is a name already.
pub fn exists_in(config: &Path, profiles: &Path, name: &str) -> bool {
    valid_name(name)
        && (profiles.join(name).is_dir()
            || policy_dir_in(config, name).is_dir()
            || read_declared_in(config, name).is_some())
}

/// A container's own value of `key` and where it is from: Nix's
/// declaration, else its local settings; `None` without either. For the
/// zone's helpers (the config dir alone). `Err(source)`: a file that is
/// there and cannot be read — what it says is not known, and a caller that
/// must be safe takes the strictest value.
pub fn own_value_in(
    config: &Path,
    name: &str,
    key: &str,
) -> Result<Option<(String, Source)>, Source> {
    let declared = declared_file_in(config, name);
    match fs::read_to_string(&declared) {
        Ok(text) => {
            let conf = parse_conf(&text);
            // A file of this kind always has its `home`; `<name>.conf`
            // without one is the old module's file of another container
            // (`overlay-<x>.conf` of `x`), not this one's.
            if values(&conf, "home").next().is_some() {
                if let Some(value) = values(&conf, key).last() {
                    return Ok(Some((value.to_owned(), Source::Nix)));
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Source::Nix),
    }
    match fs::read_to_string(policy_dir_in(config, name).join(FILE)) {
        Ok(text) => Ok(values(&parse_conf(&text), key)
            .last()
            .map(|value| (value.to_owned(), Source::Local))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(Source::Local),
    }
}

/// A container's own on/off `key` and where it is from ([`own_value_in`]):
/// `true`/`on` is on, anything else off — and a file that cannot be read is
/// off, where it is.
pub fn own_flag_in(config: &Path, name: &str, key: &str) -> Option<(bool, Source)> {
    match own_value_in(config, name, key) {
        Ok(own) => own.map(|(word, source)| (matches!(word.as_str(), "true" | "on"), source)),
        Err(source) => Some((false, source)),
    }
}

/// Whether a launch of the container `name` into the zone in `zone_dir`
/// reaches the host's cameras (`docs/PERMISSIONS.md` §11.10): Nix's word for
/// the container, then Nix's for the zone — a local word never overrides a
/// declared one —, then the container's own, then the zone's.
pub fn camera_for(zone_dir: &Path, config: &Path, zone: &str, name: &str) -> bool {
    let zone_setting = crate::hermetic::camera(zone_dir, config, zone);
    match own_flag_in(config, name, "camera") {
        Some((on, Source::Nix)) => on,
        _ if zone_setting.1 == Source::Nix => zone_setting.0,
        Some((on, _)) => on,
        None => zone_setting.0,
    }
}

/// Read one container. `None` when it neither exists on disk nor is declared.
pub fn load(tools: &Tools, selector: &str) -> Option<Container> {
    migrate(tools);
    load_quiet(tools, selector)
}

/// [`load`] without the move: for the move itself.
fn load_quiet(tools: &Tools, selector: &str) -> Option<Container> {
    let name = canonical(tools, selector)?;
    let name = name.as_str();
    let dir = data_dir(tools, name);
    let policy = policy_dir(tools, name);
    let declared = read_declared(tools, name);
    // A container is its data, its policy or its declaration: a program with
    // its storage in reach removing the data directory must not make its
    // network binding disappear with it.
    if !dir.is_dir() && !policy.is_dir() && declared.is_none() {
        return None;
    }
    let local = fs::read_to_string(policy.join(FILE))
        .map(|t| parse_conf(&t))
        .unwrap_or_default();
    let declared_conf = declared.as_ref().map(|(conf, _)| conf.as_slice());

    let (home, home_source) = match declared.as_ref().and_then(|(_, home)| *home) {
        Some(home) => (home, Source::Nix),
        None => match values(&local, "home").last().and_then(Home::parse) {
            Some(home) => (home, Source::Local),
            None => (kind_of_data(&dir), Source::Default),
        },
    };

    let network = declared_conf
        .and_then(|conf| values(conf, "network").last().and_then(Network::parse))
        .map(|value| Sourced {
            value,
            source: Source::Nix,
        })
        .or_else(|| {
            values(&local, "network")
                .last()
                .and_then(Network::parse)
                .map(|value| Sourced {
                    value,
                    source: Source::Local,
                })
        })
        .unwrap_or(Sourced {
            value: Network::Ask,
            source: Source::Default,
        });

    let mut apps: Vec<Sourced<String>> = Vec::new();
    if let Some(conf) = declared_conf {
        for app in values(conf, "app") {
            apps.push(Sourced {
                // The key the picker remembers it under (`stable_key`).
                value: crate::desktop::stable_key(app),
                source: Source::Nix,
            });
        }
    }
    // The picker's container pins are the local assignments.
    for file in visible_entries(&tools.state.join(".pinnedprofile")) {
        let Some(key) = file.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        let pinned = read_setting(&file).and_then(|s| canonical(tools, &s));
        if pinned.as_deref() == Some(name) && !apps.iter().any(|a| a.value == key) {
            apps.push(Sourced {
                value: key,
                source: Source::Local,
            });
        }
    }

    let declared_trust = declared_conf
        .map(|conf| values(conf, "trust").map(PathBuf::from).collect())
        .unwrap_or_default();

    let mut paths: Vec<Sourced<PathBuf>> = Vec::new();
    if let Some(conf) = declared_conf {
        for path in values(conf, "path") {
            paths.push(Sourced {
                value: expand_home(&tools.home, path),
                source: Source::Nix,
            });
        }
    }
    let mut expires = Vec::new();
    if let Ok(text) = fs::read_to_string(policy.join(PATHS_FILE)) {
        let now = now();
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let (path, until) = grant_line(line);
            // Over is over, whether or not anything has cleaned it up yet.
            if until.is_some_and(|u| u <= now) || path.is_empty() {
                continue;
            }
            let value = expand_home(&tools.home, path);
            if !paths.iter().any(|p| p.value == value) {
                if let Some(until) = until {
                    expires.push((value.clone(), until));
                }
                paths.push(Sourced {
                    value,
                    source: Source::Local,
                });
            }
        }
    }

    let flag = |conf: &[(String, String)]| {
        values(conf, "x11")
            .last()
            .map(|v| matches!(v, "true" | "on" | "yes"))
    };
    let x11 = declared_conf
        .and_then(flag)
        .map(|value| Sourced {
            value,
            source: Source::Nix,
        })
        .or_else(|| {
            flag(&local).map(|value| Sourced {
                value,
                source: Source::Local,
            })
        })
        .unwrap_or(Sourced {
            value: false,
            source: Source::Default,
        });

    let color = |conf: &[(String, String)]| {
        values(conf, "frame_color")
            .last()
            .and_then(crate::frame::Rgb::parse)
            .map(|c| c.hex())
    };
    let frame_color = declared_conf
        .and_then(color)
        .map(|value| Sourced {
            value,
            source: Source::Nix,
        })
        .or_else(|| {
            color(&local).map(|value| Sourced {
                value,
                source: Source::Local,
            })
        });

    // Read the way the sound filter reads it (`microphone::container_setting`):
    // what is shown is what decides.
    let microphone = crate::microphone::container_setting(&tools.config, name)
        .map(|(value, source)| Sourced { value, source });
    let screencast = crate::microphone::container_switch(&tools.config, name, "screencast")
        .map(|(value, source)| Sourced { value, source });
    let camera =
        own_flag_in(&tools.config, name, "camera").map(|(value, source)| Sourced { value, source });
    // Words that are no grant are left out: nothing is given by a typo.
    let mut devices: Vec<Sourced<String>> = Vec::new();
    let declared_devices: Vec<&str> = declared_conf
        .map(|conf| values(conf, "device").collect())
        .unwrap_or_default();
    for (word, source) in declared_devices
        .into_iter()
        .map(|w| (w, Source::Nix))
        .chain(values(&local, "device").map(|w| (w, Source::Local)))
    {
        if let Some(grant) = crate::devices::Grant::parse(word) {
            let value = grant.word();
            if !devices.iter().any(|d| d.value == value) {
                devices.push(Sourced { value, source });
            }
        }
    }
    // One rule a scheme, the declared one before a local one.
    let mut links: Vec<Sourced<(String, String)>> = Vec::new();
    let declared_links: Vec<&str> = declared_conf
        .map(|conf| values(conf, "link").collect())
        .unwrap_or_default();
    for (word, source) in declared_links
        .into_iter()
        .map(|w| (w, Source::Nix))
        .chain(values(&local, "link").map(|w| (w, Source::Local)))
    {
        if let Some(value) = crate::links::parse_rule(word) {
            if !links.iter().any(|l| l.value.0 == value.0) {
                links.push(Sourced { value, source });
            }
        }
    }

    Some(Container {
        name: name.to_owned(),
        home,
        home_source,
        network,
        apps,
        frame_color,
        microphone,
        screencast,
        camera,
        devices,
        links,
        declared_trust,
        paths,
        expires,
        x11,
        dir,
        policy,
    })
}

/// Every container: the data and policy directories, and the declared ones
/// that have neither yet. Sorted by name.
pub fn load_all(tools: &Tools) -> Vec<Container> {
    migrate(tools);
    load_all_quiet(tools)
}

/// [`load_all`] without the move: for the move itself.
fn load_all_quiet(tools: &Tools) -> Vec<Container> {
    let mut names: Vec<String> = Vec::new();
    for dir in [&tools.profiles, &tools.config.join(POLICY_DIR)] {
        for entry in visible_entries(dir) {
            if entry.is_dir() {
                names.push(
                    entry
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    for file in visible_entries(&tools.config.join(DECLARED)) {
        let name = file
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let Some(stem) = name.strip_suffix(".conf") else {
            continue;
        };
        let conf = fs::read_to_string(&file)
            .map(|t| parse_conf(&t))
            .unwrap_or_default();
        if values(&conf, "home").next().is_some() {
            names.push(stem.to_owned());
        } else if let Some(n) = stem
            .strip_prefix("overlay-")
            .or_else(|| stem.strip_prefix("private-"))
        {
            names.push(n.to_owned());
        }
    }
    names.retain(|n| valid_name(n));
    names.sort();
    names.dedup();
    names.iter().filter_map(|n| load_quiet(tools, n)).collect()
}

/// `~/x` against the home; anything else as it is.
pub fn expand_home(home: &Path, path: &str) -> PathBuf {
    match path.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None if path == "~" => home.to_path_buf(),
        None => PathBuf::from(path),
    }
}

/// `.` and `..` folded away without touching the filesystem.
pub fn lexical(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// A path as the filesystem resolves it, including a part that does not exist
/// yet: the deepest existing ancestor canonicalized, the rest appended as
/// written. `None` when not even `/` resolves.
///
/// A grant is checked this way BEFORE its directory is created — creating it
/// first would already have written through a symlink into wherever it
/// points.
pub fn resolved(path: &Path) -> Option<PathBuf> {
    let path = lexical(path);
    let existing = path.ancestors().find(|a| fs::symlink_metadata(a).is_ok())?;
    let rest = path.strip_prefix(existing).ok()?;
    Some(fs::canonicalize(existing).ok()?.join(rest))
}

/// Where a granted directory may be at all, besides the home: the places
/// removable and additional disks are mounted.
pub const GRANT_ROOTS: [&str; 4] = ["/mnt", "/media", "/run/media", "/srv"];

/// Why a directory may not be granted to a private home, if it may not.
///
/// A grant widens what a sandboxed program sees, on purpose — but only to
/// data. So it is an allow-list, not a list of dangers: below the home, or
/// below [`GRANT_ROOTS`]. Everything else is where the walls of the sandbox
/// are — `/run/user` has the D-Bus socket the filter exists for and the
/// compositor's, `/tmp` the X11 sockets, `/etc` the resolver the zone replaces
/// — and a list of those would be one socket short sooner or later.
///
/// Below the home, never the state of this project: `~/.local/state/vpn-zones`
/// holds the private key of every zone, the other three hold every container's
/// data and the pins that decide where programs run. Nor the home itself: that
/// is the `home` permission, asked for in words, not a path grant.
///
/// Lexical: the caller checks the resolved path as well, since a symlink is
/// followed by bwrap.
/// Below the home: where the session finds what to run — launcher entries,
/// autostart, user units, D-Bus activation, PATH, the environment, the
/// compositors' and the shells' configs, ssh's and gpg's (both run commands
/// they are told to). Never granted to a sandbox, nor anything above them.
const HOST_RUNS: &[&str] = &[
    ".local/share/applications",
    ".local/share/dbus-1",
    ".local/share/systemd",
    ".local/share/flatpak/exports",
    ".local/bin",
    ".local/state/nix",
    ".local/state/home-manager",
    ".nix-profile",
    ".config/autostart",
    ".config/systemd",
    ".config/environment.d",
    ".config/plasma-workspace",
    ".config/niri",
    ".config/sway",
    ".config/hypr",
    ".config/fish",
    ".config/home-manager",
    ".config/nixpkgs",
    ".config/nix",
    ".ssh",
    ".gnupg",
    // Second review (2026-09-25): more places the host starts code from.
    ".config/user-tmpfiles.d",
    ".local/share/user-tmpfiles.d",
    ".config/zsh",
    ".config/uwsm",
    ".config/river",
    ".config/labwc",
    ".config/i3",
    ".config/pipewire",
    ".config/wireplumber",
    // WirePlumber's scripts (looked for here before the system's: the zones'
    // PipeWire policy is one) and its state (the host's default devices).
    ".local/share/wireplumber",
    ".local/state/wireplumber",
    ".config/xdg-desktop-portal",
    ".config/git",
    ".mozilla/native-messaging-hosts",
    ".config/chromium/NativeMessagingHosts",
    ".config/google-chrome/NativeMessagingHosts",
    ".config/BraveSoftware",
    ".config/vivaldi/NativeMessagingHosts",
    ".local/share/kio/servicemenus",
    ".local/share/kservices5",
    ".local/share/kservices6",
    ".local/share/nautilus/scripts",
    ".local/share/nemo/actions",
    // Third review (2026-09-25): tools that run what their config names, and
    // the shells' own files in the home itself — a grant is not only a
    // directory, the command line takes a file too.
    ".config/direnv",
    ".local/share/direnv",
    ".docker",
    ".config/containers",
    ".profile",
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".zshenv",
    ".zshrc",
    ".zprofile",
    ".zlogin",
    ".zlogout",
    ".login",
    ".cshrc",
    ".tcshrc",
    ".xprofile",
    ".xsession",
    ".xsessionrc",
    ".xinitrc",
    ".Xresources",
    ".pam_environment",
    ".inputrc",
    ".npmrc",
    ".config/nushell",
    ".config/xonsh",
];

pub fn forbidden_path(home: &Path, path: &Path) -> Option<String> {
    if !path.is_absolute() {
        return Some("нужен абсолютный путь или ~/…".to_owned());
    }
    let path = lexical(path);
    if home.starts_with(&path) {
        return Some(
            "это весь дом или то, что выше него, — для этого есть разрешение home".to_owned(),
        );
    }
    if !path.starts_with(home) {
        let data_disk = GRANT_ROOTS
            .iter()
            .any(|root| path.starts_with(root) && path.as_path() != Path::new(root));
        return (!data_disk).then(|| {
            format!(
                "выдаются только каталоги дома и дисков ({}): в остальных местах стены песочницы",
                GRANT_ROOTS.join(", ")
            )
        });
    }
    for protected in [
        ".local/state/vpn-zones",
        ".local/state/vpn-profiles",
        ".local/state/vpn-sandboxes",
        ".config/vpn-zones",
        ".local/share/vpn-zones",
    ] {
        let protected = home.join(protected);
        if path.starts_with(&protected) || protected.starts_with(&path) {
            return Some(format!(
                "там состояние cellward ({}): ключи зон и данные контейнеров",
                protected.display()
            ));
        }
    }
    // What the host runs by itself, outside any zone and sandbox: a file
    // written there by a sandboxed program is code the session starts for it.
    for executed in HOST_RUNS {
        let executed = home.join(executed);
        if path.starts_with(&executed) || executed.starts_with(&path) {
            return Some(format!(
                "это место хост исполняет сам ({}): ярлык, автозапуск, юнит, PATH или \
                 конфиг, запускающий команды, — выдача дала бы песочнице выход наружу",
                executed.display()
            ));
        }
    }
    None
}

/// Grant a directory to a private home, or take the grant back.
/// Grant (`until`: the end of its term, if it has one) or revoke a directory.
pub fn set_path(
    tools: &Tools,
    selector: &str,
    path: &str,
    grant: bool,
    until: Option<u64>,
) -> Result<PathBuf, String> {
    let container = load(tools, selector).ok_or_else(|| format!("контейнера {selector} нет"))?;
    let value = expand_home(&tools.home, path);
    // The main home is the real one: there is nothing to grant it.
    if grant && container.home == Home::Main {
        return Err(format!(
            "{selector} — основной дом: он и так настоящий, выдавать нечего"
        ));
    }
    // A layer sees the whole real home and writes its own layer: a grant is
    // a path of the home it writes through, into the real one. Outside the
    // home there is no layer — it is the real one anyway.
    if grant && container.home == Home::Layer && !lexical(&value).starts_with(&tools.home) {
        return Err(format!(
            "{selector} — слой над домом: вне дома ({}) слоя нет, там и так настоящее",
            value.display()
        ));
    }
    if grant {
        // As written and as resolved: fs-sandbox checks both
        // again at every launch, this is only the early, readable refusal.
        let real = resolved(&value);
        let real_home = fs::canonicalize(&tools.home).unwrap_or_else(|_| tools.home.clone());
        let why = forbidden_path(&tools.home, &value)
            .or_else(|| real.as_ref().and_then(|r| forbidden_path(&real_home, r)))
            .or_else(|| {
                // The directories this installation really uses, when they are
                // not the default ones fs-sandbox knows.
                [
                    &tools.state,
                    &tools.profiles,
                    &tools.sandboxes,
                    &tools.config,
                ]
                .into_iter()
                .find(|dir| {
                    let near = |p: &Path| p.starts_with(dir) || dir.starts_with(p);
                    near(lexical(&value).as_path()) || real.as_deref().is_some_and(near)
                })
                .map(|dir| format!("там состояние cellward ({})", dir.display()))
            });
        if let Some(why) = why {
            return Err(format!("{} выдать нельзя: {why}", value.display()));
        }
    } else if container
        .paths
        .iter()
        .any(|p| p.value == value && p.source == Source::Nix)
    {
        return Err(format!("{} выдан в Nix — забирается там", value.display()));
    }
    let file = container.policy.join(PATHS_FILE);
    let now = now();
    let mut lines: Vec<String> = fs::read_to_string(&file)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| {
            let (p, u) = grant_line(l);
            !p.is_empty() && u.is_none_or(|u| u > now) && expand_home(&tools.home, p) != value
        })
        .map(str::to_owned)
        .collect();
    if grant {
        let path = value.to_string_lossy();
        lines.push(match until {
            Some(until) => format!("{UNTIL_PREFIX}{until} {path}"),
            None => path.into_owned(),
        });
    }
    fs::create_dir_all(&container.policy)
        .and_then(|()| {
            fs::write(
                &file,
                lines.join("\n") + if lines.is_empty() { "" } else { "\n" },
            )
        })
        .map_err(|e| format!("не записать {}: {e}", file.display()))?;
    Ok(value)
}

/// Take every grant whose term is over out of the paths files of the
/// containers. Returns what was taken: `(name, path)`.
pub fn expire_grants(tools: &Tools) -> Vec<(String, PathBuf)> {
    let now = now();
    let mut taken = Vec::new();
    migrate(tools);
    let Ok(entries) = fs::read_dir(tools.config.join(POLICY_DIR)) else {
        return taken;
    };
    for entry in entries.flatten() {
        let selector = entry.file_name().to_string_lossy().into_owned();
        if !valid_name(&selector) {
            continue;
        }
        let file = entry.path().join(PATHS_FILE);
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        let mut kept = Vec::new();
        let mut changed = false;
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let (path, until) = grant_line(line);
            if until.is_some_and(|u| u <= now) || path.is_empty() {
                changed = true;
                if !path.is_empty() {
                    taken.push((selector.clone(), expand_home(&tools.home, path)));
                }
            } else {
                kept.push(line.to_owned());
            }
        }
        if changed {
            let text = kept.join("\n") + if kept.is_empty() { "" } else { "\n" };
            if let Err(e) = fs::write(&file, text) {
                eprintln!("не записать {}: {e}", file.display());
            }
        }
    }
    taken
}

/// What a merge did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MergeReport {
    /// Files, links and directories copied into a place that was free.
    pub copied: usize,
    /// Entries that were in both, kept aside under `conflicts_dirs`.
    pub conflicts: usize,
    /// Sockets, pipes, devices — an overlay whiteout is a device too.
    pub skipped: usize,
    /// Where the conflicting entries went: one directory per home, or per
    /// overlay slot.
    pub conflicts_dirs: Vec<PathBuf>,
    /// Programs moved from one container to the other.
    pub apps: usize,
    /// Certificates `<into>` did not have before.
    pub new_certificates: Vec<String>,
}

/// Merge `<from>` into `<into>` (`docs/CONTAINERS.md` §3.4).
///
/// The rules, each for a reason: only containers of one kind (a layer and a
/// home of its own do not merge into each other, and the main home has no
/// data of its own to merge); nothing declared in Nix (the
/// module would put it back); nothing while either runs (files in use, and
/// I2); a path `<into>` already has is never overwritten — the one from
/// `<from>` goes to `.merged-from-<from>/`, because merging two browser
/// profiles is not a decision a tool can make; certificates new to `<into>`
/// need `allow_new_certificates` (the caller shows the warning); permissions are
/// not copied at all — a wider set is asked for, never inherited; `<from>` is
/// kept, without programs, until it is deleted by hand.
pub fn merge(
    tools: &Tools,
    from: &str,
    into: &str,
    allow_new_certificates: bool,
) -> Result<MergeReport, String> {
    let a = load(tools, from).ok_or_else(|| format!("контейнера {from} нет"))?;
    let b = load(tools, into).ok_or_else(|| format!("контейнера {into} нет"))?;
    if a.selector() == b.selector() {
        return Err("это один и тот же контейнер".to_owned());
    }
    if a.home != b.home {
        return Err(format!(
            "{from} и {into} — разные виды дома ({} и {}): такие не объединяются",
            a.home.label(),
            b.home.label()
        ));
    }
    if a.home == Home::Main {
        return Err(format!(
            "{from} и {into} — основной дом: своих данных у них нет, объединять нечего"
        ));
    }
    for c in [&a, &b] {
        if read_declared(tools, &c.name).is_some() {
            return Err(format!(
                "{} объявлен в Nix — объединяй в конфигурации",
                c.selector()
            ));
        }
        if let Some(busy) = running_network(tools, c) {
            return Err(format!(
                "программы контейнера {} работают (в сети {busy}) — закрой их",
                c.selector()
            ));
        }
    }

    let known: Vec<String> = crate::trust::stored(&b.trust_dir())
        .into_iter()
        .map(|c| c.sha256)
        .collect();
    let incoming: Vec<crate::trust::Stored> = crate::trust::stored(&a.trust_dir())
        .into_iter()
        .filter(|c| !known.contains(&c.sha256))
        .collect();
    if !incoming.is_empty() && !allow_new_certificates {
        return Err(format!(
            "у {from} есть корневые сертификаты, которых нет у {into} ({}): объединение сделает их \
             доверенными для программ {into} — подтверди флагом --yes",
            incoming.len()
        ));
    }

    let mut report = MergeReport::default();
    let pairs: Vec<(PathBuf, PathBuf)> = match a.home {
        Home::Private | Home::Main => vec![(a.dir.join("home"), b.dir.join("home"))],
        Home::Layer => fs::read_dir(&a.dir)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.join("upper").is_dir())
                    .map(|slot| {
                        let name = slot.file_name().unwrap_or_default().to_owned();
                        (slot.join("upper"), b.dir.join(name).join("upper"))
                    })
                    .collect()
            })
            .unwrap_or_default(),
    };
    for (src, dst) in pairs {
        if !src.is_dir() {
            continue;
        }
        fs::create_dir_all(&dst).map_err(|e| format!("не создать {}: {e}", dst.display()))?;
        let conflicts = fresh_aside(&dst, &a.name);
        merge_tree(&src, &dst, &conflicts, &mut report)
            .map_err(|e| format!("не удалось перенести {}: {e}", src.display()))?;
        if fs::symlink_metadata(&conflicts).is_ok() {
            report.conflicts_dirs.push(conflicts);
        }
    }

    for cert in &incoming {
        let dir = b.trust_dir();
        fs::create_dir_all(&dir)
            .and_then(|()| fs::copy(&cert.path, dir.join(format!("{}.pem", cert.sha256))))
            .map_err(|e| format!("не перенести сертификат {}: {e}", cert.sha256))?;
        report.new_certificates.push(cert.sha256.clone());
    }

    // The programs follow: their pins, and the picker's memory of the last
    // choice so that it does not offer the emptied container first.
    for (sub, counts) in [(".pinnedprofile", true), (".lastprofile", false)] {
        for file in visible_entries(&tools.state.join(sub)) {
            if read_setting(&file)
                .and_then(|s| canonical(tools, &s))
                .as_deref()
                == Some(a.name.as_str())
                && fs::write(&file, b.selector()).is_ok()
                && counts
            {
                report.apps += 1;
            }
        }
    }
    Ok(report)
}

/// A name for the conflicts directory that nothing has taken yet.
///
/// Never an existing one: a program of `<into>` can create any name in its own
/// home, a symlink to `~/.ssh` included, and the merge runs outside the
/// sandbox — writing into a planted path would carry files of one container
/// past the walls of the other. A fresh directory has only what the merge
/// itself creates below it.
fn fresh_aside(dst: &Path, from: &str) -> PathBuf {
    let base = format!(".merged-from-{from}");
    let mut candidate = dst.join(&base);
    let mut n = 2;
    while fs::symlink_metadata(&candidate).is_ok() {
        candidate = dst.join(format!("{base}-{n}"));
        n += 1;
    }
    candidate
}

/// Copy `src` into `dst` where `dst` has nothing; what `dst` already has goes
/// to the same relative place under `aside` instead.
///
/// Nothing is followed: a symlink is copied as a symlink, and a symlink in
/// `dst` is a taken name, not a directory to descend into — the two homes
/// belong to programs, and a link planted in one must not lead the merge
/// anywhere else.
pub fn merge_tree(
    src: &Path,
    dst: &Path,
    aside: &Path,
    report: &mut MergeReport,
) -> io::Result<()> {
    let mut names: Vec<PathBuf> = fs::read_dir(src)?.flatten().map(|e| e.path()).collect();
    names.sort();
    for from in names {
        let Some(name) = from.file_name().map(|n| n.to_owned()) else {
            continue;
        };
        let to = dst.join(&name);
        let kind = fs::symlink_metadata(&from)?.file_type();
        let taken = fs::symlink_metadata(&to);
        if kind.is_dir() {
            match taken {
                Err(_) => copy_tree(&from, &to, report)?,
                Ok(meta) if meta.file_type().is_dir() => {
                    merge_tree(&from, &to, &aside.join(&name), report)?
                }
                Ok(_) => {
                    copy_tree(&from, &aside.join(&name), report)?;
                    report.conflicts += 1;
                }
            }
        } else if kind.is_file() || kind.is_symlink() {
            if taken.is_err() {
                copy_one(&from, &to, kind.is_symlink())?;
                report.copied += 1;
            } else {
                fs::create_dir_all(aside)?;
                copy_one(&from, &aside.join(&name), kind.is_symlink())?;
                report.conflicts += 1;
            }
        } else {
            report.skipped += 1;
        }
    }
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path, report: &mut MergeReport) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    report.copied += 1;
    for entry in fs::read_dir(src)?.flatten() {
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let kind = fs::symlink_metadata(&from)?.file_type();
        if kind.is_dir() {
            copy_tree(&from, &to, report)?;
        } else if kind.is_file() || kind.is_symlink() {
            copy_one(&from, &to, kind.is_symlink())?;
            report.copied += 1;
        } else {
            report.skipped += 1;
        }
    }
    Ok(())
}

fn copy_one(from: &Path, to: &Path, symlink: bool) -> io::Result<()> {
    if symlink {
        std::os::unix::fs::symlink(fs::read_link(from)?, to)
    } else {
        fs::copy(from, to).map(|_| ())
    }
}

/// The container a program is assigned to in Nix, if any.
pub fn declared_owner(tools: &Tools, app: &str) -> Option<String> {
    load_all(tools).into_iter().find_map(|c| {
        c.apps
            .iter()
            .any(|a| a.value == app && a.source == Source::Nix)
            .then(|| c.selector())
    })
}

/// Bind a container to a network (or unbind it with `ask`), locally.
///
/// Refused when the network is declared in Nix — the module would put it back
/// on the next switch — and when programs of the container are running in
/// another network right now: a process cannot be moved, and a container in
/// two networks at once is exactly what binding exists to prevent
/// (`docs/CONTAINERS.md` I2).
pub fn set_network(tools: &Tools, selector: &str, network: &Network) -> Result<(), String> {
    let container = load(tools, selector).ok_or_else(|| format!("контейнера {selector} нет"))?;
    if container.network.source == Source::Nix {
        return Err(format!(
            "сеть контейнера {selector} задана в Nix ({}) — меняется там",
            container.network.value.as_str()
        ));
    }
    if let (Network::Named(net), Some(busy)) = (network, running_network(tools, &container)) {
        if &busy != net {
            return Err(format!(
                "программы контейнера {selector} сейчас работают в сети {busy} — закрой их, \
                 потом меняй сеть"
            ));
        }
    }
    let value = (*network != Network::Ask).then(|| network.as_str());
    write_key(&container.policy.join(FILE), "network", value, true)
}

/// Give a container an X server of its own in zones, or take it away, locally.
pub fn set_x11(tools: &Tools, selector: &str, on: bool) -> Result<(), String> {
    let container = load(tools, selector).ok_or_else(|| format!("контейнера {selector} нет"))?;
    if container.x11.source == Source::Nix {
        return Err(format!(
            "x11 контейнера {selector} задан в Nix — меняется там"
        ));
    }
    write_key(
        &container.policy.join(FILE),
        "x11",
        on.then_some("true"),
        true,
    )
}

/// Give a container a frame colour of its own (`None`: none — the zone's),
/// locally.
pub fn set_frame_color(tools: &Tools, selector: &str, color: Option<&str>) -> Result<(), String> {
    let container = load(tools, selector).ok_or_else(|| format!("контейнера {selector} нет"))?;
    if container
        .frame_color
        .as_ref()
        .is_some_and(|c| c.source == Source::Nix)
    {
        return Err(format!(
            "цвет рамки контейнера {selector} задан в Nix — меняется там"
        ));
    }
    let value = match color {
        Some(text) => Some(
            crate::frame::Rgb::parse(text)
                .ok_or_else(|| format!("«{text}» — не цвет: нужен #rrggbb"))?
                .hex(),
        ),
        None => None,
    };
    write_key(
        &container.policy.join(FILE),
        "frame_color",
        value.as_deref(),
        true,
    )
}

/// Give a container a microphone setting of its own (`None`: none — the
/// zone's), locally.
pub fn set_microphone(
    tools: &Tools,
    selector: &str,
    setting: Option<crate::microphone::Setting>,
) -> Result<(), String> {
    set_switch(tools, selector, "microphone", "микрофон", setting)
}

/// Give a container a screen cast setting of its own (`None`: none — the
/// zone's), locally.
pub fn set_screencast(
    tools: &Tools,
    selector: &str,
    setting: Option<crate::microphone::Setting>,
) -> Result<(), String> {
    set_switch(tools, selector, "screencast", "трансляция экрана", setting)
}

/// Let a container's programs reach the host's cameras, or not (`None`: as
/// its zone), locally.
pub fn set_camera(tools: &Tools, selector: &str, on: Option<bool>) -> Result<(), String> {
    let container = load(tools, selector).ok_or_else(|| format!("контейнера {selector} нет"))?;
    if container
        .camera
        .as_ref()
        .is_some_and(|c| c.source == Source::Nix)
    {
        return Err(format!(
            "камера контейнера {selector} задана в Nix — меняется там"
        ));
    }
    write_key(
        &container.policy.join(FILE),
        "camera",
        on.map(|on| if on { "true" } else { "false" }),
        true,
    )
}

/// Give a container a device, or take one back (`add` false), locally. A
/// device Nix gave is taken back there.
pub fn set_device(tools: &Tools, selector: &str, word: &str, add: bool) -> Result<(), String> {
    let container = load(tools, selector).ok_or_else(|| format!("контейнера {selector} нет"))?;
    let grant = crate::devices::Grant::parse(word).ok_or_else(|| {
        format!(
            "«{word}» — не устройство: games, security-keys, phone, serial, vm или \
             usb:<производитель>:<модель>[:<серийный>]"
        )
    })?;
    let word = grant.word();
    if !add
        && container
            .devices
            .iter()
            .any(|d| d.value == word && d.source == Source::Nix)
    {
        return Err(format!(
            "{word} выдано контейнеру {selector} в Nix — убирается там"
        ));
    }
    let mut local: Vec<String> = container
        .devices
        .iter()
        .filter(|d| d.source == Source::Local)
        .map(|d| d.value.clone())
        .collect();
    local.retain(|d| *d != word);
    if add {
        local.push(word);
    }
    write_values(&container.policy.join(FILE), "device", &local)
}

/// A container's rule for links of `scheme`, locally: they open in program
/// `id` without asking which (`None`: the rule taken away). Refused where
/// Nix set one.
pub fn set_link(
    tools: &Tools,
    selector: &str,
    scheme: &str,
    id: Option<&str>,
) -> Result<(), String> {
    let container = load(tools, selector).ok_or_else(|| format!("контейнера {selector} нет"))?;
    let Some(scheme) = crate::links::scheme_of(&format!("{scheme}:")) else {
        return Err(format!("«{scheme}» — не схема ссылки (https, tg, mailto…)"));
    };
    if container
        .links
        .iter()
        .any(|l| l.value.0 == scheme && l.source == Source::Nix)
    {
        return Err(format!(
            "ссылки {scheme}: контейнера {selector} заданы в Nix — меняются там"
        ));
    }
    let mut local: Vec<String> = container
        .links
        .iter()
        .filter(|l| l.source == Source::Local && l.value.0 != scheme)
        .map(|l| crate::links::rule_word(&l.value.0, &l.value.1))
        .collect();
    if let Some(id) = id.map(crate::links::bare_id) {
        if !crate::links::plausible_id(id) {
            return Err(format!(
                "«{id}» — не id ярлыка (имя .desktop-файла без расширения)"
            ));
        }
        local.push(crate::links::rule_word(&scheme, id));
    }
    write_values(&container.policy.join(FILE), "link", &local)
}

/// A container's `yes|no|ask` switch `key`, locally; refused where Nix set
/// it. `said`: its name for a person.
fn set_switch(
    tools: &Tools,
    selector: &str,
    key: &str,
    said: &str,
    setting: Option<crate::microphone::Setting>,
) -> Result<(), String> {
    let container = load(tools, selector).ok_or_else(|| format!("контейнера {selector} нет"))?;
    if crate::microphone::container_switch(&tools.config, &container.name, key)
        .is_some_and(|(_, source)| source == Source::Nix)
    {
        return Err(format!(
            "{said} контейнера {selector}: задано в Nix — меняется там"
        ));
    }
    write_key(
        &container.policy.join(FILE),
        key,
        setting.map(crate::microphone::Setting::as_str),
        true,
    )
}

/// Change the kind of a container's home, locally. Refused when the kind is
/// declared in Nix, and while its programs run: their home would change under
/// them. The data of the old kind go aside at the next launch
/// ([`prepare_data`]), nothing is erased.
pub fn set_home(tools: &Tools, selector: &str, home: Home) -> Result<(), String> {
    let container = load(tools, selector).ok_or_else(|| format!("контейнера {selector} нет"))?;
    if container.home_source == Source::Nix {
        return Err(format!(
            "вид дома контейнера {selector} задан в Nix — меняется там"
        ));
    }
    if container.home == home {
        return Ok(());
    }
    if !layout_done(&tools.config) {
        return Err(
            "перенос контейнеров в новый каталог ещё не закончен (см. его сообщения) — вид \
             дома меняется после него"
                .to_owned(),
        );
    }
    if let Some(busy) = running_network(tools, &container) {
        return Err(format!(
            "программы контейнера {selector} работают (в сети {busy}) — закрой их, потом меняй дом"
        ));
    }
    if home == Home::Main
        && fs::read_dir(container.trust_dir()).is_ok_and(|mut d| d.next().is_some())
    {
        return Err(format!(
            "у контейнера {selector} свои корневые сертификаты, а у основного дома их быть не может \
             (они легли бы в настоящий дом) — сначала cellward trust reset {selector}"
        ));
    }
    write_key(
        &container.policy.join(FILE),
        "home",
        Some(home.setting()),
        true,
    )?;
    let mut changed = container;
    changed.home = home;
    prepare_data(&changed)
}

/// Make a container: its policy with the kind of its home, and its data
/// directory. Refused for a name that cannot be one and for one that exists.
pub fn create(tools: &Tools, name: &str, home: Home) -> Result<Container, String> {
    if !valid_name(name) {
        return Err(format!(
            "«{name}» не может быть именем контейнера: нельзя / : пробелы, начало с - или ., \
             и слова main, ask, own"
        ));
    }
    if load(tools, name).is_some() {
        return Err(format!("контейнер {name} уже есть"));
    }
    if move_pending(tools, name) {
        return Err(format!(
            "у имени {name} есть данные, которые ещё не перенесены в новый каталог — сначала \
             перенос"
        ));
    }
    write_key(
        &policy_dir(tools, name).join(FILE),
        "home",
        Some(home.setting()),
        true,
    )?;
    let container = load(tools, name).ok_or_else(|| format!("контейнер {name} не создался"))?;
    prepare_data(&container)?;
    Ok(container)
}

/// The live launches of a container: `(program, record)`.
///
/// Every container has a registry directory of its own. A named sandbox
/// started before it had one filed its records under `__main__` as
/// `sb:<its old name>`: those are read too, while they live, by what that
/// name is now ([`canonical`] — `sb:work` is `work-sb` when a layer had the
/// name).
pub fn live_records(tools: &Tools, container: &Container) -> Vec<(String, registry::Record)> {
    let running = tools.state.join(".running");
    let alive = |pid| registry::alive(&running, pid);
    let mut records = registry::live_records(&running.join(&container.name), &alive);
    records.extend(
        registry::live_records(&running.join(registry::MAIN), &alive)
            .into_iter()
            .filter(|(_, r)| {
                r.selector.starts_with(SANDBOX_PREFIX)
                    && canonical(tools, &r.selector).as_deref() == Some(container.name.as_str())
            }),
    );
    records
}

/// The network the container's programs run in right now, if any: the first
/// live record of any of its programs ([`live_records`]).
pub fn running_network(tools: &Tools, container: &Container) -> Option<String> {
    live_records(tools, container)
        .into_iter()
        .map(|(_, r)| r.zone)
        .find(|zone| !zone.is_empty())
}

/// Why a launch into `zone` may not use this container, or `None` when it may.
///
/// The two invariants of `docs/CONTAINERS.md`: a container bound to a network
/// runs in that network only (I1), and a container never runs in two networks
/// at once (I2).
pub fn refusal(container: &Container, zone: &str, running: Option<&str>) -> Option<String> {
    let selector = container.selector();
    if !container.network.value.accepts(zone) {
        let bound = container.network.value.as_str();
        let how = if container.network.source == Source::Nix {
            "сеть задана в Nix и меняется там".to_owned()
        } else {
            format!("сменить сеть контейнера: cellward container set {selector} network {zone}")
        };
        return Some(format!(
            "контейнер «{selector}» работает в сети «{bound}», а запуск просит «{zone}». \
             Одна личность — одна сеть: {how}"
        ));
    }
    // The main home is one identity in every network anyway: there is
    // nothing to keep apart (`docs/PERMISSIONS.md` §11.7).
    if container.home == Home::Main {
        return None;
    }
    match running {
        Some(busy) if busy != zone => Some(format!(
            "программы контейнера «{selector}» уже работают в сети «{busy}», а запуск просит \
             «{zone}». Контейнер не бывает в двух сетях сразу: закрой его программы или запусти \
             в «{busy}»"
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_name_containers_and_nothing_else() {
        assert_eq!(parse_selector("work"), Some("work"));
        assert_eq!(parse_selector("Работа"), Some("Работа"));
        // The old prefix of a home of its own: the same name now.
        assert_eq!(parse_selector("sb:work"), Some("work"));
        assert_eq!(parse_selector("sb:app-firefox"), Some("app-firefox"));
        for not_one in [
            "",
            "__main__",
            "__fs__",
            "__tmp__",
            "tmpjoin:/tmp/x",
            "sb:",
            "a/b",
            "a b",
            "a:b",
            "?",
            "-x",
            ".x",
            "main",
            "ask",
            "own",
            "pinmain",
            "profiles",
            "sandboxes",
        ] {
            assert_eq!(parse_selector(not_one), None, "{not_one}");
        }
        assert!(Home::parse("overlay") == Some(Home::Layer));
        assert_eq!(Home::Layer.as_str(), "overlay", "status schema 1");
        assert_eq!(Home::Layer.setting(), "layer");
    }

    #[test]
    fn a_renamed_sandbox_is_found_by_its_old_selector() {
        let t = Tmp::new("renamed");
        fs::create_dir_all(t.0.join(POLICY_DIR)).unwrap();
        fs::write(t.0.join(POLICY_DIR).join(RENAMED), "sb:work\twork-sb\n").unwrap();
        assert_eq!(canonical_in(&t.0, "sb:work").as_deref(), Some("work-sb"));
        assert_eq!(canonical_in(&t.0, "work").as_deref(), Some("work"));
        assert_eq!(canonical_in(&t.0, "sb:dev").as_deref(), Some("dev"));
        assert_eq!(canonical_in(&t.0, "__main__"), None);
    }

    #[test]
    fn networks_parse_and_decide() {
        assert_eq!(Network::parse("ask"), Some(Network::Ask));
        assert_eq!(Network::parse(" nl \n"), Some(Network::Named("nl".into())));
        for bad in ["", "a/b", "a b", "-x", ".x"] {
            assert_eq!(Network::parse(bad), None, "{bad}");
        }
        assert!(Network::Ask.accepts("anything"));
        assert!(Network::Named("nl".into()).accepts("nl"));
        assert!(!Network::Named("nl".into()).accepts("unconfined"));
        assert_eq!(
            Network::parse("direct"),
            Some(Network::Named("unconfined".into()))
        );
    }

    #[test]
    fn the_conf_format_is_flat_lines() {
        let conf =
            parse_conf("# comment\nnetwork = nl\n\napp=firefox\napp = tg \nno equals\n = x\n");
        assert_eq!(
            conf,
            vec![
                ("network".to_owned(), "nl".to_owned()),
                ("app".to_owned(), "firefox".to_owned()),
                ("app".to_owned(), "tg".to_owned()),
            ]
        );
        assert_eq!(values(&conf, "app").collect::<Vec<_>>(), ["firefox", "tg"]);
    }

    struct Layout {
        base: PathBuf,
        config: PathBuf,
        profiles: PathBuf,
        sandboxes: PathBuf,
        state: PathBuf,
    }

    impl Layout {
        fn new(tag: &str) -> Self {
            let base = std::env::temp_dir().join(format!("vz-layout-{}-{tag}", std::process::id()));
            let _ = fs::remove_dir_all(&base);
            Self {
                config: base.join("config"),
                profiles: base.join("profiles"),
                sandboxes: base.join("sandboxes"),
                state: base.join("state"),
                base,
            }
        }

        fn migrate(&self) -> Moved {
            migrate_in(&self.config, &self.profiles, &self.sandboxes, &self.state)
        }
    }

    impl Drop for Layout {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    fn conf_of(config: &Path, name: &str) -> Vec<(String, String)> {
        parse_conf(&fs::read_to_string(policy_dir_in(config, name).join(FILE)).unwrap_or_default())
    }

    /// One name, one data directory, one policy directory: the sandboxes'
    /// data join the rest, the policy of both layouts before moves in, the
    /// kind is written, and a name a layer has makes the sandbox `-sb`.
    #[test]
    fn the_layout_moves_to_one_name_per_container() {
        let l = Layout::new("one");
        // The previous layout: policy per kind.
        let p1 = l.config.join(POLICY_DIR);
        fs::create_dir_all(p1.join("sandboxes/dev/trust")).unwrap();
        fs::create_dir_all(p1.join("profiles/work")).unwrap();
        fs::write(p1.join(LAYOUT_1_MARK), "").unwrap();
        fs::write(p1.join("sandboxes/dev/perms"), "downloads\n").unwrap();
        fs::write(p1.join("sandboxes/dev/trust/a.pem"), "x").unwrap();
        fs::write(p1.join("profiles/work/container.conf"), "network = nl\n").unwrap();
        fs::create_dir_all(l.sandboxes.join("dev/home/.config")).unwrap();
        fs::write(l.sandboxes.join("dev/home/.config/x"), "dev's").unwrap();
        // What home-manager's activation makes for a declared container
        // before anything moves: empty, and nobody's name.
        fs::create_dir_all(l.profiles.join("dev")).unwrap();
        fs::create_dir_all(l.profiles.join("work/home/upper")).unwrap();
        // A sandbox with a layer's name.
        fs::create_dir_all(l.sandboxes.join("work/home")).unwrap();
        fs::write(l.sandboxes.join("work/home/f"), "the sandbox's").unwrap();
        // After the previous move, a file next to the data is nobody's.
        fs::write(
            l.sandboxes.join("dev/container.conf"),
            "network = unconfined\n",
        )
        .unwrap();
        // Memory that names them.
        fs::create_dir_all(l.state.join(".pinnedprofile")).unwrap();
        fs::write(l.state.join(".pinnedprofile/tg"), "sb:work").unwrap();
        fs::write(l.state.join(".pinnedprofile/ff"), "sb:dev").unwrap();
        fs::write(l.state.join(".pinnedprofile/kate"), "work").unwrap();
        fs::write(l.config.join("default-profile"), "sb:work").unwrap();

        let moved = l.migrate();
        assert!(moved.failed.is_empty(), "{moved:?}");
        assert_eq!(
            moved.renamed,
            [("sb:work".to_owned(), "work-sb".to_owned())]
        );

        assert_eq!(
            fs::read_to_string(l.profiles.join("dev/home/.config/x")).unwrap(),
            "dev's"
        );
        assert_eq!(
            fs::read_to_string(l.profiles.join("work-sb/home/f")).unwrap(),
            "the sandbox's"
        );
        assert!(
            l.profiles.join("work/home/upper").is_dir(),
            "the layer stays"
        );
        assert!(!l.sandboxes.join("dev").exists());

        let dev = policy_dir_in(&l.config, "dev");
        assert_eq!(
            fs::read_to_string(dev.join("perms")).unwrap(),
            "downloads\n"
        );
        assert!(dev.join("trust/a.pem").is_file());
        assert_eq!(
            conf_of(&l.config, "dev"),
            [("home".to_owned(), "private".to_owned())]
        );
        assert_eq!(
            conf_of(&l.config, "work"),
            [
                ("network".to_owned(), "nl".to_owned()),
                ("home".to_owned(), "layer".to_owned())
            ]
        );
        assert_eq!(conf_of(&l.config, "work-sb")[0].1, "private");
        assert!(!p1.join("profiles").exists() && !p1.join("sandboxes").exists());

        assert_eq!(
            read_setting(&l.state.join(".pinnedprofile/tg")).unwrap(),
            "work-sb"
        );
        assert_eq!(
            read_setting(&l.state.join(".pinnedprofile/ff")).unwrap(),
            "dev"
        );
        assert_eq!(
            read_setting(&l.state.join(".pinnedprofile/kate")).unwrap(),
            "work"
        );
        assert_eq!(
            read_setting(&l.config.join("default-profile")).unwrap(),
            "work-sb"
        );
        assert_eq!(
            canonical_in(&l.config, "sb:work").as_deref(),
            Some("work-sb")
        );

        // Once: what appears next to the data afterwards is nobody's.
        fs::write(
            l.profiles.join("dev/container.conf"),
            "network = unconfined\n",
        )
        .unwrap();
        assert_eq!(l.migrate(), Moved::default());
        assert_eq!(
            conf_of(&l.config, "dev"),
            [("home".to_owned(), "private".to_owned())]
        );
    }

    /// Before the previous move ran, the policy is still next to the data,
    /// and is taken from there — plain files only; a link is left, and the
    /// move is not marked done while it is; a link to a directory is no
    /// container; a name that cannot be one stays where it is.
    #[test]
    fn the_oldest_layout_moves_too_and_no_link_with_it() {
        let l = Layout::new("oldest");
        fs::create_dir_all(l.sandboxes.join("dev/home")).unwrap();
        fs::write(l.sandboxes.join("dev/paths"), "~/g\n").unwrap();
        fs::create_dir_all(l.profiles.join("----")).unwrap();
        fs::create_dir_all(l.base.join("elsewhere")).unwrap();
        fs::write(l.base.join("elsewhere/conf"), "network = unconfined\n").unwrap();
        std::os::unix::fs::symlink(
            l.base.join("elsewhere/conf"),
            l.sandboxes.join("dev").join(FILE),
        )
        .unwrap();
        std::os::unix::fs::symlink(l.base.join("elsewhere"), l.sandboxes.join("linked")).unwrap();

        let moved = l.migrate();
        assert_eq!(moved.left, [l.profiles.join("----")]);
        assert!(!moved.failed.is_empty(), "the link is a failure");
        let dev = policy_dir_in(&l.config, "dev");
        assert_eq!(fs::read_to_string(dev.join(PATHS_FILE)).unwrap(), "~/g\n");
        // Nothing of it taken, not even the kind yet: the link is to be
        // looked at, and the next try finds the container as it was.
        assert!(
            fs::symlink_metadata(dev.join(FILE)).is_err(),
            "a link was moved"
        );
        assert!(!policy_dir_in(&l.config, "linked").exists());
        assert!(
            l.sandboxes.join("dev/home").is_dir(),
            "kept whole until its policy moved"
        );
        assert!(!l.config.join(POLICY_DIR).join(LAYOUT_MARK).exists());

        // The link gone, the next look finishes.
        fs::remove_file(l.sandboxes.join("dev").join(FILE)).unwrap();
        let moved = l.migrate();
        assert!(moved.failed.is_empty(), "{moved:?}");
        assert!(l.profiles.join("dev/home").is_dir());
        assert_eq!(conf_of(&l.config, "dev")[0].1, "private");
        assert!(l.config.join(POLICY_DIR).join(LAYOUT_MARK).exists());
    }

    /// A name Nix declares as a layer is the layer's, even while its
    /// directory is only the empty one home-manager made: a sandbox of that
    /// name moves in as `<name>-sb`. The plan and the renames are written
    /// before anything moves, so a move that stops half-way still sends a
    /// stale `sb:<name>` to the right place — and the launch of a container
    /// whose data have not moved is refused meanwhile.
    #[test]
    fn a_declared_name_is_kept_and_the_plan_comes_first() {
        let l = Layout::new("declared");
        let declared = l.config.join(DECLARED);
        fs::create_dir_all(&declared).unwrap();
        fs::write(declared.join("work.conf"), "home = layer\n").unwrap();
        fs::create_dir_all(l.profiles.join("work")).unwrap();
        fs::create_dir_all(l.sandboxes.join("work/home")).unwrap();
        fs::write(l.sandboxes.join("work/home/f"), "sandbox").unwrap();
        // A second sandbox whose old policy holds a link: its move stops.
        fs::create_dir_all(l.sandboxes.join("dev/home")).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", l.sandboxes.join("dev").join(FILE)).unwrap();

        let moved = l.migrate();
        assert!(!moved.failed.is_empty(), "{moved:?}");
        assert_eq!(
            fs::read_to_string(l.profiles.join("work-sb/home/f")).unwrap(),
            "sandbox"
        );
        assert!(l.profiles.join("work").is_dir(), "the declared layer's own");
        assert_eq!(
            canonical_in(&l.config, "sb:work").as_deref(),
            Some("work-sb")
        );
        assert!(move_pending_in(&l.config, &l.sandboxes, "dev"));
        assert!(!move_pending_in(&l.config, &l.sandboxes, "work-sb"));
        // The next try follows the same plan: the moved sandbox is not taken
        // for a layer, and its kind stays.
        fs::remove_file(l.sandboxes.join("dev").join(FILE)).unwrap();
        let moved = l.migrate();
        assert!(moved.failed.is_empty(), "{moved:?}");
        assert_eq!(conf_of(&l.config, "work-sb")[0].1, "private");
        assert_eq!(
            fs::read_to_string(l.profiles.join("work-sb").join(DATA_KIND)).unwrap(),
            "private"
        );
        assert!(!move_pending_in(&l.config, &l.sandboxes, "dev"));
        assert!(!l.config.join(POLICY_DIR).join(LAYOUT_PLAN).exists());
    }

    /// A name that no number makes a name (a temporary container's
    /// beginning) is left where it is — the move ends, it does not loop under
    /// its lock. A sandbox Nix declares keeps its name, and the layer that
    /// had it moves aside. A step done is not done again: a container moved
    /// and changed since stays as it was changed, however long the rest of
    /// the move is stuck.
    #[test]
    fn the_move_ends_keeps_declared_names_and_does_not_redo_a_step() {
        let l = Layout::new("steps");
        fs::create_dir_all(l.profiles.join("vpn-profile-x")).unwrap();
        fs::create_dir_all(l.sandboxes.join("vpn-profile-y/home")).unwrap();
        let declared = l.config.join(DECLARED);
        fs::create_dir_all(&declared).unwrap();
        fs::write(declared.join("work.conf"), "home = private\n").unwrap();
        fs::create_dir_all(l.profiles.join("work/home/upper")).unwrap();
        fs::write(l.profiles.join("work/home/upper/f"), "layer").unwrap();
        fs::create_dir_all(l.sandboxes.join("work/home")).unwrap();
        fs::write(l.sandboxes.join("work/home/f"), "sandbox").unwrap();
        fs::create_dir_all(l.profiles.join("keep")).unwrap();
        // A sandbox whose move stops: a link among its old files.
        fs::create_dir_all(l.sandboxes.join("dev/home")).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", l.sandboxes.join("dev").join(FILE)).unwrap();

        let moved = l.migrate();
        assert!(
            moved.left.contains(&l.profiles.join("vpn-profile-x")),
            "{moved:?}"
        );
        assert!(
            moved.left.contains(&l.sandboxes.join("vpn-profile-y")),
            "{moved:?}"
        );
        assert_eq!(
            fs::read_to_string(l.profiles.join("work/home/f")).unwrap(),
            "sandbox"
        );
        assert_eq!(
            fs::read_to_string(l.profiles.join("work-layer/home/upper/f")).unwrap(),
            "layer"
        );
        assert_eq!(conf_of(&l.config, "work")[0].1, "private");
        assert!(!moved.failed.is_empty());

        // `keep` is moved; its kind changed by hand since.
        write_key(
            &policy_dir_in(&l.config, "keep").join(FILE),
            "home",
            Some("private"),
            true,
        )
        .unwrap();
        fs::write(l.profiles.join("keep").join(DATA_KIND), "private").unwrap();
        let moved = l.migrate();
        assert!(!moved.failed.is_empty(), "still stuck on dev");
        assert_eq!(
            conf_of(&l.config, "keep")[0].1,
            "private",
            "a done step redone"
        );
        assert_eq!(
            fs::read_to_string(l.profiles.join("keep").join(DATA_KIND)).unwrap(),
            "private"
        );
    }

    /// A rename never lands on the name of a sandbox that keeps its own:
    /// with a layer `a` and sandboxes `a` and `a-sb`, the sandbox `a` is
    /// `a-sb2`, and a stale `sb:a-sb` still means `a-sb`.
    #[test]
    fn a_rename_never_takes_a_kept_name() {
        let l = Layout::new("kept");
        fs::create_dir_all(l.profiles.join("a/home/upper")).unwrap();
        fs::create_dir_all(l.sandboxes.join("a/home")).unwrap();
        fs::write(l.sandboxes.join("a/home/f"), "a").unwrap();
        fs::create_dir_all(l.sandboxes.join("a-sb/home")).unwrap();
        fs::write(l.sandboxes.join("a-sb/home/f"), "a-sb").unwrap();
        let moved = l.migrate();
        assert!(moved.failed.is_empty(), "{moved:?}");
        assert_eq!(
            fs::read_to_string(l.profiles.join("a-sb/home/f")).unwrap(),
            "a-sb"
        );
        assert_eq!(
            fs::read_to_string(l.profiles.join("a-sb2/home/f")).unwrap(),
            "a"
        );
        assert_eq!(canonical_in(&l.config, "sb:a").as_deref(), Some("a-sb2"));
        assert_eq!(canonical_in(&l.config, "sb:a-sb").as_deref(), Some("a-sb"));
    }

    fn tools_in(base: &Path) -> Tools {
        let entries: std::collections::BTreeMap<String, String> = Tools::keys()
            .iter()
            .map(|k| {
                let dir = match *k {
                    "home" | "state" | "profiles" | "sandboxes" | "config" => base.join(k),
                    other => PathBuf::from(format!("/p/{other}")),
                };
                ((*k).to_owned(), dir.to_string_lossy().into_owned())
            })
            .collect();
        Tools::from_entries(Path::new("/m.json"), &entries).unwrap()
    }

    /// A container's own frame colour: set, refused when it is no colour,
    /// taken back to the zone's (`docs/PERMISSIONS.md` §11.10).
    #[test]
    fn a_container_has_a_frame_colour_of_its_own() {
        let t = Tmp::new("colour");
        let tools = tools_in(&t.0);
        fs::create_dir_all(tools.config.join(POLICY_DIR)).unwrap();
        fs::write(tools.config.join(POLICY_DIR).join(LAYOUT_MARK), LAYOUT).unwrap();
        fs::write(tools.config.join(POLICY_DIR).join(PINS_MOVED), "").unwrap();
        create(&tools, "work", Home::Private).unwrap();
        assert_eq!(load(&tools, "work").unwrap().frame_color, None);
        set_frame_color(&tools, "work", Some("#D94C4C")).unwrap();
        assert_eq!(
            load(&tools, "work").unwrap().frame_color,
            Some(Sourced {
                value: "#d94c4c".into(),
                source: Source::Local
            })
        );
        assert!(set_frame_color(&tools, "work", Some("red")).is_err());
        set_frame_color(&tools, "work", None).unwrap();
        assert_eq!(load(&tools, "work").unwrap().frame_color, None);
    }

    /// The network a program was pinned to becomes its container's
    /// (`docs/PERMISSIONS.md` §11.8), once.
    #[test]
    fn a_programs_network_pin_becomes_its_containers() {
        let t = Tmp::new("pins");
        let tools = tools_in(&t.0);
        fs::create_dir_all(tools.config.join(POLICY_DIR)).unwrap();
        fs::write(tools.config.join(POLICY_DIR).join(LAYOUT_MARK), LAYOUT).unwrap();
        // Written, not made with `create`: that looks, and a look moves the
        // pins — before this test has laid them out.
        for (name, home) in [("work", Home::Layer), ("dev", Home::Private)] {
            write_key(
                &policy_dir(&tools, name).join(FILE),
                "home",
                Some(home.setting()),
                true,
            )
            .unwrap();
        }
        write_key(
            &policy_dir(&tools, "shared").join(FILE),
            "home",
            Some("layer"),
            true,
        )
        .unwrap();
        let state = &tools.state;
        for dir in [".pinned", ".pinnedprofile"] {
            fs::create_dir_all(state.join(dir)).unwrap();
        }
        for zone in ["nl", "de"] {
            fs::create_dir_all(state.join(zone)).unwrap();
            fs::write(state.join(zone).join("config.conf"), "").unwrap();
        }
        // A named default is shared: nobody chose its network by pinning one
        // program.
        fs::create_dir_all(&tools.config).unwrap();
        fs::write(tools.config.join("default-profile"), "work").unwrap();
        let pin = |key: &str, net: &str, container: Option<&str>| {
            fs::write(state.join(".pinned").join(key), net).unwrap();
            if let Some(c) = container {
                fs::write(state.join(".pinnedprofile").join(key), c).unwrap();
            }
        };
        pin("a", "nl", Some("work"));
        pin("b", "nl", Some("dev"));
        pin("c", "de", Some("dev"));
        pin("d", "offline", Some("__main__"));
        pin("e", "nl", None);
        pin("f", "de", Some("app-f"));
        pin("g", "nl", Some("gone"));
        // A program of `shared` with no pin was asked every time: no
        // agreement.
        pin("j", "nl", Some("shared"));
        fs::write(state.join(".pinnedprofile/k"), "shared").unwrap();
        // A zone that is gone.
        pin("x", "gone-zone", None);

        let said = migrate_pins(&tools);
        assert!(!said.is_empty());
        let net = |name: &str| load(&tools, name).map(|c| c.network.value);
        assert_eq!(net("work"), Some(Network::Named("nl".into())));
        assert_eq!(net("dev"), Some(Network::Ask), "its programs disagree");
        assert_eq!(net("app-f"), Some(Network::Named("de".into())));
        assert_eq!(load(&tools, "app-f").map(|c| c.home), Some(Home::Private));
        assert!(
            load(&tools, "gone").is_none(),
            "a container that is gone stays gone"
        );
        assert_eq!(net("shared"), Some(Network::Ask), "k never agreed");
        assert!(
            read_setting(&state.join(".last/x")).is_none(),
            "a gone zone is no choice"
        );
        let main = load(&tools, "main-offline").unwrap();
        assert_eq!(
            (main.home, main.network.value),
            (Home::Main, Network::Named("offline".into()))
        );
        assert_eq!(
            read_setting(&state.join(".pinnedprofile/d")).as_deref(),
            Some("main-offline")
        );
        for (key, last) in [
            ("b", "nl"),
            ("c", "de"),
            ("e", "nl"),
            ("g", "nl"),
            ("j", "nl"),
        ] {
            assert_eq!(
                read_setting(&state.join(".last").join(key)).as_deref(),
                Some(last),
                "{key}"
            );
        }
        assert!(visible_entries(&state.join(".pinned")).is_empty());
        // Once: a pin written afterwards is nobody's.
        fs::write(state.join(".pinned/a"), "de").unwrap();
        assert!(migrate_pins(&tools).is_empty());
        assert_eq!(net("work"), Some(Network::Named("nl".into())));
    }

    /// A kind of home written into a file next to a container's data, where
    /// a program could write, is not taken: the plan's kind is.
    #[test]
    fn the_kind_is_the_plans_not_a_moved_files() {
        let l = Layout::new("planted");
        fs::create_dir_all(l.sandboxes.join("dev/home")).unwrap();
        fs::write(
            l.sandboxes.join("dev").join(FILE),
            "home = main\nnetwork = nl\n",
        )
        .unwrap();
        fs::write(l.sandboxes.join("dev").join(DATA_KIND), "main").unwrap();
        let moved = l.migrate();
        assert!(moved.failed.is_empty(), "{moved:?}");
        let conf = conf_of(&l.config, "dev");
        assert!(
            conf.contains(&("home".to_owned(), "private".to_owned())),
            "{conf:?}"
        );
        assert!(
            !conf.iter().any(|(k, v)| k == "home" && v == "main"),
            "{conf:?}"
        );
        assert_eq!(
            fs::read_to_string(l.profiles.join("dev").join(DATA_KIND)).unwrap(),
            "private"
        );
    }

    /// A change of the kind of home sets the other kind's data aside and
    /// brings back what was set aside before: nothing erased, nothing read as
    /// the other kind.
    #[test]
    fn a_new_kind_of_home_sets_the_old_one_aside() {
        let t = Tmp::new("kind");
        let mut c = container(Network::Ask, Source::Default);
        c.dir = t.0.join("dev");
        fs::create_dir_all(c.dir.join("home/.config")).unwrap();
        fs::write(c.dir.join("home/.config/x"), "private").unwrap();
        fs::write(c.dir.join(DATA_KIND), "private").unwrap();

        c.home = Home::Layer;
        prepare_data(&c).unwrap();
        assert!(!c.dir.join("home").exists(), "a private home is no layer");
        assert_eq!(
            fs::read_to_string(c.dir.join("home.private/.config/x")).unwrap(),
            "private"
        );
        fs::create_dir_all(c.dir.join("home/upper")).unwrap();

        c.home = Home::Private;
        prepare_data(&c).unwrap();
        assert_eq!(
            fs::read_to_string(c.dir.join("home/.config/x")).unwrap(),
            "private"
        );
        assert!(c.dir.join("home.layer/upper").is_dir());
        assert_eq!(
            fs::read_to_string(c.dir.join(DATA_KIND)).unwrap(),
            "private"
        );

        // The main home has no data of its own: what the earlier kind left
        // goes aside too, and comes back.
        c.home = Home::Main;
        assert!(!data_ready(&c));
        prepare_data(&c).unwrap();
        assert!(data_ready(&c));
        assert!(!c.dir.join("home").exists());
        assert!(c.dir.join("home.private/.config/x").is_file());
        c.home = Home::Private;
        prepare_data(&c).unwrap();
        assert!(c.dir.join("home/.config/x").is_file());

        // A link in the place of the home is no home: bwrap would follow it.
        let t2 = Tmp::new("kind-link");
        let mut l = container(Network::Ask, Source::Default);
        l.dir = t2.0.join("dev");
        fs::create_dir_all(&l.dir).unwrap();
        std::os::unix::fs::symlink("/etc", l.dir.join("home")).unwrap();
        assert!(prepare_data(&l).unwrap_err().contains("ссылка"));
    }

    #[test]
    fn the_kind_of_old_data_is_read_from_their_shape() {
        let t = Tmp::new("shape");
        fs::create_dir_all(t.0.join("layer/home/upper")).unwrap();
        fs::create_dir_all(t.0.join("private/home")).unwrap();
        fs::create_dir_all(t.0.join("old-layer/.config")).unwrap();
        assert_eq!(kind_of_data(&t.0.join("layer")), Home::Layer);
        assert_eq!(kind_of_data(&t.0.join("private")), Home::Private);
        assert_eq!(kind_of_data(&t.0.join("old-layer")), Home::Layer);
        assert_eq!(kind_of_data(&t.0.join("nothing")), Home::Private);
    }

    fn container(network: Network, source: Source) -> Container {
        Container {
            name: "work".into(),
            home: Home::Private,
            home_source: Source::Local,
            network: Sourced {
                value: network,
                source,
            },
            apps: Vec::new(),
            declared_trust: Vec::new(),
            paths: Vec::new(),
            expires: Vec::new(),
            x11: Sourced {
                value: false,
                source: Source::Default,
            },
            frame_color: None,
            microphone: None,
            screencast: None,
            camera: None,
            devices: Vec::new(),
            links: Vec::new(),
            dir: PathBuf::from("/s/work"),
            policy: PathBuf::from("/c/containers/work"),
        }
    }

    #[test]
    fn a_bound_container_runs_in_its_network_only() {
        let c = container(Network::Named("nl".into()), Source::Local);
        assert_eq!(refusal(&c, "nl", None), None);
        let why = refusal(&c, "unconfined", None).unwrap();
        assert!(
            why.contains("«nl»") && why.contains("«unconfined»"),
            "{why}"
        );
        assert!(
            why.contains("cellward container set work network unconfined"),
            "{why}"
        );
        // Declared in Nix: the way out is the module, not the CLI.
        let c = container(Network::Named("nl".into()), Source::Nix);
        assert!(refusal(&c, "unconfined", None)
            .unwrap()
            .contains("задана в Nix"));
    }

    #[test]
    fn a_container_is_never_in_two_networks_at_once() {
        let c = container(Network::Ask, Source::Default);
        assert_eq!(refusal(&c, "nl", None), None);
        assert_eq!(refusal(&c, "nl", Some("nl")), None);
        let why = refusal(&c, "de", Some("nl")).unwrap();
        assert!(why.contains("двух сетях"), "{why}");
        // The main home is one identity everywhere: nothing to keep apart.
        let mut main = container(Network::Ask, Source::Default);
        main.home = Home::Main;
        assert_eq!(refusal(&main, "de", Some("nl")), None);
    }

    #[test]
    fn the_state_of_this_project_is_never_granted() {
        let home = Path::new("/home/u");
        assert_eq!(forbidden_path(home, Path::new("/home/u/.wine")), None);
        assert_eq!(forbidden_path(home, Path::new("/mnt/games")), None);
        assert_eq!(forbidden_path(home, Path::new("/run/media/u/disk")), None);
        for bad in [
            "/home/u",
            "/home",
            "/",
            "/mnt",
            "/run/user/1000",
            "/run/user/1000/bus",
            "/tmp/.X11-unix",
            "/etc",
            "/nix/store",
            "/persist",
            "/mnt/../run/user",
            "/home/u/.local/state/vpn-zones",
            "/home/u/.local/state/vpn-zones/nl",
            "/home/u/.local/state",
            "/home/u/.config/vpn-zones/declared",
            "/home/u/.local/state/vpn-sandboxes/x/home",
            "/home/u/.wine/../.local/state/vpn-zones",
            // What the host runs by itself: a sandbox writing there would
            // leave code for the session to start outside it.
            "/home/u/.local/share/applications",
            "/home/u/.local/share/applications/wine",
            "/home/u/.local/share",
            "/home/u/.local/share/vpn-zones/bin",
            "/home/u/.config/autostart",
            "/home/u/.config",
            "/home/u/.config/systemd/user",
            "/home/u/.local/bin",
            "/home/u/.ssh",
            // WirePlumber's scripts: the zones' PipeWire policy is one.
            "/home/u/.local/share/wireplumber/scripts",
            "/home/u/.local/state/wireplumber",
        ] {
            assert!(forbidden_path(home, Path::new(bad)).is_some(), "{bad}");
        }
        assert!(forbidden_path(home, Path::new("relative")).is_some());
        assert_eq!(expand_home(home, "~/.wine"), PathBuf::from("/home/u/.wine"));
        assert_eq!(expand_home(home, "/abs"), PathBuf::from("/abs"));
    }

    #[test]
    fn a_grant_is_resolved_before_anything_is_created() {
        let t = Tmp::new("resolved");
        let real = t.0.join("real");
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, t.0.join("link")).unwrap();
        let real = fs::canonicalize(&real).unwrap();
        assert_eq!(
            resolved(&t.0.join("link/not/yet")),
            Some(real.join("not/yet"))
        );
        assert!(!real.join("not").exists(), "resolving creates nothing");
        assert_eq!(resolved(&t.0.join("link/../real")), Some(real));
    }

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p =
                std::env::temp_dir().join(format!("vpn-zone-merge-{}-{tag}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_merge_copies_what_is_free_and_sets_aside_what_is_taken() {
        let t = Tmp::new("tree");
        let (src, dst) = (t.0.join("src"), t.0.join("dst"));
        fs::create_dir_all(src.join(".config/app")).unwrap();
        fs::create_dir_all(dst.join(".config/other")).unwrap();
        fs::write(src.join(".config/app/settings"), "from").unwrap();
        fs::write(src.join("both.txt"), "from").unwrap();
        fs::write(dst.join("both.txt"), "into").unwrap();
        fs::write(src.join("only-from.txt"), "from").unwrap();
        std::os::unix::fs::symlink("only-from.txt", src.join("link")).unwrap();
        // A directory in one and a file in the other is a conflict too.
        fs::create_dir_all(src.join("clash")).unwrap();
        fs::write(src.join("clash/inner"), "x").unwrap();
        fs::write(dst.join("clash"), "file").unwrap();

        let aside = dst.join(".merged-from-a");
        let mut report = MergeReport::default();
        merge_tree(&src, &dst, &aside, &mut report).unwrap();

        assert_eq!(
            fs::read_to_string(dst.join(".config/app/settings")).unwrap(),
            "from"
        );
        assert!(dst.join(".config/other").is_dir(), "what into had is kept");
        assert_eq!(fs::read_to_string(dst.join("both.txt")).unwrap(), "into");
        assert_eq!(fs::read_to_string(aside.join("both.txt")).unwrap(), "from");
        assert_eq!(
            fs::read_to_string(dst.join("only-from.txt")).unwrap(),
            "from"
        );
        assert_eq!(
            fs::read_link(dst.join("link")).unwrap(),
            PathBuf::from("only-from.txt")
        );
        assert_eq!(fs::read_to_string(dst.join("clash")).unwrap(), "file");
        assert_eq!(fs::read_to_string(aside.join("clash/inner")).unwrap(), "x");
        assert_eq!(report.conflicts, 2);
        assert!(report.copied >= 4, "{report:?}");
    }

    /// The camera of a launch: the container's own word, the zone's where
    /// it has none, Nix's over either's local one.
    #[test]
    fn a_containers_camera_is_its_own_and_nix_is_not_overridden() {
        let base = std::env::temp_dir().join(format!("vz-camera-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let zone = base.join("state/nl");
        let config = base.join("config");
        fs::create_dir_all(&zone).unwrap();
        fs::create_dir_all(config.join("containers/work")).unwrap();
        fs::create_dir_all(config.join("declared/containers")).unwrap();
        let conf = config.join("containers/work/container.conf");
        assert!(!camera_for(&zone, &config, "nl", "work"));
        fs::write(zone.join(crate::hermetic::CAMERA), "on").unwrap();
        assert!(camera_for(&zone, &config, "nl", "work"));
        fs::write(&conf, "camera = false\n").unwrap();
        assert!(!camera_for(&zone, &config, "nl", "work"));
        fs::write(zone.join(crate::hermetic::CAMERA), "off").unwrap();
        fs::write(&conf, "camera = true\n").unwrap();
        assert!(camera_for(&zone, &config, "nl", "work"));
        // Nix's word for the zone over the container's local one.
        fs::write(config.join("declared/camera"), "nl\n").unwrap();
        fs::write(&conf, "camera = false\n").unwrap();
        assert!(camera_for(&zone, &config, "nl", "work"));
        // Nix's for the container over everything.
        fs::write(
            config.join("declared/containers/work.conf"),
            "home = private\ncamera = false\n",
        )
        .unwrap();
        assert!(!camera_for(&zone, &config, "nl", "work"));
        let _ = fs::remove_dir_all(&base);
    }
}
