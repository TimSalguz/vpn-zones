//! The tool manifest: everything the CLI needs Nix to pin, in one file.
//!
//! `vpn-zone` runs programs through `systemctl`, `nsenter`, `unshare`, `ip`,
//! `kdialog` and `vpn-zone-core`, and it has to name them by ABSOLUTE path: part
//! of what it starts runs inside a namespace where `PATH` can be anything at all
//! (`docs/GOTCHAS.md` §12). The bash version got those paths by string
//! interpolation, which is exactly what a compiled binary cannot do — so Nix
//! writes them into a small JSON file in the store and the wrapper in
//! `home.packages` points at it with ONE environment variable:
//!
//! ```sh
//! export VPN_ZONE_TOOLS=/nix/store/…-vpn-zone-tools.json
//! exec /nix/store/…-vpn-zone-rust/bin/vpn-zone "$@"
//! ```
//!
//! The same file carries the four paths that used to be interpolated as well:
//! `$HOME`, the state and profile directories and the profile-relative
//! `vpn-zone`/`vpn-zone-pick` that end up in generated `.desktop` files. Those
//! are deliberately NOT derived from `$HOME` at run time — home-manager knows
//! where it put them, and a zone directory silently moving because a service
//! started with a different `HOME` would be the worst kind of bug.
//!
//! **Why the parser is written out by hand.** The format is ours and flat: an
//! object of string to string, nothing else. `serde` would be a dependency (and
//! a build-time code generator) for two dozen lines of straight-line code, and
//! this file is read on the startup path of every program launched into a zone.
//! Anything the parser does not understand — a nested object, a number, a
//! missing key — is a loud error, never a silent default: a manifest that does
//! not match the code means the wrapper and the binary come from different
//! generations, and guessing would start a program in the wrong network.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

/// Variable the wrapper sets. Single by design: one thing to get right when the
/// binary is called from somewhere unusual (a unit, a test, a debugger).
pub const ENV_VAR: &str = "VPN_ZONE_TOOLS";

/// The paths of one manifest, resolved and checked once at startup.
///
/// Fields, not a map lookup: a missing key is then a single error at load time
/// with the key named in it, instead of a surprise in the middle of `vpn-zone
/// run` when the program was supposed to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tools {
    /// `$HOME` as home-manager knows it.
    pub home: PathBuf,
    /// `~/.local/state/vpn-zones` — the zones, and `.running`, `.pinned` and
    /// the rest of the picker's memory.
    pub state: PathBuf,
    /// `~/.local/state/vpn-profiles` — data containers. Deliberately outside the
    /// zone directory: a zone can be deleted when its VPN is blocked, the
    /// environment set up inside a container must outlive that
    /// (`docs/GOTCHAS.md` §5).
    pub profiles: PathBuf,
    /// `~/.local/state/vpn-sandboxes` — named sandboxes, which are not
    /// containers: their home is their own and empty.
    pub sandboxes: PathBuf,
    /// `~/.config/vpn-zones` — the settings the picker and the GUI share.
    pub config: PathBuf,
    /// `<profile>/bin/vpn-zone`: what a delegated launch re-enters through, and
    /// what the generated `.desktop` files call. The PROFILE path, not the
    /// store one — that is what breaks the dependency cycle between `vpn-zone`
    /// and `sync` and keeps shortcuts from going stale (`docs/GOTCHAS.md` §10).
    pub runner: PathBuf,
    /// `<profile>/bin/vpn-zone-pick`, for the same reason.
    pub picker: PathBuf,
    /// `vpn-zone-core`: the crate's own helper binary — `sync`, `profile-run`,
    /// `wl-sandbox`, `fs-sandbox`. This one IS a store path: it is versioned
    /// together with this binary and must not drift from it.
    pub core: PathBuf,
    pub systemctl: PathBuf,
    pub systemd_run: PathBuf,
    pub nsenter: PathBuf,
    pub unshare: PathBuf,
    pub ip: PathBuf,
    pub kdialog: PathBuf,
    /// The three the filesystem sandbox is given on its command line. The CLI
    /// does not run them itself; it passes them on to `vpn-zone-core
    /// fs-sandbox`, which is what the zone holder's unit does with `--ip` and
    /// friends.
    pub bwrap: PathBuf,
    pub dbus_proxy: PathBuf,
    pub xwayland: PathBuf,
}

/// The keys of the manifest, in the order they are reported. Kept next to the
/// struct so that `module/default.nix` and this file can be diffed by eye.
const KEYS: [&str; 17] = [
    "home",
    "state",
    "profiles",
    "sandboxes",
    "config",
    "runner",
    "picker",
    "core",
    "systemctl",
    "systemd-run",
    "nsenter",
    "unshare",
    "ip",
    "kdialog",
    "bwrap",
    "dbus-proxy",
    "xwayland",
];

/// Why the manifest could not be used. Every variant names the file: when this
/// goes wrong the user needs to know WHICH file to look at, and it is not one
/// they wrote.
#[derive(Debug)]
pub enum Error {
    NotSet,
    Unreadable(PathBuf, io::Error),
    Malformed(PathBuf, ParseError),
    MissingKey(PathBuf, &'static str),
    EmptyKey(PathBuf, &'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSet => write!(
                f,
                "не задана {ENV_VAR} — vpn-zone запускают обёрткой из home.packages, а не напрямую"
            ),
            Self::Unreadable(path, e) => {
                write!(f, "не читается список инструментов {}: {e}", path.display())
            }
            Self::Malformed(path, e) => {
                write!(f, "испорчен список инструментов {}: {e}", path.display())
            }
            Self::MissingKey(path, key) => write!(
                f,
                "в списке инструментов {} нет «{key}» — обёртка старее бинаря, пересобери модуль",
                path.display()
            ),
            Self::EmptyKey(path, key) => {
                write!(f, "в списке инструментов {} пустое «{key}»", path.display())
            }
        }
    }
}

impl std::error::Error for Error {}

impl Tools {
    /// Read the manifest the wrapper pointed at.
    pub fn from_env() -> Result<Self, Error> {
        let path = std::env::var_os(ENV_VAR)
            .filter(|v| !v.is_empty())
            .ok_or(Error::NotSet)?;
        Self::load(Path::new(&path))
    }

    /// Read and check one manifest file.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text =
            std::fs::read_to_string(path).map_err(|e| Error::Unreadable(path.to_path_buf(), e))?;
        let entries = parse_object(&text).map_err(|e| Error::Malformed(path.to_path_buf(), e))?;
        Self::from_entries(path, &entries)
    }

    /// Turn a parsed manifest into the struct, naming whatever is missing.
    pub fn from_entries(path: &Path, entries: &BTreeMap<String, String>) -> Result<Self, Error> {
        let take = |key: &'static str| -> Result<PathBuf, Error> {
            match entries.get(key) {
                None => Err(Error::MissingKey(path.to_path_buf(), key)),
                Some(v) if v.is_empty() => Err(Error::EmptyKey(path.to_path_buf(), key)),
                Some(v) => Ok(PathBuf::from(v)),
            }
        };
        Ok(Self {
            home: take("home")?,
            state: take("state")?,
            profiles: take("profiles")?,
            sandboxes: take("sandboxes")?,
            config: take("config")?,
            runner: take("runner")?,
            picker: take("picker")?,
            core: take("core")?,
            systemctl: take("systemctl")?,
            systemd_run: take("systemd-run")?,
            nsenter: take("nsenter")?,
            unshare: take("unshare")?,
            ip: take("ip")?,
            kdialog: take("kdialog")?,
            bwrap: take("bwrap")?,
            dbus_proxy: take("dbus-proxy")?,
            xwayland: take("xwayland")?,
        })
    }

    /// The keys a manifest has to carry. For diagnostics and for the tests that
    /// build one.
    pub fn keys() -> &'static [&'static str] {
        &KEYS
    }
}

/// What the manifest was not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Byte offset the parser stopped at.
    pub at: usize,
    pub what: &'static str,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "байт {}: {}", self.at, self.what)
    }
}

impl std::error::Error for ParseError {}

/// Parse `{"key": "value", …}` — a flat JSON object of strings, and nothing
/// else.
///
/// Duplicate keys keep the LAST value, the way every JSON reader does;
/// `builtins.toJSON` cannot produce them anyway.
pub fn parse_object(text: &str) -> Result<BTreeMap<String, String>, ParseError> {
    let bytes = text.as_bytes();
    let mut at = skip_ws(bytes, 0);
    expect(bytes, &mut at, b'{', "ожидалась «{»")?;
    let mut out = BTreeMap::new();

    at = skip_ws(bytes, at);
    if bytes.get(at) == Some(&b'}') {
        at += 1;
    } else {
        loop {
            at = skip_ws(bytes, at);
            let key = parse_string(bytes, &mut at)?;
            at = skip_ws(bytes, at);
            expect(bytes, &mut at, b':', "ожидалось «:»")?;
            at = skip_ws(bytes, at);
            let value = parse_string(bytes, &mut at)?;
            out.insert(key, value);
            at = skip_ws(bytes, at);
            match bytes.get(at) {
                Some(b',') => at += 1,
                Some(b'}') => {
                    at += 1;
                    break;
                }
                _ => {
                    return Err(ParseError {
                        at,
                        what: "ожидалось «,» или «}»",
                    })
                }
            }
        }
    }

    at = skip_ws(bytes, at);
    if at != bytes.len() {
        return Err(ParseError {
            at,
            what: "лишний текст после объекта",
        });
    }
    Ok(out)
}

fn skip_ws(bytes: &[u8], mut at: usize) -> usize {
    while matches!(bytes.get(at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        at += 1;
    }
    at
}

fn expect(bytes: &[u8], at: &mut usize, byte: u8, what: &'static str) -> Result<(), ParseError> {
    if bytes.get(*at) == Some(&byte) {
        *at += 1;
        return Ok(());
    }
    Err(ParseError { at: *at, what })
}

/// One JSON string, escapes and all. Values are paths, so this has to be exact:
/// a store path with a ` ` in it is not the path next to it.
fn parse_string(bytes: &[u8], at: &mut usize) -> Result<String, ParseError> {
    expect(bytes, at, b'"', "ожидалась строка в кавычках")?;
    let mut out = String::new();
    loop {
        let Some(&b) = bytes.get(*at) else {
            return Err(ParseError {
                at: *at,
                what: "строка не закрыта",
            });
        };
        *at += 1;
        match b {
            b'"' => return Ok(out),
            b'\\' => {
                let Some(&esc) = bytes.get(*at) else {
                    return Err(ParseError {
                        at: *at,
                        what: "строка не закрыта",
                    });
                };
                *at += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{8}'),
                    b'f' => out.push('\u{c}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => out.push(parse_unicode_escape(bytes, at)?),
                    _ => {
                        return Err(ParseError {
                            at: *at - 1,
                            what: "неизвестная escape-последовательность",
                        })
                    }
                }
            }
            // A raw control character is invalid JSON; anything else — including
            // every byte of a UTF-8 sequence, which `builtins.toJSON` writes
            // literally — is taken as it stands.
            0x00..=0x1f => {
                return Err(ParseError {
                    at: *at - 1,
                    what: "управляющий символ внутри строки",
                })
            }
            _ => {
                // The input was `&str`, so a byte that starts a multi-byte
                // sequence is followed by its continuation bytes; copy them all
                // at once and let `char` do the decoding.
                let start = *at - 1;
                let len = utf8_len(b);
                let end = start + len;
                let Some(chunk) = bytes.get(start..end) else {
                    return Err(ParseError {
                        at: start,
                        what: "обрезанная UTF-8 последовательность",
                    });
                };
                // Cannot fail: the slice came from a `&str` and starts at a
                // character boundary.
                out.push_str(std::str::from_utf8(chunk).map_err(|_| ParseError {
                    at: start,
                    what: "битая UTF-8 последовательность",
                })?);
                *at = end;
            }
        }
    }
}

/// `\uXXXX`, surrogate pairs included — Nix escapes nothing above ASCII, but a
/// hand-written manifest may well.
fn parse_unicode_escape(bytes: &[u8], at: &mut usize) -> Result<char, ParseError> {
    let first = hex4(bytes, at)?;
    if !(0xd800..0xdc00).contains(&first) {
        return char::from_u32(first).ok_or(ParseError {
            at: *at,
            what: "недопустимый код символа",
        });
    }
    // A high surrogate is only half a character: the low half has to follow as
    // its own escape.
    if bytes.get(*at) != Some(&b'\\') || bytes.get(*at + 1) != Some(&b'u') {
        return Err(ParseError {
            at: *at,
            what: "суррогатная пара не дописана",
        });
    }
    *at += 2;
    let second = hex4(bytes, at)?;
    if !(0xdc00..0xe000).contains(&second) {
        return Err(ParseError {
            at: *at,
            what: "суррогатная пара не дописана",
        });
    }
    let code = 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00);
    char::from_u32(code).ok_or(ParseError {
        at: *at,
        what: "недопустимый код символа",
    })
}

fn hex4(bytes: &[u8], at: &mut usize) -> Result<u32, ParseError> {
    let mut value: u32 = 0;
    for _ in 0..4 {
        let Some(&b) = bytes.get(*at) else {
            return Err(ParseError {
                at: *at,
                what: "оборванный \\u-escape",
            });
        };
        let digit = match b {
            b'0'..=b'9' => u32::from(b - b'0'),
            b'a'..=b'f' => u32::from(b - b'a') + 10,
            b'A'..=b'F' => u32::from(b - b'A') + 10,
            _ => {
                return Err(ParseError {
                    at: *at,
                    what: "не шестнадцатеричная цифра в \\u-escape",
                })
            }
        };
        value = value * 16 + digit;
        *at += 1;
    }
    Ok(value)
}

/// Length in bytes of the UTF-8 sequence this byte starts.
fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn a_flat_object_of_strings_is_all_there_is() {
        let parsed = parse_object(r#"{"ip":"/nix/store/x/bin/ip","kdialog":"/k"}"#).unwrap();
        assert_eq!(
            parsed,
            map(&[("ip", "/nix/store/x/bin/ip"), ("kdialog", "/k")])
        );
    }

    #[test]
    fn whitespace_and_newlines_are_ignored() {
        let parsed = parse_object("  {\n\t\"a\" : \"1\" ,\n \"b\":\"2\"\n}  \n").unwrap();
        assert_eq!(parsed, map(&[("a", "1"), ("b", "2")]));
        assert_eq!(parse_object("{}").unwrap(), BTreeMap::new());
        assert_eq!(parse_object(" { } ").unwrap(), BTreeMap::new());
    }

    #[test]
    fn escapes_are_decoded() {
        let parsed = parse_object(
            r#"{"quote":"a\"b","slash":"a\\b\/c","white":"a\nb\tc","short":"A","pair":"😀"}"#,
        )
        .unwrap();
        assert_eq!(parsed["quote"], "a\"b");
        assert_eq!(parsed["slash"], "a\\b/c");
        assert_eq!(parsed["white"], "a\nb\tc");
        assert_eq!(parsed["short"], "A");
        assert_eq!(parsed["pair"], "😀");
    }

    #[test]
    fn non_ascii_is_taken_as_it_is() {
        // `builtins.toJSON` writes UTF-8 literally rather than escaping it.
        let parsed = parse_object("{\"путь\":\"/дом/файл\"}").unwrap();
        assert_eq!(parsed["путь"], "/дом/файл");
    }

    #[test]
    fn the_last_value_of_a_repeated_key_wins() {
        let parsed = parse_object(r#"{"ip":"/one","ip":"/two"}"#).unwrap();
        assert_eq!(parsed["ip"], "/two");
    }

    #[test]
    fn anything_that_is_not_a_flat_string_object_is_refused() {
        for bad in [
            "",
            "{",
            "[]",
            r#"{"a":1}"#,
            r#"{"a":true}"#,
            r#"{"a":null}"#,
            r#"{"a":{"b":"c"}}"#,
            r#"{"a":["b"]}"#,
            r#"{"a":"b",}"#,
            r#"{"a" "b"}"#,
            r#"{a:"b"}"#,
            r#"{"a":"b"} junk"#,
            r#"{"a":"b"#,
            r#"{"a":"\q"}"#,
            r#"{"a":"\u00"}"#,
            r#"{"a":"\ud83d"}"#,
            "{\"a\":\"line\nbreak\"}",
        ] {
            assert!(
                parse_object(bad).is_err(),
                "«{bad}» приняли за список инструментов"
            );
        }
    }

    #[test]
    fn a_complete_manifest_becomes_paths() {
        let entries: BTreeMap<String, String> = Tools::keys()
            .iter()
            .map(|k| ((*k).to_owned(), format!("/p/{k}")))
            .collect();
        let tools = Tools::from_entries(Path::new("/m.json"), &entries).unwrap();
        assert_eq!(tools.home, PathBuf::from("/p/home"));
        assert_eq!(tools.systemd_run, PathBuf::from("/p/systemd-run"));
        assert_eq!(tools.dbus_proxy, PathBuf::from("/p/dbus-proxy"));
        assert_eq!(tools.core, PathBuf::from("/p/core"));
    }

    #[test]
    fn a_missing_or_empty_key_names_itself() {
        let mut entries: BTreeMap<String, String> = Tools::keys()
            .iter()
            .map(|k| ((*k).to_owned(), format!("/p/{k}")))
            .collect();
        entries.remove("nsenter");
        let e = Tools::from_entries(Path::new("/m.json"), &entries).unwrap_err();
        assert!(matches!(e, Error::MissingKey(_, "nsenter")), "{e}");
        assert!(e.to_string().contains("nsenter"));

        entries.insert("nsenter".to_owned(), String::new());
        let e = Tools::from_entries(Path::new("/m.json"), &entries).unwrap_err();
        assert!(matches!(e, Error::EmptyKey(_, "nsenter")), "{e}");
    }
}
