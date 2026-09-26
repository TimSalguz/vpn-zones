//! Tab completion for the `cellward` CLI (`cw` and the old `vpn-zone` are the
//! same program).
//!
//! One machine, two thin shells: the hidden verb `cellward _complete --
//! <words…> <cursor>` prints one candidate per line, and the zsh/bash scripts
//! installed by the module (module/default.nix) do nothing but call it. The
//! rules live HERE, next to the verbs they describe, so a new verb and its
//! completion cannot drift apart silently — and the candidate list is a pure
//! function of the command line plus a directory snapshot, tested as one.
//!
//! Protocol. `words` is the full command line including the program name;
//! `cursor` is the 1-based index of the word being completed — the shells'
//! own convention (`$CURRENT` in zsh, `COMP_CWORD + 1` in bash). Candidates
//! are filtered by the current word's prefix ON THIS SIDE: zsh would match
//! them itself, but bash inserts whatever it is given. The one special
//! candidate `__files__` asks the shell to fall back to its file completion —
//! paths are the thing the shell completes better than we can.

use std::ffi::OsString;
use std::fs;
use std::path::Path;

use crate::tools::Tools;

/// The shell's cue to complete file names instead.
pub const FILES: &str = "__files__";

/// Names the candidates are built from — a snapshot, so `candidates()` stays a
/// pure function and the tests need no filesystem.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub zones: Vec<String>,
    /// Every container by its name, whatever its home.
    pub containers: Vec<String>,
    /// Programs with a remembered permission set (`fs-perms/*`).
    pub perm_keys: Vec<String>,
    /// Programs pinned to a container (`.pinnedprofile/*`) — what `forget`
    /// takes.
    pub pinned: Vec<String>,
    /// Launcher ids the picker knows by name (`.labels/*`) — what `launch`
    /// takes.
    pub apps: Vec<String>,
}

impl Snapshot {
    /// Visible directory entries, dot-names skipped — the same rule
    /// `vpn-zone list` applies to the state directory.
    fn names(dir: &Path) -> Vec<String> {
        let Ok(entries) = fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut out: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| !n.starts_with('.'))
            .collect();
        out.sort();
        out
    }

    pub fn gather(tools: &Tools) -> Self {
        Self {
            zones: Self::names(&tools.state),
            containers: {
                let mut names: Vec<String> = Self::names(&tools.profiles)
                    .into_iter()
                    .chain(Self::names(
                        &tools.config.join(crate::container::POLICY_DIR),
                    ))
                    .filter(|n| crate::container::valid_name(n))
                    .collect();
                names.sort();
                names.dedup();
                names
            },
            perm_keys: Self::names(&tools.config.join("fs-perms")),
            pinned: Self::names(&tools.state.join(".pinnedprofile")),
            apps: Self::names(&tools.state.join(".labels")),
        }
    }
}

/// Every verb the dispatcher knows, in the order of `USAGE`. `_complete`
/// itself is absent on purpose: a hidden verb must not advertise itself.
const VERBS: &[&str] = &[
    "add",
    "up",
    "down",
    "list",
    "status",
    "run",
    "launch",
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
    "wayland-sandbox",
    "wayland-proxy",
    "frame",
    "check",
    "hermetic",
    "x11",
    "nix-daemon",
    "host-files",
    "camera",
    "microphone",
    "screencast",
    "ask-again",
    "question-timeout",
    "handshake-check",
    "audio-manager",
    "doctor",
    "watch",
    "journal",
    "kill",
    "lock",
    "unlock",
    "profile",
    "trust",
    "container",
    "devices",
    "help",
];

/// Verbs whose first argument is a zone name.
const ZONE_VERBS: &[&str] = &[
    "kill",
    "hermetic",
    "x11",
    "nix-daemon",
    "host-files",
    "camera",
    "microphone",
    "screencast",
    "audio-manager",
    "up",
    "down",
    "status",
    "check",
    "run",
    "rm",
    "lock",
    "unlock",
];

/// What belongs at the cursor. Empty means "nothing to suggest" — bash then
/// completes nothing rather than nonsense.
pub fn candidates(words: &[String], cursor: usize, snap: &Snapshot) -> Vec<String> {
    // 1-based cursor → 0-based index of the word under it. Position 0 is the
    // program name — nothing of ours.
    let Some(pos) = cursor.checked_sub(1).filter(|p| *p >= 1) else {
        return Vec::new();
    };
    let prefix = words.get(pos).map(String::as_str).unwrap_or("");
    let word = |i: usize| words.get(i).map(String::as_str).unwrap_or("");

    fn strs(out: &mut Vec<String>, items: &[&str]) {
        out.extend(items.iter().map(|s| (*s).to_string()));
    }
    fn owned(out: &mut Vec<String>, items: &[String]) {
        out.extend(items.iter().cloned());
    }

    let mut out: Vec<String> = Vec::new();
    if pos == 1 {
        strs(&mut out, VERBS);
    } else {
        let verb = word(1);
        match verb {
            "run" => {
                // `run <зона> [флаги] -- <команда…>`: after the `--` it is the
                // program's own command line — the shell's file completion
                // does that part better.
                if words[2..pos.min(words.len())].iter().any(|w| w == "--") {
                    return vec![FILES.to_string()];
                }
                match word(pos - 1) {
                    "--container" | "--profile" | "-p" | "--sandbox" => {
                        owned(&mut out, &snap.containers)
                    }
                    _ if pos == 2 => owned(&mut out, &snap.zones),
                    _ => strs(
                        &mut out,
                        &[
                            "--container",
                            "--profile",
                            "--sandbox",
                            "--fs-sandbox",
                            "--tmp-profile",
                            "--",
                        ],
                    ),
                }
            }
            // The flag only for a dash: an empty word is a zone's place.
            "hermetic" if pos == 2 && prefix.starts_with('-') => strs(&mut out, &["--default"]),
            v if ZONE_VERBS.contains(&v) && pos == 2 => owned(&mut out, &snap.zones),
            "add" if pos == 3 => return vec![FILES.to_string()],
            "x11" if pos == 3 => strs(&mut out, &["on", "off"]),
            // The default first; `default` only where it follows something.
            "nix-daemon" if pos == 3 => strs(&mut out, &["off", "on"]),
            "host-files" if pos == 3 => strs(&mut out, &["read-only", "writable"]),
            "camera" | "audio-manager" if pos == 3 => strs(&mut out, &["off", "on"]),
            "microphone" | "screencast" if pos == 3 => strs(&mut out, &["ask", "yes", "no"]),
            "ask-again" if pos == 2 => strs(&mut out, &["3m", "1m", "10m", "1h"]),
            "question-timeout" if pos == 2 => {
                strs(&mut out, &["2m", "5m", "30m", "never", "default"])
            }
            "handshake-check" if pos == 2 => strs(&mut out, &["6s", "15s", "30s", "default"]),
            "hermetic" if pos == 3 => match word(2) {
                "--default" => strs(&mut out, &["on", "off"]),
                _ => strs(&mut out, &["default", "on", "off"]),
            },
            "doctor" => {
                owned(&mut out, &snap.zones);
                strs(&mut out, &["--json"]);
            }
            "mode" if pos == 2 => strs(&mut out, &["picker", "per-zone", "both", "off"]),
            "wayland-sandbox" if pos == 2 => strs(&mut out, &["on", "off"]),
            "frame" if pos == 2 => strs(&mut out, &["show", "hide", "width", "title", "color"]),
            "frame" if pos == 3 && word(2) == "width" => strs(&mut out, &["4"]),
            "frame" if pos == 3 && word(2) == "title" => {
                strs(&mut out, &["always", "hover", "off"])
            }
            "frame" if pos == 3 && word(2) == "color" => owned(&mut out, &snap.zones),
            "frame" if pos == 4 && word(2) == "color" => strs(&mut out, &["default"]),
            "default" if pos == 2 => {
                strs(&mut out, &["offline", "unconfined"]);
                owned(&mut out, &snap.zones);
            }
            "default-profile" if pos == 2 => {
                strs(&mut out, &["ask", "main", "own"]);
                owned(&mut out, &snap.containers);
            }
            "forget" if pos == 2 => {
                owned(&mut out, &snap.pinned);
                strs(&mut out, &["--all"]);
            }
            "perms" if pos == 2 => strs(&mut out, &["list", "reset"]),
            "perms" if pos == 3 && word(2) == "reset" => {
                owned(&mut out, &snap.perm_keys);
                strs(&mut out, &["--all"]);
            }
            "sandbox" | "profile" if pos == 2 => strs(&mut out, &["create", "list", "rm"]),
            "sandbox" | "profile" if pos == 3 && word(2) == "rm" => {
                owned(&mut out, &snap.containers)
            }
            "trust" if pos == 2 => strs(&mut out, &["add", "list", "rm", "reset"]),
            "trust" if pos == 3 => owned(&mut out, &snap.containers),
            "trust" if pos == 4 && word(2) == "add" => return vec![FILES.to_string()],
            "launch" if pos == 2 => owned(&mut out, &snap.apps),
            "container" if pos == 2 => strs(
                &mut out,
                &[
                    "list", "show", "create", "rm", "set", "assign", "unassign", "grant", "revoke",
                    "merge", "devices", "links",
                ],
            ),
            "container" if pos == 4 && word(2) == "create" => strs(&mut out, &["--home"]),
            "container" if pos == 5 && word(2) == "create" => {
                strs(&mut out, &["private", "layer", "main"])
            }
            "container"
                if pos == 3
                    && matches!(
                        word(2),
                        "grant" | "revoke" | "merge" | "show" | "set" | "rm" | "devices" | "links"
                    ) =>
            {
                owned(&mut out, &snap.containers)
            }
            "container" if pos == 4 && matches!(word(2), "grant" | "revoke") => {
                return vec![FILES.to_string()]
            }
            "container" if pos == 5 && word(2) == "grant" => strs(&mut out, &["--for"]),
            "container" if pos == 4 && word(2) == "merge" => owned(&mut out, &snap.containers),
            "container" if pos == 4 && word(2) == "set" => strs(
                &mut out,
                &[
                    "network",
                    "x11",
                    "home",
                    "color",
                    "microphone",
                    "screencast",
                    "camera",
                ],
            ),
            "container" if pos == 4 && word(2) == "devices" => strs(&mut out, &["add", "rm"]),
            "container" if pos == 5 && word(2) == "devices" => strs(
                &mut out,
                &["games", "security-keys", "phone", "serial", "vm", "usb:"],
            ),
            "devices" if pos == 2 => strs(&mut out, &["--json"]),
            "container" if pos == 4 && word(2) == "links" => strs(&mut out, &["set", "rm"]),
            "container" if pos == 5 && word(2) == "links" => {
                strs(&mut out, &["https", "http", "mailto", "tg"])
            }
            "container" if pos == 6 && word(2) == "links" && word(4) == "set" => {
                owned(&mut out, &snap.apps)
            }
            "container" if pos == 5 && word(2) == "set" && word(4) == "camera" => {
                strs(&mut out, &["default", "on", "off"])
            }
            "container" if pos == 5 && word(2) == "set" && word(4) == "x11" => {
                strs(&mut out, &["on", "off"])
            }
            "container" if pos == 5 && word(2) == "set" && word(4) == "color" => {
                strs(&mut out, &["default"])
            }
            "container"
                if pos == 5
                    && word(2) == "set"
                    && matches!(word(4), "microphone" | "screencast") =>
            {
                strs(&mut out, &["default", "yes", "no", "ask"])
            }
            "container" if pos == 5 && word(2) == "set" && word(4) == "home" => {
                strs(&mut out, &["private", "layer", "main"])
            }
            "container" if pos == 5 && word(2) == "set" => {
                strs(&mut out, &["ask", "unconfined", "offline"]);
                owned(&mut out, &snap.zones);
            }
            "container" if pos == 4 && word(2) == "assign" => owned(&mut out, &snap.containers),
            _ => {}
        }
    }

    out.retain(|c| c.starts_with(prefix));
    out.dedup();
    out
}

/// The `_complete` verb: parse the protocol, print one candidate per line.
///
/// Anything malformed prints nothing and exits 0 — a completion that fails
/// LOUDLY garbles the command line the user is still typing.
pub fn run(tools: &Tools, args: &[OsString]) -> u8 {
    let args = match args.first() {
        Some(sep) if sep == "--" => &args[1..],
        _ => args,
    };
    let Some((cursor_raw, words_raw)) = args.split_last() else {
        return 0;
    };
    let Ok(cursor) = cursor_raw.to_string_lossy().parse::<usize>() else {
        return 0;
    };
    let words: Vec<String> = words_raw
        .iter()
        .map(|w| w.to_string_lossy().into_owned())
        .collect();
    for candidate in candidates(&words, cursor, &Snapshot::gather(tools)) {
        println!("{candidate}");
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap() -> Snapshot {
        Snapshot {
            zones: vec!["nl".into(), "ru".into()],
            containers: vec!["dev".into(), "work".into()],
            perm_keys: vec!["telegram".into()],
            pinned: vec!["firefox".into()],
            apps: vec!["firefox".into(), "org.telegram.desktop".into()],
        }
    }

    fn complete(line: &[&str], cursor: usize) -> Vec<String> {
        let words: Vec<String> = line.iter().map(|s| (*s).to_string()).collect();
        candidates(&words, cursor, &snap())
    }

    #[test]
    fn the_first_word_offers_verbs_and_respects_the_prefix() {
        assert!(complete(&["vpn-zone", ""], 2).contains(&"up".to_string()));
        assert_eq!(
            complete(&["vpn-zone", "de"], 2),
            ["default", "default-profile", "devices"]
        );
        // The hidden verb stays hidden.
        assert!(!complete(&["vpn-zone", "_"], 2)
            .iter()
            .any(|c| c == "_complete"));
    }

    /// `cellward`, `cw` and the old `vpn-zone` are one program: the command's
    /// own name is not what the answer depends on.
    #[test]
    fn every_name_of_the_command_completes_the_same() {
        for line in [
            &["", "de"][..],
            &["", "run", "nl", "--profile", ""],
            &["", "container", "set", "dev", "network", "o"],
        ] {
            let expected = complete(&[&["vpn-zone"], &line[1..]].concat(), line.len());
            assert!(!expected.is_empty(), "{line:?}");
            for name in ["cellward", "cw"] {
                assert_eq!(
                    complete(&[&[name], &line[1..]].concat(), line.len()),
                    expected,
                    "{name} {line:?}"
                );
            }
        }
    }

    #[test]
    fn zone_verbs_offer_zones() {
        for verb in ZONE_VERBS {
            assert_eq!(complete(&["vpn-zone", verb, ""], 3), ["nl", "ru"], "{verb}");
        }
        // …and only in the zone slot.
        assert!(complete(&["vpn-zone", "down", "nl", ""], 4).is_empty());
    }

    #[test]
    fn run_understands_its_flags() {
        let flags = complete(&["vpn-zone", "run", "nl", ""], 4);
        assert!(flags.contains(&"--profile".to_string()));
        assert_eq!(
            complete(&["vpn-zone", "run", "nl", "--container", ""], 5),
            ["dev", "work"]
        );
        // The old words name the same containers.
        for flag in ["--profile", "-p", "--sandbox"] {
            assert_eq!(
                complete(&["vpn-zone", "run", "nl", flag, ""], 5),
                ["dev", "work"],
                "{flag}"
            );
        }
        // After the `--` it is the program's command line: files, not ours.
        assert_eq!(
            complete(&["vpn-zone", "run", "nl", "--", "fire"], 5),
            [FILES]
        );
    }

    #[test]
    fn subverbs_and_their_arguments() {
        assert_eq!(complete(&["vpn-zone", "perms", ""], 3), ["list", "reset"]);
        assert_eq!(
            complete(&["vpn-zone", "perms", "reset", ""], 4),
            ["telegram", "--all"]
        );
        assert_eq!(
            complete(&["vpn-zone", "sandbox", "rm", ""], 4),
            ["dev", "work"]
        );
        assert_eq!(
            complete(&["vpn-zone", "profile", "rm", ""], 4),
            ["dev", "work"]
        );
        assert_eq!(
            complete(&["vpn-zone", "container", "create", "x", "--home", ""], 6),
            ["private", "layer", "main"]
        );
        assert_eq!(
            complete(&["vpn-zone", "container", "set", "work", "h"], 5),
            ["home"]
        );
        assert_eq!(complete(&["vpn-zone", "trust", "r"], 3), ["rm", "reset"]);
        assert_eq!(
            complete(&["vpn-zone", "trust", "add", ""], 4),
            ["dev", "work"]
        );
        assert_eq!(
            complete(&["vpn-zone", "trust", "add", "work", ""], 5),
            [FILES]
        );
        assert_eq!(
            complete(&["vpn-zone", "container", "set", "dev", "network", "o"], 6),
            ["offline"]
        );
        assert_eq!(
            complete(&["vpn-zone", "container", "assign", "firefox", ""], 5),
            ["dev", "work"]
        );
        assert_eq!(
            complete(&["vpn-zone", "container", "set", "work", "x11", ""], 6),
            ["on", "off"]
        );
        assert_eq!(complete(&["vpn-zone", "hermetic", "-"], 3), ["--default"]);
        assert_eq!(
            complete(&["vpn-zone", "hermetic", "--default", ""], 4),
            ["on", "off"]
        );
        assert_eq!(
            complete(&["vpn-zone", "hermetic", "nl", "d"], 4),
            ["default"]
        );
        assert_eq!(
            complete(&["cellward", "screencast", "nl", ""], 4),
            ["ask", "yes", "no"]
        );
        assert_eq!(complete(&["cellward", "screencast", ""], 3), ["nl", "ru"]);
        assert_eq!(
            complete(&["vpn-zone", "container", "grant", ""], 4),
            ["dev", "work"]
        );
        assert_eq!(
            complete(&["vpn-zone", "container", "grant", "dev", ""], 5),
            [FILES]
        );
        assert_eq!(
            complete(&["vpn-zone", "container", "merge", "work", ""], 5),
            ["dev", "work"]
        );
        assert_eq!(
            complete(&["vpn-zone", "forget", ""], 3),
            ["firefox", "--all"]
        );
        assert_eq!(complete(&["vpn-zone", "default", "o"], 3), ["offline"]);
        assert_eq!(
            complete(&["vpn-zone", "doctor", "nl", ""], 4),
            ["nl", "ru", "--json"]
        );
        assert_eq!(
            complete(&["vpn-zone", "launch", "org"], 3),
            ["org.telegram.desktop"]
        );
        assert_eq!(complete(&["vpn-zone", "add", "name", ""], 4), [FILES]);
    }

    #[test]
    fn nothing_is_suggested_where_nothing_belongs() {
        // The program name itself, a cursor of zero, free-text slots.
        assert!(complete(&["vpn-zone"], 1).is_empty());
        assert!(complete(&["vpn-zone", "up"], 0).is_empty());
        assert!(complete(&["vpn-zone", "add", ""], 3).is_empty());
        assert!(complete(&["vpn-zone", "list", ""], 3).is_empty());
    }
}
