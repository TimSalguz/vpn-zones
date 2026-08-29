//! Tab completion for the `vpn-zone` CLI.
//!
//! One machine, two thin shells: the hidden verb `vpn-zone _complete --
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
    pub profiles: Vec<String>,
    pub sandboxes: Vec<String>,
    /// Programs with a remembered permission set (`fs-perms/*`).
    pub perm_keys: Vec<String>,
    /// Programs pinned to a network (`.pinned/*`) — what `forget` takes.
    pub pinned: Vec<String>,
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
            profiles: Self::names(&tools.profiles),
            sandboxes: Self::names(&tools.sandboxes),
            perm_keys: Self::names(&tools.config.join("fs-perms")),
            pinned: Self::names(&tools.state.join(".pinned")),
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
    "unlock",
    "profile",
    "help",
];

/// Verbs whose first argument is a zone name.
const ZONE_VERBS: &[&str] = &[
    "up",
    "down",
    "status",
    "check",
    "run",
    "rm",
    "lock",
    "unlock",
    "reset-profile",
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
                    "--profile" | "-p" => owned(&mut out, &snap.profiles),
                    "--sandbox" => owned(&mut out, &snap.sandboxes),
                    _ if pos == 2 => owned(&mut out, &snap.zones),
                    _ => strs(
                        &mut out,
                        &["--profile", "--sandbox", "--fs-sandbox", "--tmp-profile", "--"],
                    ),
                }
            }
            v if ZONE_VERBS.contains(&v) && pos == 2 => owned(&mut out, &snap.zones),
            "add" if pos == 3 => return vec![FILES.to_string()],
            "isolate" if pos == 2 => strs(&mut out, &["overlay", "off"]),
            "mode" if pos == 2 => strs(&mut out, &["picker", "per-zone", "both", "off"]),
            "wayland-sandbox" if pos == 2 => strs(&mut out, &["on", "off"]),
            "default" if pos == 2 => {
                strs(&mut out, &["offline", "direct"]);
                owned(&mut out, &snap.zones);
            }
            "default-profile" if pos == 2 => {
                strs(&mut out, &["ask", "main", "own"]);
                owned(&mut out, &snap.profiles);
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
            "sandbox" if pos == 2 => strs(&mut out, &["create", "list", "rm"]),
            "sandbox" if pos == 3 && word(2) == "rm" => owned(&mut out, &snap.sandboxes),
            "profile" if pos == 2 => strs(&mut out, &["create", "list", "rm"]),
            "profile" if pos == 3 && word(2) == "rm" => owned(&mut out, &snap.profiles),
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
            profiles: vec!["work".into()],
            sandboxes: vec!["dev".into()],
            perm_keys: vec!["telegram".into()],
            pinned: vec!["firefox".into()],
        }
    }

    fn complete(line: &[&str], cursor: usize) -> Vec<String> {
        let words: Vec<String> = line.iter().map(|s| (*s).to_string()).collect();
        candidates(&words, cursor, &snap())
    }

    #[test]
    fn the_first_word_offers_verbs_and_respects_the_prefix() {
        assert!(complete(&["vpn-zone", ""], 2).contains(&"up".to_string()));
        assert_eq!(complete(&["vpn-zone", "de"], 2), ["default", "default-profile"]);
        // The hidden verb stays hidden.
        assert!(!complete(&["vpn-zone", "_"], 2).iter().any(|c| c == "_complete"));
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
        assert_eq!(complete(&["vpn-zone", "run", "nl", "--profile", ""], 5), ["work"]);
        assert_eq!(complete(&["vpn-zone", "run", "nl", "-p", ""], 5), ["work"]);
        assert_eq!(complete(&["vpn-zone", "run", "nl", "--sandbox", ""], 5), ["dev"]);
        // After the `--` it is the program's command line: files, not ours.
        assert_eq!(complete(&["vpn-zone", "run", "nl", "--", "fire"], 5), [FILES]);
    }

    #[test]
    fn subverbs_and_their_arguments() {
        assert_eq!(complete(&["vpn-zone", "perms", ""], 3), ["list", "reset"]);
        assert_eq!(
            complete(&["vpn-zone", "perms", "reset", ""], 4),
            ["telegram", "--all"]
        );
        assert_eq!(complete(&["vpn-zone", "sandbox", "rm", ""], 4), ["dev"]);
        assert_eq!(complete(&["vpn-zone", "profile", "rm", ""], 4), ["work"]);
        assert_eq!(
            complete(&["vpn-zone", "forget", ""], 3),
            ["firefox", "--all"]
        );
        assert_eq!(
            complete(&["vpn-zone", "default", "o"], 3),
            ["offline"]
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
