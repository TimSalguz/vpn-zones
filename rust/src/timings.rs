//! The few waits that are meant to end by a clock, as settings the person
//! owns (the owner, 2026-09-27: "the ones kept on purpose — adjustable in
//! stillconf").
//!
//! Every other wait in the project ends on an event — the thing is there, or
//! whoever makes it is gone (`docs/LEAK-MODEL.md`). These do not, on purpose:
//!
//! * [`QUESTION`]: how long a question of the broker's waits for its answer
//!   before it is closed and the request refused. One question is open at a
//!   time: while it waits, the next is refused, not queued — `never` keeps it
//!   until it is answered;
//! * [`HANDSHAKE_CHECK`]: how long the zone-adding dialog waits before it
//!   tells whether the new zone's tunnel has shaken hands. "Not yet" is never
//!   told from "never" without some time; the zone stays up either way, and
//!   the notice says "not yet".
//!
//! Each is a one-line file of `~/.config/vpn-zones`, `declared/` (Nix) before
//! the local one, then the default — `cellward <name> <term>|default`, and
//! `settings.<name>` in `status --json`. A value outside the bounds is passed
//! over, never read as no wait.

use std::path::Path;
use std::time::Duration;

use crate::container::Source;

/// A term, or none at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Term {
    After(u64),
    Never,
}

impl Term {
    /// As the setting's file and `status --json` write it: `2m`, `never`.
    pub fn text(self) -> String {
        match self {
            Term::After(secs) => crate::grants::term_text(secs),
            Term::Never => "never".to_owned(),
        }
    }

    pub fn duration(self) -> Option<Duration> {
        match self {
            Term::After(secs) => Some(Duration::from_secs(secs)),
            Term::Never => None,
        }
    }
}

/// A setting that is a term.
#[derive(Debug, Clone, Copy)]
pub struct Setting {
    /// The file, the command and the key in `status --json` (with `_`).
    pub name: &'static str,
    /// Its option in `programs.cellward`.
    pub nix: &'static str,
    pub default: Term,
    pub min: u64,
    pub max: u64,
    /// Whether `never` is a value.
    pub never: bool,
}

pub const QUESTION: Setting = Setting {
    name: "question-timeout",
    nix: "questionTimeout",
    default: Term::After(120),
    min: 30,
    max: 86_400,
    never: true,
};

pub const HANDSHAKE_CHECK: Setting = Setting {
    name: "handshake-check",
    nix: "handshakeCheckAfter",
    default: Term::After(6),
    min: 1,
    max: 600,
    never: false,
};

impl Setting {
    /// A value as the command and the file take it: a term within the bounds,
    /// or `never` where that is one.
    pub fn parse(&self, text: &str) -> Option<Term> {
        let text = text.trim();
        if text == "never" {
            return self.never.then_some(Term::Never);
        }
        crate::grants::parse_term(text)
            .filter(|secs| (self.min..=self.max).contains(secs))
            .map(Term::After)
    }

    /// Its value and where it comes from: Nix, the local file, the default.
    pub fn read(&self, config: &Path) -> (Term, Source) {
        let declared = config.join(crate::cli::DECLARED_DIR).join(self.name);
        for (path, source) in [
            (declared, Source::Nix),
            (config.join(self.name), Source::Local),
        ] {
            if let Some(term) = std::fs::read_to_string(&path)
                .ok()
                .and_then(|t| self.parse(&t))
            {
                return (term, source);
            }
        }
        (self.default, Source::Default)
    }

    /// The bounds, as the command's help says them.
    pub fn bounds(&self) -> String {
        let range = format!(
            "{}…{}",
            crate::grants::term_text(self.min),
            crate::grants::term_text(self.max)
        );
        if self.never {
            format!("{range} или never")
        } else {
            range
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_term_is_read_from_nix_before_the_local_file_and_within_its_bounds() {
        let dir = std::env::temp_dir().join(format!("vz-timings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(crate::cli::DECLARED_DIR)).unwrap();
        assert_eq!(QUESTION.read(&dir), (Term::After(120), Source::Default));
        std::fs::write(dir.join(QUESTION.name), "never\n").unwrap();
        assert_eq!(QUESTION.read(&dir), (Term::Never, Source::Local));
        std::fs::write(dir.join(crate::cli::DECLARED_DIR).join(QUESTION.name), "5m").unwrap();
        assert_eq!(QUESTION.read(&dir), (Term::After(300), Source::Nix));
        // Out of bounds, or not a word it takes: passed over.
        std::fs::write(dir.join(crate::cli::DECLARED_DIR).join(QUESTION.name), "5s").unwrap();
        assert_eq!(QUESTION.read(&dir), (Term::Never, Source::Local));
        assert_eq!(HANDSHAKE_CHECK.parse("never"), None);
        assert_eq!(HANDSHAKE_CHECK.parse("15s"), Some(Term::After(15)));
        assert_eq!(HANDSHAKE_CHECK.parse("11m"), None);
        assert_eq!(Term::After(120).text(), "2m");
        assert_eq!(Term::Never.duration(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
