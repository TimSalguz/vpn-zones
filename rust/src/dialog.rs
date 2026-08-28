//! The three shapes of `kdialog` call this project makes, and the one
//! `notify-send` one.
//!
//! They live together because the traps are shared, and every one of them was
//! paid for by a dialog that closed without a word:
//!
//! * **the answer comes back on stdout, and a cancel is a non-zero exit.** The
//!   shell wrote `choice=$(kdialog … ) || exit 0`, so "the user said no" and
//!   "kdialog is not installed" are the same thing on purpose — both mean this
//!   launch is over, and quietly;
//! * **stderr is thrown away.** Qt is chatty on a session without a
//!   compositor, and those lines end up in a launcher's log where nobody reads
//!   them;
//! * **an argument starting with `-` is taken for an option** and kdialog
//!   closes with no message at all. That is why profile and sandbox names may
//!   not start with a dash (`docs/GOTCHAS.md` §11), and why the menu builders
//!   skip such directories instead of showing them;
//! * **`--separate-output` matters for a checklist** (one token per line), and
//!   `--dontagain <key>` is what lets a warning be silenced for good.
//!
//! There is no display check here on purpose: the CALLER has to decide what to
//! do without a graphical session, because "cancelled" and "there was nowhere
//! to ask" call for opposite answers (`docs/GOTCHAS.md` §5, §6, §11).

use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, Stdio};

/// Application name every notification of this project carries.
pub const APP: &str = "VPN-зоны";

/// One dialog that returns a choice: `--menu`, `--inputbox`,
/// `--getopenfilename`.
///
/// `None` means "no answer": cancelled, closed, or kdialog could not be
/// started. Trailing newlines are dropped the way command substitution did;
/// nothing else is touched, because a label may legitimately end in a space.
pub fn ask<I, S>(kdialog: &Path, args: I) -> Option<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let out = Command::new(kdialog)
        .args(args)
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    while text.ends_with('\n') || text.ends_with('\r') {
        text.pop();
    }
    Some(text)
}

/// A yes/no dialog: `--warningcontinuecancel` and friends. `true` is "continue".
///
/// A kdialog that could not be started answers `false` — the same reading as a
/// cancel, and the safe one for a question about deleting something.
pub fn confirm<I, S>(kdialog: &Path, args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(kdialog)
        .args(args)
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// A dialog with nothing to answer: `--msgbox`, `--error`. Failures are ignored
/// — the shell wrote `|| true` after every one of them, because a missing
/// dialog must not turn a message into a failed command.
pub fn message<I, S>(kdialog: &Path, args: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let _ = Command::new(kdialog)
        .args(args)
        .stderr(Stdio::null())
        .status();
}

/// `notify-send -a "VPN-зоны" [-u <urgency>] -t <ms> <title> <body>`.
///
/// The argument order is the shell's, urgency included: `notify-send` takes
/// options before the positional summary, and a flag after it would be shown as
/// part of the text.
pub fn notify(notify_send: &Path, urgency: Option<&str>, timeout: &str, title: &str, body: &str) {
    let mut cmd = Command::new(notify_send);
    cmd.arg("-a").arg(APP);
    if let Some(urgency) = urgency {
        cmd.arg("-u").arg(urgency);
    }
    cmd.arg("-t").arg(timeout).arg(title).arg(body);
    let _ = cmd.status();
}
