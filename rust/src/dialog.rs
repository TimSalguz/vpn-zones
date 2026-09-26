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
pub const APP: &str = "cellward";

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

/// An answer that allows, given sooner than this after a question a zone's
/// program brought up, is taken for a key pressed for something else.
/// kdialog's default button is its first — "allow" in every question here
/// (a `QDialogButtonBox`'s first accepting button; a yes/no box has no way to
/// pick another) — and the new dialog takes the focus from whatever the
/// person was typing into: an Enter meant for a chat would say yes. A program
/// can bring the question up at the moment it likes. Counted from the start
/// of kdialog, which takes a few hundred milliseconds to show its window —
/// about a second is left to read the question, and nobody reads it in that.
pub const TOO_FAST: std::time::Duration = std::time::Duration::from_millis(1500);

/// A "yes" to a question put at `asked`: a refusal when it came sooner than
/// [`TOO_FAST`].
pub fn not_too_soon(asked: std::time::Instant) -> Result<(), String> {
    let after = asked.elapsed();
    if after < TOO_FAST {
        return Err(format!(
            "ответ через {} мс — быстрее, чем читают вопрос: принят за случайное нажатие",
            after.as_millis()
        ));
    }
    Ok(())
}

/// A three-way question (`--yesnocancel` with its own labels): `Some(0)` yes,
/// `Some(1)` no, `Some(2)` cancel; `None` when kdialog could not be started or
/// was killed — which the caller reads as the safe answer.
pub fn choose3<I, S>(kdialog: &Path, args: I) -> Option<i32>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(kdialog)
        .args(args)
        .stderr(Stdio::null())
        .status()
        .ok()
        .and_then(|s| s.code())
}

/// A question with a deadline: kdialog's exit code, as [`choose3`] reads it,
/// or `None` when it could not be started, was killed, or had no answer by
/// `timeout` — then it is killed, so that an answer given later cannot count.
/// No `timeout`: it waits for the answer.
/// For a question a program keeps waiting on (the microphone, which holds
/// its request until the person answers): a dialog nobody sees must not keep
/// the request, nor a "yes" after the program stopped waiting mean anything.
pub fn choose_within<I, S>(
    kdialog: &Path,
    args: I,
    timeout: Option<std::time::Duration>,
) -> Option<i32>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut child = Command::new(kdialog)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.code(),
            Ok(None) if timeout.is_none_or(|t| started.elapsed() < t) => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
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

/// `notify-send -a "cellward" [-u <urgency>] -t <ms> <title> <body>`.
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
    // `--`: a title made of a window's own name may start with a dash.
    cmd.arg("-t").arg(timeout).arg("--").arg(title).arg(body);
    let _ = cmd.status();
}

/// A test's stand-in program at `path`, written by a child process.
///
/// Written from this process, the file would be open for writing while
/// another test's thread forks: that child holds the descriptor until its
/// `exec`, and running the stand-in then fails with "Text file busy" — a
/// dialog that "could not be started", at random. A pipe is all this process
/// holds here.
#[cfg(test)]
pub(crate) fn test_program(path: &Path, script: &str) {
    use std::io::Write;
    let mut sh = Command::new("/bin/sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    sh.stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    assert!(sh.wait().unwrap().success(), "{}", path.display());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// A "yes" right after the question is a stray key; one after a moment
    /// to read it stands.
    #[test]
    fn a_yes_too_soon_is_a_stray_key() {
        let why = not_too_soon(Instant::now()).unwrap_err();
        assert!(why.contains("случайное нажатие"), "{why}");
        let long_ago = Instant::now()
            .checked_sub(TOO_FAST + Duration::from_millis(10))
            .unwrap();
        assert_eq!(not_too_soon(long_ago), Ok(()));
    }
}
