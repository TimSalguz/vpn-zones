//! `vpn-zone-core x11-run`: an X server of the launch's own, for a program in a
//! zone whose container has the `x11` permission (`docs/HERMETICITY.md` §7, A).
//!
//! The host's X server is out of reach in a zone: `/tmp/.X11-unix` is a tmpfs
//! there and `DISPLAY` is dropped from the launch, because one X server shows
//! every client the windows, the keyboard and the clipboard of all the others.
//! A container that needs X gets an `xwayland-satellite` instead — on the
//! Wayland socket the launch already has, which `wl-sandbox` has restricted —
//! and only its own programs are its clients.
//!
//! Unlike the sandbox's launcher (`fs-sandbox-x11`), nothing here dies with a
//! pid namespace, so this one supervises: it starts the satellite (which is
//! told to die with it), starts the program, waits for it, and takes the
//! satellite down.

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::profile::EXIT_NOT_STARTED;

/// The marker of a zone whose programs get an X server of their own, in the
/// zone's directory.
pub const ZONE_FLAG: &str = "x11";
/// The zones declared to have one, one name per line, below the config dir.
pub const DECLARED_ZONES: &str = "declared/zone-x11";

/// Where the per-zone setting comes from, if the zone has one:
/// `(on, source)`. Declared in Nix wins over the local marker.
pub fn zone_setting(state: &Path, config: &Path, zone: &str) -> (bool, crate::container::Source) {
    use crate::container::Source;
    if let Ok(text) = std::fs::read_to_string(config.join(DECLARED_ZONES)) {
        if text.lines().map(str::trim).any(|l| l == zone) {
            return (true, Source::Nix);
        }
    }
    if state.join(zone).join(ZONE_FLAG).exists() {
        (true, Source::Local)
    } else {
        (false, Source::Default)
    }
}

/// Where X servers put their sockets.
pub const X11_DIR: &str = "/tmp/.X11-unix";
/// The displays a satellite may take: `:100`…`:499`, like the sandbox's.
const FIRST: u32 = 100;
const LAST: u32 = 499;

/// What `x11-run` was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub xwayland: PathBuf,
    pub cmd: Vec<OsString>,
}

impl Args {
    /// Parse `[--xwayland P] -- cmd...`.
    pub fn parse(argv: &[OsString]) -> Result<Self, String> {
        let split = argv
            .iter()
            .position(|a| a == "--")
            .ok_or("need -- before the command")?;
        let cmd = argv[split + 1..].to_vec();
        if cmd.is_empty() {
            return Err("nothing to run".to_owned());
        }
        let mut xwayland = PathBuf::from("xwayland-satellite");
        let mut rest = argv[..split].iter();
        while let Some(arg) = rest.next() {
            match arg.as_bytes() {
                b"--xwayland" => {
                    xwayland = rest
                        .next()
                        .map(PathBuf::from)
                        .ok_or("--xwayland needs a path")?;
                }
                _ => return Err(format!("unknown argument: {}", arg.to_string_lossy())),
            }
        }
        Ok(Self { xwayland, cmd })
    }
}

/// The first display number with neither a socket nor a lock file.
pub fn free_display(dir: &Path, lock_dir: &Path) -> Option<u32> {
    (FIRST..=LAST).find(|n| {
        std::fs::symlink_metadata(dir.join(format!("X{n}"))).is_err()
            && std::fs::symlink_metadata(lock_dir.join(format!(".X{n}-lock"))).is_err()
    })
}

/// Start the satellite, run the program on it, take the satellite down.
pub fn run(args: Args) -> u8 {
    let dir = Path::new(X11_DIR);
    let Some(number) = free_display(dir, Path::new("/tmp")) else {
        eprintln!("x11-run: no free X display — the program starts without X");
        return exec(&args.cmd);
    };
    let display = format!(":{number}");
    let mut satellite = Command::new(&args.xwayland);
    satellite
        .arg(&display)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: prctl in the child before exec, async-signal-safe and pointer-free:
    // the satellite dies with this process, whatever kills it.
    unsafe {
        satellite.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            Ok(())
        });
    }
    let mut satellite = match satellite.spawn() {
        Ok(child) => child,
        Err(e) => {
            eprintln!(
                "x11-run: cannot start {} ({e}) — the program starts without X",
                args.xwayland.display()
            );
            return exec(&args.cmd);
        }
    };
    // Waited for as long as it takes, or until the satellite ends without
    // it: no clock — on a loaded machine the server comes up late, and a
    // deadline would start the program without X exactly there.
    let socket = dir.join(format!("X{number}"));
    let up = crate::sys::wait_for_child_entry(&socket, &mut satellite, |p| {
        std::fs::symlink_metadata(p).is_ok()
    });
    if !up {
        eprintln!("x11-run: the X server ended before its socket was there — the program starts without it");
        let _ = satellite.kill();
        let _ = satellite.wait();
        return exec(&args.cmd);
    }

    let status = Command::new(&args.cmd[0])
        .args(&args.cmd[1..])
        .env("DISPLAY", &display)
        .env_remove("XAUTHORITY")
        .status();
    let _ = satellite.kill();
    let _ = satellite.wait();
    match status {
        Ok(status) => {
            use std::os::unix::process::ExitStatusExt;
            crate::profile::exit_code_of(status.into_raw())
        }
        Err(e) => {
            eprintln!(
                "x11-run: cannot start {}: {e}",
                args.cmd[0].to_string_lossy()
            );
            EXIT_NOT_STARTED
        }
    }
}

fn exec(cmd: &[OsString]) -> u8 {
    let e = crate::profile::exec_command(cmd);
    eprintln!("x11-run: cannot start {}: {e}", cmd[0].to_string_lossy());
    EXIT_NOT_STARTED
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn the_command_follows_the_separator() {
        let a = Args::parse(&argv(&["--xwayland", "/s/xw", "--", "steam", "-silent"])).unwrap();
        assert_eq!(a.xwayland, PathBuf::from("/s/xw"));
        assert_eq!(a.cmd, argv(&["steam", "-silent"]));
        assert!(Args::parse(&argv(&["steam"])).is_err());
        assert!(Args::parse(&argv(&["--"])).is_err());
        assert!(Args::parse(&argv(&["--weird", "--", "x"])).is_err());
    }

    #[test]
    fn a_display_with_a_socket_or_a_lock_is_taken() {
        let base = std::env::temp_dir().join(format!("vpn-zone-x11-{}", std::process::id()));
        let sockets = base.join("sockets");
        std::fs::create_dir_all(&sockets).unwrap();
        assert_eq!(free_display(&sockets, &base), Some(100));
        std::fs::write(sockets.join("X100"), "").unwrap();
        std::fs::write(base.join(".X101-lock"), "").unwrap();
        assert_eq!(free_display(&sockets, &base), Some(102));
        let _ = std::fs::remove_dir_all(&base);
    }
}
