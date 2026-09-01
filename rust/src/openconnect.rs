//! The OpenConnect backend: a userspace VPN client in the uplink namespace.
//!
//! Second kind of zone next to kernel WireGuard/AmneziaWG, and the first one
//! whose tunnel is built by a program instead of by the kernel. The contour is
//! the one `docs/LEAK-MODEL.md` describes for userspace clients and `ROADMAP`
//! M4 asks for — the same wall in the same place:
//!
//! ```text
//! host ── pasta ── [uplink-ns]  openconnect: TLS/DTLS to the gateway,
//!                     │         /dev/net/tun, the vpnc-script
//!                     │         the tun is CREATED here and MOVES ↓
//!                  [app-ns]     lo + the tunnel, nothing else, ever
//! ```
//!
//! **Why the client may create a tun at all without root.** `TUNSETIFF` checks
//! `CAP_NET_ADMIN` against the user namespace that owns the network namespace
//! the `/dev/net/tun` descriptor belongs to — not against the host's root. The
//! zone's uplink is a network namespace owned by our own user namespace, and
//! inside it we are uid 0 with every capability, so the check passes. All the
//! device node itself has to be is readable and writable (`crw-rw-rw-`), which
//! is how every distribution ships it. (`docs/GOTCHAS.md` §2)
//!
//! **Why the tun can be moved out from under a running client.** A tun device
//! and the file descriptor attached to it are two different things: the
//! descriptor addresses the *queue*, the device lives in a network namespace.
//! `ip link set <dev> netns <pid>` moves the device; the queue keeps working, so
//! `openconnect` goes on reading and writing packets from the uplink while the
//! interface those packets appear on is in the app namespace. This is the same
//! property WireGuard's UDP socket has, only reached from the other side, and it
//! is what keeps the TLS session — the thing that must never be visible to the
//! programs — on the far side of the wall.
//!
//! **What this module is.** Three pure pieces and one small process:
//!
//! * [`OcConfig`] — the `[OpenConnect]` section of a zone config, parsed and
//!   checked (an argument allowlist, a password file that must not be readable
//!   by anybody else, and no way at all to turn certificate checking off);
//! * [`plan`] — the vpnc-script contract as a pure function: the environment
//!   `openconnect` hands the script becomes an action, and every branch has a
//!   test instead of a shell `case`;
//! * [`Plan`] — the handful of facts the app namespace needs (address, MTU,
//!   resolvers, search domain), written to a file the app namespace reads;
//! * `oc-script` — what `openconnect` actually runs: it moves the interface into
//!   the app namespace and writes that file. It configures NOTHING: every
//!   address, route and resolver of the app namespace is applied by the app
//!   namespace itself (`crate::zone`), exactly as for a WireGuard zone.
//!
//! **Split tunnelling is deliberately not implemented.** `CISCO_SPLIT_INC_*`
//! says which networks the gateway would like to see; a zone sends EVERYTHING
//! into the tunnel and has no second interface to send the rest through, so the
//! list is ignored and the journal says how many entries went. That is not a
//! hole: what the gateway does with traffic it did not ask for is the gateway's
//! business, and the alternative — a route pointing anywhere else — is the one
//! thing this project refuses to have in the app namespace.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::config::WgConfig;

/// The section that turns a zone config into an OpenConnect one.
pub const SECTION: &str = "OpenConnect";

/// Where the app namespace picks the tunnel's facts up. A dotted name, like
/// `.stripped.conf`: nothing that walks the zone directory has any business
/// seeing it.
pub const PLAN_FILE: &str = ".oc-plan";

/// What `--protocol` defaults to: Cisco AnyConnect, which is also what ocserv
/// speaks.
pub const DEFAULT_PROTOCOL: &str = "anyconnect";

/// Everything this build of `openconnect` understands. Checked here so that a
/// typo is a message about the config and not an obscure failure minutes later.
const PROTOCOLS: [&str; 7] = ["anyconnect", "nc", "gp", "pulse", "f5", "fortinet", "array"];

/// MTU when neither the config nor the gateway says one. Same number the
/// upstream `vpnc-script` falls back to.
pub const DEFAULT_MTU: u32 = 1412;

/// Environment the uplink hands `openconnect`, which hands it to the script.
pub const ENV_DIR: &str = "VPN_ZONE_OC_DIR";
pub const ENV_NETNS_PID: &str = "VPN_ZONE_OC_NETNS_PID";
pub const ENV_IP: &str = "VPN_ZONE_OC_IP";
pub const ENV_MTU: &str = "VPN_ZONE_OC_MTU";

/// Extra `openconnect` flags a zone config may add, and whether each one takes
/// a value.
///
/// An ALLOWLIST, and the shape is part of it: a flag with a value has to be
/// written `--flag=value`, never as two words. Both halves matter.
///
/// * The list keeps `--script`, `--csd-wrapper`, `--external-browser` and
///   `--setuid` out — the first would replace the only thing that puts the
///   tunnel behind the wall, the next two run a program of the server's
///   choosing, the last changes who we are. So do `--no-system-trust` and
///   `--allow-insecure-crypto`: there is no way, through this file or any
///   other, to make the client trust a server it should not.
/// * The shape keeps a value from being read as a flag. Were `--useragent x`
///   accepted as two arguments, `Args = --useragent --script` would smuggle the
///   forbidden one in as a value that `openconnect` then reads as a flag of its
///   own the moment the list is reordered. `--flag=value` cannot split.
const ALLOWED_ARGS: [(&str, bool); 17] = [
    ("--base-mtu", true),
    ("--deflate", false),
    ("--dtls-ciphers", true),
    ("--force-dpd", true),
    ("--local-hostname", true),
    ("--no-deflate", false),
    ("--no-dtls", false),
    ("--no-http-keepalive", false),
    ("--no-xmlpost", false),
    ("--os", true),
    ("--passtos", false),
    ("--pfs", false),
    ("--queue-len", true),
    ("--reconnect-timeout", true),
    ("--sni", true),
    ("--useragent", true),
    ("--version-string", true),
];

/// The `[OpenConnect]` section of a zone config, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcConfig {
    /// Host name or literal address of the gateway, without a scheme.
    pub server: String,
    /// Port, when the config wrote one.
    pub port: Option<u16>,
    /// `--protocol`; `anyconnect` unless said otherwise.
    pub protocol: String,
    pub user: Option<String>,
    pub authgroup: Option<String>,
    /// `--servercert`: a fingerprint the server's certificate must match. With
    /// none, the system trust store decides — and there is no third option.
    pub server_cert: Option<String>,
    /// Absolute path of a file holding the password on its first line. Checked
    /// for being nobody else's business; read as late as possible.
    pub password_file: Option<PathBuf>,
    /// `MTU =` in the config, which wins over what the gateway offers.
    pub mtu: Option<u32>,
    /// Extra flags from `Args =`, each one from [`ALLOWED_ARGS`].
    pub extra: Vec<String>,
}

/// Everything a config can be wrong about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// No `[OpenConnect]` section: this is not an OpenConnect zone at all.
    NoSection,
    MissingServer,
    BadServer(String),
    BadPort(String),
    UnknownProtocol(String),
    UnknownKey(String),
    BadMtu(String),
    BadServerCert(String),
    /// A password file has to be named absolutely: the zone holder's working
    /// directory is not the user's.
    RelativePasswordFile(String),
    PasswordFileMissing(String),
    /// Readable by the group or by everyone. A VPN password in a file every
    /// process on the machine can open is not a secret.
    PasswordFileOpen {
        path: String,
        mode: u32,
    },
    PasswordFileNotOurs {
        path: String,
        uid: u32,
    },
    PasswordFileEmpty(String),
    /// A flag that is not on the allowlist, or one written as two words.
    ForbiddenArg(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSection => write!(f, "no [{SECTION}] section"),
            Self::MissingServer => write!(f, "[{SECTION}] has no Server="),
            Self::BadServer(v) => write!(
                f,
                "Server = {v}: expected host or host:port, without a scheme or a path"
            ),
            Self::BadPort(v) => write!(f, "Server = {v}: the port is not a number 1..65535"),
            Self::UnknownProtocol(v) => write!(
                f,
                "Protocol = {v}: openconnect speaks {}",
                PROTOCOLS.join(", ")
            ),
            Self::UnknownKey(k) => write!(f, "[{SECTION}]: unknown key {k}"),
            Self::BadMtu(v) => write!(f, "MTU = {v}: not a number"),
            Self::BadServerCert(v) => write!(
                f,
                "ServerCert = {v}: expected pin-sha256:<base64>, sha256:<hex> or sha1:<hex>"
            ),
            Self::RelativePasswordFile(p) => {
                write!(f, "PasswordFile = {p}: the path has to be absolute")
            }
            Self::PasswordFileMissing(p) => write!(f, "PasswordFile = {p}: no such file"),
            Self::PasswordFileOpen { path, mode } => write!(
                f,
                "PasswordFile = {path} is mode {mode:04o} — it holds a password and has to be \
                 0600 (chmod 600 {path})"
            ),
            Self::PasswordFileNotOurs { path, uid } => {
                write!(f, "PasswordFile = {path} belongs to uid {uid}, not to you")
            }
            Self::PasswordFileEmpty(p) => write!(f, "PasswordFile = {p} is empty"),
            Self::ForbiddenArg(a) => write!(
                f,
                "Args: {a} is not allowed — only these flags are, and a value has to be \
                 written --flag=value: {}",
                allowed_args_text()
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

fn allowed_args_text() -> String {
    ALLOWED_ARGS
        .iter()
        .map(|(name, takes)| {
            if *takes {
                format!("{name}=…")
            } else {
                (*name).to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Does this parsed config file describe an OpenConnect zone?
///
/// The whole of the zone-kind decision, in one place: a file with an
/// `[OpenConnect]` section is one, anything else is WireGuard/AmneziaWG. The
/// two cannot be confused — a WireGuard config has no such section, and a
/// config that has one is refused before a zone is created if it does not parse
/// (`vpn-zone add`).
pub fn is_openconnect(ini: &WgConfig) -> bool {
    ini.section(SECTION).is_some()
}

impl OcConfig {
    /// Read the `[OpenConnect]` section out of an already parsed config file.
    ///
    /// The file goes through the project's own INI reader
    /// ([`crate::config::WgConfig`]) first, so CRLF, comments and free spacing
    /// are already dealt with in one place rather than twice.
    pub fn from_ini(ini: &WgConfig) -> Result<Self, ConfigError> {
        let section = ini.section(SECTION).ok_or(ConfigError::NoSection)?;

        // Unknown keys are refused rather than ignored. A misspelt `ServerCert`
        // that is quietly dropped means a zone that connects without the pin
        // the user believes is there.
        for entry in &section.entries {
            let known = [
                "server",
                "protocol",
                "user",
                "authgroup",
                "servercert",
                "passwordfile",
                "mtu",
                "args",
            ]
            .contains(&entry.key.to_ascii_lowercase().as_str());
            if !known {
                return Err(ConfigError::UnknownKey(entry.key.clone()));
            }
        }

        let raw_server = section.get("Server").ok_or(ConfigError::MissingServer)?;
        let (server, port) = split_server(raw_server)?;

        let protocol = section
            .get("Protocol")
            .unwrap_or(DEFAULT_PROTOCOL)
            .to_string();
        if !PROTOCOLS.contains(&protocol.as_str()) {
            return Err(ConfigError::UnknownProtocol(protocol));
        }

        let server_cert = match section.get("ServerCert") {
            Some(pin) if is_fingerprint(pin) => Some(pin.to_string()),
            Some(pin) => return Err(ConfigError::BadServerCert(pin.to_string())),
            None => None,
        };

        let mtu = match section.get("MTU") {
            Some(v) => Some(
                v.parse::<u32>()
                    .map_err(|_| ConfigError::BadMtu(v.to_string()))?,
            ),
            None => None,
        };

        let password_file = match section.get("PasswordFile") {
            Some(p) if Path::new(p).is_absolute() => Some(PathBuf::from(p)),
            Some(p) => return Err(ConfigError::RelativePasswordFile(p.to_string())),
            None => None,
        };

        let extra = match section.get("Args") {
            Some(args) => check_args(args)?,
            None => Vec::new(),
        };

        Ok(Self {
            server,
            port,
            protocol,
            user: section.get("User").map(str::to_string),
            authgroup: section.get("AuthGroup").map(str::to_string),
            server_cert,
            password_file,
            mtu,
            extra,
        })
    }

    /// Parse a whole config file.
    pub fn parse(input: &[u8]) -> Result<Self, String> {
        let ini = WgConfig::parse(input).map_err(|e| e.to_string())?;
        Self::from_ini(&ini).map_err(|e| e.to_string())
    }

    /// `host` or `host:port`, the way `openconnect` takes it on the command
    /// line.
    pub fn server_arg(&self) -> String {
        match self.port {
            Some(port) => format!("{}:{port}", self.server),
            None => self.server.clone(),
        }
    }

    /// Is the server written as a literal address? Then nothing has to be
    /// resolved and `--resolve` is pointless.
    pub fn server_literal(&self) -> Option<IpAddr> {
        self.server.parse().ok()
    }

    /// Check the password file without reading it.
    ///
    /// Split from reading on purpose: the check belongs to `vpn-zone add` and to
    /// the start of a zone, where a clear message costs nothing; the CONTENT is
    /// read once, in the uplink, right before it is handed to the client — so
    /// the password does not sit in the memory of the process the app namespace
    /// is forked from.
    pub fn check_password_file(&self) -> Result<(), ConfigError> {
        let Some(path) = self.password_file.as_ref() else {
            return Ok(());
        };
        let shown = path.display().to_string();
        let meta =
            fs::metadata(path).map_err(|_| ConfigError::PasswordFileMissing(shown.clone()))?;
        let mode = meta.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(ConfigError::PasswordFileOpen { path: shown, mode });
        }
        // WHO owns it, but only when there is a "we" to compare against. This
        // runs twice: once as the user, from `vpn-zone add`, where a file
        // belonging to somebody else is worth refusing outright — and once
        // inside the zone's user namespace, where we are uid 0 and every uid in
        // the mapping is the user's own. Comparing there would refuse every
        // password file there is (`docs/GOTCHAS.md` §1: the double mapping).
        // SAFETY: getuid(2) takes no arguments and cannot fail.
        let uid = unsafe { libc::getuid() };
        if uid != 0 && meta.uid() != uid {
            return Err(ConfigError::PasswordFileNotOurs {
                path: shown,
                uid: meta.uid(),
            });
        }
        if meta.len() == 0 {
            return Err(ConfigError::PasswordFileEmpty(shown));
        }
        Ok(())
    }

    /// The first line of the password file, without its newline.
    pub fn read_password(&self) -> Result<Option<String>, String> {
        let Some(path) = self.password_file.as_ref() else {
            return Ok(None);
        };
        self.check_password_file().map_err(|e| e.to_string())?;
        let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let first = text.lines().next().unwrap_or_default().to_string();
        if first.is_empty() {
            return Err(ConfigError::PasswordFileEmpty(path.display().to_string()).to_string());
        }
        Ok(Some(first))
    }
}

/// `host` / `host:port` / `[v6]:port`, and nothing that looks like a URL.
///
/// A scheme or a path is refused rather than trimmed: the value goes on a
/// command line as the server, and quietly turning `https://host/x` into `host`
/// would silently ignore half of what the user wrote.
fn split_server(raw: &str) -> Result<(String, Option<u16>), ConfigError> {
    let bad = || ConfigError::BadServer(raw.to_string());
    if raw.is_empty() || raw.contains('/') || raw.contains(char::is_whitespace) || raw.contains('@')
    {
        return Err(bad());
    }
    let (host, port) = if let Some(rest) = raw.strip_prefix('[') {
        // `[2001:db8::1]:443`
        let (inside, after) = rest.split_once(']').ok_or_else(bad)?;
        (inside, after.strip_prefix(':'))
    } else if raw.matches(':').count() > 1 {
        // A bare v6 literal; a port would have needed brackets.
        (raw, None)
    } else {
        match raw.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (raw, None),
        }
    };
    if host.is_empty() {
        return Err(bad());
    }
    let port = match port {
        Some(p) => Some(
            p.parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| ConfigError::BadPort(raw.to_string()))?,
        ),
        None => None,
    };
    Ok((host.to_string(), port))
}

/// `pin-sha256:<base64>`, `sha256:<hex>` or `sha1:<hex>` — the three shapes
/// `openconnect --servercert` prints and accepts.
fn is_fingerprint(pin: &str) -> bool {
    let Some((kind, rest)) = pin.split_once(':') else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    match kind {
        "pin-sha256" => rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='),
        "sha256" | "sha1" => rest.bytes().all(|b| b.is_ascii_hexdigit() || b == b':'),
        _ => false,
    }
}

/// Split `Args =` and let through only what the allowlist names.
fn check_args(args: &str) -> Result<Vec<String>, ConfigError> {
    let mut out = Vec::new();
    for word in args.split_whitespace() {
        let (name, has_value) = match word.split_once('=') {
            Some((name, _)) => (name, true),
            None => (word, false),
        };
        let allowed = ALLOWED_ARGS
            .iter()
            .find(|(flag, _)| *flag == name)
            .map(|(_, takes)| *takes);
        match allowed {
            Some(takes) if takes == has_value => out.push(word.to_string()),
            _ => return Err(ConfigError::ForbiddenArg(word.to_string())),
        }
    }
    Ok(out)
}

// --- THE VPNC-SCRIPT CONTRACT ------------------------------------------------

/// What the app namespace has to do with the interface it is about to receive.
///
/// Deliberately small. Everything `openconnect` says that a hermetic zone has no
/// use for — split routes, the banner, WINS servers, the gateway's own address —
/// is dropped here, where the dropping can be tested, rather than half-applied
/// somewhere further down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Name of the interface, which is the zone's one tunnel name.
    pub iface: String,
    /// The address the gateway assigned, applied as a `/32` on a
    /// point-to-point device — what the upstream `vpnc-script` does too.
    pub address: Ipv4Addr,
    pub mtu: u32,
    /// Resolvers, already checked to be addresses.
    pub dns: Vec<IpAddr>,
    /// `search` line for the zone's resolv.conf, or none.
    pub search: Option<String>,
    /// How many `CISCO_SPLIT_INC_*` entries were deliberately ignored — for the
    /// journal, so that "why does this zone route everything" has an answer.
    pub ignored_splits: usize,
    /// Did the gateway offer IPv6 anyway? Recorded so the journal can say the
    /// zone is not using it (`--disable-ipv6` normally stops it being offered).
    pub ipv6_offered: bool,
}

/// What the script was called for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// `pre-init`: the tun does not exist yet. Nothing to do — the device is
    /// created by `openconnect` itself and needs no help from us.
    Nothing,
    /// `connect`: move the interface down and tell the app namespace about it.
    Connect(Box<Plan>),
    /// `disconnect`: forget the plan. Nothing has to be torn down — the device
    /// is destroyed when `openconnect` closes it, and the app namespace's
    /// default route goes with it. That IS the kill switch.
    Disconnect,
}

/// Why the environment could not be turned into an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptError {
    NoReason,
    UnknownReason(String),
    Missing(&'static str),
    BadAddress(String),
    BadIface(String),
    BadMtu(String),
}

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoReason => write!(
                f,
                "no $reason — this is run by openconnect as its --script, not by hand"
            ),
            Self::UnknownReason(r) => write!(
                f,
                "unknown $reason: {r} — openconnect is newer than this backend"
            ),
            Self::Missing(k) => write!(f, "the gateway said nothing about ${k}"),
            Self::BadAddress(v) => write!(f, "$INTERNAL_IP4_ADDRESS is not an address: {v}"),
            Self::BadIface(v) => write!(f, "$TUNDEV is not an interface name: {v}"),
            Self::BadMtu(v) => write!(f, "$INTERNAL_IP4_MTU is not a number: {v}"),
        }
    }
}

impl std::error::Error for ScriptError {}

/// The vpnc-script contract as a pure function.
///
/// `openconnect` calls its `--script` with `$reason` and a couple of dozen
/// variables (the same set `vpnc` used, which is why the upstream script is
/// called `vpnc-script`). The five reasons and what a hermetic zone does about
/// each:
///
/// | `$reason` | what happens here |
/// |---|---|
/// | `pre-init` | nothing — the client makes its own tun |
/// | `connect` | move the interface into the app namespace, write the plan |
/// | `reconnect` | nothing: the same device, the same address, already there |
/// | `attempt-reconnect` | nothing, and the zone is DEAD meanwhile — by design |
/// | `disconnect` | drop the plan; the vanishing device takes the route with it |
///
/// An `mtu_override` (the zone config's `MTU =`) beats what the gateway offers,
/// because a gateway that gets it wrong is exactly why a user writes one.
pub fn plan(
    env: &BTreeMap<String, String>,
    mtu_override: Option<u32>,
) -> Result<Action, ScriptError> {
    let get = |key: &str| env.get(key).map(String::as_str).filter(|v| !v.is_empty());
    let reason = get("reason").ok_or(ScriptError::NoReason)?;
    match reason {
        "pre-init" | "reconnect" | "attempt-reconnect" => return Ok(Action::Nothing),
        "disconnect" => return Ok(Action::Disconnect),
        "connect" => {}
        other => return Err(ScriptError::UnknownReason(other.to_string())),
    }

    let iface = get("TUNDEV").ok_or(ScriptError::Missing("TUNDEV"))?;
    if !is_iface_name(iface) {
        return Err(ScriptError::BadIface(iface.to_string()));
    }
    let raw_addr =
        get("INTERNAL_IP4_ADDRESS").ok_or(ScriptError::Missing("INTERNAL_IP4_ADDRESS"))?;
    let address: Ipv4Addr = raw_addr
        .parse()
        .map_err(|_| ScriptError::BadAddress(raw_addr.to_string()))?;

    let mtu = match mtu_override {
        Some(mtu) => mtu,
        None => match get("INTERNAL_IP4_MTU") {
            Some(v) => v.parse().map_err(|_| ScriptError::BadMtu(v.to_string()))?,
            None => DEFAULT_MTU,
        },
    };

    // Resolvers have to BE addresses. A name here would be written into the
    // zone's resolv.conf verbatim and never resolve; anything with a newline in
    // it would write a line of its own into that file, and the gateway is not
    // who decides what is in it.
    let dns: Vec<IpAddr> = get("INTERNAL_IP4_DNS")
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect();

    // One search domain, the gateway's default one. `CISCO_SPLIT_DNS` (the
    // split-DNS list) is ignored together with the split routes: this zone has
    // one resolver set and one tunnel, and a per-domain resolver would be a
    // second path by another name.
    let search = get("CISCO_DEF_DOMAIN")
        .map(str::to_string)
        .filter(|d| is_domain(d));

    let ignored_splits = get("CISCO_SPLIT_INC")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0)
        + get("CISCO_IPV6_SPLIT_INC")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);

    Ok(Action::Connect(Box::new(Plan {
        iface: iface.to_string(),
        address,
        mtu,
        dns,
        search,
        ignored_splits,
        ipv6_offered: get("INTERNAL_IP6_ADDRESS").is_some()
            || get("INTERNAL_IP6_NETMASK").is_some(),
    })))
}

/// A name the kernel would accept for an interface, and nothing else: this goes
/// on a command line and into a file the app namespace reads back.
fn is_iface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// A domain that may be written into a resolv.conf `search` line.
fn is_domain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

impl Plan {
    /// The plan as the file the app namespace reads.
    ///
    /// A format of our own, four lines of `key=value`, for the same reason the
    /// tool manifest has one (`docs/GOTCHAS.md` §12): it is ours, it is flat,
    /// and a parser with a name for every field turns a mismatch into a message
    /// instead of a default.
    pub fn to_text(&self) -> String {
        let dns = self
            .dns
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        let search = match &self.search {
            Some(domain) => format!("search={domain}\n"),
            None => String::new(),
        };
        format!(
            "iface={}\naddress={}\nmtu={}\ndns={dns}\n{search}",
            self.iface, self.address, self.mtu
        )
    }

    /// Read a plan back, refusing anything that is not exactly one.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut iface = None;
        let mut address = None;
        let mut mtu = None;
        let mut dns = Vec::new();
        let mut search = None;
        for (idx, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| format!("{PLAN_FILE} line {}: not a key=value line", idx + 1))?;
            match key {
                "iface" if is_iface_name(value) => iface = Some(value.to_string()),
                "address" => {
                    address =
                        Some(value.parse::<Ipv4Addr>().map_err(|_| {
                            format!("{PLAN_FILE}: address={value} is not an address")
                        })?);
                }
                "mtu" => {
                    mtu = Some(
                        value
                            .parse::<u32>()
                            .map_err(|_| format!("{PLAN_FILE}: mtu={value} is not a number"))?,
                    );
                }
                "dns" => {
                    dns = value
                        .split_whitespace()
                        .filter_map(|s| s.parse().ok())
                        .collect();
                }
                "search" if is_domain(value) => search = Some(value.to_string()),
                other => return Err(format!("{PLAN_FILE}: bad value for {other}")),
            }
        }
        Ok(Self {
            iface: iface.ok_or_else(|| format!("{PLAN_FILE}: no iface="))?,
            address: address.ok_or_else(|| format!("{PLAN_FILE}: no address="))?,
            mtu: mtu.ok_or_else(|| format!("{PLAN_FILE}: no mtu="))?,
            dns,
            search,
            ignored_splits: 0,
            ipv6_offered: false,
        })
    }
}

// --- THE SCRIPT ITSELF -------------------------------------------------------

/// Bad usage of `vpn-zone-core oc-script`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgError {
    ExtraArguments,
    MissingEnv(&'static str),
    BadPid(String),
}

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExtraArguments => write!(
                f,
                "takes no arguments: openconnect passes everything in the environment"
            ),
            Self::MissingEnv(k) => write!(
                f,
                "${k} is not set — this is the --script of a zone's openconnect, not a command"
            ),
            Self::BadPid(v) => write!(f, "${ENV_NETNS_PID} is not a pid: {v}"),
        }
    }
}

impl std::error::Error for ArgError {}

/// What the script needs from us rather than from `openconnect`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// The zone's state directory: where the plan file goes.
    pub dir: PathBuf,
    /// Host pid of the app-namespace process — the target of the move. A host
    /// pid because no pid namespace is created anywhere in a zone.
    pub netns_pid: i32,
    pub ip: PathBuf,
    pub mtu: Option<u32>,
}

impl Args {
    /// Everything comes from the environment: `openconnect` runs its `--script`
    /// through `/bin/sh -c` with no arguments of its own.
    pub fn from_env(
        argv: &[std::ffi::OsString],
        env: &BTreeMap<String, String>,
    ) -> Result<Self, ArgError> {
        if !argv.is_empty() {
            return Err(ArgError::ExtraArguments);
        }
        let dir = env
            .get(ENV_DIR)
            .filter(|v| !v.is_empty())
            .ok_or(ArgError::MissingEnv(ENV_DIR))?;
        let pid = env
            .get(ENV_NETNS_PID)
            .filter(|v| !v.is_empty())
            .ok_or(ArgError::MissingEnv(ENV_NETNS_PID))?;
        // Without a path for `ip` we fall back to a PATH lookup, exactly as the
        // zone holder does when it is run by hand out of a nix-shell.
        let ip = match env.get(ENV_IP).filter(|v| !v.is_empty()) {
            Some(path) => PathBuf::from(path),
            None => PathBuf::from("ip"),
        };
        Ok(Self {
            dir: PathBuf::from(dir),
            netns_pid: pid.parse().map_err(|_| ArgError::BadPid(pid.clone()))?,
            ip,
            mtu: env.get(ENV_MTU).and_then(|v| v.parse().ok()),
        })
    }
}

/// The environment of this process, as a map.
pub fn environment() -> BTreeMap<String, String> {
    std::env::vars().collect()
}

/// Run the script. The exit code is what `openconnect` sees, and a non-zero one
/// on `connect` aborts the connection — which is the fail-closed answer to "the
/// interface could not be put behind the wall".
pub fn run(args: &Args, env: &BTreeMap<String, String>) -> u8 {
    let action = match plan(env, args.mtu) {
        Ok(action) => action,
        Err(e) => {
            eprintln!("oc-script: {e}");
            return 1;
        }
    };
    let plan_path = args.dir.join(PLAN_FILE);
    match action {
        Action::Nothing => 0,
        Action::Disconnect => {
            // Nothing to tear down: the device dies with the client's
            // descriptor and takes the app namespace's only route with it. The
            // file goes so that nothing reports a tunnel that is not there.
            let _ = fs::remove_file(&plan_path);
            println!("oc-script: disconnected — the zone has no route out any more");
            0
        }
        Action::Connect(plan) => match connect(args, &plan, &plan_path) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("oc-script: {e}");
                // Leave nothing half-done behind: a plan file without an
                // interface would make the app namespace configure thin air.
                let _ = fs::remove_file(&plan_path);
                1
            }
        },
    }
}

/// Move the interface into the app namespace, then publish the plan.
///
/// The ORDER is the whole of it. The plan file appearing is what tells the
/// uplink that the app namespace may configure the interface; publish it before
/// the move and the app namespace would look for a device that is still one
/// namespace up. The write is a rename over a temporary file for the same
/// reason the status mirror is: a reader sees the whole file or none of it.
fn connect(args: &Args, plan: &Plan, plan_path: &Path) -> Result<(), String> {
    if plan.ignored_splits > 0 {
        println!(
            "oc-script: {} split-include route(s) from the gateway ignored — a zone sends \
             everything into the tunnel and has no second interface to send the rest through",
            plan.ignored_splits
        );
    }
    if plan.ipv6_offered {
        println!(
            "oc-script: the gateway offered IPv6; this backend does not use it yet, and the \
             app namespace closes the family instead of routing it anywhere else"
        );
    }

    let target = args.netns_pid.to_string();
    let status = std::process::Command::new(&args.ip)
        .args(["link", "set", plan.iface.as_str(), "netns", target.as_str()])
        .status()
        .map_err(|e| format!("cannot run {}: {e}", args.ip.display()))?;
    if !status.success() {
        return Err(format!(
            "cannot move {} into the app namespace (pid {target}): ip exited {status}",
            plan.iface
        ));
    }

    let tmp = plan_path.with_extension("tmp");
    fs::write(&tmp, plan.to_text()).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, plan_path)
        .map_err(|e| format!("cannot rename {} into place: {e}", tmp.display()))?;
    println!(
        "oc-script: {} moved into the app namespace, address {}, mtu {}",
        plan.iface, plan.address, plan.mtu
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn config(body: &str) -> Result<OcConfig, ConfigError> {
        let ini = WgConfig::parse_str(body).unwrap();
        OcConfig::from_ini(&ini)
    }

    #[test]
    fn a_minimal_section_is_enough() {
        let cfg = config("[OpenConnect]\nServer = vpn.example.org\n").unwrap();
        assert_eq!(cfg.server, "vpn.example.org");
        assert_eq!(cfg.port, None);
        assert_eq!(cfg.protocol, "anyconnect");
        assert_eq!(cfg.server_arg(), "vpn.example.org");
        assert!(cfg.user.is_none() && cfg.server_cert.is_none() && cfg.extra.is_empty());
    }

    #[test]
    fn a_wireguard_config_is_not_an_openconnect_one() {
        let wg =
            WgConfig::parse_str("[Interface]\nPrivateKey = x\n[Peer]\nPublicKey = y\n").unwrap();
        assert!(!is_openconnect(&wg));
        assert_eq!(OcConfig::from_ini(&wg), Err(ConfigError::NoSection));

        let oc = WgConfig::parse_str("[OpenConnect]\nServer = vpn.example.org\n").unwrap();
        assert!(is_openconnect(&oc));
    }

    #[test]
    fn the_server_is_a_host_and_a_port_and_never_a_url() {
        assert_eq!(
            split_server("vpn.example.org").unwrap(),
            ("vpn.example.org".into(), None)
        );
        assert_eq!(
            split_server("vpn.example.org:4443").unwrap(),
            ("vpn.example.org".into(), Some(4443))
        );
        assert_eq!(
            split_server("198.51.100.7").unwrap(),
            ("198.51.100.7".into(), None)
        );
        // v6 in both shapes: bracketed with a port, bare without one.
        assert_eq!(
            split_server("[2001:db8::1]:443").unwrap(),
            ("2001:db8::1".into(), Some(443))
        );
        assert_eq!(
            split_server("2001:db8::1").unwrap(),
            ("2001:db8::1".into(), None)
        );

        for bad in [
            "https://vpn.example.org",
            "vpn.example.org/path",
            "user@vpn.example.org",
            "vpn.example.org 443",
            "",
        ] {
            assert!(
                matches!(split_server(bad), Err(ConfigError::BadServer(_))),
                "{bad} was accepted"
            );
        }
        assert!(matches!(
            split_server("vpn.example.org:0"),
            Err(ConfigError::BadPort(_))
        ));
        assert!(matches!(
            split_server("vpn.example.org:https"),
            Err(ConfigError::BadPort(_))
        ));
    }

    #[test]
    fn a_typo_in_a_key_is_refused_rather_than_ignored() {
        // The whole point: a misspelt ServerCert that is silently dropped means
        // a zone that connects without the pin the user thinks is there.
        assert_eq!(
            config("[OpenConnect]\nServer = a.b\nServerCer = sha256:ab\n"),
            Err(ConfigError::UnknownKey("ServerCer".to_string()))
        );
        assert!(matches!(
            config("[OpenConnect]\nServer = a.b\nProtocol = openvpn\n"),
            Err(ConfigError::UnknownProtocol(_))
        ));
        assert_eq!(
            config("[OpenConnect]\nUser = bob\n"),
            Err(ConfigError::MissingServer)
        );
        assert!(matches!(
            config("[OpenConnect]\nServer = a.b\nMTU = big\n"),
            Err(ConfigError::BadMtu(_))
        ));
        // Keys are case-insensitive, as everywhere else in the project.
        let cfg = config("[openconnect]\nserver = a.b\nprotocol = gp\nmtu = 1300\n").unwrap();
        assert_eq!(cfg.protocol, "gp");
        assert_eq!(cfg.mtu, Some(1300));
    }

    #[test]
    fn only_a_real_fingerprint_may_pin_the_server() {
        for good in [
            "pin-sha256:HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=",
            "sha256:8a5e:cb:00",
            "sha1:abcdef0123",
        ] {
            let cfg = config(&format!(
                "[OpenConnect]\nServer = a.b\nServerCert = {good}\n"
            ))
            .unwrap();
            assert_eq!(cfg.server_cert.as_deref(), Some(good));
        }
        // Anything that is not a fingerprint is refused: there must be no way to
        // spell "trust whatever answers" in this file.
        for bad in ["yes", "accept", "sha256:", "md5:aabb", "--no-system-trust"] {
            assert!(
                matches!(
                    config(&format!(
                        "[OpenConnect]\nServer = a.b\nServerCert = {bad}\n"
                    )),
                    Err(ConfigError::BadServerCert(_))
                ),
                "{bad} was accepted as a pin"
            );
        }
    }

    #[test]
    fn extra_arguments_are_an_allowlist_and_a_shape() {
        let cfg =
            config("[OpenConnect]\nServer = a.b\nArgs = --no-dtls --os=linux-64 --pfs\n").unwrap();
        assert_eq!(cfg.extra, ["--no-dtls", "--os=linux-64", "--pfs"]);

        // The dangerous ones, one by one. --script would replace the very thing
        // that puts the tunnel behind the wall.
        for bad in [
            "--script=/bin/sh",
            "--script",
            "--csd-wrapper=/tmp/x",
            "--external-browser=/tmp/x",
            "--no-system-trust",
            "--allow-insecure-crypto",
            "--setuid=root",
            "--background",
            "-b",
            "--interface=eth0",
            "--servercert=whatever",
            "--config=/tmp/x",
            "vpn.evil.example",
        ] {
            assert!(
                matches!(
                    config(&format!("[OpenConnect]\nServer = a.b\nArgs = {bad}\n")),
                    Err(ConfigError::ForbiddenArg(_))
                ),
                "{bad} slipped through"
            );
        }
        // The shape matters too: a value-taking flag written as one word only,
        // and a flag without a value never with one.
        assert!(matches!(
            config("[OpenConnect]\nServer = a.b\nArgs = --os linux-64\n"),
            Err(ConfigError::ForbiddenArg(_))
        ));
        assert!(matches!(
            config("[OpenConnect]\nServer = a.b\nArgs = --no-dtls=1\n"),
            Err(ConfigError::ForbiddenArg(_))
        ));
    }

    #[test]
    fn a_password_file_has_to_be_absolute_and_nobody_elses() {
        use std::os::unix::fs::PermissionsExt;

        assert!(matches!(
            config("[OpenConnect]\nServer = a.b\nPasswordFile = secret.txt\n"),
            Err(ConfigError::RelativePasswordFile(_))
        ));

        let dir = std::env::temp_dir().join(format!("vpn-oc-pass-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pass");

        let cfg = config(&format!(
            "[OpenConnect]\nServer = a.b\nPasswordFile = {}\n",
            path.display()
        ))
        .unwrap();
        assert!(matches!(
            cfg.check_password_file(),
            Err(ConfigError::PasswordFileMissing(_))
        ));

        fs::write(&path, "hunter2\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            cfg.check_password_file(),
            Err(ConfigError::PasswordFileOpen { .. })
        ));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        cfg.check_password_file().unwrap();
        assert_eq!(cfg.read_password().unwrap().as_deref(), Some("hunter2"));

        fs::write(&path, "").unwrap();
        assert!(matches!(
            cfg.check_password_file(),
            Err(ConfigError::PasswordFileEmpty(_))
        ));

        // No file at all is not an error: certificate or interactive-less
        // authentication may need none.
        let none = config("[OpenConnect]\nServer = a.b\n").unwrap();
        none.check_password_file().unwrap();
        assert_eq!(none.read_password().unwrap(), None);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn every_reason_maps_to_exactly_one_action() {
        for quiet in ["pre-init", "reconnect", "attempt-reconnect"] {
            assert_eq!(
                plan(&env(&[("reason", quiet)]), None).unwrap(),
                Action::Nothing
            );
        }
        assert_eq!(
            plan(&env(&[("reason", "disconnect")]), None).unwrap(),
            Action::Disconnect
        );
        assert_eq!(plan(&env(&[]), None), Err(ScriptError::NoReason));
        assert_eq!(
            plan(&env(&[("reason", "hello")]), None),
            Err(ScriptError::UnknownReason("hello".to_string()))
        );
    }

    #[test]
    fn connect_takes_the_address_the_mtu_and_the_resolvers_and_nothing_else() {
        let action = plan(
            &env(&[
                ("reason", "connect"),
                ("TUNDEV", "awg0"),
                ("VPNGATEWAY", "198.51.100.7"),
                ("INTERNAL_IP4_ADDRESS", "10.5.0.7"),
                ("INTERNAL_IP4_NETMASK", "255.255.255.0"),
                ("INTERNAL_IP4_MTU", "1300"),
                ("INTERNAL_IP4_DNS", "10.5.0.1 10.5.0.2"),
                ("INTERNAL_IP4_NBNS", "10.5.0.9"),
                ("CISCO_DEF_DOMAIN", "corp.example.org"),
                ("CISCO_BANNER", "Welcome\nto the corp"),
                ("CISCO_SPLIT_INC", "3"),
                ("CISCO_SPLIT_INC_0_ADDR", "10.0.0.0"),
                ("CISCO_IPV6_SPLIT_INC", "1"),
            ]),
            None,
        )
        .unwrap();
        let Action::Connect(plan) = action else {
            panic!("expected a connect plan");
        };
        assert_eq!(plan.iface, "awg0");
        assert_eq!(plan.address, "10.5.0.7".parse::<Ipv4Addr>().unwrap());
        assert_eq!(plan.mtu, 1300);
        assert_eq!(
            plan.dns,
            [
                "10.5.0.1".parse::<IpAddr>().unwrap(),
                "10.5.0.2".parse::<IpAddr>().unwrap()
            ]
        );
        assert_eq!(plan.search.as_deref(), Some("corp.example.org"));
        // Four split entries, all of them dropped, and the count kept so the
        // journal can say so.
        assert_eq!(plan.ignored_splits, 4);
        assert!(!plan.ipv6_offered);
    }

    #[test]
    fn the_config_mtu_beats_the_gateways_and_a_missing_one_has_a_default() {
        let base = [
            ("reason", "connect"),
            ("TUNDEV", "awg0"),
            ("INTERNAL_IP4_ADDRESS", "10.5.0.7"),
        ];
        let with_mtu: Vec<(&str, &str)> = base
            .iter()
            .copied()
            .chain([("INTERNAL_IP4_MTU", "1400")])
            .collect();

        let Action::Connect(p) = plan(&env(&with_mtu), Some(1200)).unwrap() else {
            panic!()
        };
        assert_eq!(p.mtu, 1200);
        let Action::Connect(p) = plan(&env(&with_mtu), None).unwrap() else {
            panic!()
        };
        assert_eq!(p.mtu, 1400);
        let Action::Connect(p) = plan(&env(&base), None).unwrap() else {
            panic!()
        };
        assert_eq!(p.mtu, DEFAULT_MTU);
    }

    #[test]
    fn what_the_gateway_says_cannot_write_a_line_of_its_own() {
        // The gateway is not who decides what is in the zone's resolv.conf. A
        // resolver that is not an address is dropped; a "domain" with anything
        // but domain characters in it never reaches the file.
        let Action::Connect(p) = plan(
            &env(&[
                ("reason", "connect"),
                ("TUNDEV", "awg0"),
                ("INTERNAL_IP4_ADDRESS", "10.5.0.7"),
                ("INTERNAL_IP4_DNS", "10.5.0.1 evil.example.org 10.5.0.2"),
                ("CISCO_DEF_DOMAIN", "corp\nnameserver 203.0.113.9"),
            ]),
            None,
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(p.dns.len(), 2);
        assert_eq!(p.search, None);

        // And a device name that is not one never reaches an `ip` command line.
        for bad in ["", "a b", "-x; rm -rf /", "0123456789abcdef"] {
            let e = plan(
                &env(&[
                    ("reason", "connect"),
                    ("TUNDEV", bad),
                    ("INTERNAL_IP4_ADDRESS", "10.5.0.7"),
                ]),
                None,
            );
            assert!(e.is_err(), "TUNDEV={bad:?} was accepted");
        }
    }

    #[test]
    fn a_missing_address_is_fatal_rather_than_guessed_at() {
        assert_eq!(
            plan(&env(&[("reason", "connect"), ("TUNDEV", "awg0")]), None),
            Err(ScriptError::Missing("INTERNAL_IP4_ADDRESS"))
        );
        assert_eq!(
            plan(&env(&[("reason", "connect")]), None),
            Err(ScriptError::Missing("TUNDEV"))
        );
        assert!(matches!(
            plan(
                &env(&[
                    ("reason", "connect"),
                    ("TUNDEV", "awg0"),
                    ("INTERNAL_IP4_ADDRESS", "not-an-address"),
                ]),
                None
            ),
            Err(ScriptError::BadAddress(_))
        ));
    }

    #[test]
    fn a_plan_survives_the_round_trip_through_its_file() {
        let plan = Plan {
            iface: "awg0".to_string(),
            address: "10.5.0.7".parse().unwrap(),
            mtu: 1300,
            dns: vec!["10.5.0.1".parse().unwrap(), "fd00::1".parse().unwrap()],
            search: Some("corp.example.org".to_string()),
            ignored_splits: 3,
            ipv6_offered: true,
        };
        let text = plan.to_text();
        assert_eq!(
            text,
            "iface=awg0\naddress=10.5.0.7\nmtu=1300\ndns=10.5.0.1 fd00::1\nsearch=corp.example.org\n"
        );
        let back = Plan::parse(&text).unwrap();
        assert_eq!(back.iface, plan.iface);
        assert_eq!(back.address, plan.address);
        assert_eq!(back.mtu, plan.mtu);
        assert_eq!(back.dns, plan.dns);
        assert_eq!(back.search, plan.search);

        // Without a search domain the line is absent, not empty.
        let bare = Plan {
            search: None,
            dns: Vec::new(),
            ..plan
        };
        assert_eq!(
            bare.to_text(),
            "iface=awg0\naddress=10.5.0.7\nmtu=1300\ndns=\n"
        );
        assert_eq!(Plan::parse(&bare.to_text()).unwrap().search, None);

        // And a file that is not a plan is a message, never a default.
        for bad in [
            "",
            "iface=awg0\n",
            "iface=awg0\naddress=10.5.0.7\n",
            "iface=awg0\naddress=nope\nmtu=1\n",
            "iface=awg0\naddress=10.5.0.7\nmtu=x\n",
            "iface=a b\naddress=10.5.0.7\nmtu=1\n",
            "nonsense\n",
        ] {
            assert!(Plan::parse(bad).is_err(), "{bad:?} parsed as a plan");
        }
    }

    #[test]
    fn the_script_takes_its_bearings_from_the_environment_only() {
        let full = env(&[
            (ENV_DIR, "/home/u/.local/state/vpn-zones/work"),
            (ENV_NETNS_PID, "4242"),
            (ENV_IP, "/nix/store/x/bin/ip"),
            (ENV_MTU, "1300"),
        ]);
        let args = Args::from_env(&[], &full).unwrap();
        assert_eq!(args.netns_pid, 4242);
        assert_eq!(args.ip, PathBuf::from("/nix/store/x/bin/ip"));
        assert_eq!(args.mtu, Some(1300));

        // openconnect runs the script through `/bin/sh -c` with no arguments;
        // anything positional means it was called by hand or by something else.
        assert_eq!(
            Args::from_env(&[std::ffi::OsString::from("connect")], &full),
            Err(ArgError::ExtraArguments)
        );
        assert_eq!(
            Args::from_env(&[], &env(&[(ENV_NETNS_PID, "1")])),
            Err(ArgError::MissingEnv(ENV_DIR))
        );
        assert_eq!(
            Args::from_env(&[], &env(&[(ENV_DIR, "/x")])),
            Err(ArgError::MissingEnv(ENV_NETNS_PID))
        );
        assert!(matches!(
            Args::from_env(&[], &env(&[(ENV_DIR, "/x"), (ENV_NETNS_PID, "no")])),
            Err(ArgError::BadPid(_))
        ));
        // Without a path for `ip` the script falls back to PATH, as the zone
        // holder does when it is run by hand out of a nix-shell.
        let minimal = Args::from_env(&[], &env(&[(ENV_DIR, "/x"), (ENV_NETNS_PID, "7")])).unwrap();
        assert_eq!(minimal.ip, PathBuf::from("ip"));
        assert_eq!(minimal.mtu, None);
    }
}
