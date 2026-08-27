//! WireGuard / AmneziaWG configuration parsing.
//!
//! This is the bash pipeline from `module/default.nix` (`zoneInit`) turned into
//! code with tests. Every quirk handled here comes from a real config that
//! broke a real zone; they are written down in `docs/GOTCHAS.md` §4:
//!
//! * **CRLF.** Amnezia hands out `.conf` files in Windows format. The `\r` ends
//!   up at the end of the value and the zone dies on the first command with a
//!   message where the carriage return is invisible
//!   (`inet prefix is expected rather than "10.8.1.10/32"`).
//! * **Empty `I1`..`I5`.** Recent Amnezia writes the junk-packet parameters and
//!   fills in only some of them, producing lines like `I2 = `. `awg setconf`
//!   rejects the *whole file* on such a line (`Line unrecognized: \`I2='`) and
//!   the zone does not come up at all. Only lines with an *empty* value may be
//!   dropped: filled obfuscation parameters are mandatory, without them the
//!   server never answers.
//! * **wg-quick directives.** `Address`/`DNS`/`MTU`/`Table`/`PreUp`/`PostUp`/
//!   `PreDown`/`PostDown`/`SaveConfig` are instructions for wg-quick, not
//!   protocol keys; `setconf` fails on the first one, so they are stripped from
//!   what goes to `setconf` and applied by hand.
//! * **Endpoints come in three shapes** — `host:port`, `v4:port` and
//!   `[v6]:port`. Splitting on the last colon mangles a v6 literal, and "has a
//!   letter, so it is a hostname" also matches the hex digits of a v6 address.
//!
//! Deliberate differences from the bash version, all of them strictly safer:
//!
//! * key matching is case-insensitive everywhere (the `grep` that strips
//!   wg-quick directives was case-sensitive, so a lowercase `address =` line
//!   used to slip through into `setconf`);
//! * full-line comments are dropped from the `setconf` text (`setconf` accepts
//!   them, but nothing downstream needs them).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// wg-quick directives that `wg setconf` / `awg setconf` do not understand.
const WG_QUICK_KEYS: [&str; 9] = [
    "address",
    "dns",
    "mtu",
    "table",
    "preup",
    "postup",
    "predown",
    "postdown",
    "saveconfig",
];

/// AmneziaWG obfuscation parameters.
///
/// Same set the bash version greps for when it decides whether a config can be
/// carried by the in-tree `wireguard` module. Newer AmneziaWG releases add more
/// (`S3`, `S4`, `J1`..`J3`, `Itime`); they belong here as soon as the zone code
/// starts supporting them.
const OBFUSCATION_KEYS: [&str; 14] = [
    "jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5",
];

/// Which section an entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    Interface,
    Peer,
    /// Anything else — kept verbatim, `setconf` gets to judge it.
    Other,
}

/// Address family of an address or an endpoint literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

/// One `Key = value` line. `value` is never empty: empty ones are dropped at
/// parse time (see [`WgConfig::dropped_empty`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Key as written in the file, so that the text handed to `setconf` stays
    /// byte-for-byte familiar to the user.
    pub key: String,
    pub value: String,
    /// 1-based line number, for diagnostics.
    pub line: usize,
}

/// A `[Section]` with its entries, in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub kind: SectionKind,
    /// Name as written, without the brackets.
    pub name: String,
    pub entries: Vec<Entry>,
}

impl Section {
    /// First value of `key` in this section, case-insensitively.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.key.eq_ignore_ascii_case(key))
            .map(|e| e.value.as_str())
    }
}

/// A dropped `Key = ` line: the reason recent Amnezia configs used to kill
/// zones outright. Kept so callers can report what was thrown away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DroppedKey {
    pub key: String,
    pub line: usize,
}

/// A parsed WireGuard / AmneziaWG config.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WgConfig {
    pub sections: Vec<Section>,
    /// Keys that had an empty value and were dropped.
    pub dropped_empty: Vec<DroppedKey>,
}

/// Everything that can go wrong while parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    NotUtf8,
    UnterminatedSection { line: usize, text: String },
    EntryOutsideSection { line: usize, text: String },
    MissingEquals { line: usize, text: String },
    EmptyKey { line: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUtf8 => write!(f, "config is not valid UTF-8"),
            Self::UnterminatedSection { line, text } => {
                write!(f, "line {line}: section header without `]`: {text}")
            }
            Self::EntryOutsideSection { line, text } => {
                write!(f, "line {line}: key outside of any section: {text}")
            }
            Self::MissingEquals { line, text } => {
                write!(f, "line {line}: not a `Key = value` line: {text}")
            }
            Self::EmptyKey { line } => write!(f, "line {line}: empty key"),
        }
    }
}

impl std::error::Error for ParseError {}

impl WgConfig {
    /// Parse raw file bytes.
    pub fn parse(input: &[u8]) -> Result<Self, ParseError> {
        let text = std::str::from_utf8(input).map_err(|_| ParseError::NotUtf8)?;
        Self::parse_str(text)
    }

    /// Parse config text. CRLF is normalised on the way in: `\r` is whitespace
    /// for `trim`, so it never reaches a value.
    pub fn parse_str(text: &str) -> Result<Self, ParseError> {
        let mut cfg = Self::default();

        for (idx, raw) in text.split('\n').enumerate() {
            let line = idx + 1;
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }

            if let Some(rest) = trimmed.strip_prefix('[') {
                let name = rest
                    .strip_suffix(']')
                    .ok_or_else(|| ParseError::UnterminatedSection {
                        line,
                        text: trimmed.to_string(),
                    })?
                    .trim();
                cfg.sections.push(Section {
                    kind: section_kind(name),
                    name: name.to_string(),
                    entries: Vec::new(),
                });
                continue;
            }

            let (key, value) =
                trimmed
                    .split_once('=')
                    .ok_or_else(|| ParseError::MissingEquals {
                        line,
                        text: trimmed.to_string(),
                    })?;
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() {
                return Err(ParseError::EmptyKey { line });
            }

            // `I2 = ` and friends: dropping them is the whole difference
            // between a zone that comes up and one that does not.
            if value.is_empty() {
                cfg.dropped_empty.push(DroppedKey {
                    key: key.to_string(),
                    line,
                });
                continue;
            }

            let Some(section) = cfg.sections.last_mut() else {
                return Err(ParseError::EntryOutsideSection {
                    line,
                    text: trimmed.to_string(),
                });
            };

            section.entries.push(Entry {
                key: key.to_string(),
                value: value.to_string(),
                line,
            });
        }

        Ok(cfg)
    }

    /// First `[Interface]` section.
    pub fn interface(&self) -> Option<&Section> {
        self.sections
            .iter()
            .find(|s| s.kind == SectionKind::Interface)
    }

    /// All `[Peer]` sections, in file order.
    pub fn peers(&self) -> impl Iterator<Item = &Section> + '_ {
        self.sections.iter().filter(|s| s.kind == SectionKind::Peer)
    }

    /// First value of `key` anywhere in the file, case-insensitively.
    ///
    /// Section-agnostic on purpose: this mirrors the bash `field()` helper
    /// (`grep -iE "^\s*key\s*=" | head -1`), and it keeps working on configs
    /// that put `Endpoint`-ish keys in unexpected places.
    pub fn first_value(&self, key: &str) -> Option<&str> {
        self.sections.iter().find_map(|s| s.get(key))
    }

    /// Is this an AmneziaWG config, i.e. does it carry filled obfuscation
    /// parameters? Such a config cannot be carried by the in-tree `wireguard`
    /// module — the zone has to fail loudly instead of silently degrading.
    pub fn is_obfuscated(&self) -> bool {
        self.sections.iter().any(|s| {
            s.entries
                .iter()
                .any(|e| OBFUSCATION_KEYS.contains(&e.key.to_ascii_lowercase().as_str()))
        })
    }

    /// `Address = 10.8.1.10/32, fd00::2/128` — every entry, both families.
    ///
    /// All of them are applied, not just the first: a v6-only `Address` used to
    /// kill the zone on `ip -4 addr add`, and a v6 address in a mixed list used
    /// to be dropped silently, which is a leak of the "IPv6 goes around the
    /// tunnel" kind.
    pub fn addresses(&self) -> Vec<Address> {
        self.first_value("Address")
            .map(|v| split_list(v).into_iter().map(Address::parse).collect())
            .unwrap_or_default()
    }

    /// Addresses of one family only.
    pub fn addresses_of(&self, family: Family) -> Vec<Address> {
        self.addresses()
            .into_iter()
            .filter(|a| a.family == family)
            .collect()
    }

    /// `DNS = 10.8.1.1, fd00::1`. Entries are returned as written: wg-quick
    /// also allows search domains here, and deciding what is what is the
    /// caller's business.
    pub fn dns(&self) -> Vec<String> {
        self.first_value("DNS")
            .map(|v| split_list(v).into_iter().map(str::to_string).collect())
            .unwrap_or_default()
    }

    /// `MTU = 1420`. `None` when absent or unparsable — the caller supplies the
    /// default (1420, as wg-quick does).
    pub fn mtu(&self) -> Option<u32> {
        self.first_value("MTU")?.parse().ok()
    }

    /// `Endpoint` of the first peer that has one.
    pub fn endpoint(&self) -> Option<Endpoint> {
        Endpoint::parse(self.first_value("Endpoint")?)
    }

    /// The text that goes to `wg setconf` / `awg setconf`: protocol keys only.
    ///
    /// Exactly what the `sed`+`grep -v` pipeline in `zoneInit` produces —
    /// wg-quick directives and empty values removed, everything else kept in
    /// file order, LF line endings.
    pub fn to_setconf(&self) -> String {
        let mut out = String::new();
        for section in &self.sections {
            out.push('[');
            out.push_str(&section.name);
            out.push_str("]\n");
            for entry in &section.entries {
                if is_wg_quick_key(&entry.key) {
                    continue;
                }
                out.push_str(&entry.key);
                out.push_str(" = ");
                out.push_str(&entry.value);
                out.push('\n');
            }
        }
        out
    }
}

/// One entry of an `Address` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// Entry as written, e.g. `10.8.1.10/32`.
    pub raw: String,
    pub family: Family,
    /// Parsed address, `None` if it is not a literal we understand (kept
    /// non-fatal: `ip addr add` gets to produce the error message).
    pub ip: Option<IpAddr>,
    pub prefix_len: Option<u8>,
}

impl Address {
    fn parse(raw: &str) -> Self {
        let (host, prefix) = match raw.split_once('/') {
            Some((h, p)) => (h, p.parse::<u8>().ok()),
            None => (raw, None),
        };
        let ip = host.parse::<IpAddr>().ok();
        // Family from the parsed literal when possible; the colon test is the
        // fallback for garbage we still want to route to the right `ip` call.
        let family = match ip {
            Some(IpAddr::V4(_)) => Family::V4,
            Some(IpAddr::V6(_)) => Family::V6,
            None if host.contains(':') => Family::V6,
            None => Family::V4,
        };
        Self {
            raw: raw.to_string(),
            family,
            ip,
            prefix_len: prefix,
        }
    }
}

/// Host part of an `Endpoint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointHost {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    /// A name that still has to be resolved — and it has to be resolved while
    /// the zone still uses the host resolver, before the tunnel exists.
    Name(String),
}

impl fmt::Display for EndpointHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(a) => write!(f, "{a}"),
            Self::V6(a) => write!(f, "{a}"),
            Self::Name(n) => write!(f, "{n}"),
        }
    }
}

/// `Endpoint = host:port`, in all three shapes it comes in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: EndpointHost,
    pub port: Option<u16>,
    /// Value as written.
    pub raw: String,
}

impl Endpoint {
    /// `host:port`, `v4:port` or `[v6]:port`; a bare literal without a port is
    /// accepted too.
    ///
    /// A v6 literal is recognised by having more than one colon (or brackets),
    /// never by "does it contain letters" — hex digits are letters as well, and
    /// that test used to send v6 endpoints down the hostname path.
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }

        let (host_str, port_str) = if let Some(rest) = raw.strip_prefix('[') {
            // `[fd00::1]:51820`
            let (inside, after) = rest.split_once(']')?;
            (inside, after.strip_prefix(':'))
        } else if raw.matches(':').count() > 1 {
            // Bare v6 literal: a port would have needed brackets.
            (raw, None)
        } else {
            match raw.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (raw, None),
            }
        };

        let host = if let Ok(v4) = host_str.parse::<Ipv4Addr>() {
            EndpointHost::V4(v4)
        } else if let Ok(v6) = host_str.parse::<Ipv6Addr>() {
            EndpointHost::V6(v6)
        } else {
            EndpointHost::Name(host_str.to_string())
        };

        Some(Self {
            host,
            port: port_str.and_then(|p| p.parse().ok()),
            raw: raw.to_string(),
        })
    }

    /// Family of the literal; `None` for a name, which only resolution can
    /// answer.
    pub fn family(&self) -> Option<Family> {
        match self.host {
            EndpointHost::V4(_) => Some(Family::V4),
            EndpointHost::V6(_) => Some(Family::V6),
            EndpointHost::Name(_) => None,
        }
    }
}

fn section_kind(name: &str) -> SectionKind {
    if name.eq_ignore_ascii_case("interface") {
        SectionKind::Interface
    } else if name.eq_ignore_ascii_case("peer") {
        SectionKind::Peer
    } else {
        SectionKind::Other
    }
}

fn is_wg_quick_key(key: &str) -> bool {
    WG_QUICK_KEYS.contains(&key.to_ascii_lowercase().as_str())
}

fn split_list(value: &str) -> Vec<&str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Keys are synthetic strings of the right shape. Never put a real key in a
    // repository that is public.
    const KEY_A: &str = "U1lOVEhFVElDLUtFWS1BLURPLU5PVC1VU0UtMDAwMDAwMDA9";
    const KEY_B: &str = "U1lOVEhFVElDLUtFWS1CLURPLU5PVC1VU0UtMDAwMDAwMDA9";

    /// Does the `setconf` text carry a line with this key? Substring searches
    /// would also hit the base64 of a key value.
    fn has_key(setconf: &str, key: &str) -> bool {
        setconf.lines().any(|l| {
            l.split_once('=')
                .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case(key))
        })
    }

    fn plain() -> String {
        format!(
            "[Interface]\n\
             PrivateKey = {KEY_A}\n\
             Address = 10.8.1.10/32\n\
             DNS = 10.8.1.1\n\
             MTU = 1420\n\
             \n\
             [Peer]\n\
             PublicKey = {KEY_B}\n\
             AllowedIPs = 0.0.0.0/0\n\
             Endpoint = 198.51.100.7:51820\n"
        )
    }

    #[test]
    fn crlf_never_reaches_a_value() {
        let text = plain().replace('\n', "\r\n");
        let cfg = WgConfig::parse(text.as_bytes()).unwrap();
        assert_eq!(cfg.addresses()[0].raw, "10.8.1.10/32");
        assert_eq!(cfg.dns(), ["10.8.1.1"]);
        assert_eq!(cfg.mtu(), Some(1420));
        assert!(!cfg.to_setconf().contains('\r'));
        assert!(cfg.to_setconf().contains(&format!("PrivateKey = {KEY_A}")));
    }

    #[test]
    fn empty_amnezia_parameters_are_dropped_and_filled_ones_are_kept() {
        let text = format!(
            "[Interface]\n\
             PrivateKey = {KEY_A}\n\
             Jc = 4\n\
             Jmin = 40\n\
             Jmax = 70\n\
             S1 = 15\n\
             S2 = 30\n\
             H1 = 1234567\n\
             H2 = 2345678\n\
             H3 = 3456789\n\
             H4 = 4567890\n\
             I1 = <b 0xf1>\n\
             I2 = \n\
             I3 = <b 0xf3>\n\
             I4 =\n\
             I5 = \n\
             [Peer]\n\
             PublicKey = {KEY_B}\n"
        );
        let cfg = WgConfig::parse_str(&text).unwrap();

        let dropped: Vec<&str> = cfg.dropped_empty.iter().map(|d| d.key.as_str()).collect();
        assert_eq!(dropped, ["I2", "I4", "I5"]);

        let setconf = cfg.to_setconf();
        assert!(!has_key(&setconf, "I2"));
        assert!(!has_key(&setconf, "I4"));
        assert!(!has_key(&setconf, "I5"));
        assert!(setconf.contains("I1 = <b 0xf1>"));
        assert!(setconf.contains("I3 = <b 0xf3>"));
        assert!(setconf.contains("Jc = 4"));
    }

    #[test]
    fn obfuscated_configs_are_told_apart_from_plain_ones() {
        assert!(!WgConfig::parse_str(&plain()).unwrap().is_obfuscated());

        let awg = plain().replace("[Peer]", "Jc = 4\nS1 = 15\n\n[Peer]");
        assert!(WgConfig::parse_str(&awg).unwrap().is_obfuscated());

        // A parameter present but empty is not obfuscation: it is the broken
        // line we drop, and a config with only such lines runs on plain
        // WireGuard.
        let empty_only = plain().replace("[Peer]", "I2 = \n\n[Peer]");
        assert!(!WgConfig::parse_str(&empty_only).unwrap().is_obfuscated());
    }

    #[test]
    fn endpoint_shapes() {
        let v6 = Endpoint::parse("[fd00::1]:51820").unwrap();
        assert_eq!(v6.host, EndpointHost::V6("fd00::1".parse().unwrap()));
        assert_eq!(v6.port, Some(51820));
        assert_eq!(v6.family(), Some(Family::V6));
        assert_eq!(v6.host.to_string(), "fd00::1");

        let v4 = Endpoint::parse("198.51.100.7:51820").unwrap();
        assert_eq!(v4.host, EndpointHost::V4("198.51.100.7".parse().unwrap()));
        assert_eq!(v4.port, Some(51820));
        assert_eq!(v4.family(), Some(Family::V4));

        // Hex digits are letters too: this one must not become a hostname.
        let bare_v6 = Endpoint::parse("fd00:dead:beef::1").unwrap();
        assert_eq!(bare_v6.family(), Some(Family::V6));
        assert_eq!(bare_v6.port, None);

        let name = Endpoint::parse("vpn.example.org:51820").unwrap();
        assert_eq!(name.host, EndpointHost::Name("vpn.example.org".to_string()));
        assert_eq!(name.port, Some(51820));
        assert_eq!(name.family(), None);

        assert_eq!(Endpoint::parse(""), None);
    }

    #[test]
    fn address_families() {
        let v6_only = plain().replace("Address = 10.8.1.10/32", "Address = fd00::2/128");
        let cfg = WgConfig::parse_str(&v6_only).unwrap();
        assert!(cfg.addresses_of(Family::V4).is_empty());
        let v6 = cfg.addresses_of(Family::V6);
        assert_eq!(v6.len(), 1);
        assert_eq!(v6[0].prefix_len, Some(128));
        assert_eq!(v6[0].ip, Some("fd00::2".parse::<IpAddr>().unwrap()));

        let mixed = plain().replace(
            "Address = 10.8.1.10/32",
            "Address = 10.8.1.10/32, fd00::2/128 ,10.8.2.10/32",
        );
        let cfg = WgConfig::parse_str(&mixed).unwrap();
        assert_eq!(cfg.addresses().len(), 3);
        assert_eq!(cfg.addresses_of(Family::V4).len(), 2);
        assert_eq!(cfg.addresses_of(Family::V6).len(), 1);
        assert_eq!(cfg.addresses_of(Family::V6)[0].raw, "fd00::2/128");
    }

    #[test]
    fn missing_dns_and_endpoint_are_not_errors() {
        let text = format!("[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.8.1.10/32\n");
        let cfg = WgConfig::parse_str(&text).unwrap();
        assert!(cfg.dns().is_empty());
        assert_eq!(cfg.endpoint(), None);
        assert_eq!(cfg.mtu(), None);
    }

    #[test]
    fn keys_are_case_insensitive_and_spacing_is_free() {
        let text = format!(
            "[interface]\n\
             privatekey={KEY_A}\n\
             \taddress   =   10.8.1.10/32   \n\
             Dns\t=\t10.8.1.1\n\
             mtu = 1280\n\
             [PEER]\n\
             endpoint = 198.51.100.7:51820\n"
        );
        let cfg = WgConfig::parse_str(&text).unwrap();
        assert_eq!(cfg.addresses()[0].raw, "10.8.1.10/32");
        assert_eq!(cfg.dns(), ["10.8.1.1"]);
        assert_eq!(cfg.mtu(), Some(1280));
        assert_eq!(cfg.endpoint().unwrap().port, Some(51820));
        assert_eq!(cfg.interface().unwrap().get("PrivateKey"), Some(KEY_A));
        assert_eq!(cfg.peers().count(), 1);

        // The wg-quick directives are stripped whatever their case — the bash
        // `grep` was case-sensitive here and let lowercase ones through.
        let setconf = cfg.to_setconf();
        assert!(!has_key(&setconf, "address"));
        assert!(!has_key(&setconf, "dns"));
        assert!(!has_key(&setconf, "mtu"));
        assert!(setconf.contains("endpoint = 198.51.100.7:51820"));
    }

    #[test]
    fn setconf_keeps_protocol_keys_only() {
        let text = format!(
            "# a comment\n\
             [Interface]\n\
             PrivateKey = {KEY_A}\n\
             Address = 10.8.1.10/32\n\
             DNS = 10.8.1.1\n\
             MTU = 1420\n\
             Table = off\n\
             PreUp = /bin/true\n\
             PostUp = /bin/true\n\
             PreDown = /bin/true\n\
             PostDown = /bin/true\n\
             SaveConfig = true\n\
             ListenPort = 51820\n\
             [Peer]\n\
             PublicKey = {KEY_B}\n\
             PresharedKey = {KEY_A}\n\
             AllowedIPs = 0.0.0.0/0, ::/0\n\
             PersistentKeepalive = 25\n\
             Endpoint = 198.51.100.7:51820\n"
        );
        let cfg = WgConfig::parse_str(&text).unwrap();
        assert_eq!(
            cfg.to_setconf(),
            format!(
                "[Interface]\n\
                 PrivateKey = {KEY_A}\n\
                 ListenPort = 51820\n\
                 [Peer]\n\
                 PublicKey = {KEY_B}\n\
                 PresharedKey = {KEY_A}\n\
                 AllowedIPs = 0.0.0.0/0, ::/0\n\
                 PersistentKeepalive = 25\n\
                 Endpoint = 198.51.100.7:51820\n"
            )
        );
    }

    #[test]
    fn broken_files_are_reported_not_swallowed() {
        assert_eq!(
            WgConfig::parse_str("[Interface\nPrivateKey = x\n"),
            Err(ParseError::UnterminatedSection {
                line: 1,
                text: "[Interface".to_string(),
            })
        );
        assert_eq!(
            WgConfig::parse_str("PrivateKey = x\n"),
            Err(ParseError::EntryOutsideSection {
                line: 1,
                text: "PrivateKey = x".to_string(),
            })
        );
        assert_eq!(
            WgConfig::parse_str("[Interface]\nPrivateKey\n"),
            Err(ParseError::MissingEquals {
                line: 2,
                text: "PrivateKey".to_string(),
            })
        );
        assert_eq!(
            WgConfig::parse_str("[Interface]\n = value\n"),
            Err(ParseError::EmptyKey { line: 2 })
        );
        assert_eq!(
            WgConfig::parse(b"[Interface]\n\xff\n"),
            Err(ParseError::NotUtf8)
        );
    }
}
