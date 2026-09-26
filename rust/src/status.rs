//! Machine-readable state (`docs/CONTAINERS.md` §9).
//!
//! `vpn-zone status --json`, `vpn-zone container list --json` and
//! `vpn-zone container show <name> --json` print parts of one schema, for
//! configuration tools that set this project up through its module options and
//! must never parse its files.
//!
//! Two promises, both part of the contract:
//!
//! * **`schema_version`** is in every document. Within a version changes are
//!   additive only; removing a field or changing its meaning is a new version
//!   and a CHANGELOG entry;
//! * **every settable value says where it comes from**: `{"value": …, "source":
//!   "nix" | "local" | "default"}`. A tool that offers to change a value
//!   declared in Nix would be fighting the module; this tells it not to.
//!   Runtime facts (`up`, `running`, `tunnel_alive`) are plain values.
//!
//! Written by hand, like the manifest is read by hand: the schema is ours and
//! small, and `serde` would be a code generator in the build for it.

use std::fs;

use crate::cli::{liveness_line, read_setting, strip_cr, visible_entries, zone_pid};
use crate::config::WgConfig;
use crate::container::{self, Container, Home, Source};
use crate::fs_sandbox::Perms;
use crate::launch::NO_ESCAPE;
use crate::tools::Tools;

pub const SCHEMA_VERSION: u32 = 1;

/// A JSON string literal.
pub fn string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // DEL and C1 too: valid JSON either way, but `--json` is read in
            // terminals as well, and U+009B is an escape sequence's start
            // in some of them (a name from a zone may carry one).
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn array(items: Vec<String>) -> String {
    format!("[{}]", items.join(","))
}

fn sourced(value: String, source: Source) -> String {
    format!(
        "{{\"value\":{value},\"source\":{}}}",
        string(source.as_str())
    )
}

fn sourced_str(value: &str, source: Source) -> String {
    sourced(string(value), source)
}

/// A one-line setting file of `~/.config/vpn-zones`, or its default.
fn setting(tools: &Tools, name: &str, default: &str) -> (String, Source) {
    match crate::cli::setting(tools, name) {
        Some((value, source)) if !value.is_empty() => (value, source),
        _ => (default.to_owned(), Source::Default),
    }
}

pub fn defaults(tools: &Tools) -> String {
    let (network, network_source) = setting(tools, "default", "offline");
    let network = crate::launch::network_name(&network).to_owned();
    let (container, container_source) = setting(tools, "default-profile", "ask");
    // A container by the name `containers[].selector` has — `sb:work` from
    // before one name per container is `work` (or `work-sb`) there.
    let container = match container.as_str() {
        "ask" | "main" | "own" => container,
        other => crate::container::canonical(tools, other).unwrap_or(container),
    };
    let (mode, mode_source) = setting(tools, "mode", "picker");
    let (wayland, wayland_source) = setting(tools, "wayland-sandbox", "on");
    // As `launch::proxy_wanted` decides it: only `off` switches it off.
    let (proxy, proxy_source) = setting(tools, "wayland-proxy", "on");
    let (autostart, autostart_source) = setting(tools, "autostart", "ask");
    let (user_entries, user_entries_source) = setting(tools, "user-entries", "take-over");
    let (hermetic, hermetic_source) = crate::hermetic::default_setting(&tools.config);
    // The zones' borders: whether the switch shows them (local only — it is
    // flipped for a call and back, `crate::frame`), and their width.
    let (_, frames_source) = setting(tools, crate::frame::SWITCH_SETTING, "shown");
    let frames = !crate::frame::hidden(&tools.config);
    let (frame_width, frame_width_source) = crate::frame::width(&tools.config);
    // And their title strip: always, hover or off (`crate::frame::title_mode`).
    let (frame_title, frame_title_source) = crate::frame::title_mode(&tools.config);
    // How long a refused permission is not asked about again.
    let (ask_again, ask_again_source) = crate::grants::ask_again(&tools.config);
    // The waits that end by a clock on purpose (`crate::timings`).
    let (question, question_source) = crate::timings::QUESTION.read(&tools.config);
    let (handshake, handshake_source) = crate::timings::HANDSHAKE_CHECK.read(&tools.config);
    format!(
        "{{\"network\":{},\"container\":{},\"launcher_mode\":{},\"compositor_restriction\":{},\
         \"wayland_proxy\":{},\"frames\":{},\"frame_width\":{},\"frame_title\":{},\
         \"autostart_unassigned\":{},\"user_entries\":{},\"hermetic\":{},\"ask_again\":{},\
         \"question_timeout\":{},\"handshake_check\":{}}}",
        sourced_str(&network, network_source),
        sourced_str(&container, container_source),
        sourced_str(&mode, mode_source),
        sourced((wayland == "on").to_string(), wayland_source),
        sourced((proxy.trim() != "off").to_string(), proxy_source),
        sourced(frames.to_string(), frames_source),
        sourced(frame_width.to_string(), frame_width_source),
        sourced_str(frame_title.as_str(), frame_title_source),
        sourced_str(&autostart, autostart_source),
        sourced_str(&user_entries, user_entries_source),
        sourced(hermetic.to_string(), hermetic_source),
        sourced_str(&crate::grants::term_text(ask_again), ask_again_source),
        sourced_str(&question.text(), question_source),
        sourced_str(&handshake.text(), handshake_source)
    )
}

/// The host interface a `host-interface` zone goes out through.
fn host_interface(dir: &std::path::Path) -> Option<String> {
    let raw = fs::read(dir.join("config.conf")).ok()?;
    let ini = WgConfig::parse(&strip_cr(&raw)).ok()?;
    crate::hostif::HostIfConfig::from_ini(&ini)
        .ok()
        .map(|h| h.interface)
}

/// The system zone a `system-zone` zone goes out through (`docs/SYSTEM.md` §7b).
fn system_zone_of(dir: &std::path::Path) -> Option<String> {
    let raw = fs::read(dir.join("config.conf")).ok()?;
    let ini = WgConfig::parse(&strip_cr(&raw)).ok()?;
    crate::sysuplink::SysUplinkConfig::from_ini(&ini)
        .ok()
        .map(|s| s.zone)
}

/// The kind of a zone directory, or `None` when it is not a zone.
fn zone_kind(dir: &std::path::Path) -> Option<&'static str> {
    if dir.join("offline").exists() {
        return Some("offline");
    }
    let raw = fs::read(dir.join("config.conf")).ok()?;
    let ini = WgConfig::parse(&strip_cr(&raw)).ok();
    Some(match ini {
        Some(ini) if crate::openconnect::is_openconnect(&ini) => "openconnect",
        // Not encrypted by the zone: a configuration tool has to be able to
        // say so without reading the file.
        Some(ini) if crate::hostif::is_host_interface(&ini) => "host-interface",
        // No tunnel of its own: the named system zone's.
        Some(ini) if crate::sysuplink::is_system_zone(&ini) => "system-zone",
        _ => "wireguard",
    })
}

pub fn networks(tools: &Tools) -> String {
    let mut items = vec![
        // `aliases`: the names it is also read by — `direct`, its name until
        // 2026-09, may still be in a configuration or in Nix.
        "{\"name\":\"unconfined\",\"kind\":\"unconfined\",\"aliases\":[\"direct\"],\"source\":\"default\",\"up\":true,\
         \"locked\":false,\"tunnel_alive\":null,\"handshake_age_s\":null,\"rx_bytes\":null,\
             \"tx_bytes\":null,\"interface\":null,\"x11\":null,\"hermetic\":null,\"nix_daemon\":null,\"host_files_writable\":null,\"camera\":null,\"microphone\":null,\"screencast\":null,\"audio_manager\":null,\"system_zone\":null,\"frame_color\":null,\"build\":null,\"restart_needed\":null}"
            .to_owned(),
    ];
    let mut offline_listed = false;
    let installed = crate::build::installed(tools);
    for dir in visible_entries(&tools.state) {
        if !dir.is_dir() {
            continue;
        }
        let Some(kind) = zone_kind(&dir) else {
            continue;
        };
        let name = dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        // A zone left with a name that now means the host's network: it would
        // be a second `unconfined` here, and a launch refuses it anyway.
        // (`vpn-zone doctor` names it.)
        if crate::launch::is_unconfined_name(&name) {
            continue;
        }
        offline_listed |= name == "offline";
        let up = zone_pid(&tools.state, dir.file_name().unwrap_or_default()).is_some();
        // A running zone's build: an update leaves it running, on the build it
        // was started from (`crate::build`).
        let build = if up {
            crate::build::string(crate::build::age(&dir, &installed))
        } else {
            "null".to_owned()
        };
        // What it came up with and is set otherwise now — in force from its
        // next start (`hermetic::APPLIED`); `null` down, or not known.
        let restart_needed = if up {
            crate::hermetic::restart_needed(&dir, &tools.config, &name).map_or(
                "null".to_owned(),
                |names| {
                    let names: Vec<String> = names.into_iter().map(string).collect();
                    format!("[{}]", names.join(","))
                },
            )
        } else {
            "null".to_owned()
        };
        let mirror = if up && kind != "offline" {
            fs::read_to_string(dir.join("status")).ok()
        } else {
            None
        };
        let alive = mirror.as_deref().map_or("null".to_owned(), |m| {
            crate::cli::alive_line(&dir, m).is_some().to_string()
        });
        // Counters for status bars, from the same mirror; `null` when there is
        // nothing to read (down, offline, or a zone from an older version).
        let reading = mirror.as_deref().map(crate::watch::parse_mirror);
        let counters = match &reading {
            Some(r) => format!(
                "\"handshake_age_s\":{},\"rx_bytes\":{},\"tx_bytes\":{}",
                r.handshake_age_s
                    .map_or("null".to_owned(), |a| a.to_string()),
                r.rx_bytes,
                r.tx_bytes
            ),
            None => "\"handshake_age_s\":null,\"rx_bytes\":null,\"tx_bytes\":null".to_owned(),
        };
        // Named for the one kind that has one: "через enp4s0 — без шифрования"
        // has to be sayable without reading the config.
        let interface = if kind == "host-interface" {
            host_interface(&dir).map_or("null".to_owned(), |i| string(&i))
        } else {
            "null".to_owned()
        };
        let system_zone = if kind == "system-zone" {
            system_zone_of(&dir).map_or("null".to_owned(), |z| string(&z))
        } else {
            "null".to_owned()
        };
        let x11 = {
            let (on, source) = crate::x11::zone_setting(&tools.state, &tools.config, &name);
            sourced(on.to_string(), source)
        };
        let hermetic = {
            let (on, source) = crate::hermetic::zone_setting(&dir, &tools.config, &name);
            sourced(on.to_string(), source)
        };
        // What the zone is let besides (`vpn-zone nix-daemon`, `host-files`):
        // in force when it next comes up, and from where.
        let nix_daemon = {
            let (on, source) = crate::hermetic::nix_daemon(&dir, &tools.config, &name);
            sourced(on.to_string(), source)
        };
        let host_files_writable = {
            let (on, source) = crate::hermetic::host_files_writable(&dir, &tools.config, &name);
            sourced(on.to_string(), source)
        };
        let camera = {
            let (on, source) = crate::hermetic::camera(&dir, &tools.config, &name);
            sourced(on.to_string(), source)
        };
        // Whether its programs record the microphone: in force at once (the
        // sound filter reads it for every record stream).
        let microphone = {
            let (setting, source) = crate::microphone::setting(&dir, &tools.config, &name);
            sourced_str(setting.as_str(), source)
        };
        // Whether its programs cast the screen, and may have the choice
        // remembered: in force at once (the zone's bus filter reads it for
        // every call of the screen cast portal).
        let screencast = {
            let (setting, source) = crate::screencast::setting(&dir, &tools.config, &name);
            sourced_str(setting.as_str(), source)
        };
        // Whether a hermetic zone gets the host's raw PipeWire socket instead
        // of the restricted one (`crate::pw_context`); from its next start.
        let audio_manager = {
            let (on, source) = crate::hermetic::audio_manager(&dir, &tools.config, &name);
            sourced(on.to_string(), source)
        };
        // The colour of the border around its programs' windows.
        let frame_color = {
            let (color, source) = crate::frame::zone_color(&tools.state, &tools.config, &name);
            sourced_str(&color.hex(), source)
        };
        let source = if kind == "offline" {
            "default"
        } else {
            "local"
        };
        items.push(format!(
            "{{\"name\":{},\"kind\":\"{kind}\",\"aliases\":[],\"source\":\"{source}\",\"up\":{up},\"locked\":{},\"tunnel_alive\":{alive},{counters},\"interface\":{interface},\"x11\":{x11},\"hermetic\":{hermetic},\"nix_daemon\":{nix_daemon},\"host_files_writable\":{host_files_writable},\"camera\":{camera},\"microphone\":{microphone},\"screencast\":{screencast},\"audio_manager\":{audio_manager},\"system_zone\":{system_zone},\"frame_color\":{frame_color},\"build\":{build},\"restart_needed\":{restart_needed}}}",
            string(&name),
            dir.join(NO_ESCAPE).exists()
        ));
    }
    if !offline_listed {
        let (color, source) = crate::frame::zone_color(&tools.state, &tools.config, "offline");
        // Its directory is made when it first comes up; the setting may be
        // declared before that.
        let (mic, mic_source) =
            crate::microphone::setting(&tools.state.join("offline"), &tools.config, "offline");
        let (cast, cast_source) =
            crate::screencast::setting(&tools.state.join("offline"), &tools.config, "offline");
        items.push(format!(
            "{{\"name\":\"offline\",\"kind\":\"offline\",\"aliases\":[],\"source\":\"default\",\"up\":false,\
             \"locked\":false,\"tunnel_alive\":null,\"handshake_age_s\":null,\"rx_bytes\":null,\
             \"tx_bytes\":null,\"interface\":null,\"x11\":null,\"hermetic\":null,\"nix_daemon\":null,\"host_files_writable\":null,\"camera\":null,\
             \"microphone\":{},\"screencast\":{},\"audio_manager\":null,\"system_zone\":null,\"frame_color\":{},\"build\":null,\"restart_needed\":null}}",
            sourced_str(mic.as_str(), mic_source),
            sourced_str(cast.as_str(), cast_source),
            sourced_str(&color.hex(), source)
        ));
    }
    array(items)
}

/// One system zone (`docs/SYSTEM.md` §8): the same counters as a network,
/// `null` where the reader may not look — the run directory is the group
/// `vpn-zones`'s.
pub fn system_network(
    name: &str,
    kind: &str,
    source: &str,
    state: &crate::system::RunState,
    uplink: Option<&str>,
) -> String {
    use crate::system::RunState;
    let (readable, up, mirror) = match state {
        RunState::Closed => (false, "null", None),
        RunState::Down => (true, "false", None),
        RunState::Up(mirror) => (true, "true", mirror.as_deref()),
    };
    let alive = mirror.map_or("null".to_owned(), |m| {
        liveness_line(m).is_some().to_string()
    });
    let counters = match mirror.map(crate::watch::parse_mirror) {
        Some(r) => format!(
            "\"handshake_age_s\":{},\"rx_bytes\":{},\"tx_bytes\":{}",
            r.handshake_age_s
                .map_or("null".to_owned(), |a| a.to_string()),
            r.rx_bytes,
            r.tx_bytes
        ),
        None => "\"handshake_age_s\":null,\"rx_bytes\":null,\"tx_bytes\":null".to_owned(),
    };
    format!(
        "{{\"name\":{},\"netns\":{},\"kind\":{},\"source\":{},\"up\":{up},\"tunnel_alive\":{alive},{counters},\"readable\":{readable},\"uplink\":{}}}",
        string(name),
        string(&crate::system::netns_path(name).to_string_lossy()),
        string(kind),
        string(source),
        uplink.map_or("null".to_owned(), string)
    )
}

/// The declared system zones — a separate array and not entries of
/// `networks`: a tool that did not know the difference would offer a system
/// zone to a program container, which cannot use one.
pub fn system_networks() -> String {
    array(
        crate::system::all_zones()
            .iter()
            .map(|name| {
                let settings = crate::system::settings(name);
                let declared = settings.as_ref().is_some_and(|s| s.declared);
                system_network(
                    name,
                    crate::system::declared_kind(name),
                    if declared { "nix" } else { "local" },
                    &crate::system::run_state(name),
                    settings.as_ref().and_then(|s| s.uplink.as_deref()),
                )
            })
            .collect(),
    )
}

/// The live launches of a container: `{app, pid, network}`.
fn running(tools: &Tools, c: &Container) -> String {
    let records = container::live_records(tools, c);
    array(
        records
            .iter()
            .map(|(app, r)| {
                format!(
                    "{{\"app\":{},\"pid\":{},\"network\":{}}}",
                    string(app),
                    r.pid,
                    string(&r.zone)
                )
            })
            .collect(),
    )
}

/// One trusted certificate, with what openssl can tell about it.
fn trust(tools: &Tools, c: &Container) -> String {
    let declared = c
        .declared_trust
        .iter()
        .flat_map(|dir| crate::trust::stored(dir.as_path()))
        .map(|cert| (cert, Source::Nix));
    let local = crate::trust::stored(&c.trust_dir())
        .into_iter()
        .map(|cert| (cert, Source::Local));
    array(
        declared
            .chain(local)
            .map(|(cert, source)| {
                let info = crate::cli::certificate_info(tools, &cert.path, "PEM").ok();
                let field = |f: fn(&crate::trust::CertInfo) -> &str| {
                    info.as_ref().map_or("null".to_owned(), |i| string(f(i)))
                };
                format!(
                    "{{\"sha256\":{},\"subject\":{},\"not_after\":{},\"source\":{}}}",
                    string(&cert.sha256),
                    field(|i| i.subject.as_str()),
                    field(|i| i.not_after.as_str()),
                    string(source.as_str())
                )
            })
            .collect(),
    )
}

pub fn container(tools: &Tools, c: &Container) -> String {
    let home_source = c.home_source;
    let apps = array(
        c.apps
            .iter()
            .map(|app| sourced_str(&app.value, app.source))
            .collect(),
    );
    // A private home has permissions of its own; an overlay is the real home
    // with its data split, and has none to speak of; the main home is the
    // real one.
    let permissions = match c.home {
        Home::Layer | Home::Main => "null".to_owned(),
        Home::Private => {
            let file = c.policy.join("perms");
            let (perms, source) = match fs::read_to_string(&file) {
                Ok(text) => (Perms::parse(&text), Source::Local),
                Err(_) => (Perms::default(), Source::Default),
            };
            let filesystem: Vec<String> = [
                (perms.downloads, "downloads"),
                (perms.documents, "documents"),
                (perms.pictures, "pictures"),
                (perms.home, "home"),
            ]
            .iter()
            .filter(|(on, _)| *on)
            .map(|(_, name)| string(name))
            .collect();
            // `expires`: the end of a grant's term, `null` for a grant without one.
            let paths = array(
                c.paths
                    .iter()
                    .map(|p| {
                        let expires = c
                            .expires
                            .iter()
                            .find(|(path, _)| *path == p.value)
                            .map_or("null".to_owned(), |(_, until)| {
                                string(&crate::journal::utc(*until))
                            });
                        format!(
                            "{{\"value\":{},\"source\":{},\"expires\":{expires}}}",
                            string(&p.value.to_string_lossy()),
                            string(p.source.as_str())
                        )
                    })
                    .collect(),
            );
            format!(
                "{{\"filesystem\":{},\"x11\":{},\"paths\":{paths}}}",
                sourced(array(filesystem), source),
                sourced(perms.x11.to_string(), source)
            )
        }
    };
    let (wayland, wayland_source) = setting(tools, "wayland-sandbox", "on");
    let compositor = if wayland == "on" {
        "restricted"
    } else {
        "full"
    };
    // Its own colour, or none: the zone's is the network's (`networks[]`).
    let frame_color = match &c.frame_color {
        Some(color) => sourced_str(&color.value, color.source),
        None => sourced("null".to_owned(), Source::Default),
    };
    // Its own microphone and screen cast settings, or none: the zone's
    // (`networks[]`).
    let microphone = match &c.microphone {
        Some(m) => sourced_str(m.value.as_str(), m.source),
        None => sourced("null".to_owned(), Source::Default),
    };
    let screencast = match &c.screencast {
        Some(m) => sourced_str(m.value.as_str(), m.source),
        None => sourced("null".to_owned(), Source::Default),
    };
    let camera = match &c.camera {
        Some(m) => sourced(m.value.to_string(), m.source),
        None => sourced("null".to_owned(), Source::Default),
    };
    // The devices it is given (`crate::devices`), each with where from.
    let devices = array(
        c.devices
            .iter()
            .map(|d| sourced_str(&d.value, d.source))
            .collect(),
    );
    // Its rules for links (`crate::links`): the program its links of a
    // scheme open in without the choice of one, each with where from.
    let links = array(
        c.links
            .iter()
            .map(|l| {
                format!(
                    "{{\"scheme\":{},\"program\":{},\"source\":{}}}",
                    string(&l.value.0),
                    string(&l.value.1),
                    string(l.source.as_str())
                )
            })
            .collect(),
    );
    format!(
        "{{\"name\":{},\"selector\":{},\"home\":{},\"network\":{},\"apps\":{apps},\
         \"permissions\":{permissions},\"compositor\":{},\"trust\":{},\"running\":{},\
         \"x11\":{},\"frame_color\":{frame_color},\"microphone\":{microphone},\"screencast\":{screencast},\"camera\":{camera},\"devices\":{devices},\"links\":{links}}}",
        string(&c.name),
        string(&c.selector()),
        sourced_str(c.home.as_str(), home_source),
        sourced_str(c.network.value.as_str(), c.network.source),
        sourced_str(compositor, wayland_source),
        trust(tools, c),
        running(tools, c),
        sourced(c.x11.value.to_string(), c.x11.source)
    )
}

pub fn containers(tools: &Tools) -> String {
    array(
        container::load_all(tools)
            .iter()
            .map(|c| container(tools, c))
            .collect(),
    )
}

/// Every program the picker knows about: labelled, or assigned to a
/// container — by the picker or in Nix. Its `network` is its container's.
pub fn apps(tools: &Tools) -> String {
    let names = |sub: &str| -> Vec<String> {
        visible_entries(&tools.state.join(sub))
            .iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect()
    };
    let all = container::load_all(tools);
    let mut ids: Vec<String> = names(".labels");
    ids.extend(names(".pinnedprofile"));
    for c in &all {
        ids.extend(c.apps.iter().map(|a| a.value.clone()));
    }
    ids.sort();
    ids.dedup();

    array(
        ids.iter()
            .map(|id| {
                let label = read_setting(&tools.state.join(".labels").join(id))
                    .map_or("null".to_owned(), |l| string(&l));
                let assigned = all.iter().find_map(|c| {
                    c.apps
                        .iter()
                        .find(|a| &a.value == id)
                        .map(|a| sourced_str(&c.selector(), a.source))
                });
                let assigned = assigned.unwrap_or_else(|| sourced("null".to_owned(), Source::Default));
                // The network is the container's (`docs/PERMISSIONS.md`
                // §11.8): the one the program's container is bound to.
                let network = all
                    .iter()
                    .find(|c| c.apps.iter().any(|a| &a.value == id))
                    .and_then(|c| match &c.network.value {
                        container::Network::Named(n) => Some(sourced_str(n, c.network.source)),
                        container::Network::Ask => None,
                    })
                    .unwrap_or_else(|| sourced("null".to_owned(), Source::Default));
                format!(
                    "{{\"id\":{},\"label\":{label},\"container\":{assigned},\"network\":{network}}}",
                    string(id)
                )
            })
            .collect(),
    )
}

/// `vpn-zone status --bar`: one JSON line in the shape status bars take
/// (`text`, `tooltip`, `class`, as waybar's `return-type: json` reads it).
///
/// The text names the zones that are up, a dead tunnel marked; the class is
/// the worst of them — `dead` when a tunnel `vpn-zone watch` found dead, `up`
/// when zones are up and none is, `none` when no zone is up. Nothing here reads
/// the network itself: the watcher's memory and the status mirrors only, so a
/// bar polling every second costs nothing.
pub fn bar(tools: &Tools) -> String {
    let mut up = Vec::new();
    let mut dead = false;
    for dir in visible_entries(&tools.state) {
        let Some(name) = dir.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        if zone_kind(&dir).is_none() || zone_pid(&tools.state, name.as_ref()).is_none() {
            continue;
        }
        let verdict = fs::read_to_string(tools.state.join(crate::watch::WATCH_DIR).join(&name))
            .ok()
            .and_then(|t| crate::watch::parse_memory(&t))
            .map(|(_, v)| v);
        let is_dead = verdict == Some(crate::watch::Verdict::Dead);
        dead |= is_dead;
        up.push(if is_dead { format!("{name} ✗") } else { name });
    }
    let class = if dead {
        "dead"
    } else if up.is_empty() {
        "none"
    } else {
        "up"
    };
    let mut tooltip = if up.is_empty() {
        "cellward: ни одна зона не поднята".to_owned()
    } else if dead {
        "cellward: туннель не отвечает (✗)".to_owned()
    } else {
        "cellward: поднятые зоны".to_owned()
    };
    // What runs with nothing of a zone around it is to be seen, not looked
    // for: a mark in the text and the programs in the tooltip.
    let unconfined = unconfined_launches(&tools.state);
    let mut text = up.join(" ");
    if !unconfined.is_empty() {
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(&format!("⚠{}", unconfined.len()));
        tooltip.push_str(&format!(
            "\nБез ограничений (⚠) сейчас: {}",
            unconfined.join(", ")
        ));
    }
    format!(
        "{{\"text\":{},\"tooltip\":{},\"class\":{},\"unconfined\":{}}}",
        string(&text),
        string(&tooltip),
        string(class),
        unconfined.len()
    )
}

/// The programs running in `unconfined` right now, by the registry: one name
/// per live pid (a launch is recorded under its id and its binary both).
pub fn unconfined_launches(state: &std::path::Path) -> Vec<String> {
    let mut seen = std::collections::BTreeMap::new();
    let running = state.join(".running");
    for dir in crate::registry::dirs(&running) {
        for file in visible_entries(&dir) {
            if !file.is_file() {
                continue;
            }
            let Ok(text) = fs::read_to_string(&file) else {
                continue;
            };
            let name = file
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            for record in text.lines().filter_map(crate::registry::parse_record) {
                if record.zone == crate::launch::UNCONFINED
                    && crate::registry::alive(&running, record.pid)
                {
                    seen.entry(record.pid).or_insert_with(|| name.clone());
                }
            }
        }
    }
    seen.into_values().collect()
}

/// The whole document of `vpn-zone status --json`.
pub fn document(tools: &Tools) -> String {
    // The host ids of the zones' sockets on the host, for a host egress policy
    // (`meta skuid`/`meta skgid`); `null` without subordinate ranges.
    let uplink_owner = crate::zone::uplink_owner().map_or("null".to_owned(), |(uid, gid)| {
        format!("{{\"uid\":{uid},\"gid\":{gid}}}")
    });
    format!(
        "{{\"schema_version\":{SCHEMA_VERSION},\"defaults\":{},\"networks\":{},\"containers\":{},\"apps\":{},\"system_networks\":{},\"uplink_owner\":{uplink_owner}}}",
        defaults(tools),
        networks(tools),
        containers(tools),
        apps(tools),
        system_networks()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_escaped_the_json_way() {
        assert_eq!(string("plain"), "\"plain\"");
        assert_eq!(string("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(string("line\nnext\ttab"), "\"line\\nnext\\ttab\"");
        assert_eq!(string("\u{1}"), "\"\\u0001\"");
        assert_eq!(string("\u{7f}\u{9b}"), "\"\\u007f\\u009b\"");
        assert_eq!(string("Огненный лис"), "\"Огненный лис\"");
    }

    #[test]
    fn a_sourced_value_carries_its_origin() {
        assert_eq!(
            sourced_str("nl", Source::Nix),
            "{\"value\":\"nl\",\"source\":\"nix\"}"
        );
        assert_eq!(
            sourced("true".to_owned(), Source::Default),
            "{\"value\":true,\"source\":\"default\"}"
        );
        assert_eq!(array(vec![]), "[]");
        assert_eq!(array(vec!["1".into(), "2".into()]), "[1,2]");
    }

    #[test]
    fn a_system_zone_says_only_what_its_reader_may_know() {
        use crate::system::RunState;

        let closed = system_network("nl", "wireguard", "nix", &RunState::Closed, None);
        for part in [
            "\"name\":\"nl\"",
            "\"netns\":\"/run/netns/vz-nl\"",
            "\"source\":\"nix\"",
            "\"up\":null",
            "\"tunnel_alive\":null",
            "\"rx_bytes\":null",
            "\"readable\":false",
        ] {
            assert!(closed.contains(part), "{part} in {closed}");
        }

        let down = system_network("nl", "wireguard", "nix", &RunState::Down, None);
        assert!(down.contains("\"up\":false"), "{down}");
        assert!(down.contains("\"readable\":true"), "{down}");
        assert!(down.contains("\"tunnel_alive\":null"), "{down}");

        let mirror = "interface: awg0\n\npeer: abc=\n  endpoint: 192.0.2.1:51820\n  \
                      latest handshake: 12 seconds ago\n  \
                      transfer: 1.00 KiB received, 2.00 KiB sent\n";
        let up = system_network(
            "nl",
            "wireguard",
            "nix",
            &RunState::Up(Some(mirror.to_owned())),
            None,
        );
        assert!(up.contains("\"up\":true"), "{up}");
        assert!(up.contains("\"uplink\":null"), "{up}");
        assert!(up.contains("\"tunnel_alive\":true"), "{up}");
        assert!(up.contains("\"handshake_age_s\":12"), "{up}");
        assert!(up.contains("\"rx_bytes\":1024"), "{up}");

        let plain = system_network(
            "pl",
            "plain",
            "local",
            &RunState::Up(Some(
                "interface: awg0\n  backend: plain\n  connected: yes\n".to_owned(),
            )),
            Some("enp4s0"),
        );
        assert!(plain.contains("\"kind\":\"plain\""), "{plain}");
        assert!(plain.contains("\"uplink\":\"enp4s0\""), "{plain}");
        assert!(plain.contains("\"source\":\"local\""), "{plain}");
        assert!(plain.contains("\"tunnel_alive\":true"), "{plain}");

        // Up, before the holder has written its first mirror.
        let early = system_network("nl", "wireguard", "nix", &RunState::Up(None), None);
        assert!(early.contains("\"up\":true"), "{early}");
        assert!(early.contains("\"tunnel_alive\":null"), "{early}");
    }
}
