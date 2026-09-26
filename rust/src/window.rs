//! The launch window's contract: what the picker tells `vpn-zone-window` on
//! its standard input, and what the window answers on its standard output.
//!
//! The window is a program of its own (`window/`, a crate with a toolkit this
//! one does not need): one window with the network and the container side by
//! side, instead of two kdialog menus in a row with every entry twice ("… —
//! всегда"). The picker keeps every decision; the window only shows the
//! choices and brings back which ones were taken. Without it the picker asks
//! with kdialog, as before.
//!
//! One line per item, fields separated by a tab. Nothing a field carries may
//! contain a tab or a line break — [`clean`] takes them out:
//!
//! ```text
//! title⇥<text>
//! note⇥<text>                         (any number)
//! net⇥<tag>⇥<label>⇥<flags>
//! container⇥<tag>⇥<label>⇥<flags>
//! pin-net⇥0|1
//! pin-container⇥0|1
//! guard⇥<ms>                          (nothing starts before; optional)
//! pins⇥0                              (no "always"; optional)
//! asker⇥<net>                         (a zone asks: Enter starts only there)
//! program⇥<text>                      (what the command runs, on the host)
//! cmd⇥<word>                          (the zone's command, a word each)
//! rule⇥<text>                         (a checkbox of its own: a container's
//!                                      rule for links, `crate::links`)
//! ```
//!
//! Flags, comma-separated: `selected`; `dead` (the tunnel does not answer);
//! `busy=<zone>` (open in that network, so usable only with it); `bound=<zone>`
//! (the container belongs to that network); `new` (choosing it asks for a
//! name). The answer, exit status 0; a close or Esc is exit status 1 and no
//! answer:
//!
//! ```text
//! net⇥<tag>
//! container⇥<tag>
//! name⇥<text>                         (for a `new` container)
//! pin-net⇥0|1
//! pin-container⇥0|1
//! rule⇥0|1                            (where the request had one)
//! ```
//!
//! The same window is the hotkey menu of a running program
//! (`crate::focus`): `mode⇥menu`, a title, notes, and one
//! `action⇥<tag>⇥<label>⇥<flags>` per entry (`danger` for one that breaks
//! something); the answer is `action⇥<tag>`.

/// One row of a column.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Item {
    pub tag: String,
    pub label: String,
    pub selected: bool,
    pub dead: bool,
    pub busy: Option<String>,
    pub bound: Option<String>,
    pub new: bool,
}

/// Everything the window shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Request {
    pub title: String,
    pub notes: Vec<String>,
    pub nets: Vec<Item>,
    pub containers: Vec<Item>,
    pub pin_net: bool,
    pub pin_container: bool,
    /// Milliseconds after the window opens during which nothing is started:
    /// the answer to a program in a zone that brought the window up, which
    /// takes the focus from whatever the person was typing into.
    pub guard_ms: u64,
    /// No "always" in the window (`crate::picker` from a zone).
    pub no_pins: bool,
    /// The network of the zone that asks: Enter starts only there, another
    /// takes a click on the button that names it.
    pub asker: Option<String>,
    /// What the command's first word is on the host.
    pub program: String,
    /// The zone's command, one word each, shown apart from the notes.
    pub command: Vec<String>,
    /// A checkbox of its own, unticked: the rule a link's program would be
    /// kept by (`crate::links`) — what it says.
    pub rule: Option<String>,
}

/// The hotkey menu: entries to choose one of.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Menu {
    pub title: String,
    pub notes: Vec<String>,
    /// `(tag, label, danger)`.
    pub actions: Vec<(String, String, bool)>,
}

/// The menu as the window reads it.
pub fn render_menu(menu: &Menu) -> String {
    let mut out = format!("mode\tmenu\ntitle\t{}\n", clean(&menu.title));
    for note in &menu.notes {
        out.push_str(&format!("note\t{}\n", clean(note)));
    }
    for (tag, label, danger) in &menu.actions {
        out.push_str(&format!(
            "action\t{}\t{}\t{}\n",
            clean(tag),
            clean(label),
            if *danger { "danger" } else { "" }
        ));
    }
    out
}

/// The chosen entry's tag.
pub fn parse_menu_reply(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.strip_prefix("action\t"))
        .map(str::to_owned)
        .filter(|t| !t.is_empty())
}

/// What came back.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reply {
    pub net: String,
    pub container: String,
    pub name: Option<String>,
    pub pin_net: bool,
    pub pin_container: bool,
    /// The request's rule ticked.
    pub rule: bool,
}

/// A field as the format can carry it: tabs and line breaks become spaces.
pub fn clean(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c == '\t' || c == '\n' || c == '\r' {
                ' '
            } else {
                c
            }
        })
        .collect()
}

fn flags(item: &Item) -> String {
    let mut out = Vec::new();
    if item.selected {
        out.push("selected".to_owned());
    }
    if item.dead {
        out.push("dead".to_owned());
    }
    if let Some(zone) = &item.busy {
        out.push(format!("busy={}", clean(zone).replace(',', " ")));
    }
    if let Some(zone) = &item.bound {
        out.push(format!("bound={}", clean(zone).replace(',', " ")));
    }
    if item.new {
        out.push("new".to_owned());
    }
    out.join(",")
}

/// The request as the window reads it.
pub fn render(req: &Request) -> String {
    let mut out = format!("title\t{}\n", clean(&req.title));
    for note in &req.notes {
        out.push_str(&format!("note\t{}\n", clean(note)));
    }
    for (kind, items) in [("net", &req.nets), ("container", &req.containers)] {
        for item in items {
            out.push_str(&format!(
                "{kind}\t{}\t{}\t{}\n",
                clean(&item.tag),
                clean(&item.label),
                flags(item)
            ));
        }
    }
    out.push_str(&format!("pin-net\t{}\n", u8::from(req.pin_net)));
    out.push_str(&format!("pin-container\t{}\n", u8::from(req.pin_container)));
    if req.guard_ms > 0 {
        out.push_str(&format!("guard\t{}\n", req.guard_ms));
    }
    if req.no_pins {
        out.push_str("pins\t0\n");
    }
    if let Some(asker) = &req.asker {
        out.push_str(&format!("asker\t{}\n", clean(asker)));
    }
    if !req.program.is_empty() {
        out.push_str(&format!("program\t{}\n", clean(&req.program)));
    }
    for word in &req.command {
        out.push_str(&format!("cmd\t{}\n", clean(word)));
    }
    if let Some(rule) = &req.rule {
        out.push_str(&format!("rule\t{}\n", clean(rule)));
    }
    out
}

/// The window's answer. `None` when it is not one: no network or no container
/// chosen — a window that crashed half-way must not start anything.
pub fn parse_reply(text: &str) -> Option<Reply> {
    let mut reply = Reply::default();
    let (mut net, mut container) = (None, None);
    for line in text.lines() {
        let (key, value) = line.split_once('\t').unwrap_or((line, ""));
        match key {
            "net" => net = Some(value.to_owned()),
            "container" => container = Some(value.to_owned()),
            "name" => reply.name = Some(value.to_owned()).filter(|v| !v.is_empty()),
            "pin-net" => reply.pin_net = value == "1",
            "pin-container" => reply.pin_container = value == "1",
            "rule" => reply.rule = value == "1",
            _ => {}
        }
    }
    reply.net = net.filter(|n| !n.is_empty())?;
    reply.container = container?;
    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_is_one_line_per_item_and_nothing_breaks_a_line() {
        let req = Request {
            title: "Запуск: Fire\tfox".to_owned(),
            notes: vec!["уже\nработает".to_owned()],
            nets: vec![
                Item {
                    tag: "nl".to_owned(),
                    label: "VPN: nl".to_owned(),
                    selected: true,
                    ..Item::default()
                },
                Item {
                    tag: "de".to_owned(),
                    label: "VPN: de".to_owned(),
                    dead: true,
                    ..Item::default()
                },
            ],
            containers: vec![Item {
                tag: "work".to_owned(),
                label: "Профиль work".to_owned(),
                busy: Some("nl".to_owned()),
                ..Item::default()
            }],
            pin_net: true,
            pin_container: false,
            ..Request::default()
        };
        assert_eq!(
            render(&req),
            "title\tЗапуск: Fire fox\nnote\tуже работает\n\
             net\tnl\tVPN: nl\tselected\nnet\tde\tVPN: de\tdead\n\
             container\twork\tПрофиль work\tbusy=nl\npin-net\t1\npin-container\t0\n"
        );
    }

    /// A window a zone's program brought up: the guard and no "always" go
    /// along; an ordinary one says neither.
    #[test]
    fn the_guard_and_no_always_are_said_only_when_set() {
        let req = Request {
            guard_ms: 1500,
            no_pins: true,
            ..Request::default()
        };
        assert!(render(&req).ends_with("guard\t1500\npins\t0\n"));
        let plain = render(&Request::default());
        assert!(!plain.contains("guard") && !plain.contains("pins\t"));
    }

    #[test]
    fn the_menu_goes_out_one_line_per_entry_and_one_comes_back() {
        let menu = Menu {
            title: "Firefox".to_owned(),
            notes: vec!["сеть nl".to_owned()],
            actions: vec![
                ("close".to_owned(), "Закрыть".to_owned(), false),
                ("kill-zone".to_owned(), "Оборвать сеть nl".to_owned(), true),
            ],
        };
        assert_eq!(
            render_menu(&menu),
            "mode\tmenu\ntitle\tFirefox\nnote\tсеть nl\n\
             action\tclose\tЗакрыть\t\naction\tkill-zone\tОборвать сеть nl\tdanger\n"
        );
        assert_eq!(
            parse_menu_reply("action\tclose\n").as_deref(),
            Some("close")
        );
        assert_eq!(parse_menu_reply("action\t\n"), None);
        assert_eq!(parse_menu_reply(""), None);
    }

    #[test]
    fn an_answer_needs_a_network_and_a_container() {
        let reply = parse_reply(
            "net\tnl\ncontainer\t__newsb__\nname\tобщая\npin-net\t1\npin-container\t0\nrule\t1\n",
        )
        .unwrap();
        assert_eq!(
            reply,
            Reply {
                net: "nl".to_owned(),
                container: "__newsb__".to_owned(),
                name: Some("общая".to_owned()),
                pin_net: true,
                pin_container: false,
                rule: true,
            }
        );
        // The main container is the empty tag — present, and empty.
        assert_eq!(
            parse_reply("net\toffline\ncontainer\t\n")
                .unwrap()
                .container,
            ""
        );
        assert_eq!(parse_reply("container\t\n"), None);
        assert_eq!(parse_reply("net\tnl\n"), None);
        assert_eq!(parse_reply(""), None);
    }
}
