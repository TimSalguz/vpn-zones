//! `vpn-zone-window` — the launch window of vpn-zones: the network and the
//! container of a program, side by side, in one window.
//!
//! The picker (`vpn-zone-pick`) keeps every decision; this program only shows
//! the choices and brings back which ones were taken. It reads the request on
//! standard input and writes the answer on standard output — the contract is
//! `rust/src/window.rs` of vpn-zones, repeated here in `parse_request` and
//! `answer`. Exit status 0 is an answer; 1 is a close, Esc or Cancel, and
//! nothing is started.
//!
//! Keyboard: ←/→ or Tab switch the column, ↑/↓ or a digit choose in it, Space
//! ticks "always" of that column, Enter starts, Esc closes.
//!
//! A window a program in a zone brought up (`guard`, `pins`, `asker`) takes
//! nothing — no key, no click, no choice — until the person has been still
//! for the guard's time with the window focused: it takes the focus when the
//! program likes, and somebody still typing or clicking into something else
//! must not pick a row and say yes. Every key and every press starts the
//! guard again, captured by a widget or not, and so does the focus coming
//! back. There, Enter starts only in the network that asks; another network
//! takes a click on the button that names it, after the guard once more (a
//! changed choice restarts it); digits choose nothing. And it has no
//! "always": a program there picks which launcher's name the window carries,
//! and "always" for that name would decide later launches from the menu.
//! The command it asks to run is its own block, word by word and numbered,
//! apart from the window's notes. A container that is
//! open in another network (or belongs to one) cannot go with a different
//! network: it is shown greyed out with the reason, and the choice skips it.

use std::io::Read;

use iced::keyboard::{self, key, Key};
use iced::widget::{button, checkbox, column, container, row, scrollable, text, text_input};
use iced::{Alignment, Element, Length, Subscription, Task};

/// One row of a column, as the picker sent it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Item {
    tag: String,
    label: String,
    selected: bool,
    dead: bool,
    busy: Option<String>,
    bound: Option<String>,
    new: bool,
}

/// Everything the window shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Request {
    /// `menu`: the hotkey menu of a running program — entries, one of which
    /// is chosen. Anything else: the launch window.
    mode: String,
    /// The menu's entries: `(tag, label, danger)`.
    actions: Vec<(String, String, bool)>,
    title: String,
    notes: Vec<String>,
    nets: Vec<Item>,
    containers: Vec<Item>,
    pin_net: bool,
    pin_container: bool,
    /// For how long, in milliseconds, nothing is started (`guard⇥<ms>`).
    guard: u64,
    /// `pins⇥0`: no "always" checkboxes, and none ticked.
    no_pins: bool,
    /// `asker⇥<net>`: the network of the zone that asks — Enter starts only
    /// there.
    asker: Option<String>,
    /// `program⇥<text>`: what the command's first word is on the host.
    program: String,
    /// `cmd⇥<word>`: the command, one word each.
    command: Vec<String>,
    /// `rule⇥<text>`: a checkbox of its own, unticked — a container's rule
    /// for links; answered `rule⇥0|1`.
    rule: Option<String>,
}

fn parse_item(fields: &[&str]) -> Option<Item> {
    let tag = (*fields.first()?).to_owned();
    let label = (*fields.get(1)?).to_owned();
    let mut item = Item {
        tag,
        label,
        ..Item::default()
    };
    for flag in fields.get(2).unwrap_or(&"").split(',') {
        match flag.split_once('=') {
            Some(("busy", zone)) => item.busy = Some(zone.to_owned()),
            Some(("bound", zone)) => item.bound = Some(zone.to_owned()),
            _ => match flag {
                "selected" => item.selected = true,
                "dead" => item.dead = true,
                "new" => item.new = true,
                _ => {}
            },
        }
    }
    Some(item)
}

/// The request: one line per item, fields separated by tabs.
fn parse_request(text: &str) -> Request {
    let mut req = Request::default();
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        match fields[0] {
            "mode" => req.mode = fields.get(1).unwrap_or(&"").to_string(),
            "action" if fields.len() >= 3 => req.actions.push((
                fields[1].to_owned(),
                fields[2].to_owned(),
                fields
                    .get(3)
                    .is_some_and(|f| f.split(',').any(|f| f == "danger")),
            )),
            "title" => req.title = fields.get(1).unwrap_or(&"").to_string(),
            "note" => req.notes.push(fields.get(1).unwrap_or(&"").to_string()),
            "net" => req.nets.extend(parse_item(&fields[1..])),
            "container" => req.containers.extend(parse_item(&fields[1..])),
            "pin-net" => req.pin_net = fields.get(1) == Some(&"1"),
            "pin-container" => req.pin_container = fields.get(1) == Some(&"1"),
            "guard" => req.guard = fields.get(1).and_then(|v| v.parse().ok()).unwrap_or(0),
            "pins" => req.no_pins = fields.get(1) == Some(&"0"),
            "asker" => req.asker = fields.get(1).map(|v| v.to_string()),
            "program" => req.program = fields.get(1).unwrap_or(&"").to_string(),
            "cmd" => req.command.push(fields.get(1).unwrap_or(&"").to_string()),
            "rule" => {
                req.rule = fields
                    .get(1)
                    .map(|v| v.to_string())
                    .filter(|v| !v.is_empty())
            }
            _ => {}
        }
    }
    if req.no_pins {
        req.pin_net = false;
        req.pin_container = false;
    }
    req
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pane {
    Net,
    Container,
}

#[derive(Debug, Clone)]
enum Msg {
    /// A menu entry, by its index.
    Action(usize),
    Net(usize),
    Container(usize),
    PinNet(bool),
    PinContainer(bool),
    Rule(bool),
    Name(String),
    Launch,
    Cancel,
    /// A key, and whether a widget took it already.
    Key(Key, keyboard::Modifiers, bool),
    /// A mouse button pressed anywhere in the window.
    Press,
    /// The window got (`true`) or lost the focus.
    Focus(bool),
    /// The guard's time is over, if nothing came since this count of
    /// holds: taking a choice is possible.
    Armed(u64),
}

struct Window {
    req: Request,
    /// The highlighted menu entry.
    entry: usize,
    pane: Pane,
    net: usize,
    container: usize,
    pin_net: bool,
    pin_container: bool,
    /// The request's rule ticked.
    rule: bool,
    name: String,
    /// False while the request's guard runs.
    armed: bool,
    /// How many times the guard was started: only the last one arms.
    holds: u64,
}

/// Why a container cannot go with this network, if it cannot.
fn blocked(item: &Item, net: &str) -> Option<String> {
    if let Some(zone) = item.busy.as_deref().filter(|z| *z != net) {
        return Some(format!("открыт в сети {zone}"));
    }
    if let Some(zone) = item.bound.as_deref().filter(|z| *z != net) {
        return Some(format!("привязан к сети {zone}"));
    }
    None
}

const NAME_FIELD: &str = "new-container-name";

impl Window {
    fn new(req: Request) -> Self {
        // Nothing marked: `offline`, never the first row (the host's network).
        let net = req
            .nets
            .iter()
            .position(|i| i.selected)
            .or_else(|| req.nets.iter().position(|i| i.tag == "offline"))
            .unwrap_or(0);
        let container = req.containers.iter().position(|i| i.selected).unwrap_or(0);
        Self {
            pin_net: req.pin_net,
            pin_container: req.pin_container,
            rule: false,
            pane: Pane::Net,
            net,
            container,
            name: String::new(),
            entry: 0,
            armed: req.guard == 0,
            holds: 0,
            req,
        }
    }

    fn menu(&self) -> bool {
        self.req.mode == "menu"
    }

    fn net_tag(&self) -> &str {
        self.req.nets.get(self.net).map_or("", |i| i.tag.as_str())
    }

    fn container_ok(&self, i: usize) -> bool {
        self.req
            .containers
            .get(i)
            .is_some_and(|c| blocked(c, self.net_tag()).is_none())
    }

    /// Everything needed to start: a container that goes with the network, a
    /// name for a new one, and the guard's time over.
    fn ready(&self) -> bool {
        let Some(c) = self.req.containers.get(self.container) else {
            return false;
        };
        self.armed && self.container_ok(self.container) && (!c.new || !self.name.trim().is_empty())
    }

    fn naming(&self) -> bool {
        self.req
            .containers
            .get(self.container)
            .is_some_and(|c| c.new)
    }

    /// Move the choice in the focused column by `step`, skipping containers
    /// that cannot go with the network.
    fn step(&mut self, step: isize) {
        match self.pane {
            Pane::Net => {
                let n = self.req.nets.len() as isize;
                if n > 0 {
                    self.net = (self.net as isize + step).rem_euclid(n) as usize;
                }
            }
            Pane::Container => {
                let n = self.req.containers.len() as isize;
                let mut at = self.container as isize;
                for _ in 0..n {
                    at = (at + step).rem_euclid(n);
                    if self.container_ok(at as usize) {
                        self.container = at as usize;
                        break;
                    }
                }
            }
        }
    }

    fn pick(&mut self, index: usize) {
        match self.pane {
            Pane::Net if index < self.req.nets.len() => self.net = index,
            Pane::Container if self.container_ok(index) => self.container = index,
            _ => {}
        }
    }

    /// The answer, as the picker reads it.
    fn answer(&self) -> String {
        let mut out = format!("net\t{}\n", self.net_tag());
        let c = &self.req.containers[self.container];
        out.push_str(&format!("container\t{}\n", c.tag));
        if c.new {
            out.push_str(&format!(
                "name\t{}\n",
                self.name.trim().replace(['\t', '\n'], " ")
            ));
        }
        out.push_str(&format!("pin-net\t{}\n", u8::from(self.pin_net)));
        out.push_str(&format!(
            "pin-container\t{}\n",
            u8::from(self.pin_container)
        ));
        if self.req.rule.is_some() {
            out.push_str(&format!("rule\t{}\n", u8::from(self.rule)));
        }
        out
    }

    fn guarded(&self) -> bool {
        self.req.guard > 0
    }

    /// The guard, from the start: nothing is taken until it is over.
    fn hold(&mut self) -> Task<Msg> {
        self.armed = false;
        self.holds += 1;
        arm_after(self.req.guard, self.holds)
    }

    /// Whether Enter may start: anywhere in an ordinary window, only in the
    /// asking network in a zone's.
    fn enter_starts(&self) -> bool {
        self.req
            .asker
            .as_deref()
            .is_none_or(|a| a == self.net_tag())
    }

    fn update(&mut self, msg: Msg) -> Task<Msg> {
        // A guarded window takes no choice before the guard is over: the
        // input is somebody's elsewhere, and the guard starts again.
        if self.guarded() && !self.armed {
            match msg {
                Msg::Net(_)
                | Msg::Container(_)
                | Msg::PinNet(_)
                | Msg::PinContainer(_)
                | Msg::Name(_)
                | Msg::Launch
                | Msg::Action(_)
                | Msg::Press => return self.hold(),
                Msg::Key(ref key, _, _) if key.as_ref() != Key::Named(key::Named::Escape) => {
                    return self.hold()
                }
                _ => {}
            }
        }
        match msg {
            Msg::Action(i) => {
                if let Some((tag, _, _)) = self.req.actions.get(i) {
                    println!("action\t{tag}");
                    std::process::exit(0);
                }
            }
            Msg::Net(i) => {
                self.pane = Pane::Net;
                let changed = self.net != i;
                self.net = i;
                if changed && self.guarded() {
                    return self.hold();
                }
            }
            Msg::Container(i) => {
                self.pane = Pane::Container;
                if self.container_ok(i) {
                    let changed = self.container != i;
                    self.container = i;
                    if changed && self.guarded() {
                        return self.hold();
                    }
                    if self.naming() {
                        return iced::widget::operation::focus(NAME_FIELD);
                    }
                }
            }
            Msg::PinNet(v) => self.pin_net = v && !self.req.no_pins,
            Msg::PinContainer(v) => self.pin_container = v && !self.req.no_pins,
            Msg::Rule(v) => self.rule = v && self.req.rule.is_some(),
            Msg::Armed(holds) => self.armed |= holds == self.holds,
            Msg::Press => {}
            // Losing the focus disarms; getting it back starts the guard.
            Msg::Focus(focused) if self.guarded() => {
                if focused {
                    return self.hold();
                }
                self.armed = false;
                self.holds += 1;
            }
            Msg::Focus(_) => {}
            Msg::Name(name) => self.name = name,
            Msg::Launch => {
                if self.naming() && self.name.trim().is_empty() {
                    return iced::widget::operation::focus(NAME_FIELD);
                }
                if self.ready() {
                    print!("{}", self.answer());
                    std::process::exit(0);
                }
            }
            Msg::Cancel => std::process::exit(1),
            // A key a widget took (the name field) is the widget's.
            Msg::Key(key, _, true) if key.as_ref() != Key::Named(key::Named::Escape) => {}
            Msg::Key(key, modifiers, _) => return self.key(key, modifiers),
        }
        Task::none()
    }

    fn key(&mut self, key: Key, modifiers: keyboard::Modifiers) -> Task<Msg> {
        if self.menu() {
            let n = self.req.actions.len();
            match key.as_ref() {
                Key::Named(key::Named::Escape) => return self.update(Msg::Cancel),
                Key::Named(key::Named::Enter) => return self.update(Msg::Action(self.entry)),
                Key::Named(key::Named::ArrowUp) if n > 0 => self.entry = (self.entry + n - 1) % n,
                Key::Named(key::Named::ArrowDown) if n > 0 => self.entry = (self.entry + 1) % n,
                Key::Character(c) => {
                    if let Some(d) = c
                        .chars()
                        .next()
                        .and_then(|c| c.to_digit(10))
                        .filter(|d| *d > 0)
                    {
                        if (d as usize) <= n {
                            self.entry = d as usize - 1;
                        }
                    }
                }
                _ => {}
            }
            return Task::none();
        }
        let before = (self.net, self.container);
        let task = self.key_choose(key, modifiers);
        // A choice changed by the keyboard in a zone's window: the guard again.
        if self.guarded() && (self.net, self.container) != before {
            return self.hold();
        }
        task
    }

    fn key_choose(&mut self, key: Key, modifiers: keyboard::Modifiers) -> Task<Msg> {
        match key.as_ref() {
            Key::Named(key::Named::Escape) => return self.update(Msg::Cancel),
            Key::Named(key::Named::Enter) if self.enter_starts() => {
                return self.update(Msg::Launch)
            }
            Key::Named(key::Named::ArrowLeft) => self.pane = Pane::Net,
            Key::Named(key::Named::ArrowRight) => self.pane = Pane::Container,
            Key::Named(key::Named::Tab) => {
                self.pane = match (self.pane, modifiers.shift()) {
                    (Pane::Net, false) | (Pane::Container, true) => Pane::Container,
                    _ => Pane::Net,
                }
            }
            Key::Named(key::Named::ArrowUp) => self.step(-1),
            Key::Named(key::Named::ArrowDown) => self.step(1),
            Key::Named(key::Named::Space) if !self.req.no_pins => match self.pane {
                Pane::Net => self.pin_net = !self.pin_net,
                Pane::Container => self.pin_container = !self.pin_container,
            },
            // Digits choose nothing in a zone's window.
            Key::Character(c) if self.req.asker.is_none() => {
                if let Some(d) = c
                    .chars()
                    .next()
                    .and_then(|c| c.to_digit(10))
                    .filter(|d| *d > 0)
                {
                    self.pick(d as usize - 1);
                    if self.pane == Pane::Container && self.naming() {
                        return iced::widget::operation::focus(NAME_FIELD);
                    }
                }
            }
            _ => {}
        }
        Task::none()
    }

    fn column_view<'a>(
        &'a self,
        heading: &'a str,
        pane: Pane,
        items: &'a [Item],
        chosen: usize,
        on_pick: fn(usize) -> Msg,
    ) -> Element<'a, Msg> {
        let focused = self.pane == pane;
        let mut list = column![].spacing(2);
        for (i, item) in items.iter().enumerate() {
            let why = (pane == Pane::Container)
                .then(|| blocked(item, self.net_tag()))
                .flatten();
            let mark = if i == chosen { "●" } else { "○" };
            let number = if i < 9 {
                format!("{} ", i + 1)
            } else {
                "  ".to_owned()
            };
            let mut label = format!("{number}{mark} {}", item.label);
            if item.dead {
                label.push_str(" — туннель молчит");
            }
            if let Some(why) = &why {
                label.push_str(&format!(" — {why}"));
            }
            let style = if i == chosen && focused {
                button::primary
            } else if i == chosen {
                button::secondary
            } else {
                button::text
            };
            let b = button(text(label).size(14))
                .width(Length::Fill)
                .padding([4, 8])
                .style(style)
                .on_press_maybe(why.is_none().then(|| on_pick(i)));
            list = list.push(b);
        }
        let title = text(if focused {
            format!("▸ {heading}")
        } else {
            heading.to_owned()
        })
        .size(16);
        column![title, scrollable(list).height(Length::Fill)]
            .spacing(6)
            .width(Length::FillPortion(1))
            .into()
    }

    /// The hotkey menu: the program, what is known of it, the entries.
    fn view_menu(&self) -> Element<'_, Msg> {
        let mut page = column![text(&self.req.title).size(20)]
            .spacing(10)
            .padding(16);
        for note in &self.req.notes {
            page = page.push(text(note.as_str()).size(14));
        }
        let mut list = column![].spacing(4);
        for (i, (_, label, danger)) in self.req.actions.iter().enumerate() {
            let style = match (i == self.entry, *danger) {
                (true, true) => button::danger,
                (true, false) => button::primary,
                _ => button::text,
            };
            let mark = if *danger { "⚠ " } else { "" };
            list = list.push(
                button(text(format!("{} {mark}{label}", i + 1)).size(15))
                    .width(Length::Fill)
                    .padding([6, 10])
                    .style(style)
                    .on_press(Msg::Action(i)),
            );
        }
        page = page.push(list);
        page = page.push(
            row![
                container(text("")).width(Length::Fill),
                button(text("Закрыть меню  Esc").size(14))
                    .padding([6, 14])
                    .style(button::secondary)
                    .on_press(Msg::Cancel)
            ]
            .align_y(Alignment::Center),
        );
        page.into()
    }

    fn view(&self) -> Element<'_, Msg> {
        if self.menu() {
            return self.view_menu();
        }
        let nets = self.column_view("Сеть", Pane::Net, &self.req.nets, self.net, Msg::Net);
        let containers = self.column_view(
            "Контейнер",
            Pane::Container,
            &self.req.containers,
            self.container,
            Msg::Container,
        );
        let mut right = column![containers].spacing(8).width(Length::FillPortion(1));
        if self.naming() {
            right = right.push(
                text_input("Название (буквы, цифры, дефис)", &self.name)
                    .id(NAME_FIELD)
                    .on_input(Msg::Name)
                    .on_submit(Msg::Launch)
                    .padding(6),
            );
        }
        let mut left = column![nets].spacing(8).width(Length::FillPortion(1));
        if !self.req.no_pins {
            right = right.push(
                checkbox(self.pin_container)
                    .label("Всегда этот контейнер")
                    .on_toggle(Msg::PinContainer),
            );
            left = left.push(
                checkbox(self.pin_net)
                    .label("Всегда эту сеть")
                    .on_toggle(Msg::PinNet),
            );
        }

        // The program's name inside the window too: niri draws no title bars.
        let mut page = column![text(&self.req.title).size(20)]
            .spacing(12)
            .padding(16);
        for note in &self.req.notes {
            page = page.push(text(format!("ⓘ {note}")).size(14));
        }
        if !self.req.command.is_empty() {
            page = page.push(self.command_view());
        }
        page = page.push(row![left, right].spacing(16).height(Length::Fill));
        if let Some(rule) = &self.req.rule {
            page = page.push(checkbox(self.rule).label(rule).on_toggle(Msg::Rule));
        }
        let label = if !self.armed {
            "Секунду…".to_owned()
        } else if self.enter_starts() {
            "Запустить  Enter".to_owned()
        } else {
            let net = self.req.nets.get(self.net).map_or("", |n| n.label.as_str());
            format!("Запустить: {net}")
        };
        let launch = button(text(label).size(14))
            .padding([6, 14])
            .style(button::primary)
            .on_press_maybe(self.ready().then_some(Msg::Launch));
        let cancel = button(text("Отмена  Esc").size(14))
            .padding([6, 14])
            .style(button::secondary)
            .on_press(Msg::Cancel);
        page = page.push(
            row![container(text("")).width(Length::Fill), launch, cancel]
                .spacing(10)
                .align_y(Alignment::Center),
        );
        page.into()
    }

    /// The command a zone's program asks to run: apart from the notes, the
    /// program as the host finds it, then every word numbered, in a block of
    /// its own height that scrolls — the lists and the buttons stay in view
    /// however long it is, and a long word breaks instead of running off.
    fn command_view(&self) -> Element<'_, Msg> {
        let mut words = column![].spacing(2);
        for (i, word) in self.req.command.iter().enumerate() {
            words = words.push(
                text(format!("{:>2}. {word}", i + 1))
                    .size(13)
                    .wrapping(iced::widget::text::Wrapping::WordOrGlyph),
            );
        }
        let mut block = column![text("Команда").size(15)].spacing(4);
        if !self.req.program.is_empty() {
            block = block.push(
                text(format!("Программа: {}", self.req.program))
                    .size(13)
                    .wrapping(iced::widget::text::Wrapping::WordOrGlyph),
            );
        }
        block = block.push(scrollable(words).height(Length::Fixed(110.0)));
        container(block)
            .padding(8)
            .width(Length::Fill)
            .style(container::bordered_box)
            .into()
    }

    fn subscription(&self) -> Subscription<Msg> {
        iced::event::listen_with(|event, status, _window| match event {
            iced::Event::Keyboard(keyboard::Event::KeyPressed { key, modifiers, .. }) => Some(
                Msg::Key(key, modifiers, status == iced::event::Status::Captured),
            ),
            iced::Event::Mouse(iced::mouse::Event::ButtonPressed(_)) => Some(Msg::Press),
            iced::Event::Window(iced::window::Event::Focused) => Some(Msg::Focus(true)),
            iced::Event::Window(iced::window::Event::Unfocused) => Some(Msg::Focus(false)),
            _ => None,
        })
    }
}

/// `Msg::Armed(keys)` after `guard` milliseconds: a plain sleep on the
/// executor's pool — no timer backend in this build, and the pool has threads
/// to spare for it.
fn arm_after(guard: u64, holds: u64) -> Task<Msg> {
    let guard = std::time::Duration::from_millis(guard);
    Task::perform(async move { std::thread::sleep(guard) }, move |()| {
        Msg::Armed(holds)
    })
}

fn main() -> iced::Result {
    // The fonts of this window: a short list of its own (package.nix), not
    // every font of the system — iced reads all it is given at each start,
    // over a thousand on a desktop, seconds under load. Set before anything
    // starts a thread.
    if let Some(fonts) = option_env!("VPN_ZONE_WINDOW_FONTS") {
        std::env::set_var("FONTCONFIG_FILE", fonts);
    }
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        std::process::exit(1);
    }
    let req = parse_request(&input);
    // Nothing to choose from is not a window: the caller falls back.
    let empty = if req.mode == "menu" {
        req.actions.is_empty()
    } else {
        req.nets.is_empty() || req.containers.is_empty()
    };
    if empty {
        std::process::exit(1);
    }
    let size = if req.mode == "menu" {
        iced::Size::new(520.0, 380.0)
    } else if req.command.is_empty() {
        iced::Size::new(760.0, 460.0)
    } else {
        iced::Size::new(800.0, 640.0)
    };
    let title = if req.title.is_empty() {
        "Запуск".to_owned()
    } else {
        req.title.clone()
    };
    let boot = std::sync::Mutex::new(Some(req));
    iced::application(
        move || {
            let req = boot
                .lock()
                .ok()
                .and_then(|mut r| r.take())
                .unwrap_or_default();
            let window = Window::new(req);
            let arm = if window.armed {
                Task::none()
            } else {
                arm_after(window.req.guard, 0)
            };
            (window, arm)
        },
        Window::update,
        Window::view,
    )
    .title(move |_: &Window| title.clone())
    // None: the system's colour scheme decides, light or dark.
    .theme(|_: &Window| None::<iced::Theme>)
    .subscription(Window::subscription)
    .window(iced::window::Settings {
        size,
        position: iced::window::Position::Centered,
        // The name a compositor's window rule matches — to float it in a
        // tiling one, say. Without it the window has no app id at all.
        #[cfg(target_os = "linux")]
        platform_specific: iced::window::settings::PlatformSpecific {
            application_id: "vpn-zone-window".to_owned(),
            ..Default::default()
        },
        ..iced::window::Settings::default()
    })
    .run()
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST: &str = "title\tЗапуск: Firefox\nnote\tуже работает\n\
        net\tunconfined\tБез ограничений\t\nnet\toffline\tБез сети\t\nnet\tnl\tVPN: nl\tselected\n\
        net\tde\tVPN: de\tdead\n\
        container\t\tОсновной\t\ncontainer\t__ownsb__\tСвоя песочница\tselected\n\
        container\twork\tПрофиль work\tbusy=de\ncontainer\t__newsb__\tНовая песочница…\tnew\n\
        pin-net\t1\npin-container\t0\n";

    #[test]
    fn the_request_is_read_as_the_picker_writes_it() {
        let req = parse_request(REQUEST);
        assert_eq!(req.title, "Запуск: Firefox");
        assert_eq!(req.notes, ["уже работает"]);
        assert_eq!(req.nets.len(), 4);
        assert!(req.nets[2].selected && req.nets[3].dead);
        assert_eq!(req.containers[0].tag, "");
        assert_eq!(req.containers[2].busy.as_deref(), Some("de"));
        assert!(req.containers[3].new);
        assert!(req.pin_net && !req.pin_container);
    }

    #[test]
    fn the_keyboard_chooses_and_the_answer_is_what_was_chosen() {
        let mut w = Window::new(parse_request(REQUEST));
        assert_eq!((w.net, w.container), (2, 1));
        // A container open in another network is skipped while nl is chosen.
        w.pane = Pane::Container;
        w.step(1);
        assert_eq!(w.container, 3, "work (busy in de) is skipped");
        // ...and becomes reachable when its network is chosen.
        w.pane = Pane::Net;
        w.pick(3);
        w.pane = Pane::Container;
        w.pick(2);
        assert_eq!(w.container, 2);
        let _ = w.key(
            Key::Named(key::Named::Space),
            keyboard::Modifiers::default(),
        );
        assert_eq!(
            w.answer(),
            "net\tde\ncontainer\twork\npin-net\t1\npin-container\t1\n"
        );
    }

    #[test]
    fn the_menu_is_read_and_walked_with_the_keyboard() {
        let req = parse_request(
            "mode\tmenu\ntitle\tFirefox\nnote\tсеть nl\n\
             action\tpin\tВсегда в nl\t\naction\tkill-zone\tОборвать nl\tdanger\n",
        );
        assert_eq!(req.mode, "menu");
        assert_eq!(
            req.actions,
            [
                ("pin".to_owned(), "Всегда в nl".to_owned(), false),
                ("kill-zone".to_owned(), "Оборвать nl".to_owned(), true)
            ]
        );
        let mut w = Window::new(req);
        assert!(w.menu());
        let _ = w.key(
            Key::Named(key::Named::ArrowDown),
            keyboard::Modifiers::default(),
        );
        assert_eq!(w.entry, 1);
        let _ = w.key(
            Key::Named(key::Named::ArrowDown),
            keyboard::Modifiers::default(),
        );
        assert_eq!(w.entry, 0, "round");
        let _ = w.key(Key::Character("2".into()), keyboard::Modifiers::default());
        assert_eq!(w.entry, 1);
    }

    /// A window a zone's program brought up: nothing starts during the guard,
    /// and there is no "always" to tick.
    fn press(w: &mut Window, key: Key) {
        let _ = w.update(Msg::Key(key, keyboard::Modifiers::default(), false));
    }

    fn arm(w: &mut Window) {
        let _ = w.update(Msg::Armed(w.holds));
    }

    /// A window a zone's program brought up takes nothing until the guard is
    /// over — no key, no click, no choice — and every one of them, captured
    /// by a widget or not, and the focus coming back start it again. There is
    /// no "always" to tick.
    #[test]
    fn a_guarded_window_takes_nothing_until_the_person_is_still() {
        let req = parse_request(&format!("{REQUEST}guard\t1500\npins\t0\n"));
        assert_eq!(req.guard, 1500);
        assert!(req.no_pins && !req.pin_net, "a pin sent along is dropped");
        let mut w = Window::new(req);
        assert!(!w.armed && !w.ready());
        // Somebody still typing or clicking: nothing is chosen or started,
        // and the guard that was running no longer arms the window.
        press(&mut w, Key::Character("1".into()));
        let _ = w.update(Msg::Net(0));
        let _ = w.update(Msg::Container(0));
        let _ = w.update(Msg::Launch);
        let _ = w.update(Msg::PinContainer(true));
        assert_eq!(
            (w.net, w.container),
            (2, 1),
            "a choice was taken during the guard"
        );
        assert!(!w.pin_container);
        let stale = w.holds;
        let _ = w.update(Msg::Key(
            Key::Character("x".into()),
            keyboard::Modifiers::default(),
            true,
        ));
        let _ = w.update(Msg::Armed(stale));
        assert!(
            !w.armed,
            "a key a widget took did not start the guard again"
        );
        let stale = w.holds;
        let _ = w.update(Msg::Press);
        let _ = w.update(Msg::Armed(stale));
        assert!(!w.armed, "a click did not start the guard again");
        arm(&mut w);
        assert!(w.ready());
        // The focus goes and comes back: disarmed, and the guard again.
        let _ = w.update(Msg::Focus(false));
        assert!(!w.armed);
        let _ = w.update(Msg::Focus(true));
        assert!(!w.armed);
        arm(&mut w);
        press(&mut w, Key::Named(key::Named::Space));
        assert!(!w.pin_net && !w.pin_container);
        assert!(w.answer().ends_with("pin-net\t0\npin-container\t0\n"));
    }

    /// A link's rule: offered unticked, answered as ticked or not, and never
    /// ticked where it was not offered.
    #[test]
    fn a_rule_is_offered_unticked_and_answered() {
        let text = "title\tt\nnet\tnl\tnl\tselected\ncontainer\t\tОсновной\t\n\
                    pins\t0\nrule\tВсегда открывать ссылки https: из контейнера tg в Firefox\n";
        let req = parse_request(text);
        assert_eq!(
            req.rule.as_deref(),
            Some("Всегда открывать ссылки https: из контейнера tg в Firefox")
        );
        let mut w = Window::new(req);
        assert!(w.answer().ends_with("rule\t0\n"));
        let _ = w.update(Msg::Rule(true));
        assert!(w.answer().ends_with("rule\t1\n"));
        let mut plain = Window::new(parse_request(
            "title\tt\nnet\tnl\tnl\ncontainer\t\tОсновной\t\n",
        ));
        let _ = plain.update(Msg::Rule(true));
        assert!(!plain.answer().contains("rule"));
    }

    /// In a zone's window Enter starts only in the network that asks; digits
    /// choose nothing; a choice changed by the keyboard or a click takes the
    /// guard again before anything starts.
    #[test]
    fn in_a_zones_window_enter_starts_only_where_it_asks() {
        let req = parse_request(&format!(
            "{REQUEST}guard\t1500\npins\t0\nasker\tnl\nprogram\t/nix/store/x/bin/firefox\n\
             cmd\tfirefox\ncmd\thttps://a\n"
        ));
        assert_eq!(req.asker.as_deref(), Some("nl"));
        assert_eq!(req.command, ["firefox", "https://a"]);
        let mut w = Window::new(req);
        arm(&mut w);
        assert_eq!(w.net_tag(), "nl");
        press(&mut w, Key::Character("1".into()));
        assert_eq!(w.net_tag(), "nl", "a digit chose a network");
        // Up to another network: the guard again, and Enter does not start.
        press(&mut w, Key::Named(key::Named::ArrowUp));
        assert_eq!(w.net_tag(), "offline");
        assert!(!w.armed);
        arm(&mut w);
        assert!(!w.enter_starts());
        // A click on another row: the guard again as well.
        let _ = w.update(Msg::Net(0));
        assert!(!w.armed && w.net_tag() == "unconfined");
        arm(&mut w);
        assert!(w.ready(), "the button that names it starts");
        let _ = w.update(Msg::Net(2));
        arm(&mut w);
        assert!(w.enter_starts());
    }

    #[test]
    fn a_new_container_needs_a_name_before_anything_starts() {
        let mut w = Window::new(parse_request(REQUEST));
        w.pane = Pane::Container;
        w.pick(3);
        assert!(w.naming() && !w.ready());
        w.name = "  общая  ".to_owned();
        assert!(w.ready());
        assert!(w.answer().contains("container\t__newsb__\nname\tобщая\n"));
    }
}
