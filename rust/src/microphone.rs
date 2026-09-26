//! The microphone by permission (owner, 2026-09-25): a program in a zone
//! records only as the zone's setting says — `yes`, `no`, or `ask`, the
//! default: the first time a program of the zone records, the person on the
//! host is asked, as a phone asks — allow once, allow always, deny.
//!
//! **By container** (owner, 2026-09-26; `docs/PERMISSIONS.md` §11.10): a
//! program of a container records as the container's own setting says
//! (`microphone =` in its settings), and the zone's is only what a container
//! with none gets. Which word wins: Nix's for the container, Nix's for the
//! zone, the container's local one, the zone's marker, `ask` — a local word
//! never overrides a declared one. The filter knows the container by the
//! launch the program descends from (`crate::origin`); a program whose
//! container is not known gets the zone's word, but `yes` is `ask` for it,
//! and it is never offered "always". "Always" is the container's: `yes` in
//! its settings. For the zone's own programs, everything below is as it was.
//!
//! **Where it is decided.** In the sound filter (`crate::pulse_filter`), one
//! process per zone on the host, when a program asks for a record stream: the
//! setting is read then, so a change applies at once, without restarting the
//! zone. For `ask` the filter holds that one request — the connection's other
//! commands go on — until the answer, and then passes it or answers it
//! `ERROR`/`ACCESS`. The zone in the question is the filter's own, the one it
//! was started for; nothing a program says names it. The program's name in
//! the question is its own word (its properties) and is shown as that,
//! cleaned (`shown_program`).
//!
//! **Where the setting lives** is out of the zone's own file system, so that a
//! program cannot answer its own question: the zone's marker in its state
//! directory (`~/.local/state/vpn-zones/<zone>/microphone`, hidden from zones
//! — LEAK-MODEL §17), and `declared/microphone` below `~/.config/vpn-zones`
//! (Nix, `programs.cellward.microphone`; read-only in zones). The filter
//! that reads and writes them runs in the host's user namespace
//! (`zone::Helpers`), and so does the kdialog it asks with: a program of the
//! zone cannot reach the host's file system through their `/proc/<pid>/root`.
//! What this does NOT hold: a zone that is not hermetic keeps the host's
//! `systemd --user`, and through it runs anything on the host — a recorder,
//! or a write to the marker; and the raw `pipewire-0` of an ordinary zone
//! and of an audio manager records past it (LEAK-MODEL §20). The switch is
//! the PulseAudio path's, and a hermetic zone's restricted PipeWire's
//! (`crate::pw_context` publishes it for WirePlumber's policy, for each
//! client by its container: `yes` or not — `ask` is `no` there, nothing can
//! hold a native stream for a question yet).
//!
//! **Which wins**: Nix over the zone's marker, the marker over the default
//! (`ask`). A value that is none of the three, or a file that is there but
//! cannot be read, is `no`: nothing opens the microphone by accident. "Allow
//! always" writes `yes` into the marker — offered only where the marker
//! decides, i.e. not when Nix set the zone's value.
//!
//! **Nobody to ask** — no `WAYLAND_DISPLAY` or `DISPLAY` in the filter's
//! environment, or no answer within [`TIMEOUT`] — is a refusal, said on the
//! filter's stderr (the zone's unit journal) and in `vpn-zone journal`. One
//! question at a time per zone: a request while one is open is refused, not
//! queued — a stream of questions is how a "yes" is got by accident (the
//! broker's rule). A person's "deny" stands for that connection: the
//! program's retries on it are refused without asking again; and for a
//! pause (`vpn-zone ask-again`, [`AFTER_DENY`] unless set) no program of the
//! zone is asked at all, so that one that
//! reconnects after every refusal cannot keep a dialog waiting for a stray
//! Enter. "Always" is the ZONE's — the container's, for a program of one:
//! the button and the text say so, since the program's name in the question
//! is only its own word.
//!
//! Monitors (what the host plays) are not a microphone, and never recordable
//! whatever this says (`pulse_filter::record_refused`, the server's word).

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::cli::DECLARED_DIR;
use crate::container::Source;
use crate::origin::Who;

/// The zone's marker, in its state directory: `yes`, `no` or `ask`.
pub const MARKER: &str = "microphone";
/// The values Nix declared, below `declared/`: `<zone> <value>` per line.
pub const DECLARED: &str = "microphone";
/// How long a question waits for its answer. Under libpulse's own wait for a
/// reply (`DEFAULT_TIMEOUT`, 30 s): past that the program has failed the
/// stream and stopped waiting, and a late "yes" would open the microphone
/// for a request nobody waits on — the server capturing, the sound going to
/// a socket whose program has moved on.
pub const TIMEOUT: Duration = Duration::from_secs(25);
/// An allowing answer sooner than this is a key meant for something else
/// (`dialog::TOO_FAST`).
pub const TOO_FAST: Duration = crate::dialog::TOO_FAST;

/// After a refusal of the person's — or a question nobody answered — the
/// zone is not asked again for this long: its requests are refused without
/// a dialog.
pub const AFTER_DENY: Duration = Duration::from_secs(crate::grants::ASK_AGAIN_DEFAULT);
/// At most one line in `vpn-zone journal` per this long for refusals nobody
/// was asked about: a program asking in a loop must not wash the journal's
/// history out (it rotates at a megabyte). stderr gets every one.
const QUIET: Duration = Duration::from_secs(10);

/// A zone's microphone setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setting {
    Yes,
    No,
    Ask,
}

impl Setting {
    /// One of the three words; anything else is `None`.
    pub fn parse(word: &str) -> Option<Self> {
        match word.trim() {
            "yes" => Some(Self::Yes),
            "no" => Some(Self::No),
            "ask" => Some(Self::Ask),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::Ask => "ask",
        }
    }
}

/// The zone's setting and where it comes from.
pub fn setting(zone_dir: &Path, config: &Path, zone: &str) -> (Setting, Source) {
    zone_switch(Some(zone_dir), config, zone, MARKER, DECLARED)
}

/// A container's own `yes|no|ask` switch `key` (`microphone =`,
/// `screencast =` in its declaration or its local settings) and where it
/// comes from; `None` without one. A word that is none of the three, or a
/// file that is there and cannot be read, is `no`.
pub fn container_switch(config: &Path, name: &str, key: &str) -> Option<(Setting, Source)> {
    match crate::container::own_value_in(config, name, key) {
        Ok(own) => own.map(|(word, source)| (Setting::parse(&word).unwrap_or(Setting::No), source)),
        Err(source) => Some((Setting::No, source)),
    }
}

/// A container's own microphone setting ([`container_switch`]).
pub fn container_setting(config: &Path, name: &str) -> Option<(Setting, Source)> {
    container_switch(config, name, "microphone")
}

/// A switch for a program of `who`, the zone's being `zone_setting`, and
/// where it comes from (`docs/PERMISSIONS.md` §11.10) — the microphone's and
/// the screen cast's rule. For a container: Nix's word for the container,
/// then Nix's for the zone — a local setting never overrides a declared one
/// —, then the container's own local one (`key` in its settings), then the
/// zone's local one, then `ask`. For the zone's own programs, the zone's.
/// For one whose container is not known, the zone's — but never `yes`: a
/// program that left its container's launch must not get the zone's "yes"
/// that its container may have been refused; it is asked.
pub fn by_container(
    zone_setting: (Setting, Source),
    config: &Path,
    key: &str,
    who: &Who,
) -> (Setting, Source) {
    match who {
        Who::Main => zone_setting,
        Who::Unknown => match zone_setting {
            (Setting::Yes, source) => (Setting::Ask, source),
            other => other,
        },
        Who::Container(name) => match container_switch(config, name, key) {
            Some(own @ (_, Source::Nix)) => own,
            _ if zone_setting.1 == Source::Nix => zone_setting,
            Some(own) => own,
            None => zone_setting,
        },
    }
}

/// The microphone for a program of `who` in `zone` ([`by_container`]).
pub fn setting_for(zone_dir: &Path, config: &Path, zone: &str, who: &Who) -> (Setting, Source) {
    by_container(setting(zone_dir, config, zone), config, "microphone", who)
}

/// A zone's `yes|no|ask` switch by the microphone's rules — the screen
/// cast's too (`crate::screencast`): the zone's `marker` in its state
/// directory, `declared/<declared>` (`<zone> <value>` per line) over it, `ask`
/// without either; a value that is none of the three, or a file that is there
/// and cannot be read, is `no`. No `zone_dir`: it could not be reached, which
/// is a marker that cannot be read.
pub fn zone_switch(
    zone_dir: Option<&Path>,
    config: &Path,
    zone: &str,
    marker: &str,
    declared: &str,
) -> (Setting, Source) {
    match std::fs::read_to_string(config.join(DECLARED_DIR).join(declared)) {
        Ok(text) => {
            let declared = text.lines().find_map(|line| {
                let (name, value) = line.trim().split_once(char::is_whitespace)?;
                (name == zone).then(|| Setting::parse(value).unwrap_or(Setting::No))
            });
            if let Some(value) = declared {
                return (value, Source::Nix);
            }
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        // Nix may have said "no" for this zone in a file that cannot be read.
        Err(_) => return (Setting::No, Source::Nix),
    }
    let Some(zone_dir) = zone_dir else {
        return (Setting::No, Source::Local);
    };
    match std::fs::read_to_string(zone_dir.join(marker)) {
        Ok(text) if text.trim().is_empty() => (Setting::Ask, Source::Default),
        Ok(text) => (Setting::parse(&text).unwrap_or(Setting::No), Source::Local),
        Err(e) if e.kind() == ErrorKind::NotFound => (Setting::Ask, Source::Default),
        Err(_) => (Setting::No, Source::Local),
    }
}

/// How strict a setting is: `no` over `ask` over `yes`.
fn strictness(setting: Setting) -> u8 {
    match setting {
        Setting::Yes => 0,
        Setting::Ask => 1,
        Setting::No => 2,
    }
}

/// The strictest setting among the programs of `zone` now: the zone's own
/// programs' (always there to be), and that of every container whose
/// programs may be in the zone (`origin::containers_in`: a live launch, or
/// one since the zone came up — a daemon outlives its launch). A throwaway
/// container has no setting of its own: the zone's is its. For a path that
/// decides for the whole zone at once — the restricted PipeWire
/// (`crate::pw_context`) — until it knows its clients' containers: a
/// container's "no" is not passed there by its zone's "yes" either.
pub fn strictest_running(zone_dir: &Path, config: &Path, profiles: &Path, zone: &str) -> Setting {
    let mut strictest = setting(zone_dir, config, zone).0;
    let Some(state) = zone_dir.parent() else {
        return Setting::No;
    };
    let places = crate::origin::Places {
        state,
        config,
        profiles,
    };
    for name in crate::origin::containers_in(places, zone) {
        let own = setting_for(zone_dir, config, zone, &Who::Container(name)).0;
        if strictness(own) > strictness(strictest) {
            strictest = own;
        }
    }
    strictest
}

/// What becomes of a record stream, by the setting alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Refuse(String),
    /// The person is asked; `remember` — "allow always" may be offered.
    Ask {
        remember: bool,
    },
}

/// The verdict for a setting from `source`, with or without a graphical
/// session to ask on.
pub fn verdict(setting: Setting, source: Source, display: bool) -> Verdict {
    match setting {
        Setting::Yes => Verdict::Allow,
        Setting::No => Verdict::Refuse(match source {
            Source::Nix => "микрофон запрещён (задано в Nix)".to_owned(),
            _ => "микрофон запрещён".to_owned(),
        }),
        Setting::Ask if !display => {
            Verdict::Refuse("спросить некого (нет графической сессии)".to_owned())
        }
        Setting::Ask => Verdict::Ask {
            remember: source != Source::Nix,
        },
    }
}

/// The person's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// This one stream.
    Once,
    /// This stream, and `yes` — in the container's settings, or the zone's
    /// marker for the zone's own programs.
    Always,
    /// Refused, and why.
    Deny(String),
}

/// The answer from kdialog's exit code: `choices` is whether "always" was
/// among the buttons (yes, no, cancel = once, always, deny) or not (yes, no
/// = once, deny). No code — not started, killed, the deadline — and a code
/// no button gives are a refusal.
pub fn answer_of(code: Option<i32>, remember: bool) -> Answer {
    match (code, remember) {
        (Some(0), _) => Answer::Once,
        (Some(1), true) => Answer::Always,
        (Some(1), false) | (Some(2), true) => Answer::Deny("человек отказал".to_owned()),
        (None, _) => Answer::Deny(format!(
            "нет ответа за {} с (или диалог не открылся)",
            TIMEOUT.as_secs()
        )),
        (Some(_), _) => Answer::Deny("диалог закрылся без ответа".to_owned()),
    }
}

/// `answer`, given `after` the question was put: one that allows sooner
/// than `too_fast` is a refusal (see [`TOO_FAST`]).
pub fn considered(answer: Answer, after: Duration, too_fast: Duration) -> Answer {
    match answer {
        Answer::Once | Answer::Always if after < too_fast => Answer::Deny(format!(
            "ответ через {} мс — быстрее, чем читают вопрос: принят за случайное нажатие",
            after.as_millis()
        )),
        other => other,
    }
}

/// How much of a program's name a question shows.
const SHOWN_NAME: usize = 80;

/// A program's name as it may be shown in a question: its own word, so no
/// control characters, markup or reordering marks (`broker::shown_word`),
/// not endless, and never empty.
pub fn shown_program(name: &str) -> String {
    let clean = crate::broker::shown_word(name);
    let clean = clean.trim();
    if clean.is_empty() {
        return "без имени".to_owned();
    }
    if clean.chars().count() > SHOWN_NAME {
        let head: String = clean.chars().take(SHOWN_NAME).collect();
        return format!("{head}…");
    }
    clean.to_owned()
}

/// A container's name as a question shows it: the person's own word, but
/// shown the way a program's is, with no markup to render.
fn shown_container(name: &str) -> String {
    crate::broker::shown_word(name)
}

/// The question's text. The zone is the filter's, the container the one the
/// program's launch was for (`crate::origin`); the program is named as it
/// names itself, and said to be that. `remember`: "always" is offered — and
/// said to be the whole container's (or zone's), not the named program's.
pub fn question(zone: &str, who: &Who, program: &str, remember: bool) -> String {
    let from = match who {
        Who::Main => format!("Программа из зоны «{zone}» (без контейнера)"),
        Who::Container(name) => format!(
            "Программа из контейнера «{}» (зона «{zone}»)",
            shown_container(name)
        ),
        Who::Unknown => format!("Программа из зоны «{zone}» (её контейнер не известен)"),
    };
    let always = match (remember, who) {
        (false, _) | (true, Who::Unknown) => String::new(),
        (true, Who::Container(name)) => {
            let name = shown_container(name);
            format!(
                "«{}» — это любой программе контейнера «{name}», без вопросов, пока это \
                 не отменить (cellward container set {name} microphone ask).\n\n",
                always_label(zone, who),
            )
        }
        (true, Who::Main) => format!(
            "«{}» — это любой программе зоны «{zone}», кроме контейнеров со своей \
             настройкой, без вопросов, пока это не отменить (cellward microphone {zone} \
             ask).\n\n",
            always_label(zone, who)
        ),
    };
    format!(
        "{from} хочет записывать звук с микрофона.\n\n\
         Она называет себя: «{}» — это её собственные слова.\n\n{always}Разрешить?",
        shown_program(program)
    )
}

/// The "always" button: whose it is, in its own words.
pub fn always_label(zone: &str, who: &Who) -> String {
    match who {
        Who::Container(name) => format!("Всегда — контейнеру «{}»", shown_container(name)),
        _ => format!("Всегда — всей зоне «{zone}»"),
    }
}

/// Where the filter reads and writes the settings.
#[derive(Debug)]
struct Files {
    /// The zone's state directory: its marker.
    zone_dir: PathBuf,
    /// `~/.config/vpn-zones`: Nix's words, the containers' settings.
    config: PathBuf,
    /// `~/.local/state/vpn-profiles`: whether a container is still one.
    profiles: PathBuf,
}

/// What the filter of one zone knows to decide by. One per filter process,
/// i.e. per zone: its question lock is the zone's, whichever container
/// asks — one dialog at a time on the screen.
#[derive(Debug)]
pub struct Policy {
    zone: String,
    /// Where the settings are read. `None` for a fixed setting (tests).
    files: Option<Files>,
    fixed: Setting,
    kdialog: PathBuf,
    /// A graphical session to ask on, from the filter's environment.
    display: bool,
    timeout: Duration,
    /// An allowing answer sooner than this is a refusal ([`TOO_FAST`]).
    too_fast: Duration,
    /// Where `vpn-zone journal` lives; `None` to write none.
    journal: Option<PathBuf>,
    /// A question is open for this zone.
    asking: AtomicBool,
    /// No question before then: the person refused, or did not answer.
    quiet_until: Mutex<Option<Instant>>,
    /// The pause after a refusal; `None` — as the setting says at the time
    /// (`crate::grants::ask_again`).
    after_deny: Option<Duration>,
    /// The last journal line for a refusal nobody was asked about.
    last_told: Mutex<Option<Instant>>,
}

impl Default for Policy {
    /// No zone behind it: never records.
    fn default() -> Self {
        Self::fixed(Setting::No, false)
    }
}

impl Policy {
    /// The filter of the zone `zone`, its state in `zone_dir`.
    pub fn new(
        zone: &str,
        zone_dir: PathBuf,
        config: PathBuf,
        profiles: PathBuf,
        kdialog: PathBuf,
    ) -> Self {
        let journal = zone_dir.parent().map(Path::to_path_buf);
        Self {
            zone: zone.to_owned(),
            files: Some(Files {
                zone_dir,
                config,
                profiles,
            }),
            fixed: Setting::No,
            kdialog,
            display: crate::launch::has_display(),
            timeout: TIMEOUT,
            too_fast: TOO_FAST,
            journal,
            asking: AtomicBool::new(false),
            quiet_until: Mutex::new(None),
            after_deny: None,
            last_told: Mutex::new(None),
        }
    }

    /// A setting that does not come from files.
    pub fn fixed(setting: Setting, display: bool) -> Self {
        Self {
            zone: String::new(),
            files: None,
            fixed: setting,
            kdialog: PathBuf::from("/nonexistent/kdialog"),
            display,
            timeout: TIMEOUT,
            too_fast: TOO_FAST,
            journal: None,
            asking: AtomicBool::new(false),
            quiet_until: Mutex::new(None),
            after_deny: Some(AFTER_DENY),
            last_told: Mutex::new(None),
        }
    }

    pub fn zone(&self) -> &str {
        &self.zone
    }

    pub fn has_display(&self) -> bool {
        self.display
    }

    /// The setting for a program of `who` now, and where it comes from
    /// ([`setting_for`]).
    pub fn setting(&self, who: &Who) -> (Setting, Source) {
        match &self.files {
            Some(f) => setting_for(&f.zone_dir, &f.config, &self.zone, who),
            None => (self.fixed, Source::Default),
        }
    }

    /// What becomes of a record stream of `program`, a program of `who`,
    /// now. A question it calls for is this zone's one open question:
    /// [`Policy::ask`] must follow, which closes it. No "always" for a
    /// program whose container is not known: there is nowhere its answer
    /// would belong.
    pub fn decide(&self, program: &str, who: &Who) -> Verdict {
        let (setting, source) = self.setting(who);
        let verdict = match verdict(setting, source, self.display) {
            Verdict::Ask { remember } => Verdict::Ask {
                remember: remember && *who != Who::Unknown,
            },
            other => other,
        };
        match &verdict {
            Verdict::Refuse(why) if setting == Setting::Ask => {
                self.tell(program, who, false, why, false)
            }
            Verdict::Ask { .. } if self.quiet() => {
                let why = format!(
                    "человек недавно отказал — зону спросят снова через {}",
                    self.quiet_left()
                );
                self.tell(program, who, false, &why, false);
                return Verdict::Refuse(why);
            }
            // The zone's one question: taken here, closed by `ask`.
            Verdict::Ask { .. }
                if self
                    .asking
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .is_err() =>
            {
                let why = "уже открыт вопрос о микрофоне этой зоны".to_owned();
                self.tell(program, who, false, &why, false);
                return Verdict::Refuse(why);
            }
            _ => {}
        }
        verdict
    }

    /// The pause after a refusal, as it is set now.
    fn pause(&self) -> Duration {
        match (&self.after_deny, &self.files) {
            (Some(fixed), _) => *fixed,
            (None, Some(f)) => Duration::from_secs(crate::grants::ask_again(&f.config).0),
            (None, None) => AFTER_DENY,
        }
    }

    /// What is left of the quiet, for a person: `2 мин`, `40 с`.
    fn quiet_left(&self) -> String {
        let until = *self.quiet_until.lock().unwrap_or_else(|e| e.into_inner());
        let left = until.map_or(0, |u| {
            let d = u.saturating_duration_since(Instant::now());
            d.as_secs() + u64::from(d.subsec_nanos() > 0)
        });
        if left >= 60 {
            format!("{} мин", left.div_ceil(60))
        } else {
            format!("{left} с")
        }
    }

    /// Within the quiet after a refusal.
    fn quiet(&self) -> bool {
        let until = self.quiet_until.lock().unwrap_or_else(|e| e.into_inner());
        until.is_some_and(|t| Instant::now() < t)
    }

    /// Ask the person, and settle it: "always" is written, every answer
    /// told. `then` gets whether the stream may go on, and its result is
    /// returned; it runs BEFORE the zone's question is open again, so that
    /// what the answer means for the connection (a deny standing for it) is
    /// in place before the next request of that connection can ask. Closes
    /// the open question.
    pub fn ask<R>(
        &self,
        program: &str,
        who: &Who,
        remember: bool,
        then: impl FnOnce(bool) -> R,
    ) -> R {
        struct Close<'a>(&'a AtomicBool);
        impl Drop for Close<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let _close = Close(&self.asking);
        let remember = remember && *who != Who::Unknown;
        let text = question(&self.zone, who, program, remember);
        let title = match who {
            Who::Container(name) => format!("Микрофон — контейнер «{}»", shown_container(name)),
            _ => format!("Микрофон — зона «{}»", self.zone),
        };
        let always = always_label(&self.zone, who);
        let asked = Instant::now();
        let code = if remember {
            crate::dialog::choose_within(
                &self.kdialog,
                [
                    "--title",
                    title.as_str(),
                    "--yes-label",
                    "Разрешить один раз",
                    "--no-label",
                    always.as_str(),
                    "--cancel-label",
                    "Отказать",
                    "--warningyesnocancel",
                    text.as_str(),
                ],
                Some(self.timeout),
            )
        } else {
            crate::dialog::choose_within(
                &self.kdialog,
                [
                    "--title",
                    title.as_str(),
                    "--yes-label",
                    "Разрешить один раз",
                    "--no-label",
                    "Отказать",
                    "--warningyesno",
                    text.as_str(),
                ],
                Some(self.timeout),
            )
        };
        let answer = considered(answer_of(code, remember), asked.elapsed(), self.too_fast);
        let allowed = self.settle(program, who, &answer);
        then(allowed)
    }

    /// Close the open question without asking (it could not be asked).
    pub fn abandon(&self) {
        self.asking.store(false, Ordering::SeqCst);
    }

    /// What an answer does: "always" writes `yes` — and if that cannot be
    /// written, this stream still goes on, as "once" (the person said yes).
    fn settle(&self, program: &str, who: &Who, answer: &Answer) -> bool {
        match answer {
            Answer::Once => {
                self.tell(program, who, true, "человек разрешил один раз", true);
                true
            }
            Answer::Always => {
                match self.remember(who) {
                    Ok(()) => self.tell(program, who, true, "человек разрешил всегда", true),
                    Err(e) => self.tell(
                        program,
                        who,
                        true,
                        &format!("человек разрешил всегда, но это не записано ({e}) — один раз"),
                        true,
                    ),
                }
                true
            }
            Answer::Deny(why) => {
                *self.quiet_until.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(Instant::now() + self.pause());
                self.tell(program, who, false, why, true);
                false
            }
        }
    }

    /// `yes` where the answer belongs: the container's local settings, the
    /// zone's marker for the zone's own programs. Not into a container that
    /// was removed while the question was open: that would bring it back as
    /// a policy with nothing else.
    fn remember(&self, who: &Who) -> Result<(), String> {
        let Some(f) = &self.files else {
            return Ok(());
        };
        match who {
            Who::Main => std::fs::write(f.zone_dir.join(MARKER), "yes").map_err(|e| e.to_string()),
            Who::Container(name) => {
                // Under the lock `container rm` removes under: an answer that
                // comes while its container is being removed does not bring
                // it back as a policy with nothing else.
                let _lock = crate::registry::lock(&f.config.join(crate::container::POLICY_DIR))
                    .map_err(|e| e.to_string())?;
                if !crate::container::exists_in(&f.config, &f.profiles, name) {
                    return Err(format!("контейнера {name} больше нет"));
                }
                crate::container::write_key(
                    &crate::container::policy_dir_in(&f.config, name).join(crate::container::FILE),
                    "microphone",
                    Some(Setting::Yes.as_str()),
                    true,
                )
            }
            Who::Unknown => Err("контейнер не известен".to_owned()),
        }
    }

    /// A decision about the microphone on stderr and in `vpn-zone journal`:
    /// whether it was allowed, for whom, and why. `asked`: the person was —
    /// those lines come at a person's pace; the others at most one per
    /// [`QUIET`].
    fn tell(&self, program: &str, who: &Who, allowed: bool, why: &str, asked: bool) {
        let program = shown_program(program);
        let decision = if allowed { "allowed" } else { "refused" };
        // The journal's word for whose: the container's name, "" for none,
        // "?" for not known (the broker's `zone/?`).
        let container = match who {
            Who::Main => String::new(),
            Who::Container(name) => name.clone(),
            Who::Unknown => "?".to_owned(),
        };
        let whose = match who {
            Who::Main => String::new(),
            _ => format!(", container {container}"),
        };
        eprintln!(
            "pulse-filter: zone {}{whose}: microphone for «{program}» {decision}: {why}",
            self.zone
        );
        let Some(state) = &self.journal else {
            return;
        };
        if !asked {
            let mut last = self.last_told.lock().unwrap_or_else(|e| e.into_inner());
            if last.is_some_and(|t| t.elapsed() < QUIET) {
                return;
            }
            *last = Some(Instant::now());
        }
        if let Err(e) = crate::journal::append(
            state,
            "microphone",
            &[
                ("zone", self.zone.as_str()),
                ("container", container.as_str()),
                ("program", program.as_str()),
                ("decision", decision),
                ("why", why),
            ],
        ) {
            eprintln!("pulse-filter: journal: {e}");
        }
    }
}

#[cfg(test)]
impl Policy {
    /// A zone's policy in `dir` with a kdialog, a display and a deadline of
    /// the test's choosing.
    pub(crate) fn for_test(
        zone_dir: PathBuf,
        config: PathBuf,
        profiles: PathBuf,
        kdialog: PathBuf,
        display: bool,
        timeout: Duration,
    ) -> Self {
        Self {
            display,
            timeout,
            // The test's kdialog answers at once.
            too_fast: Duration::ZERO,
            ..Self::new("nl", zone_dir, config, profiles, kdialog)
        }
    }

    /// With the real guard against a stray key.
    pub(crate) fn with_too_fast(mut self, too_fast: Duration) -> Self {
        self.too_fast = too_fast;
        self
    }

    /// The quiet after a refusal, shortened (or none).
    pub(crate) fn with_after_deny(mut self, after_deny: Duration) -> Self {
        self.after_deny = Some(after_deny);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dirs {
        base: PathBuf,
    }

    impl Dirs {
        fn new(tag: &str) -> Self {
            let base =
                std::env::temp_dir().join(format!("vpn-zone-mic-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(base.join("state/nl")).unwrap();
            std::fs::create_dir_all(base.join("config/declared/containers")).unwrap();
            std::fs::create_dir_all(base.join("profiles")).unwrap();
            Self { base }
        }
        fn zone(&self) -> PathBuf {
            self.base.join("state/nl")
        }
        fn config(&self) -> PathBuf {
            self.base.join("config")
        }
        fn write(&self, path: &str, text: &str) {
            std::fs::write(self.base.join(path), text).unwrap();
        }
        fn setting(&self) -> (Setting, Source) {
            setting(&self.zone(), &self.config(), "nl")
        }
        /// A kdialog that answers with `script` (a shell body).
        fn kdialog(&self, name: &str, script: &str) -> PathBuf {
            let path = self.base.join(name);
            crate::dialog::test_program(&path, &format!("#!/bin/sh\n{script}\n"));
            path
        }
        fn policy(&self, kdialog: PathBuf, display: bool, timeout: Duration) -> Policy {
            Policy::for_test(
                self.zone(),
                self.config(),
                self.base.join("profiles"),
                kdialog,
                display,
                timeout,
            )
        }
        fn journal(&self) -> String {
            std::fs::read_to_string(self.base.join("state").join(crate::journal::FILE))
                .unwrap_or_default()
        }
    }

    impl Drop for Dirs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    /// Ask by default; the zone's marker over it; Nix over both; anything
    /// that is not one of the three words is no.
    #[test]
    fn nix_wins_over_the_marker_and_the_marker_over_ask() {
        let d = Dirs::new("precedence");
        assert_eq!(d.setting(), (Setting::Ask, Source::Default));
        d.write("state/nl/microphone", "");
        assert_eq!(d.setting(), (Setting::Ask, Source::Default));
        d.write("state/nl/microphone", "yes\n");
        assert_eq!(d.setting(), (Setting::Yes, Source::Local));
        d.write("state/nl/microphone", "no");
        assert_eq!(d.setting(), (Setting::No, Source::Local));
        d.write("state/nl/microphone", "ask");
        assert_eq!(d.setting(), (Setting::Ask, Source::Local));
        d.write("state/nl/microphone", "on");
        assert_eq!(d.setting(), (Setting::No, Source::Local));
        // Another zone's line is not this zone's.
        d.write("config/declared/microphone", "de yes\nnlx yes\n");
        assert_eq!(d.setting(), (Setting::No, Source::Local));
        d.write("state/nl/microphone", "yes");
        d.write("config/declared/microphone", "de yes\nnl no\n");
        assert_eq!(d.setting(), (Setting::No, Source::Nix));
        d.write("config/declared/microphone", "nl ask\n");
        assert_eq!(d.setting(), (Setting::Ask, Source::Nix));
        d.write("config/declared/microphone", "nl maybe\n");
        assert_eq!(d.setting(), (Setting::No, Source::Nix));
        // A declared file that is there and cannot be read: no.
        std::fs::remove_file(d.config().join("declared/microphone")).unwrap();
        std::fs::create_dir(d.config().join("declared/microphone")).unwrap();
        assert_eq!(d.setting(), (Setting::No, Source::Nix));
    }

    #[test]
    fn ask_without_a_display_is_a_refusal_and_always_only_where_the_marker_decides() {
        assert_eq!(verdict(Setting::Yes, Source::Local, false), Verdict::Allow);
        assert!(matches!(
            verdict(Setting::No, Source::Default, true),
            Verdict::Refuse(_)
        ));
        let Verdict::Refuse(why) = verdict(Setting::Ask, Source::Default, false) else {
            panic!("asked with nobody to ask");
        };
        assert!(why.contains("графической"), "{why}");
        assert_eq!(
            verdict(Setting::Ask, Source::Local, true),
            Verdict::Ask { remember: true }
        );
        assert_eq!(
            verdict(Setting::Ask, Source::Nix, true),
            Verdict::Ask { remember: false }
        );
    }

    #[test]
    fn the_buttons_mean_once_always_deny() {
        assert_eq!(answer_of(Some(0), true), Answer::Once);
        assert_eq!(answer_of(Some(1), true), Answer::Always);
        assert!(matches!(answer_of(Some(2), true), Answer::Deny(_)));
        assert_eq!(answer_of(Some(0), false), Answer::Once);
        assert!(matches!(answer_of(Some(1), false), Answer::Deny(_)));
        // No "always" where it was not offered, whatever the code.
        assert!(matches!(answer_of(Some(2), false), Answer::Deny(_)));
        assert!(matches!(answer_of(None, true), Answer::Deny(_)));
        assert!(matches!(answer_of(Some(255), true), Answer::Deny(_)));
    }

    /// The program's name is its own word: shown clean, bounded, never empty.
    #[test]
    fn a_programs_name_is_shown_clean() {
        assert_eq!(shown_program("Firefox"), "Firefox");
        assert_eq!(
            shown_program("<b>Системный</b>\nмикрофон\u{202E}"),
            "‹b›Системный‹/b› микрофон"
        );
        assert_eq!(shown_program(" \u{200B}"), "без имени");
        let long = shown_program(&"a".repeat(500));
        assert_eq!(long.chars().count(), SHOWN_NAME + 1);
        let q = question("nl", &Who::Main, "zoom\n\nЗона: host", true);
        assert!(q.contains("зоны «nl»"), "{q}");
        assert!(
            q.contains("«zoom  Зона: host» — это её собственные слова"),
            "{q}"
        );
        // "Always" is the zone's, and the text says so where it is offered.
        assert!(
            q.contains(
                "«Всегда — всей зоне «nl»» — это любой программе зоны «nl», кроме контейнеров"
            ),
            "{q}"
        );
        let q = question("nl", &Who::Main, "zoom", false);
        assert!(!q.contains("Всегда"), "{q}");
    }

    #[test]
    fn once_always_and_deny_as_the_person_answers() {
        let d = Dirs::new("answers");
        let marker = d.zone().join(MARKER);
        // Once: this stream, nothing written.
        let p = d.policy(d.kdialog("once", "exit 0"), true, TIMEOUT);
        assert_eq!(p.decide("app", &Who::Main), Verdict::Ask { remember: true });
        assert!(p.ask("app", &Who::Main, true, |a| a));
        assert!(!marker.exists());
        // Deny.
        let p = d.policy(d.kdialog("deny", "exit 2"), true, TIMEOUT);
        assert_eq!(p.decide("app", &Who::Main), Verdict::Ask { remember: true });
        assert!(!p.ask("app", &Who::Main, true, |a| a));
        assert!(!marker.exists());
        // Always: yes in the marker, and the next stream is not asked about.
        let p = d.policy(d.kdialog("always", "exit 1"), true, TIMEOUT);
        assert_eq!(p.decide("app", &Who::Main), Verdict::Ask { remember: true });
        assert!(p.ask("app", &Who::Main, true, |a| a));
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "yes");
        assert_eq!(p.decide("app", &Who::Main), Verdict::Allow);
        // Nix says ask: "always" is not offered, and its button is a no.
        std::fs::remove_file(&marker).unwrap();
        d.write("config/declared/microphone", "nl ask\n");
        let p = d.policy(d.kdialog("two", "exit 1"), true, TIMEOUT);
        assert_eq!(
            p.decide("app", &Who::Main),
            Verdict::Ask { remember: false }
        );
        assert!(!p.ask("app", &Who::Main, false, |a| a));
        assert!(!marker.exists());
        let journal = d.journal();
        assert_eq!(journal.matches("\"event\":\"microphone\"").count(), 4);
        assert!(journal.contains("\"decision\":\"refused\",\"why\":\"человек отказал\""));
    }

    /// No answer in time: refused, and the dialog is gone.
    #[test]
    fn no_answer_in_time_is_a_refusal() {
        let d = Dirs::new("timeout");
        let pidfile = d.base.join("kdialog.pid");
        let kdialog = d.kdialog(
            "slow",
            &format!("echo $$ > {}; exec sleep 30", pidfile.display()),
        );
        let p = d.policy(kdialog, true, Duration::from_secs(1));
        assert_eq!(p.decide("app", &Who::Main), Verdict::Ask { remember: true });
        let started = Instant::now();
        assert!(!p.ask("app", &Who::Main, true, |a| a));
        assert!(started.elapsed() < Duration::from_secs(10));
        let pid: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // SAFETY: signal 0 only checks that the process exists.
        assert_ne!(
            unsafe { libc::kill(pid, 0) },
            0,
            "the dialog outlived its deadline"
        );
        let said = format!("нет ответа за {} с", TIMEOUT.as_secs());
        assert!(d.journal().contains(&said), "{}", d.journal());
        // Under libpulse's own wait for the reply (30 s): an answer the
        // program no longer waits for must not open the microphone.
        assert!(TIMEOUT < Duration::from_secs(30));
        // Nobody answered: the zone is not asked again for a while either.
        assert!(
            matches!(p.decide("app", &Who::Main), Verdict::Refuse(why) if why.contains("недавно"))
        );
        // A kdialog that cannot be started is no answer either.
        let p = d.policy(d.base.join("missing"), true, TIMEOUT);
        assert_eq!(p.decide("app", &Who::Main), Verdict::Ask { remember: true });
        assert!(!p.ask("app", &Who::Main, true, |a| a));
    }

    /// After a refusal the zone is not asked for a while: a program that
    /// reconnects after every "no" cannot keep a dialog up for a stray Enter.
    #[test]
    fn a_refusal_quiets_the_zone_for_a_while() {
        let d = Dirs::new("quiet");
        let asked = d.base.join("asked");
        let kdialog = d.kdialog("deny", &format!("touch {}; exit 2", asked.display()));
        let p = d.policy(kdialog.clone(), true, TIMEOUT);
        assert_eq!(p.decide("app", &Who::Main), Verdict::Ask { remember: true });
        assert!(!p.ask("app", &Who::Main, true, |a| a));
        std::fs::remove_file(&asked).unwrap();
        let Verdict::Refuse(why) = p.decide("app", &Who::Main) else {
            panic!("asked again right after a refusal");
        };
        assert!(why.contains("недавно отказал"), "{why}");
        assert!(!asked.exists());
        // The switch itself still decides: yes lets it through at once.
        d.write("state/nl/microphone", "yes");
        assert_eq!(p.decide("app", &Who::Main), Verdict::Allow);
        std::fs::remove_file(d.zone().join(MARKER)).unwrap();
        // Once the quiet is over, the zone is asked again.
        let p = d
            .policy(kdialog, true, TIMEOUT)
            .with_after_deny(Duration::ZERO);
        assert_eq!(p.decide("app", &Who::Main), Verdict::Ask { remember: true });
        assert!(!p.ask("app", &Who::Main, true, |a| a));
        assert_eq!(p.decide("app", &Who::Main), Verdict::Ask { remember: true });
        p.abandon();
    }

    /// An "allow" sooner than a question can be read is a key meant for
    /// something else — the dialog took the focus, and its default button
    /// allows. A refusal, however soon, stays one; so does an answer given
    /// in time.
    #[test]
    fn an_allow_too_soon_is_a_stray_key() {
        let fast = Duration::from_millis(1500);
        let soon = Duration::from_millis(300);
        let late = Duration::from_secs(3);
        for answer in [Answer::Once, Answer::Always] {
            assert!(matches!(
                considered(answer.clone(), soon, fast),
                Answer::Deny(why) if why.contains("случайное нажатие")
            ));
            assert_eq!(considered(answer.clone(), late, fast), answer);
        }
        let no = Answer::Deny("человек отказал".to_owned());
        assert_eq!(considered(no.clone(), soon, fast), no);
        // Through the question: the kdialog says "once" at once, the
        // microphone stays shut, and the zone is quiet as after a refusal.
        let d = Dirs::new("stray");
        let p = d
            .policy(d.kdialog("once", "exit 0"), true, TIMEOUT)
            .with_too_fast(TOO_FAST);
        assert_eq!(p.decide("app", &Who::Main), Verdict::Ask { remember: true });
        assert!(!p.ask("app", &Who::Main, true, |a| a));
        assert!(!d.zone().join(MARKER).exists());
        assert!(d.journal().contains("случайное нажатие"), "{}", d.journal());
        assert!(matches!(p.decide("app", &Who::Main), Verdict::Refuse(_)));
        // Answered after a moment: allowed.
        let d = Dirs::new("read");
        let p = d
            .policy(d.kdialog("once", "sleep 0.3; exit 0"), true, TIMEOUT)
            .with_too_fast(Duration::from_millis(200));
        assert_eq!(p.decide("app", &Who::Main), Verdict::Ask { remember: true });
        assert!(p.ask("app", &Who::Main, true, |a| a));
    }

    /// The pause after a refusal is the setting's, Nix's first — read when
    /// the person refuses, so a change applies without a restart. A file
    /// that holds no pause within the bounds is passed over, never taken for
    /// no pause at all.
    #[test]
    fn the_pause_after_a_refusal_is_the_setting() {
        let d = Dirs::new("pause");
        let p = d.policy(d.kdialog("deny", "exit 2"), true, TIMEOUT);
        assert_eq!(p.pause(), AFTER_DENY);
        d.write("config/ask-again", "10m");
        assert_eq!(p.pause(), Duration::from_secs(600));
        d.write("config/declared/ask-again", "1h\n");
        assert_eq!(p.pause(), Duration::from_secs(3_600));
        for bad in ["5s", "0m", "2d", "", "soon"] {
            d.write("config/declared/ask-again", bad);
            assert_eq!(p.pause(), Duration::from_secs(600), "{bad:?}");
        }
        d.write("config/ask-again", "1s");
        assert_eq!(p.pause(), AFTER_DENY);
        d.write("config/ask-again", "45s");
        assert!(!p.ask("app", &Who::Main, true, |a| a));
        let Verdict::Refuse(why) = p.decide("app", &Who::Main) else {
            panic!("asked again right after a refusal");
        };
        assert!(
            why.contains("через 45 с") || why.contains("через 44 с"),
            "{why}"
        );
    }

    /// What an answer means for the connection is settled while the zone's
    /// question is still open: a request in between is refused as "a
    /// question is open", never asked about anew.
    #[test]
    fn the_answer_is_settled_before_the_question_closes() {
        let d = Dirs::new("settle");
        let p = d.policy(d.kdialog("once", "exit 0"), true, TIMEOUT);
        assert_eq!(p.decide("app", &Who::Main), Verdict::Ask { remember: true });
        let meanwhile = p.ask("app", &Who::Main, true, |allowed| {
            assert!(allowed);
            p.decide("app", &Who::Main)
        });
        assert!(
            matches!(&meanwhile, Verdict::Refuse(why) if why.contains("уже открыт")),
            "{meanwhile:?}"
        );
    }

    /// No display: refused without a dialog, said in the journal; one
    /// question at a time.
    #[test]
    fn nobody_to_ask_and_one_question_at_a_time() {
        let d = Dirs::new("nodisplay");
        let asked = d.base.join("asked");
        let kdialog = d.kdialog("mark", &format!("touch {}; exit 0", asked.display()));
        let p = d.policy(kdialog.clone(), false, TIMEOUT);
        assert!(
            matches!(p.decide("app", &Who::Main), Verdict::Refuse(why) if why.contains("графической"))
        );
        assert!(!asked.exists());
        assert!(
            d.journal().contains("нет графической сессии"),
            "{}",
            d.journal()
        );
        // A second refusal right after is on stderr only.
        assert!(matches!(p.decide("app", &Who::Main), Verdict::Refuse(_)));
        assert_eq!(d.journal().matches("\"event\":\"microphone\"").count(), 1);

        let p = d.policy(kdialog, true, TIMEOUT);
        assert_eq!(p.decide("app", &Who::Main), Verdict::Ask { remember: true });
        assert!(
            matches!(p.decide("other", &Who::Main), Verdict::Refuse(why) if why.contains("уже открыт"))
        );
        assert!(p.ask("app", &Who::Main, true, |a| a));
        assert!(asked.exists());
        // Answered: the next one may ask again.
        assert_eq!(p.decide("app", &Who::Main), Verdict::Ask { remember: true });
        assert!(p.ask("app", &Who::Main, true, |a| a));
    }

    /// A container's own setting (`docs/PERMISSIONS.md` §11.10): Nix's
    /// word for the container, then Nix's for the zone, then the
    /// container's local one, then the zone's marker. A container with
    /// none of its own is the zone's.
    #[test]
    fn a_container_has_its_own_setting_and_nix_is_never_overridden() {
        let d = Dirs::new("container");
        let work = Who::Container("work".into());
        let setting = |who: &Who| setting_for(&d.zone(), &d.config(), "nl", who);
        assert_eq!(setting(&work), (Setting::Ask, Source::Default));
        d.write("state/nl/microphone", "yes");
        assert_eq!(setting(&work), (Setting::Yes, Source::Local));
        // Its own local word over the zone's marker.
        std::fs::create_dir_all(d.config().join("containers/work")).unwrap();
        d.write("config/containers/work/container.conf", "microphone = no\n");
        assert_eq!(setting(&work), (Setting::No, Source::Local));
        assert_eq!(setting(&Who::Main), (Setting::Yes, Source::Local));
        d.write(
            "config/containers/work/container.conf",
            "microphone = maybe\n",
        );
        assert_eq!(setting(&work), (Setting::No, Source::Local));
        // Nix's word for the zone over the container's local one.
        d.write(
            "config/containers/work/container.conf",
            "microphone = yes\n",
        );
        d.write("config/declared/microphone", "nl no\n");
        assert_eq!(setting(&work), (Setting::No, Source::Nix));
        // Nix's word for the container over everything.
        d.write(
            "config/declared/containers/work.conf",
            "home = private\nmicrophone = ask\n",
        );
        assert_eq!(setting(&work), (Setting::Ask, Source::Nix));
        // An old module's file of another container is not this one's.
        d.write("config/declared/containers/work.conf", "microphone = yes\n");
        assert_eq!(setting(&work), (Setting::No, Source::Nix));
        // A settings file that cannot be read: no.
        std::fs::remove_file(d.config().join("declared/microphone")).unwrap();
        std::fs::remove_file(d.config().join("containers/work/container.conf")).unwrap();
        std::fs::create_dir(d.config().join("containers/work/container.conf")).unwrap();
        assert_eq!(setting(&work), (Setting::No, Source::Local));
    }

    /// "Always" for a program of a container is the container's: its
    /// settings get `yes`, the zone's marker nothing — and the zone's own
    /// programs are still asked.
    #[test]
    fn always_for_a_container_is_the_containers() {
        let d = Dirs::new("always-container");
        let work = Who::Container("work".into());
        std::fs::create_dir_all(d.base.join("profiles/work")).unwrap();
        let p = d.policy(d.kdialog("always", "exit 1"), true, TIMEOUT);
        assert_eq!(p.decide("app", &work), Verdict::Ask { remember: true });
        assert!(p.ask("app", &work, true, |a| a));
        let conf =
            std::fs::read_to_string(d.config().join("containers/work/container.conf")).unwrap();
        assert!(conf.contains("microphone = yes"), "{conf}");
        assert!(!d.zone().join(MARKER).exists());
        assert_eq!(p.decide("app", &work), Verdict::Allow);
        assert_eq!(p.decide("app", &Who::Main), Verdict::Ask { remember: true });
        p.abandon();
        let journal = d.journal();
        assert!(journal.contains("\"container\":\"work\""), "{journal}");
        // A container removed while its question was open is not brought
        // back by the answer.
        let gone = Who::Container("gone".into());
        assert_eq!(p.decide("app", &gone), Verdict::Ask { remember: true });
        assert!(p.ask("app", &gone, true, |a| a));
        assert!(!d.config().join("containers/gone").exists());
        assert!(d.journal().contains("не записано"), "{}", d.journal());
    }

    /// A program whose container is not known is asked even where the zone
    /// says yes, and is never offered "always".
    #[test]
    fn a_program_of_no_known_container_is_asked_and_never_for_always() {
        let d = Dirs::new("unknown");
        d.write("state/nl/microphone", "yes");
        let asked = d.base.join("asked");
        let kdialog = d.kdialog("always", &format!("touch {}; exit 1", asked.display()));
        let p = d.policy(kdialog, true, TIMEOUT);
        assert_eq!(p.decide("app", &Who::Main), Verdict::Allow);
        assert_eq!(
            p.decide("app", &Who::Unknown),
            Verdict::Ask { remember: false }
        );
        // Its "always" button is not there: exit 1 is a refusal.
        assert!(!p.ask("app", &Who::Unknown, true, |a| a));
        assert!(asked.exists());
        assert!(
            d.journal().contains("\"container\":\"?\""),
            "{}",
            d.journal()
        );
        // Nobody to ask: refused.
        let p = d.policy(d.kdialog("once", "exit 0"), false, TIMEOUT);
        assert!(matches!(p.decide("app", &Who::Unknown), Verdict::Refuse(_)));
        d.write("state/nl/microphone", "no");
        assert!(matches!(p.decide("app", &Who::Unknown), Verdict::Refuse(_)));
    }

    /// The question says whose program it is, and whose "always" is.
    #[test]
    fn the_question_names_the_container() {
        let work = Who::Container("work".into());
        let q = question("nl", &work, "zoom", true);
        assert!(
            q.starts_with("Программа из контейнера «work» (зона «nl»)"),
            "{q}"
        );
        assert!(
            q.contains("«Всегда — контейнеру «work»» — это любой программе контейнера «work»"),
            "{q}"
        );
        assert!(
            q.contains("cellward container set work microphone ask"),
            "{q}"
        );
        let q = question("nl", &Who::Unknown, "zoom", true);
        assert!(q.contains("её контейнер не известен"), "{q}");
        assert!(!q.contains("Всегда"), "{q}");
        // A container's name is shown with no markup.
        let q = question("nl", &Who::Container("<b>x</b>".into()), "zoom", false);
        assert!(q.contains("«‹b›x‹/b›»"), "{q}");
        assert_eq!(always_label("nl", &Who::Main), "Всегда — всей зоне «nl»");
    }

    /// For the whole zone at once: the zone's own setting, made stricter by
    /// every container launched into the zone since it came up.
    #[test]
    fn the_whole_zone_is_as_strict_as_its_strictest_container() {
        let d = Dirs::new("strictest");
        let strictest =
            || strictest_running(&d.zone(), &d.config(), &d.base.join("profiles"), "nl");
        d.write("state/nl/microphone", "yes");
        assert_eq!(strictest(), Setting::Yes);
        std::fs::create_dir_all(d.config().join("containers/quiet")).unwrap();
        d.write(
            "config/containers/quiet/container.conf",
            "microphone = no\n",
        );
        // Not in the zone: not counted.
        assert_eq!(strictest(), Setting::Yes);
        crate::origin::note_launched(&d.base.join("state"), "nl", "quiet").unwrap();
        assert_eq!(strictest(), Setting::No);
        // A container with none of its own is the zone's.
        crate::origin::note_launched(&d.base.join("state"), "nl", "plain").unwrap();
        d.write(
            "config/containers/quiet/container.conf",
            "microphone = yes\n",
        );
        assert_eq!(strictest(), Setting::Yes);
        d.write("state/nl/microphone", "ask");
        assert_eq!(strictest(), Setting::Ask);
    }
}
