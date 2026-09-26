//! The zone frame, drawn by the Wayland proxy (`docs/WINDOW-FRAME.md` §5,
//! stage 2): a coloured band of [`crate::frame`]'s width around every
//! toplevel of the program, in its zone's colour, and a title strip of the
//! same colour along its top with `<zone> · <container>` on it
//! (`crate::wl_title` draws the text).
//!
//! **The "trailer" scheme (§5.1).** The border is four subsurfaces of the
//! program's own root surface — top, bottom, left, right —, each one pixel
//! of the colour stretched by `wp_viewport` to its strip; the title strip is
//! a fifth, with the text a subsurface of it. The root surface does not
//! move, so nothing the program knows in surface coordinates changes:
//! pointer and touch positions, text input, pointer constraints, activation
//! are its own as before. What changes is what is relative to the WINDOW
//! GEOMETRY (§5.2), and the proxy translates exactly that — with `B` the
//! border and `T` the title strip when it takes room (mode `always`, not in
//! fullscreen; else 0):
//!
//! | the program says / is told           | the compositor is told / said        |
//! |--------------------------------------|--------------------------------------|
//! | `set_window_geometry(x, y, w, h)`    | `(x−B, y−B−T, w+2B, h+2B+T)`         |
//! | `configure(w, h)`, `configure_bounds` ← | `(w−2B, h−2B−T)`; 0 stays 0       |
//! | `set_min_size`/`set_max_size`        | non-zero `+2B`, `+2B+T`              |
//! | `show_window_menu(x, y)`             | `(x+B, y+B+T)`                       |
//! | a popup's anchor rect, parent size   | `+B`, `+B+T`; `+2B`, `+2B+T` (for the call only) |
//! | `xdg_popup.configure(x, y)` ←        | `(x−B, y−B−T)`                       |
//! | `xdg_toplevel_drag.attach(x, y)`     | `(x+B, y+B+T)`                       |
//!
//! So the frame lies INSIDE the geometry the compositor sees (§1): niri with
//! `clip-to-geometry` and sway, which clips every tiled window, show it, and
//! a compositor that sizes the window gets exactly the size it asked for —
//! the program draws in what is left. Geometry and size limits are
//! double-buffered state of the program's next commit, so the proxy keeps
//! them and sends the translated values just before that commit, together
//! with the strips' new place and size: the strips are synchronized
//! subsurfaces, and the program's commit applies all of it at once — a
//! resize never shows a frame of the old size (§5.3). A program that sets
//! no geometry has the size of its root surface for one (buffer, scale,
//! transform, viewport), and the strips go around that.
//!
//! **Fullscreen** (§5.7). The border stays (the owner's answer, §11), the
//! title strip goes, and its room with it: the configure that says
//! fullscreen is answered less the border only. Which state a commit is of
//! is the configure the program acked last — kept by serial from the
//! compositor's configure to the program's `ack_configure`, so the geometry
//! and the strip laid before a commit match the size the program drew. But
//! whether the strip SHOWS is not the program's alone: it is hidden only
//! while the compositor's latest configure says fullscreen too. A program
//! that acks the fullscreen configure and never the one that ends it is
//! shown out of fullscreen by the compositor all the same; its strip then
//! comes out at once, over the top of its content (its commits have no room
//! for it), until it acks ([`Window::title_wanted`]).
//!
//! **Hover** (§0а). In mode `hover` the strip takes no room: it lies over the
//! top of the program's content, hidden, and comes out while the pointer is
//! at the very top of the window (the top border, the first
//! [`HOVER_EDGE`] pixels of the content) or on the strip itself — seen on the
//! program's own `wl_pointer`, to which the compositor sends the pointer's
//! events over the proxy's surfaces too. Shown and hidden at once, not at the
//! program's next commit: the strip is desynchronized for its own commit and
//! synchronized again ([`TitleParts::apply_now`]); so is the text drawn anew
//! at a new scale.
//!
//! **Scale.** The strips are a single pixel stretched to a size in logical
//! pixels: at any scale, fractional included, the compositor fills whole
//! device pixels with one colour — nothing to blur, no buffer per scale, no
//! redraw on a resize, only `set_destination` and `set_position`. The text
//! is drawn at the scale the compositor prefers for it —
//! `wp_fractional_scale_v1` when it offers that to the restricted client,
//! `wl_surface.preferred_buffer_scale` when not — and given its logical size
//! by `wp_viewport`; a resize only cuts it (the viewport's source), never
//! draws it again (§6.3). The default width and the strip's height are a
//! whole number of pixels at the usual scales ([`crate::frame::DEFAULT_WIDTH`],
//! [`TITLE_HEIGHT`]). The pixel is the middle one of a 3×3 buffer of the
//! colour (`set_source(1, 1, 1, 1)`): a compositor that scales bilinearly
//! without clamping to the texture's edge — wlroots' pixman renderer does,
//! at a fractional scale — blends it with its neighbours, and a lone 1×1
//! would fade into transparency at the strip's edges; these neighbours are
//! the same colour.
//!
//! **What the program cannot do** (§10). Every object here is the proxy's
//! own: it has an id upstream only, none in the program's table, so the
//! program cannot name it — not destroy it, not attach to it, not move it,
//! not draw in it. Its own new subsurfaces would stack above the frame; each
//! time the stacking of the root's children changes, the strips and the
//! title are put back on top (§5.9). Input on them is not the program's: the
//! compositor sends it to the connection, and the filters below drop it —
//! enter, motion, buttons, axes and their frame of the pointer, touches that
//! began there, a tablet tool near it, gestures begun on it, a drag over it.
//! What decides "not the program's" is that the surface has no id in the
//! program's table: a strip, or a surface the program has already destroyed.
//! (Relative pointer motion carries no surface and passes: over a strip it
//! tells the program only that the pointer moves.)
//!
//! The frame is NOT a trust boundary (§5.9): a popup of the program can lie
//! over it, a fullscreen program draws what it likes, and in mode `hover` a
//! program can draw a strip of another zone's name where ours is hidden. It
//! is a convenience and a reminder.
//!
//! **Never worse than stage 1.** The proxy binds what it needs with a
//! registry of its own — `wl_compositor`, `wl_subcompositor`, `wl_shm`,
//! `wp_viewporter`, and `wp_fractional_scale_manager_v1` when there is one;
//! the program is shown no new global, ever. When one of the first four is
//! missing, windows go without a frame and the proxy says so once; nothing
//! about them is translated then. A window is only given a frame once the
//! proxy knows (its registry has been answered: always before the
//! compositor's first configure of a window, which comes later on the same
//! connection), and from then on for its whole life. Without a font the
//! title strip is there without its text.

#![forbid(unsafe_code)]

use std::cell::{Cell, RefCell};
use std::collections::{HashSet, VecDeque};
use std::os::fd::OwnedFd;
use std::rc::{Rc, Weak};

use wl_proxy::client::Client;
use wl_proxy::fixed::Fixed;
use wl_proxy::object::{ConcreteObject, Object, ObjectCoreApi, ObjectRcUtils, ObjectUtils};
use wl_proxy::protocols::drm::wl_drm::{WlDrm, WlDrmHandler};
use wl_proxy::protocols::fractional_scale_v1::wp_fractional_scale_manager_v1::WpFractionalScaleManagerV1;
use wl_proxy::protocols::fractional_scale_v1::wp_fractional_scale_v1::{
    WpFractionalScaleV1, WpFractionalScaleV1Handler,
};
use wl_proxy::protocols::linux_dmabuf_v1::zwp_linux_buffer_params_v1::{
    ZwpLinuxBufferParamsV1, ZwpLinuxBufferParamsV1Flags, ZwpLinuxBufferParamsV1Handler,
};
use wl_proxy::protocols::linux_dmabuf_v1::zwp_linux_dmabuf_v1::{
    ZwpLinuxDmabufV1, ZwpLinuxDmabufV1Handler,
};
use wl_proxy::protocols::pointer_gestures_unstable_v1::zwp_pointer_gesture_hold_v1::{
    ZwpPointerGestureHoldV1, ZwpPointerGestureHoldV1Handler,
};
use wl_proxy::protocols::pointer_gestures_unstable_v1::zwp_pointer_gesture_pinch_v1::{
    ZwpPointerGesturePinchV1, ZwpPointerGesturePinchV1Handler,
};
use wl_proxy::protocols::pointer_gestures_unstable_v1::zwp_pointer_gesture_swipe_v1::{
    ZwpPointerGestureSwipeV1, ZwpPointerGestureSwipeV1Handler,
};
use wl_proxy::protocols::pointer_gestures_unstable_v1::zwp_pointer_gestures_v1::{
    ZwpPointerGesturesV1, ZwpPointerGesturesV1Handler,
};
use wl_proxy::protocols::single_pixel_buffer_v1::wp_single_pixel_buffer_manager_v1::{
    WpSinglePixelBufferManagerV1, WpSinglePixelBufferManagerV1Handler,
};
use wl_proxy::protocols::tablet_v2::zwp_tablet_manager_v2::{
    ZwpTabletManagerV2, ZwpTabletManagerV2Handler,
};
use wl_proxy::protocols::tablet_v2::zwp_tablet_seat_v2::{ZwpTabletSeatV2, ZwpTabletSeatV2Handler};
use wl_proxy::protocols::tablet_v2::zwp_tablet_tool_v2::{
    ZwpTabletToolV2, ZwpTabletToolV2ButtonState, ZwpTabletToolV2Handler,
};
use wl_proxy::protocols::tablet_v2::zwp_tablet_v2::ZwpTabletV2;
use wl_proxy::protocols::viewporter::wp_viewport::{WpViewport, WpViewportHandler};
use wl_proxy::protocols::viewporter::wp_viewporter::{WpViewporter, WpViewporterHandler};
use wl_proxy::protocols::wayland::wl_buffer::{WlBuffer, WlBufferHandler};
use wl_proxy::protocols::wayland::wl_callback::{WlCallback, WlCallbackHandler};
use wl_proxy::protocols::wayland::wl_compositor::{WlCompositor, WlCompositorHandler};
use wl_proxy::protocols::wayland::wl_data_device::{WlDataDevice, WlDataDeviceHandler};
use wl_proxy::protocols::wayland::wl_data_device_manager::{
    WlDataDeviceManager, WlDataDeviceManagerHandler,
};
use wl_proxy::protocols::wayland::wl_data_offer::WlDataOffer;
use wl_proxy::protocols::wayland::wl_data_source::WlDataSource;
use wl_proxy::protocols::wayland::wl_output::WlOutputTransform;
use wl_proxy::protocols::wayland::wl_pointer::{
    WlPointer, WlPointerAxis, WlPointerAxisRelativeDirection, WlPointerAxisSource,
    WlPointerButtonState, WlPointerHandler,
};
use wl_proxy::protocols::wayland::wl_registry::{WlRegistry, WlRegistryHandler};
use wl_proxy::protocols::wayland::wl_seat::{WlSeat, WlSeatHandler};
use wl_proxy::protocols::wayland::wl_shm::{WlShm, WlShmFormat, WlShmHandler};
use wl_proxy::protocols::wayland::wl_shm_pool::{WlShmPool, WlShmPoolHandler};
use wl_proxy::protocols::wayland::wl_subcompositor::{WlSubcompositor, WlSubcompositorHandler};
use wl_proxy::protocols::wayland::wl_subsurface::{WlSubsurface, WlSubsurfaceHandler};
use wl_proxy::protocols::wayland::wl_surface::{WlSurface, WlSurfaceHandler};
use wl_proxy::protocols::wayland::wl_touch::{WlTouch, WlTouchHandler};
use wl_proxy::protocols::xdg_shell::xdg_popup::{XdgPopup, XdgPopupHandler};
use wl_proxy::protocols::xdg_shell::xdg_positioner::{XdgPositioner, XdgPositionerHandler};
use wl_proxy::protocols::xdg_shell::xdg_surface::{XdgSurface, XdgSurfaceHandler};
use wl_proxy::protocols::xdg_shell::xdg_toplevel::{XdgToplevel, XdgToplevelHandler};
use wl_proxy::protocols::xdg_shell::xdg_wm_base::{XdgWmBase, XdgWmBaseHandler};
use wl_proxy::protocols::xdg_toplevel_drag_v1::xdg_toplevel_drag_manager_v1::{
    XdgToplevelDragManagerV1, XdgToplevelDragManagerV1Handler,
};
use wl_proxy::protocols::xdg_toplevel_drag_v1::xdg_toplevel_drag_v1::{
    XdgToplevelDragV1, XdgToplevelDragV1Handler,
};
use wl_proxy::protocols::ObjectInterface;

use crate::frame::TitleMode;
use crate::wl_proxy::Border;
use crate::wl_title::{Lease, Text};

// --- THE ARITHMETIC ---------------------------------------------------------
// What the frame takes of a window is its [`Insets`]: the border all round,
// and the title strip under the top border when it takes room. All zero is
// "no frame", and every function is then the identity. Saturating: a
// program's nonsense near i32::MAX stays nonsense, it does not wrap into
// something plausible.

/// A rectangle in a surface's coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

/// What the frame takes of a window: `border` on every side, and `title`
/// more at the top (0 when the strip takes no room: hover, off, fullscreen).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Insets {
    pub border: i32,
    pub title: i32,
}

impl Insets {
    /// Above the program's geometry: the border and the strip.
    pub fn top(self) -> i32 {
        self.border.max(0).saturating_add(self.title.max(0))
    }

    /// Taken of the width: the border twice.
    pub fn across(self) -> i32 {
        self.border.max(0).saturating_mul(2)
    }

    /// Taken of the height: the border twice and the strip.
    pub fn down(self) -> i32 {
        self.across().saturating_add(self.title.max(0))
    }
}

/// The program's window geometry → the compositor's: grown by the insets,
/// the frame inside it.
pub(crate) fn geometry_up(g: Rect, i: Insets) -> Rect {
    Rect {
        x: g.x.saturating_sub(i.border.max(0)),
        y: g.y.saturating_sub(i.top()),
        w: g.w.saturating_add(i.across()),
        h: g.h.saturating_add(i.down()),
    }
}

/// A size the compositor asks for (`configure`, `configure_bounds`) → the
/// size the program is told: what is left inside the frame, which takes `d`
/// of it ([`Insets::across`], [`Insets::down`]). 0 is "you decide" and
/// stays so; what is left is never below 1, which would be 0.
pub(crate) fn size_down(v: i32, d: i32) -> i32 {
    if v <= 0 || d <= 0 {
        v
    } else {
        v.saturating_sub(d).max(1)
    }
}

/// A size limit of the program (`set_min_size`, `set_max_size`) → the
/// compositor's. 0 is "no limit" and stays so.
pub(crate) fn size_up(v: i32, d: i32) -> i32 {
    if v <= 0 || d <= 0 {
        v
    } else {
        v.saturating_add(d)
    }
}

/// A point relative to the program's geometry → relative to the
/// compositor's (`show_window_menu`, a popup's anchor rect): `d` is the
/// frame before it, [`Insets::border`] across or [`Insets::top`] down.
pub(crate) fn point_up(v: i32, d: i32) -> i32 {
    v.saturating_add(d.max(0))
}

/// A point relative to the compositor's geometry → the program's
/// (`xdg_popup.configure`).
pub(crate) fn point_down(v: i32, d: i32) -> i32 {
    v.saturating_sub(d.max(0))
}

/// The four strips of the border around the program's geometry `g` and the
/// title strip above it, in the root surface's coordinates: top and bottom
/// the whole width with the corners, left and right between them. They do
/// not overlap each other, the title strip, nor `g`.
pub(crate) fn strips(g: Rect, i: Insets) -> [Rect; 4] {
    let outer = geometry_up(g, i);
    let b = i.border.max(0);
    let t = i.title.max(0);
    [
        Rect {
            x: outer.x,
            y: outer.y,
            w: outer.w,
            h: b,
        },
        Rect {
            x: outer.x,
            y: g.y.saturating_add(g.h),
            w: outer.w,
            h: b,
        },
        Rect {
            x: outer.x,
            y: g.y.saturating_sub(t),
            w: b,
            h: g.h.saturating_add(t),
        },
        Rect {
            x: g.x.saturating_add(g.w),
            y: g.y.saturating_sub(t),
            w: b,
            h: g.h.saturating_add(t),
        },
    ]
}

/// Where the title strip is, over the program's geometry `g`: in the room
/// the insets keep for it, above `g`; or, `over` the content (hover), along
/// the top of `g` — never taller than `g`. `None`: no strip.
pub(crate) fn title_strip(g: Rect, i: Insets, over: bool) -> Option<Rect> {
    if i.title > 0 {
        Some(Rect {
            x: g.x,
            y: g.y.saturating_sub(i.title),
            w: g.w,
            h: i.title,
        })
    } else if over && i.border > 0 {
        Some(Rect {
            x: g.x,
            y: g.y,
            w: g.w,
            h: TITLE_HEIGHT.min(g.h),
        })
    } else {
        None
    }
}

/// How much of a line `text` wide a strip `strip` wide shows: all of it
/// after [`TITLE_PAD`], or what is left when the strip is narrower, keeping
/// [`TITLE_PAD`] clear at its end too. 0: none.
pub(crate) fn text_shown(strip: i32, text: i32) -> i32 {
    strip
        .saturating_sub(TITLE_PAD.saturating_mul(2))
        .min(text)
        .max(0)
}

/// `shown` logical pixels of a line `text` wide, in the pixels of a buffer
/// `buffer` wide that holds the whole line: the width of the viewport's
/// source. Never past the buffer.
pub(crate) fn source_width(shown: i32, text: i32, buffer: i32) -> i32 {
    if text <= 0 || shown >= text {
        return buffer.max(0);
    }
    let px = (i64::from(shown.max(0)) * i64::from(buffer) + i64::from(text) / 2) / i64::from(text);
    (px as i32).clamp(0, buffer.max(0))
}

/// Whether the pointer at `y` on the program's surface (`g` its geometry)
/// wants a hover strip shown (`Some(true)`), hidden (`Some(false)`), or as
/// it is: at the very top of the window it comes out; under where it would
/// be, it goes.
pub(crate) fn hover_at(g: Rect, y: f64) -> Option<bool> {
    let top = f64::from(g.y);
    if y < top + f64::from(HOVER_EDGE) {
        Some(true)
    } else if y >= top + f64::from(TITLE_HEIGHT) {
        Some(false)
    } else {
        None
    }
}

/// The logical size of a surface from its committed state (wl_surface and
/// wp_viewport): the destination if set, else the source, else the buffer
/// divided by its scale and turned by its transform. `None` when there is no
/// buffer, or its size is not known.
fn surface_size(s: &Committed) -> Option<(i32, i32)> {
    if let Some(dest) = s.destination {
        return Some(dest);
    }
    let (bw, bh) = s.buffer?;
    if let Some(src) = s.source {
        return Some(src);
    }
    let scale = s.scale.max(1);
    let (w, h) = (bw / scale, bh / scale);
    // 90° and 270°, flipped or not, are the odd ones.
    Some(if s.transform % 2 == 1 { (h, w) } else { (w, h) })
}

// --- THE CONNECTION'S SHARE -------------------------------------------------

/// The frame of one connection: what the proxy bound for it upstream, and
/// what it draws with. Every handler below holds it.
pub(crate) struct Frames {
    width: i32,
    /// The title strip's mode, the launch's.
    mode: TitleMode,
    /// The colour, a 3×3 XRGB8888 square in a sealed memfd, made before the
    /// proxy confined itself (`wl_proxy::pixel`): the same for every
    /// connection of the launch — one zone, one colour.
    pixel: Rc<OwnedFd>,
    /// The title's line and the memfd of its pixels (`crate::wl_title`), the
    /// launch's too. `None`: the strip goes without its text.
    text: Option<Rc<Text>>,
    own: RefCell<Own>,
    /// The scale (120ths) the compositor last preferred for a title of this
    /// connection: a new window's text is drawn at it first.
    scale: Cell<u32>,
    /// Whether "cannot draw" has been said: once per proxy.
    warned: Rc<Cell<bool>>,
    /// Windows of this connection with a frame now ([`Framed`]).
    framed: Rc<Cell<usize>>,
}

/// One framed window's share of [`Frames::framed`], given back when its frame
/// goes (or with the connection).
///
/// A frame is the proxy's own objects upstream — four strips of three, the
/// title and its text of about eight — which the program's table does not
/// hold, so `wl_proxy`'s cap on the program's objects does not count them:
/// three objects of the program (a surface, its xdg_surface, a toplevel)
/// and a commit without a buffer make about twenty in the compositor
/// (review 2026-09-25). `wl_proxy` counts these at every dispatch and ends
/// a connection with too many ([`MAX_FRAMED`]).
struct Framed(Rc<Cell<usize>>);

impl Framed {
    fn new(count: &Rc<Cell<usize>>) -> Self {
        count.set(count.get().saturating_add(1));
        Self(count.clone())
    }
}

impl Drop for Framed {
    fn drop(&mut self) {
        self.0.set(self.0.get().saturating_sub(1));
    }
}

/// Framed windows one connection may have at once: a program shows a few,
/// a big one a few dozen. Past this it is refused like one with too many
/// objects — never served without a frame.
pub(crate) const MAX_FRAMED: usize = 4096;

#[derive(Default)]
struct Own {
    /// The registry has been answered: what is missing now is missing.
    complete: bool,
    compositor: Option<Rc<WlCompositor>>,
    subcompositor: Option<Rc<WlSubcompositor>>,
    shm: Option<Rc<WlShm>>,
    viewporter: Option<Rc<WpViewporter>>,
    /// For the title's text, when the compositor offers it to the restricted
    /// client; without it, `wl_surface.preferred_buffer_scale`.
    fractional: Option<Rc<WpFractionalScaleManagerV1>>,
    buffer: Option<Rc<WlBuffer>>,
    /// The pool of the title's pixels: the launch's memfd, this connection's
    /// pool of it.
    text_pool: Option<Rc<WlShmPool>>,
}

/// The colour's buffer: a square of this side, in XRGB8888 (`wl_proxy::pixel`
/// makes it).
pub(crate) const PIXEL_SIDE: i32 = 3;
pub(crate) const PIXEL_BYTES: i32 = PIXEL_SIDE * PIXEL_SIDE * 4;

/// The title strip's height and the space before its text, logical pixels
/// (`crate::wl_title`).
pub(crate) const TITLE_HEIGHT: i32 = crate::wl_title::HEIGHT;
pub(crate) const TITLE_PAD: i32 = crate::wl_title::PAD;
/// How near the top of the program's geometry the pointer brings a hover
/// strip out, logical pixels: the border above it does too.
pub(crate) const HOVER_EDGE: i32 = 2;
/// Configures remembered until the program acks them: a program acks the
/// last it has seen, and a hostile one may never ack — bounded.
const MAX_CONFIGURES: usize = 32;
/// `xdg_toplevel.state.fullscreen`.
const FULLSCREEN: u32 = 2;

/// An object of the proxy's own: whatever the compositor sends it is not the
/// program's (it could not be passed on anyway — the object has no id in the
/// program's table).
fn quiet<T: Object + ?Sized>(object: &T) {
    object.set_forward_to_client(false);
}

/// Whether input on `surface` is the program's: it has an id in its table.
/// The proxy's strips never have one, nor has a surface the program has
/// already destroyed.
fn programs(surface: &Rc<WlSurface>) -> bool {
    surface.client_id().is_some()
}

impl Frames {
    /// Windows of this connection with a frame now: `wl_proxy` refuses the
    /// connection past [`MAX_FRAMED`].
    pub(crate) fn framed(&self) -> usize {
        self.framed.get()
    }

    /// Start the frame on a new connection, before any request of the
    /// program is read: a registry of the proxy's own and a sync after it,
    /// whose answer says the globals are all in.
    pub(crate) fn install(
        client: &Rc<Client>,
        border: &Border,
        warned: Rc<Cell<bool>>,
    ) -> Rc<Self> {
        let frames = Rc::new(Self {
            width: border.width,
            mode: border.title,
            pixel: border.pixel.clone(),
            text: border.text.clone(),
            own: RefCell::default(),
            scale: Cell::new(crate::wl_title::MIN_SCALE),
            warned,
            framed: Rc::default(),
        });
        let display = client.display();
        let registry = display.new_send_get_registry();
        quiet(&*registry);
        registry.set_handler(OwnRegistry {
            frames: frames.clone(),
        });
        let sync = display.new_send_sync();
        quiet(&*sync);
        sync.set_handler(OwnSync {
            frames: frames.clone(),
        });
        frames
    }

    /// A global the program has just bound: the objects whose messages the
    /// frame has to translate or filter get their handlers.
    pub(crate) fn watch(self: &Rc<Self>, id: &Rc<dyn Object>) {
        let f = self.clone();
        if let Some(o) = id.try_downcast::<WlCompositor>() {
            o.set_handler(Compositor { f });
        } else if let Some(o) = id.try_downcast::<XdgWmBase>() {
            o.set_handler(WmBase { f });
        } else if let Some(o) = id.try_downcast::<WlSubcompositor>() {
            o.set_handler(Subcompositor);
        } else if let Some(o) = id.try_downcast::<WpViewporter>() {
            o.set_handler(Viewporter);
        } else if let Some(o) = id.try_downcast::<WlSeat>() {
            o.set_handler(Seat);
        } else if let Some(o) = id.try_downcast::<WlShm>() {
            o.set_handler(Shm);
        } else if let Some(o) = id.try_downcast::<ZwpLinuxDmabufV1>() {
            o.set_handler(Dmabuf);
        } else if let Some(o) = id.try_downcast::<WlDrm>() {
            o.set_handler(Drm);
        } else if let Some(o) = id.try_downcast::<WpSinglePixelBufferManagerV1>() {
            o.set_handler(SinglePixel);
        } else if let Some(o) = id.try_downcast::<WlDataDeviceManager>() {
            o.set_handler(DataDeviceManager);
        } else if let Some(o) = id.try_downcast::<ZwpPointerGesturesV1>() {
            o.set_handler(Gestures);
        } else if let Some(o) = id.try_downcast::<ZwpTabletManagerV2>() {
            o.set_handler(TabletManager);
        } else if let Some(o) = id.try_downcast::<XdgToplevelDragManagerV1>() {
            o.set_handler(DragManager { f });
        }
    }

    /// The registry has been answered: make the one buffer every strip
    /// shows, and the pool the title's text comes from.
    fn finish(&self) {
        let mut own = self.own.borrow_mut();
        own.complete = true;
        let Some(shm) = own.shm.clone() else {
            return;
        };
        let pool = shm.new_send_create_pool(&self.pixel, PIXEL_BYTES);
        quiet(&*pool);
        let buffer = pool.new_send_create_buffer(
            0,
            PIXEL_SIDE,
            PIXEL_SIDE,
            PIXEL_SIDE * 4,
            WlShmFormat::XRGB8888,
        );
        quiet(&*buffer);
        pool.send_destroy();
        own.buffer = Some(buffer);
        if let Some(text) = &self.text {
            let pool = shm.new_send_create_pool(&text.fd, text.pool_size());
            quiet(&*pool);
            own.text_pool = Some(pool);
        }
    }

    /// Whether windows of this connection can have a frame; said once per
    /// proxy when not.
    fn can_draw(&self) -> bool {
        let own = self.own.borrow();
        let missing: Vec<&str> = [
            ("wl_compositor", own.compositor.is_some()),
            ("wl_subcompositor", own.subcompositor.is_some()),
            ("wl_shm", own.buffer.is_some()),
            ("wp_viewporter", own.viewporter.is_some()),
        ]
        .into_iter()
        .filter_map(|(name, there)| (!there).then_some(name))
        .collect();
        if !missing.is_empty() && !self.warned.replace(true) {
            eprintln!(
                "wl-sandbox: the compositor offers no {} — windows go without the zone's border",
                missing.join(", ")
            );
        }
        missing.is_empty()
    }

    /// The four strips of a new bordered window, above `top` (the program's
    /// topmost layer on `root`). Attached, not committed: they show with the
    /// first layout, which the program's commit applies.
    fn make_strips(
        &self,
        root: &Rc<WlSurface>,
        top: &Rc<WlSurface>,
        me: &Weak<RefCell<Window>>,
    ) -> Option<Vec<Strip>> {
        let own = self.own.borrow();
        let (Some(compositor), Some(subcompositor), Some(viewporter), Some(buffer)) = (
            &own.compositor,
            &own.subcompositor,
            &own.viewporter,
            &own.buffer,
        ) else {
            return None;
        };
        let strips = (0..4)
            .map(|i| {
                let surface = compositor.new_send_create_surface();
                quiet(&*surface);
                // The top strip brings a hover title out.
                let part = if i == 0 { Part::Top } else { Part::Side };
                surface.set_handler(Mine {
                    window: me.clone(),
                    part,
                });
                let sub = subcompositor.new_send_get_subsurface(&surface, root);
                quiet(&*sub);
                let viewport = viewporter.new_send_get_viewport(&surface);
                quiet(&*viewport);
                // The middle pixel of the square.
                let one = Fixed::from_i32_saturating(1);
                viewport.send_set_source(one, one, one, one);
                sub.send_place_above(top);
                attach_pixel(&surface, buffer);
                Strip {
                    surface,
                    sub,
                    viewport,
                }
            })
            .collect();
        Some(strips)
    }

    /// The title strip of a new window, above `top`: the colour's pixel
    /// stretched like a strip of the border (not attached yet: a hover strip
    /// starts hidden), and the text a subsurface of it — so that the text
    /// goes where the strip goes, and is hidden with it.
    fn make_title(
        self: &Rc<Self>,
        root: &Rc<WlSurface>,
        top: &Rc<WlSurface>,
        me: &Weak<RefCell<Window>>,
    ) -> Option<TitleParts> {
        let own = self.own.borrow();
        let (Some(compositor), Some(subcompositor), Some(viewporter), Some(buffer)) = (
            &own.compositor,
            &own.subcompositor,
            &own.viewporter,
            &own.buffer,
        ) else {
            return None;
        };
        let own_surface = || {
            let surface = compositor.new_send_create_surface();
            quiet(&*surface);
            surface.set_handler(Mine {
                window: me.clone(),
                part: Part::Title,
            });
            surface
        };
        let surface = own_surface();
        let sub = subcompositor.new_send_get_subsurface(&surface, root);
        quiet(&*sub);
        sub.send_place_above(top);
        let view = viewporter.new_send_get_viewport(&surface);
        quiet(&*view);
        let one = Fixed::from_i32_saturating(1);
        view.send_set_source(one, one, one, one);
        let text = match (&self.text, &own.text_pool) {
            (Some(text), Some(pool)) => {
                let text_surface = own_surface();
                let text_sub = subcompositor.new_send_get_subsurface(&text_surface, &surface);
                quiet(&*text_sub);
                text_sub.send_set_position(TITLE_PAD, 0);
                let text_view = viewporter.new_send_get_viewport(&text_surface);
                quiet(&*text_view);
                let fraction = own.fractional.as_ref().map(|manager| {
                    let fraction = manager.new_send_get_fractional_scale(&text_surface);
                    quiet(&*fraction);
                    fraction.set_handler(Scale {
                        f: self.clone(),
                        window: me.clone(),
                    });
                    fraction
                });
                Some(TextParts {
                    text: text.clone(),
                    pool: pool.clone(),
                    surface: text_surface,
                    sub: text_sub,
                    view: text_view,
                    fraction,
                    scale: self.scale.get(),
                    drawn: None,
                    current: None,
                    retired: Vec::new(),
                    shown: 0,
                })
            }
            _ => None,
        };
        Some(TitleParts {
            pixel: buffer.clone(),
            surface,
            sub,
            view,
            shown: false,
            text,
        })
    }
}

/// Attach the colour's square to one of the proxy's surfaces.
fn attach_pixel(surface: &Rc<WlSurface>, buffer: &Rc<WlBuffer>) {
    surface.send_attach(Some(buffer), 0, 0);
    if surface.version() >= 4 {
        surface.send_damage_buffer(0, 0, PIXEL_SIDE, PIXEL_SIDE);
    } else {
        surface.send_damage(0, 0, 1 << 15, 1 << 15);
    }
}

/// The proxy's own registry: the globals it draws with, the first of each,
/// at the lowest version that has what it uses.
struct OwnRegistry {
    frames: Rc<Frames>,
}

fn bind<T: ConcreteObject>(registry: &Rc<WlRegistry>, name: u32, version: u32) -> Rc<T> {
    let object = registry.state().create_object::<T>(version.max(1));
    quiet(&*object);
    registry.send_bind(name, object.clone());
    object
}

impl WlRegistryHandler for OwnRegistry {
    fn handle_global(
        &mut self,
        slf: &Rc<WlRegistry>,
        name: u32,
        interface: ObjectInterface,
        version: u32,
    ) {
        let mut own = self.frames.own.borrow_mut();
        match interface {
            // v4: damage_buffer; v6: preferred_buffer_scale, the title's
            // scale where there is no fractional one.
            ObjectInterface::WlCompositor if own.compositor.is_none() => {
                own.compositor = Some(bind(slf, name, version.min(6)));
            }
            ObjectInterface::WlSubcompositor if own.subcompositor.is_none() => {
                own.subcompositor = Some(bind(slf, name, 1));
            }
            ObjectInterface::WlShm if own.shm.is_none() => {
                own.shm = Some(bind(slf, name, 1));
            }
            ObjectInterface::WpViewporter if own.viewporter.is_none() => {
                own.viewporter = Some(bind(slf, name, 1));
            }
            ObjectInterface::WpFractionalScaleManagerV1 if own.fractional.is_none() => {
                own.fractional = Some(bind(slf, name, 1));
            }
            _ => {}
        }
    }

    fn handle_global_remove(&mut self, _slf: &Rc<WlRegistry>, _name: u32) {}
}

struct OwnSync {
    frames: Rc<Frames>,
}

impl WlCallbackHandler for OwnSync {
    fn handle_done(&mut self, _slf: &Rc<WlCallback>, _callback_data: u32) {
        self.frames.finish();
    }
}

/// What one of the proxy's surfaces is, for the input that comes to it and
/// for its scale: the top strip of the border (it brings a hover title
/// out), another strip, or the title strip and its text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    Top,
    Side,
    Title,
}

/// The handler of the proxy's own surfaces: which window, which part.
struct Mine {
    window: Weak<RefCell<Window>>,
    part: Part,
}

impl WlSurfaceHandler for Mine {
    /// The integer scale, `wl_compositor` v6: the text's where the
    /// compositor offers no fractional one.
    fn handle_preferred_buffer_scale(&mut self, _slf: &Rc<WlSurface>, factor: i32) {
        if self.part != Part::Title {
            return;
        }
        if let Some(window) = self.window.upgrade() {
            if let Ok(mut window) = window.try_borrow_mut() {
                window.integer_scale(factor);
            }
        }
    }
}

/// The text's `wp_fractional_scale_v1`.
struct Scale {
    f: Rc<Frames>,
    window: Weak<RefCell<Window>>,
}

impl WpFractionalScaleV1Handler for Scale {
    fn handle_preferred_scale(&mut self, _slf: &Rc<WpFractionalScaleV1>, scale: u32) {
        let scale = crate::wl_title::clamp_scale(scale);
        self.f.scale.set(scale);
        if let Some(window) = self.window.upgrade() {
            if let Ok(mut window) = window.try_borrow_mut() {
                window.rescale(scale);
            }
        }
    }
}

/// A buffer of the title's text: its hold on the region of the memfd it
/// shows, until the compositor releases it. Destroyed once released and no
/// longer attached (`retired`).
struct TextBuffer {
    lease: Option<Lease>,
    retired: bool,
    destroyed: bool,
}

impl TextBuffer {
    fn destroy(&mut self, slf: &Rc<WlBuffer>) {
        if !self.destroyed {
            self.destroyed = true;
            slf.send_destroy();
        }
    }
}

impl WlBufferHandler for TextBuffer {
    fn handle_release(&mut self, slf: &Rc<WlBuffer>) {
        self.lease = None;
        if self.retired {
            self.destroy(slf);
        }
    }
}

// --- WINDOWS ------------------------------------------------------------------

struct Strip {
    surface: Rc<WlSurface>,
    sub: Rc<WlSubsurface>,
    viewport: Rc<WpViewport>,
}

/// The title strip of a window: the colour stretched, and the text on it.
struct TitleParts {
    pixel: Rc<WlBuffer>,
    surface: Rc<WlSurface>,
    sub: Rc<WlSubsurface>,
    view: Rc<WpViewport>,
    /// The colour is attached: the strip is shown.
    shown: bool,
    text: Option<TextParts>,
}

impl TitleParts {
    /// Attach the colour or nothing; the caller commits.
    fn show(&mut self, on: bool) {
        if on {
            attach_pixel(&self.surface, &self.pixel);
        } else {
            self.surface.send_attach(None, 0, 0);
        }
        self.shown = on;
    }

    /// Show what is pending of the strip and its text now, without waiting
    /// for the program's commit (§5.3): the strip is a synchronized
    /// subsurface, whose state the root's commit applies, and the program
    /// may not commit for a long while — a text drawn at a new scale, a
    /// hover strip coming out. Desynchronized for its own commit, and
    /// synchronized again at once. Its pending state holds nothing else: the
    /// proxy lays it out only right before the program's commit.
    fn apply_now(&self) {
        self.sub.send_set_desync();
        self.surface.send_commit();
        self.sub.send_set_sync();
    }

    fn destroy(self) {
        if let Some(text) = self.text {
            text.destroy();
        }
        self.view.send_destroy();
        self.sub.send_destroy();
        self.surface.send_destroy();
    }
}

/// The text on a title strip: a buffer of the line at the scale the
/// compositor prefers, the viewport cutting it to what the strip shows.
struct TextParts {
    text: Rc<Text>,
    pool: Rc<WlShmPool>,
    surface: Rc<WlSurface>,
    sub: Rc<WlSubsurface>,
    view: Rc<WpViewport>,
    fraction: Option<Rc<WpFractionalScaleV1>>,
    /// The scale asked for (120ths), and the size of the buffer attached.
    scale: u32,
    drawn: Option<(i32, i32)>,
    current: Option<Rc<WlBuffer>>,
    /// Buffers no longer attached that the compositor has not released yet.
    retired: Vec<Rc<WlBuffer>>,
    /// How much of the line the strip shows, logical pixels.
    shown: i32,
}

impl TextParts {
    /// Attach the line at `self.scale` and commit (cached: the strip's
    /// commit applies it). False when there is nothing to draw it in.
    fn draw(&mut self) -> bool {
        let Some(drawn) = self.text.at(self.scale) else {
            return false;
        };
        let buffer = self.pool.new_send_create_buffer(
            drawn.offset,
            drawn.width,
            drawn.height,
            drawn.width * 4,
            WlShmFormat::XRGB8888,
        );
        quiet(&*buffer);
        buffer.set_handler(TextBuffer {
            lease: Some(drawn.lease),
            retired: false,
            destroyed: false,
        });
        self.surface.send_attach(Some(&buffer), 0, 0);
        if self.surface.version() >= 4 {
            self.surface
                .send_damage_buffer(0, 0, drawn.width, drawn.height);
        } else {
            self.surface.send_damage(0, 0, 1 << 15, 1 << 15);
        }
        self.retire();
        self.current = Some(buffer);
        self.drawn = Some((drawn.width, drawn.height));
        self.crop();
        self.surface.send_commit();
        true
    }

    /// The buffer attached until now is not any more: destroyed once the
    /// compositor has released it (at once when it has).
    fn retire(&mut self) {
        if let Some(old) = self.current.take() {
            self.retired.push(old);
        }
        self.retired.retain(|buffer| {
            let Ok(mut h) = buffer.try_get_handler_mut::<TextBuffer>() else {
                return false;
            };
            h.retired = true;
            if h.lease.is_none() {
                h.destroy(buffer);
            }
            !h.destroyed
        });
    }

    /// The viewport: `shown` logical pixels of the line, from the buffer's
    /// left, the strip's height.
    fn crop(&self) {
        let Some((width, height)) = self.drawn else {
            return;
        };
        let source = source_width(self.shown, self.text.width(), width);
        let zero = Fixed::from_i32_saturating(0);
        self.view.send_set_source(
            zero,
            zero,
            Fixed::from_i32_saturating(source),
            Fixed::from_i32_saturating(height),
        );
        self.view.send_set_destination(self.shown, TITLE_HEIGHT);
    }

    /// Fit the text to a strip `strip` wide; committed (cached) when that
    /// changed anything.
    fn fit(&mut self, strip: i32) {
        let shown = text_shown(strip, self.text.width());
        if shown == self.shown && (shown <= 0 || self.drawn.is_some()) {
            return;
        }
        self.shown = shown;
        if shown <= 0 {
            self.surface.send_attach(None, 0, 0);
            self.retire();
            self.drawn = None;
            self.surface.send_commit();
        } else if self.drawn.is_none() {
            self.draw();
        } else {
            self.crop();
            self.surface.send_commit();
        }
    }

    fn destroy(mut self) {
        if let Some(fraction) = &self.fraction {
            fraction.send_destroy();
        }
        self.view.send_destroy();
        self.sub.send_destroy();
        self.surface.send_destroy();
        // The surface is gone: nothing of its buffers is shown any more.
        for buffer in self
            .current
            .take()
            .into_iter()
            .chain(self.retired.drain(..))
        {
            if let Ok(mut h) = buffer.try_get_handler_mut::<TextBuffer>() {
                h.destroy(&buffer);
                h.lease = None;
            }
        }
    }
}

/// One xdg_surface of the program, toplevel or not. Weak references to the
/// program's objects: their handlers hold this, and a cycle would keep a
/// closed window's objects for the connection's life.
struct Window {
    /// Itself, for the handlers of the proxy's surfaces.
    me: Weak<RefCell<Window>>,
    xdg: Weak<XdgSurface>,
    root: Weak<WlSurface>,
    toplevel: Option<Weak<XdgToplevel>>,
    /// The launch's title mode.
    mode: TitleMode,
    /// Decided once, when the proxy knows whether it can draw.
    bordered: Option<bool>,
    /// The program's geometry, and what the compositor was last told.
    geometry: Option<Rect>,
    sent_geometry: Option<Rect>,
    min: Option<(i32, i32)>,
    sent_min: Option<(i32, i32)>,
    max: Option<(i32, i32)>,
    sent_max: Option<(i32, i32)>,
    strips: Option<Vec<Strip>>,
    title: Option<TitleParts>,
    /// Counted among the connection's framed windows while it has strips.
    counted: Option<Framed>,
    /// Fullscreen, as of the configure the program acked last: its next
    /// commit is of that state, and so is the frame laid before it (the
    /// title strip takes no room in fullscreen, §5.7). The configure the
    /// compositor sent last says `next_fullscreen` — the strip hides only
    /// while both say it ([`Self::title_wanted`]) —, and those not acked yet
    /// are kept by serial.
    fullscreen: bool,
    next_fullscreen: bool,
    configures: VecDeque<(u32, bool)>,
    /// The pointer is at the top of the window: a hover strip is wanted.
    hover: bool,
    /// What the frame is laid around now: the area, the insets, the strip.
    laid: Option<(Rect, Insets, Option<Rect>)>,
}

impl Window {
    fn new(
        xdg: &Rc<XdgSurface>,
        root: &Rc<WlSurface>,
        me: Weak<RefCell<Window>>,
        mode: TitleMode,
    ) -> Self {
        Self {
            me,
            xdg: Rc::downgrade(xdg),
            root: Rc::downgrade(root),
            toplevel: None,
            mode,
            bordered: None,
            geometry: None,
            sent_geometry: None,
            min: None,
            sent_min: None,
            max: None,
            sent_max: None,
            strips: None,
            title: None,
            counted: None,
            fullscreen: false,
            next_fullscreen: false,
            configures: VecDeque::new(),
            hover: false,
            laid: None,
        }
    }

    /// The border's width for this window now: 0 for anything but a
    /// toplevel, and until the proxy knows whether it can draw.
    fn border(&mut self, f: &Frames) -> i32 {
        if self.toplevel.is_none() {
            return 0;
        }
        if self.bordered.is_none() && f.own.borrow().complete {
            self.bordered = Some(f.can_draw());
        }
        if self.bordered == Some(true) {
            f.width
        } else {
            0
        }
    }

    /// What the frame takes of the window in a state `fullscreen` or not:
    /// the border, and the title strip when it takes room — always, not
    /// in fullscreen.
    fn insets(&mut self, f: &Frames, fullscreen: bool) -> Insets {
        let border = self.border(f);
        let title = if border > 0 && self.mode == TitleMode::Always && !fullscreen {
            TITLE_HEIGHT
        } else {
            0
        };
        Insets { border, title }
    }

    /// The insets of the state the program's next commit is of.
    fn current(&mut self, f: &Frames) -> Insets {
        let fullscreen = self.fullscreen;
        self.insets(f, fullscreen)
    }

    /// The area the frame is laid around now, if it is.
    fn area(&self) -> Option<Rect> {
        self.laid.map(|(area, _, _)| area)
    }

    /// Just before the program's commit of its root surface: the geometry and
    /// the size limits it set, translated, and the frame laid around what
    /// the commit makes the window — all applied by that one commit.
    fn before_commit(
        &mut self,
        f: &Rc<Frames>,
        root: &Rc<WlSurface>,
        top: &Rc<WlSurface>,
        size: Option<(i32, i32)>,
    ) {
        let i = self.current(f);
        if let (Some(g), Some(xdg)) = (self.geometry, self.xdg.upgrade()) {
            let want = geometry_up(g, i);
            if self.sent_geometry != Some(want) {
                xdg.send_set_window_geometry(want.x, want.y, want.w, want.h);
                self.sent_geometry = Some(want);
            }
        }
        if let Some(toplevel) = self.toplevel.as_ref().and_then(Weak::upgrade) {
            if let Some((w, h)) = self.min {
                let want = (size_up(w, i.across()), size_up(h, i.down()));
                if self.sent_min != Some(want) {
                    toplevel.send_set_min_size(want.0, want.1);
                    self.sent_min = Some(want);
                }
            }
            if let Some((w, h)) = self.max {
                let want = (size_up(w, i.across()), size_up(h, i.down()));
                if self.sent_max != Some(want) {
                    toplevel.send_set_max_size(want.0, want.1);
                    self.sent_max = Some(want);
                }
            }
        }
        if i.border <= 0 {
            return;
        }
        if self.strips.is_none() {
            self.strips = f.make_strips(root, top, &self.me);
            if self.strips.is_some() {
                self.counted = Some(Framed::new(&f.framed));
            }
            self.laid = None;
        }
        let area = self
            .geometry
            .or_else(|| size.map(|(w, h)| Rect { x: 0, y: 0, w, h }));
        let (Some(strips), Some(area)) = (&self.strips, area) else {
            return;
        };
        if area.w <= 0 || area.h <= 0 {
            return;
        }
        // Where the title goes: in its room when the insets keep one, else
        // over the top of the content — in mode `hover`, and in `always`
        // while the program's state is fullscreen: laid there hidden, so
        // that it can come out at once when the compositor takes the window
        // out of fullscreen before the program acks that
        // ([`Self::title_wanted`]).
        let over = self.mode != TitleMode::Off;
        let strip = title_strip(area, i, over);
        if self.laid == Some((area, i, strip)) {
            // Nothing moves; whether the strip shows may still change (the
            // program acked fullscreen, or its end).
            self.show_title(false);
            return;
        }
        for (s, r) in strips.iter().zip(self::strips(area, i)) {
            s.sub.send_set_position(r.x, r.y);
            s.viewport.send_set_destination(r.w, r.h);
            s.surface.send_commit();
        }
        self.laid = Some((area, i, strip));
        self.lay_title(f, root, top, strip);
    }

    /// Whether the title strip shows now: it is laid somewhere; in mode
    /// `hover` the pointer wants it; and fullscreen hides it only while BOTH
    /// the configure the program acked last and the one the compositor sent
    /// last say fullscreen (review 2026-09-25). The program decides when it
    /// acks: a hostile one acks the fullscreen configure and never the one
    /// that ends it, keeps committing (xdg-shell allows that), and the
    /// compositor shows the window in its normal place anyway (sway, after
    /// its transaction's timeout) — with the ack alone deciding, the strip
    /// would stay hidden for the window's life, and the program would draw
    /// another zone's in its place. Fail-closed: the compositor's word
    /// brings it out, over the top of the content (it has no room: the
    /// program's commits are still of the fullscreen size).
    fn title_wanted(&self) -> bool {
        let placed = self.laid.is_some_and(|(_, _, strip)| strip.is_some());
        let fullscreen = self.fullscreen && self.next_fullscreen;
        placed && !fullscreen && (self.mode == TitleMode::Always || self.hover)
    }

    /// Show or hide the title strip as [`Self::title_wanted`] says: `now`
    /// (the pointer, the compositor's configure — the program may not
    /// commit for a long while), or with the program's commit that comes
    /// next.
    fn show_title(&mut self, now: bool) {
        let want = self.title_wanted();
        let Some(t) = &mut self.title else {
            return;
        };
        if t.shown != want {
            t.show(want);
            if now {
                t.apply_now();
            } else {
                t.surface.send_commit();
            }
        }
    }

    /// The title strip at `strip` (or none), before the program's commit.
    fn lay_title(
        &mut self,
        f: &Rc<Frames>,
        root: &Rc<WlSurface>,
        top: &Rc<WlSurface>,
        strip: Option<Rect>,
    ) {
        let Some(r) = strip else {
            self.show_title(false);
            return;
        };
        if self.title.is_none() {
            self.title = f.make_title(root, top, &self.me);
        }
        let want = self.title_wanted();
        let Some(t) = &mut self.title else {
            return;
        };
        t.sub.send_set_position(r.x, r.y);
        t.view.send_set_destination(r.w, r.h);
        if t.shown != want {
            t.show(want);
        }
        if let Some(text) = &mut t.text {
            text.fit(r.w);
        }
        t.surface.send_commit();
    }

    /// The compositor prefers `scale` (120ths) for the title's text: drawn at
    /// it, and shown now.
    fn rescale(&mut self, scale: u32) {
        let scale = crate::wl_title::clamp_scale(scale);
        let Some(t) = &mut self.title else {
            return;
        };
        let Some(text) = &mut t.text else {
            return;
        };
        if text.scale == scale && text.drawn.is_some() {
            return;
        }
        text.scale = scale;
        if text.shown > 0 && text.draw() {
            t.apply_now();
        }
    }

    /// `wl_surface.preferred_buffer_scale` of the text: its scale where the
    /// compositor offers no fractional one.
    fn integer_scale(&mut self, factor: i32) {
        let fractional = self
            .title
            .as_ref()
            .and_then(|t| t.text.as_ref())
            .is_some_and(|text| text.fraction.is_some());
        if !fractional {
            self.rescale(u32::try_from(factor.clamp(1, 4)).unwrap_or(1) * 120);
        }
    }

    /// The pointer wants a hover strip out or in (§0а): shown now, not at the
    /// program's next commit. Nothing in another mode, nor in fullscreen.
    fn set_hover(&mut self, on: bool) {
        if self.mode != TitleMode::Hover || self.hover == on {
            return;
        }
        self.hover = on;
        self.show_title(true);
    }

    /// The compositor's configure says fullscreen or not: the strip comes
    /// out (or goes) now when that changes what [`Self::title_wanted`]
    /// says — a program that stops committing must not keep it hidden
    /// either.
    fn configured(&mut self, fullscreen: bool) {
        self.next_fullscreen = fullscreen;
        self.show_title(true);
    }

    /// Put the strips and the title on top of the root's stack again, above
    /// `top`.
    fn raise(&self, top: &Rc<WlSurface>) {
        for strip in self.strips.iter().flatten() {
            strip.sub.send_place_above(top);
        }
        if let Some(t) = &self.title {
            t.sub.send_place_above(top);
        }
    }

    /// The window is gone (its toplevel or xdg_surface destroyed): so is its
    /// frame, at once — a subsurface's destruction does not wait for a
    /// commit.
    fn drop_strips(&mut self) {
        for strip in self.strips.take().into_iter().flatten() {
            strip.viewport.send_destroy();
            strip.sub.send_destroy();
            strip.surface.send_destroy();
        }
        if let Some(t) = self.title.take() {
            t.destroy();
        }
        self.counted = None;
        self.laid = None;
    }
}

/// A layer of a surface's stack of subsurfaces: the surface itself, or a
/// child (by its wl-proxy id, which is unique for the connection's life).
enum Layer {
    Itself,
    Child(u64, Weak<WlSurface>),
}

/// wl_surface state the size of a root surface comes from, pending and
/// committed.
#[derive(Default)]
struct Pending {
    buffer: Option<Option<(i32, i32)>>,
    scale: Option<i32>,
    transform: Option<u32>,
    destination: Option<Option<(i32, i32)>>,
    source: Option<Option<(i32, i32)>>,
}

struct Committed {
    buffer: Option<(i32, i32)>,
    scale: i32,
    transform: u32,
    destination: Option<(i32, i32)>,
    source: Option<(i32, i32)>,
}

impl Default for Committed {
    fn default() -> Self {
        Self {
            buffer: None,
            scale: 1,
            transform: 0,
            destination: None,
            source: None,
        }
    }
}

/// Every surface of the program.
struct Surface {
    f: Rc<Frames>,
    /// Its xdg_surface, when it has one.
    window: Option<Rc<RefCell<Window>>>,
    /// The surface it is a subsurface of.
    parent: Option<Weak<WlSurface>>,
    /// Itself and its subsurfaces, bottom to top — as the compositor has
    /// them pending, so that the strips can be put above the top.
    stack: Vec<Layer>,
    pending: Pending,
    committed: Committed,
}

impl Surface {
    fn new(f: Rc<Frames>) -> Self {
        Self {
            f,
            window: None,
            parent: None,
            stack: vec![Layer::Itself],
            pending: Pending::default(),
            committed: Committed::default(),
        }
    }

    /// The topmost layer of this surface's stack.
    fn top(&self, me: &Rc<WlSurface>) -> Rc<WlSurface> {
        for layer in self.stack.iter().rev() {
            match layer {
                Layer::Itself => return me.clone(),
                Layer::Child(_, child) => {
                    if let Some(child) = child.upgrade() {
                        return child;
                    }
                }
            }
        }
        me.clone()
    }

    fn position(&self, id: Option<u64>) -> Option<usize> {
        self.stack.iter().position(|layer| match (layer, id) {
            (Layer::Itself, None) => true,
            (Layer::Child(c, _), Some(id)) => *c == id,
            _ => false,
        })
    }

    /// `child` moved just above or below `sibling` (this surface itself when
    /// it is the parent).
    fn reorder(
        &mut self,
        me: &Rc<WlSurface>,
        child: &Rc<WlSurface>,
        sibling: &Rc<WlSurface>,
        above: bool,
    ) {
        let Some(from) = self.position(Some(child.unique_id())) else {
            return;
        };
        let layer = self.stack.remove(from);
        let sibling = (!Rc::ptr_eq(sibling, me)).then(|| sibling.unique_id());
        // A sibling that is none (the compositor refuses it) leaves the
        // child where it would be: on top.
        let at = self
            .position(sibling)
            .map_or(self.stack.len(), |i| if above { i + 1 } else { i });
        self.stack.insert(at, layer);
        self.restack(me);
    }

    fn remove(&mut self, child: u64) {
        if let Some(at) = self.position(Some(child)) {
            self.stack.remove(at);
        }
    }

    /// The strips of this surface's window, if it has them, back on top.
    fn restack(&self, me: &Rc<WlSurface>) {
        if let Some(window) = &self.window {
            if let Ok(window) = window.try_borrow() {
                window.raise(&self.top(me));
            }
        }
    }
}

impl WlSurfaceHandler for Surface {
    fn handle_attach(
        &mut self,
        slf: &Rc<WlSurface>,
        buffer: Option<&Rc<WlBuffer>>,
        x: i32,
        y: i32,
    ) {
        slf.send_attach(buffer, x, y);
        self.pending.buffer = Some(buffer.and_then(|b| {
            b.try_get_handler_ref::<BufferSize>()
                .ok()
                .map(|s| (s.width, s.height))
        }));
    }

    fn handle_set_buffer_scale(&mut self, slf: &Rc<WlSurface>, scale: i32) {
        slf.send_set_buffer_scale(scale);
        self.pending.scale = Some(scale);
    }

    fn handle_set_buffer_transform(&mut self, slf: &Rc<WlSurface>, transform: WlOutputTransform) {
        slf.send_set_buffer_transform(transform);
        self.pending.transform = Some(transform.0);
    }

    fn handle_commit(&mut self, slf: &Rc<WlSurface>) {
        let p = std::mem::take(&mut self.pending);
        let c = &mut self.committed;
        if let Some(buffer) = p.buffer {
            c.buffer = buffer;
        }
        if let Some(scale) = p.scale {
            c.scale = scale;
        }
        if let Some(transform) = p.transform {
            c.transform = transform;
        }
        if let Some(destination) = p.destination {
            c.destination = destination;
        }
        if let Some(source) = p.source {
            c.source = source;
        }
        if let Some(window) = &self.window {
            if let Ok(mut window) = window.try_borrow_mut() {
                let top = self.top(slf);
                window.before_commit(&self.f, slf, &top, surface_size(&self.committed));
            }
        }
        slf.send_commit();
    }

    fn handle_destroy(&mut self, slf: &Rc<WlSurface>) {
        slf.send_destroy();
        if let Some(window) = self.window.take() {
            if let Ok(mut window) = window.try_borrow_mut() {
                window.drop_strips();
            }
        }
        // It leaves its parent's stack (its subsurface is inert now).
        if let Some(parent) = self.parent.take().and_then(|p| p.upgrade()) {
            if let Ok(mut h) = parent.try_get_handler_mut::<Surface>() {
                h.remove(slf.unique_id());
            }
        }
        slf.unset_handler();
    }
}

struct Compositor {
    f: Rc<Frames>,
}

impl WlCompositorHandler for Compositor {
    fn handle_create_surface(&mut self, slf: &Rc<WlCompositor>, id: &Rc<WlSurface>) {
        slf.send_create_surface(id);
        id.set_handler(Surface::new(self.f.clone()));
    }
}

struct Subcompositor;

impl WlSubcompositorHandler for Subcompositor {
    fn handle_get_subsurface(
        &mut self,
        slf: &Rc<WlSubcompositor>,
        id: &Rc<WlSubsurface>,
        surface: &Rc<WlSurface>,
        parent: &Rc<WlSurface>,
    ) {
        slf.send_get_subsurface(id, surface, parent);
        if Rc::ptr_eq(surface, parent) {
            // The compositor's error to raise.
            return;
        }
        if let Ok(mut h) = surface.try_get_handler_mut::<Surface>() {
            h.parent = Some(Rc::downgrade(parent));
        }
        if let Ok(mut h) = parent.try_get_handler_mut::<Surface>() {
            // A new subsurface goes on top of its parent's stack — above the
            // strips, until they are raised again right here.
            h.stack
                .push(Layer::Child(surface.unique_id(), Rc::downgrade(surface)));
            h.restack(parent);
        }
        id.set_handler(Subsurface {
            child: Rc::downgrade(surface),
            parent: Rc::downgrade(parent),
        });
    }
}

struct Subsurface {
    child: Weak<WlSurface>,
    parent: Weak<WlSurface>,
}

impl Subsurface {
    fn reorder(&self, sibling: &Rc<WlSurface>, above: bool) {
        let (Some(child), Some(parent)) = (self.child.upgrade(), self.parent.upgrade()) else {
            return;
        };
        if let Ok(mut h) = parent.try_get_handler_mut::<Surface>() {
            h.reorder(&parent, &child, sibling, above);
        };
    }
}

impl WlSubsurfaceHandler for Subsurface {
    fn handle_place_above(&mut self, slf: &Rc<WlSubsurface>, sibling: &Rc<WlSurface>) {
        slf.send_place_above(sibling);
        self.reorder(sibling, true);
    }

    fn handle_place_below(&mut self, slf: &Rc<WlSubsurface>, sibling: &Rc<WlSurface>) {
        slf.send_place_below(sibling);
        self.reorder(sibling, false);
    }

    fn handle_destroy(&mut self, slf: &Rc<WlSubsurface>) {
        slf.send_destroy();
        let child = self.child.upgrade();
        if let (Some(child), Some(parent)) = (&child, self.parent.upgrade()) {
            if let Ok(mut h) = parent.try_get_handler_mut::<Surface>() {
                h.remove(child.unique_id());
            }
        }
        if let Some(child) = child {
            if let Ok(mut h) = child.try_get_handler_mut::<Surface>() {
                h.parent = None;
            }
        }
        slf.unset_handler();
    }
}

struct WmBase {
    f: Rc<Frames>,
}

impl XdgWmBaseHandler for WmBase {
    fn handle_get_xdg_surface(
        &mut self,
        slf: &Rc<XdgWmBase>,
        id: &Rc<XdgSurface>,
        surface: &Rc<WlSurface>,
    ) {
        slf.send_get_xdg_surface(id, surface);
        // Only a surface whose commits pass here can have its geometry kept
        // for its commit; any other (none should be) is passed on as it is.
        let mode = self.f.mode;
        let window = Rc::new_cyclic(|me| RefCell::new(Window::new(id, surface, me.clone(), mode)));
        let attached = match surface.try_get_handler_mut::<Surface>() {
            Ok(mut h) => {
                h.window = Some(window.clone());
                true
            }
            Err(_) => false,
        };
        if attached {
            id.set_handler(XdgSurfaceH {
                f: self.f.clone(),
                window,
            });
        }
    }

    fn handle_create_positioner(&mut self, slf: &Rc<XdgWmBase>, id: &Rc<XdgPositioner>) {
        slf.send_create_positioner(id);
        id.set_handler(Positioner::default());
    }
}

struct XdgSurfaceH {
    f: Rc<Frames>,
    window: Rc<RefCell<Window>>,
}

impl XdgSurfaceHandler for XdgSurfaceH {
    fn handle_set_window_geometry(
        &mut self,
        slf: &Rc<XdgSurface>,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
    ) {
        // An empty one is an error: the compositor's to raise, now.
        if width <= 0 || height <= 0 {
            slf.send_set_window_geometry(x, y, width, height);
            return;
        }
        match self.window.try_borrow_mut() {
            Ok(mut window) => {
                window.geometry = Some(Rect {
                    x,
                    y,
                    w: width,
                    h: height,
                })
            }
            Err(_) => slf.send_set_window_geometry(x, y, width, height),
        }
    }

    fn handle_get_toplevel(&mut self, slf: &Rc<XdgSurface>, id: &Rc<XdgToplevel>) {
        slf.send_get_toplevel(id);
        crate::wl_proxy::window_opened();
        if let Ok(mut window) = self.window.try_borrow_mut() {
            window.toplevel = Some(Rc::downgrade(id));
        }
        id.set_handler(Toplevel {
            f: self.f.clone(),
            window: self.window.clone(),
        });
    }

    fn handle_get_popup(
        &mut self,
        slf: &Rc<XdgSurface>,
        id: &Rc<XdgPopup>,
        parent: Option<&Rc<XdgSurface>>,
        positioner: &Rc<XdgPositioner>,
    ) {
        let i = parent.map_or(Insets::default(), |p| insets_of_xdg(&self.f, p));
        with_positioner_up(positioner, i, || slf.send_get_popup(id, parent, positioner));
        id.set_handler(Popup { i });
    }

    /// The compositor's configure of this surface: whether it says
    /// fullscreen (its toplevel's configure came just before) is kept by
    /// serial, until the program acks it.
    fn handle_configure(&mut self, slf: &Rc<XdgSurface>, serial: u32) {
        if let Ok(mut window) = self.window.try_borrow_mut() {
            let fullscreen = window.next_fullscreen;
            window.configures.push_back((serial, fullscreen));
            if window.configures.len() > MAX_CONFIGURES {
                window.configures.pop_front();
            }
        }
        slf.send_configure(serial);
    }

    /// The program acks a configure: its next commit is of that state, and
    /// of every one before it (xdg-shell).
    fn handle_ack_configure(&mut self, slf: &Rc<XdgSurface>, serial: u32) {
        slf.send_ack_configure(serial);
        if let Ok(mut window) = self.window.try_borrow_mut() {
            if let Some(at) = window.configures.iter().position(|(s, _)| *s == serial) {
                window.fullscreen = window.configures[at].1;
                window.configures.drain(..=at);
            }
        }
    }

    fn handle_destroy(&mut self, slf: &Rc<XdgSurface>) {
        slf.send_destroy();
        if let Ok(mut window) = self.window.try_borrow_mut() {
            window.drop_strips();
            if let Some(root) = window.root.upgrade() {
                if let Ok(mut h) = root.try_get_handler_mut::<Surface>() {
                    h.window = None;
                }
            }
        }
        slf.unset_handler();
    }
}

/// The frame of the window whose xdg_surface is `xdg` now (none when not
/// ours or not framed).
fn insets_of_xdg(f: &Frames, xdg: &Rc<XdgSurface>) -> Insets {
    xdg.try_get_handler_ref::<XdgSurfaceH>()
        .ok()
        .and_then(|h| h.window.try_borrow_mut().ok().map(|mut w| w.current(f)))
        .unwrap_or_default()
}

/// The frame of the window of `toplevel` now.
fn insets_of_toplevel(f: &Frames, toplevel: &Rc<XdgToplevel>) -> Insets {
    toplevel
        .try_get_handler_ref::<Toplevel>()
        .ok()
        .and_then(|h| h.window.try_borrow_mut().ok().map(|mut w| w.current(f)))
        .unwrap_or_default()
}

/// Send `call` (a popup made or moved on `positioner`) with the positioner's
/// anchor rect and parent size translated into the compositor's geometry of
/// a parent with the frame `i`, and put them back after: the positioner's
/// state is copied when it is used, and the program may use it again
/// elsewhere.
fn with_positioner_up(positioner: &Rc<XdgPositioner>, i: Insets, call: impl FnOnce()) {
    let state = if i != Insets::default() {
        positioner
            .try_get_handler_ref::<Positioner>()
            .ok()
            .map(|p| (p.anchor, p.parent_size))
    } else {
        None
    };
    let Some((anchor, parent_size)) = state else {
        call();
        return;
    };
    if let Some(a) = anchor {
        positioner.send_set_anchor_rect(point_up(a.x, i.border), point_up(a.y, i.top()), a.w, a.h);
    }
    if let Some((w, h)) = parent_size {
        positioner.send_set_parent_size(size_up(w, i.across()), size_up(h, i.down()));
    }
    call();
    if let Some(a) = anchor {
        positioner.send_set_anchor_rect(a.x, a.y, a.w, a.h);
    }
    if let Some((w, h)) = parent_size {
        positioner.send_set_parent_size(w, h);
    }
}

struct Toplevel {
    f: Rc<Frames>,
    window: Rc<RefCell<Window>>,
}

impl Toplevel {
    /// The frame of the window in a state `fullscreen` or not.
    fn insets(&self, fullscreen: bool) -> Insets {
        self.window
            .try_borrow_mut()
            .map_or(Insets::default(), |mut w| w.insets(&self.f, fullscreen))
    }

    /// The frame of the window now.
    fn current(&self) -> Insets {
        self.window
            .try_borrow_mut()
            .map_or(Insets::default(), |mut w| w.current(&self.f))
    }
}

/// Whether a configure's states (an array of u32) hold `state`.
fn has_state(states: &[u8], state: u32) -> bool {
    states
        .as_chunks::<4>()
        .0
        .iter()
        .any(|word| u32::from_ne_bytes(*word) == state)
}

impl XdgToplevelHandler for Toplevel {
    /// The size less the frame of the state this configure asks for: in
    /// fullscreen the title strip takes no room (§5.7), so the program is
    /// told the output less the border only.
    fn handle_configure(&mut self, slf: &Rc<XdgToplevel>, width: i32, height: i32, states: &[u8]) {
        let fullscreen = has_state(states, FULLSCREEN);
        if let Ok(mut window) = self.window.try_borrow_mut() {
            window.configured(fullscreen);
        }
        let i = self.insets(fullscreen);
        slf.send_configure(
            size_down(width, i.across()),
            size_down(height, i.down()),
            states,
        );
    }

    /// The bounds of a window that is not fullscreen.
    fn handle_configure_bounds(&mut self, slf: &Rc<XdgToplevel>, width: i32, height: i32) {
        let i = self.insets(false);
        slf.send_configure_bounds(size_down(width, i.across()), size_down(height, i.down()));
    }

    fn handle_set_min_size(&mut self, slf: &Rc<XdgToplevel>, width: i32, height: i32) {
        match self.window.try_borrow_mut() {
            Ok(mut window) if width >= 0 && height >= 0 => window.min = Some((width, height)),
            // A negative one is an error: the compositor's to raise, now.
            _ => slf.send_set_min_size(width, height),
        }
    }

    fn handle_set_max_size(&mut self, slf: &Rc<XdgToplevel>, width: i32, height: i32) {
        match self.window.try_borrow_mut() {
            Ok(mut window) if width >= 0 && height >= 0 => window.max = Some((width, height)),
            _ => slf.send_set_max_size(width, height),
        }
    }

    fn handle_show_window_menu(
        &mut self,
        slf: &Rc<XdgToplevel>,
        seat: &Rc<WlSeat>,
        serial: u32,
        x: i32,
        y: i32,
    ) {
        let i = self.current();
        slf.send_show_window_menu(seat, serial, point_up(x, i.border), point_up(y, i.top()));
    }

    fn handle_destroy(&mut self, slf: &Rc<XdgToplevel>) {
        slf.send_destroy();
        if let Ok(mut window) = self.window.try_borrow_mut() {
            window.drop_strips();
            window.toplevel = None;
        }
        slf.unset_handler();
    }
}

/// A positioner's state that is relative to the parent's geometry.
#[derive(Default)]
struct Positioner {
    anchor: Option<Rect>,
    parent_size: Option<(i32, i32)>,
}

impl XdgPositionerHandler for Positioner {
    fn handle_set_anchor_rect(
        &mut self,
        slf: &Rc<XdgPositioner>,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
    ) {
        slf.send_set_anchor_rect(x, y, width, height);
        self.anchor = Some(Rect {
            x,
            y,
            w: width,
            h: height,
        });
    }

    fn handle_set_parent_size(
        &mut self,
        slf: &Rc<XdgPositioner>,
        parent_width: i32,
        parent_height: i32,
    ) {
        slf.send_set_parent_size(parent_width, parent_height);
        self.parent_size = Some((parent_width, parent_height));
    }
}

/// A popup, with the frame of its parent when it was made (none when the
/// parent has none).
struct Popup {
    i: Insets,
}

impl XdgPopupHandler for Popup {
    fn handle_configure(&mut self, slf: &Rc<XdgPopup>, x: i32, y: i32, width: i32, height: i32) {
        slf.send_configure(
            point_down(x, self.i.border),
            point_down(y, self.i.top()),
            width,
            height,
        );
    }

    fn handle_reposition(
        &mut self,
        slf: &Rc<XdgPopup>,
        positioner: &Rc<XdgPositioner>,
        token: u32,
    ) {
        with_positioner_up(positioner, self.i, || {
            slf.send_reposition(positioner, token)
        });
    }

    fn handle_destroy(&mut self, slf: &Rc<XdgPopup>) {
        slf.send_destroy();
        slf.unset_handler();
    }
}

struct DragManager {
    f: Rc<Frames>,
}

impl XdgToplevelDragManagerV1Handler for DragManager {
    fn handle_get_xdg_toplevel_drag(
        &mut self,
        slf: &Rc<XdgToplevelDragManagerV1>,
        id: &Rc<XdgToplevelDragV1>,
        data_source: &Rc<WlDataSource>,
    ) {
        slf.send_get_xdg_toplevel_drag(id, data_source);
        id.set_handler(Drag { f: self.f.clone() });
    }
}

struct Drag {
    f: Rc<Frames>,
}

impl XdgToplevelDragV1Handler for Drag {
    fn handle_attach(
        &mut self,
        slf: &Rc<XdgToplevelDragV1>,
        toplevel: &Rc<XdgToplevel>,
        x_offset: i32,
        y_offset: i32,
    ) {
        let i = insets_of_toplevel(&self.f, toplevel);
        slf.send_attach(
            toplevel,
            point_up(x_offset, i.border),
            point_up(y_offset, i.top()),
        );
    }
}

// --- THE SIZE OF A BUFFER -----------------------------------------------------
// Only for a window without a geometry of its own: its root surface's size is
// its buffer's. Kept on the buffer as its handler, so it goes with it.

struct BufferSize {
    width: i32,
    height: i32,
}

impl WlBufferHandler for BufferSize {}

fn sized(buffer: &Rc<WlBuffer>, width: i32, height: i32) {
    buffer.set_handler(BufferSize { width, height });
}

struct Shm;

impl WlShmHandler for Shm {
    fn handle_create_pool(
        &mut self,
        slf: &Rc<WlShm>,
        id: &Rc<WlShmPool>,
        fd: &Rc<OwnedFd>,
        size: i32,
    ) {
        slf.send_create_pool(id, fd, size);
        id.set_handler(Pool);
    }
}

struct Pool;

impl WlShmPoolHandler for Pool {
    fn handle_create_buffer(
        &mut self,
        slf: &Rc<WlShmPool>,
        id: &Rc<WlBuffer>,
        offset: i32,
        width: i32,
        height: i32,
        stride: i32,
        format: WlShmFormat,
    ) {
        slf.send_create_buffer(id, offset, width, height, stride, format);
        sized(id, width, height);
    }
}

struct Dmabuf;

impl ZwpLinuxDmabufV1Handler for Dmabuf {
    fn handle_create_params(
        &mut self,
        slf: &Rc<ZwpLinuxDmabufV1>,
        params_id: &Rc<ZwpLinuxBufferParamsV1>,
    ) {
        slf.send_create_params(params_id);
        params_id.set_handler(Params::default());
    }
}

#[derive(Default)]
struct Params {
    size: Option<(i32, i32)>,
}

impl ZwpLinuxBufferParamsV1Handler for Params {
    fn handle_create(
        &mut self,
        slf: &Rc<ZwpLinuxBufferParamsV1>,
        width: i32,
        height: i32,
        format: u32,
        flags: ZwpLinuxBufferParamsV1Flags,
    ) {
        slf.send_create(width, height, format, flags);
        self.size = Some((width, height));
    }

    fn handle_created(&mut self, slf: &Rc<ZwpLinuxBufferParamsV1>, buffer: &Rc<WlBuffer>) {
        slf.send_created(buffer);
        if let Some((w, h)) = self.size {
            sized(buffer, w, h);
        }
    }

    fn handle_create_immed(
        &mut self,
        slf: &Rc<ZwpLinuxBufferParamsV1>,
        buffer_id: &Rc<WlBuffer>,
        width: i32,
        height: i32,
        format: u32,
        flags: ZwpLinuxBufferParamsV1Flags,
    ) {
        slf.send_create_immed(buffer_id, width, height, format, flags);
        sized(buffer_id, width, height);
    }
}

struct Drm;

impl WlDrmHandler for Drm {
    fn handle_create_buffer(
        &mut self,
        slf: &Rc<WlDrm>,
        id: &Rc<WlBuffer>,
        name: u32,
        width: i32,
        height: i32,
        stride: u32,
        format: u32,
    ) {
        slf.send_create_buffer(id, name, width, height, stride, format);
        sized(id, width, height);
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_create_planar_buffer(
        &mut self,
        slf: &Rc<WlDrm>,
        id: &Rc<WlBuffer>,
        name: u32,
        width: i32,
        height: i32,
        format: u32,
        offset0: i32,
        stride0: i32,
        offset1: i32,
        stride1: i32,
        offset2: i32,
        stride2: i32,
    ) {
        slf.send_create_planar_buffer(
            id, name, width, height, format, offset0, stride0, offset1, stride1, offset2, stride2,
        );
        sized(id, width, height);
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_create_prime_buffer(
        &mut self,
        slf: &Rc<WlDrm>,
        id: &Rc<WlBuffer>,
        name: &Rc<OwnedFd>,
        width: i32,
        height: i32,
        format: u32,
        offset0: i32,
        stride0: i32,
        offset1: i32,
        stride1: i32,
        offset2: i32,
        stride2: i32,
    ) {
        slf.send_create_prime_buffer(
            id, name, width, height, format, offset0, stride0, offset1, stride1, offset2, stride2,
        );
        sized(id, width, height);
    }
}

struct SinglePixel;

impl WpSinglePixelBufferManagerV1Handler for SinglePixel {
    fn handle_create_u32_rgba_buffer(
        &mut self,
        slf: &Rc<WpSinglePixelBufferManagerV1>,
        id: &Rc<WlBuffer>,
        r: u32,
        g: u32,
        b: u32,
        a: u32,
    ) {
        slf.send_create_u32_rgba_buffer(id, r, g, b, a);
        sized(id, 1, 1);
    }
}

struct Viewporter;

impl WpViewporterHandler for Viewporter {
    fn handle_get_viewport(
        &mut self,
        slf: &Rc<WpViewporter>,
        id: &Rc<WpViewport>,
        surface: &Rc<WlSurface>,
    ) {
        slf.send_get_viewport(id, surface);
        id.set_handler(Viewport {
            surface: Rc::downgrade(surface),
        });
    }
}

/// The program's viewport on one of its surfaces: part of the surface's size.
struct Viewport {
    surface: Weak<WlSurface>,
}

impl Viewport {
    fn pending(&self, f: impl FnOnce(&mut Pending)) {
        if let Some(surface) = self.surface.upgrade() {
            if let Ok(mut h) = surface.try_get_handler_mut::<Surface>() {
                f(&mut h.pending);
            }
        }
    }
}

impl WpViewportHandler for Viewport {
    fn handle_set_destination(&mut self, slf: &Rc<WpViewport>, width: i32, height: i32) {
        slf.send_set_destination(width, height);
        let destination = (width > 0 && height > 0).then_some((width, height));
        self.pending(|p| p.destination = Some(destination));
    }

    fn handle_set_source(
        &mut self,
        slf: &Rc<WpViewport>,
        x: Fixed,
        y: Fixed,
        width: Fixed,
        height: Fixed,
    ) {
        slf.send_set_source(x, y, width, height);
        let (w, h) = (width.to_f64(), height.to_f64());
        let source = (w > 0.0 && h > 0.0).then(|| (w.ceil() as i32, h.ceil() as i32));
        self.pending(|p| p.source = Some(source));
    }

    fn handle_destroy(&mut self, slf: &Rc<WpViewport>) {
        slf.send_destroy();
        self.pending(|p| {
            p.destination = Some(None);
            p.source = Some(None);
        });
        slf.unset_handler();
    }
}

// --- INPUT ON THE BORDER --------------------------------------------------------

struct Seat;

impl WlSeatHandler for Seat {
    fn handle_get_pointer(&mut self, slf: &Rc<WlSeat>, id: &Rc<WlPointer>) {
        slf.send_get_pointer(id);
        id.set_handler(Pointer::default());
    }

    fn handle_get_touch(&mut self, slf: &Rc<WlSeat>, id: &Rc<WlTouch>) {
        slf.send_get_touch(id);
        id.set_handler(Touch::default());
    }
}

/// The program's pointer. While the pointer is over a strip (`away`), every
/// event of it is dropped; a `frame` is passed only when something of its
/// group was — leaving the program's surface for a strip is a `leave` and a
/// `frame` to the program, and nothing after.
///
/// It is also what brings a hover title out (§0а, [`hover_at`]): the
/// compositor sends a client's pointer events to every `wl_pointer` of it,
/// so the proxy sees the pointer over the program's windows and over its
/// own strips on the program's pointer. (A program that binds no pointer
/// has no hover title; the proxy's own pointer is stage 3's.)
#[derive(Default)]
struct Pointer {
    away: bool,
    sent: bool,
    /// The window whose root surface the pointer is on.
    on: Option<Weak<RefCell<Window>>>,
    /// The window the pointer left in this frame: its hover strip goes in
    /// unless the pointer is back on it by the frame's end.
    leaving: Option<Weak<RefCell<Window>>>,
}

/// Where on a window the pointer is.
#[derive(PartialEq, Eq)]
enum Spot {
    /// The program's root surface.
    Root,
    /// The top strip of the border or the title strip.
    Top,
    /// Another strip of the border.
    Side,
}

/// The window `surface` belongs to, and where on it: the program's root
/// surface of a window, or a surface of the proxy's.
fn spot(surface: &Rc<WlSurface>) -> Option<(Rc<RefCell<Window>>, Spot)> {
    if let Ok(own) = surface.try_get_handler_ref::<Mine>() {
        let spot = if own.part == Part::Side {
            Spot::Side
        } else {
            Spot::Top
        };
        return own.window.upgrade().map(|w| (w, spot));
    }
    let h = surface.try_get_handler_ref::<Surface>().ok()?;
    h.window.clone().map(|w| (w, Spot::Root))
}

fn set_hover(window: &Rc<RefCell<Window>>, on: bool) {
    if let Ok(mut window) = window.try_borrow_mut() {
        window.set_hover(on);
    }
}

impl Pointer {
    fn pass(&mut self, send: impl FnOnce()) {
        if !self.away {
            send();
            self.sent = true;
        }
    }

    /// The pointer came onto `surface` at `y`.
    fn hover_enter(&mut self, surface: &Rc<WlSurface>, y: Fixed) {
        let target = spot(surface);
        let want = match &target {
            Some((_, Spot::Top)) => Some(true),
            Some((_, Spot::Side)) => Some(false),
            Some((window, Spot::Root)) => window
                .try_borrow()
                .ok()
                .and_then(|w| w.area())
                .and_then(|g| hover_at(g, y.to_f64())),
            None => None,
        };
        if let Some(left) = self.leaving.take().and_then(|w| w.upgrade()) {
            let back = target.as_ref().is_some_and(|(w, _)| Rc::ptr_eq(w, &left));
            if !back || want == Some(false) {
                set_hover(&left, false);
            }
        }
        if let (Some((window, _)), Some(on)) = (&target, want) {
            set_hover(window, on);
        }
        self.on = match target {
            Some((window, Spot::Root)) => Some(Rc::downgrade(&window)),
            _ => None,
        };
    }

    /// The pointer left `surface`: its window's hover strip goes in at the
    /// end of the frame, unless the pointer is back on the window by then —
    /// at once for a pointer without frames (before `wl_pointer` v5).
    fn hover_leave(&mut self, slf: &Rc<WlPointer>, surface: &Rc<WlSurface>) {
        self.on = None;
        if let Some((window, spot)) = spot(surface) {
            if spot == Spot::Side {
                return;
            }
            if slf.version() >= 5 {
                self.leaving = Some(Rc::downgrade(&window));
            } else {
                set_hover(&window, false);
            }
        }
    }

    /// The end of a frame: a window left and not come back to.
    fn hover_frame(&mut self) {
        if let Some(left) = self.leaving.take().and_then(|w| w.upgrade()) {
            set_hover(&left, false);
        }
    }

    /// The pointer moved on the program's root surface to `y`.
    fn hover_motion(&mut self, y: Fixed) {
        let Some(window) = self.on.as_ref().and_then(Weak::upgrade) else {
            return;
        };
        let want = window
            .try_borrow()
            .ok()
            .and_then(|w| w.area())
            .and_then(|g| hover_at(g, y.to_f64()));
        if let Some(on) = want {
            set_hover(&window, on);
        }
    }
}

impl WlPointerHandler for Pointer {
    fn handle_enter(
        &mut self,
        slf: &Rc<WlPointer>,
        serial: u32,
        surface: &Rc<WlSurface>,
        surface_x: Fixed,
        surface_y: Fixed,
    ) {
        self.hover_enter(surface, surface_y);
        self.away = !programs(surface);
        self.pass(|| slf.send_enter(serial, surface, surface_x, surface_y));
    }

    fn handle_leave(&mut self, slf: &Rc<WlPointer>, serial: u32, surface: &Rc<WlSurface>) {
        self.hover_leave(slf, surface);
        if programs(surface) {
            self.away = false;
            self.pass(|| slf.send_leave(serial, surface));
        } else {
            self.away = false;
        }
    }

    fn handle_motion(
        &mut self,
        slf: &Rc<WlPointer>,
        time: u32,
        surface_x: Fixed,
        surface_y: Fixed,
    ) {
        self.hover_motion(surface_y);
        self.pass(|| slf.send_motion(time, surface_x, surface_y));
    }

    fn handle_button(
        &mut self,
        slf: &Rc<WlPointer>,
        serial: u32,
        time: u32,
        button: u32,
        state: WlPointerButtonState,
    ) {
        self.pass(|| slf.send_button(serial, time, button, state));
    }

    fn handle_axis(&mut self, slf: &Rc<WlPointer>, time: u32, axis: WlPointerAxis, value: Fixed) {
        self.pass(|| slf.send_axis(time, axis, value));
    }

    fn handle_frame(&mut self, slf: &Rc<WlPointer>) {
        self.hover_frame();
        if std::mem::take(&mut self.sent) {
            slf.send_frame();
        }
    }

    fn handle_axis_source(&mut self, slf: &Rc<WlPointer>, axis_source: WlPointerAxisSource) {
        self.pass(|| slf.send_axis_source(axis_source));
    }

    fn handle_axis_stop(&mut self, slf: &Rc<WlPointer>, time: u32, axis: WlPointerAxis) {
        self.pass(|| slf.send_axis_stop(time, axis));
    }

    fn handle_axis_discrete(&mut self, slf: &Rc<WlPointer>, axis: WlPointerAxis, discrete: i32) {
        self.pass(|| slf.send_axis_discrete(axis, discrete));
    }

    fn handle_axis_value120(&mut self, slf: &Rc<WlPointer>, axis: WlPointerAxis, value120: i32) {
        self.pass(|| slf.send_axis_value120(axis, value120));
    }

    fn handle_axis_relative_direction(
        &mut self,
        slf: &Rc<WlPointer>,
        axis: WlPointerAxis,
        direction: WlPointerAxisRelativeDirection,
    ) {
        self.pass(|| slf.send_axis_relative_direction(axis, direction));
    }

    fn handle_warp(&mut self, slf: &Rc<WlPointer>, surface_x: Fixed, surface_y: Fixed) {
        self.pass(|| slf.send_warp(surface_x, surface_y));
    }
}

/// The program's touch: a touch point that went down on a strip is dropped
/// until it goes up; a `frame` passes when something of its group did.
#[derive(Default)]
struct Touch {
    away: HashSet<i32>,
    sent: bool,
}

impl Touch {
    fn pass(&mut self, id: i32, send: impl FnOnce()) {
        if !self.away.contains(&id) {
            send();
            self.sent = true;
        }
    }
}

impl WlTouchHandler for Touch {
    fn handle_down(
        &mut self,
        slf: &Rc<WlTouch>,
        serial: u32,
        time: u32,
        surface: &Rc<WlSurface>,
        id: i32,
        x: Fixed,
        y: Fixed,
    ) {
        if programs(surface) {
            self.away.remove(&id);
            self.pass(id, || slf.send_down(serial, time, surface, id, x, y));
        } else {
            self.away.insert(id);
        }
    }

    fn handle_up(&mut self, slf: &Rc<WlTouch>, serial: u32, time: u32, id: i32) {
        self.pass(id, || slf.send_up(serial, time, id));
        self.away.remove(&id);
    }

    fn handle_motion(&mut self, slf: &Rc<WlTouch>, time: u32, id: i32, x: Fixed, y: Fixed) {
        self.pass(id, || slf.send_motion(time, id, x, y));
    }

    fn handle_shape(&mut self, slf: &Rc<WlTouch>, id: i32, major: Fixed, minor: Fixed) {
        self.pass(id, || slf.send_shape(id, major, minor));
    }

    fn handle_orientation(&mut self, slf: &Rc<WlTouch>, id: i32, orientation: Fixed) {
        self.pass(id, || slf.send_orientation(id, orientation));
    }

    fn handle_frame(&mut self, slf: &Rc<WlTouch>) {
        if std::mem::take(&mut self.sent) {
            slf.send_frame();
        }
    }

    fn handle_cancel(&mut self, slf: &Rc<WlTouch>) {
        // Every touch point is over; the program's are its news.
        self.away.clear();
        self.sent = false;
        slf.send_cancel();
    }
}

struct Gestures;

impl ZwpPointerGesturesV1Handler for Gestures {
    fn handle_get_swipe_gesture(
        &mut self,
        slf: &Rc<ZwpPointerGesturesV1>,
        id: &Rc<ZwpPointerGestureSwipeV1>,
        pointer: &Rc<WlPointer>,
    ) {
        slf.send_get_swipe_gesture(id, pointer);
        id.set_handler(Gesture::default());
    }

    fn handle_get_pinch_gesture(
        &mut self,
        slf: &Rc<ZwpPointerGesturesV1>,
        id: &Rc<ZwpPointerGesturePinchV1>,
        pointer: &Rc<WlPointer>,
    ) {
        slf.send_get_pinch_gesture(id, pointer);
        id.set_handler(Gesture::default());
    }

    fn handle_get_hold_gesture(
        &mut self,
        slf: &Rc<ZwpPointerGesturesV1>,
        id: &Rc<ZwpPointerGestureHoldV1>,
        pointer: &Rc<WlPointer>,
    ) {
        slf.send_get_hold_gesture(id, pointer);
        id.set_handler(Gesture::default());
    }
}

/// A gesture begun on a strip is dropped to its end.
#[derive(Default)]
struct Gesture {
    away: bool,
}

impl ZwpPointerGestureSwipeV1Handler for Gesture {
    fn handle_begin(
        &mut self,
        slf: &Rc<ZwpPointerGestureSwipeV1>,
        serial: u32,
        time: u32,
        surface: &Rc<WlSurface>,
        fingers: u32,
    ) {
        self.away = !programs(surface);
        if !self.away {
            slf.send_begin(serial, time, surface, fingers);
        }
    }

    fn handle_update(
        &mut self,
        slf: &Rc<ZwpPointerGestureSwipeV1>,
        time: u32,
        dx: Fixed,
        dy: Fixed,
    ) {
        if !self.away {
            slf.send_update(time, dx, dy);
        }
    }

    fn handle_end(
        &mut self,
        slf: &Rc<ZwpPointerGestureSwipeV1>,
        serial: u32,
        time: u32,
        cancelled: i32,
    ) {
        if !std::mem::take(&mut self.away) {
            slf.send_end(serial, time, cancelled);
        }
    }
}

impl ZwpPointerGesturePinchV1Handler for Gesture {
    fn handle_begin(
        &mut self,
        slf: &Rc<ZwpPointerGesturePinchV1>,
        serial: u32,
        time: u32,
        surface: &Rc<WlSurface>,
        fingers: u32,
    ) {
        self.away = !programs(surface);
        if !self.away {
            slf.send_begin(serial, time, surface, fingers);
        }
    }

    fn handle_update(
        &mut self,
        slf: &Rc<ZwpPointerGesturePinchV1>,
        time: u32,
        dx: Fixed,
        dy: Fixed,
        scale: Fixed,
        rotation: Fixed,
    ) {
        if !self.away {
            slf.send_update(time, dx, dy, scale, rotation);
        }
    }

    fn handle_end(
        &mut self,
        slf: &Rc<ZwpPointerGesturePinchV1>,
        serial: u32,
        time: u32,
        cancelled: i32,
    ) {
        if !std::mem::take(&mut self.away) {
            slf.send_end(serial, time, cancelled);
        }
    }
}

impl ZwpPointerGestureHoldV1Handler for Gesture {
    fn handle_begin(
        &mut self,
        slf: &Rc<ZwpPointerGestureHoldV1>,
        serial: u32,
        time: u32,
        surface: &Rc<WlSurface>,
        fingers: u32,
    ) {
        self.away = !programs(surface);
        if !self.away {
            slf.send_begin(serial, time, surface, fingers);
        }
    }

    fn handle_end(
        &mut self,
        slf: &Rc<ZwpPointerGestureHoldV1>,
        serial: u32,
        time: u32,
        cancelled: i32,
    ) {
        if !std::mem::take(&mut self.away) {
            slf.send_end(serial, time, cancelled);
        }
    }
}

struct TabletManager;

impl ZwpTabletManagerV2Handler for TabletManager {
    fn handle_get_tablet_seat(
        &mut self,
        slf: &Rc<ZwpTabletManagerV2>,
        tablet_seat: &Rc<ZwpTabletSeatV2>,
        seat: &Rc<WlSeat>,
    ) {
        slf.send_get_tablet_seat(tablet_seat, seat);
        tablet_seat.set_handler(TabletSeat);
    }
}

struct TabletSeat;

impl ZwpTabletSeatV2Handler for TabletSeat {
    fn handle_tool_added(&mut self, slf: &Rc<ZwpTabletSeatV2>, id: &Rc<ZwpTabletToolV2>) {
        slf.send_tool_added(id);
        id.set_handler(Tool::default());
    }
}

/// A tablet tool near a strip: everything of it is dropped until it leaves,
/// a `frame` passes when something of its group did.
#[derive(Default)]
struct Tool {
    away: bool,
    sent: bool,
}

impl Tool {
    fn pass(&mut self, send: impl FnOnce()) {
        if !self.away {
            send();
            self.sent = true;
        }
    }
}

impl ZwpTabletToolV2Handler for Tool {
    fn handle_proximity_in(
        &mut self,
        slf: &Rc<ZwpTabletToolV2>,
        serial: u32,
        tablet: &Rc<ZwpTabletV2>,
        surface: &Rc<WlSurface>,
    ) {
        self.away = !programs(surface);
        self.pass(|| slf.send_proximity_in(serial, tablet, surface));
    }

    fn handle_proximity_out(&mut self, slf: &Rc<ZwpTabletToolV2>) {
        self.pass(|| slf.send_proximity_out());
        self.away = false;
    }

    fn handle_down(&mut self, slf: &Rc<ZwpTabletToolV2>, serial: u32) {
        self.pass(|| slf.send_down(serial));
    }

    fn handle_up(&mut self, slf: &Rc<ZwpTabletToolV2>) {
        self.pass(|| slf.send_up());
    }

    fn handle_motion(&mut self, slf: &Rc<ZwpTabletToolV2>, x: Fixed, y: Fixed) {
        self.pass(|| slf.send_motion(x, y));
    }

    fn handle_pressure(&mut self, slf: &Rc<ZwpTabletToolV2>, pressure: u32) {
        self.pass(|| slf.send_pressure(pressure));
    }

    fn handle_distance(&mut self, slf: &Rc<ZwpTabletToolV2>, distance: u32) {
        self.pass(|| slf.send_distance(distance));
    }

    fn handle_tilt(&mut self, slf: &Rc<ZwpTabletToolV2>, tilt_x: Fixed, tilt_y: Fixed) {
        self.pass(|| slf.send_tilt(tilt_x, tilt_y));
    }

    fn handle_rotation(&mut self, slf: &Rc<ZwpTabletToolV2>, degrees: Fixed) {
        self.pass(|| slf.send_rotation(degrees));
    }

    fn handle_slider(&mut self, slf: &Rc<ZwpTabletToolV2>, position: i32) {
        self.pass(|| slf.send_slider(position));
    }

    fn handle_wheel(&mut self, slf: &Rc<ZwpTabletToolV2>, degrees: Fixed, clicks: i32) {
        self.pass(|| slf.send_wheel(degrees, clicks));
    }

    fn handle_button(
        &mut self,
        slf: &Rc<ZwpTabletToolV2>,
        serial: u32,
        button: u32,
        state: ZwpTabletToolV2ButtonState,
    ) {
        self.pass(|| slf.send_button(serial, button, state));
    }

    fn handle_frame(&mut self, slf: &Rc<ZwpTabletToolV2>, time: u32) {
        if std::mem::take(&mut self.sent) {
            slf.send_frame(time);
        }
    }
}

struct DataDeviceManager;

impl WlDataDeviceManagerHandler for DataDeviceManager {
    fn handle_get_data_device(
        &mut self,
        slf: &Rc<WlDataDeviceManager>,
        id: &Rc<WlDataDevice>,
        seat: &Rc<WlSeat>,
    ) {
        slf.send_get_data_device(id, seat);
        id.set_handler(DataDevice::default());
    }
}

/// A drag over a strip is not over the program: its enter, motion, leave and
/// drop are dropped. (The offer announced before the enter has already gone
/// to the program; unused, it is harmless.)
#[derive(Default)]
struct DataDevice {
    away: bool,
}

impl WlDataDeviceHandler for DataDevice {
    fn handle_enter(
        &mut self,
        slf: &Rc<WlDataDevice>,
        serial: u32,
        surface: &Rc<WlSurface>,
        x: Fixed,
        y: Fixed,
        id: Option<&Rc<WlDataOffer>>,
    ) {
        self.away = !programs(surface);
        if !self.away {
            slf.send_enter(serial, surface, x, y, id);
        }
    }

    fn handle_leave(&mut self, slf: &Rc<WlDataDevice>) {
        if !std::mem::take(&mut self.away) {
            slf.send_leave();
        }
    }

    fn handle_motion(&mut self, slf: &Rc<WlDataDevice>, time: u32, x: Fixed, y: Fixed) {
        if !self.away {
            slf.send_motion(time, x, y);
        }
    }

    fn handle_drop(&mut self, slf: &Rc<WlDataDevice>) {
        if !std::mem::take(&mut self.away) {
            slf.send_drop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const R: Rect = Rect {
        x: 26,
        y: 23,
        w: 640,
        h: 480,
    };

    /// The border alone, 4 wide.
    const B: Insets = Insets {
        border: 4,
        title: 0,
    };
    /// The border and the title strip under it.
    const BT: Insets = Insets {
        border: 4,
        title: TITLE_HEIGHT,
    };

    #[test]
    fn the_geometry_grows_by_the_frame() {
        assert_eq!(
            geometry_up(R, B),
            Rect {
                x: 22,
                y: 19,
                w: 648,
                h: 488
            }
        );
        // The title strip is taken at the top only.
        assert_eq!(
            geometry_up(R, BT),
            Rect {
                x: 22,
                y: 23 - 4 - TITLE_HEIGHT,
                w: 648,
                h: 488 + TITLE_HEIGHT
            }
        );
        assert_eq!(geometry_up(R, Insets::default()), R, "no frame, no change");
        // Nonsense stays nonsense instead of wrapping.
        let edge = Rect {
            x: i32::MIN,
            y: 0,
            w: i32::MAX,
            h: 1,
        };
        let up = geometry_up(edge, BT);
        assert_eq!((up.x, up.w), (i32::MIN, i32::MAX));
        assert_eq!((B.top(), B.across(), B.down()), (4, 8, 8));
        assert_eq!(
            (BT.top(), BT.across(), BT.down()),
            (4 + TITLE_HEIGHT, 8, 8 + TITLE_HEIGHT)
        );
    }

    #[test]
    fn configure_takes_the_frame_off_and_leaves_zero_alone() {
        assert_eq!(size_down(800, 8), 792);
        assert_eq!(size_down(0, 8), 0, "0 is \"you decide\"");
        assert_eq!(size_down(8, 8), 1, "never 0 by subtraction");
        assert_eq!(size_down(5, 8), 1);
        assert_eq!(size_down(800, 0), 800);
        assert_eq!(
            size_down(-1, 8),
            -1,
            "the compositor's nonsense is passed on"
        );
        // Limits go the other way; 0 is "no limit".
        assert_eq!(size_up(300, 8), 308);
        assert_eq!(size_up(0, 8), 0);
        assert_eq!(size_up(i32::MAX, 8), i32::MAX);
        assert_eq!((point_up(10, 4), point_down(10, 4)), (14, 6));
        assert_eq!((point_up(10, 0), point_down(10, 0)), (10, 10));
    }

    /// What a compositor sizes is what it gets: the program, told the size
    /// left inside the frame, sets a geometry of that size; grown by the
    /// frame it is the compositor's size again, and the border's strips and
    /// the title strip fill exactly the band between.
    #[test]
    fn a_configured_window_is_exactly_the_size_the_compositor_asked_for() {
        for b in [1, 4, 7, 32] {
            for title in [0, TITLE_HEIGHT] {
                let i = Insets { border: b, title };
                for (w, h) in [(800, 600), (1920, 1080), (2 * b + 1, 2 * b + title + 1)] {
                    let program = Rect {
                        x: 10,
                        y: 20,
                        w: size_down(w, i.across()),
                        h: size_down(h, i.down()),
                    };
                    let up = geometry_up(program, i);
                    assert_eq!((up.w, up.h), (w, h), "{i:?}");
                    let mut parts = strips(program, i).to_vec();
                    parts.extend(title_strip(program, i, false));
                    assert_eq!(parts.len(), if title > 0 { 5 } else { 4 });
                    // They tile the band: their area is the difference.
                    let area: i64 = parts.iter().map(|r| r.w as i64 * r.h as i64).sum();
                    assert_eq!(
                        area,
                        w as i64 * h as i64 - program.w as i64 * program.h as i64,
                        "{i:?}"
                    );
                    // And every part is inside the compositor's geometry,
                    // none inside the program's, none over another.
                    let overlap = |a: &Rect, r: &Rect| {
                        a.x < r.x + r.w && a.x + a.w > r.x && a.y < r.y + r.h && a.y + a.h > r.y
                    };
                    for (n, r) in parts.iter().enumerate() {
                        assert!(r.x >= up.x && r.y >= up.y, "{r:?}");
                        assert!(
                            r.x + r.w <= up.x + up.w && r.y + r.h <= up.y + up.h,
                            "{r:?}"
                        );
                        assert!(!overlap(r, &program), "{r:?} overlaps the program");
                        for other in &parts[n + 1..] {
                            assert!(!overlap(r, other), "{r:?} overlaps {other:?}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn the_strips_are_where_the_border_is() {
        let [top, bottom, left, right] = strips(R, B);
        assert_eq!(
            top,
            Rect {
                x: 22,
                y: 19,
                w: 648,
                h: 4
            }
        );
        assert_eq!(
            bottom,
            Rect {
                x: 22,
                y: 503,
                w: 648,
                h: 4
            }
        );
        assert_eq!(
            left,
            Rect {
                x: 22,
                y: 23,
                w: 4,
                h: 480
            }
        );
        assert_eq!(
            right,
            Rect {
                x: 666,
                y: 23,
                w: 4,
                h: 480
            }
        );
        assert_eq!(title_strip(R, B, false), None, "no strip, no room");
    }

    /// The title strip: under the top border, between the side strips, the
    /// program's width; or, hovering, over the top of the program's content.
    #[test]
    fn the_title_strip_is_under_the_top_border_or_over_the_content() {
        let [top, _, left, right] = strips(R, BT);
        let strip = title_strip(R, BT, false).unwrap();
        assert_eq!(
            strip,
            Rect {
                x: 26,
                y: 23 - TITLE_HEIGHT,
                w: 640,
                h: TITLE_HEIGHT
            }
        );
        assert_eq!(top.y + top.h, strip.y, "right under the top border");
        assert_eq!(strip.y + strip.h, R.y, "right above the program");
        assert_eq!((left.x + left.w, right.x), (strip.x, strip.x + strip.w));
        assert_eq!((left.y, left.h), (strip.y, R.h + TITLE_HEIGHT));
        // Hovering, it takes no room: over the program, never taller.
        assert_eq!(
            title_strip(R, B, true),
            Some(Rect {
                x: 26,
                y: 23,
                w: 640,
                h: TITLE_HEIGHT
            })
        );
        let low = Rect { h: 5, ..R };
        assert_eq!(title_strip(low, B, true).unwrap().h, 5);
        assert_eq!(
            title_strip(R, Insets::default(), true),
            None,
            "no frame, no strip"
        );
    }

    /// The text: the whole line after the pad when it fits, else what fits
    /// with the pad at both ends; the viewport cuts the same share of its
    /// buffer, at any scale.
    #[test]
    fn the_text_is_cut_to_the_strip() {
        assert_eq!(text_shown(640, 120), 120);
        assert_eq!(text_shown(100, 120), 100 - 2 * TITLE_PAD);
        assert_eq!(text_shown(2 * TITLE_PAD, 120), 0);
        assert_eq!(text_shown(3, 120), 0);
        assert_eq!(text_shown(640, 0), 0);
        // The whole line: the whole buffer.
        assert_eq!(source_width(120, 120, 180), 180);
        // Half of it at 1.5: half of the buffer, rounded.
        assert_eq!(source_width(60, 120, 180), 90);
        assert_eq!(source_width(61, 120, 180), 92);
        assert_eq!(source_width(0, 120, 180), 0);
        assert_eq!(source_width(500, 120, 180), 180, "never past the buffer");
        assert_eq!(source_width(10, 0, 0), 0);
    }

    /// A hover strip comes out at the very top of the window, and goes in
    /// when the pointer is below where it would be.
    #[test]
    fn the_pointer_at_the_top_brings_the_hover_strip_out() {
        let g = R;
        let top = f64::from(g.y);
        assert_eq!(hover_at(g, top), Some(true));
        assert_eq!(hover_at(g, top + f64::from(HOVER_EDGE) - 0.5), Some(true));
        assert_eq!(hover_at(g, top - 3.0), Some(true), "a CSD shadow above");
        assert_eq!(hover_at(g, top + f64::from(HOVER_EDGE)), None);
        assert_eq!(hover_at(g, top + f64::from(TITLE_HEIGHT) - 1.0), None);
        assert_eq!(hover_at(g, top + f64::from(TITLE_HEIGHT)), Some(false));
        assert_eq!(hover_at(g, top + 300.0), Some(false));
    }

    #[test]
    fn a_configure_says_fullscreen_by_its_states() {
        let states: Vec<u8> = [1u32, 4, FULLSCREEN]
            .iter()
            .flat_map(|s| s.to_ne_bytes())
            .collect();
        assert!(has_state(&states, FULLSCREEN));
        assert!(!has_state(&states[..8], FULLSCREEN));
        assert!(!has_state(&[], FULLSCREEN));
        // A torn word is not a state.
        assert!(!has_state(&states[..11], FULLSCREEN));
    }

    #[test]
    fn a_surface_without_geometry_is_its_buffer_scaled_turned_or_viewported() {
        let mut c = Committed::default();
        assert_eq!(surface_size(&c), None, "no buffer, no size");
        c.buffer = Some((1200, 800));
        assert_eq!(surface_size(&c), Some((1200, 800)));
        c.scale = 2;
        assert_eq!(surface_size(&c), Some((600, 400)));
        c.transform = 1; // 90°
        assert_eq!(surface_size(&c), Some((400, 600)));
        c.transform = 6; // flipped 180°
        assert_eq!(surface_size(&c), Some((600, 400)));
        c.source = Some((300, 200));
        assert_eq!(surface_size(&c), Some((300, 200)));
        c.destination = Some((1000, 700));
        assert_eq!(surface_size(&c), Some((1000, 700)));
        c.buffer = None;
        assert_eq!(
            surface_size(&c),
            Some((1000, 700)),
            "a destination is the size even before the buffer's is known"
        );
    }
}
