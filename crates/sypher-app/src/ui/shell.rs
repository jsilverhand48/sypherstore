//! The Wayland layer-shell window that hosts the popup.
//!
//! ## Why this is hand-rolled
//!
//! The popup was originally an `eframe` window created hidden and revealed on
//! the hotkey. That cannot work on Wayland: `winit`'s Wayland backend
//! implements `set_visible` as a no-op (`// Not possible on Wayland.`), so a
//! window created hidden can never be mapped. The compositor's own window list
//! confirmed the surface simply never existed.
//!
//! `zwlr_layer_shell_v1` is the protocol built for this shape of window, and
//! it is what every Wayland launcher uses. It buys three things a normal
//! xdg-toplevel cannot give us:
//!
//! - **Map and unmap on demand.** Creating the layer surface maps it;
//!   destroying it unmaps it. No hidden-window trickery.
//! - **Exclusive keyboard focus.** `KeyboardInteractivity::Exclusive` makes
//!   the compositor hand us the keyboard unconditionally, so there is no
//!   focus-stealing prevention to fight. This was the other risk flagged for
//!   this milestone and the protocol removes it outright.
//! - **Compositor-side centring**, with no anchors set, so the popup lands in
//!   the middle of the focused output without us computing geometry.
//!
//! ## What is kept alive between popups
//!
//! The expensive things: the Wayland connection, the wgpu instance, adapter,
//! device and queue, the egui context and its font atlas, and the egui-wgpu
//! renderer. Only the `wl_surface`, the `LayerSurface` and the `wgpu::Surface`
//! are created per popup, which is cheap enough to be imperceptible. That
//! preserves the "appears instantly" property that made the hidden-window
//! design attractive in the first place.

use std::ptr::NonNull;
use std::sync::mpsc::Sender;

use anyhow::{Context as _, Result};
use raw_window_handle::{
    RawDisplayHandle, RawWindowHandle, WaylandDisplayHandle, WaylandWindowHandle,
};
use smithay_client_toolkit::{
    compositor::{CompositorHandler, CompositorState},
    delegate_dispatch2, delegate_registry,
    output::{OutputHandler, OutputState},
    registry::{ProvidesRegistryState, RegistryState},
    registry_handlers,
    seat::{
        keyboard::{KeyEvent, KeyboardHandler, Keysym, Modifiers, RawModifiers},
        pointer::{PointerEvent, PointerEventKind, PointerHandler},
        Capability, SeatHandler, SeatState,
    },
    shell::{
        wlr_layer::{
            KeyboardInteractivity, Layer, LayerShell, LayerShellHandler, LayerSurface,
            LayerSurfaceConfigure,
        },
        WaylandSurface,
    },
};
use wayland_client::{
    globals::registry_queue_init,
    protocol::{wl_keyboard, wl_output, wl_pointer, wl_seat, wl_surface},
    Connection, Proxy, QueueHandle,
};

/// Linux input codes for the mouse buttons, from `linux/input-event-codes.h`.
/// Wayland reports these directly rather than a protocol-specific enum.
const BTN_LEFT: u32 = 0x110;
const BTN_RIGHT: u32 = 0x111;
const BTN_MIDDLE: u32 = 0x112;

use crate::state::{DaemonEvent, UiRequest};
use crate::ui::popup::{Popup, POPUP_SIZE};

/// Namespace reported to the compositor. Shows up in KWin's window rules and
/// lets a user target the popup specifically.
const NAMESPACE: &str = "sypherstore-popup";

/// Runs the popup shell on the calling thread until the daemon shuts down.
///
/// Must be called from the main thread. Blocks for the process lifetime.
pub fn run(
    events: calloop::channel::Channel<DaemonEvent>,
    requests: Sender<UiRequest>,
) -> Result<()> {
    let conn = Connection::connect_to_env()
        .context("connecting to the Wayland compositor (is WAYLAND_DISPLAY set?)")?;
    let (globals, event_queue) =
        registry_queue_init(&conn).context("initializing the Wayland registry")?;
    let qh: QueueHandle<Shell> = event_queue.handle();

    let compositor =
        CompositorState::bind(&globals, &qh).context("wl_compositor is unavailable")?;
    let layer_shell = LayerShell::bind(&globals, &qh).context(
        "zwlr_layer_shell_v1 is unavailable; Sypherstore's popup needs a compositor \
         that supports the layer shell (KWin, Sway, Hyprland and wlroots all do)",
    )?;

    let gpu = Gpu::new(&conn).context("initializing the GPU")?;

    let egui_ctx = egui::Context::default();
    let renderer = egui_wgpu::Renderer::new(
        &gpu.device,
        gpu.format,
        egui_wgpu::RendererOptions::default(),
    );
    let popup = Popup::new(&egui_ctx, requests);

    let mut shell = Shell {
        registry_state: RegistryState::new(&globals),
        seat_state: SeatState::new(&globals, &qh),
        output_state: OutputState::new(&globals, &qh),
        compositor,
        layer_shell,
        gpu,
        egui_ctx,
        renderer,
        window: None,
        keyboard: None,
        pointer: None,
        pointer_pos: egui::Pos2::ZERO,
        input: Vec::new(),
        modifiers: egui::Modifiers::NONE,
        scale: 1.0,
        popup,
        should_exit: false,
        start: std::time::Instant::now(),
        repaint_after: None,
    };

    let mut event_loop: calloop::EventLoop<Shell> =
        calloop::EventLoop::try_new().context("creating the event loop")?;
    let loop_handle = event_loop.handle();

    calloop_wayland_source::WaylandSource::new(conn.clone(), event_queue)
        .insert(loop_handle.clone())
        .map_err(|e| anyhow::anyhow!("inserting the Wayland source: {e}"))?;

    // Events from the worker arrive here. calloop wakes the loop, which is
    // what lets a hotkey press map the window while we are otherwise idle and
    // blocked on the compositor.
    loop_handle
        .insert_source(events, |event, _, shell: &mut Shell| {
            if let calloop::channel::Event::Msg(event) = event {
                shell.on_daemon_event(event);
            }
        })
        .map_err(|e| anyhow::anyhow!("inserting the event channel: {e}"))?;

    tracing::info!("popup shell ready (layer-shell)");

    while !shell.should_exit {
        // A pending redraw must not block: without a timeout the loop would
        // sleep until the next input even though a frame is owed. Two sources
        // ask for one, and the sooner wins:
        //
        //  - the popup, for its unlock countdown and message expiry;
        //  - egui itself, for animations and for state that changed during the
        //    last frame.
        let ticking = shell
            .popup
            .wants_repaint()
            .then(|| std::time::Duration::from_millis(100));
        let timeout = match (ticking, shell.repaint_after.take()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        event_loop
            .dispatch(timeout, &mut shell)
            .context("dispatching events")?;

        shell.after_dispatch(&qh);
    }

    Ok(())
}

/// GPU objects that outlive individual popups.
struct Gpu {
    instance: wgpu::Instance,
    adapter: wgpu::Adapter,
    device: wgpu::Device,
    queue: wgpu::Queue,
    format: wgpu::TextureFormat,
    display_handle: RawDisplayHandle,
}

impl Gpu {
    fn new(conn: &Connection) -> Result<Self> {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            // GL is kept as a fallback so the popup still renders on a machine
            // with no working Vulkan driver.
            backends: wgpu::Backends::VULKAN | wgpu::Backends::GL,
            flags: wgpu::InstanceFlags::default(),
            memory_budget_thresholds: Default::default(),
            backend_options: Default::default(),
            display: None,
        });

        let display_handle = RawDisplayHandle::Wayland(WaylandDisplayHandle::new(
            NonNull::new(conn.backend().display_ptr().cast())
                .context("null Wayland display pointer")?,
        ));

        // The adapter is chosen without a surface. Requesting one compatible
        // with a specific surface would mean creating a throwaway window here,
        // and every surface we will ever make is a plain Wayland surface on
        // the same display, so there is nothing to discriminate on.
        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::LowPower,
            force_fallback_adapter: false,
            compatible_surface: None,
        }))
        .context("no suitable GPU adapter found")?;

        let (device, queue) = pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor {
            label: Some("sypherstore"),
            // The popup is a few thousand triangles of text and rectangles;
            // the downlevel defaults keep us working on old integrated parts.
            required_limits: wgpu::Limits::downlevel_defaults(),
            ..Default::default()
        }))
        .context("could not open the GPU device")?;

        tracing::debug!(adapter = ?adapter.get_info().name, "GPU ready");

        Ok(Self {
            instance,
            adapter,
            device,
            queue,
            // egui expects a gamma-space target.
            format: wgpu::TextureFormat::Bgra8Unorm,
            display_handle,
        })
    }
}

/// A mapped popup: the Wayland surface and its GPU surface.
struct Window {
    /// Held purely to keep the surface mapped: dropping this destroys the
    /// layer surface, which is precisely how the popup is hidden. Never read.
    #[allow(dead_code)]
    layer: LayerSurface,
    surface: wgpu::Surface<'static>,
    width: u32,
    height: u32,
    /// Set once the compositor has sent its first configure. Drawing before
    /// that is a protocol error.
    configured: bool,
}

struct Shell {
    registry_state: RegistryState,
    seat_state: SeatState,
    output_state: OutputState,
    compositor: CompositorState,
    layer_shell: LayerShell,

    gpu: Gpu,
    egui_ctx: egui::Context,
    renderer: egui_wgpu::Renderer,

    window: Option<Window>,
    keyboard: Option<wl_keyboard::WlKeyboard>,
    pointer: Option<wl_pointer::WlPointer>,
    /// Last known cursor position, in egui points.
    ///
    /// Wayland delivers the position with motion but not with button events,
    /// so a click carries no coordinates of its own and has to reuse this.
    pointer_pos: egui::Pos2,

    /// Input accumulated since the last frame.
    input: Vec<egui::Event>,
    modifiers: egui::Modifiers,
    scale: f32,

    popup: Popup,
    should_exit: bool,
    start: std::time::Instant,
    /// How soon egui wants to be drawn again.
    ///
    /// egui asks for this when anything is mid-animation, and crucially also
    /// when a widget changed state during the frame. Without honouring it, a
    /// click that switches the popup's mode would render once and then block,
    /// leaving the new mode invisible until unrelated input arrived.
    repaint_after: Option<std::time::Duration>,
}

impl Shell {
    /// Applies a worker event, then maps or unmaps to match.
    fn on_daemon_event(&mut self, event: DaemonEvent) {
        self.popup.handle_event(event);
    }

    /// Reconciles the window with what the popup wants, and draws.
    ///
    /// Called after every dispatch rather than from inside a handler, so that
    /// mapping and unmapping happen at one predictable point instead of
    /// re-entrantly from a Wayland callback.
    fn after_dispatch(&mut self, qh: &QueueHandle<Self>) {
        let wants_visible = self.popup.tick(&self.egui_ctx);

        match (wants_visible, self.window.is_some()) {
            (true, false) => self.map(qh),
            (false, true) => self.unmap(),
            _ => {}
        }

        if wants_visible {
            self.draw();
        }
    }

    /// Creates and maps the layer surface.
    fn map(&mut self, qh: &QueueHandle<Self>) {
        let surface = self.compositor.create_surface(qh);

        let layer = self.layer_shell.create_layer_surface(
            qh,
            surface,
            // Overlay sits above fullscreen windows, so the popup is reachable
            // from a maximized browser or a video player.
            Layer::Overlay,
            Some(NAMESPACE),
            None,
        );
        // No anchor: the compositor centres an unanchored layer surface, which
        // is exactly what we want and saves computing output geometry.
        layer.set_size(POPUP_SIZE[0] as u32, POPUP_SIZE[1] as u32);
        // Exclusive is what makes focus stealing a non-issue: the compositor
        // routes the keyboard to us for as long as the surface is mapped.
        layer.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
        // The first commit must carry no buffer; the compositor replies with a
        // configure telling us the size to draw at.
        layer.commit();

        let surface_ptr = match NonNull::new(layer.wl_surface().id().as_ptr().cast()) {
            Some(ptr) => ptr,
            None => {
                tracing::error!("wl_surface has no raw pointer; cannot map the popup");
                return;
            }
        };
        let raw_window_handle =
            RawWindowHandle::Wayland(WaylandWindowHandle::new(surface_ptr));

        let wgpu_surface = match unsafe {
            self.gpu
                .instance
                .create_surface_unsafe(wgpu::SurfaceTargetUnsafe::RawHandle {
                    raw_display_handle: Some(self.gpu.display_handle),
                    raw_window_handle,
                })
        } {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "could not create the GPU surface");
                return;
            }
        };

        self.window = Some(Window {
            layer,
            surface: wgpu_surface,
            width: POPUP_SIZE[0] as u32,
            height: POPUP_SIZE[1] as u32,
            configured: false,
        });
        tracing::info!("popup mapped");
    }

    /// Destroys the layer surface, unmapping the popup.
    fn unmap(&mut self) {
        if self.window.take().is_some() {
            // Dropping `Window` destroys the wgpu surface and then the
            // LayerSurface, which is what actually unmaps it. Order matters:
            // the GPU surface must not outlive the wl_surface it wraps.
            tracing::info!("popup unmapped");
        }
        // egui keeps per-window interaction state (focus, scroll offsets).
        // Clearing it means the next popup opens fresh rather than restoring
        // the last one's focus ring.
        self.egui_ctx.memory_mut(|m| *m = Default::default());
    }

    /// Reconfigures the GPU surface for the current size.
    fn configure_surface(&mut self) {
        let Some(window) = &mut self.window else {
            return;
        };
        let mut config = match window
            .surface
            .get_default_config(&self.gpu.adapter, window.width, window.height)
        {
            Some(c) => c,
            None => {
                tracing::error!("the GPU surface is not compatible with this adapter");
                return;
            }
        };
        config.format = self.gpu.format;
        // FIFO is the only universally supported mode and the popup has no
        // reason to render faster than the display.
        config.present_mode = wgpu::PresentMode::Fifo;
        config.alpha_mode = wgpu::CompositeAlphaMode::PreMultiplied;
        window.surface.configure(&self.gpu.device, &config);
    }

    /// Runs egui and paints one frame.
    fn draw(&mut self) {
        let Some(window) = &self.window else {
            return;
        };
        if !window.configured {
            // The compositor has not told us our size yet.
            return;
        }
        let (width, height) = (window.width, window.height);
        let pixels_per_point = self.scale;

        let raw_input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(width as f32 / pixels_per_point, height as f32 / pixels_per_point),
            )),
            time: Some(self.start.elapsed().as_secs_f64()),
            modifiers: self.modifiers,
            events: std::mem::take(&mut self.input),
            focused: true,
            ..Default::default()
        };
        self.egui_ctx.set_pixels_per_point(pixels_per_point);

        let popup = &mut self.popup;
        let full_output = self.egui_ctx.run_ui(raw_input, |ui| {
            egui::Frame::central_panel(ui.style()).show(ui, |ui| popup.draw(ui));
        });

        // Ask to be woken again if egui has more to draw. Capped, because
        // egui reports `Duration::MAX` to mean "nothing pending", which would
        // overflow the event loop's timeout arithmetic.
        self.repaint_after = full_output
            .viewport_output
            .get(&egui::ViewportId::ROOT)
            .map(|v| v.repaint_delay)
            .filter(|d| *d < std::time::Duration::from_secs(1));

        let paint_jobs = self
            .egui_ctx
            .tessellate(full_output.shapes, full_output.pixels_per_point);

        let screen_descriptor = egui_wgpu::ScreenDescriptor {
            size_in_pixels: [width, height],
            pixels_per_point,
        };

        for (id, delta) in &full_output.textures_delta.set {
            self.renderer
                .update_texture(&self.gpu.device, &self.gpu.queue, *id, delta);
        }

        let Some(window) = &self.window else {
            return;
        };
        use wgpu::CurrentSurfaceTexture as Cst;
        let frame = match window.surface.get_current_texture() {
            // Suboptimal still renders correctly; it only means the surface
            // would be better off reconfigured, which the next configure does.
            Cst::Success(f) | Cst::Suboptimal(f) => f,
            Cst::Outdated | Cst::Lost => {
                // Skip this frame and rebuild the swapchain.
                tracing::debug!("surface outdated, reconfiguring");
                self.configure_surface();
                return;
            }
            // Nothing is visible, so there is nothing worth drawing.
            Cst::Occluded => return,
            other => {
                tracing::error!(status = ?other, "could not acquire a frame");
                return;
            }
        };

        let view = frame
            .texture
            .create_view(&wgpu::TextureViewDescriptor::default());
        let mut encoder = self
            .gpu
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("sypherstore-popup"),
            });

        let user_buffers = self.renderer.update_buffers(
            &self.gpu.device,
            &self.gpu.queue,
            &mut encoder,
            &paint_jobs,
            &screen_descriptor,
        );

        {
            let render_pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("sypherstore-popup"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &view,
                    resolve_target: None,
                    ops: wgpu::Operations {
                        load: wgpu::LoadOp::Clear(wgpu::Color {
                            r: 0.07,
                            g: 0.07,
                            b: 0.09,
                            a: 1.0,
                        }),
                        store: wgpu::StoreOp::Store,
                    },
                    depth_slice: None,
                })],
                depth_stencil_attachment: None,
                timestamp_writes: None,
                occlusion_query_set: None,
                multiview_mask: None,
            });
            // egui-wgpu needs a 'static pass; `forget_lifetime` is the
            // sanctioned way to get one, and the pass is dropped below before
            // anything it borrows.
            let mut render_pass = render_pass.forget_lifetime();
            self.renderer
                .render(&mut render_pass, &paint_jobs, &screen_descriptor);
        }

        for id in &full_output.textures_delta.free {
            self.renderer.free_texture(id);
        }

        self.gpu
            .queue
            .submit(user_buffers.into_iter().chain(Some(encoder.finish())));
        frame.present();
    }

    /// Pushes a key into egui's input queue.
    fn push_key(&mut self, event: &KeyEvent, pressed: bool) {
        if let Some(key) = translate_keysym(event.keysym) {
            self.input.push(egui::Event::Key {
                key,
                physical_key: None,
                pressed,
                repeat: false,
                modifiers: self.modifiers,
            });
        }

        // Text is only produced on press, and never while Ctrl or Alt is held:
        // those are commands, and inserting their character into the search
        // box would be wrong.
        if pressed && !self.modifiers.ctrl && !self.modifiers.alt {
            if let Some(text) = &event.utf8 {
                if !text.is_empty() && !text.chars().any(|c| c.is_control()) {
                    self.input.push(egui::Event::Text(text.clone()));
                }
            }
        }
    }
}

/// Maps an X keysym to egui's key enum.
///
/// Only the keys the popup acts on are translated. Everything else arrives as
/// text, which is all the search box needs.
fn translate_keysym(sym: Keysym) -> Option<egui::Key> {
    Some(match sym {
        Keysym::Escape => egui::Key::Escape,
        Keysym::Return | Keysym::KP_Enter => egui::Key::Enter,
        Keysym::Tab => egui::Key::Tab,
        Keysym::BackSpace => egui::Key::Backspace,
        Keysym::Delete => egui::Key::Delete,
        Keysym::Up => egui::Key::ArrowUp,
        Keysym::Down => egui::Key::ArrowDown,
        Keysym::Left => egui::Key::ArrowLeft,
        Keysym::Right => egui::Key::ArrowRight,
        Keysym::Home => egui::Key::Home,
        Keysym::End => egui::Key::End,
        Keysym::Page_Up => egui::Key::PageUp,
        Keysym::Page_Down => egui::Key::PageDown,
        _ => return None,
    })
}

impl CompositorHandler for Shell {
    fn scale_factor_changed(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_surface::WlSurface,
        new_factor: i32,
    ) {
        // Wayland reports integer scale here. Without honouring it the popup
        // renders at 1x on a HiDPI display and looks blurry.
        self.scale = new_factor.max(1) as f32;
        tracing::debug!(scale = self.scale, "scale factor changed");
        self.configure_surface();
    }

    fn transform_changed(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_surface::WlSurface,
        _: wayland_client::protocol::wl_output::Transform,
    ) {
    }

    fn frame(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_surface::WlSurface,
        _time: u32,
    ) {
    }

    fn surface_enter(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_surface::WlSurface,
        _: &wl_output::WlOutput,
    ) {
    }

    fn surface_leave(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_surface::WlSurface,
        _: &wl_output::WlOutput,
    ) {
    }
}

impl LayerShellHandler for Shell {
    fn closed(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &LayerSurface) {
        // The compositor dismissed the surface (an output went away, or a
        // session lock took over). Treat it as the user closing the popup
        // rather than as a fatal error.
        tracing::debug!("layer surface closed by the compositor");
        self.popup.force_hide();
        self.window = None;
    }

    fn configure(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &LayerSurface,
        configure: LayerSurfaceConfigure,
        _serial: u32,
    ) {
        let (mut width, mut height) = configure.new_size;
        // A zero dimension means "you choose", which happens when nothing
        // constrains us.
        if width == 0 {
            width = POPUP_SIZE[0] as u32;
        }
        if height == 0 {
            height = POPUP_SIZE[1] as u32;
        }

        if let Some(window) = &mut self.window {
            window.width = width;
            window.height = height;
            window.configured = true;
        }
        self.configure_surface();
        tracing::info!(width, height, "layer surface configured");
    }
}

impl SeatHandler for Shell {
    fn seat_state(&mut self) -> &mut SeatState {
        &mut self.seat_state
    }

    fn new_seat(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_seat::WlSeat) {}

    fn new_capability(
        &mut self,
        _: &Connection,
        qh: &QueueHandle<Self>,
        seat: wl_seat::WlSeat,
        capability: Capability,
    ) {
        if capability == Capability::Keyboard && self.keyboard.is_none() {
            match self.seat_state.get_keyboard(qh, &seat, None) {
                Ok(kb) => {
                    tracing::debug!("keyboard acquired");
                    self.keyboard = Some(kb);
                }
                Err(e) => tracing::error!(error = %e, "could not acquire the keyboard"),
            }
        }
        if capability == Capability::Pointer && self.pointer.is_none() {
            match self.seat_state.get_pointer(qh, &seat) {
                Ok(ptr) => {
                    tracing::debug!("pointer acquired");
                    self.pointer = Some(ptr);
                }
                Err(e) => tracing::error!(error = %e, "could not acquire the pointer"),
            }
        }
    }

    fn remove_capability(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: wl_seat::WlSeat,
        capability: Capability,
    ) {
        if capability == Capability::Keyboard {
            if let Some(kb) = self.keyboard.take() {
                kb.release();
            }
        }
        if capability == Capability::Pointer {
            if let Some(ptr) = self.pointer.take() {
                ptr.release();
            }
        }
    }

    fn remove_seat(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_seat::WlSeat) {}
}

impl KeyboardHandler for Shell {
    fn enter(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: &wl_surface::WlSurface,
        _: u32,
        _: &[u32],
        _: &[Keysym],
    ) {
        tracing::debug!("keyboard focus gained");
    }

    fn leave(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: &wl_surface::WlSurface,
        _: u32,
    ) {
        // Losing focus while mapped means something took the keyboard from us.
        // Dismiss rather than linger: a popup that cannot be typed into is
        // just an obstruction, and one showing a secret list should not sit
        // there unattended.
        tracing::debug!("keyboard focus lost; dismissing");
        self.modifiers = egui::Modifiers::NONE;
        self.popup.force_hide();
    }

    fn press_key(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: u32,
        event: KeyEvent,
    ) {
        self.push_key(&event, true);
    }

    fn release_key(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: u32,
        event: KeyEvent,
    ) {
        self.push_key(&event, false);
    }

    fn repeat_key(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: u32,
        event: KeyEvent,
    ) {
        // Held arrow keys should keep moving the selection.
        self.push_key(&event, true);
    }

    fn update_modifiers(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: u32,
        modifiers: Modifiers,
        _: RawModifiers,
        _: u32,
    ) {
        self.modifiers = egui::Modifiers {
            alt: modifiers.alt,
            ctrl: modifiers.ctrl,
            shift: modifiers.shift,
            mac_cmd: false,
            command: modifiers.ctrl,
        };
    }
}

impl PointerHandler for Shell {
    fn pointer_frame(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_pointer::WlPointer,
        events: &[PointerEvent],
    ) {
        for event in events {
            // Only our own surface's events matter. A layer surface can see
            // events for others on the same seat.
            if self
                .window
                .as_ref()
                .is_none_or(|w| w.layer.wl_surface() != &event.surface)
            {
                continue;
            }

            let pos = egui::pos2(event.position.0 as f32, event.position.1 as f32);

            match event.kind {
                PointerEventKind::Enter { .. } | PointerEventKind::Motion { .. } => {
                    self.pointer_pos = pos;
                    self.input.push(egui::Event::PointerMoved(pos));
                }
                PointerEventKind::Leave { .. } => {
                    // Without this, egui keeps the last hovered widget lit up
                    // after the cursor has left the popup entirely.
                    self.input.push(egui::Event::PointerGone);
                }
                PointerEventKind::Press { button, .. }
                | PointerEventKind::Release { button, .. } => {
                    let Some(button) = translate_button(button) else {
                        continue;
                    };
                    let pressed = matches!(event.kind, PointerEventKind::Press { .. });

                    // Wayland omits the position on button events, so the
                    // click is placed at the last motion. Sending a move first
                    // guarantees egui has registered the position even if the
                    // press arrives in the same frame as the motion that
                    // produced it.
                    self.pointer_pos = pos;
                    self.input.push(egui::Event::PointerMoved(pos));
                    self.input.push(egui::Event::PointerButton {
                        pos,
                        button,
                        pressed,
                        modifiers: self.modifiers,
                    });
                }
                PointerEventKind::Axis {
                    horizontal,
                    vertical,
                    ..
                } => {
                    // Wayland reports a positive axis value for scrolling
                    // down and right. egui's delta describes how the *content*
                    // moves, which is the opposite direction, so both axes are
                    // negated. Getting this wrong inverts scrolling, which is
                    // immediately obvious but easy to introduce.
                    let delta = egui::vec2(-horizontal.absolute as f32, -vertical.absolute as f32);
                    if delta != egui::Vec2::ZERO {
                        self.input.push(egui::Event::MouseWheel {
                            unit: egui::MouseWheelUnit::Point,
                            delta,
                            // A wheel has no touch phase; `Move` is what egui
                            // documents for that case.
                            phase: egui::TouchPhase::Move,
                            modifiers: self.modifiers,
                        });
                    }
                }
            }
        }
    }
}

/// Maps a Linux button code to egui's button enum.
///
/// Anything else (side buttons, tilt wheels) is ignored rather than guessed at.
fn translate_button(code: u32) -> Option<egui::PointerButton> {
    match code {
        BTN_LEFT => Some(egui::PointerButton::Primary),
        BTN_RIGHT => Some(egui::PointerButton::Secondary),
        BTN_MIDDLE => Some(egui::PointerButton::Middle),
        _ => None,
    }
}

impl OutputHandler for Shell {
    fn output_state(&mut self) -> &mut OutputState {
        &mut self.output_state
    }

    fn new_output(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_output::WlOutput) {}
    fn update_output(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_output::WlOutput) {}
    fn output_destroyed(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_output::WlOutput) {}
}

impl ProvidesRegistryState for Shell {
    fn registry(&mut self) -> &mut RegistryState {
        &mut self.registry_state
    }
    registry_handlers![OutputState, SeatState];
}

// One blanket impl covers every protocol sctk knows about; 0.21 replaced the
// old per-protocol `delegate_compositor!` / `delegate_seat!` / ... macros.
delegate_dispatch2!(Shell);
delegate_registry!(Shell);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigation_keys_are_translated() {
        assert_eq!(translate_keysym(Keysym::Escape), Some(egui::Key::Escape));
        assert_eq!(translate_keysym(Keysym::Return), Some(egui::Key::Enter));
        assert_eq!(translate_keysym(Keysym::KP_Enter), Some(egui::Key::Enter));
        assert_eq!(translate_keysym(Keysym::Up), Some(egui::Key::ArrowUp));
        assert_eq!(translate_keysym(Keysym::Down), Some(egui::Key::ArrowDown));
    }

    #[test]
    fn printable_keys_are_left_to_the_text_path() {
        // Letters must not become egui::Key events, or the search box would
        // receive both a key press and its text and could double-insert.
        assert_eq!(translate_keysym(Keysym::a), None);
        assert_eq!(translate_keysym(Keysym::Z), None);
        assert_eq!(translate_keysym(Keysym::_1), None);
    }
}
