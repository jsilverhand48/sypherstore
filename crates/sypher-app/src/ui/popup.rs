//! The hotkey popup: state and drawing.
//!
//! This module is deliberately shell-agnostic. It owns the popup's state
//! machine (what is selected, what is filtered, whether the vault is unlocked)
//! and knows how to draw itself into an [`egui::Ui`], but it does not know
//! what kind of window it lives in. The Wayland layer surface that hosts it is
//! in [`crate::ui::shell`].
//!
//! That separation was not academic. The popup was first built on `eframe`,
//! which turned out to be unable to show or hide a window on Wayland at all
//! (`winit`'s `set_visible` is a no-op there). Because the drawing and the
//! state machine were already independent of the window, replacing the entire
//! windowing layer left this file almost untouched.
//!
//! ## What it can and cannot do
//!
//! The list renders from metadata alone, so it appears fully populated while
//! the vault is still locked. Only *using* an entry needs the inner key. That
//! ordering is deliberate: the user sees their options, then decides whether
//! the touch is worth it, instead of being asked to authenticate before they
//! know what they will get.
//!
//! ## Keyboard first, but not keyboard only
//!
//! Every action has a key: Up/Down move the selection, Enter uses it, Escape
//! dismisses, typing filters, and Ctrl+N/E/D add, edit and delete. The window
//! has no title bar to drag, because reaching for the mouse costs more time
//! than typing the site name.
//!
//! The clickable affordances (the **+ Add** button, each row's **x**, and
//! **Save**/**Cancel** in the editor) exist anyway, for two reasons: they
//! advertise what is possible to someone who has not memorised the chords, and
//! a destructive or committing action is worth making explicit rather than
//! leaving it to a chord that has to be known in advance.

use std::sync::mpsc::Sender;

use uuid::Uuid;


use sypher_core::model::{SecretMeta, SecretType};
use sypher_core::search::fuzzy::{Ranked, SearchContext, Searcher};

use crate::state::{DaemonEvent, UiLockState, UiRequest};
use crate::ui::editor::{Editor, Field};

/// Fixed popup size. Large enough for eight rows plus the search field.
pub const POPUP_SIZE: [f32; 2] = [640.0, 420.0];

/// How long a status or error message stays on screen.
const MESSAGE_LINGER: std::time::Duration = std::time::Duration::from_secs(4);

/// What the popup is currently showing.
///
/// Modes share one surface rather than opening extra windows: on Wayland each
/// window is a separate surface with its own configure handshake and keyboard
/// grab, and the popup is modal in spirit anyway.
pub enum Mode {
    /// The searchable secret list.
    List,
    /// Adding or editing a secret.
    Edit(Box<Editor>),
    /// Confirming a deletion. Holds the target and its name for the prompt.
    ConfirmDelete(Uuid, String),
    /// Collecting the authenticator's PIN.
    Pin(PinEntry),
}

/// State of the PIN prompt.
///
/// The typed PIN lives in a `String` for the same reason the editor's secret
/// does: `egui::TextEdit` requires one. `Drop` zeroizes it, and it is handed
/// to the worker and cleared as soon as the user submits.
#[derive(Default)]
pub struct PinEntry {
    pub value: String,
    /// Set when a previous PIN was rejected.
    pub retry: bool,
    pub needs_focus: bool,
}

impl Drop for PinEntry {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.value.zeroize();
    }
}

/// One frame's worth of key presses, read once so the borrow of `ctx` ends
/// before the handlers mutate `self`.
struct Keys {
    escape: bool,
    up: bool,
    down: bool,
    enter: bool,
    tab: bool,
    shift: bool,
    ctrl: bool,
    n: bool,
    e: bool,
    d: bool,
    s: bool,
}

pub struct Popup {
    /// Requests to the worker. Events come the other way via
    /// [`Popup::handle_event`], which the shell calls from its event loop.
    requests: Sender<UiRequest>,

    mode: Mode,

    /// Cached metadata. Refreshed each time the popup is shown, never held
    /// across a hide, so a deleted secret cannot linger in the list.
    secrets: Vec<SecretMeta>,
    /// Ranked view of `secrets` for the current query.
    ranked: Vec<Ranked>,
    searcher: Searcher,
    context: SearchContext,

    query: String,
    selected: usize,
    lock_state: UiLockState,
    visible: bool,
    /// Set for one frame after showing, to move focus into the search box.
    needs_focus: bool,
    message: Option<(String, bool, std::time::Instant)>,
}

impl Popup {
    pub fn new(ctx: &egui::Context, requests: Sender<UiRequest>) -> Self {
        configure_style(ctx);
        Self {
            requests,
            mode: Mode::List,
            secrets: Vec::new(),
            ranked: Vec::new(),
            searcher: Searcher::new(),
            context: SearchContext::default(),
            query: String::new(),
            selected: 0,
            lock_state: UiLockState::Locked,
            visible: false,
            needs_focus: false,
            message: None,
        }
    }

    /// Applies one event from the worker.
    pub fn handle_event(&mut self, event: DaemonEvent) {
        match event {
            DaemonEvent::Show {
                secrets,
                host,
                application,
            } => {
                self.secrets = secrets;
                self.context = SearchContext { host, application };
                // A fresh query each time: carrying over the last search would
                // make the popup open showing a stale filter.
                self.query.clear();
                self.selected = 0;
                self.message = None;
                self.rerank();
                self.mode = Mode::List;
                self.visible = true;
                self.needs_focus = true;
            }
            DaemonEvent::Hide => self.hide(),
            DaemonEvent::LockChanged(state) => self.lock_state = state,
            DaemonEvent::Error(msg) => {
                self.message = Some((msg, true, std::time::Instant::now()))
            }
            DaemonEvent::Status(msg) => {
                self.message = Some((msg, false, std::time::Instant::now()))
            }
            DaemonEvent::EditReady { meta, payload } => {
                // The worker only sends this after a successful assertion, so
                // reaching here means the edit was authorized.
                self.mode = Mode::Edit(Box::new(Editor::from_existing(&meta, &payload)));
                self.visible = true;
                self.needs_focus = true;
            }
            DaemonEvent::Refresh(secrets) => {
                self.secrets = secrets;
                self.rerank();
            }
            DaemonEvent::RequestPin { retry } => {
                self.mode = Mode::Pin(PinEntry {
                    value: String::new(),
                    retry,
                    needs_focus: true,
                });
                // The assertion is blocked waiting on this, so the popup has
                // to be on screen even if the user had dismissed it.
                self.visible = true;
            }
        }
    }

    /// Hides the popup and tells the worker it was dismissed.
    fn hide(&mut self) {
        if !self.visible {
            return;
        }
        self.visible = false;
        // Dropping the editor zeroizes the plaintext it was holding.
        self.mode = Mode::List;
        // Drop the cached metadata on hide. It is not secret, but a stale list
        // is a correctness hazard if the vault changed while we were hidden.
        self.secrets.clear();
        self.ranked.clear();
        self.query.clear();
        let _ = self.requests.send(UiRequest::Dismissed);
    }

    /// Hides without the usual bookkeeping, for when the compositor has taken
    /// the surface away from us and there is nothing left to dismiss.
    pub fn force_hide(&mut self) {
        self.hide();
    }

    fn rerank(&mut self) {
        self.ranked = self.searcher.rank(&self.secrets, &self.query, &self.context);
        if self.selected >= self.ranked.len() {
            self.selected = self.ranked.len().saturating_sub(1);
        }
    }

    /// Handles keyboard input. Returns true if the popup should close.
    fn handle_keys(&mut self, ctx: &egui::Context) -> bool {
        let keys = ctx.input(|i| Keys {
            escape: i.key_pressed(egui::Key::Escape),
            up: i.key_pressed(egui::Key::ArrowUp),
            down: i.key_pressed(egui::Key::ArrowDown),
            enter: i.key_pressed(egui::Key::Enter),
            tab: i.key_pressed(egui::Key::Tab),
            shift: i.modifiers.shift,
            ctrl: i.modifiers.ctrl,
            n: i.key_pressed(egui::Key::N),
            e: i.key_pressed(egui::Key::E),
            d: i.key_pressed(egui::Key::D),
            s: i.key_pressed(egui::Key::S),
        });

        match &mut self.mode {
            Mode::List => self.handle_list_keys(&keys),
            Mode::Edit(_) => {
                self.handle_edit_keys(&keys);
                false
            }
            Mode::ConfirmDelete(..) => {
                self.handle_confirm_keys(&keys);
                false
            }
            Mode::Pin(_) => {
                self.handle_pin_keys(&keys);
                false
            }
        }
    }

    /// PIN-mode keys. Enter submits, Escape cancels the assertion.
    fn handle_pin_keys(&mut self, keys: &Keys) {
        if keys.escape {
            let _ = self.requests.send(UiRequest::PinResponse(None));
            self.mode = Mode::List;
            return;
        }
        if keys.enter {
            let Mode::Pin(entry) = &mut self.mode else {
                return;
            };
            if entry.value.is_empty() {
                return;
            }
            // `take` moves the PIN out; the emptied String is then zeroized by
            // PinEntry's Drop when the mode changes.
            let pin = std::mem::take(&mut entry.value);
            let _ = self.requests.send(UiRequest::PinResponse(Some(pin)));
            self.mode = Mode::List;
        }
    }

    /// List-mode keys. Returns true to close the popup.
    fn handle_list_keys(&mut self, keys: &Keys) -> bool {
        if keys.escape {
            return true;
        }

        if keys.ctrl && keys.n {
            self.mode = Mode::Edit(Box::new(Editor::new()));
            self.needs_focus = true;
            return false;
        }
        if keys.ctrl && keys.e {
            // Editing needs the plaintext, which only the worker can produce
            // and only after a fresh assertion.
            if let Some(target) = self.ranked.get(self.selected).map(|r| r.meta.id) {
                let _ = self.requests.send(UiRequest::BeginEdit(target));
            }
            return false;
        }
        if keys.ctrl && keys.d {
            if let Some(entry) = self.ranked.get(self.selected) {
                self.mode = Mode::ConfirmDelete(entry.meta.id, entry.meta.name.clone());
            }
            return false;
        }

        // Active navigation counts as use: without this the vault could
        // relock while the user is still scrolling through a long list.
        if keys.up || keys.down {
            let _ = self.requests.send(UiRequest::Touch);
        }
        if keys.up && self.selected > 0 {
            self.selected -= 1;
        }
        if keys.down && self.selected + 1 < self.ranked.len() {
            self.selected += 1;
        }
        if keys.enter {
            self.activate_selected();
        }
        false
    }

    /// Edit-mode keys. Escape abandons the form; Ctrl+S saves.
    fn handle_edit_keys(&mut self, keys: &Keys) {
        if keys.escape {
            // Returning to the list drops the Editor, zeroizing its plaintext.
            self.mode = Mode::List;
            self.needs_focus = true;
            return;
        }
        let Mode::Edit(editor) = &mut self.mode else {
            return;
        };
        if keys.tab {
            editor.cycle_focus(keys.shift);
        }
        if keys.ctrl && keys.s {
            self.save_editor();
        }
    }

    /// Delete-confirmation keys.
    fn handle_confirm_keys(&mut self, keys: &Keys) {
        if keys.escape {
            self.mode = Mode::List;
            return;
        }
        // Enter confirms. Deliberately not bound to `y`, so a stray keystroke
        // while the prompt is up cannot destroy a secret.
        if keys.enter {
            if let Mode::ConfirmDelete(id, _) = &self.mode {
                let _ = self.requests.send(UiRequest::Delete(*id));
            }
            self.mode = Mode::List;
        }
    }

    /// Acts on the highlighted row.
    ///
    /// While locked this starts an unlock instead of using the secret, so
    /// Enter always does the obvious next thing and the user never has to know
    /// there are two separate steps.
    fn activate_selected(&mut self) {
        let Some(target) = self.ranked.get(self.selected).map(|r| r.meta.id) else {
            return;
        };
        match self.lock_state {
            UiLockState::Unlocked { .. } => {
                let _ = self.requests.send(UiRequest::Use(target));
            }
            UiLockState::Locked => {
                let _ = self.requests.send(UiRequest::Unlock);
            }
            UiLockState::WaitingForTouch => {}
        }
    }

    /// Validates the form and sends it to the worker.
    fn save_editor(&mut self) {
        let Mode::Edit(editor) = &mut self.mode else {
            return;
        };
        let is_update = !editor.is_new();
        match editor.build() {
            Ok((meta, payload)) => {
                let _ = self.requests.send(UiRequest::Save {
                    meta,
                    payload,
                    is_update,
                });
                self.mode = Mode::List;
                self.needs_focus = true;
            }
            Err(message) => editor.error = Some(message),
        }
    }

    /// Draws the header. Returns true if the Add button was clicked.
    ///
    /// Takes `&mut self` only through the caller, so the click is reported
    /// upward rather than acted on here; mutating mode mid-draw would
    /// invalidate the borrow the rest of the frame depends on.
    fn draw_header(&self, ui: &mut egui::Ui) -> bool {
        let mut add_clicked = false;
        ui.horizontal(|ui| {
            ui.heading("Sypherstore");
            if ui
                .button("  + Add  ")
                .on_hover_text("Add a new secret (Ctrl+N)")
                .clicked()
            {
                add_clicked = true;
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let (text, color) = match self.lock_state {
                    UiLockState::Locked => ("Locked", egui::Color32::from_rgb(0xE0, 0x6C, 0x75)),
                    UiLockState::WaitingForTouch => (
                        "Touch your YubiKey...",
                        egui::Color32::from_rgb(0xE5, 0xC0, 0x7B),
                    ),
                    UiLockState::Unlocked { .. } => {
                        ("Unlocked", egui::Color32::from_rgb(0x98, 0xC3, 0x79))
                    }
                };
                ui.colored_label(color, text);
                if let UiLockState::Unlocked { remaining } = self.lock_state {
                    ui.weak(format!("{}s ", remaining.as_secs()));
                }
            });
        });
        add_clicked
    }

    fn draw_list(&mut self, ui: &mut egui::Ui) {
        if self.ranked.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.weak(if self.secrets.is_empty() {
                    "The vault is empty."
                } else {
                    "No secrets matched."
                });
            });
            return;
        }

        let usable = self.lock_state.is_unlocked();
        let mut clicked: Option<usize> = None;
        let mut delete_requested: Option<usize> = None;

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (i, entry) in self.ranked.iter().enumerate() {
                    let selected = i == self.selected;
                    let row = draw_row(ui, entry, selected, usable);
                    if row.activated {
                        clicked = Some(i);
                    }
                    if row.deleted {
                        delete_requested = Some(i);
                    }
                    // Keep the keyboard selection on screen as the user
                    // arrows past the visible window.
                    if selected {
                        row.response.scroll_to_me(None);
                    }
                }
            });

        // Deletion takes precedence: if the click landed on the x, the user
        // did not mean to paste the secret.
        if let Some(i) = delete_requested {
            if let Some(entry) = self.ranked.get(i) {
                self.selected = i;
                self.mode = Mode::ConfirmDelete(entry.meta.id, entry.meta.name.clone());
            }
            return;
        }
        if let Some(i) = clicked {
            self.selected = i;
            self.activate_selected();
        }
    }

    fn draw_footer(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if let Some((msg, is_error, _)) = &self.message {
                let color = if *is_error {
                    egui::Color32::from_rgb(0xE0, 0x6C, 0x75)
                } else {
                    egui::Color32::from_rgb(0x98, 0xC3, 0x79)
                };
                ui.colored_label(color, msg);
            } else {
                let hint = match self.lock_state {
                    UiLockState::Unlocked { .. } => "Enter: paste   Up/Down: select   Esc: close",
                    UiLockState::Locked => "Enter: unlock   Up/Down: select   Esc: close",
                    UiLockState::WaitingForTouch => "Waiting for your YubiKey...   Esc: cancel",
                };
                ui.weak(hint);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.weak(format!("{} shown", self.ranked.len()));
            });
        });
    }
}

impl Popup {
    /// Advances the state machine. Called once per frame by the shell, and
    /// also while hidden so a `Show` event can wake and map the window.
    ///
    /// Returns `true` when the popup wants to be on screen.
    pub fn tick(&mut self, ctx: &egui::Context) -> bool {
        if let Some((_, _, at)) = self.message {
            if at.elapsed() > MESSAGE_LINGER {
                self.message = None;
            }
        }

        if self.visible && self.handle_keys(ctx) {
            self.hide();
        }

        self.visible
    }

    /// Draws the popup. Only called while visible.
    pub fn draw(&mut self, ui: &mut egui::Ui) {
        match &self.mode {
            Mode::List => self.draw_list_mode(ui),
            Mode::Edit(_) => self.draw_edit_mode(ui),
            Mode::ConfirmDelete(..) => self.draw_confirm_mode(ui),
            Mode::Pin(_) => self.draw_pin_mode(ui),
        }
    }

    /// The PIN prompt.
    fn draw_pin_mode(&mut self, ui: &mut egui::Ui) {
        let Mode::Pin(entry) = &mut self.mode else {
            return;
        };
        ui.vertical_centered(|ui| {
            ui.add_space(70.0);
            ui.heading("Authenticator PIN");
            ui.add_space(8.0);
            if entry.retry {
                ui.colored_label(
                    egui::Color32::from_rgb(0xE0, 0x6C, 0x75),
                    "That PIN was not accepted. Try again.",
                );
            } else {
                ui.weak("Your security key needs its PIN to continue.");
            }
            ui.add_space(16.0);

            let response = ui.add(
                egui::TextEdit::singleline(&mut entry.value)
                    .password(true)
                    .desired_width(240.0)
                    .horizontal_align(egui::Align::Center),
            );
            if entry.needs_focus {
                response.request_focus();
                entry.needs_focus = false;
            }

            ui.add_space(20.0);
            ui.weak("Enter to continue    Esc to cancel");
        });
    }

    /// The searchable list of secrets.
    fn draw_list_mode(&mut self, ui: &mut egui::Ui) {
        if self.draw_header(ui) {
            self.mode = Mode::Edit(Box::new(Editor::new()));
            self.needs_focus = true;
            return;
        }
        ui.separator();

        let response = ui.add(
            egui::TextEdit::singleline(&mut self.query)
                .hint_text("Search by name, site, username or tag")
                .desired_width(f32::INFINITY),
        );
        if self.needs_focus {
            response.request_focus();
            self.needs_focus = false;
        }
        if response.changed() {
            self.selected = 0;
            self.rerank();
            let _ = self.requests.send(UiRequest::Touch);
        }

        ui.add_space(6.0);
        ui.separator();

        // Reserve the footer's height so the list does not jump when a
        // message appears.
        let footer_height = 24.0;
        let list_height = (ui.available_height() - footer_height).max(0.0);
        ui.allocate_ui(egui::vec2(ui.available_width(), list_height), |ui| {
            self.draw_list(ui);
        });

        ui.separator();
        self.draw_footer(ui);
    }

    /// The add/edit form.
    ///
    /// The Save and Cancel clicks are collected into locals and acted on after
    /// the `editor` borrow ends: `save_editor` takes `&mut self`, so calling it
    /// from inside the drawing closure would not borrow-check.
    fn draw_edit_mode(&mut self, ui: &mut egui::Ui) {
        let mut save = false;
        let mut cancel = false;

        {
        let Mode::Edit(editor) = &mut self.mode else {
            return;
        };

        ui.horizontal(|ui| {
            ui.heading(editor.title());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.weak("Ctrl+S save   Tab next   Esc cancel");
            });
        });
        ui.separator();

        // Reserve the button row before the form claims the rest of the
        // height, otherwise the scroll area fills the surface and pushes Save
        // off the bottom where it cannot be clicked.
        let footer_height = 38.0;
        let body_height = (ui.available_height() - footer_height).max(0.0);
        ui.allocate_ui(egui::vec2(ui.available_width(), body_height), |ui| {
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("editor")
                    .num_columns(2)
                    .spacing([12.0, 8.0])
                    .show(ui, |ui| {
                        text_row(ui, "Name", &mut editor.name, Field::Name, editor.focus, &mut editor.focus_dirty, false);
                        ui.end_row();

                        // The one field rendered as a password: everything
                        // else here is already stored in the clear.
                        text_row(ui, "Secret", &mut editor.value, Field::Value, editor.focus, &mut editor.focus_dirty, true);
                        ui.end_row();

                        ui.label("Type");
                        egui::ComboBox::from_id_salt("secret_type")
                            .selected_text(editor.secret_type.label())
                            .show_ui(ui, |ui| {
                                for t in SecretType::ALL {
                                    ui.selectable_value(&mut editor.secret_type, t, t.label());
                                }
                            });
                        ui.end_row();

                        text_row(ui, "Username", &mut editor.username, Field::Username, editor.focus, &mut editor.focus_dirty, false);
                        ui.end_row();
                        text_row(ui, "Site", &mut editor.domain, Field::Domain, editor.focus, &mut editor.focus_dirty, false);
                        ui.end_row();
                        text_row(ui, "Application", &mut editor.application, Field::Application, editor.focus, &mut editor.focus_dirty, false);
                        ui.end_row();
                        text_row(ui, "Tags", &mut editor.tags, Field::Tags, editor.focus, &mut editor.focus_dirty, false);
                        ui.end_row();
                        text_row(ui, "Notes", &mut editor.notes, Field::Notes, editor.focus, &mut editor.focus_dirty, false);
                        ui.end_row();
                    });
            });
        });

        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("  Save  ").clicked() {
                save = true;
            }
            if ui.button("  Cancel  ").clicked() {
                cancel = true;
            }
            // Beside the buttons rather than under the form: a validation
            // failure is a response to pressing Save, and inside the scroll
            // area it could be scrolled out of sight.
            if let Some(error) = &editor.error {
                ui.colored_label(egui::Color32::from_rgb(0xE0, 0x6C, 0x75), error);
            }
        });
        }

        if cancel {
            // Dropping the Editor zeroizes the plaintext it was holding.
            self.mode = Mode::List;
            self.needs_focus = true;
        } else if save {
            self.save_editor();
        }
    }

    /// The delete confirmation.
    fn draw_confirm_mode(&mut self, ui: &mut egui::Ui) {
        let Mode::ConfirmDelete(_, name) = &self.mode else {
            return;
        };
        ui.vertical_centered(|ui| {
            ui.add_space(80.0);
            ui.heading("Delete this secret?");
            ui.add_space(12.0);
            ui.label(
                egui::RichText::new(name.as_str())
                    .strong()
                    .size(18.0),
            );
            ui.add_space(12.0);
            ui.colored_label(
                egui::Color32::from_rgb(0xE0, 0x6C, 0x75),
                "This cannot be undone.",
            );
            ui.add_space(24.0);
            ui.weak("Enter to delete    Esc to cancel");
        });
    }

    /// Whether anything on screen is animating and needs a follow-up frame.
    ///
    /// Used by the shell to decide between scheduling another frame and going
    /// back to sleep, which is what keeps an idle daemon at zero CPU.
    pub fn wants_repaint(&self) -> bool {
        self.visible && (self.lock_state.is_unlocked() || self.message.is_some())
    }
}

/// Draws one labelled text field in the editor grid.
///
/// `focus_dirty` is consumed the frame the field takes focus, so Tab moves
/// focus exactly once rather than fighting the widget every frame.
#[allow(clippy::too_many_arguments)]
fn text_row(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut String,
    field: Field,
    focused: Field,
    focus_dirty: &mut bool,
    password: bool,
) {
    ui.label(label);
    let response = ui.add(
        egui::TextEdit::singleline(value)
            .password(password)
            .desired_width(420.0),
    );
    if *focus_dirty && field == focused {
        response.request_focus();
        *focus_dirty = false;
    }
}

/// What the user did to a row this frame.
struct RowAction {
    response: egui::Response,
    /// The row body was clicked: use the secret.
    activated: bool,
    /// The x was clicked: begin deletion.
    deleted: bool,
}

/// Draws one secret row with its delete affordance.
fn draw_row(ui: &mut egui::Ui, entry: &Ranked, selected: bool, usable: bool) -> RowAction {
    let meta = &entry.meta;
    let row_height = 44.0;
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), row_height),
        egui::Sense::click(),
    );

    if selected {
        ui.painter()
            .rect_filled(rect, 4.0, ui.visuals().selection.bg_fill);
    } else if response.hovered() {
        ui.painter()
            .rect_filled(rect, 4.0, ui.visuals().widgets.hovered.bg_fill);
    }

    let text_color = if usable {
        ui.visuals().text_color()
    } else {
        // Dimmed while locked, so it is visually obvious that the rows are
        // not yet actionable.
        ui.visuals().weak_text_color()
    };

    // The delete button occupies the right edge, so the body is inset to
    // avoid it. Without this the row's click area would sit under the x and
    // swallow the click.
    let delete_width = 28.0;
    let body_rect = egui::Rect::from_min_max(
        rect.min + egui::vec2(8.0, 4.0),
        egui::pos2(rect.max.x - delete_width, rect.max.y - 4.0),
    );

    let delete_rect = egui::Rect::from_min_max(
        egui::pos2(rect.max.x - delete_width, rect.min.y),
        rect.max,
    );
    let mut delete_ui = ui.new_child(egui::UiBuilder::new().max_rect(delete_rect));
    let deleted = delete_ui
        .centered_and_justified(|ui| {
            ui.add(
                egui::Button::new(
                    egui::RichText::new("\u{00d7}")
                        .size(18.0)
                        .color(egui::Color32::from_rgb(0xE0, 0x6C, 0x75)),
                )
                .frame(false),
            )
            .on_hover_text("Delete this secret")
            .clicked()
        })
        .inner;

    let mut inner = ui.new_child(egui::UiBuilder::new().max_rect(body_rect));
    inner.vertical(|ui| {
        ui.horizontal(|ui| {
            ui.colored_label(text_color, egui::RichText::new(&meta.name).strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.weak(meta.secret_type.label());
            });
        });
        ui.horizontal(|ui| {
            let mut subtitle = String::new();
            if !meta.username.is_empty() {
                subtitle.push_str(&meta.username);
            }
            if !meta.domain.is_empty() {
                if !subtitle.is_empty() {
                    subtitle.push_str("  ·  ");
                }
                subtitle.push_str(&meta.domain);
            }
            if !subtitle.is_empty() {
                ui.weak(subtitle);
            }
            if !meta.tags.is_empty() {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.weak(meta.tags.join(", "));
                });
            }
        });
    });

    RowAction {
        activated: response.clicked() && !deleted,
        deleted,
        response,
    }
}

/// Applies the popup's visual style.
fn configure_style(ctx: &egui::Context) {
    ctx.set_visuals(egui::Visuals::dark());
    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.window_margin = egui::Margin::same(12);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use sypher_core::model::SecretType;

    fn meta(name: &str, domain: &str) -> SecretMeta {
        let mut m = SecretMeta::new(name, SecretType::Password);
        m.domain = domain.to_string();
        m
    }

    /// Builds a `Popup` without a shell or GPU, to exercise the state
    /// machine that navigation and filtering depend on.
    fn popup() -> (Popup, std::sync::mpsc::Receiver<UiRequest>) {
        let (rtx, rrx) = std::sync::mpsc::channel();
        let popup = Popup {
            requests: rtx,
            mode: Mode::List,
            secrets: vec![
                meta("GitHub", "github.com"),
                meta("GitLab", "gitlab.com"),
                meta("Google", "google.com"),
            ],
            ranked: Vec::new(),
            searcher: Searcher::new(),
            context: SearchContext::default(),
            query: String::new(),
            selected: 0,
            lock_state: UiLockState::Locked,
            visible: true,
            needs_focus: false,
            message: None,
        };
        (popup, rrx)
    }

    /// Builds a `Keys` with everything released, then applies `f`.
    ///
    /// Driving the handlers directly rather than through egui keeps these
    /// tests free of a GPU and a compositor.
    fn keys_with(f: impl FnOnce(&mut Keys)) -> Keys {
        let mut k = Keys {
            escape: false,
            up: false,
            down: false,
            enter: false,
            tab: false,
            shift: false,
            ctrl: false,
            n: false,
            e: false,
            d: false,
            s: false,
        };
        f(&mut k);
        k
    }

    #[test]
    fn ranking_populates_the_visible_list() {
        let (mut p, _rx) = popup();
        p.rerank();
        assert_eq!(p.ranked.len(), 3);
    }

    #[test]
    fn filtering_narrows_the_list() {
        let (mut p, _rx) = popup();
        p.query = "gitlab".into();
        p.rerank();
        assert_eq!(p.ranked.len(), 1);
        assert_eq!(p.ranked[0].meta.name, "GitLab");
    }

    #[test]
    fn selection_is_clamped_when_the_list_shrinks() {
        // Typing after arrowing down must not leave the cursor past the end.
        let (mut p, _rx) = popup();
        p.rerank();
        p.selected = 2;

        p.query = "gitlab".into();
        p.rerank();
        assert_eq!(p.selected, 0, "selection must stay in range");
    }

    #[test]
    fn an_empty_result_set_clamps_to_zero() {
        let (mut p, _rx) = popup();
        p.selected = 2;
        p.query = "zzzznomatch".into();
        p.rerank();
        assert!(p.ranked.is_empty());
        assert_eq!(p.selected, 0);
    }

    #[test]
    fn enter_while_locked_requests_an_unlock_not_a_paste() {
        let (mut p, rx) = popup();
        p.rerank();
        p.lock_state = UiLockState::Locked;
        p.activate_selected();

        assert!(matches!(rx.try_recv(), Ok(UiRequest::Unlock)));
    }

    #[test]
    fn enter_while_unlocked_requests_the_secret() {
        let (mut p, rx) = popup();
        p.rerank();
        p.lock_state = UiLockState::Unlocked {
            remaining: std::time::Duration::from_secs(30),
        };
        let expected = p.ranked[0].meta.id;
        p.activate_selected();

        match rx.try_recv() {
            Ok(UiRequest::Use(id)) => assert_eq!(id, expected),
            other => panic!("expected Use, got {other:?}"),
        }
    }

    #[test]
    fn enter_while_waiting_for_a_touch_does_nothing() {
        // Otherwise a second Enter would queue a second assertion and make the
        // key blink twice.
        let (mut p, rx) = popup();
        p.rerank();
        p.lock_state = UiLockState::WaitingForTouch;
        p.activate_selected();
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn activating_an_empty_list_is_a_no_op() {
        let (mut p, rx) = popup();
        p.secrets.clear();
        p.rerank();
        p.lock_state = UiLockState::Unlocked {
            remaining: std::time::Duration::from_secs(30),
        };
        p.activate_selected();
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn ctrl_n_opens_an_empty_editor() {
        let (mut p, _rx) = popup();
        p.rerank();
        p.handle_list_keys(&keys_with(|k| {
            k.ctrl = true;
            k.n = true;
        }));
        match &p.mode {
            Mode::Edit(e) => assert!(e.is_new()),
            _ => panic!("expected the editor to open"),
        }
    }

    #[test]
    fn ctrl_e_asks_the_worker_to_decrypt_rather_than_editing_locally() {
        // The popup has no plaintext and must not invent a way to get it; the
        // worker owns the assertion.
        let (mut p, rx) = popup();
        p.rerank();
        let target = p.ranked[0].meta.id;
        p.handle_list_keys(&keys_with(|k| {
            k.ctrl = true;
            k.e = true;
        }));
        assert!(matches!(p.mode, Mode::List), "must not open until decrypted");
        match rx.try_recv() {
            Ok(UiRequest::BeginEdit(id)) => assert_eq!(id, target),
            other => panic!("expected BeginEdit, got {other:?}"),
        }
    }

    #[test]
    fn ctrl_d_asks_for_confirmation_before_deleting() {
        let (mut p, rx) = popup();
        p.rerank();
        p.handle_list_keys(&keys_with(|k| {
            k.ctrl = true;
            k.d = true;
        }));
        assert!(matches!(p.mode, Mode::ConfirmDelete(..)));
        assert!(rx.try_recv().is_err(), "must not delete before confirming");
    }

    #[test]
    fn confirming_deletes_and_escaping_does_not() {
        let (mut p, rx) = popup();
        p.rerank();
        let target = p.ranked[0].meta.id;

        p.mode = Mode::ConfirmDelete(target, "GitHub".into());
        p.handle_confirm_keys(&keys_with(|k| k.escape = true));
        assert!(rx.try_recv().is_err(), "escape must cancel");

        p.mode = Mode::ConfirmDelete(target, "GitHub".into());
        p.handle_confirm_keys(&keys_with(|k| k.enter = true));
        match rx.try_recv() {
            Ok(UiRequest::Delete(id)) => assert_eq!(id, target),
            other => panic!("expected Delete, got {other:?}"),
        }
    }

    #[test]
    fn escaping_the_editor_returns_to_the_list_without_saving() {
        let (mut p, rx) = popup();
        let mut editor = Editor::new();
        editor.name = "Draft".into();
        editor.value = "unsaved".into();
        p.mode = Mode::Edit(Box::new(editor));

        p.handle_edit_keys(&keys_with(|k| k.escape = true));

        assert!(matches!(p.mode, Mode::List));
        assert!(rx.try_recv().is_err(), "abandoning must not save");
    }

    #[test]
    fn saving_a_valid_form_sends_it_to_the_worker() {
        let (mut p, rx) = popup();
        let mut editor = Editor::new();
        editor.name = "New Thing".into();
        editor.value = "s3cr3t".into();
        p.mode = Mode::Edit(Box::new(editor));

        p.handle_edit_keys(&keys_with(|k| {
            k.ctrl = true;
            k.s = true;
        }));

        match rx.try_recv() {
            Ok(UiRequest::Save { meta, payload, is_update }) => {
                assert_eq!(meta.name, "New Thing");
                assert_eq!(payload.value.as_slice(), b"s3cr3t");
                assert!(!is_update);
            }
            other => panic!("expected Save, got {other:?}"),
        }
        assert!(matches!(p.mode, Mode::List), "saving returns to the list");
    }

    #[test]
    fn an_invalid_form_reports_the_error_and_stays_open() {
        let (mut p, rx) = popup();
        // No name, which `build` rejects.
        let mut editor = Editor::new();
        editor.value = "x".into();
        p.mode = Mode::Edit(Box::new(editor));

        p.handle_edit_keys(&keys_with(|k| {
            k.ctrl = true;
            k.s = true;
        }));

        match &p.mode {
            Mode::Edit(e) => assert!(e.error.is_some(), "the user needs to see why"),
            _ => panic!("an invalid form must stay open"),
        }
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn hiding_drops_the_editor_and_its_plaintext() {
        let (mut p, _rx) = popup();
        let mut editor = Editor::new();
        editor.value = "sensitive".into();
        p.mode = Mode::Edit(Box::new(editor));
        p.visible = true;

        p.hide();

        assert!(matches!(p.mode, Mode::List), "the editor must not survive a hide");
    }

    #[test]
    fn a_submitted_pin_reaches_the_worker_and_is_cleared() {
        let (mut p, rx) = popup();
        p.handle_event(DaemonEvent::RequestPin { retry: false });
        let Mode::Pin(entry) = &mut p.mode else {
            panic!("expected the PIN prompt");
        };
        entry.value = "123456".into();

        p.handle_pin_keys(&keys_with(|k| k.enter = true));

        match rx.try_recv() {
            Ok(UiRequest::PinResponse(Some(pin))) => assert_eq!(pin, "123456"),
            other => panic!("expected a PIN, got {other:?}"),
        }
        assert!(
            matches!(p.mode, Mode::List),
            "the prompt must close so the PIN is not left on screen"
        );
    }

    #[test]
    fn an_empty_pin_is_not_submitted() {
        // Otherwise Enter on an empty field burns one of the key's few PIN
        // retries for nothing.
        let (mut p, rx) = popup();
        p.handle_event(DaemonEvent::RequestPin { retry: false });
        p.handle_pin_keys(&keys_with(|k| k.enter = true));
        assert!(rx.try_recv().is_err());
        assert!(matches!(p.mode, Mode::Pin(_)), "the prompt should stay open");
    }

    #[test]
    fn cancelling_the_pin_prompt_answers_none() {
        // The assertion thread is blocked on this; without an answer it would
        // sit there until its timeout.
        let (mut p, rx) = popup();
        p.handle_event(DaemonEvent::RequestPin { retry: false });
        p.handle_pin_keys(&keys_with(|k| k.escape = true));

        assert!(matches!(rx.try_recv(), Ok(UiRequest::PinResponse(None))));
        assert!(matches!(p.mode, Mode::List));
    }

    #[test]
    fn a_pin_request_forces_the_popup_visible() {
        // The user may have dismissed the popup while the touch was pending.
        let (mut p, _rx) = popup();
        p.visible = false;
        p.handle_event(DaemonEvent::RequestPin { retry: true });
        assert!(p.visible, "a blocked assertion must be able to ask");
    }

    #[test]
    fn deleting_a_row_asks_for_confirmation_rather_than_deleting() {
        let (mut p, rx) = popup();
        p.rerank();
        let target = p.ranked[1].meta.id;

        // Simulates the row's x being clicked.
        p.selected = 1;
        p.mode = Mode::ConfirmDelete(target, p.ranked[1].meta.name.clone());

        assert!(rx.try_recv().is_err(), "nothing may be deleted yet");
        p.handle_confirm_keys(&keys_with(|k| k.enter = true));
        match rx.try_recv() {
            Ok(UiRequest::Delete(id)) => assert_eq!(id, target),
            other => panic!("expected Delete, got {other:?}"),
        }
    }

    #[test]
    fn domain_context_reorders_the_list() {
        let (mut p, _rx) = popup();
        p.context = SearchContext {
            host: Some("gitlab.com".into()),
            application: None,
        };
        p.rerank();
        assert_eq!(p.ranked[0].meta.name, "GitLab");
    }
}
