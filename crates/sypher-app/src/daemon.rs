//! The long-running daemon: hotkey, popup, and the lock timer.
//!
//! ## Startup order
//!
//! 1. Open the vault and recover the outer key. This happens once, at start,
//!    and needs no user interaction.
//! 2. Start the tokio worker on a background thread: portal session, relock
//!    timer, and the request loop.
//! 3. Hand the main thread to the Wayland shell, which owns it until exit.
//!
//! Step 3 is why the worker goes on the background thread rather than the
//! other way around: the Wayland event loop wants the main thread, and the
//! GPU objects it owns are not `Send`.
//!
//! ## Popup latency
//!
//! The GPU device, the egui context and its font atlas are all built once at
//! startup and kept for the process lifetime; only the Wayland surface itself
//! is created per popup. That is what keeps the hotkey feeling instant without
//! needing a permanently-mapped window, which Wayland would not allow anyway.
//! See [`crate::ui::shell`] for why the window cannot simply be hidden.

use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::mpsc as tokio_mpsc;

use sypher_core::config::Config;
use sypher_core::vault::db::Vault;
use sypher_core::vault::paths::VaultPaths;
use sypher_core::vault::session::Session;

use crate::state::{DaemonEvent, Shared, UiLockState, UiRequest};
use crate::browser::kwin::{self, WindowTracker};
use crate::paste::Typist;
use crate::pin::PinBroker;
use crate::{hotkey, hw};

/// How often the worker re-checks the unlock deadline.
///
/// Half a second is well under the shortest sensible timeout and keeps the
/// header countdown honest, while costing nothing measurable when idle.
const TICK_INTERVAL: Duration = Duration::from_millis(500);

/// Runs the daemon. Returns when the popup's event loop exits.
pub fn run(paths: &VaultPaths) -> Result<()> {
    hw::warn_if_mock();

    if !paths.is_initialized() {
        anyhow::bail!(
            "no vault at {}. Run `sypherstore init` first.",
            paths.root.display()
        );
    }

    let config = Config::load(&paths.config()).context("loading the config")?;
    let vault = Vault::open(paths).context("opening the vault")?;
    let session = Session::open_locked(vault, hw::outer(paths).as_ref(), config.unlock_timeout())
        .context("recovering the machine key (is this the machine the vault was created on?)")?;

    tracing::info!(
        timeout_secs = config.unlock_timeout_secs,
        hotkey = %config.hotkey,
        "daemon starting"
    );

    let shared = Shared::new(session);

    // Worker -> UI uses a calloop channel so that sending an event also wakes
    // the Wayland event loop; a plain mpsc would leave the shell asleep until
    // the next input arrived, and the hotkey would appear to do nothing.
    let (event_tx, event_rx) = calloop::channel::channel::<DaemonEvent>();
    // UI -> worker is a plain channel, bridged into async by the worker.
    let (request_tx, request_rx) = std_mpsc::channel::<UiRequest>();

    let worker = spawn_worker(WorkerArgs {
        paths: paths.clone(),
        config: config.clone(),
        shared: Arc::clone(&shared),
        event_tx,
        request_rx,
    });

    // Blocks until the daemon exits.
    let result = crate::ui::shell::run(event_rx, request_tx);

    worker.shutdown();
    result
}

struct WorkerArgs {
    paths: VaultPaths,
    config: Config,
    shared: Arc<Shared>,
    event_tx: calloop::channel::Sender<DaemonEvent>,
    request_rx: std_mpsc::Receiver<UiRequest>,
}

/// Handle to the background worker thread.
struct Worker {
    shutdown: tokio_mpsc::UnboundedSender<()>,
    handle: std::thread::JoinHandle<()>,
}

impl Worker {
    fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.join();
    }
}

/// Starts the tokio runtime on its own thread and runs the worker loop there.
fn spawn_worker(args: WorkerArgs) -> Worker {
    let (shutdown_tx, shutdown_rx) = tokio_mpsc::unbounded_channel();

    let handle = std::thread::Builder::new()
        .name("sypherstore-worker".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(2)
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!(error = %e, "could not start the async runtime");
                    return;
                }
            };
            runtime.block_on(worker_loop(args, shutdown_rx));
            tracing::info!("worker stopped");
        })
        .expect("spawning the worker thread");

    Worker {
        shutdown: shutdown_tx,
        handle,
    }
}

/// The worker's main loop.
///
/// Owns the vault session and everything that can block, so the UI thread
/// never has to wait on hardware.
async fn worker_loop(args: WorkerArgs, mut shutdown: tokio_mpsc::UnboundedReceiver<()>) {
    let WorkerArgs {
        paths,
        config,
        shared,
        event_tx,
        request_rx,
    } = args;

    let ui = UiHandle { events: event_tx };

    // Bridge the UI's synchronous channel into the async world. A dedicated
    // blocking thread is the simplest correct way: `Receiver::recv` blocks,
    // and doing that on a runtime worker would stall other tasks.
    let (req_tx, mut requests) = tokio_mpsc::unbounded_channel::<UiRequest>();
    std::thread::Builder::new()
        .name("sypherstore-ui-bridge".into())
        .spawn(move || {
            while let Ok(req) = request_rx.recv() {
                if req_tx.send(req).is_err() {
                    break;
                }
            }
        })
        .expect("spawning the ui bridge thread");

    // Install signal handlers before anything that can block. Until the
    // handler exists, SIGUSR1's default disposition terminates the process,
    // so a developer testing the popup would silently kill the daemon instead.
    //
    // SIGUSR1 simulates a hotkey press. The portal path depends on the
    // compositor, the portal backend and a user-granted permission, none of
    // which can be exercised from a terminal; this makes the popup itself
    // testable in isolation from all three.
    let mut sigusr1 =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!(error = %e, "could not install the SIGUSR1 handler");
                None
            }
        };

    // Registering the global shortcut can block indefinitely: `BindShortcuts`
    // does not return until the user answers the portal's permission dialog,
    // and they may never answer it. Awaiting it here would leave the worker
    // deaf to every other event in the meantime, including its own shutdown,
    // so registration runs as a task and reports back over a oneshot.
    let (hotkey_tx, mut hotkeys) = tokio_mpsc::unbounded_channel::<()>();
    let (session_tx, mut session_rx) = tokio::sync::oneshot::channel();
    let hotkey_config = config.hotkey.clone();
    tokio::spawn(async move {
        let _ = session_tx.send(hotkey::register(&hotkey_config, hotkey_tx).await);
    });
    // Holds the portal session once it arrives; dropping it unbinds the
    // shortcut, so it must live as long as the daemon.
    let mut _hotkey_session = None;

    // The authenticator's PIN, when it wants one, is collected in the popup.
    // The daemon has no terminal, so without this an assertion on a
    // PIN-protected key would fail outright.
    let pin_ui = ui.clone();
    let (pin_broker, pin_answers) = PinBroker::new(move |retry| {
        pin_ui.send(DaemonEvent::RequestPin { retry });
    });

    // Window tracking is push-based: KWin reports activations as they happen
    // so nothing has to be queried on the hotkey's critical path.
    let tracker = WindowTracker::new();
    let _kwin = if config.browser_detection {
        match kwin::start(tracker.clone()).await {
            Ok(handle) => Some(handle),
            Err(e) => {
                // Degrades to showing every secret, which is the documented
                // fallback, so this is a warning rather than a failure.
                tracing::warn!(
                    error = %format!("{e:#}"),
                    "window tracking unavailable; the popup will not filter by site"
                );
                None
            }
        }
    } else {
        None
    };

    // Connected lazily on the first paste. Doing it at startup would pop a
    // consent dialog during login, before the user has asked for anything.
    let mut typist: Option<Typist> = None;

    let mut ticker = tokio::time::interval(TICK_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_state = UiLockState::Locked;

    loop {
        tokio::select! {
            _ = shutdown.recv() => {
                tracing::info!("worker shutting down");
                if let Some(kwin) = &_kwin {
                    kwin.shutdown().await;
                }
                shared.with_session(|s| s.lock());
                break;
            }

            Some(()) = hotkeys.recv() => {
                on_hotkey(&shared, &paths, &config, &tracker, &ui, &pin_broker).await;
            }

            result = &mut session_rx, if _hotkey_session.is_none() => {
                match result {
                    Ok(Ok(session)) => {
                        tracing::info!("global shortcut registered");
                        _hotkey_session = Some(session);
                    }
                    Ok(Err(e)) => {
                        // Not fatal: the CLI still works and the user can bind
                        // a shortcut by hand in System Settings, so a portal
                        // failure must not look like a broken install.
                        tracing::error!(
                            error = %format!("{e:#}"),
                            "global shortcut unavailable"
                        );
                        ui.error(format!("Global shortcut unavailable: {e}"));
                    }
                    Err(_) => tracing::error!("the shortcut registration task died"),
                }
            }

            Some(()) = async {
                match sigusr1.as_mut() {
                    Some(sig) => sig.recv().await,
                    // No handler: park this branch forever rather than let
                    // `select!` spin on an immediately-ready future.
                    None => std::future::pending().await,
                }
            } => {
                tracing::info!("SIGUSR1: simulating a hotkey press");
                on_hotkey(&shared, &paths, &config, &tracker, &ui, &pin_broker).await;
            }

            Some(request) = requests.recv() => {
                on_request(request, &shared, &paths, &config, &ui, &mut typist, &pin_answers, &pin_broker).await;
            }

            _ = ticker.tick() => {
                // Ticking is what actually enforces the timeout: without it a
                // vault left unlocked with the popup hidden would stay
                // unlocked until the next interaction.
                let state = shared.ui_lock_state();
                if state != last_state {
                    if matches!(state, UiLockState::Locked)
                        && matches!(last_state, UiLockState::Unlocked { .. })
                    {
                        tracing::info!("relocked on timeout");
                    }
                    last_state = state;
                    ui.lock_changed(state);
                } else if state.is_unlocked() {
                    // Refresh the countdown even when the variant is
                    // unchanged, so the header does not appear frozen.
                    ui.lock_changed(state);
                    last_state = state;
                }
            }
        }
    }
}

/// Handles a hotkey press.
///
/// Metadata is now encrypted, so the list cannot be shown until the vault is
/// unlocked. The popup opens immediately (empty while locked) and the unlock,
/// which blocks on a touch and PIN, runs separately; when it finishes the list
/// is decrypted and pushed to the popup. When the vault is already unlocked the
/// list is loaded up front so the popup appears populated.
async fn on_hotkey(
    shared: &Arc<Shared>,
    paths: &VaultPaths,
    config: &Config,
    tracker: &WindowTracker,
    ui: &UiHandle,
    pin_broker: &Arc<PinBroker>,
) {
    let (host, application) = detect_context(config, tracker).await;

    let unlocked = shared.ui_lock_state().is_unlocked();
    let secrets = if unlocked {
        match shared.with_session(|s| s.list()) {
            Ok(secrets) => secrets,
            Err(e) => {
                tracing::error!(error = %e, "could not read the vault");
                Vec::new()
            }
        }
    } else {
        // Locked: reveal nothing. The list arrives via Refresh after unlock.
        Vec::new()
    };

    ui.show(secrets, host, application);
    ui.lock_changed(shared.ui_lock_state());

    // Unlocking up front means the secret is ready by the time the user has
    // typed enough to pick one, rather than making them wait afterwards.
    if !unlocked {
        start_unlock(shared, paths, ui, pin_broker);
    } else {
        shared.with_session(|s| s.touch());
    }
}

async fn on_request(
    request: UiRequest,
    shared: &Arc<Shared>,
    paths: &VaultPaths,
    config: &Config,
    ui: &UiHandle,
    typist: &mut Option<Typist>,
    pin_answers: &std_mpsc::Sender<Option<String>>,
    pin_broker: &Arc<PinBroker>,
) {
    match request {
        UiRequest::Unlock => start_unlock(shared, paths, ui, pin_broker),

        UiRequest::PinResponse(pin) => {
            // Hands the answer to whichever assertion thread is blocked on it.
            if pin_answers.send(pin).is_err() {
                tracing::warn!("a PIN arrived with no assertion waiting for it");
            }
        }

        UiRequest::Touch => shared.with_session(|s| s.touch()),

        UiRequest::Dismissed => {
            tracing::debug!("popup dismissed");
        }

        UiRequest::Use(id) => {
            let payload = match shared.with_session(|s| s.open(&id)) {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(secret_id = %id, error = %e, "could not open the secret");
                    ui.error(format!("{e}"));
                    return;
                }
            };

            // Hide first. The popup holds an exclusive keyboard grab, so
            // nothing can be typed anywhere until its surface is gone.
            ui.send(DaemonEvent::Hide);

            if let Err(e) = deliver(&payload.value, config, paths, typist).await {
                tracing::error!(error = %format!("{e:#}"), "could not deliver the secret");
                ui.error(format!("{e}"));
            } else {
                ui.status("Typed.");
            }
            // `payload` drops here, zeroizing every buffer inside it.
        }

        UiRequest::BeginEdit(id) => {
            // Revealing an existing secret in an editable field is a stronger
            // action than pasting one: the plaintext goes on screen and sits
            // there. When `confirm_on_edit` is set we demand a fresh touch
            // even if the vault is already unlocked, so an unlocked session
            // left unattended cannot be used to read secrets back out.
            if config.confirm_on_edit {
                shared.with_session(|s| s.lock());
                if let Err(e) = reassert(shared, paths, pin_broker).await {
                    tracing::warn!(error = %e, "re-assertion for edit failed");
                    ui.error(format!("{e}"));
                    return;
                }
            }

            let result = shared.with_session(|s| {
                let meta = s.meta_for(&id)?;
                let payload = s.open(&id)?;
                Ok::<_, sypher_core::vault::session::SessionError>((meta, payload))
            });

            match result {
                Ok((meta, payload)) => {
                    tracing::info!(secret_id = %id, "secret opened for editing");
                    ui.send(DaemonEvent::EditReady { meta, payload });
                }
                Err(e) => {
                    tracing::error!(secret_id = %id, error = %e, "could not open for editing");
                    ui.error(format!("{e}"));
                }
            }
        }

        UiRequest::Save { meta, payload, is_update } => {
            // Saving re-seals, which needs the inner key.
            if !shared.ui_lock_state().is_unlocked() {
                if let Err(e) = reassert(shared, paths, pin_broker).await {
                    ui.error(format!("{e}"));
                    return;
                }
            }

            let outcome = shared.with_session(|s| {
                if is_update {
                    s.update(&meta, &payload)
                } else {
                    s.add(&meta, &payload)
                }
            });

            match outcome {
                Ok(()) => {
                    tracing::info!(secret_id = %meta.id, is_update, "secret saved");
                    ui.status(if is_update { "Updated." } else { "Added." });
                    refresh(shared, ui);
                }
                Err(e) => {
                    tracing::error!(error = %e, "could not save the secret");
                    ui.error(format!("{e}"));
                }
            }
        }

        UiRequest::Delete(id) => {
            // Destroying a secret demands a fresh touch, even while unlocked.
            // Deleting needs no key cryptographically, so this is a policy
            // choice: it stops anyone who finds an unlocked session from
            // wiping the vault. The cost is that a user without their
            // authenticator cannot clean up entries.
            shared.with_session(|s| s.lock());
            if let Err(e) = reassert(shared, paths, pin_broker).await {
                tracing::warn!(error = %e, "re-assertion for delete failed");
                ui.error(format!("Delete cancelled: {e}"));
                return;
            }

            match shared.with_session(|s| s.delete(&id)) {
                Ok(()) => {
                    tracing::info!(secret_id = %id, "secret deleted");
                    ui.status("Deleted.");
                    refresh(shared, ui);
                }
                Err(e) => {
                    tracing::error!(secret_id = %id, error = %e, "could not delete");
                    ui.error(format!("{e}"));
                }
            }
        }
    }
}

/// Performs an assertion on a blocking thread and waits for it.
///
/// Unlike [`start_unlock`], this is awaited by the caller, because the actions
/// that use it are meaningless without the key.
async fn reassert(
    shared: &Arc<Shared>,
    paths: &VaultPaths,
    pin_broker: &Arc<PinBroker>,
) -> Result<()> {
    let shared = Arc::clone(shared);
    let paths = paths.clone();
    let broker = Arc::clone(pin_broker);
    tokio::task::spawn_blocking(move || {
        let provider = hw::inner_with_prompt(&paths, pin_prompt(broker));
        shared.with_session(|s| s.unlock(provider.as_ref()))
    })
    .await
    .context("the assertion task panicked")?
    .context("unlocking the vault")?;
    Ok(())
}

/// Adapts the broker into the callback the FIDO provider expects.
///
/// The provider only invokes this when the device actually demands
/// verification, so a key without a PIN never causes a prompt.
fn pin_prompt(
    broker: Arc<PinBroker>,
) -> Arc<dyn Fn() -> Result<String, sypher_core::crypto::keys::ProviderError> + Send + Sync> {
    Arc::new(move || broker.request_pin(false))
}

/// Pushes the current metadata to the popup after a change.
fn refresh(shared: &Arc<Shared>, ui: &UiHandle) {
    match shared.with_session(|s| s.list()) {
        Ok(secrets) => ui.send(DaemonEvent::Refresh(secrets)),
        Err(e) => tracing::error!(error = %e, "could not reload the vault"),
    }
}

/// Starts an assertion on a blocking thread.
///
/// The assertion waits on a physical touch, so it must not run on a runtime
/// worker: doing so would stall the tick timer and the hotkey stream for as
/// long as the user takes to reach for their key.
fn start_unlock(
    shared: &Arc<Shared>,
    paths: &VaultPaths,
    ui: &UiHandle,
    pin_broker: &Arc<PinBroker>,
) {
    if !shared.begin_unlock() {
        tracing::debug!("an unlock is already in flight; ignoring");
        return;
    }
    ui.lock_changed(UiLockState::WaitingForTouch);

    let shared = Arc::clone(shared);
    let paths = paths.clone();
    let ui = ui.clone();
    let broker = Arc::clone(pin_broker);

    tokio::task::spawn_blocking(move || {
        let provider = hw::inner_with_prompt(&paths, pin_prompt(broker));
        let result = shared.with_session(|s| s.unlock(provider.as_ref()));
        shared.end_unlock();

        match result {
            Ok(()) => {
                tracing::info!("unlocked via popup");
                ui.lock_changed(shared.ui_lock_state());
                // The list was empty while locked; now that metadata can be
                // decrypted, push the real contents to the popup.
                refresh(&shared, &ui);
                ui.status("Unlocked.");
            }
            Err(e) => {
                tracing::warn!(error = %e, "unlock failed");
                ui.lock_changed(UiLockState::Locked);
                ui.error(format!("{e}"));
            }
        }
    });
}

/// Works out what the user was looking at, within a hard time budget.
///
/// Returns `(host, application)`. Either may be `None`, and both being `None`
/// simply means the popup shows everything, which is always a valid outcome.
///
/// The window class is free: it was pushed to us by KWin ahead of time. Only
/// the URL costs anything, and only for a browser.
async fn detect_context(
    config: &Config,
    tracker: &WindowTracker,
) -> (Option<String>, Option<String>) {
    if !config.browser_detection {
        return (None, None);
    }

    let window = tracker.current();
    if window.class.is_empty() {
        return (None, None);
    }

    let application = Some(window.app_name());

    if !window.is_browser() {
        // A non-browser window can still match an application-bound secret.
        return (None, application);
    }

    let budget = Duration::from_millis(config.browser_detect_timeout_ms);
    let url = crate::browser::url::focused_url(&window.app_name(), budget).await;
    let host = url.as_deref().and_then(sypher_core::search::domain::normalize_host);

    if let Some(host) = &host {
        tracing::info!(host = %host, "filtering the popup by site");
    }
    (host, application)
}

/// Types a secret into the focused window, or falls back to the clipboard.
///
/// The RemoteDesktop session is established on first use and then reused: the
/// portal handshake costs a round trip and, without a stored restore token,
/// a consent dialog every single time.
async fn deliver(
    secret: &sypher_core::secure::SecureBuf,
    config: &Config,
    paths: &VaultPaths,
    typist: &mut Option<Typist>,
) -> Result<()> {
    if typist.is_none() {
        match Typist::connect(config.remote_desktop_restore_token.clone()).await {
            Ok(connected) => {
                // Persist the token so the next daemon start skips the dialog.
                if let Some(token) = connected.restore_token() {
                    if config.remote_desktop_restore_token.as_deref() != Some(token) {
                        let mut updated = config.clone();
                        updated.remote_desktop_restore_token = Some(token.to_string());
                        if let Err(e) = updated.save(&paths.config()) {
                            // Not fatal: the session works, it just means the
                            // consent dialog returns next time.
                            tracing::warn!(error = %e, "could not save the restore token");
                        } else {
                            tracing::info!("saved the RemoteDesktop restore token");
                        }
                    }
                }
                *typist = Some(connected);
            }
            Err(e) => {
                if !config.clipboard_fallback {
                    return Err(e).context(
                        "keyboard access unavailable, and the clipboard fallback is disabled \
                         (set clipboard_fallback in config.json to enable it)",
                    );
                }
                tracing::warn!(
                    error = %format!("{e:#}"),
                    "RemoteDesktop unavailable, falling back to the clipboard"
                );
                return crate::paste::copy_via_clipboard(
                    secret,
                    Duration::from_millis(config.clipboard_clear_ms),
                );
            }
        }
    }

    let Some(active) = typist.as_ref() else {
        return Err(anyhow::anyhow!("no keyboard session available"));
    };
    active.type_secret(secret).await
}

/// Sends events to the UI thread and wakes its event loop.
///
/// The calloop channel does both in one step: the send is what breaks the
/// shell out of its blocking wait on the compositor.
#[derive(Clone)]
struct UiHandle {
    events: calloop::channel::Sender<DaemonEvent>,
}

impl UiHandle {
    fn send(&self, event: DaemonEvent) {
        // A failed send means the UI is gone, which happens during shutdown.
        let _ = self.events.send(event);
    }

    fn show(
        &self,
        secrets: Vec<sypher_core::model::SecretMeta>,
        host: Option<String>,
        application: Option<String>,
    ) {
        self.send(DaemonEvent::Show {
            secrets,
            host,
            application,
        });
    }

    fn lock_changed(&self, state: UiLockState) {
        self.send(DaemonEvent::LockChanged(state));
    }

    fn error(&self, msg: String) {
        self.send(DaemonEvent::Error(msg));
    }

    fn status(&self, msg: impl Into<String>) {
        self.send(DaemonEvent::Status(msg.into()));
    }
}
