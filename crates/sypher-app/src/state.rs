//! Shared state and the protocol between the UI thread and the async worker.
//!
//! ## Why there are two threads
//!
//! `winit` requires the event loop to own the main thread, and the portal,
//! DBus and hardware work is all async or blocking. So the daemon runs an
//! eframe event loop on the main thread and a tokio runtime on a second
//! thread, and they talk over channels.
//!
//! ## The rule that shapes this module
//!
//! **The UI thread must never block on the vault.** An unlock waits for a
//! physical touch, which can take seconds, and a frozen popup during that wait
//! would look like a crash. So the UI owns no `Session`; it holds a cached
//! metadata list and sends [`UiRequest`]s. The worker owns the `Session`,
//! does everything that can block, and reports back with [`DaemonEvent`]s.
//!
//! That also means the mutex around the session is only ever contended by the
//! worker, which keeps its critical sections simple to reason about.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use uuid::Uuid;

use sypher_core::model::{SecretMeta, SecretPayload};
use sypher_core::vault::session::Session;

/// Messages from the worker to the UI.
#[derive(Debug, Clone)]
pub enum DaemonEvent {
    /// Show the popup, seeded with this metadata and context.
    Show {
        secrets: Vec<SecretMeta>,
        /// Hostname of the focused browser tab, when known (M7).
        host: Option<String>,
        /// Window class of the previously focused application (M7).
        application: Option<String>,
    },
    /// Hide the popup.
    Hide,
    /// The lock state changed; update the header and enable or disable rows.
    LockChanged(UiLockState),
    /// An operation failed. Rendered in the popup rather than only logged,
    /// because a daemon error the user cannot see is one they cannot act on.
    Error(String),
    /// A transient confirmation, e.g. "pasted".
    Status(String),
    /// A secret was decrypted for editing. Carries the plaintext, so it is
    /// only ever sent in response to an explicit edit request that already
    /// required a fresh assertion.
    EditReady {
        meta: SecretMeta,
        payload: SecretPayload,
    },
    /// The vault changed; the popup should reload its metadata.
    Refresh(Vec<SecretMeta>),
    /// The authenticator demanded its PIN. The popup must collect one and
    /// answer with [`UiRequest::PinResponse`], or the blocked assertion will
    /// time out.
    RequestPin {
        /// Set when a previous attempt was rejected, so the popup can say so.
        retry: bool,
    },
}

/// Messages from the UI to the worker.
#[derive(Debug, Clone)]
pub enum UiRequest {
    /// Begin an unlock: perform an assertion, prompting for a touch.
    Unlock,
    /// The user chose a secret. Decrypt and type it (M5).
    Use(Uuid),
    /// The popup closed; nothing to do but note it.
    Dismissed,
    /// Extend the unlock window because the user is actively interacting.
    Touch,
    /// Decrypt a secret so it can be edited. Always forces a fresh assertion
    /// when `confirm_on_edit` is set, even if the vault is already unlocked.
    BeginEdit(Uuid),
    /// Store a new secret, or replace an existing one when `meta.id` matches
    /// a stored secret and `is_update` is set.
    Save {
        meta: SecretMeta,
        payload: SecretPayload,
        is_update: bool,
    },
    /// Remove a secret. Requires a fresh assertion first.
    Delete(Uuid),
    /// The PIN the user typed, or `None` if they cancelled.
    PinResponse(Option<String>),
}

/// The lock state as the UI needs to render it.
///
/// Deliberately not `sypher_core`'s `LockState`: the UI needs a `Waiting`
/// variant that the vault has no concept of, because from the vault's point of
/// view an in-progress assertion is simply still locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiLockState {
    /// No inner key. Rows are visible but cannot be used.
    Locked,
    /// An assertion is in flight; the user should touch their key.
    WaitingForTouch,
    /// Usable, with this much time left before the automatic relock.
    Unlocked { remaining: Duration },
}

impl UiLockState {
    pub fn is_unlocked(&self) -> bool {
        matches!(self, UiLockState::Unlocked { .. })
    }
}

/// State shared between the two threads.
///
/// The session mutex is only taken by the worker. `unlock_in_flight` exists so
/// that a second hotkey press during a touch prompt does not queue a second
/// assertion, which would make the key blink twice and confuse the user.
pub struct Shared {
    session: Mutex<Session>,
    unlock_in_flight: AtomicBool,
}

impl Shared {
    pub fn new(session: Session) -> Arc<Self> {
        Arc::new(Self {
            session: Mutex::new(session),
            unlock_in_flight: AtomicBool::new(false),
        })
    }

    /// Runs `f` with the session locked.
    ///
    /// Recovers from a poisoned mutex rather than propagating the panic: a
    /// worker that panicked mid-operation should not permanently disable the
    /// daemon, and the vault's own invariants do not depend on the mutex.
    pub fn with_session<T>(&self, f: impl FnOnce(&mut Session) -> T) -> T {
        let mut guard = self
            .session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut guard)
    }

    /// Claims the right to start an unlock.
    ///
    /// Returns `false` if one is already running, in which case the caller
    /// must not start another.
    pub fn begin_unlock(&self) -> bool {
        self.unlock_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Releases the claim taken by [`Shared::begin_unlock`].
    pub fn end_unlock(&self) {
        self.unlock_in_flight.store(false, Ordering::Release);
    }

    pub fn unlock_in_flight(&self) -> bool {
        self.unlock_in_flight.load(Ordering::Acquire)
    }

    /// Current lock state, translated for the UI.
    ///
    /// Ticks the session, so an expired deadline is acted on here rather than
    /// merely observed.
    pub fn ui_lock_state(&self) -> UiLockState {
        if self.unlock_in_flight() {
            return UiLockState::WaitingForTouch;
        }
        self.with_session(|s| match s.tick() {
            sypher_core::vault::session::LockState::Locked => UiLockState::Locked,
            sypher_core::vault::session::LockState::Unlocked { remaining } => {
                UiLockState::Unlocked { remaining }
            }
        })
    }
}

#[cfg(all(test, feature = "mock-hw"))]
mod tests {
    use super::*;
    use sypher_core::vault::db::Vault;
    use sypher_core::vault::paths::VaultPaths;

    fn shared(timeout: Duration) -> (tempfile::TempDir, Arc<Shared>) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = VaultPaths::at(tmp.path().join("vault"));
        paths.ensure_dirs().unwrap();
        let vault = Vault::open(&paths).unwrap();
        let session = Session::initialize(
            vault,
            &sypher_core::mock_hw::MockOuterProvider::new(&paths),
            &sypher_core::mock_hw::MockInnerProvider::new(&paths),
            timeout,
        )
        .unwrap();
        (tmp, Shared::new(session))
    }

    #[test]
    fn only_one_unlock_can_be_in_flight() {
        let (_tmp, shared) = shared(Duration::from_secs(60));
        assert!(shared.begin_unlock(), "first claim should succeed");
        assert!(!shared.begin_unlock(), "second claim must be refused");

        shared.end_unlock();
        assert!(shared.begin_unlock(), "claim available again after release");
    }

    #[test]
    fn an_in_flight_unlock_shows_as_waiting() {
        let (_tmp, shared) = shared(Duration::from_secs(60));
        assert!(shared.ui_lock_state().is_unlocked());

        shared.begin_unlock();
        assert_eq!(shared.ui_lock_state(), UiLockState::WaitingForTouch);

        shared.end_unlock();
        assert!(shared.ui_lock_state().is_unlocked());
    }

    #[test]
    fn lock_state_reflects_the_timeout() {
        let (_tmp, shared) = shared(Duration::from_millis(50));
        assert!(shared.ui_lock_state().is_unlocked());
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(shared.ui_lock_state(), UiLockState::Locked);
    }
}
