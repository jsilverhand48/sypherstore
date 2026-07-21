//! Collecting an authenticator PIN through the popup.
//!
//! ## The shape of the problem
//!
//! The CTAP library's PIN hook is a synchronous callback: it is invoked from
//! deep inside a blocking `make_credential` or `get_assertion` call and must
//! return a `String`. The popup, meanwhile, lives on a different thread and
//! only produces input frame by frame.
//!
//! So the callback has to block while the UI runs. That is safe here for one
//! specific reason: every assertion already runs on a `spawn_blocking` thread
//! precisely because it waits on a human. Blocking that thread a little longer
//! costs nothing, and the UI thread is never involved.
//!
//! ## Why there is a timeout
//!
//! If the popup were dismissed without answering, the callback would wait
//! forever and leak a blocking thread, and the vault would appear wedged.
//! The broker therefore gives up after [`PIN_TIMEOUT`] and reports a
//! cancellation, which surfaces as a normal failed unlock.

use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::Mutex;
use std::time::Duration;

use sypher_core::crypto::keys::ProviderError;

/// How long to wait for the user to type a PIN before giving up.
///
/// Generous, because the user may have to find the popup and read it, but
/// finite so a dismissed prompt cannot wedge an assertion thread.
const PIN_TIMEOUT: Duration = Duration::from_secs(120);

/// Bridges the synchronous CTAP PIN callback to the asynchronous UI.
pub struct PinBroker {
    /// Asks the popup to show a PIN field.
    request: Box<dyn Fn(bool) + Send + Sync>,
    /// Answers arrive here.
    ///
    /// Behind a mutex because the callback signature is `Fn`, not `FnMut`,
    /// and a `Receiver` needs exclusive access to read. Contention is
    /// impossible in practice: only one assertion runs at a time, enforced by
    /// `Shared::begin_unlock`.
    answers: Mutex<Receiver<Option<String>>>,
    /// Retained so the channel stays open even when no request is pending;
    /// otherwise a late answer would find a closed channel.
    _sender: Sender<Option<String>>,
}

impl PinBroker {
    /// Builds a broker and the sender the worker uses to deliver answers.
    pub fn new(
        request: impl Fn(bool) + Send + Sync + 'static,
    ) -> (std::sync::Arc<Self>, Sender<Option<String>>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let broker = std::sync::Arc::new(Self {
            request: Box::new(request),
            answers: Mutex::new(rx),
            _sender: tx.clone(),
        });
        (broker, tx)
    }

    /// Asks the user for a PIN and blocks until they answer.
    ///
    /// `retry` is set when a previous PIN was rejected, so the popup can say
    /// so rather than looking like it ignored the first attempt.
    pub fn request_pin(&self, retry: bool) -> Result<String, ProviderError> {
        // Drain anything stale before asking. A PIN left over from a cancelled
        // attempt would otherwise be consumed as the answer to this one, and
        // the user would see a rejection they did not cause.
        {
            let answers = self.answers.lock().unwrap_or_else(|e| e.into_inner());
            while answers.try_recv().is_ok() {}
        }

        (self.request)(retry);

        let answers = self.answers.lock().unwrap_or_else(|e| e.into_inner());
        match answers.recv_timeout(PIN_TIMEOUT) {
            Ok(Some(pin)) => Ok(pin),
            Ok(None) => Err(ProviderError::Cancelled),
            Err(RecvTimeoutError::Timeout) => {
                tracing::warn!("timed out waiting for the authenticator PIN");
                Err(ProviderError::Timeout)
            }
            Err(RecvTimeoutError::Disconnected) => Err(ProviderError::Cancelled),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn delivers_the_pin_the_user_typed() {
        let (broker, tx) = PinBroker::new(|_| {});
        let b = Arc::clone(&broker);

        let handle = std::thread::spawn(move || b.request_pin(false));
        // Give the request a moment to start waiting.
        std::thread::sleep(Duration::from_millis(30));
        tx.send(Some("123456".into())).unwrap();

        assert_eq!(handle.join().unwrap().unwrap(), "123456");
    }

    #[test]
    fn a_cancelled_prompt_reports_cancellation() {
        let (broker, tx) = PinBroker::new(|_| {});
        let b = Arc::clone(&broker);

        let handle = std::thread::spawn(move || b.request_pin(false));
        std::thread::sleep(Duration::from_millis(30));
        tx.send(None).unwrap();

        assert!(matches!(
            handle.join().unwrap(),
            Err(ProviderError::Cancelled)
        ));
    }

    #[test]
    fn the_retry_flag_reaches_the_ui() {
        let seen = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&seen);
        let (broker, tx) = PinBroker::new(move |retry| {
            if retry {
                observed.fetch_add(1, Ordering::SeqCst);
            }
        });

        let b = Arc::clone(&broker);
        let handle = std::thread::spawn(move || b.request_pin(true));
        std::thread::sleep(Duration::from_millis(30));
        tx.send(Some("x".into())).unwrap();
        handle.join().unwrap().unwrap();

        assert_eq!(seen.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_stale_answer_is_not_used_for_the_next_request() {
        // Without draining, a PIN sent after a timeout would be silently
        // consumed by the *next* prompt, producing a rejection the user
        // cannot explain.
        let (broker, tx) = PinBroker::new(|_| {});
        tx.send(Some("stale".into())).unwrap();

        let b = Arc::clone(&broker);
        let handle = std::thread::spawn(move || b.request_pin(false));
        std::thread::sleep(Duration::from_millis(30));
        tx.send(Some("fresh".into())).unwrap();

        assert_eq!(handle.join().unwrap().unwrap(), "fresh");
    }
}
