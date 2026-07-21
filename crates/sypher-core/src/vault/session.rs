//! The lock state machine and the only path to plaintext.
//!
//! Everything else in the crate is a component; this is where they compose
//! into the security property the product promises. Two rules are enforced
//! here and nowhere else:
//!
//! 1. **Reading a secret requires both keys.** No API on [`Session`] returns
//!    plaintext without an inner key present: every such path goes through
//!    `ensure_unlocked`, which fails closed when `self.inner_kek` is `None`.
//! 2. **The inner key dies on a timer.** [`Session::tick`] zeroizes it once
//!    the deadline passes. The deadline moves forward on use, not on wall
//!    clock, so an idle vault relocks even if the daemon is busy.
//!
//! The outer key is deliberately *not* part of the lock state. It is recovered
//! once at cold start and held for the process lifetime, because requiring a
//! TPM unseal per operation would add latency to every popup for no security
//! gain: an attacker who can read our memory has already lost us the game, and
//! one who cannot is stopped by the inner layer regardless.
//!
//! ```text
//!   Locked { outer_kek }
//!      │  unlock(assertion)      ┌──────────────────────────┐
//!      └───────────────────────► │ Unlocked { inner, until }│
//!                                └──────────────────────────┘
//!         tick() past deadline           │  touch() extends
//!      ◄───────────────── zeroize ───────┘
//! ```

use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::crypto::envelope::{self, EnvelopeError};
use crate::crypto::keys::{
    derive_inner_kek, InnerKeyProvider, Key, OuterKeyProvider, ProviderError,
};
use crate::model::{SecretMeta, SecretPayload};
use crate::vault::db::{
    Vault, VaultError, META_CREDENTIAL_ID, META_HMAC_SALT, META_KDF_SALT, META_VERIFY_BLOB,
    META_VERIFY_ID,
};

/// Whether the vault currently holds an inner key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// No inner key. Metadata is readable; no secret can be decrypted.
    Locked,
    /// Inner key resident. Relocks after the remaining duration of inactivity.
    Unlocked { remaining: Duration },
}

impl LockState {
    pub fn is_unlocked(&self) -> bool {
        matches!(self, LockState::Unlocked { .. })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("the vault is locked; a YubiKey touch is required")]
    Locked,
    #[error("the vault is already initialized at this location")]
    AlreadyInitialized,
    #[error(
        "unlock succeeded but the keys do not match this vault: \
         wrong YubiKey, or the vault was moved from another machine"
    )]
    VerificationFailed,
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error(transparent)]
    Envelope(#[from] EnvelopeError),
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error(transparent)]
    Key(#[from] crate::crypto::keys::KeyError),
}

/// An open vault with its outer key resident and its inner key gated.
pub struct Session {
    vault: Vault,
    outer_kek: Key,
    /// `Some` exactly when unlocked. Zeroized on relock by virtue of `Key`
    /// wrapping a self-wiping buffer.
    inner_kek: Option<Key>,
    /// When the inner key expires. Meaningless while `inner_kek` is `None`.
    deadline: Option<Instant>,
    timeout: Duration,
}

impl Session {
    /// Creates a vault: generates the outer KEK, registers an authenticator
    /// credential, and stores the verification blob.
    ///
    /// Both provisioning steps run before anything is written, so a failure
    /// partway through (an unplugged key, a busy TPM) leaves no half-created
    /// vault behind.
    pub fn initialize(
        vault: Vault,
        outer: &dyn OuterKeyProvider,
        inner: &dyn InnerKeyProvider,
        timeout: Duration,
    ) -> Result<Self, SessionError> {
        if vault.get_meta(META_KDF_SALT)?.is_some() {
            return Err(SessionError::AlreadyInitialized);
        }

        let outer_kek = outer.provision()?;
        let credential_id = inner.provision()?;

        let kdf_salt = crate::crypto::keys::generate_salt()?;
        let hmac_salt = crate::crypto::keys::generate_salt()?;

        // Derive the inner key immediately so init fails loudly here rather
        // than at first unlock if the authenticator misbehaves.
        let assertion = inner.assert_secret(&credential_id, &hmac_salt)?;
        let inner_kek = derive_inner_kek(assertion.as_slice(), &kdf_salt)?;

        let verify_id = Uuid::new_v4();
        let verify_blob = envelope::seal_verification(&verify_id, &inner_kek, &outer_kek)?;

        vault.set_meta_bytes(META_KDF_SALT, &kdf_salt)?;
        vault.set_meta_bytes(META_HMAC_SALT, &hmac_salt)?;
        vault.set_meta_bytes(META_CREDENTIAL_ID, &credential_id)?;
        vault.set_meta_bytes(META_VERIFY_BLOB, &verify_blob)?;
        vault.set_meta(META_VERIFY_ID, &verify_id.to_string())?;

        tracing::info!("vault initialized");
        Ok(Self {
            vault,
            outer_kek,
            inner_kek: Some(inner_kek),
            deadline: Some(Instant::now() + timeout),
            timeout,
        })
    }

    /// Opens an existing vault, recovering the outer key only.
    ///
    /// This is the cold-start path and must not require user interaction: the
    /// daemon calls it at login, long before any hotkey press.
    pub fn open_locked(
        vault: Vault,
        outer: &dyn OuterKeyProvider,
        timeout: Duration,
    ) -> Result<Self, SessionError> {
        if vault.get_meta(META_KDF_SALT)?.is_none() {
            return Err(VaultError::NotInitialized("kdf_salt".into()).into());
        }
        let outer_kek = outer.unseal()?;
        tracing::info!("vault opened, outer key recovered; locked");
        Ok(Self {
            vault,
            outer_kek,
            inner_kek: None,
            deadline: None,
            timeout,
        })
    }

    /// Performs an assertion and admits the inner key, then verifies it.
    ///
    /// The verification step is what turns "the wrong YubiKey was touched"
    /// into an immediate, clear error instead of a confusing decryption
    /// failure the next time the user tries to paste something.
    pub fn unlock(&mut self, inner: &dyn InnerKeyProvider) -> Result<(), SessionError> {
        let credential_id = self.vault.require_meta_bytes(META_CREDENTIAL_ID)?;
        let hmac_salt = self.vault.require_meta_bytes(META_HMAC_SALT)?;
        let kdf_salt = self.vault.require_meta_bytes(META_KDF_SALT)?;

        let assertion = inner.assert_secret(&credential_id, &hmac_salt)?;
        let inner_kek = derive_inner_kek(assertion.as_slice(), &kdf_salt)?;

        let verify_blob = self.vault.require_meta_bytes(META_VERIFY_BLOB)?;
        let verify_id = self
            .vault
            .get_meta(META_VERIFY_ID)?
            .and_then(|s| Uuid::parse_str(&s).ok())
            .ok_or_else(|| VaultError::BadMeta(META_VERIFY_ID.into()))?;

        let ok = envelope::verify_keys(&verify_id, &inner_kek, &self.outer_kek, &verify_blob)
            .unwrap_or(false);
        if !ok {
            // Do not retain a key that cannot read this vault.
            tracing::warn!("unlock rejected: verification blob did not decrypt");
            return Err(SessionError::VerificationFailed);
        }

        self.inner_kek = Some(inner_kek);
        self.deadline = Some(Instant::now() + self.timeout);
        tracing::info!(timeout_secs = self.timeout.as_secs(), "vault unlocked");
        Ok(())
    }

    /// Zeroizes the inner key and returns to Locked.
    ///
    /// Dropping the `Key` wipes its buffer, so there is nothing further to do.
    pub fn lock(&mut self) {
        if self.inner_kek.take().is_some() {
            tracing::info!("vault locked, inner key zeroized");
        }
        self.deadline = None;
    }

    /// Relocks if the deadline has passed. Returns the resulting state.
    ///
    /// The daemon calls this on a timer and before every operation, so a
    /// missed timer tick cannot extend the unlocked window.
    pub fn tick(&mut self) -> LockState {
        match (self.inner_kek.as_ref(), self.deadline) {
            (Some(_), Some(deadline)) => {
                let now = Instant::now();
                if now >= deadline {
                    self.lock();
                    LockState::Locked
                } else {
                    LockState::Unlocked {
                        remaining: deadline - now,
                    }
                }
            }
            _ => {
                // Defensive: an inner key with no deadline would never expire.
                if self.inner_kek.is_some() {
                    self.lock();
                }
                LockState::Locked
            }
        }
    }

    /// Extends the unlock window. Called when the user interacts with the
    /// popup or uses a secret.
    pub fn touch(&mut self) {
        if self.inner_kek.is_some() {
            self.deadline = Some(Instant::now() + self.timeout);
        }
    }

    /// Current lock state without advancing the machine.
    pub fn state(&self) -> LockState {
        match (self.inner_kek.as_ref(), self.deadline) {
            (Some(_), Some(deadline)) => Instant::now()
                .checked_duration_since(deadline)
                .map(|_| LockState::Locked)
                .unwrap_or(LockState::Unlocked {
                    remaining: deadline - Instant::now(),
                }),
            _ => LockState::Locked,
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.state().is_unlocked()
    }

    /// Read-only access to metadata, available while locked.
    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    /// The machine-bound outer key.
    ///
    /// Exposed only for backups, which encrypt the whole database under a key
    /// derived from it. Deliberately not the inner key: nothing outside this
    /// module has any business holding that.
    pub fn outer_key(&self) -> &Key {
        &self.outer_kek
    }

    /// Lists metadata for the popup. Deliberately available while locked.
    pub fn list(&self) -> Result<Vec<SecretMeta>, SessionError> {
        Ok(self.vault.list_meta()?)
    }

    /// Advances the state machine and fails if that left the vault locked.
    ///
    /// Ticking first means a caller cannot use a key whose deadline expired
    /// while they were waiting on something else. Kept separate from
    /// [`Session::keys`] so the mutable tick borrow ends before the two key
    /// references are taken.
    fn ensure_unlocked(&mut self) -> Result<(), SessionError> {
        if self.tick().is_unlocked() {
            Ok(())
        } else {
            Err(SessionError::Locked)
        }
    }

    /// Borrows both KEKs as `(inner, outer)`. Only valid after
    /// [`Session::ensure_unlocked`].
    fn keys(&self) -> Result<(&Key, &Key), SessionError> {
        let inner = self.inner_kek.as_ref().ok_or(SessionError::Locked)?;
        Ok((inner, &self.outer_kek))
    }

    /// Decrypts one secret. The only route from ciphertext to plaintext.
    pub fn open(&mut self, id: &Uuid) -> Result<SecretPayload, SessionError> {
        let blob = self.vault.get_blob(id)?;
        self.ensure_unlocked()?;
        let (inner, outer) = self.keys()?;
        let payload = envelope::open_payload(id, inner, outer, &blob)?;
        self.touch();
        tracing::debug!(secret_id = %id, "secret decrypted");
        Ok(payload)
    }

    /// Seals and stores a new secret.
    pub fn add(
        &mut self,
        meta: &SecretMeta,
        payload: &SecretPayload,
    ) -> Result<(), SessionError> {
        self.ensure_unlocked()?;
        let (inner, outer) = self.keys()?;
        let blob = envelope::seal_payload(&meta.id, inner, outer, payload)?;
        self.vault.insert(meta, &blob)?;
        self.touch();
        tracing::info!(secret_id = %meta.id, name = %meta.name, "secret added");
        Ok(())
    }

    /// Re-seals and replaces an existing secret.
    pub fn update(
        &mut self,
        meta: &SecretMeta,
        payload: &SecretPayload,
    ) -> Result<(), SessionError> {
        self.ensure_unlocked()?;
        let (inner, outer) = self.keys()?;
        let blob = envelope::seal_payload(&meta.id, inner, outer, payload)?;
        self.vault.update(meta, &blob)?;
        self.touch();
        tracing::info!(secret_id = %meta.id, "secret updated");
        Ok(())
    }

    /// Deletes a secret. Allowed while locked: removing a row needs no key,
    /// and refusing would mean a user who cannot find their YubiKey also
    /// cannot clean up an entry they know is stale.
    pub fn delete(&mut self, id: &Uuid) -> Result<(), SessionError> {
        self.vault.delete(id)?;
        tracing::info!(secret_id = %id, "secret deleted");
        Ok(())
    }
}

#[cfg(all(test, feature = "mock-hw"))]
mod tests {
    use super::*;
    use crate::mock_hw::{MockInnerProvider, MockOuterProvider};
    use crate::model::SecretType;
    use crate::secure::SecureBuf;
    use crate::vault::paths::VaultPaths;

    struct Fixture {
        _tmp: tempfile::TempDir,
        paths: VaultPaths,
    }

    impl Fixture {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let paths = VaultPaths::at(tmp.path().join("vault"));
            paths.ensure_dirs().unwrap();
            Self { _tmp: tmp, paths }
        }

        fn outer(&self) -> MockOuterProvider {
            MockOuterProvider::new(&self.paths)
        }

        fn inner(&self) -> MockInnerProvider {
            MockInnerProvider::new(&self.paths)
        }

        fn init(&self, timeout: Duration) -> Session {
            let vault = Vault::open(&self.paths).unwrap();
            Session::initialize(vault, &self.outer(), &self.inner(), timeout).unwrap()
        }

        fn reopen(&self, timeout: Duration) -> Session {
            let vault = Vault::open(&self.paths).unwrap();
            Session::open_locked(vault, &self.outer(), timeout).unwrap()
        }
    }

    fn sample() -> (SecretMeta, SecretPayload) {
        let mut meta = SecretMeta::new("GitHub", SecretType::Password);
        meta.domain = "github.com".into();
        meta.username = "octocat".into();
        let payload = SecretPayload::new(SecureBuf::copy_from(b"correct-horse"));
        (meta, payload)
    }

    #[test]
    fn full_lifecycle_add_read_update_delete() {
        let fx = Fixture::new();
        let mut s = fx.init(Duration::from_secs(60));
        let (meta, payload) = sample();

        s.add(&meta, &payload).unwrap();
        assert_eq!(s.open(&meta.id).unwrap(), payload);

        let updated = SecretPayload::new(SecureBuf::copy_from(b"new-password"));
        s.update(&meta, &updated).unwrap();
        assert_eq!(s.open(&meta.id).unwrap(), updated);

        s.delete(&meta.id).unwrap();
        assert!(s.open(&meta.id).is_err());
    }

    #[test]
    fn a_reopened_vault_starts_locked_but_lists_metadata() {
        let fx = Fixture::new();
        let (meta, payload) = sample();
        {
            let mut s = fx.init(Duration::from_secs(60));
            s.add(&meta, &payload).unwrap();
        }

        let mut s = fx.reopen(Duration::from_secs(60));
        assert!(!s.is_unlocked());

        // Metadata is readable with no touch: this is what makes the popup
        // appear instantly.
        let listed = s.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "GitHub");

        // The secret itself is not.
        assert!(matches!(s.open(&meta.id), Err(SessionError::Locked)));

        s.unlock(&fx.inner()).unwrap();
        assert_eq!(s.open(&meta.id).unwrap(), payload);
    }

    #[test]
    fn secrets_survive_a_full_restart_roundtrip() {
        let fx = Fixture::new();
        let (meta, payload) = sample();
        {
            let mut s = fx.init(Duration::from_secs(60));
            s.add(&meta, &payload).unwrap();
        }
        let mut s = fx.reopen(Duration::from_secs(60));
        s.unlock(&fx.inner()).unwrap();
        assert_eq!(s.open(&meta.id).unwrap(), payload);
    }

    #[test]
    fn the_vault_relocks_after_the_timeout() {
        let fx = Fixture::new();
        let mut s = fx.init(Duration::from_millis(60));
        let (meta, payload) = sample();
        s.add(&meta, &payload).unwrap();
        assert!(s.is_unlocked());

        std::thread::sleep(Duration::from_millis(120));

        assert_eq!(s.tick(), LockState::Locked);
        assert!(matches!(s.open(&meta.id), Err(SessionError::Locked)));
    }

    #[test]
    fn using_a_secret_extends_the_window() {
        let fx = Fixture::new();
        let mut s = fx.init(Duration::from_millis(150));
        let (meta, payload) = sample();
        s.add(&meta, &payload).unwrap();

        // Three reads spaced under the timeout must not relock, because each
        // one pushes the deadline forward.
        for _ in 0..3 {
            std::thread::sleep(Duration::from_millis(60));
            assert!(s.open(&meta.id).is_ok(), "use should extend the deadline");
        }
        assert!(s.is_unlocked());
    }

    #[test]
    fn explicit_lock_zeroizes_immediately() {
        let fx = Fixture::new();
        let mut s = fx.init(Duration::from_secs(3600));
        let (meta, payload) = sample();
        s.add(&meta, &payload).unwrap();

        s.lock();
        assert!(!s.is_unlocked());
        assert!(matches!(s.open(&meta.id), Err(SessionError::Locked)));
    }

    #[test]
    fn a_locked_vault_cannot_add_or_update() {
        let fx = Fixture::new();
        let (meta, payload) = sample();
        {
            let mut s = fx.init(Duration::from_secs(60));
            s.add(&meta, &payload).unwrap();
        }
        let mut s = fx.reopen(Duration::from_secs(60));

        let (other, other_payload) = sample();
        assert!(matches!(
            s.add(&other, &other_payload),
            Err(SessionError::Locked)
        ));
        assert!(matches!(
            s.update(&meta, &other_payload),
            Err(SessionError::Locked)
        ));
    }

    #[test]
    fn delete_works_while_locked() {
        // Removing a row needs no key, and a user without their YubiKey should
        // still be able to clean up.
        let fx = Fixture::new();
        let (meta, payload) = sample();
        {
            let mut s = fx.init(Duration::from_secs(60));
            s.add(&meta, &payload).unwrap();
        }
        let mut s = fx.reopen(Duration::from_secs(60));
        assert!(!s.is_unlocked());
        s.delete(&meta.id).unwrap();
        assert!(s.list().unwrap().is_empty());
    }

    #[test]
    fn initializing_twice_is_refused() {
        let fx = Fixture::new();
        let _s = fx.init(Duration::from_secs(60));

        let vault = Vault::open(&fx.paths).unwrap();
        assert!(matches!(
            Session::initialize(vault, &fx.outer(), &fx.inner(), Duration::from_secs(60)),
            Err(SessionError::AlreadyInitialized)
        ));
    }

    #[test]
    fn opening_an_uninitialized_vault_is_a_clean_error() {
        let fx = Fixture::new();
        let vault = Vault::open(&fx.paths).unwrap();
        assert!(matches!(
            Session::open_locked(vault, &fx.outer(), Duration::from_secs(60)),
            Err(SessionError::Vault(VaultError::NotInitialized(_)))
        ));
    }

    #[test]
    fn a_different_authenticator_is_rejected_by_verification() {
        // Simulates touching the wrong YubiKey: the assertion succeeds but
        // derives a key that cannot read this vault. The user must get a clear
        // error, not a mysterious failure at paste time.
        let fx = Fixture::new();
        let (meta, payload) = sample();
        {
            let mut s = fx.init(Duration::from_secs(60));
            s.add(&meta, &payload).unwrap();
        }

        // Re-provision the mock authenticator with a fresh seed.
        std::fs::remove_file(fx.paths.mock_hw().join("inner_seed")).unwrap();
        let wrong = MockInnerProvider::new(&fx.paths);
        wrong.provision().unwrap();

        let mut s = fx.reopen(Duration::from_secs(60));
        assert!(matches!(
            s.unlock(&wrong),
            Err(SessionError::VerificationFailed)
        ));
        assert!(!s.is_unlocked(), "a rejected key must not be retained");
    }

    #[test]
    fn a_vault_copied_to_another_machine_does_not_open() {
        // The outer layer's whole purpose: the sealed KEK does not travel.
        let source = Fixture::new();
        let (meta, payload) = sample();
        {
            let mut s = source.init(Duration::from_secs(60));
            s.add(&meta, &payload).unwrap();
        }

        // Copy the database but not the (machine-bound) sealed outer key.
        let dest = Fixture::new();
        std::fs::copy(source.paths.db(), dest.paths.db()).unwrap();

        let vault = Vault::open(&dest.paths).unwrap();
        assert!(
            matches!(
                Session::open_locked(vault, &dest.outer(), Duration::from_secs(60)),
                Err(SessionError::Provider(ProviderError::NotProvisioned))
            ),
            "a stolen vault.db must not be openable"
        );
    }

    #[test]
    fn ciphertext_in_the_database_does_not_contain_the_secret() {
        let fx = Fixture::new();
        let mut s = fx.init(Duration::from_secs(60));
        let mut meta = SecretMeta::new("Bank", SecretType::Password);
        meta.domain = "bank.example".into();
        s.add(
            &meta,
            &SecretPayload::new(SecureBuf::copy_from(b"needle-in-haystack")),
        )
        .unwrap();
        drop(s);

        let raw = std::fs::read(fx.paths.db()).unwrap();
        assert!(
            !raw.windows(18).any(|w| w == b"needle-in-haystack"),
            "plaintext found in vault.db"
        );
    }

    #[test]
    fn state_reports_a_shrinking_remaining_window() {
        let fx = Fixture::new();
        let s = fx.init(Duration::from_secs(60));
        let LockState::Unlocked { remaining: first } = s.state() else {
            panic!("expected unlocked");
        };
        std::thread::sleep(Duration::from_millis(30));
        let LockState::Unlocked { remaining: second } = s.state() else {
            panic!("expected unlocked");
        };
        assert!(second < first);
    }
}
