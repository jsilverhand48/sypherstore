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

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::envelope::{self, EnvelopeError};
use crate::crypto::keys::{
    derive_wrap_key, InnerKeyProvider, Key, OuterKeyProvider, ProviderError,
};
use crate::model::{SecretMeta, SecretPayload};
use crate::vault::db::{
    Vault, VaultError, META_ENROLLMENTS, META_HMAC_SALT, META_KDF_SALT, META_VERIFY_BLOB,
    META_VERIFY_ID,
};

/// One enrolled authenticator's record: how to recognise it and its wrapped
/// copy of the vault's `inner_kek`.
///
/// Stored as a CBOR list in the `meta` table. `credential_id` is the opaque
/// non-resident handle the authenticator returned at enrollment; `wrap_blob` is
/// `inner_kek` sealed under the wrap key derived from this key's hmac-secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Enrollment {
    /// Human label, e.g. "primary" or "backup", shown when listing keys.
    #[serde(rename = "l")]
    label: String,
    #[serde(rename = "c")]
    credential_id: Vec<u8>,
    #[serde(rename = "w")]
    wrap_blob: Vec<u8>,
}

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
    #[error(
        "the authenticator that answered is not enrolled in this vault. \
         Use a registered key, or enroll this one from an unlocked session."
    )]
    NoMatchingKey,
    #[error("the vault's enrollment record is corrupt: {0}")]
    BadEnrollments(String),
    #[error("that authenticator is already enrolled in this vault")]
    AlreadyEnrolled,
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

        // The key that actually encrypts secrets is random and generated here,
        // not derived from the authenticator. Each enrolled key stores a
        // wrapped copy of it, which is what lets a backup key open the vault.
        let inner_kek = Key::generate()?;

        let kdf_salt = crate::crypto::keys::generate_salt()?;
        let hmac_salt = crate::crypto::keys::generate_salt()?;

        // Register the primary authenticator and wrap inner_kek under it. Doing
        // the assertion now means init fails loudly here rather than at first
        // unlock if the authenticator misbehaves.
        let credential_id = inner.provision()?;
        let primary = wrap_for(inner, &credential_id, &hmac_salt, &kdf_salt, &inner_kek, "primary")?;
        let enrollments = vec![primary];

        let verify_id = Uuid::new_v4();
        let verify_blob = envelope::seal_verification(&verify_id, &inner_kek, &outer_kek)?;

        vault.set_meta_bytes(META_KDF_SALT, &kdf_salt)?;
        vault.set_meta_bytes(META_HMAC_SALT, &hmac_salt)?;
        save_enrollments(&vault, &enrollments)?;
        vault.set_meta_bytes(META_VERIFY_BLOB, &verify_blob)?;
        vault.set_meta(META_VERIFY_ID, &verify_id.to_string())?;

        tracing::info!("vault initialized with 1 enrolled authenticator");
        Ok(Self {
            vault,
            outer_kek,
            inner_kek: Some(inner_kek),
            deadline: Some(Instant::now() + timeout),
            timeout,
        })
    }

    /// Enrolls an additional authenticator so it can also open this vault.
    ///
    /// Requires the session to be unlocked: enrolling a backup means wrapping
    /// the *existing* `inner_kek` under the new key, and that key is only in
    /// hand once an already-enrolled key has unlocked. This is the "primary
    /// present" model, the new authenticator is added alongside the old, and
    /// every existing secret stays readable by both.
    ///
    /// Prompts the new key twice: once to register a credential, once to derive
    /// its wrap key.
    pub fn enroll_key(
        &mut self,
        inner: &dyn InnerKeyProvider,
        label: &str,
    ) -> Result<(), SessionError> {
        self.ensure_unlocked()?;
        let inner_kek = self.inner_kek.clone().ok_or(SessionError::Locked)?;

        let hmac_salt = self.vault.require_meta_bytes(META_HMAC_SALT)?;
        let kdf_salt = self.vault.require_meta_bytes(META_KDF_SALT)?;
        let mut enrollments = load_enrollments(&self.vault)?;

        let credential_id = inner.provision()?;
        if enrollments.iter().any(|e| e.credential_id == credential_id) {
            return Err(SessionError::AlreadyEnrolled);
        }

        let label = if label.trim().is_empty() {
            format!("key-{}", enrollments.len() + 1)
        } else {
            label.trim().to_string()
        };
        let enrollment = wrap_for(inner, &credential_id, &hmac_salt, &kdf_salt, &inner_kek, &label)?;
        enrollments.push(enrollment);
        save_enrollments(&self.vault, &enrollments)?;

        self.touch();
        tracing::info!(count = enrollments.len(), label = %label, "enrolled an authenticator");
        Ok(())
    }

    /// Labels of every enrolled authenticator. Needs no key.
    pub fn enrolled_labels(&self) -> Result<Vec<String>, SessionError> {
        Ok(load_enrollments(&self.vault)?
            .into_iter()
            .map(|e| e.label)
            .collect())
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
        let hmac_salt = self.vault.require_meta_bytes(META_HMAC_SALT)?;
        let kdf_salt = self.vault.require_meta_bytes(META_KDF_SALT)?;
        let enrollments = load_enrollments(&self.vault)?;

        // One assertion carrying every enrolled credential in its allow-list.
        // The authenticator answers for whichever it holds and tells us which,
        // so a two-key vault opens with a single touch.
        let credential_ids: Vec<Vec<u8>> =
            enrollments.iter().map(|e| e.credential_id.clone()).collect();
        let (matched_id, assertion) = inner.assert_first_available(&credential_ids, &hmac_salt)?;

        let enrollment = enrollments
            .iter()
            .find(|e| e.credential_id == matched_id)
            .ok_or(SessionError::NoMatchingKey)?;

        // Derive this key's wrap key and unwrap its copy of inner_kek. A wrong
        // key fails the AEAD tag here.
        let wrap = derive_wrap_key(assertion.as_slice(), &kdf_salt)?;
        let inner_kek = match envelope::unwrap_key(&wrap, &enrollment.wrap_blob) {
            Ok(k) => k,
            Err(_) => {
                tracing::warn!(label = %enrollment.label, "unlock rejected: could not unwrap inner key");
                return Err(SessionError::VerificationFailed);
            }
        };

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
        tracing::info!(
            timeout_secs = self.timeout.as_secs(),
            key = %enrollment.label,
            "vault unlocked"
        );
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

    /// Lists metadata for the popup, newest-updated first.
    ///
    /// Requires an unlock: every row's metadata is sealed, so the list cannot
    /// be built without the inner key. This is the change that makes the popup
    /// show nothing until the YubiKey is present.
    pub fn list(&mut self) -> Result<Vec<SecretMeta>, SessionError> {
        self.ensure_unlocked()?;
        let (inner, outer) = self.keys()?;
        let rows = self.vault.list_rows()?;

        let mut metas = Vec::with_capacity(rows.len());
        for row in rows {
            let meta = envelope::open_meta(&row.meta_id, &row.id, inner, outer, &row.meta_blob)?;
            metas.push(meta);
        }
        // The sort key lives inside the sealed blob, so ordering happens here
        // rather than in SQL.
        metas.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        Ok(metas)
    }

    /// Decrypts one secret's metadata. Requires an unlock.
    pub fn meta_for(&mut self, id: &Uuid) -> Result<SecretMeta, SessionError> {
        let row = self.vault.get_meta_row(id)?;
        self.ensure_unlocked()?;
        let (inner, outer) = self.keys()?;
        Ok(envelope::open_meta(&row.meta_id, &row.id, inner, outer, &row.meta_blob)?)
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

    /// Seals and stores a new secret: metadata and payload in separate
    /// envelopes, plus a fresh random UUID for the metadata envelope.
    pub fn add(
        &mut self,
        meta: &SecretMeta,
        payload: &SecretPayload,
    ) -> Result<(), SessionError> {
        self.ensure_unlocked()?;
        let (inner, outer) = self.keys()?;
        let meta_id = Uuid::new_v4();
        let meta_blob = envelope::seal_meta(&meta_id, inner, outer, meta)?;
        let payload_blob = envelope::seal_payload(&meta.id, inner, outer, payload)?;
        self.vault.insert_row(&meta.id, &meta_id, &meta_blob, &payload_blob)?;
        self.touch();
        tracing::info!(secret_id = %meta.id, "secret added");
        Ok(())
    }

    /// Re-seals and replaces an existing secret.
    ///
    /// The metadata envelope's UUID is rotated on every update, so an observer
    /// diffing the database cannot even tell that a row's metadata was replaced
    /// with the same content.
    pub fn update(
        &mut self,
        meta: &SecretMeta,
        payload: &SecretPayload,
    ) -> Result<(), SessionError> {
        self.ensure_unlocked()?;
        let (inner, outer) = self.keys()?;
        let meta_id = Uuid::new_v4();
        let meta_blob = envelope::seal_meta(&meta_id, inner, outer, meta)?;
        let payload_blob = envelope::seal_payload(&meta.id, inner, outer, payload)?;
        self.vault.update_row(&meta.id, &meta_id, &meta_blob, &payload_blob)?;
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

/// Registers one authenticator's wrapped copy of `inner_kek`.
///
/// Performs the assertion (one touch) and seals `inner_kek` under the wrap key
/// derived from it. Shared by init (the primary) and `enroll_key` (a backup).
fn wrap_for(
    inner: &dyn InnerKeyProvider,
    credential_id: &[u8],
    hmac_salt: &[u8],
    kdf_salt: &[u8],
    inner_kek: &Key,
    label: &str,
) -> Result<Enrollment, SessionError> {
    let assertion = inner.assert_secret(credential_id, hmac_salt)?;
    let wrap = derive_wrap_key(assertion.as_slice(), kdf_salt)?;
    let wrap_blob = envelope::wrap_key(&wrap, inner_kek)?;
    Ok(Enrollment {
        label: label.to_string(),
        credential_id: credential_id.to_vec(),
        wrap_blob,
    })
}

/// Reads the enrolled-authenticator list from the vault's meta table.
fn load_enrollments(vault: &Vault) -> Result<Vec<Enrollment>, SessionError> {
    let bytes = vault.require_meta_bytes(META_ENROLLMENTS)?;
    ciborium::from_reader(bytes.as_slice())
        .map_err(|e| SessionError::BadEnrollments(e.to_string()))
}

/// Writes the enrolled-authenticator list back to the vault's meta table.
fn save_enrollments(vault: &Vault, enrollments: &[Enrollment]) -> Result<(), SessionError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(enrollments, &mut bytes)
        .map_err(|e| SessionError::BadEnrollments(e.to_string()))?;
    vault.set_meta_bytes(META_ENROLLMENTS, &bytes)?;
    Ok(())
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
    fn a_reopened_vault_starts_locked_and_reveals_nothing_until_unlocked() {
        let fx = Fixture::new();
        let (meta, payload) = sample();
        {
            let mut s = fx.init(Duration::from_secs(60));
            s.add(&meta, &payload).unwrap();
        }

        let mut s = fx.reopen(Duration::from_secs(60));
        assert!(!s.is_unlocked());

        // Metadata is now sealed: neither the list nor a single secret is
        // readable without a touch. The row count leaks, nothing else.
        assert!(matches!(s.list(), Err(SessionError::Locked)));
        assert!(matches!(s.open(&meta.id), Err(SessionError::Locked)));
        assert_eq!(s.vault().count().unwrap(), 1);

        s.unlock(&fx.inner()).unwrap();
        let listed = s.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "GitHub");
        assert_eq!(listed[0].domain, "github.com");
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
        // Deletion needs no key; confirm via the count, which also needs none.
        assert_eq!(s.vault().count().unwrap(), 0);
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
    fn ciphertext_in_the_database_does_not_contain_the_secret_or_metadata() {
        let fx = Fixture::new();
        let mut s = fx.init(Duration::from_secs(60));
        let mut meta = SecretMeta::new("MyBankName", SecretType::Password);
        meta.domain = "bank-needle.example".into();
        meta.username = "account-holder-needle".into();
        meta.tags = vec!["tag-needle".into()];
        s.add(
            &meta,
            &SecretPayload::new(SecureBuf::copy_from(b"needle-in-haystack")),
        )
        .unwrap();
        drop(s);

        let raw = std::fs::read(fx.paths.db()).unwrap();
        // Neither the secret nor any metadata field may appear in the clear now
        // that metadata is sealed too.
        for needle in [
            b"needle-in-haystack".as_slice(),
            b"MyBankName".as_slice(),
            b"bank-needle.example".as_slice(),
            b"account-holder-needle".as_slice(),
            b"tag-needle".as_slice(),
        ] {
            assert!(
                !raw.windows(needle.len()).any(|w| w == needle),
                "cleartext {:?} found in vault.db",
                String::from_utf8_lossy(needle)
            );
        }
    }

    /// A test authenticator that answers for exactly one credential id, the way
    /// a real physical key holds one non-resident credential. Two of these
    /// stand in for two separate YubiKeys.
    struct OneKey {
        credential_id: Vec<u8>,
        seed: [u8; 8],
    }

    impl OneKey {
        fn new(tag: u8) -> Self {
            Self {
                credential_id: vec![tag; 16],
                seed: [tag; 8],
            }
        }
    }

    impl crate::crypto::keys::InnerKeyProvider for OneKey {
        fn provision(&self) -> Result<Vec<u8>, ProviderError> {
            Ok(self.credential_id.clone())
        }

        fn assert_secret(&self, credential_id: &[u8], salt: &[u8]) -> Result<SecureBuf, ProviderError> {
            if credential_id != self.credential_id {
                // This physical key does not hold that credential.
                return Err(ProviderError::NoDevice("credential not on this key".into()));
            }
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(self.seed);
            h.update(credential_id);
            h.update(salt);
            let mut out = h.finalize();
            Ok(SecureBuf::take_from(out.as_mut_slice()))
        }
    }

    #[test]
    fn a_backup_key_can_be_enrolled_and_opens_the_vault_alone() {
        let fx = Fixture::new();
        let primary = OneKey::new(1);
        let backup = OneKey::new(2);
        let (meta, payload) = sample();

        // Create with the primary and store a secret.
        {
            let vault = Vault::open(&fx.paths).unwrap();
            let mut s =
                Session::initialize(vault, &fx.outer(), &primary, Duration::from_secs(60)).unwrap();
            s.add(&meta, &payload).unwrap();
            // Enrolling the backup requires an unlocked session (primary present).
            s.enroll_key(&backup, "backup").unwrap();
            assert_eq!(s.enrolled_labels().unwrap(), vec!["primary", "backup"]);
        }

        // Reopen and unlock with ONLY the backup key. The primary's credential
        // is in the allow-list but the backup does not hold it, so the vault
        // must open via the backup's own wrapped copy of inner_kek.
        let mut s = fx.reopen(Duration::from_secs(60));
        s.unlock(&backup).unwrap();
        assert_eq!(s.open(&meta.id).unwrap(), payload);
        assert_eq!(s.list().unwrap()[0].name, "GitHub");
    }

    #[test]
    fn enrolling_a_second_time_with_the_same_key_is_refused() {
        let fx = Fixture::new();
        let primary = OneKey::new(1);
        let vault = Vault::open(&fx.paths).unwrap();
        let mut s =
            Session::initialize(vault, &fx.outer(), &primary, Duration::from_secs(60)).unwrap();
        assert!(matches!(
            s.enroll_key(&primary, "again"),
            Err(SessionError::AlreadyEnrolled)
        ));
    }

    #[test]
    fn an_unenrolled_key_cannot_unlock() {
        let fx = Fixture::new();
        let primary = OneKey::new(1);
        let stranger = OneKey::new(9);
        {
            let vault = Vault::open(&fx.paths).unwrap();
            let _ =
                Session::initialize(vault, &fx.outer(), &primary, Duration::from_secs(60)).unwrap();
        }
        let mut s = fx.reopen(Duration::from_secs(60));
        // The stranger holds no enrolled credential, so the allow-list assertion
        // finds nothing to answer with.
        assert!(s.unlock(&stranger).is_err());
        assert!(!s.is_unlocked());
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
