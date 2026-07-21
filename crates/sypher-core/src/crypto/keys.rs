//! Key hierarchy and the traits that abstract the two hardware layers.
//!
//! There are exactly two root keys in the system:
//!
//! - `outer_kek`, 32 random bytes sealed by the TPM. Recovered once at cold
//!   start and resident for the process lifetime. It binds the vault to *this
//!   machine*: copying `vault.db` to another host yields an undecryptable file.
//! - `inner_kek`, derived from a FIDO2 `hmac-secret` assertion. Resident only
//!   while the vault is unlocked. It binds the vault to *this YubiKey*, and
//!   because the assertion requires a touch, to a deliberate human action.
//!
//! Neither root key ever encrypts a secret directly. Each secret gets its own
//! pair of subkeys derived from its UUID via HKDF-Expand. This costs one hash
//! per operation and buys two things: no per-row DEK has to be stored, and a
//! nonce reuse in one row cannot compromise another, because the rows use
//! independent keys.
//!
//! ```text
//!   TPM ──seal──> outer_kek ──HKDF-Expand(uuid)──> k_outer_i ──> outer layer
//!   FIDO2 hmac-secret ──HKDF-Extract(salt)──> inner_kek ──HKDF-Expand(uuid)──> k_inner_i
//! ```

use hkdf::Hkdf;
use sha2::Sha256;
use uuid::Uuid;

use crate::secure::SecureBuf;

/// Length of every symmetric key in the system.
pub const KEY_LEN: usize = 32;

/// Length of the per-vault KDF salt.
pub const SALT_LEN: usize = 32;

/// HKDF info string for turning a FIDO2 hmac-secret output into `inner_kek`.
const INFO_INNER_KEK: &[u8] = b"sypherstore/v1/inner-kek";
/// HKDF info prefix for a secret's inner subkey. The UUID is appended.
const INFO_SECRET_INNER: &[u8] = b"sypherstore/v1/secret-inner/";
/// HKDF info prefix for a secret's outer subkey. The UUID is appended.
const INFO_SECRET_OUTER: &[u8] = b"sypherstore/v1/secret-outer/";

/// A 32-byte symmetric key held in locked, self-wiping memory.
///
/// This is a newtype over [`SecureBuf`] rather than an alias so that a key
/// cannot be passed where arbitrary plaintext is expected, or vice versa.
#[derive(Clone, PartialEq, Eq)]
pub struct Key(SecureBuf);

impl Key {
    /// Wraps exactly [`KEY_LEN`] bytes, wiping the caller's copy.
    pub fn take_from(bytes: &mut [u8]) -> Result<Self, KeyError> {
        if bytes.len() != KEY_LEN {
            return Err(KeyError::BadKeyLength(bytes.len()));
        }
        Ok(Key(SecureBuf::take_from(bytes)))
    }

    /// Wraps a copy of exactly [`KEY_LEN`] bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != KEY_LEN {
            return Err(KeyError::BadKeyLength(bytes.len()));
        }
        Ok(Key(SecureBuf::copy_from(bytes)))
    }

    /// Generates a fresh random key. Used once per vault, for `outer_kek`.
    pub fn generate() -> Result<Self, KeyError> {
        Ok(Key(SecureBuf::random(KEY_LEN)?))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key([redacted])")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("key must be {KEY_LEN} bytes, got {0}")]
    BadKeyLength(usize),
    #[error("HKDF expansion failed")]
    Hkdf,
    #[error("failed to gather randomness: {0}")]
    Random(#[from] getrandom::Error),
}

/// Derives `inner_kek` from a raw FIDO2 hmac-secret output.
///
/// The vault's KDF salt is used as the HKDF salt so that two vaults registered
/// against the same YubiKey credential still end up with independent inner
/// keys. Extract-then-expand is the right construction here because the
/// hmac-secret output, while high entropy, is not guaranteed to be uniformly
/// distributed the way a key we generated ourselves would be.
pub fn derive_inner_kek(hmac_secret: &[u8], vault_salt: &[u8]) -> Result<Key, KeyError> {
    let hk = Hkdf::<Sha256>::new(Some(vault_salt), hmac_secret);
    let mut out = SecureBuf::zeroed(KEY_LEN);
    hk.expand(INFO_INNER_KEK, &mut out).map_err(|_| KeyError::Hkdf)?;
    Ok(Key(out))
}

/// Derives a secret's inner subkey from `inner_kek` and the secret's UUID.
pub fn derive_secret_inner_key(inner_kek: &Key, id: &Uuid) -> Result<Key, KeyError> {
    derive_subkey(inner_kek, INFO_SECRET_INNER, id)
}

/// Derives a secret's outer subkey from `outer_kek` and the secret's UUID.
pub fn derive_secret_outer_key(outer_kek: &Key, id: &Uuid) -> Result<Key, KeyError> {
    derive_subkey(outer_kek, INFO_SECRET_OUTER, id)
}

/// Expand-only HKDF. The KEK is already a uniform 32-byte value, so the
/// extract step would add nothing.
fn derive_subkey(kek: &Key, info_prefix: &[u8], id: &Uuid) -> Result<Key, KeyError> {
    let mut info = Vec::with_capacity(info_prefix.len() + 16);
    info.extend_from_slice(info_prefix);
    info.extend_from_slice(id.as_bytes());

    let hk = Hkdf::<Sha256>::from_prk(kek.as_bytes()).map_err(|_| KeyError::Hkdf)?;
    let mut out = SecureBuf::zeroed(KEY_LEN);
    hk.expand(&info, &mut out).map_err(|_| KeyError::Hkdf)?;
    Ok(Key(out))
}

/// Generates a fresh per-vault KDF salt.
pub fn generate_salt() -> Result<[u8; SALT_LEN], KeyError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt)?;
    Ok(salt)
}

/// The machine-bound outer layer, normally backed by the TPM.
///
/// Implementations must be usable without user interaction: the outer key is
/// recovered once at daemon start, before any hotkey press, so blocking on a
/// touch or a PIN here would make cold start hang.
pub trait OuterKeyProvider: Send + Sync {
    /// Generates and seals a new `outer_kek`, returning it. Called once, at
    /// `sypherstore init`.
    fn provision(&self) -> Result<Key, ProviderError>;

    /// Seals a caller-supplied key instead of generating a fresh one.
    ///
    /// This is the disaster-recovery path: it re-binds an existing vault's
    /// outer key to a new TPM. It is deliberately a distinct method from
    /// [`OuterKeyProvider::provision`] so that "create a vault" and "adopt an
    /// existing key" can never be confused at a call site.
    fn provision_with(&self, key: &Key) -> Result<(), ProviderError>;

    /// Recovers the previously sealed `outer_kek`.
    fn unseal(&self) -> Result<Key, ProviderError>;

    /// Whether this vault has already been provisioned on this machine.
    fn is_provisioned(&self) -> bool;
}

/// The presence-bound inner layer, normally backed by a FIDO2 authenticator.
///
/// Implementations are expected to block on a physical touch. Callers must
/// therefore run these off the UI thread and show a prompt first.
pub trait InnerKeyProvider: Send + Sync {
    /// Registers a credential and returns the opaque handle to persist
    /// alongside the vault. Called once, at `sypherstore init`.
    fn provision(&self) -> Result<Vec<u8>, ProviderError>;

    /// Performs an assertion against `credential_id` with `salt`, returning
    /// the raw hmac-secret output. The same inputs must always yield the same
    /// output, since that is what makes the vault decryptable across sessions.
    fn assert_secret(&self, credential_id: &[u8], salt: &[u8]) -> Result<SecureBuf, ProviderError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("no device found: {0}")]
    NoDevice(String),
    #[error("the vault is not provisioned on this machine")]
    NotProvisioned,
    #[error("the operation timed out waiting for the user")]
    Timeout,
    #[error("the user cancelled the operation")]
    Cancelled,
    #[error("device error: {0}")]
    Device(String),
    #[error("stored key material is corrupt: {0}")]
    Corrupt(String),
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_salt() -> [u8; SALT_LEN] {
        [7u8; SALT_LEN]
    }

    #[test]
    fn inner_kek_derivation_is_deterministic() {
        let a = derive_inner_kek(b"hmac-secret-output", &fixed_salt()).unwrap();
        let b = derive_inner_kek(b"hmac-secret-output", &fixed_salt()).unwrap();
        assert_eq!(a, b, "two assertions with the same salt must agree");
    }

    #[test]
    fn inner_kek_depends_on_both_secret_and_salt() {
        let base = derive_inner_kek(b"secret-a", &fixed_salt()).unwrap();
        let other_secret = derive_inner_kek(b"secret-b", &fixed_salt()).unwrap();
        let other_salt = derive_inner_kek(b"secret-a", &[9u8; SALT_LEN]).unwrap();
        assert_ne!(base, other_secret);
        assert_ne!(base, other_salt, "vaults must not share an inner key");
    }

    #[test]
    fn subkeys_are_distinct_per_secret_and_per_layer() {
        let kek = Key::from_slice(&[3u8; KEY_LEN]).unwrap();
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();

        let inner_a = derive_secret_inner_key(&kek, &id_a).unwrap();
        let inner_b = derive_secret_inner_key(&kek, &id_b).unwrap();
        let outer_a = derive_secret_outer_key(&kek, &id_a).unwrap();

        assert_ne!(inner_a, inner_b, "different secrets must not share a subkey");
        assert_ne!(
            inner_a, outer_a,
            "the two layers must not collide on the same KEK and UUID"
        );
        assert_eq!(inner_a, derive_secret_inner_key(&kek, &id_a).unwrap());
    }

    #[test]
    fn key_rejects_wrong_lengths() {
        assert!(Key::from_slice(&[0u8; 16]).is_err());
        assert!(Key::from_slice(&[0u8; 33]).is_err());
        assert!(Key::from_slice(&[0u8; KEY_LEN]).is_ok());
    }

    #[test]
    fn key_debug_is_redacted() {
        let k = Key::from_slice(&[0xAB; KEY_LEN]).unwrap();
        assert_eq!(format!("{k:?}"), "Key([redacted])");
    }
}
