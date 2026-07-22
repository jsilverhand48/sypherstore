//! File-backed stand-ins for the TPM and the FIDO2 authenticator.
//!
//! **These provide no security whatsoever.** The outer KEK is written to a
//! plain file and the inner "hmac-secret" is a hash of a file-stored seed.
//! Anyone who can read the vault directory can decrypt every secret in it.
//!
//! They exist so that the crypto, storage, search and UI layers can be
//! developed and tested on any machine, including CI, without a TPM or a
//! YubiKey, and so that the hardware-independent behaviour has real test
//! coverage. They are gated behind the `mock-hw` cargo feature, which the
//! release build never enables, and every mock file is stamped with a warning
//! banner so a stray one is obvious.

use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::crypto::keys::{InnerKeyProvider, Key, OuterKeyProvider, ProviderError, KEY_LEN};
use crate::secure::SecureBuf;
use crate::vault::paths::{write_private_atomic, VaultPaths};

/// Written into every mock file so an accidentally shipped one is unmistakable.
const BANNER: &[u8] = b"SYPHERSTORE-MOCK-KEY-NO-SECURITY\n";

/// Stands in for the TPM by keeping the outer KEK in a file.
pub struct MockOuterProvider {
    path: PathBuf,
}

impl MockOuterProvider {
    pub fn new(paths: &VaultPaths) -> Self {
        Self {
            path: paths.mock_hw().join("outer_kek"),
        }
    }

    fn ensure_dir(&self) -> Result<(), ProviderError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(())
    }
}

impl MockOuterProvider {
    /// Shared by both provisioning paths.
    fn write_key(&self, key: &Key) -> Result<(), ProviderError> {
        self.ensure_dir()?;
        let mut file = BANNER.to_vec();
        file.extend_from_slice(key.as_bytes());
        write_private_atomic(&self.path, &file)
            .map_err(|e| ProviderError::Device(e.to_string()))?;
        tracing::warn!(
            path = %self.path.display(),
            "wrote a MOCK outer key: this vault is NOT hardware protected"
        );
        Ok(())
    }
}

impl OuterKeyProvider for MockOuterProvider {
    fn provision(&self) -> Result<Key, ProviderError> {
        let key = Key::generate()?;
        self.write_key(&key)?;
        Ok(key)
    }

    fn provision_with(&self, key: &Key) -> Result<(), ProviderError> {
        self.write_key(key)
    }

    fn unseal(&self) -> Result<Key, ProviderError> {
        let file = match std::fs::read(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ProviderError::NotProvisioned)
            }
            Err(e) => return Err(e.into()),
        };
        let body = file
            .strip_prefix(BANNER)
            .ok_or_else(|| ProviderError::Corrupt("missing mock banner".into()))?;
        if body.len() != KEY_LEN {
            return Err(ProviderError::Corrupt(format!(
                "expected {KEY_LEN} key bytes, found {}",
                body.len()
            )));
        }
        Ok(Key::from_slice(body)?)
    }

    fn is_provisioned(&self) -> bool {
        self.path.exists()
    }
}

/// Stands in for the YubiKey by deriving the "assertion" from a file seed.
///
/// The real provider blocks on a touch and returns a value only the hardware
/// can compute. This one is a pure function of the seed, the credential id and
/// the salt, which reproduces the property the rest of the system actually
/// depends on: the same inputs always yield the same output.
pub struct MockInnerProvider {
    path: PathBuf,
}

impl MockInnerProvider {
    pub fn new(paths: &VaultPaths) -> Self {
        Self {
            path: paths.mock_hw().join("inner_seed"),
        }
    }

    fn load_seed(&self) -> Result<Vec<u8>, ProviderError> {
        let file = match std::fs::read(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ProviderError::NoDevice(
                    "mock authenticator not provisioned".into(),
                ))
            }
            Err(e) => return Err(e.into()),
        };
        file.strip_prefix(BANNER)
            .map(|b| b.to_vec())
            .ok_or_else(|| ProviderError::Corrupt("missing mock banner".into()))
    }
}

impl InnerKeyProvider for MockInnerProvider {
    fn provision(&self) -> Result<Vec<u8>, ProviderError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // One mock file stands for one physical authenticator. Registering a
        // second credential on it (as `enroll-key` does) must NOT regenerate
        // the seed, or the first credential's derived secret would change and
        // its vault would stop opening. Real hardware keeps its device secret
        // across registrations; only the per-credential id differs, and the
        // mock already varies its output by credential id. So keep any existing
        // seed and only create one the first time.
        if !self.path.exists() {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|e| ProviderError::Device(e.to_string()))?;
            let mut file = BANNER.to_vec();
            file.extend_from_slice(&seed);
            write_private_atomic(&self.path, &file)
                .map_err(|e| ProviderError::Device(e.to_string()))?;
        }

        // The real provider returns an authenticator-chosen credential id; a
        // random one here keeps the calling code identical.
        let mut credential_id = vec![0u8; 32];
        getrandom::getrandom(&mut credential_id)
            .map_err(|e| ProviderError::Device(e.to_string()))?;

        tracing::warn!(
            path = %self.path.display(),
            "provisioned a MOCK authenticator: no touch is required to unlock"
        );
        Ok(credential_id)
    }

    fn assert_secret(&self, credential_id: &[u8], salt: &[u8]) -> Result<SecureBuf, ProviderError> {
        let seed = self.load_seed()?;
        let mut hasher = Sha256::new();
        hasher.update(b"sypherstore-mock-hmac-secret");
        hasher.update(&seed);
        hasher.update((credential_id.len() as u64).to_le_bytes());
        hasher.update(credential_id);
        hasher.update(salt);
        let mut out = hasher.finalize();
        Ok(SecureBuf::take_from(out.as_mut_slice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::SALT_LEN;

    fn paths() -> (tempfile::TempDir, VaultPaths) {
        let tmp = tempfile::tempdir().unwrap();
        let p = VaultPaths::at(tmp.path().join("vault"));
        p.ensure_dirs().unwrap();
        (tmp, p)
    }

    #[test]
    fn outer_key_survives_a_reload() {
        let (_tmp, paths) = paths();
        let provider = MockOuterProvider::new(&paths);
        assert!(!provider.is_provisioned());

        let key = provider.provision().unwrap();
        assert!(provider.is_provisioned());
        assert_eq!(provider.unseal().unwrap(), key);
    }

    #[test]
    fn unsealing_before_provisioning_is_a_clean_error() {
        let (_tmp, paths) = paths();
        let provider = MockOuterProvider::new(&paths);
        assert!(matches!(
            provider.unseal(),
            Err(ProviderError::NotProvisioned)
        ));
    }

    #[test]
    fn corrupt_outer_key_file_is_detected() {
        let (_tmp, paths) = paths();
        let provider = MockOuterProvider::new(&paths);
        provider.provision().unwrap();

        // Truncating the key material must be caught, not silently accepted
        // as a short key.
        let path = paths.mock_hw().join("outer_kek");
        let mut file = BANNER.to_vec();
        file.extend_from_slice(b"too-short");
        std::fs::write(&path, &file).unwrap();
        assert!(matches!(provider.unseal(), Err(ProviderError::Corrupt(_))));

        std::fs::write(&path, b"no banner at all, 32 bytes here!").unwrap();
        assert!(matches!(provider.unseal(), Err(ProviderError::Corrupt(_))));
    }

    #[test]
    fn assertions_are_deterministic() {
        let (_tmp, paths) = paths();
        let provider = MockInnerProvider::new(&paths);
        let cred = provider.provision().unwrap();
        let salt = [4u8; SALT_LEN];

        let a = provider.assert_secret(&cred, &salt).unwrap();
        let b = provider.assert_secret(&cred, &salt).unwrap();
        assert_eq!(a, b, "the vault depends on assertions being reproducible");
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn assertions_vary_with_credential_and_salt() {
        let (_tmp, paths) = paths();
        let provider = MockInnerProvider::new(&paths);
        let cred = provider.provision().unwrap();

        let base = provider.assert_secret(&cred, &[1u8; SALT_LEN]).unwrap();
        let other_salt = provider.assert_secret(&cred, &[2u8; SALT_LEN]).unwrap();
        let other_cred = provider.assert_secret(b"different", &[1u8; SALT_LEN]).unwrap();

        assert_ne!(base, other_salt);
        assert_ne!(base, other_cred);
    }

    #[test]
    fn asserting_without_a_device_is_a_clean_error() {
        let (_tmp, paths) = paths();
        let provider = MockInnerProvider::new(&paths);
        assert!(matches!(
            provider.assert_secret(b"cred", &[0u8; SALT_LEN]),
            Err(ProviderError::NoDevice(_))
        ));
    }

    #[test]
    fn mock_files_carry_a_warning_banner() {
        let (_tmp, paths) = paths();
        MockOuterProvider::new(&paths).provision().unwrap();
        let raw = std::fs::read(paths.mock_hw().join("outer_kek")).unwrap();
        assert!(raw.starts_with(BANNER));
    }
}
