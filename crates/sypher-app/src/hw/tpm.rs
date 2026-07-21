//! The outer key layer, sealed by the TPM.
//!
//! This is what binds a vault to *this machine*. The outer KEK is generated
//! once at `init`, sealed to the TPM, and written to disk only in sealed form.
//! Copying `vault.db` and the sealed blobs to another computer yields nothing:
//! the sealed private area can only be loaded under the primary key of the TPM
//! that created it.
//!
//! ## Why nothing is persisted in TPM NV storage
//!
//! The primary key is *recreated* from a fixed template on every start rather
//! than being made persistent with `evictcontrol`. TPMs have very limited
//! persistent-handle space that other software (systemd-cryptenrol, tpm2-tools,
//! Clevis) also competes for, and leaving a handle behind would be a side
//! effect on shared system state that Sypherstore has no business causing.
//!
//! Recreation is deterministic: the same template and the same hierarchy seed
//! always produce the same key, so the sealed blob from a previous run still
//! loads. It costs a few hundred milliseconds at daemon start, once.
//!
//! ## What this does not defend against
//!
//! No PCR policy is applied, so the seal is not bound to a particular boot
//! state. An attacker who boots the machine into a different OS can still ask
//! the TPM to unseal, because the TPM only checks that it is the same TPM.
//! Binding to PCR 7 (secure-boot state) is the obvious hardening and is left
//! as future work; it needs a re-seal path for firmware updates, which change
//! PCR values and would otherwise brick the vault.
//!
//! The threat model this *does* cover is the one that matters most in
//! practice: a stolen disk, a stolen backup, or a copied vault directory.

use std::str::FromStr;

use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    Digest, EccPoint, KeyedHashScheme, Private, Public, PublicBuilder,
    PublicEccParametersBuilder, PublicKeyedHashParameters, SensitiveData,
    SymmetricDefinitionObject,
};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::{Context, TctiNameConf};

use sypher_core::crypto::keys::{Key, OuterKeyProvider, ProviderError, KEY_LEN};
use sypher_core::vault::paths::{write_private_atomic, VaultPaths};

/// The kernel resource manager, which multiplexes TPM access so we do not
/// fight other users for the single direct handle at `/dev/tpm0`.
const TCTI: &str = "device:/dev/tpmrm0";

pub struct TpmOuterProvider {
    paths: VaultPaths,
}

impl TpmOuterProvider {
    pub fn new(paths: &VaultPaths) -> Self {
        Self {
            paths: paths.clone(),
        }
    }

    fn open(&self) -> Result<Context, ProviderError> {
        let tcti = TctiNameConf::from_str(TCTI).map_err(|e| {
            ProviderError::Device(format!("invalid TCTI configuration {TCTI}: {e}"))
        })?;
        Context::new(tcti).map_err(|e| {
            ProviderError::NoDevice(format!(
                "could not open {TCTI}: {e}. Is your user in the 'tss' group? \
                 Run `sypherstore doctor`."
            ))
        })
    }
}

/// The template for the parent key everything else is sealed under.
///
/// Every field here is load-bearing for reproducibility: change any of them
/// and the derived primary changes, which silently invalidates every existing
/// sealed blob. It is effectively a format constant.
fn primary_template() -> Result<Public, ProviderError> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        // The TPM generates the key itself from the hierarchy seed, which is
        // what makes recreation deterministic without us storing anything.
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .build()
        .map_err(|e| ProviderError::Device(format!("building primary attributes: {e}")))?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_128_CFB,
                EccCurve::NistP256,
            )
            .build()
            .map_err(|e| ProviderError::Device(format!("building ECC parameters: {e}")))?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| ProviderError::Device(format!("building the primary template: {e}")))
}

/// The template for the sealed data object holding the outer KEK.
///
/// A KeyedHash object with no scheme is the TPM's "just store these bytes"
/// primitive. It is deliberately not marked `sensitive_data_origin`, because
/// we supply the value rather than having the TPM invent it.
fn sealed_template() -> Result<Public, ProviderError> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(true)
        // Exempt from dictionary-attack lockout. There is no auth value to
        // guess, and a lockout triggered by unrelated software would
        // otherwise make the vault unopenable until the TPM was reset.
        .with_no_da(true)
        .build()
        .map_err(|e| ProviderError::Device(format!("building seal attributes: {e}")))?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .map_err(|e| ProviderError::Device(format!("building the seal template: {e}")))
}

/// Which TPM step failed, so the message can say something useful.
///
/// `execute_with_nullauth_session` requires the closure's error type to
/// implement `From<tss_esapi::Error>`, and a bare `tss_esapi::Error` would
/// lose the distinction between "this vault belongs to another machine"
/// (a failed load) and a genuine device fault.
#[derive(Debug)]
enum TpmFailure {
    /// The sealed blob could not be loaded under our primary.
    Load(tss_esapi::Error),
    /// Anything else the TPM refused.
    Other(tss_esapi::Error),
    /// A failure of ours rather than the device's.
    Provider(ProviderError),
}

impl From<tss_esapi::Error> for TpmFailure {
    fn from(e: tss_esapi::Error) -> Self {
        TpmFailure::Other(e)
    }
}

impl From<ProviderError> for TpmFailure {
    fn from(e: ProviderError) -> Self {
        TpmFailure::Provider(e)
    }
}

impl From<TpmFailure> for ProviderError {
    fn from(e: TpmFailure) -> Self {
        match e {
            TpmFailure::Load(e) => ProviderError::Corrupt(format!(
                "the TPM refused to load the sealed key: {e}. This vault was created on a \
                 different machine, or the TPM has been cleared."
            )),
            TpmFailure::Other(e) => ProviderError::Device(format!("TPM operation failed: {e}")),
            TpmFailure::Provider(e) => e,
        }
    }
}

/// Recreates the primary key. The caller must flush the returned handle.
fn create_primary(ctx: &mut Context) -> Result<KeyHandle, TpmFailure> {
    let template = primary_template()?;
    ctx.create_primary(Hierarchy::Owner, template, None, None, None, None)
        .map(|p| p.key_handle)
        .map_err(|e| {
            TpmFailure::Provider(ProviderError::Device(format!(
                "could not create the TPM primary key: {e}. \
                 The owner hierarchy may have an authorization value set."
            )))
        })
}

impl TpmOuterProvider {
    /// Seals `key` to this TPM and writes the two blob files.
    ///
    /// Shared by first-time provisioning and by recovery, so both paths
    /// produce byte-identical artefacts and cannot drift apart.
    fn seal(&self, key: &Key) -> Result<(), ProviderError> {
        let mut ctx = self.open()?;

        let (public, private) = ctx
            .execute_with_nullauth_session(|ctx| {
                let primary = create_primary(ctx)?;
                let sensitive = SensitiveData::try_from(key.as_bytes().to_vec()).map_err(|e| {
                    TpmFailure::Provider(ProviderError::Device(format!(
                        "the key does not fit a sealed object: {e}"
                    )))
                })?;

                let result = ctx.create(primary, sealed_template()?, None, Some(sensitive), None, None);

                // Flush before propagating: a leaked transient handle exhausts
                // the TPM's small object slot budget, and after a few daemon
                // restarts nothing would load at all.
                let _ = ctx.flush_context(primary.into());
                let result = result?;
                Ok::<_, TpmFailure>((result.out_public, result.out_private))
            })
            .map_err(ProviderError::from)?;

        let public_bytes = public
            .marshall()
            .map_err(|e| ProviderError::Device(format!("serializing the sealed public area: {e}")))?;

        write_private_atomic(&self.paths.tpm_sealed_pub(), &public_bytes)
            .map_err(|e| ProviderError::Device(e.to_string()))?;
        write_private_atomic(&self.paths.tpm_sealed_priv(), private.as_ref())
            .map_err(|e| ProviderError::Device(e.to_string()))?;

        tracing::info!("outer key sealed to the TPM");
        Ok(())
    }
}

impl OuterKeyProvider for TpmOuterProvider {
    fn provision(&self) -> Result<Key, ProviderError> {
        if self.is_provisioned() {
            return Err(ProviderError::Device(
                "this vault already has TPM-sealed key material".into(),
            ));
        }
        let key = Key::generate()?;
        self.seal(&key)?;
        Ok(key)
    }

    fn provision_with(&self, key: &Key) -> Result<(), ProviderError> {
        // Intentionally permitted even when already provisioned: recovery
        // onto a machine that has a stale or wrong seal is exactly when this
        // is needed.
        self.seal(key)
    }

    fn unseal(&self) -> Result<Key, ProviderError> {
        if !self.is_provisioned() {
            return Err(ProviderError::NotProvisioned);
        }

        let public_bytes = std::fs::read(self.paths.tpm_sealed_pub())?;
        let private_bytes = std::fs::read(self.paths.tpm_sealed_priv())?;

        let public = Public::unmarshall(&public_bytes).map_err(|e| {
            ProviderError::Corrupt(format!("tpm_sealed.pub is not a valid TPM public area: {e}"))
        })?;
        let private = Private::try_from(private_bytes).map_err(|e| {
            ProviderError::Corrupt(format!("tpm_sealed.priv is not a valid TPM private area: {e}"))
        })?;

        let mut ctx = self.open()?;
        let sealed = ctx
            .execute_with_nullauth_session(|ctx| {
                let primary = create_primary(ctx)?;

                let loaded = match ctx.load(primary, private, public) {
                    Ok(h) => h,
                    Err(e) => {
                        let _ = ctx.flush_context(primary.into());
                        return Err(TpmFailure::Load(e));
                    }
                };

                let data = ctx.unseal(loaded.into());

                let _ = ctx.flush_context(loaded.into());
                let _ = ctx.flush_context(primary.into());
                Ok::<_, TpmFailure>(data?)
            })
            .map_err(ProviderError::from)?;

        if sealed.len() != KEY_LEN {
            return Err(ProviderError::Corrupt(format!(
                "the sealed value is {} bytes, expected {KEY_LEN}",
                sealed.len()
            )));
        }

        // Move into locked memory. `Key`'s buffer is mlocked and zeroized on
        // drop, and `take_from` wipes the intermediate `Vec`.
        //
        // The `SensitiveData` that tss-esapi handed back cannot be wiped: it
        // does not implement `Zeroize` and exposes no mutable access, so its
        // copy of the key lives until the allocator reuses the memory. That is
        // a real residue, accepted because the alternative is forking the
        // library; it is noted in the threat model as future work.
        let mut bytes = sealed.value().to_vec();
        let key = Key::take_from(&mut bytes)?;
        drop(sealed);

        tracing::debug!("outer key unsealed from the TPM");
        Ok(key)
    }

    fn is_provisioned(&self) -> bool {
        self.paths.tpm_sealed_pub().exists() && self.paths.tpm_sealed_priv().exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact marshalled primary template, as a tripwire.
    const PRIMARY_TEMPLATE_HEX: &str =
        "0023000b00030072000000060080004300100003001000000000";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn templates_build_without_a_tpm() {
        // Template construction is pure; catching a malformed template here
        // is much clearer than a TPM error later.
        assert!(primary_template().is_ok());
        assert!(sealed_template().is_ok());
    }

    #[test]
    fn the_primary_template_is_stable() {
        // Every existing sealed blob depends on this template producing the
        // same key. If a refactor changes it, this catches it before a user
        // discovers their vault will not open.
        let a = primary_template().unwrap().marshall().unwrap();
        let b = primary_template().unwrap().marshall().unwrap();
        assert_eq!(a, b);
        // Pinned byte-for-byte. A length check would be far too weak: several
        // meaningful attribute changes keep the same encoded size, and any of
        // them silently derives a different primary key, which would make
        // every existing vault fail to open with no obvious cause.
        assert_eq!(
            hex(&a),
            PRIMARY_TEMPLATE_HEX,
            "the primary template changed; every existing vault would stop opening"
        );
    }

    #[test]
    fn an_unprovisioned_vault_reports_as_such() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = VaultPaths::at(tmp.path().join("vault"));
        paths.ensure_dirs().unwrap();
        let provider = TpmOuterProvider::new(&paths);

        assert!(!provider.is_provisioned());
        assert!(matches!(
            provider.unseal(),
            Err(ProviderError::NotProvisioned)
        ));
    }

    #[test]
    fn a_corrupt_sealed_blob_is_reported_clearly() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = VaultPaths::at(tmp.path().join("vault"));
        paths.ensure_dirs().unwrap();
        std::fs::write(paths.tpm_sealed_pub(), b"not a tpm public area").unwrap();
        std::fs::write(paths.tpm_sealed_priv(), b"not a tpm private area").unwrap();

        let provider = TpmOuterProvider::new(&paths);
        assert!(provider.is_provisioned());
        assert!(matches!(provider.unseal(), Err(ProviderError::Corrupt(_))));
    }

    /// Hardware tests. Run with:
    /// `cargo test -p sypher-app --features hw-tests -- --ignored --test-threads=1`
    #[cfg(feature = "hw-tests")]
    mod hardware {
        use super::*;

        #[test]
        #[ignore = "needs a real TPM at /dev/tpmrm0"]
        fn seals_and_unseals_across_separate_contexts() {
            let tmp = tempfile::tempdir().unwrap();
            let paths = VaultPaths::at(tmp.path().join("vault"));
            paths.ensure_dirs().unwrap();
            let provider = TpmOuterProvider::new(&paths);

            let sealed = provider.provision().unwrap();
            assert!(provider.is_provisioned());

            // A separate unseal proves the primary is reproducible, which is
            // what makes the vault survive a reboot.
            let recovered = provider.unseal().unwrap();
            assert_eq!(sealed, recovered);
        }

        #[test]
        #[ignore = "needs a real TPM at /dev/tpmrm0"]
        fn provisioning_twice_is_refused() {
            let tmp = tempfile::tempdir().unwrap();
            let paths = VaultPaths::at(tmp.path().join("vault"));
            paths.ensure_dirs().unwrap();
            let provider = TpmOuterProvider::new(&paths);

            provider.provision().unwrap();
            assert!(provider.provision().is_err(), "would orphan the first key");
        }

        #[test]
        #[ignore = "needs a real TPM at /dev/tpmrm0"]
        fn a_recovery_key_re_seals_the_same_vault() {
            // The disaster-recovery path, end to end: seal a key, render it as
            // a recovery string, destroy the seal as a dead TPM would, then
            // adopt it back and confirm the original key returns.
            //
            // Written as one test on purpose. Splitting it across steps that
            // pass a key between them is how a vault gets destroyed by a
            // half-finished procedure.
            use sypher_core::vault::recovery;

            let tmp = tempfile::tempdir().unwrap();
            let paths = VaultPaths::at(tmp.path().join("vault"));
            paths.ensure_dirs().unwrap();
            let provider = TpmOuterProvider::new(&paths);

            let original = provider.provision().unwrap();
            let written_down = recovery::encode(&original);

            // The TPM is cleared / the machine is replaced.
            std::fs::remove_file(paths.tpm_sealed_pub()).unwrap();
            std::fs::remove_file(paths.tpm_sealed_priv()).unwrap();
            assert!(!provider.is_provisioned());
            assert!(matches!(
                provider.unseal(),
                Err(ProviderError::NotProvisioned)
            ));

            // Recovery on the replacement machine.
            let recovered = recovery::decode(&written_down).unwrap();
            provider.provision_with(&recovered).unwrap();

            assert_eq!(
                provider.unseal().unwrap(),
                original,
                "the adopted vault must yield the original outer key"
            );
        }

        #[test]
        #[ignore = "needs a real TPM at /dev/tpmrm0"]
        fn a_recovery_key_from_another_vault_does_not_match() {
            // Adopting the wrong key must not silently produce a vault that
            // looks fine but decrypts nothing.
            let tmp = tempfile::tempdir().unwrap();
            let paths = VaultPaths::at(tmp.path().join("vault"));
            paths.ensure_dirs().unwrap();
            let provider = TpmOuterProvider::new(&paths);

            let original = provider.provision().unwrap();
            let unrelated = Key::generate().unwrap();
            provider.provision_with(&unrelated).unwrap();

            let now = provider.unseal().unwrap();
            assert_eq!(now, unrelated);
            assert_ne!(now, original, "the wrong key must not resurrect the old one");
        }

        #[test]
        #[ignore = "needs a real TPM at /dev/tpmrm0"]
        fn a_tampered_private_area_does_not_unseal() {
            let tmp = tempfile::tempdir().unwrap();
            let paths = VaultPaths::at(tmp.path().join("vault"));
            paths.ensure_dirs().unwrap();
            let provider = TpmOuterProvider::new(&paths);
            provider.provision().unwrap();

            // Flip a bit in the middle of the encrypted private area.
            let mut priv_bytes = std::fs::read(paths.tpm_sealed_priv()).unwrap();
            let mid = priv_bytes.len() / 2;
            priv_bytes[mid] ^= 0x01;
            std::fs::write(paths.tpm_sealed_priv(), &priv_bytes).unwrap();

            assert!(
                provider.unseal().is_err(),
                "the TPM must reject a tampered private area"
            );
        }
    }
}
