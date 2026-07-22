//! The inner key layer, derived from a FIDO2 authenticator.
//!
//! This is what binds a vault to *a physical key you touch*. Where the TPM
//! layer proves "this is the same machine", this layer proves "a human is
//! present right now and has the token".
//!
//! ## Why hmac-secret rather than PIV or a signature
//!
//! The obvious approach, signing a challenge, does not work: FIDO2 signatures
//! include a monotonically increasing counter, so the same challenge produces
//! a different signature every time. Nothing reproducible can be derived from
//! one.
//!
//! The `hmac-secret` extension exists precisely for this. The authenticator
//! holds a per-credential secret it never reveals, and returns
//! `HMAC-SHA256(credential_secret, salt)` for a caller-supplied salt. The same
//! salt always yields the same 32 bytes, and no one without the token can
//! compute them. That is exactly a key-derivation oracle gated on touch.
//!
//! PIV would also work and is what many YubiKey integrations use, but this
//! particular key exposes only the FIDO interface over USB (`1050:0402`), so
//! PIV/CCID is not available. hmac-secret is the right primitive regardless.
//!
//! ## A PIN is always required
//!
//! Every operation runs with user verification: the authenticator's PIN is
//! requested and passed on registration and on every unlock. This is a
//! deliberate second factor on top of the touch, so that a stolen-and-plugged
//! key alone cannot unlock the vault without also knowing the PIN. A key with
//! no PIN set therefore cannot be used, which is intended.
//!
//! ## More than one enrolled key
//!
//! Unlock passes every enrolled credential in the assertion's allow-list, so
//! whichever key is present answers with a single touch and reports which
//! credential it used. That is how a backup YubiKey opens the same vault.
//!
//! ## What an attacker with the vault but not the key can do
//!
//! Nothing. The inner ciphertext is sealed under a key derived from the
//! authenticator's secret, which never leaves the device. Brute force means
//! brute forcing 32 bytes of HMAC output.
//!
//! ## What an attacker with the key but not the machine can do
//!
//! Also nothing, because the outer TPM layer still applies. Both are required,
//! which is the whole point of the two-layer envelope.

use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::{
    Extension as AssertionExtension, GetAssertionArgsBuilder,
};
use ctap_hid_fido2::fidokey::make_credential::make_credential_params::{
    Extension as CredentialExtension, MakeCredentialArgsBuilder,
};
use ctap_hid_fido2::fidokey::FidoKeyHid;
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::{FidoKeyHidFactory, LibCfg};

use std::sync::Arc;

use sypher_core::crypto::keys::{InnerKeyProvider, ProviderError};
use sypher_core::secure::SecureBuf;

/// Supplies the authenticator's PIN on demand.
///
/// A callback rather than a stored value, so the PIN is requested only when
/// the device actually demands it and is not held between operations. The CLI
/// implements this with a terminal prompt; the daemon prompts in the popup.
pub type PinPrompt = Arc<dyn Fn() -> Result<String, ProviderError> + Send + Sync>;

/// Relying-party id for the credential.
///
/// A `.local` name that resolves to nothing, because this credential is not
/// for a website and must never be usable as one. Changing it orphans every
/// existing vault, since the authenticator derives its per-credential secret
/// partly from the RP id.
const RP_ID: &str = "sypherstore.local";

/// Shown by authenticators that have a display.
const RP_NAME: &str = "Sypherstore";

/// The challenge sent with each request.
///
/// For a normal WebAuthn login this must be a server-issued nonce, because the
/// signature is what proves freshness. Here nothing consumes the signature at
/// all; the value we want is the hmac-secret output, which does not depend on
/// the challenge. A fixed value keeps the operation deterministic and makes it
/// obvious that no replay protection is being claimed.
const CHALLENGE: &[u8] = b"sypherstore-fixed-challenge-v1";

/// Length of an hmac-secret salt and of its output.
const HMAC_LEN: usize = 32;

pub struct FidoInnerProvider {
    /// Called only if the authenticator refuses to act without user
    /// verification. `None` means no PIN can be obtained, and such a device
    /// will fail with a clear message rather than silently mis-deriving.
    pin_prompt: Option<PinPrompt>,
}

impl FidoInnerProvider {
    pub fn new() -> Self {
        Self { pin_prompt: None }
    }

    /// A provider that can obtain a PIN when the authenticator demands one.
    pub fn with_pin_prompt(prompt: PinPrompt) -> Self {
        Self {
            pin_prompt: Some(prompt),
        }
    }

    /// Obtains a PIN, or explains why the operation cannot proceed.
    fn request_pin(&self) -> Result<String, ProviderError> {
        match &self.pin_prompt {
            Some(prompt) => prompt(),
            None => Err(ProviderError::Device(
                "this authenticator requires its PIN, but there is no way to ask for one here"
                    .into(),
            )),
        }
    }

    /// Opens the first connected FIDO2 authenticator.
    fn open(&self) -> Result<FidoKeyHid, ProviderError> {
        let devices = ctap_hid_fido2::get_fidokey_devices();
        if devices.is_empty() {
            return Err(ProviderError::NoDevice(
                "no FIDO2 authenticator found. Plug in your YubiKey. If it is plugged in, \
                 check that /dev/hidraw* is readable (run `sypherstore doctor`)."
                    .into(),
            ));
        }
        if devices.len() > 1 {
            // Which one gets used would otherwise be luck of enumeration
            // order, and a vault registered against one key will not open
            // with another.
            tracing::warn!(
                count = devices.len(),
                "multiple FIDO2 authenticators connected; using the first"
            );
        }

        FidoKeyHidFactory::create(&LibCfg::init()).map_err(|e| {
            ProviderError::Device(format!("could not open the FIDO2 authenticator: {e}"))
        })
    }
}

impl Default for FidoInnerProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl InnerKeyProvider for FidoInnerProvider {
    fn provision(&self) -> Result<Vec<u8>, ProviderError> {
        let device = self.open()?;

        // Named so an authenticator with a display shows something the user
        // recognizes when it prompts.
        let user = PublicKeyCredentialUserEntity::new(
            Some(b"sypherstore"),
            Some(RP_NAME),
            Some(RP_NAME),
        );

        // A PIN is mandatory for this vault, so obtain it up front and register
        // the credential with user verification. Non-resident: the credential
        // id is stored in our vault rather than consuming one of the
        // authenticator's limited resident-key slots.
        let pin = self.request_pin()?;
        let attestation = device
            .make_credential_with_args(
                &MakeCredentialArgsBuilder::new(RP_ID, CHALLENGE)
                    .extensions(&[CredentialExtension::HmacSecret(Some(true))])
                    .user_entity(&user)
                    .pin(&pin)
                    .build(),
            )
            .map_err(map_device_error)?;

        // The authenticator must confirm it actually enabled hmac-secret. If
        // it silently ignored the extension, every later assertion would
        // return nothing and the vault would be permanently unopenable, so
        // failing loudly here is essential.
        let enabled = attestation.extensions.iter().any(|e| {
            matches!(
                e,
                CredentialExtension::HmacSecret(Some(true)) | CredentialExtension::HmacSecret(None)
            )
        });
        if !enabled {
            return Err(ProviderError::Device(
                "this authenticator did not enable the hmac-secret extension. \
                 Sypherstore needs a CTAP2 authenticator that supports it."
                    .into(),
            ));
        }

        let credential_id = attestation.credential_descriptor.id;
        if credential_id.is_empty() {
            return Err(ProviderError::Device(
                "the authenticator returned an empty credential id".into(),
            ));
        }

        tracing::info!(
            bytes = credential_id.len(),
            "registered a FIDO2 credential for this vault"
        );
        Ok(credential_id)
    }

    fn assert_secret(&self, credential_id: &[u8], salt: &[u8]) -> Result<SecureBuf, ProviderError> {
        // A single known credential is just an allow-list of one.
        let (_, secret) = self.assert_first_available(&[credential_id.to_vec()], salt)?;
        Ok(secret)
    }

    fn assert_first_available(
        &self,
        credential_ids: &[Vec<u8>],
        salt: &[u8],
    ) -> Result<(Vec<u8>, SecureBuf), ProviderError> {
        let salt = check_salt(salt)?;
        if credential_ids.is_empty() {
            return Err(ProviderError::NoDevice(
                "this vault has no enrolled authenticators".into(),
            ));
        }

        let device = self.open()?;

        // PIN is required on every unlock. One request, one touch: every
        // enrolled credential goes in the allow-list and the authenticator
        // answers for whichever it holds.
        let pin = self.request_pin()?;
        let mut builder = GetAssertionArgsBuilder::new(RP_ID, CHALLENGE)
            .extensions(&[AssertionExtension::HmacSecret(Some(salt))])
            .pin(&pin);
        for id in credential_ids {
            builder = builder.add_credential_id(id);
        }
        let assertions = device
            .get_assertion_with_args(&builder.build())
            .map_err(map_device_error)?;

        let assertion = assertions.first().ok_or_else(|| {
            ProviderError::Device(
                "the authenticator returned no assertion. It is not one of the keys enrolled \
                 in this vault, or its credential was deleted."
                    .into(),
            )
        })?;

        // The authenticator reports which credential it used. Some omit it when
        // the allow-list held exactly one, in which case that one is implied.
        let matched = if !assertion.credential_id.is_empty() {
            assertion.credential_id.clone()
        } else if credential_ids.len() == 1 {
            credential_ids[0].clone()
        } else {
            return Err(ProviderError::Device(
                "the authenticator did not say which credential it used".into(),
            ));
        };

        for extension in &assertion.extensions {
            if let AssertionExtension::HmacSecret(Some(output)) = extension {
                if output.len() != HMAC_LEN {
                    return Err(ProviderError::Device(format!(
                        "hmac-secret returned {} bytes, expected {HMAC_LEN}",
                        output.len()
                    )));
                }
                // Copy into locked memory, then wipe the library's buffer.
                let mut raw = output.to_vec();
                let secret = SecureBuf::take_from(&mut raw);
                tracing::debug!("hmac-secret assertion succeeded");
                return Ok((matched, secret));
            }
        }

        Err(ProviderError::Device(
            "the authenticator completed the assertion but returned no hmac-secret output. \
             The credential may have been created without the extension."
                .into(),
        ))
    }
}

/// Validates and copies the hmac-secret salt, rejecting a wrong length before
/// any hardware is touched.
fn check_salt(salt: &[u8]) -> Result<[u8; HMAC_LEN], ProviderError> {
    salt.try_into().map_err(|_| {
        ProviderError::Device(format!(
            "the hmac-secret salt must be {HMAC_LEN} bytes, got {}",
            salt.len()
        ))
    })
}

/// Turns a library error into something a user can act on.
///
/// The underlying errors are CTAP status codes wrapped in prose; the ones that
/// matter to a person are "you did not touch it" and "wrong PIN", and those
/// deserve distinct handling rather than a generic device failure.
fn map_device_error(error: impl std::fmt::Display) -> ProviderError {
    let text = error.to_string();
    let lower = text.to_ascii_lowercase();

    if lower.contains("timeout") || lower.contains("user action timeout") {
        ProviderError::Timeout
    } else if lower.contains("operation_denied") || lower.contains("operation denied") {
        // Observed when the sensor is not touched in time. Saying so beats a
        // raw CTAP code, which reads like a permissions problem.
        ProviderError::Cancelled
    } else if lower.contains("keepalive cancel") || lower.contains("cancel") {
        ProviderError::Cancelled
    } else if lower.contains("pin") {
        ProviderError::Device(format!(
            "{text}. If your authenticator has a PIN, Sypherstore needs it configured."
        ))
    } else {
        ProviderError::Device(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rp_id_is_not_a_real_website() {
        // A credential scoped to a resolvable domain could be solicited by a
        // site pretending to be it. `.local` cannot be registered.
        assert!(RP_ID.ends_with(".local"));
        assert_eq!(RP_NAME, "Sypherstore");
    }

    #[test]
    fn the_rp_id_is_fixed() {
        // The authenticator derives its per-credential secret partly from the
        // RP id, so changing this orphans every existing vault.
        assert_eq!(RP_ID, "sypherstore.local");
    }

    #[test]
    fn an_untouched_sensor_reads_as_a_cancellation_not_a_pin_problem() {
        // This exact string came from a real YubiKey when the sensor was not
        // touched in time. It must map to a cancellation, not a PIN error.
        let untouched = "response_status err = 0x27 CTAP2_ERR_OPERATION_DENIED  Not authorized \
                         for requested operation.";
        assert!(matches!(
            map_device_error(untouched),
            ProviderError::Cancelled
        ));
    }

    #[test]
    fn without_a_prompt_a_pin_requirement_is_explained_not_hidden() {
        // A PIN is now mandatory, so a provider with no way to ask for one must
        // say so rather than proceeding.
        let provider = FidoInnerProvider::new();
        let err = provider.request_pin().unwrap_err();
        assert!(
            matches!(err, ProviderError::Device(m) if m.contains("PIN")),
            "the user must be told a PIN is needed"
        );
    }

    #[test]
    fn a_wrong_length_salt_is_refused_before_touching_hardware() {
        // Catching this here means the user does not get a touch prompt for a
        // request that was never going to work.
        let provider = FidoInnerProvider::new();
        let err = provider.assert_secret(b"cred", &[0u8; 16]).unwrap_err();
        assert!(
            matches!(err, ProviderError::Device(m) if m.contains("32 bytes")),
            "expected a salt length complaint"
        );
    }

    #[test]
    fn an_empty_allow_list_is_refused_before_touching_hardware() {
        let provider = FidoInnerProvider::new();
        let err = provider
            .assert_first_available(&[], &[0u8; HMAC_LEN])
            .unwrap_err();
        assert!(matches!(err, ProviderError::NoDevice(_)));
    }

    #[test]
    fn timeouts_and_cancellations_are_distinguished() {
        assert!(matches!(
            map_device_error("CTAP2 error: user action timeout"),
            ProviderError::Timeout
        ));
        assert!(matches!(
            map_device_error("keepalive cancel"),
            ProviderError::Cancelled
        ));
        assert!(matches!(
            map_device_error("something else entirely"),
            ProviderError::Device(_)
        ));
    }

    /// Hardware tests. Each one requires physically touching the key.
    /// `cargo test -p sypher-app --features hw-tests -- --ignored --test-threads=1`
    #[cfg(feature = "hw-tests")]
    mod hardware {
        use super::*;

        #[test]
        #[ignore = "needs a YubiKey and a physical touch"]
        fn registers_a_credential_and_derives_a_stable_secret() {
            let provider = FidoInnerProvider::new();

            eprintln!("TOUCH YOUR KEY to register...");
            let credential = provider.provision().unwrap();
            assert!(!credential.is_empty());

            let salt = [7u8; HMAC_LEN];
            eprintln!("TOUCH YOUR KEY again (first assertion)...");
            let first = provider.assert_secret(&credential, &salt).unwrap();
            eprintln!("TOUCH YOUR KEY again (second assertion)...");
            let second = provider.assert_secret(&credential, &salt).unwrap();

            // The property the entire vault depends on.
            assert_eq!(first, second, "assertions must be reproducible");
            assert_eq!(first.len(), HMAC_LEN);
        }

        #[test]
        #[ignore = "needs a YubiKey and a physical touch"]
        fn a_different_salt_yields_a_different_secret() {
            let provider = FidoInnerProvider::new();
            eprintln!("TOUCH YOUR KEY to register...");
            let credential = provider.provision().unwrap();

            eprintln!("TOUCH YOUR KEY (salt A)...");
            let a = provider.assert_secret(&credential, &[1u8; HMAC_LEN]).unwrap();
            eprintln!("TOUCH YOUR KEY (salt B)...");
            let b = provider.assert_secret(&credential, &[2u8; HMAC_LEN]).unwrap();

            assert_ne!(a, b, "the salt must actually affect the output");
        }
    }
}
