//! Selection of the two hardware key providers.
//!
//! This module is the single place where the build decides whether the vault
//! is protected by real hardware or by the development mocks. Everything above
//! it works against the `OuterKeyProvider` / `InnerKeyProvider` traits and
//! cannot tell the difference, which is what lets the security-critical logic
//! be tested without a TPM or a YubiKey attached.
//!
//! The `mock-hw` feature is deliberately all-or-nothing: there is no way to
//! mock one layer and not the other, since a vault with one real layer and one
//! fake one would be easy to mistake for a secure one.

use sypher_core::crypto::keys::{InnerKeyProvider, OuterKeyProvider};
use sypher_core::vault::paths::VaultPaths;

#[cfg(not(feature = "mock-hw"))]
pub mod fido;
#[cfg(not(feature = "mock-hw"))]
pub mod tpm;

/// The machine-bound outer provider for this build.
#[cfg(not(feature = "mock-hw"))]
pub fn outer(paths: &VaultPaths) -> Box<dyn OuterKeyProvider> {
    Box::new(tpm::TpmOuterProvider::new(paths))
}

/// The presence-bound inner provider for this build.
///
/// Wired with a terminal PIN prompt. Authenticators with a PIN set refuse
/// hmac-secret without user verification, so without this the vault could not
/// be opened at all on such a device. The prompt only fires if the device
/// actually demands it.
#[cfg(not(feature = "mock-hw"))]
pub fn inner(_paths: &VaultPaths) -> Box<dyn InnerKeyProvider> {
    Box::new(fido::FidoInnerProvider::with_pin_prompt(std::sync::Arc::new(
        prompt_pin_on_terminal,
    )))
}

/// An inner provider that collects its PIN through `prompt` instead of the
/// terminal. Used by the daemon, which has no terminal to prompt on.
#[cfg(not(feature = "mock-hw"))]
pub fn inner_with_prompt(
    _paths: &VaultPaths,
    prompt: fido::PinPrompt,
) -> Box<dyn InnerKeyProvider> {
    Box::new(fido::FidoInnerProvider::with_pin_prompt(prompt))
}

/// Reads the authenticator PIN from the terminal without echoing it.
///
/// Returns a plain `String` because that is what the CTAP library's builder
/// takes; it is dropped as soon as the operation completes. A `SecureBuf`
/// would have to be copied into a `String` at the call site anyway, so the
/// protection would be illusory. This is noted as a known residue.
#[cfg(not(feature = "mock-hw"))]
fn prompt_pin_on_terminal() -> Result<String, sypher_core::crypto::keys::ProviderError> {
    use std::io::IsTerminal;

    if !std::io::stdin().is_terminal() {
        return Err(sypher_core::crypto::keys::ProviderError::Device(
            "this authenticator needs its PIN, but there is no terminal to ask on. \
             Run this command interactively."
                .into(),
        ));
    }
    rpassword::prompt_password("Authenticator PIN: ").map_err(|e| {
        sypher_core::crypto::keys::ProviderError::Device(format!("could not read the PIN: {e}"))
    })
}

#[cfg(feature = "mock-hw")]
pub fn outer(paths: &VaultPaths) -> Box<dyn OuterKeyProvider> {
    Box::new(sypher_core::mock_hw::MockOuterProvider::new(paths))
}

/// Mirrors the hardware signature. The mock never needs a PIN, so the prompt
/// is accepted and ignored rather than making callers branch on the feature.
#[cfg(feature = "mock-hw")]
pub fn inner_with_prompt(
    paths: &VaultPaths,
    _prompt: std::sync::Arc<
        dyn Fn() -> Result<String, sypher_core::crypto::keys::ProviderError> + Send + Sync,
    >,
) -> Box<dyn InnerKeyProvider> {
    inner(paths)
}

#[cfg(feature = "mock-hw")]
pub fn inner(paths: &VaultPaths) -> Box<dyn InnerKeyProvider> {
    Box::new(sypher_core::mock_hw::MockInnerProvider::new(paths))
}

/// Whether this build uses the insecure mocks.
pub const IS_MOCK: bool = cfg!(feature = "mock-hw");

/// Banner printed by every command that touches key material in a mock build.
///
/// Printed to stderr on each invocation rather than once at init: a developer
/// who leaves a mock binary on their PATH should be reminded every single
/// time, not just when they created the vault.
pub fn warn_if_mock() {
    if IS_MOCK {
        eprintln!(
            "warning: this is a MOCK HARDWARE build. The TPM and YubiKey are\n\
             warning: simulated with plain files in the vault directory and\n\
             warning: provide NO protection. Do not store real secrets."
        );
    }
}
