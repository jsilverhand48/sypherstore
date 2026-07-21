//! Sypherstore core: the hardware-independent half of the vault.
//!
//! This crate deliberately has no GUI, DBus, TPM or FIDO2 dependencies. The
//! two hardware layers enter through the `OuterKeyProvider` and
//! `InnerKeyProvider` traits in [`crypto::keys`], which `sypher-app`
//! implements against real devices and [`mock_hw`] implements against files.
//! Keeping the split at a trait boundary is what makes the security-critical
//! logic (the envelope, the lock state machine) testable on any machine.
//!
//! Start reading at [`vault::session::Session`], which composes everything
//! else and is the only path from ciphertext to plaintext.

pub mod config;
pub mod crypto;
pub mod model;
pub mod search;
pub mod secure;
pub mod vault;

#[cfg(feature = "mock-hw")]
pub mod mock_hw;
