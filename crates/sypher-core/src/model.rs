//! The vault's data model.
//!
//! The central split in this file is between [`SecretMeta`] and
//! [`SecretPayload`]. Metadata is stored in the clear and is what the popup
//! renders and searches; the payload is what lives inside the double-encrypted
//! envelope and only exists in memory while the vault is unlocked.
//!
//! Keeping them in separate types is a load-bearing safety property, not just
//! organization: the popup list can be built without ever holding an inner
//! key, and no code path can accidentally serialize a payload into a metadata
//! column, because the columns take `SecretMeta` fields only.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::secure::SecureBuf;

/// The kinds of secret the vault can hold.
///
/// The type drives how the editor UI labels fields and what the popup offers
/// to paste, but it does not change the envelope format: every type is stored
/// as the same CBOR payload with different fields populated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretType {
    Password,
    ApiKey,
    SshKey,
    GpgKey,
    Certificate,
    Token,
    RecoveryCodes,
    CreditCard,
    SecureNote,
    Database,
    WifiPassword,
    LicenseKey,
    Other,
}

impl SecretType {
    /// Every variant, in the order the editor's dropdown should show them.
    pub const ALL: [SecretType; 13] = [
        SecretType::Password,
        SecretType::ApiKey,
        SecretType::SshKey,
        SecretType::GpgKey,
        SecretType::Certificate,
        SecretType::Token,
        SecretType::RecoveryCodes,
        SecretType::CreditCard,
        SecretType::SecureNote,
        SecretType::Database,
        SecretType::WifiPassword,
        SecretType::LicenseKey,
        SecretType::Other,
    ];

    /// Stable identifier used in the database and on the CLI. Changing one of
    /// these strings is a breaking migration.
    pub fn as_str(&self) -> &'static str {
        match self {
            SecretType::Password => "password",
            SecretType::ApiKey => "api_key",
            SecretType::SshKey => "ssh_key",
            SecretType::GpgKey => "gpg_key",
            SecretType::Certificate => "certificate",
            SecretType::Token => "token",
            SecretType::RecoveryCodes => "recovery_codes",
            SecretType::CreditCard => "credit_card",
            SecretType::SecureNote => "secure_note",
            SecretType::Database => "database",
            SecretType::WifiPassword => "wifi_password",
            SecretType::LicenseKey => "license_key",
            SecretType::Other => "other",
        }
    }

    /// Human-facing label for the UI.
    pub fn label(&self) -> &'static str {
        match self {
            SecretType::Password => "Password",
            SecretType::ApiKey => "API Key",
            SecretType::SshKey => "SSH Key",
            SecretType::GpgKey => "GPG Key",
            SecretType::Certificate => "Certificate",
            SecretType::Token => "Token",
            SecretType::RecoveryCodes => "Recovery Codes",
            SecretType::CreditCard => "Credit Card",
            SecretType::SecureNote => "Secure Note",
            SecretType::Database => "Database",
            SecretType::WifiPassword => "Wi-Fi Password",
            SecretType::LicenseKey => "License Key",
            SecretType::Other => "Other",
        }
    }

    /// Parses the stable identifier. Unknown values from a newer schema map to
    /// `Other` rather than failing, so an older binary can still list and
    /// paste rows it does not fully understand.
    pub fn from_str_lenient(s: &str) -> Self {
        SecretType::ALL
            .iter()
            .copied()
            .find(|t| t.as_str() == s)
            .unwrap_or(SecretType::Other)
    }
}

impl fmt::Display for SecretType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The cleartext half of a secret: everything needed to find and display it.
///
/// Deliberately contains no secret value. The username is here because domain
/// filtering and search need it and because the popup shows it to disambiguate
/// two accounts on the same site; it is the one field where searchability was
/// chosen over confidentiality, and the spec's threat model accepts that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMeta {
    pub id: Uuid,
    /// Display name, e.g. "GitHub (work)".
    pub name: String,
    /// Hostname this secret belongs to, e.g. "github.com". Empty when the
    /// secret is not web-bound.
    pub domain: String,
    /// Desktop application this secret belongs to, matched against the active
    /// window class. Empty when not application-bound.
    pub application: String,
    pub secret_type: SecretType,
    pub username: String,
    pub tags: Vec<String>,
    /// Unix seconds.
    pub created_at: i64,
    pub updated_at: i64,
}

impl SecretMeta {
    /// Builds a metadata record for a brand new secret, assigning its UUID and
    /// timestamps.
    pub fn new(name: impl Into<String>, secret_type: SecretType) -> Self {
        let now = now_unix();
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            domain: String::new(),
            application: String::new(),
            secret_type,
            username: String::new(),
            tags: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }
}

/// The encrypted half of a secret: the part that only exists in plaintext
/// between a successful unlock and the next zeroize.
///
/// All fields are [`SecureBuf`] rather than `String` so that every plaintext
/// byte is mlocked and wiped on drop. `notes` and `extra` are optional because
/// most secrets do not use them and an absent field costs nothing in CBOR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretPayload {
    /// The secret itself: password, key body, token, card number.
    pub value: SecureBuf,
    /// Free-form notes.
    pub notes: Option<SecureBuf>,
    /// Arbitrary additional key material, e.g. an SSH passphrase alongside a
    /// key body, or a card's CVV and expiry. Keyed by a caller-chosen label.
    pub extra: Vec<(String, SecureBuf)>,
}

impl SecretPayload {
    /// A payload carrying only a secret value, which is the common case.
    pub fn new(value: SecureBuf) -> Self {
        Self {
            value,
            notes: None,
            extra: Vec::new(),
        }
    }

    /// Looks up an extra field by label.
    pub fn extra_field(&self, label: &str) -> Option<&SecureBuf> {
        self.extra
            .iter()
            .find(|(k, _)| k == label)
            .map(|(_, v)| v)
    }
}

/// Wire form of [`SecretPayload`], used only inside the envelope.
///
/// This mirrors `SecretPayload` with plain `Vec<u8>` fields because ciborium
/// needs `Serialize`/`Deserialize`, which `SecureBuf` deliberately does not
/// implement: deriving them would make it trivially easy to write a secret
/// into JSON config or a log. The conversion functions below are the only
/// bridge, and both wipe the insecure side before returning.
#[derive(Serialize, Deserialize, Zeroize)]
pub(crate) struct PayloadWire {
    #[serde(rename = "v")]
    pub value: Vec<u8>,
    #[serde(rename = "n", default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<u8>>,
    #[serde(rename = "x", default, skip_serializing_if = "Vec::is_empty")]
    pub extra: Vec<(String, Vec<u8>)>,
}

impl Drop for PayloadWire {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl PayloadWire {
    /// Copies out of the locked buffers into a serializable form. The result
    /// is unprotected memory, so callers must serialize and drop it promptly;
    /// `Drop` zeroizes it either way.
    pub(crate) fn from_payload(p: &SecretPayload) -> Self {
        Self {
            value: p.value.as_slice().to_vec(),
            notes: p.notes.as_ref().map(|n| n.as_slice().to_vec()),
            extra: p
                .extra
                .iter()
                .map(|(k, v)| (k.clone(), v.as_slice().to_vec()))
                .collect(),
        }
    }

    /// Moves the decoded bytes into locked buffers, wiping this wire copy as
    /// it goes.
    pub(crate) fn into_payload(mut self) -> SecretPayload {
        SecretPayload {
            value: SecureBuf::take_from(&mut self.value),
            notes: self
                .notes
                .as_mut()
                .map(|n| SecureBuf::take_from(n.as_mut_slice())),
            extra: self
                .extra
                .iter_mut()
                .map(|(k, v)| (std::mem::take(k), SecureBuf::take_from(v.as_mut_slice())))
                .collect(),
        }
    }
}

/// Current wall-clock time in Unix seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_type_identifiers_roundtrip() {
        for t in SecretType::ALL {
            assert_eq!(SecretType::from_str_lenient(t.as_str()), t);
        }
    }

    #[test]
    fn unknown_secret_type_degrades_to_other() {
        assert_eq!(
            SecretType::from_str_lenient("quantum_key_from_the_future"),
            SecretType::Other
        );
    }

    #[test]
    fn payload_survives_the_wire_roundtrip() {
        let payload = SecretPayload {
            value: SecureBuf::copy_from(b"correct horse battery staple"),
            notes: Some(SecureBuf::copy_from(b"recovery kit in the safe")),
            extra: vec![("cvv".to_string(), SecureBuf::copy_from(b"123"))],
        };
        let wire = PayloadWire::from_payload(&payload);
        let back = wire.into_payload();
        assert_eq!(back, payload);
        assert_eq!(back.extra_field("cvv").unwrap().as_slice(), b"123");
        assert!(back.extra_field("nope").is_none());
    }

    #[test]
    fn new_meta_has_distinct_ids_and_matching_timestamps() {
        let a = SecretMeta::new("GitHub", SecretType::Password);
        let b = SecretMeta::new("GitHub", SecretType::Password);
        assert_ne!(a.id, b.id);
        assert_eq!(a.created_at, a.updated_at);
    }
}
