//! The double-encryption envelope.
//!
//! Every secret is wrapped twice. The inner layer is keyed by the YubiKey, the
//! outer by the TPM, and a blob is only readable when both are present. The
//! ordering matters: the inner ciphertext is produced first and then wrapped,
//! so an attacker who compromises the TPM alone (say, by stealing the running
//! machine) peels off the outer layer and finds another AEAD ciphertext, not
//! plaintext.
//!
//! ## Layout
//!
//! ```text
//!   blob := header || n2 || c2
//!
//!   header := "SYPH" | version:u8 | cipher:u8 | uuid:16        (22 bytes)
//!   c1     := XChaCha20Poly1305(k_inner, n1, aad = header) [ CBOR payload ]
//!   c2     := XChaCha20Poly1305(k_outer, n2, aad = header) [ n1 || c1 ]
//! ```
//!
//! ## Why the header is authenticated data
//!
//! Both layers bind the same header as AAD, and the header contains the
//! secret's UUID. Since the subkeys are themselves derived from that UUID, an
//! attacker with write access to `vault.db` cannot move a blob from one row to
//! another: the subkeys for the target row will not decrypt it, and even if
//! they somehow did, the AAD check would fail. This defeats the swap attack
//! where a low-value secret's blob is copied over a high-value one to learn
//! which is which, or to make a paste emit an attacker-chosen value.
//!
//! Including the version and cipher id in the AAD also makes downgrade attacks
//! detectable: an attacker who rewrites the version byte to point at a weaker
//! future cipher invalidates the tag.
//!
//! ## Nonces
//!
//! Both nonces are 192 bits from the OS CSPRNG. At that width, random
//! generation has negligible collision probability without any counter state,
//! which is why XChaCha20 was chosen over ChaCha20 or AES-GCM: there is no
//! nonce bookkeeping to get wrong across restores from backup.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use uuid::Uuid;

use super::keys::{
    derive_secret_inner_key, derive_secret_outer_key, Key, KeyError,
};
use crate::model::{MetaWire, PayloadWire, SecretMeta, SecretPayload};
use crate::secure::SecureBuf;

/// File magic, so a stray blob is identifiable outside the database.
const MAGIC: &[u8; 4] = b"SYPH";
/// Envelope format version. Bump on any layout change.
pub const VERSION: u8 = 1;
/// Cipher identifier: 1 = XChaCha20-Poly1305 both layers.
pub const CIPHER_XCHACHA20POLY1305: u8 = 1;

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 4 + 1 + 1 + 16;

/// Plaintext written into the verification blob stored in `meta`.
///
/// After an unlock, decrypting this proves both keys are correct without
/// touching a real secret. Without it, a wrong inner key would only surface
/// when the user tried to paste something, and would be indistinguishable from
/// a corrupt row.
pub const VERIFICATION_PLAINTEXT: &[u8] = b"sypherstore-verify";

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("Not a sypherstore envelope (bad magic)")]
    BadMagic,
    #[error("Unsupported envelope version {0}, this build understands {VERSION}")]
    UnsupportedVersion(u8),
    #[error("Unsupported cipher id {0}")]
    UnsupportedCipher(u8),
    #[error("Envelope is truncated: {0} bytes is too short")]
    Truncated(usize),
    #[error("Envelope belongs to secret {found}, not {expected}")]
    IdMismatch { expected: Uuid, found: Uuid },
    /// Deliberately uninformative: distinguishing "wrong key" from "tampered
    /// ciphertext" would hand an attacker an oracle.
    #[error("Decryption failed: wrong key or corrupt data")]
    Decrypt,
    #[error("Payload encoding failed: {0}")]
    Encode(String),
    #[error("Payload decoding failed: {0}")]
    Decode(String),
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error("Failed to gather randomness: {0}")]
    Random(#[from] getrandom::Error),
}

/// Builds the 22-byte authenticated header for a secret.
fn build_header(id: &Uuid) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..4].copy_from_slice(MAGIC);
    h[4] = VERSION;
    h[5] = CIPHER_XCHACHA20POLY1305;
    h[6..22].copy_from_slice(id.as_bytes());
    h
}

/// Validates a header and returns the UUID it claims.
fn parse_header(blob: &[u8]) -> Result<Uuid, EnvelopeError> {
    if blob.len() < HEADER_LEN + NONCE_LEN + TAG_LEN {
        return Err(EnvelopeError::Truncated(blob.len()));
    }
    if &blob[0..4] != MAGIC {
        return Err(EnvelopeError::BadMagic);
    }
    let version = blob[4];
    if version != VERSION {
        return Err(EnvelopeError::UnsupportedVersion(version));
    }
    let cipher = blob[5];
    if cipher != CIPHER_XCHACHA20POLY1305 {
        return Err(EnvelopeError::UnsupportedCipher(cipher));
    }
    let mut id_bytes = [0u8; 16];
    id_bytes.copy_from_slice(&blob[6..22]);
    Ok(Uuid::from_bytes(id_bytes))
}

/// Encrypts arbitrary bytes through both layers, bound to `id`.
///
/// This is the primitive under both [`seal_payload`] and the verification
/// blob. Callers holding a structured payload should use `seal_payload`.
pub fn seal_bytes(
    id: &Uuid,
    inner_kek: &Key,
    outer_kek: &Key,
    plaintext: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    let header = build_header(id);
    let k_inner = derive_secret_inner_key(inner_kek, id)?;
    let k_outer = derive_secret_outer_key(outer_kek, id)?;

    // Inner layer.
    let mut n1 = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut n1)?;
    let inner_cipher = XChaCha20Poly1305::new(k_inner.as_bytes().into());
    let c1 = inner_cipher
        .encrypt(
            XNonce::from_slice(&n1),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| EnvelopeError::Decrypt)?;

    // Outer layer wraps the inner nonce together with the inner ciphertext, so
    // n1 is itself confidential. That is not required for security (nonces are
    // public in the AEAD model) but it denies an attacker holding only the
    // outer key any structural information about the inner layer.
    let mut inner_framed = Vec::with_capacity(NONCE_LEN + c1.len());
    inner_framed.extend_from_slice(&n1);
    inner_framed.extend_from_slice(&c1);

    let mut n2 = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut n2)?;
    let outer_cipher = XChaCha20Poly1305::new(k_outer.as_bytes().into());
    let c2 = outer_cipher
        .encrypt(
            XNonce::from_slice(&n2),
            Payload {
                msg: &inner_framed,
                aad: &header,
            },
        )
        .map_err(|_| EnvelopeError::Decrypt)?;

    let mut blob = Vec::with_capacity(HEADER_LEN + NONCE_LEN + c2.len());
    blob.extend_from_slice(&header);
    blob.extend_from_slice(&n2);
    blob.extend_from_slice(&c2);
    Ok(blob)
}

/// Decrypts a blob produced by [`seal_bytes`], checking it belongs to `id`.
///
/// The plaintext lands directly in a [`SecureBuf`]; the intermediate outer
/// plaintext is wiped before returning.
pub fn open_bytes(
    id: &Uuid,
    inner_kek: &Key,
    outer_kek: &Key,
    blob: &[u8],
) -> Result<SecureBuf, EnvelopeError> {
    let found = parse_header(blob)?;
    if found != *id {
        return Err(EnvelopeError::IdMismatch {
            expected: *id,
            found,
        });
    }
    let header = &blob[..HEADER_LEN];
    let n2 = XNonce::from_slice(&blob[HEADER_LEN..HEADER_LEN + NONCE_LEN]);
    let c2 = &blob[HEADER_LEN + NONCE_LEN..];

    let k_outer = derive_secret_outer_key(outer_kek, id)?;
    let outer_cipher = XChaCha20Poly1305::new(k_outer.as_bytes().into());
    let mut inner_framed = outer_cipher
        .decrypt(n2, Payload { msg: c2, aad: header })
        .map_err(|_| EnvelopeError::Decrypt)?;

    if inner_framed.len() < NONCE_LEN + TAG_LEN {
        return Err(EnvelopeError::Truncated(inner_framed.len()));
    }
    let (n1, c1) = inner_framed.split_at(NONCE_LEN);

    let k_inner = derive_secret_inner_key(inner_kek, id)?;
    let inner_cipher = XChaCha20Poly1305::new(k_inner.as_bytes().into());
    let mut plaintext = inner_cipher
        .decrypt(
            XNonce::from_slice(n1),
            Payload { msg: c1, aad: header },
        )
        .map_err(|_| EnvelopeError::Decrypt)?;

    let out = SecureBuf::take_from(&mut plaintext);
    // The outer plaintext held the inner ciphertext, not secrets, but wiping
    // it keeps the "no unlocked copies" invariant simple to audit.
    zeroize::Zeroize::zeroize(&mut inner_framed);
    Ok(out)
}

/// Encrypts a structured payload into a storable blob.
pub fn seal_payload(
    id: &Uuid,
    inner_kek: &Key,
    outer_kek: &Key,
    payload: &SecretPayload,
) -> Result<Vec<u8>, EnvelopeError> {
    let wire = PayloadWire::from_payload(payload);
    let mut cbor = Vec::new();
    ciborium::into_writer(&wire, &mut cbor)
        .map_err(|e| EnvelopeError::Encode(e.to_string()))?;
    let result = seal_bytes(id, inner_kek, outer_kek, &cbor);
    // The CBOR buffer is plaintext in unprotected memory; it must not outlive
    // this call regardless of whether sealing succeeded.
    zeroize::Zeroize::zeroize(&mut cbor);
    result
}

/// Decrypts a blob back into a structured payload.
pub fn open_payload(
    id: &Uuid,
    inner_kek: &Key,
    outer_kek: &Key,
    blob: &[u8],
) -> Result<SecretPayload, EnvelopeError> {
    let cbor = open_bytes(id, inner_kek, outer_kek, blob)?;
    let wire: PayloadWire = ciborium::from_reader(cbor.as_slice())
        .map_err(|e| EnvelopeError::Decode(e.to_string()))?;
    Ok(wire.into_payload())
}

/// Domain string bound as AAD when wrapping `inner_kek`. Distinct from any
/// secret's envelope so a wrap blob can never be mistaken for a payload.
const WRAP_AAD: &[u8] = b"sypherstore/v1/inner-kek-wrap";

/// Encrypts `inner_kek` under an authenticator's wrap key.
///
/// A single AEAD layer, not the double envelope: the wrap key is itself gated
/// on a YubiKey touch, and the machine binding is provided separately by the
/// TPM-sealed `outer_kek`, so wrapping here only needs to bind the plaintext to
/// this authenticator. One wrapped copy is stored per enrolled key, which is
/// what lets a backup YubiKey open the same vault.
pub fn wrap_key(wrap_key: &Key, inner_kek: &Key) -> Result<Vec<u8>, EnvelopeError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce)?;
    let cipher = XChaCha20Poly1305::new(wrap_key.as_bytes().into());
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: inner_kek.as_bytes(),
                aad: WRAP_AAD,
            },
        )
        .map_err(|_| EnvelopeError::Decrypt)?;

    let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Recovers `inner_kek` from a blob produced by [`wrap_key`].
///
/// A wrong wrap key (the wrong authenticator, or the right one against a
/// different vault) fails the AEAD tag and returns [`EnvelopeError::Decrypt`].
pub fn unwrap_key(wrap_key: &Key, blob: &[u8]) -> Result<Key, EnvelopeError> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(EnvelopeError::Truncated(blob.len()));
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(wrap_key.as_bytes().into());
    let mut plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload { msg: ct, aad: WRAP_AAD },
        )
        .map_err(|_| EnvelopeError::Decrypt)?;
    let key = Key::take_from(&mut plaintext)?;
    zeroize::Zeroize::zeroize(&mut plaintext);
    Ok(key)
}

/// Encrypts a secret's searchable metadata into a storable blob.
///
/// Sealed to `meta_id`, a random UUID distinct from the secret's own id, so the
/// metadata envelope and the payload envelope derive different subkeys and
/// neither can be opened in the other's place.
pub fn seal_meta(
    meta_id: &Uuid,
    inner_kek: &Key,
    outer_kek: &Key,
    meta: &SecretMeta,
) -> Result<Vec<u8>, EnvelopeError> {
    let wire = MetaWire::from_meta(meta);
    let mut cbor = Vec::new();
    ciborium::into_writer(&wire, &mut cbor)
        .map_err(|e| EnvelopeError::Encode(e.to_string()))?;
    seal_bytes(meta_id, inner_kek, outer_kek, &cbor)
}

/// Decrypts a metadata blob, reattaching the plaintext row `id`.
pub fn open_meta(
    meta_id: &Uuid,
    id: &Uuid,
    inner_kek: &Key,
    outer_kek: &Key,
    blob: &[u8],
) -> Result<SecretMeta, EnvelopeError> {
    let cbor = open_bytes(meta_id, inner_kek, outer_kek, blob)?;
    let wire: MetaWire = ciborium::from_reader(cbor.as_slice())
        .map_err(|e| EnvelopeError::Decode(e.to_string()))?;
    Ok(wire.into_meta(*id))
}

/// Builds the vault's verification blob. Stored in `meta` at init.
pub fn seal_verification(
    id: &Uuid,
    inner_kek: &Key,
    outer_kek: &Key,
) -> Result<Vec<u8>, EnvelopeError> {
    seal_bytes(id, inner_kek, outer_kek, VERIFICATION_PLAINTEXT)
}

/// Confirms both keys are correct by decrypting the verification blob.
///
/// A wrong key yields `Ok(false)` only when it decrypts to unexpected content,
/// which cannot happen against an AEAD; in practice a wrong key returns
/// `Err(Decrypt)`. Both are treated as "do not proceed" by callers.
pub fn verify_keys(
    id: &Uuid,
    inner_kek: &Key,
    outer_kek: &Key,
    blob: &[u8],
) -> Result<bool, EnvelopeError> {
    let plaintext = open_bytes(id, inner_kek, outer_kek, blob)?;
    Ok(plaintext.as_slice() == VERIFICATION_PLAINTEXT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (Key, Key) {
        (
            Key::from_slice(&[1u8; 32]).unwrap(),
            Key::from_slice(&[2u8; 32]).unwrap(),
        )
    }

    fn sample_payload() -> SecretPayload {
        SecretPayload {
            value: SecureBuf::copy_from("hunter2-ünïcode-🔐".as_bytes()),
            notes: Some(SecureBuf::copy_from(b"second factor in the drawer")),
            extra: vec![("totp".to_string(), SecureBuf::copy_from(b"JBSWY3DPEHPK3PXP"))],
        }
    }

    #[test]
    fn roundtrips_a_payload() {
        let (inner, outer) = keys();
        let id = Uuid::new_v4();
        let payload = sample_payload();

        let blob = seal_payload(&id, &inner, &outer, &payload).unwrap();
        let back = open_payload(&id, &inner, &outer, &blob).unwrap();

        assert_eq!(back, payload);
    }

    #[test]
    fn ciphertext_does_not_contain_the_plaintext() {
        let (inner, outer) = keys();
        let id = Uuid::new_v4();
        let payload = SecretPayload::new(SecureBuf::copy_from(b"needle-in-haystack"));
        let blob = seal_payload(&id, &inner, &outer, &payload).unwrap();

        assert!(
            !blob
                .windows(b"needle-in-haystack".len())
                .any(|w| w == b"needle-in-haystack"),
            "plaintext appears verbatim in the envelope"
        );
    }

    #[test]
    fn each_seal_uses_a_fresh_nonce() {
        let (inner, outer) = keys();
        let id = Uuid::new_v4();
        let payload = sample_payload();
        let a = seal_payload(&id, &inner, &outer, &payload).unwrap();
        let b = seal_payload(&id, &inner, &outer, &payload).unwrap();
        assert_ne!(a, b, "identical plaintext must not produce identical blobs");
        // The header is deterministic; everything after it must differ.
        assert_eq!(a[..HEADER_LEN], b[..HEADER_LEN]);
    }

    #[test]
    fn wrong_inner_key_fails() {
        let (inner, outer) = keys();
        let id = Uuid::new_v4();
        let blob = seal_payload(&id, &inner, &outer, &sample_payload()).unwrap();

        let bad_inner = Key::from_slice(&[9u8; 32]).unwrap();
        assert!(matches!(
            open_payload(&id, &bad_inner, &outer, &blob),
            Err(EnvelopeError::Decrypt)
        ));
    }

    #[test]
    fn wrong_outer_key_fails() {
        let (inner, outer) = keys();
        let id = Uuid::new_v4();
        let blob = seal_payload(&id, &inner, &outer, &sample_payload()).unwrap();

        let bad_outer = Key::from_slice(&[9u8; 32]).unwrap();
        assert!(matches!(
            open_payload(&id, &inner, &bad_outer, &blob),
            Err(EnvelopeError::Decrypt)
        ));
    }

    #[test]
    fn outer_key_alone_does_not_reveal_plaintext() {
        // The whole point of layering: peeling the outer layer must leave
        // ciphertext, not the secret.
        let (inner, outer) = keys();
        let id = Uuid::new_v4();
        let payload = SecretPayload::new(SecureBuf::copy_from(b"needle-in-haystack"));
        let blob = seal_payload(&id, &inner, &outer, &payload).unwrap();

        let k_outer = derive_secret_outer_key(&outer, &id).unwrap();
        let cipher = XChaCha20Poly1305::new(k_outer.as_bytes().into());
        let n2 = XNonce::from_slice(&blob[HEADER_LEN..HEADER_LEN + NONCE_LEN]);
        let peeled = cipher
            .decrypt(
                n2,
                Payload {
                    msg: &blob[HEADER_LEN + NONCE_LEN..],
                    aad: &blob[..HEADER_LEN],
                },
            )
            .expect("outer layer should open with the outer key");

        assert!(
            !peeled
                .windows(b"needle-in-haystack".len())
                .any(|w| w == b"needle-in-haystack"),
            "inner layer exposed after peeling the outer layer only"
        );
    }

    #[test]
    fn blob_cannot_be_swapped_between_secrets() {
        let (inner, outer) = keys();
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        let blob_a = seal_payload(&id_a, &inner, &outer, &sample_payload()).unwrap();

        // Reading A's blob as if it were B is rejected on the UUID check.
        match open_payload(&id_b, &inner, &outer, &blob_a) {
            Err(EnvelopeError::IdMismatch { expected, found }) => {
                assert_eq!(expected, id_b);
                assert_eq!(found, id_a);
            }
            other => panic!("expected IdMismatch, got {other:?}"),
        }
    }

    #[test]
    fn rewriting_the_uuid_in_the_header_fails_the_aad_check() {
        // A cleverer attacker rewrites the header's UUID to match the target
        // row, defeating the equality check. The AAD and subkey derivation
        // still catch it.
        let (inner, outer) = keys();
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        let mut blob = seal_payload(&id_a, &inner, &outer, &sample_payload()).unwrap();
        blob[6..22].copy_from_slice(id_b.as_bytes());

        assert!(matches!(
            open_payload(&id_b, &inner, &outer, &blob),
            Err(EnvelopeError::Decrypt)
        ));
    }

    #[test]
    fn flipping_a_ciphertext_bit_is_detected() {
        let (inner, outer) = keys();
        let id = Uuid::new_v4();
        let mut blob = seal_payload(&id, &inner, &outer, &sample_payload()).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;

        assert!(matches!(
            open_payload(&id, &inner, &outer, &blob),
            Err(EnvelopeError::Decrypt)
        ));
    }

    #[test]
    fn unknown_version_is_rejected() {
        let (inner, outer) = keys();
        let id = Uuid::new_v4();
        let mut blob = seal_payload(&id, &inner, &outer, &sample_payload()).unwrap();
        blob[4] = 99;

        assert!(matches!(
            open_payload(&id, &inner, &outer, &blob),
            Err(EnvelopeError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn unknown_cipher_is_rejected() {
        let (inner, outer) = keys();
        let id = Uuid::new_v4();
        let mut blob = seal_payload(&id, &inner, &outer, &sample_payload()).unwrap();
        blob[5] = 42;

        assert!(matches!(
            open_payload(&id, &inner, &outer, &blob),
            Err(EnvelopeError::UnsupportedCipher(42))
        ));
    }

    #[test]
    fn bad_magic_is_rejected() {
        let (inner, outer) = keys();
        let id = Uuid::new_v4();
        let mut blob = seal_payload(&id, &inner, &outer, &sample_payload()).unwrap();
        blob[0] = b'X';

        assert!(matches!(
            open_payload(&id, &inner, &outer, &blob),
            Err(EnvelopeError::BadMagic)
        ));
    }

    #[test]
    fn truncated_blobs_are_rejected_without_panicking() {
        let (inner, outer) = keys();
        let id = Uuid::new_v4();
        let blob = seal_payload(&id, &inner, &outer, &sample_payload()).unwrap();

        for len in 0..blob.len() {
            // Must never panic on a slice index, whatever the length.
            let _ = open_payload(&id, &inner, &outer, &blob[..len]);
        }
    }

    #[test]
    fn verification_blob_accepts_right_keys_and_rejects_wrong_ones() {
        let (inner, outer) = keys();
        let id = Uuid::new_v4();
        let blob = seal_verification(&id, &inner, &outer).unwrap();

        assert!(verify_keys(&id, &inner, &outer, &blob).unwrap());

        let bad_inner = Key::from_slice(&[0xEE; 32]).unwrap();
        assert!(verify_keys(&id, &bad_inner, &outer, &blob).is_err());
    }

    #[test]
    fn inner_key_wraps_and_unwraps() {
        let wrap = Key::from_slice(&[7u8; 32]).unwrap();
        let inner = Key::from_slice(&[0x5A; 32]).unwrap();
        let blob = wrap_key(&wrap, &inner).unwrap();

        assert_eq!(unwrap_key(&wrap, &blob).unwrap(), inner);
        // The wrapped inner key must not appear verbatim in the blob.
        assert!(!blob.windows(32).any(|w| w == inner.as_bytes()));
    }

    #[test]
    fn a_wrong_wrap_key_cannot_unwrap() {
        let wrap = Key::from_slice(&[7u8; 32]).unwrap();
        let inner = Key::from_slice(&[0x5A; 32]).unwrap();
        let blob = wrap_key(&wrap, &inner).unwrap();

        let wrong = Key::from_slice(&[8u8; 32]).unwrap();
        assert!(matches!(
            unwrap_key(&wrong, &blob),
            Err(EnvelopeError::Decrypt)
        ));
    }

    #[test]
    fn two_wrap_keys_yield_the_same_inner_key() {
        // The backup-key property: two enrolled authenticators hold two wrapped
        // copies that both recover the one inner key.
        let inner = Key::from_slice(&[0x5A; 32]).unwrap();
        let primary = Key::from_slice(&[1u8; 32]).unwrap();
        let backup = Key::from_slice(&[2u8; 32]).unwrap();

        let blob_a = wrap_key(&primary, &inner).unwrap();
        let blob_b = wrap_key(&backup, &inner).unwrap();

        assert_eq!(unwrap_key(&primary, &blob_a).unwrap(), inner);
        assert_eq!(unwrap_key(&backup, &blob_b).unwrap(), inner);
    }

    #[test]
    fn empty_and_large_payloads_roundtrip() {
        let (inner, outer) = keys();
        let id = Uuid::new_v4();

        let empty = SecretPayload::new(SecureBuf::copy_from(b""));
        let blob = seal_payload(&id, &inner, &outer, &empty).unwrap();
        assert_eq!(open_payload(&id, &inner, &outer, &blob).unwrap(), empty);

        // An SSH private key or certificate chain is comfortably in this range.
        let big = SecretPayload::new(SecureBuf::copy_from(&vec![b'k'; 64 * 1024]));
        let blob = seal_payload(&id, &inner, &outer, &big).unwrap();
        assert_eq!(open_payload(&id, &inner, &outer, &blob).unwrap(), big);
    }
}
