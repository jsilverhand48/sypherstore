//! The recovery key: exporting and re-sealing the machine-bound outer key.
//!
//! ## What this is for
//!
//! Without it, the TPM binding is absolute: if the TPM is cleared, the
//! motherboard replaced, or the machine lost, every secret is gone forever.
//! That is a real and permanent failure mode, and for most people it is a
//! worse risk than the one the binding defends against.
//!
//! The recovery key is the outer KEK, written down. Given it, a *new* machine
//! can re-seal the same key to its own TPM and open an existing vault.
//!
//! ## What it does and does not give away
//!
//! The outer key **cannot decrypt anything by itself.** Every secret is sealed
//! twice; this key strips only the outer, machine-bound layer. Reading a
//! secret still requires a FIDO2 assertion from the registered authenticator.
//!
//! So exporting it moves the vault from "this machine **and** this YubiKey" to
//! "this YubiKey", for anyone holding the paper. That is a genuine reduction
//! in protection and the user must make it deliberately, but it is not a
//! master key and it does not open the vault on its own.
//!
//! Anyone who holds *both* the recovery key and the YubiKey can read the vault
//! on any machine. Store them apart.
//!
//! ## Format
//!
//! ```text
//!   SYPH1-XXXXXXXX-XXXXXXXX-...-CCCCCCCC
//! ```
//!
//! Base32 (Crockford, so `0`/`O` and `1`/`I`/`L` cannot be confused), grouped
//! in eights, with a 4-byte truncated SHA-256 checksum. The checksum is the
//! point: a key transcribed by hand from paper is going to be mistyped
//! eventually, and without it the mistake would surface as an unopenable
//! vault rather than "that key is wrong, check it".

use sha2::{Digest, Sha256};

use crate::crypto::keys::{Key, KeyError, KEY_LEN};

/// Prefix identifying the format and version.
const PREFIX: &str = "SYPH1";

/// Crockford base32: no `I`, `L`, `O` or `U`, so the characters most often
/// confused on paper are simply absent from the alphabet.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Bytes of SHA-256 kept as the checksum.
const CHECKSUM_LEN: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("not a Sypherstore recovery key (expected it to start with {PREFIX})")]
    BadPrefix,
    #[error("the recovery key contains the invalid character {0:?}")]
    BadCharacter(char),
    #[error("the recovery key is the wrong length: expected {expected} characters, got {got}")]
    BadLength { expected: usize, got: usize },
    #[error(
        "the recovery key's checksum does not match. It was probably mistyped: \
         check for transposed characters."
    )]
    BadChecksum,
    #[error(transparent)]
    Key(#[from] KeyError),
}

/// Renders a key as a transcribable recovery string.
pub fn encode(key: &Key) -> String {
    let mut payload = key.as_bytes().to_vec();
    payload.extend_from_slice(&checksum(key.as_bytes()));

    let encoded = base32_encode(&payload);
    let groups: Vec<String> = encoded
        .as_bytes()
        .chunks(8)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect();

    format!("{PREFIX}-{}", groups.join("-"))
}

/// Parses a recovery string back into a key, verifying the checksum.
///
/// Tolerant of the ways a human will retype it: any case, any grouping, spaces
/// instead of dashes. Strictness here would only punish correct transcription.
pub fn decode(input: &str) -> Result<Key, RecoveryError> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    let upper = cleaned.to_ascii_uppercase();

    let body = upper
        .strip_prefix(PREFIX)
        .ok_or(RecoveryError::BadPrefix)?;

    let expected_chars = base32_len(KEY_LEN + CHECKSUM_LEN);
    if body.len() != expected_chars {
        return Err(RecoveryError::BadLength {
            expected: expected_chars,
            got: body.len(),
        });
    }

    let mut decoded = base32_decode(body)?;
    if decoded.len() < KEY_LEN + CHECKSUM_LEN {
        return Err(RecoveryError::BadLength {
            expected: expected_chars,
            got: body.len(),
        });
    }
    decoded.truncate(KEY_LEN + CHECKSUM_LEN);

    let (key_bytes, provided) = decoded.split_at(KEY_LEN);
    if checksum(key_bytes) != provided[..CHECKSUM_LEN] {
        // Wipe before returning: a near-miss still contains 32 bytes that are
        // one transposition away from the real key.
        zeroize::Zeroize::zeroize(&mut decoded);
        return Err(RecoveryError::BadChecksum);
    }

    let key = Key::from_slice(key_bytes)?;
    zeroize::Zeroize::zeroize(&mut decoded);
    Ok(key)
}

fn checksum(bytes: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut hasher = Sha256::new();
    // Domain-separated so this hash cannot be confused with any other in the
    // system.
    hasher.update(b"sypherstore/v1/recovery-checksum");
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&digest[..CHECKSUM_LEN]);
    out
}

/// Number of base32 characters needed for `n` bytes.
fn base32_len(n: usize) -> usize {
    n.div_ceil(5) * 8
}

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(base32_len(data.len()));
    for chunk in data.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);

        let bits = u64::from(buf[0]) << 32
            | u64::from(buf[1]) << 24
            | u64::from(buf[2]) << 16
            | u64::from(buf[3]) << 8
            | u64::from(buf[4]);

        for i in 0..8 {
            let index = ((bits >> (35 - i * 5)) & 0x1f) as usize;
            out.push(ALPHABET[index] as char);
        }
    }
    out
}

fn base32_decode(text: &str) -> Result<Vec<u8>, RecoveryError> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);

    for chunk in text.as_bytes().chunks(8) {
        let mut bits: u64 = 0;
        for i in 0..8 {
            let c = chunk.get(i).copied().unwrap_or(b'0');
            let value = ALPHABET
                .iter()
                .position(|a| *a == c)
                .ok_or(RecoveryError::BadCharacter(c as char))?;
            bits |= (value as u64) << (35 - i * 5);
        }
        out.push((bits >> 32) as u8);
        out.push((bits >> 24) as u8);
        out.push((bits >> 16) as u8);
        out.push((bits >> 8) as u8);
        out.push(bits as u8);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> Key {
        Key::from_slice(&[byte; KEY_LEN]).unwrap()
    }

    #[test]
    fn a_key_roundtrips() {
        let original = Key::generate().unwrap();
        let text = encode(&original);
        assert_eq!(decode(&text).unwrap(), original);
    }

    #[test]
    fn the_rendering_is_transcribable() {
        let text = encode(&key(0x42));
        assert!(text.starts_with("SYPH1-"));
        // Grouped so a human can keep their place on a written line.
        assert!(text.contains('-'));
        // Crockford omits the characters most often misread on paper.
        for forbidden in ['I', 'L', 'O', 'U'] {
            assert!(
                !text[PREFIX.len()..].contains(forbidden),
                "{forbidden} is ambiguous in handwriting"
            );
        }
    }

    #[test]
    fn transcription_variations_all_parse() {
        let original = Key::generate().unwrap();
        let canonical = encode(&original);

        let lowercase = canonical.to_ascii_lowercase();
        let spaces = canonical.replace('-', " ");
        let squashed = canonical.replace('-', "");

        for variant in [lowercase, spaces, squashed] {
            assert_eq!(
                decode(&variant).unwrap(),
                original,
                "a human retyping it must not be punished for formatting"
            );
        }
    }

    #[test]
    fn a_single_wrong_character_is_caught() {
        // The whole reason for the checksum: without it this would silently
        // produce a wrong key and an unopenable vault.
        let text = encode(&key(0x11));
        let mut chars: Vec<char> = text.chars().collect();

        // Change a payload character, not the prefix.
        let pos = text.len() - 12;
        chars[pos] = if chars[pos] == '7' { '9' } else { '7' };
        let corrupted: String = chars.into_iter().collect();

        assert!(matches!(
            decode(&corrupted),
            Err(RecoveryError::BadChecksum)
        ));
    }

    #[test]
    fn transposed_characters_are_caught() {
        let text = encode(&Key::generate().unwrap());
        let mut chars: Vec<char> = text.chars().collect();

        // Swap two *adjacent payload* characters that differ. Group
        // separators are stripped before decoding, so swapping one of those
        // would be a no-op and the test would pass without proving anything.
        let start = PREFIX.len();
        let pair = (start..chars.len() - 1).find(|&i| {
            chars[i] != '-' && chars[i + 1] != '-' && chars[i] != chars[i + 1]
        });
        let i = pair.expect("a 58-character key must contain two differing neighbours");

        chars.swap(i, i + 1);
        let swapped: String = chars.into_iter().collect();
        assert_ne!(swapped, text, "the swap must actually change the string");
        assert!(matches!(decode(&swapped), Err(RecoveryError::BadChecksum)));
    }

    #[test]
    fn a_missing_prefix_is_reported_clearly() {
        let text = encode(&key(1));
        let without = text.trim_start_matches("SYPH1-").to_string();
        assert!(matches!(decode(&without), Err(RecoveryError::BadPrefix)));
    }

    #[test]
    fn a_truncated_key_is_reported_as_a_length_problem() {
        let text = encode(&key(2));
        let short = &text[..text.len() - 6];
        assert!(matches!(
            decode(short),
            Err(RecoveryError::BadLength { .. })
        ));
    }

    #[test]
    fn an_invalid_character_names_itself() {
        let text = encode(&key(4));
        // `U` is not in the Crockford alphabet.
        let bad = format!("{}U", &text[..text.len() - 1]);
        match decode(&bad) {
            Err(RecoveryError::BadCharacter(c)) => assert_eq!(c, 'U'),
            other => panic!("expected BadCharacter, got {other:?}"),
        }
    }

    #[test]
    fn different_keys_produce_different_strings() {
        assert_ne!(encode(&key(1)), encode(&key(2)));
    }

    #[test]
    fn garbage_input_does_not_panic() {
        for input in ["", "SYPH1", "SYPH1-", "not a key at all", "SYPH1-!!!!"] {
            let _ = decode(input);
        }
    }
}
