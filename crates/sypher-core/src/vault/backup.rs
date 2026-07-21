//! Encrypted vault backups.
//!
//! ## What a backup protects against, and what it does not
//!
//! A backup here guards against *your own mistakes*: a secret deleted by
//! accident, a botched edit, a corrupted database. It restores onto the same
//! machine.
//!
//! It is **not** disaster recovery. The archive is encrypted under a key
//! derived from the TPM-sealed outer key, so a backup is exactly as
//! machine-bound as the vault it came from. If the TPM is cleared, the
//! motherboard is replaced, or the machine is lost, the backup is as
//! unreadable as the original.
//!
//! That is not an oversight. The alternative, a passphrase-encrypted archive,
//! would create a second and far weaker way into the vault: everything the
//! TPM and the YubiKey exist to prevent could be bypassed by guessing one
//! password. A design that requires two hardware factors cannot also offer a
//! knowledge-only escape hatch and still mean anything.
//!
//! The consequence must be stated plainly to users: **if you lose this machine
//! or your YubiKey, your secrets are gone.** Keep independent copies of
//! anything you cannot afford to lose.
//!
//! ## Why the whole database is encrypted
//!
//! Secrets in `vault.db` are already sealed, but the metadata (which sites you
//! have accounts on, which usernames) is stored in the clear so the popup can
//! search without a touch. A backup is likely to end up somewhere less
//! protected than the vault directory, so the archive encrypts everything.

use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::keys::{Key, KeyError, KEY_LEN};
use crate::vault::paths::{write_private_atomic, PathError, VaultPaths};

/// Magic and version for the archive format.
const MAGIC: &[u8; 8] = b"SYPHBAK1";
const NONCE_LEN: usize = 24;

/// HKDF info separating the backup key from every other use of the outer KEK.
const INFO_BACKUP: &[u8] = b"sypherstore/v1/backup";

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("not a Sypherstore backup archive")]
    BadMagic,
    #[error("the backup is truncated")]
    Truncated,
    #[error("could not decrypt the backup: wrong machine, or the file is damaged")]
    Decrypt,
    #[error("no vault database to back up at {0}")]
    NoVault(String),
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    Path(#[from] PathError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Derives the archive key from the vault's outer key.
///
/// A distinct HKDF label means a backup key can never be confused with a
/// secret's subkey, even though both descend from the same root.
fn backup_key(outer_kek: &Key) -> Result<Key, BackupError> {
    let hk = Hkdf::<Sha256>::from_prk(outer_kek.as_bytes()).map_err(|_| KeyError::Hkdf)?;
    let mut out = vec![0u8; KEY_LEN];
    hk.expand(INFO_BACKUP, &mut out).map_err(|_| KeyError::Hkdf)?;
    let key = Key::take_from(&mut out)?;
    Ok(key)
}

/// Writes an encrypted snapshot of the vault database.
///
/// Returns the archive path. The name carries a UTC timestamp so backups sort
/// chronologically and never collide.
pub fn create(paths: &VaultPaths, outer_kek: &Key) -> Result<PathBuf, BackupError> {
    let db = paths.db();
    if !db.exists() {
        return Err(BackupError::NoVault(db.display().to_string()));
    }

    // Read through SQLite's own backup API rather than copying the file?
    // Not necessary: WAL mode plus a read of the main database yields a
    // consistent image as long as we also carry the WAL, and the simpler
    // approach here is to checkpoint first so the WAL is empty.
    checkpoint(paths)?;
    let plaintext = std::fs::read(&db)?;

    let key = backup_key(outer_kek)?;
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(KeyError::from)?;

    let mut header = Vec::with_capacity(MAGIC.len() + NONCE_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                // The header is authenticated so the magic and nonce cannot be
                // altered without detection.
                aad: MAGIC,
            },
        )
        .map_err(|_| BackupError::Decrypt)?;

    let mut archive = header;
    archive.extend_from_slice(&ciphertext);

    std::fs::create_dir_all(paths.backups())?;
    let path = paths.backups().join(format!("vault-{}.syphbak", timestamp()));
    write_private_atomic(&path, &archive)?;

    tracing::info!(
        path = %path.display(),
        bytes = archive.len(),
        "backup written"
    );
    Ok(path)
}

/// Decrypts an archive and returns the database bytes.
///
/// Deliberately returns the bytes rather than writing them: overwriting a live
/// vault is a decision the caller should make explicitly.
pub fn restore(archive: &Path, outer_kek: &Key) -> Result<Vec<u8>, BackupError> {
    let raw = std::fs::read(archive)?;
    if raw.len() < MAGIC.len() + NONCE_LEN {
        return Err(BackupError::Truncated);
    }
    if &raw[..MAGIC.len()] != MAGIC {
        return Err(BackupError::BadMagic);
    }

    let nonce = &raw[MAGIC.len()..MAGIC.len() + NONCE_LEN];
    let ciphertext = &raw[MAGIC.len() + NONCE_LEN..];

    let key = backup_key(outer_kek)?;
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: MAGIC,
            },
        )
        .map_err(|_| BackupError::Decrypt)
}

/// Lists archives, newest first.
pub fn list(paths: &VaultPaths) -> Result<Vec<PathBuf>, BackupError> {
    let dir = paths.backups();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut found: Vec<PathBuf> = std::fs::read_dir(&dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "syphbak"))
        .collect();
    // Filenames embed a sortable timestamp, so lexical order is chronological.
    found.sort();
    found.reverse();
    Ok(found)
}

/// Deletes all but the newest `keep` archives.
pub fn prune(paths: &VaultPaths, keep: usize) -> Result<usize, BackupError> {
    let archives = list(paths)?;
    let mut removed = 0;
    for old in archives.into_iter().skip(keep) {
        if std::fs::remove_file(&old).is_ok() {
            tracing::debug!(path = %old.display(), "pruned an old backup");
            removed += 1;
        }
    }
    Ok(removed)
}

/// Folds the write-ahead log back into the main database file.
///
/// Without this a backup taken during active use could miss recent writes that
/// still live only in `vault.db-wal`.
fn checkpoint(paths: &VaultPaths) -> Result<(), BackupError> {
    if let Ok(conn) = rusqlite::Connection::open(paths.db()) {
        let _ = conn.pragma_update(None, "wal_checkpoint", "TRUNCATE");
    }
    Ok(())
}

/// UTC timestamp as `YYYYMMDD-HHMMSS`, for sortable filenames.
fn timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Civil-date conversion from a Unix timestamp, so no date crate is needed
    // for the one place a human-readable stamp is wanted.
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}-{:02}{:02}{:02}",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Howard Hinnant's `civil_from_days`, the standard branch-free conversion.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::db::Vault;

    fn fixture() -> (tempfile::TempDir, VaultPaths, Key) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = VaultPaths::at(tmp.path().join("vault"));
        paths.ensure_dirs().unwrap();
        let vault = Vault::open(&paths).unwrap();
        vault.set_meta("marker", "hello").unwrap();
        drop(vault);
        (tmp, paths, Key::from_slice(&[9u8; KEY_LEN]).unwrap())
    }

    #[test]
    fn a_backup_roundtrips() {
        let (_tmp, paths, key) = fixture();
        let archive = create(&paths, &key).unwrap();
        let restored = restore(&archive, &key).unwrap();

        let original = std::fs::read(paths.db()).unwrap();
        assert_eq!(restored, original);
    }

    #[test]
    fn the_archive_does_not_expose_metadata() {
        // Cleartext metadata is the reason the whole file is encrypted.
        let (_tmp, paths, key) = fixture();
        let archive = create(&paths, &key).unwrap();
        let raw = std::fs::read(&archive).unwrap();

        assert!(
            !raw.windows(5).any(|w| w == b"hello"),
            "metadata leaked into the backup"
        );
        assert!(raw.starts_with(MAGIC));
    }

    #[test]
    fn another_machines_key_cannot_read_it() {
        let (_tmp, paths, key) = fixture();
        let archive = create(&paths, &key).unwrap();

        let other = Key::from_slice(&[1u8; KEY_LEN]).unwrap();
        assert!(matches!(
            restore(&archive, &other),
            Err(BackupError::Decrypt)
        ));
    }

    #[test]
    fn a_tampered_archive_is_rejected() {
        let (_tmp, paths, key) = fixture();
        let archive = create(&paths, &key).unwrap();

        let mut raw = std::fs::read(&archive).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        std::fs::write(&archive, &raw).unwrap();

        assert!(matches!(restore(&archive, &key), Err(BackupError::Decrypt)));
    }

    #[test]
    fn a_foreign_file_is_rejected_on_magic() {
        let (_tmp, paths, key) = fixture();
        let bogus = paths.backups().join("bogus.syphbak");
        std::fs::write(&bogus, vec![0u8; 128]).unwrap();
        assert!(matches!(restore(&bogus, &key), Err(BackupError::BadMagic)));
    }

    #[test]
    fn truncated_archives_do_not_panic() {
        let (_tmp, paths, key) = fixture();
        let archive = create(&paths, &key).unwrap();
        let raw = std::fs::read(&archive).unwrap();

        for len in 0..raw.len().min(64) {
            let partial = paths.backups().join("partial.syphbak");
            std::fs::write(&partial, &raw[..len]).unwrap();
            let _ = restore(&partial, &key);
        }
    }

    #[test]
    fn pruning_keeps_the_newest() {
        let (_tmp, paths, key) = fixture();
        for i in 0..5 {
            // Distinct names, since the timestamp has one-second resolution.
            let path = paths.backups().join(format!("vault-2020010{i}-000000.syphbak"));
            let archive = create(&paths, &key).unwrap();
            std::fs::rename(archive, path).unwrap();
        }
        assert_eq!(list(&paths).unwrap().len(), 5);

        let removed = prune(&paths, 2).unwrap();
        assert_eq!(removed, 3);

        let left = list(&paths).unwrap();
        assert_eq!(left.len(), 2);
        // Newest first, so the survivors are the highest-numbered.
        assert!(left[0].to_string_lossy().contains("20200104"));
    }

    #[test]
    fn listing_an_empty_directory_is_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = VaultPaths::at(tmp.path().join("absent"));
        assert!(list(&paths).unwrap().is_empty());
    }

    #[test]
    fn backing_up_a_missing_vault_is_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = VaultPaths::at(tmp.path().join("vault"));
        paths.ensure_dirs().unwrap();
        let key = Key::from_slice(&[3u8; KEY_LEN]).unwrap();
        assert!(matches!(create(&paths, &key), Err(BackupError::NoVault(_))));
    }

    #[test]
    fn timestamps_are_sortable_and_correct() {
        // 2021-01-01T00:00:00Z
        assert_eq!(civil_from_days(1_609_459_200 / 86_400), (2021, 1, 1));
        // A leap day, which a naive conversion gets wrong.
        assert_eq!(civil_from_days(1_582_934_400 / 86_400), (2020, 2, 29));
        assert_eq!(civil_from_days(0), (1970, 1, 1));

        let stamp = timestamp();
        assert_eq!(stamp.len(), 15, "YYYYMMDD-HHMMSS");
        assert!(stamp.chars().nth(8) == Some('-'));
    }
}
