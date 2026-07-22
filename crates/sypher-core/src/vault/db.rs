//! SQLite-backed vault storage.
//!
//! The database is now a pure blob store. Every row holds two opaque sealed
//! envelopes and nothing else readable:
//!
//! - **`meta_blob`** seals the searchable metadata (name, domain, application,
//!   username, tags). It used to be plaintext columns; encrypting it is what
//!   makes an attacker with `vault.db` unable to learn which accounts you hold.
//! - **`payload_blob`** seals the secret value and notes.
//!
//! The database layer never decrypts; it stores and returns opaque bytes and
//! two plaintext UUIDs (the row id and the metadata envelope's id, both
//! random). Keeping the store ignorant of the crypto means no query path can
//! return plaintext, and the list can only be built by a caller that holds the
//! inner key.
//!
//! `secure_delete` is on so that overwritten and deleted rows do not linger in
//! free pages, which is what makes `strings vault.db` come up empty after a
//! delete.

use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use crate::vault::paths::{set_owner_only, VaultPaths};

/// Current schema version. Bumping this requires a matching arm in
/// [`Vault::migrate`].
///
/// v2 removed every plaintext metadata column in favour of a single sealed
/// `meta_blob`, and dropped the tag tables (tags now live inside that blob).
/// There is no in-place upgrade from v1: the metadata was never encrypted, so
/// a v1 vault must be re-initialized.
const SCHEMA_VERSION: i64 = 2;

/// Meta table key holding the per-vault KDF salt (hex).
pub const META_KDF_SALT: &str = "kdf_salt";
/// Meta table key holding the per-vault FIDO2 hmac salt (hex).
///
/// One salt for the whole vault, so a single assertion carrying every enrolled
/// credential in its allow-list resolves which key is present in one touch.
pub const META_HMAC_SALT: &str = "fido_hmac_salt";
/// Meta table key holding the CBOR list of enrolled authenticators (hex).
pub const META_ENROLLMENTS: &str = "fido_enrollments";
/// Meta table key holding the verification envelope (hex).
pub const META_VERIFY_BLOB: &str = "verify_blob";
/// Meta table key holding the UUID the verification envelope is bound to.
pub const META_VERIFY_ID: &str = "verify_id";

/// One stored row: the two plaintext UUIDs and the sealed metadata.
///
/// The payload blob is deliberately absent; it is fetched only for the single
/// secret a caller chooses to open, never for the whole list.
#[derive(Debug, Clone)]
pub struct SecretRow {
    pub id: Uuid,
    pub meta_id: Uuid,
    pub meta_blob: Vec<u8>,
}

pub struct Vault {
    conn: Connection,
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("no secret with id {0}")]
    NotFound(Uuid),
    #[error("vault is not initialized: {0} is missing")]
    NotInitialized(String),
    #[error(
        "this vault uses the old pre-encryption format, which cannot be upgraded \
         in place (its metadata was stored in the clear). Back up anything you \
         need, delete the vault directory, and run `sypherstore init` again."
    )]
    IncompatibleSchema,
    #[error("vault metadata key {0:?} is missing or malformed")]
    BadMeta(String),
    #[error("a secret named {0:?} already exists")]
    DuplicateName(String),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Path(#[from] crate::vault::paths::PathError),
}

impl Vault {
    /// Opens (creating if needed) the vault database and applies migrations.
    pub fn open(paths: &VaultPaths) -> Result<Self, VaultError> {
        paths.ensure_dirs()?;
        let db_path = paths.db();
        let conn = Connection::open(&db_path)?;

        // WAL survives a crash without losing committed writes and lets the
        // popup read while a background backup is running.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        // Overwrite deleted content rather than just unlinking it, so removed
        // secrets do not remain recoverable in free pages.
        conn.pragma_update(None, "secure_delete", "ON")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "FULL")?;

        let mut vault = Self { conn };
        vault.migrate()?;

        // The database is created by SQLite with the process umask, which may
        // be permissive; tighten it after the file exists.
        set_owner_only(&db_path)?;
        Ok(vault)
    }

    /// Opens an in-memory vault. Tests only.
    pub fn open_in_memory() -> Result<Self, VaultError> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let mut vault = Self { conn };
        vault.migrate()?;
        Ok(vault)
    }

    /// Brings the schema up to [`SCHEMA_VERSION`].
    fn migrate(&mut self) -> Result<(), VaultError> {
        let current: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap_or(0);

        if current >= SCHEMA_VERSION {
            return Ok(());
        }

        // Refuse to open a v1 (pre-encryption) database rather than silently
        // corrupting it. v1 held metadata in plaintext columns this schema has
        // dropped; `CREATE TABLE IF NOT EXISTS` would leave the old shape in
        // place and every later query would fail against missing columns.
        let has_secrets: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='secrets'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if has_secrets > 0
            && self.conn.prepare("SELECT meta_id FROM secrets LIMIT 0").is_err()
        {
            return Err(VaultError::IncompatibleSchema);
        }

        // v2 is the first encrypted-metadata schema. A v1 database predates
        // metadata encryption and cannot be upgraded in place (there is no key
        // available here to re-seal its plaintext columns), so a fresh vault is
        // created and the old one must be re-initialized.
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS secrets (
                id           TEXT PRIMARY KEY NOT NULL,
                meta_id      TEXT NOT NULL,
                meta_blob    BLOB NOT NULL,
                payload_blob BLOB NOT NULL
            );
            "#,
        )?;

        self.conn
            .pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(())
    }

    // ---- meta -----------------------------------------------------------

    /// Reads a value from the `meta` table.
    pub fn get_meta(&self, key: &str) -> Result<Option<String>, VaultError> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    /// Writes a value into the `meta` table, replacing any existing entry.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), VaultError> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Reads a hex-encoded binary value from `meta`.
    pub fn get_meta_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, VaultError> {
        match self.get_meta(key)? {
            None => Ok(None),
            Some(hex) => Ok(Some(
                decode_hex(&hex).ok_or_else(|| VaultError::BadMeta(key.to_string()))?,
            )),
        }
    }

    /// Writes a binary value into `meta` as hex.
    pub fn set_meta_bytes(&self, key: &str, value: &[u8]) -> Result<(), VaultError> {
        self.set_meta(key, &encode_hex(value))
    }

    /// Reads a required binary `meta` value, erroring when absent.
    pub fn require_meta_bytes(&self, key: &str) -> Result<Vec<u8>, VaultError> {
        self.get_meta_bytes(key)?
            .ok_or_else(|| VaultError::BadMeta(key.to_string()))
    }

    // ---- secrets --------------------------------------------------------

    /// Inserts a new secret from its two sealed envelopes.
    ///
    /// The database sees only opaque bytes and the two plaintext UUIDs; the
    /// caller ([`crate::vault::session::Session`]) does the sealing.
    pub fn insert_row(
        &mut self,
        id: &Uuid,
        meta_id: &Uuid,
        meta_blob: &[u8],
        payload_blob: &[u8],
    ) -> Result<(), VaultError> {
        self.conn.execute(
            "INSERT INTO secrets (id, meta_id, meta_blob, payload_blob)
             VALUES (?1, ?2, ?3, ?4)",
            params![id.to_string(), meta_id.to_string(), meta_blob, payload_blob],
        )?;
        Ok(())
    }

    /// Replaces an existing secret's sealed envelopes.
    pub fn update_row(
        &mut self,
        id: &Uuid,
        meta_id: &Uuid,
        meta_blob: &[u8],
        payload_blob: &[u8],
    ) -> Result<(), VaultError> {
        let changed = self.conn.execute(
            "UPDATE secrets SET meta_id = ?2, meta_blob = ?3, payload_blob = ?4
             WHERE id = ?1",
            params![id.to_string(), meta_id.to_string(), meta_blob, payload_blob],
        )?;
        if changed == 0 {
            return Err(VaultError::NotFound(*id));
        }
        Ok(())
    }

    /// Deletes a secret.
    pub fn delete(&mut self, id: &Uuid) -> Result<(), VaultError> {
        let changed = self
            .conn
            .execute("DELETE FROM secrets WHERE id = ?1", params![id.to_string()])?;
        if changed == 0 {
            return Err(VaultError::NotFound(*id));
        }
        Ok(())
    }

    /// Returns every row's sealed metadata for the caller to decrypt.
    ///
    /// Order is unspecified: the caller decrypts and sorts, because the sort
    /// key (`updated_at`) lives inside the sealed blob. The payload blobs are
    /// not read, so building the list never pulls megabytes of ciphertext.
    pub fn list_rows(&self) -> Result<Vec<SecretRow>, VaultError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, meta_id, meta_blob FROM secrets")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (id, meta_id, meta_blob) = row?;
            out.push(SecretRow {
                id: Uuid::parse_str(&id).unwrap_or_else(|_| Uuid::nil()),
                meta_id: Uuid::parse_str(&meta_id).unwrap_or_else(|_| Uuid::nil()),
                meta_blob,
            });
        }
        Ok(out)
    }

    /// Reads one row's sealed metadata.
    pub fn get_meta_row(&self, id: &Uuid) -> Result<SecretRow, VaultError> {
        self.conn
            .query_row(
                "SELECT id, meta_id, meta_blob FROM secrets WHERE id = ?1",
                params![id.to_string()],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?
            .map(|(id, meta_id, meta_blob)| SecretRow {
                id: Uuid::parse_str(&id).unwrap_or_else(|_| Uuid::nil()),
                meta_id: Uuid::parse_str(&meta_id).unwrap_or_else(|_| Uuid::nil()),
                meta_blob,
            })
            .ok_or(VaultError::NotFound(*id))
    }

    /// Reads one secret's sealed payload blob.
    ///
    /// Separate from metadata so that the payload ciphertext is only ever
    /// fetched for the single secret the user chose to use.
    pub fn get_blob(&self, id: &Uuid) -> Result<Vec<u8>, VaultError> {
        self.conn
            .query_row(
                "SELECT payload_blob FROM secrets WHERE id = ?1",
                params![id.to_string()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(VaultError::NotFound(*id))
    }

    /// Number of stored secrets. Needs no key, so callers can report a count
    /// without unlocking.
    pub fn count(&self) -> Result<i64, VaultError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM secrets", [], |r| r.get(0))?)
    }

    /// Runs `VACUUM`, which with `secure_delete` rewrites the file and drops
    /// any residual freed pages. Called after deletes.
    pub fn vacuum(&self) -> Result<(), VaultError> {
        self.conn.execute_batch("VACUUM")?;
        Ok(())
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Inserts a row with placeholder sealed bytes, returning its id.
    fn insert(v: &mut Vault, meta_blob: &[u8], payload_blob: &[u8]) -> (Uuid, Uuid) {
        let id = Uuid::new_v4();
        let meta_id = Uuid::new_v4();
        v.insert_row(&id, &meta_id, meta_blob, payload_blob).unwrap();
        (id, meta_id)
    }

    #[test]
    fn insert_and_read_back() {
        let mut v = Vault::open_in_memory().unwrap();
        let (id, meta_id) = insert(&mut v, b"sealed-meta", b"sealed-payload");

        let rows = v.list_rows().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, id);
        assert_eq!(rows[0].meta_id, meta_id);
        assert_eq!(rows[0].meta_blob, b"sealed-meta");
        assert_eq!(v.get_blob(&id).unwrap(), b"sealed-payload");
    }

    #[test]
    fn list_rows_never_reads_payload_blobs() {
        // The list path must not pull payload ciphertext; the struct has no
        // field for it, so this is a structural guarantee.
        let mut v = Vault::open_in_memory().unwrap();
        insert(&mut v, b"m", b"payload-should-not-appear");
        let rows = v.list_rows().unwrap();
        let rendered = format!("{rows:?}");
        assert!(!rendered.contains("payload-should-not-appear"));
    }

    #[test]
    fn update_replaces_both_blobs() {
        let mut v = Vault::open_in_memory().unwrap();
        let (id, _) = insert(&mut v, b"meta-1", b"payload-1");

        let new_meta_id = Uuid::new_v4();
        v.update_row(&id, &new_meta_id, b"meta-2", b"payload-2").unwrap();

        let row = v.get_meta_row(&id).unwrap();
        assert_eq!(row.meta_id, new_meta_id);
        assert_eq!(row.meta_blob, b"meta-2");
        assert_eq!(v.get_blob(&id).unwrap(), b"payload-2");
    }

    #[test]
    fn update_of_a_missing_secret_is_an_error() {
        let mut v = Vault::open_in_memory().unwrap();
        assert!(matches!(
            v.update_row(&Uuid::new_v4(), &Uuid::new_v4(), b"m", b"p"),
            Err(VaultError::NotFound(_))
        ));
    }

    #[test]
    fn delete_removes_the_secret() {
        let mut v = Vault::open_in_memory().unwrap();
        let (id, _) = insert(&mut v, b"m", b"p");

        v.delete(&id).unwrap();

        assert_eq!(v.count().unwrap(), 0);
        assert!(matches!(v.get_blob(&id), Err(VaultError::NotFound(_))));
    }

    #[test]
    fn delete_of_a_missing_secret_is_an_error() {
        let mut v = Vault::open_in_memory().unwrap();
        assert!(matches!(
            v.delete(&Uuid::new_v4()),
            Err(VaultError::NotFound(_))
        ));
    }

    #[test]
    fn meta_bytes_roundtrip_through_hex() {
        let v = Vault::open_in_memory().unwrap();
        let salt = [0xDEu8, 0xAD, 0xBE, 0xEF, 0x00, 0xFF];
        v.set_meta_bytes(META_KDF_SALT, &salt).unwrap();
        assert_eq!(v.get_meta_bytes(META_KDF_SALT).unwrap().unwrap(), salt);
    }

    #[test]
    fn malformed_meta_hex_is_reported_not_panicked() {
        let v = Vault::open_in_memory().unwrap();
        v.set_meta(META_KDF_SALT, "not-hex!").unwrap();
        assert!(matches!(
            v.get_meta_bytes(META_KDF_SALT),
            Err(VaultError::BadMeta(_))
        ));
    }

    #[test]
    fn missing_required_meta_is_an_error() {
        let v = Vault::open_in_memory().unwrap();
        assert!(matches!(
            v.require_meta_bytes(META_ENROLLMENTS),
            Err(VaultError::BadMeta(_))
        ));
    }

    #[test]
    fn setting_meta_twice_overwrites() {
        let v = Vault::open_in_memory().unwrap();
        v.set_meta("k", "first").unwrap();
        v.set_meta("k", "second").unwrap();
        assert_eq!(v.get_meta("k").unwrap().unwrap(), "second");
    }

    #[test]
    fn reopening_a_vault_preserves_contents_and_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = VaultPaths::at(tmp.path().join("vault"));

        let id = {
            let mut v = Vault::open(&paths).unwrap();
            let (id, _) = insert(&mut v, b"m", b"blob");
            v.set_meta("k", "v").unwrap();
            id
        };

        // Reopening must not re-run migrations destructively.
        let v = Vault::open(&paths).unwrap();
        assert_eq!(v.count().unwrap(), 1);
        assert_eq!(v.get_blob(&id).unwrap(), b"blob");
        assert_eq!(v.get_meta("k").unwrap().unwrap(), "v");
    }

    #[test]
    fn database_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let paths = VaultPaths::at(tmp.path().join("vault"));
        let _v = Vault::open(&paths).unwrap();
        let mode = std::fs::metadata(paths.db()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_v1_database_is_refused_rather_than_corrupted() {
        // Simulate a pre-encryption vault: a `secrets` table with the old
        // plaintext columns and user_version = 1. Opening it must error
        // clearly, not silently proceed against a mismatched schema.
        let tmp = tempfile::tempdir().unwrap();
        let paths = VaultPaths::at(tmp.path().join("vault"));
        paths.ensure_dirs().unwrap();
        {
            let conn = Connection::open(paths.db()).unwrap();
            conn.execute_batch(
                "CREATE TABLE secrets (id TEXT PRIMARY KEY, name TEXT, encrypted_blob BLOB);
                 CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
                 PRAGMA user_version = 1;",
            )
            .unwrap();
        }
        assert!(matches!(
            Vault::open(&paths),
            Err(VaultError::IncompatibleSchema)
        ));
    }

    #[test]
    fn get_meta_row_finds_one_secret() {
        let mut v = Vault::open_in_memory().unwrap();
        let (id, meta_id) = insert(&mut v, b"target-meta", b"p");
        let row = v.get_meta_row(&id).unwrap();
        assert_eq!(row.meta_id, meta_id);
        assert_eq!(row.meta_blob, b"target-meta");
        assert!(matches!(
            v.get_meta_row(&Uuid::new_v4()),
            Err(VaultError::NotFound(_))
        ));
    }
}
