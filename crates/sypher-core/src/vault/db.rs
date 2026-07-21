//! SQLite-backed vault storage.
//!
//! The database holds two very different kinds of data and treats them
//! differently:
//!
//! - **Metadata** (name, domain, application, username, tags) is stored in the
//!   clear. This is what makes the popup instant: the list can be rendered and
//!   searched with no inner key and therefore no touch. The tradeoff is
//!   explicit in the threat model, an attacker with the file learns which
//!   sites you have accounts on but not a single credential.
//! - **`encrypted_blob`** is the double-sealed envelope. The database layer
//!   never decrypts; it stores and returns opaque bytes. Keeping the store
//!   ignorant of the crypto means no query path can accidentally return
//!   plaintext.
//!
//! `secure_delete` is on so that overwritten and deleted rows do not linger in
//! free pages, which is what makes `strings vault.db` come up empty after a
//! delete.

use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use crate::model::{now_unix, SecretMeta, SecretType};
use crate::vault::paths::{set_owner_only, VaultPaths};

/// Current schema version. Bumping this requires a matching arm in
/// [`Vault::migrate`].
const SCHEMA_VERSION: i64 = 1;

/// Meta table key holding the per-vault KDF salt (hex).
pub const META_KDF_SALT: &str = "kdf_salt";
/// Meta table key holding the FIDO2 credential id (hex).
pub const META_CREDENTIAL_ID: &str = "fido_credential_id";
/// Meta table key holding the FIDO2 hmac salt (hex).
pub const META_HMAC_SALT: &str = "fido_hmac_salt";
/// Meta table key holding the verification envelope (hex).
pub const META_VERIFY_BLOB: &str = "verify_blob";
/// Meta table key holding the UUID the verification envelope is bound to.
pub const META_VERIFY_ID: &str = "verify_id";

pub struct Vault {
    conn: Connection,
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("no secret with id {0}")]
    NotFound(Uuid),
    #[error("vault is not initialized: {0} is missing")]
    NotInitialized(String),
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

        if current < 1 {
            self.conn.execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS meta (
                    key   TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS secrets (
                    id             TEXT PRIMARY KEY NOT NULL,
                    name           TEXT NOT NULL,
                    domain         TEXT NOT NULL DEFAULT '',
                    application    TEXT NOT NULL DEFAULT '',
                    type           TEXT NOT NULL,
                    username       TEXT NOT NULL DEFAULT '',
                    encrypted_blob BLOB NOT NULL,
                    created_at     INTEGER NOT NULL,
                    updated_at     INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS tags (
                    id   INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE
                );

                CREATE TABLE IF NOT EXISTS secret_tags (
                    secret_id TEXT NOT NULL
                        REFERENCES secrets(id) ON DELETE CASCADE,
                    tag_id    INTEGER NOT NULL
                        REFERENCES tags(id) ON DELETE CASCADE,
                    PRIMARY KEY (secret_id, tag_id)
                );

                CREATE INDEX IF NOT EXISTS idx_secrets_domain ON secrets(domain);
                CREATE INDEX IF NOT EXISTS idx_secrets_application ON secrets(application);
                CREATE INDEX IF NOT EXISTS idx_secret_tags_tag ON secret_tags(tag_id);
                "#,
            )?;
        }

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

    /// Inserts a new secret with its sealed blob.
    pub fn insert(&mut self, meta: &SecretMeta, blob: &[u8]) -> Result<(), VaultError> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO secrets
                (id, name, domain, application, type, username,
                 encrypted_blob, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                meta.id.to_string(),
                meta.name,
                meta.domain,
                meta.application,
                meta.secret_type.as_str(),
                meta.username,
                blob,
                meta.created_at,
                meta.updated_at,
            ],
        )?;
        set_tags(&tx, &meta.id, &meta.tags)?;
        tx.commit()?;
        Ok(())
    }

    /// Replaces a secret's metadata and blob, bumping `updated_at`.
    ///
    /// The blob is required rather than optional because any metadata edit
    /// that changes the UUID-bound envelope would invalidate it; callers
    /// re-seal after a fresh assertion, which is what `confirm_on_edit`
    /// enforces at the UI layer.
    pub fn update(&mut self, meta: &SecretMeta, blob: &[u8]) -> Result<(), VaultError> {
        let tx = self.conn.transaction()?;
        let changed = tx.execute(
            "UPDATE secrets SET
                name = ?2, domain = ?3, application = ?4, type = ?5,
                username = ?6, encrypted_blob = ?7, updated_at = ?8
             WHERE id = ?1",
            params![
                meta.id.to_string(),
                meta.name,
                meta.domain,
                meta.application,
                meta.secret_type.as_str(),
                meta.username,
                blob,
                now_unix(),
            ],
        )?;
        if changed == 0 {
            return Err(VaultError::NotFound(meta.id));
        }
        tx.execute(
            "DELETE FROM secret_tags WHERE secret_id = ?1",
            params![meta.id.to_string()],
        )?;
        set_tags(&tx, &meta.id, &meta.tags)?;
        tx.commit()?;
        Ok(())
    }

    /// Deletes a secret and its tag links.
    pub fn delete(&mut self, id: &Uuid) -> Result<(), VaultError> {
        let changed = self
            .conn
            .execute("DELETE FROM secrets WHERE id = ?1", params![id.to_string()])?;
        if changed == 0 {
            return Err(VaultError::NotFound(*id));
        }
        // Tag rows cascade, but a tag with no remaining secrets would keep
        // appearing in the tag filter, so prune orphans.
        self.conn.execute(
            "DELETE FROM tags WHERE id NOT IN (SELECT tag_id FROM secret_tags)",
            [],
        )?;
        Ok(())
    }

    /// Returns every secret's metadata, newest-updated first.
    ///
    /// This is the popup's data source. It deliberately does not read
    /// `encrypted_blob`: loading megabytes of ciphertext to render a list
    /// would be wasteful, and not having it in hand makes it impossible to
    /// decrypt something the user did not select.
    pub fn list_meta(&self) -> Result<Vec<SecretMeta>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, domain, application, type, username, created_at, updated_at
             FROM secrets ORDER BY updated_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            let id_str: String = r.get(0)?;
            Ok(SecretMeta {
                id: Uuid::parse_str(&id_str).unwrap_or_else(|_| Uuid::nil()),
                name: r.get(1)?,
                domain: r.get(2)?,
                application: r.get(3)?,
                secret_type: SecretType::from_str_lenient(&r.get::<_, String>(4)?),
                username: r.get(5)?,
                tags: Vec::new(),
                created_at: r.get(6)?,
                updated_at: r.get(7)?,
            })
        })?;

        let mut out: Vec<SecretMeta> = rows.collect::<Result<_, _>>()?;
        self.attach_tags(&mut out)?;
        Ok(out)
    }

    /// Reads one secret's metadata.
    pub fn get_meta_for(&self, id: &Uuid) -> Result<SecretMeta, VaultError> {
        self.list_meta()?
            .into_iter()
            .find(|m| m.id == *id)
            .ok_or(VaultError::NotFound(*id))
    }

    /// Reads one secret's sealed blob.
    ///
    /// Separate from metadata so that ciphertext is only ever fetched for the
    /// single secret the user chose to use.
    pub fn get_blob(&self, id: &Uuid) -> Result<Vec<u8>, VaultError> {
        self.conn
            .query_row(
                "SELECT encrypted_blob FROM secrets WHERE id = ?1",
                params![id.to_string()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(VaultError::NotFound(*id))
    }

    /// Number of stored secrets.
    pub fn count(&self) -> Result<i64, VaultError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM secrets", [], |r| r.get(0))?)
    }

    /// Every tag in use, alphabetically.
    pub fn all_tags(&self) -> Result<Vec<String>, VaultError> {
        let mut stmt = self.conn.prepare("SELECT name FROM tags ORDER BY name")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Fills in the `tags` field on each metadata record.
    ///
    /// Done as one query over all secrets rather than one per secret, since
    /// the popup loads the full list on every hotkey press.
    fn attach_tags(&self, metas: &mut [SecretMeta]) -> Result<(), VaultError> {
        if metas.is_empty() {
            return Ok(());
        }
        let mut stmt = self.conn.prepare(
            "SELECT st.secret_id, t.name
             FROM secret_tags st JOIN tags t ON t.id = st.tag_id
             ORDER BY t.name",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;

        let mut by_id: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for row in rows {
            let (secret_id, tag) = row?;
            by_id.entry(secret_id).or_default().push(tag);
        }
        for m in metas.iter_mut() {
            if let Some(tags) = by_id.remove(&m.id.to_string()) {
                m.tags = tags;
            }
        }
        Ok(())
    }

    /// Runs `VACUUM`, which with `secure_delete` rewrites the file and drops
    /// any residual freed pages. Called after bulk deletes.
    pub fn vacuum(&self) -> Result<(), VaultError> {
        self.conn.execute_batch("VACUUM")?;
        Ok(())
    }
}

/// Interns tag names and links them to a secret.
fn set_tags(tx: &rusqlite::Transaction<'_>, id: &Uuid, tags: &[String]) -> Result<(), VaultError> {
    for tag in tags {
        let tag = tag.trim();
        if tag.is_empty() {
            continue;
        }
        tx.execute(
            "INSERT INTO tags (name) VALUES (?1) ON CONFLICT(name) DO NOTHING",
            params![tag],
        )?;
        let tag_id: i64 = tx.query_row(
            "SELECT id FROM tags WHERE name = ?1",
            params![tag],
            |r| r.get(0),
        )?;
        tx.execute(
            "INSERT INTO secret_tags (secret_id, tag_id) VALUES (?1, ?2)
             ON CONFLICT DO NOTHING",
            params![id.to_string(), tag_id],
        )?;
    }
    Ok(())
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

    fn meta(name: &str) -> SecretMeta {
        SecretMeta::new(name, SecretType::Password)
    }

    #[test]
    fn insert_and_read_back() {
        let mut v = Vault::open_in_memory().unwrap();
        let mut m = meta("GitHub");
        m.domain = "github.com".into();
        m.username = "octocat".into();

        v.insert(&m, b"sealed-bytes").unwrap();

        let all = v.list_meta().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "GitHub");
        assert_eq!(all[0].domain, "github.com");
        assert_eq!(all[0].id, m.id);
        assert_eq!(v.get_blob(&m.id).unwrap(), b"sealed-bytes");
    }

    #[test]
    fn list_meta_does_not_expose_blobs() {
        // Structural guarantee: SecretMeta has no field that could hold one.
        let mut v = Vault::open_in_memory().unwrap();
        let m = meta("Thing");
        v.insert(&m, b"sealed").unwrap();
        let all = v.list_meta().unwrap();
        assert_eq!(all.len(), 1);
        let rendered = format!("{:?}", all[0]);
        assert!(!rendered.contains("sealed"));
    }

    #[test]
    fn update_replaces_metadata_blob_and_tags() {
        let mut v = Vault::open_in_memory().unwrap();
        let mut m = meta("Old");
        m.tags = vec!["work".into(), "temp".into()];
        v.insert(&m, b"blob-1").unwrap();

        m.name = "New".into();
        m.tags = vec!["work".into()];
        v.update(&m, b"blob-2").unwrap();

        let all = v.list_meta().unwrap();
        assert_eq!(all[0].name, "New");
        assert_eq!(all[0].tags, vec!["work"]);
        assert_eq!(v.get_blob(&m.id).unwrap(), b"blob-2");
    }

    #[test]
    fn update_of_a_missing_secret_is_an_error() {
        let mut v = Vault::open_in_memory().unwrap();
        assert!(matches!(
            v.update(&meta("ghost"), b"blob"),
            Err(VaultError::NotFound(_))
        ));
    }

    #[test]
    fn delete_removes_the_secret_and_its_tag_links() {
        let mut v = Vault::open_in_memory().unwrap();
        let mut m = meta("Temp");
        m.tags = vec!["throwaway".into()];
        v.insert(&m, b"blob").unwrap();

        v.delete(&m.id).unwrap();

        assert_eq!(v.count().unwrap(), 0);
        assert!(matches!(v.get_blob(&m.id), Err(VaultError::NotFound(_))));
        assert!(
            v.all_tags().unwrap().is_empty(),
            "orphaned tag should be pruned"
        );
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
    fn tags_are_shared_between_secrets_not_duplicated() {
        let mut v = Vault::open_in_memory().unwrap();
        let mut a = meta("A");
        a.tags = vec!["work".into()];
        let mut b = meta("B");
        b.tags = vec!["work".into(), "cloud".into()];
        v.insert(&a, b"x").unwrap();
        v.insert(&b, b"y").unwrap();

        assert_eq!(v.all_tags().unwrap(), vec!["cloud", "work"]);

        // Deleting one secret must not remove a tag the other still uses.
        v.delete(&a.id).unwrap();
        assert_eq!(v.all_tags().unwrap(), vec!["cloud", "work"]);
    }

    #[test]
    fn blank_tags_are_ignored() {
        let mut v = Vault::open_in_memory().unwrap();
        let mut m = meta("A");
        m.tags = vec!["  ".into(), "".into(), " work ".into()];
        v.insert(&m, b"x").unwrap();
        assert_eq!(v.all_tags().unwrap(), vec!["work"]);
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
            v.require_meta_bytes(META_CREDENTIAL_ID),
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

        let m = {
            let mut v = Vault::open(&paths).unwrap();
            let m = meta("Persisted");
            v.insert(&m, b"blob").unwrap();
            v.set_meta("k", "v").unwrap();
            m
        };

        // Reopening must not re-run migrations destructively.
        let v = Vault::open(&paths).unwrap();
        assert_eq!(v.count().unwrap(), 1);
        assert_eq!(v.get_blob(&m.id).unwrap(), b"blob");
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
    fn list_is_ordered_by_recency() {
        let mut v = Vault::open_in_memory().unwrap();
        let mut older = meta("Older");
        older.updated_at = 1_000;
        let mut newer = meta("Newer");
        newer.updated_at = 2_000;
        v.insert(&older, b"a").unwrap();
        v.insert(&newer, b"b").unwrap();

        let all = v.list_meta().unwrap();
        assert_eq!(all[0].name, "Newer");
        assert_eq!(all[1].name, "Older");
    }

    #[test]
    fn get_meta_for_finds_one_secret() {
        let mut v = Vault::open_in_memory().unwrap();
        let m = meta("Target");
        v.insert(&m, b"x").unwrap();
        assert_eq!(v.get_meta_for(&m.id).unwrap().name, "Target");
        assert!(matches!(
            v.get_meta_for(&Uuid::new_v4()),
            Err(VaultError::NotFound(_))
        ));
    }
}
