//! Where the vault lives on disk.
//!
//! Resolution order is `--vault-dir` argument, then `SYPHERSTORE_VAULT`, then
//! the XDG default. The override exists so tests and development runs can use
//! a throwaway vault without any chance of touching the real one; every entry
//! point threads it through rather than reading the default directly.

use std::path::{Path, PathBuf};

/// Environment variable that overrides the vault location.
pub const ENV_VAULT_DIR: &str = "SYPHERSTORE_VAULT";

/// The set of paths that make up a vault directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPaths {
    pub root: PathBuf,
}

impl VaultPaths {
    /// Uses `dir` verbatim as the vault root.
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self { root: dir.into() }
    }

    /// Resolves the vault root from an explicit override, the environment, or
    /// the XDG data directory, in that order.
    pub fn resolve(explicit: Option<&Path>) -> Result<Self, PathError> {
        if let Some(dir) = explicit {
            return Ok(Self::at(dir));
        }
        if let Some(dir) = std::env::var_os(ENV_VAULT_DIR) {
            if !dir.is_empty() {
                return Ok(Self::at(PathBuf::from(dir)));
            }
        }
        let data = dirs::data_dir().ok_or(PathError::NoDataDir)?;
        Ok(Self::at(data.join("sypherstore").join("vault")))
    }

    /// The SQLite database holding metadata and encrypted blobs.
    pub fn db(&self) -> PathBuf {
        self.root.join("vault.db")
    }

    /// Non-secret configuration: timeouts, hotkey, portal restore token.
    pub fn config(&self) -> PathBuf {
        self.root.join("config.json")
    }

    /// TPM-sealed public area for the outer KEK.
    pub fn tpm_sealed_pub(&self) -> PathBuf {
        self.root.join("tpm_sealed.pub")
    }

    /// TPM-sealed private area for the outer KEK.
    pub fn tpm_sealed_priv(&self) -> PathBuf {
        self.root.join("tpm_sealed.priv")
    }

    /// Cached favicons and application icons for the popup.
    pub fn icons(&self) -> PathBuf {
        self.root.join("icons")
    }

    /// Scheduled encrypted vault backups.
    pub fn backups(&self) -> PathBuf {
        self.root.join("backups")
    }

    /// Mock key material, used only under the `mock-hw` feature.
    pub fn mock_hw(&self) -> PathBuf {
        self.root.join("mock_hw")
    }

    /// Creates the vault directory tree with owner-only permissions.
    ///
    /// The mode is set on the directory itself rather than relying on the
    /// process umask, which a user may well have loosened.
    pub fn ensure_dirs(&self) -> Result<(), PathError> {
        for dir in [&self.root, &self.icons(), &self.backups()] {
            std::fs::create_dir_all(dir)?;
            set_owner_only(dir)?;
        }
        Ok(())
    }

    /// Whether this looks like an initialized vault.
    pub fn is_initialized(&self) -> bool {
        self.db().exists()
    }
}

/// Restricts a path to `0700` (directories) or `0600` (files).
///
/// Called on every file the vault writes. Even though all contents are
/// encrypted, the metadata alone (which sites you have accounts on) is worth
/// protecting from other local users.
pub fn set_owner_only(path: &Path) -> Result<(), PathError> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)?;
    let mode = if meta.is_dir() { 0o700 } else { 0o600 };
    let mut perms = meta.permissions();
    if perms.mode() & 0o777 != mode {
        perms.set_mode(mode);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

/// Writes `contents` to `path` atomically with `0600` permissions.
///
/// Writing through a temporary file plus rename means a crash mid-write cannot
/// leave a half-written config or sealed blob, which for `tpm_sealed.priv`
/// would mean an unrecoverable vault.
pub fn write_private_atomic(path: &Path, contents: &[u8]) -> Result<(), PathError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(contents)?;
        // Durability matters here: a rename can land before the data does.
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Directory for the rotating log file.
pub fn log_dir() -> Result<PathBuf, PathError> {
    let state = dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .ok_or(PathError::NoDataDir)?;
    Ok(state.join("sypherstore"))
}

#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("could not determine the XDG data directory")]
    NoDataDir,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn explicit_dir_wins_over_environment() {
        let paths = VaultPaths::resolve(Some(Path::new("/tmp/explicit"))).unwrap();
        assert_eq!(paths.root, Path::new("/tmp/explicit"));
    }

    #[test]
    fn paths_hang_off_the_root() {
        let p = VaultPaths::at("/vaults/demo");
        assert_eq!(p.db(), Path::new("/vaults/demo/vault.db"));
        assert_eq!(p.config(), Path::new("/vaults/demo/config.json"));
        assert_eq!(
            p.tpm_sealed_priv(),
            Path::new("/vaults/demo/tpm_sealed.priv")
        );
    }

    #[test]
    fn ensure_dirs_creates_an_owner_only_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let p = VaultPaths::at(tmp.path().join("vault"));
        p.ensure_dirs().unwrap();

        assert!(p.root.is_dir());
        assert!(p.icons().is_dir());
        assert!(p.backups().is_dir());

        let mode = std::fs::metadata(&p.root).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "vault dir must not be group/world readable");
    }

    #[test]
    fn atomic_write_produces_a_private_file_with_no_leftovers() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("sealed.priv");
        write_private_atomic(&target, b"sealed-bytes").unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"sealed-bytes");
        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(!target.with_extension("tmp").exists(), "temp file left behind");
    }

    #[test]
    fn atomic_write_replaces_existing_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("config.json");
        write_private_atomic(&target, b"first-and-longer").unwrap();
        write_private_atomic(&target, b"second").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"second");
    }

    #[test]
    fn uninitialized_vault_is_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let p = VaultPaths::at(tmp.path());
        assert!(!p.is_initialized());
    }
}
