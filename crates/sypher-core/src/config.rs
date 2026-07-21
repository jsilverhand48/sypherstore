//! Non-secret user configuration, stored as JSON next to the vault.
//!
//! Nothing in this file is confidential. The portal restore token is the one
//! entry that looks like it might be: it is not a capability on its own, it
//! only lets the compositor recognize a previously approved session so the
//! consent dialog is not shown again. It is still written `0600` along with
//! everything else, since the config also reveals the hotkey and timeout.
//!
//! Unknown keys are rejected rather than ignored. A misspelled
//! `clipboard_fallbak` that silently kept its default would be a security
//! footgun: the user would believe they had changed a setting that never
//! moved. The cost is that a config written by a newer build fails to load on
//! an older one, which is the direction we would rather fail in.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::vault::paths::{write_private_atomic, PathError};

/// Default idle timeout before the inner key is zeroized.
pub const DEFAULT_TIMEOUT_SECS: u64 = 60;
/// Default global hotkey. Meta+Shift+V avoids Plasma's own Meta+V clipboard
/// history binding.
pub const DEFAULT_HOTKEY: &str = "Meta+Shift+V";
/// Ceiling on the unlock timeout. A vault that stays unlocked for an hour is
/// not meaningfully protected by the inner layer, so the setting is clamped
/// rather than trusted.
pub const MAX_TIMEOUT_SECS: u64 = 3600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Seconds of inactivity after which the inner key is zeroized and the
    /// vault returns to Locked.
    pub unlock_timeout_secs: u64,

    /// Global shortcut requested from the GlobalShortcuts portal. The
    /// compositor may override this; Plasma shows the effective binding in
    /// System Settings.
    pub hotkey: String,

    /// Restore token for the RemoteDesktop portal session, so the consent
    /// dialog appears once rather than on every paste. Not a secret.
    pub remote_desktop_restore_token: Option<String>,

    /// Fall back to the clipboard when the RemoteDesktop portal is
    /// unavailable. Off by default: the clipboard is readable by every other
    /// application on the session, so this materially weakens the paste path.
    pub clipboard_fallback: bool,

    /// How long a clipboard fallback paste leaves the secret on the clipboard
    /// before restoring the previous contents.
    pub clipboard_clear_ms: u64,

    /// Filter the popup list by the focused browser's URL.
    pub browser_detection: bool,

    /// Hard budget for the whole window-class plus URL-extraction pipeline.
    /// On expiry the popup shows every secret rather than making the user
    /// wait, since a slow filter is worse than no filter.
    pub browser_detect_timeout_ms: u64,

    /// Require a fresh touch to reveal or edit a secret even while unlocked.
    pub confirm_on_edit: bool,

    /// Keep this many scheduled backups before pruning the oldest.
    pub backup_retention: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            unlock_timeout_secs: DEFAULT_TIMEOUT_SECS,
            hotkey: DEFAULT_HOTKEY.to_string(),
            remote_desktop_restore_token: None,
            clipboard_fallback: false,
            clipboard_clear_ms: 100,
            browser_detection: true,
            browser_detect_timeout_ms: 300,
            confirm_on_edit: true,
            backup_retention: 10,
        }
    }
}

impl Config {
    /// Loads the config, falling back to defaults when the file is absent.
    ///
    /// A malformed file is an error rather than a silent reset: silently
    /// reverting to defaults would quietly re-enable the clipboard fallback or
    /// lengthen the timeout, and the user would have no way to notice.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let cfg: Config = serde_json::from_slice(&bytes)
                    .map_err(|e| ConfigError::Parse(path.display().to_string(), e.to_string()))?;
                Ok(cfg.clamped())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(ConfigError::Io(e)),
        }
    }

    /// Writes the config atomically with `0600` permissions.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| ConfigError::Serialize(e.to_string()))?;
        write_private_atomic(path, &json)?;
        Ok(())
    }

    /// Returns a copy with out-of-range values pulled back into bounds.
    ///
    /// A hand-edited zero timeout would make the vault re-prompt on every
    /// keystroke, and a huge one would defeat the inner layer; both are
    /// corrected rather than rejected so a typo cannot lock the user out of
    /// their own daemon.
    pub fn clamped(mut self) -> Self {
        self.unlock_timeout_secs = self.unlock_timeout_secs.clamp(5, MAX_TIMEOUT_SECS);
        self.browser_detect_timeout_ms = self.browser_detect_timeout_ms.clamp(50, 2000);
        self.clipboard_clear_ms = self.clipboard_clear_ms.clamp(50, 60_000);
        self.backup_retention = self.backup_retention.min(365);
        if self.hotkey.trim().is_empty() {
            self.hotkey = DEFAULT_HOTKEY.to_string();
        }
        self
    }

    /// The unlock timeout as a `Duration`.
    pub fn unlock_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.unlock_timeout_secs)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("could not parse {0}: {1}")]
    Parse(String, String),
    #[error("could not serialize config: {0}")]
    Serialize(String),
    #[error(transparent)]
    Path(#[from] PathError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_yields_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = Config::load(&tmp.path().join("absent.json")).unwrap();
        assert_eq!(cfg, Config::default());
        assert_eq!(cfg.unlock_timeout_secs, 60);
        assert!(!cfg.clipboard_fallback, "clipboard must default to off");
    }

    #[test]
    fn roundtrips_through_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.json");

        let mut cfg = Config::default();
        cfg.unlock_timeout_secs = 120;
        cfg.remote_desktop_restore_token = Some("token-abc".into());
        cfg.clipboard_fallback = true;
        cfg.save(&path).unwrap();

        assert_eq!(Config::load(&path).unwrap(), cfg);
    }

    #[test]
    fn saved_config_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.json");
        Config::default().save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn malformed_config_is_an_error_not_a_silent_reset() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.json");
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(matches!(Config::load(&path), Err(ConfigError::Parse(..))));
    }

    #[test]
    fn out_of_range_values_are_clamped_on_load() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.json");
        std::fs::write(
            &path,
            br#"{"unlock_timeout_secs":0,"browser_detect_timeout_ms":99999,"hotkey":"  "}"#,
        )
        .unwrap();

        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.unlock_timeout_secs, 5);
        assert_eq!(cfg.browser_detect_timeout_ms, 2000);
        assert_eq!(cfg.hotkey, DEFAULT_HOTKEY);
    }

    #[test]
    fn absurdly_long_timeout_is_capped() {
        let cfg = Config {
            unlock_timeout_secs: u64::MAX,
            ..Default::default()
        }
        .clamped();
        assert_eq!(cfg.unlock_timeout_secs, MAX_TIMEOUT_SECS);
    }

    #[test]
    fn partial_config_fills_in_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.json");
        std::fs::write(&path, br#"{"unlock_timeout_secs":90}"#).unwrap();

        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.unlock_timeout_secs, 90);
        assert_eq!(cfg.hotkey, DEFAULT_HOTKEY);
        assert!(cfg.browser_detection);
    }
}
