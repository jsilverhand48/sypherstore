//! Command-line surface.
//!
//! Kept separate from the implementations in `commands` so the argument
//! grammar can be read in one place, and so tests can construct a `Cli`
//! without going through `std::env::args`.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use sypher_core::model::SecretType;

#[derive(Debug, Parser)]
#[command(
    name = "sypherstore",
    version,
    about = "Offline, hardware-backed password and secret manager",
    long_about = "Secrets are sealed twice: once by this machine's TPM and once by \
                  your FIDO2 authenticator. Both must be present to decrypt anything."
)]
pub struct Cli {
    /// Use a vault at this path instead of the default location.
    ///
    /// Intended for throwaway development vaults. The environment variable is
    /// honoured too, so a shell can be pointed at a scratch vault for a whole
    /// session.
    #[arg(long, global = true, env = sypher_core::vault::paths::ENV_VAULT_DIR)]
    pub vault_dir: Option<PathBuf>,

    /// Log at debug level.
    #[arg(long, short, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the background daemon: global hotkey, popup and paste engine.
    Daemon,

    /// Create a new vault on this machine.
    ///
    /// Seals a fresh key with the TPM and registers a credential on your
    /// authenticator. Requires one touch.
    Init,

    /// Check that this machine has everything Sypherstore needs.
    Doctor,

    /// Add a secret.
    Add(AddArgs),

    /// List stored secrets. Shows metadata only; no touch required.
    List(ListArgs),

    /// Delete a secret by id or exact name.
    Delete(DeleteArgs),

    /// Write an encrypted snapshot of the vault.
    ///
    /// Backups are encrypted to this machine's TPM key, so they restore only
    /// here. They protect against mistakes, not hardware loss.
    Backup,

    /// List or restore encrypted snapshots.
    #[command(subcommand)]
    Restore(RestoreCommand),

    /// Export or use the vault's recovery key.
    #[command(subcommand)]
    Recovery(RecoveryCommand),

    /// Development and debugging helpers.
    #[command(subcommand)]
    Dev(DevCommand),
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// Display name, e.g. "GitHub (work)".
    pub name: String,

    /// Site this secret belongs to, e.g. "github.com". Used to filter the
    /// popup when that site is focused.
    #[arg(long)]
    pub domain: Option<String>,

    /// Desktop application window class this secret belongs to.
    #[arg(long)]
    pub application: Option<String>,

    /// Account name.
    #[arg(long, short)]
    pub username: Option<String>,

    /// What kind of secret this is.
    #[arg(long = "type", short = 't', value_parser = parse_secret_type, default_value = "password")]
    pub secret_type: SecretType,

    /// Tags for grouping and search. Repeatable.
    #[arg(long)]
    pub tag: Vec<String>,

    /// Read the secret from stdin instead of prompting.
    ///
    /// For scripted imports. A trailing newline is stripped. Note that this
    /// puts the secret in a pipe, which is less protected than the prompt.
    #[arg(long)]
    pub stdin: bool,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// Only show secrets matching this fuzzy query.
    pub query: Option<String>,

    /// Only show secrets relevant to this hostname or URL.
    #[arg(long)]
    pub host: Option<String>,

    /// Print full UUIDs rather than short ids.
    #[arg(long)]
    pub long: bool,
}

#[derive(Debug, Args)]
pub struct DeleteArgs {
    /// UUID (full or unique prefix) or exact name of the secret.
    pub target: String,

    /// Skip the confirmation prompt.
    #[arg(long, short)]
    pub force: bool,
}

#[derive(Debug, Subcommand)]
pub enum RecoveryCommand {
    /// Print the recovery key so it can be written down and stored offline.
    ///
    /// The recovery key removes this vault's binding to this machine. It does
    /// NOT remove the requirement for your authenticator: reading a secret
    /// still needs a touch. Store it apart from your YubiKey.
    Export {
        /// Write to this file (mode 0600) instead of the terminal.
        ///
        /// Preferred when the terminal is logged or recorded, since printed
        /// output survives in scrollback.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Skip the confirmation prompt.
        #[arg(long, short)]
        force: bool,
    },

    /// Re-seal an existing vault's key to this machine's TPM.
    ///
    /// Run on a new machine after copying the vault directory across. You
    /// will be asked for the recovery key.
    Adopt {
        /// Skip the confirmation prompt.
        #[arg(long, short)]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum RestoreCommand {
    /// Show available snapshots, newest first.
    List,
    /// Replace the current vault with a snapshot.
    ///
    /// The existing database is backed up first, so a mistaken restore is
    /// itself recoverable.
    Apply {
        /// Path to a `.syphbak` archive.
        archive: PathBuf,
        /// Skip the confirmation prompt.
        #[arg(long, short)]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum DevCommand {
    /// Decrypt and print a secret. Requires an unlock.
    ///
    /// This deliberately prints a secret to the terminal, which the normal
    /// paste path never does. It exists to prove the crypto roundtrip during
    /// development.
    Decrypt {
        /// UUID (full or unique prefix) or exact name.
        target: String,
    },

    /// Perform an unlock and verify the keys, without reading any secret.
    UnlockTest,

    /// Print the resolved vault paths and configuration.
    Info,
}

/// Parses a secret type from its stable identifier.
///
/// Rejects unknown values rather than falling back to `Other`, because a typo
/// on the command line should be corrected, not silently filed away under the
/// wrong type.
fn parse_secret_type(s: &str) -> Result<SecretType, String> {
    SecretType::ALL
        .iter()
        .copied()
        .find(|t| t.as_str() == s)
        .ok_or_else(|| {
            let known: Vec<&str> = SecretType::ALL.iter().map(|t| t.as_str()).collect();
            format!("unknown type {s:?}; expected one of: {}", known.join(", "))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_an_add_with_all_the_trimmings() {
        let cli = Cli::try_parse_from([
            "sypherstore", "add", "GitHub",
            "--domain", "github.com",
            "--username", "octocat",
            "--type", "api_key",
            "--tag", "work",
            "--tag", "dev",
        ])
        .unwrap();

        let Command::Add(args) = cli.command else {
            panic!("expected add");
        };
        assert_eq!(args.name, "GitHub");
        assert_eq!(args.domain.as_deref(), Some("github.com"));
        assert_eq!(args.secret_type, SecretType::ApiKey);
        assert_eq!(args.tag, vec!["work", "dev"]);
    }

    #[test]
    fn add_defaults_to_a_password() {
        let cli = Cli::try_parse_from(["sypherstore", "add", "Thing"]).unwrap();
        let Command::Add(args) = cli.command else {
            panic!("expected add");
        };
        assert_eq!(args.secret_type, SecretType::Password);
    }

    #[test]
    fn an_unknown_type_is_rejected_with_the_valid_options() {
        let err = Cli::try_parse_from(["sypherstore", "add", "X", "--type", "passwrod"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("passwrod"), "{err}");
        assert!(err.contains("password"), "should list valid types: {err}");
    }

    #[test]
    fn vault_dir_is_accepted_before_or_after_the_subcommand() {
        for argv in [
            vec!["sypherstore", "--vault-dir", "/tmp/v", "list"],
            vec!["sypherstore", "list", "--vault-dir", "/tmp/v"],
        ] {
            let cli = Cli::try_parse_from(argv).unwrap();
            assert_eq!(cli.vault_dir.as_deref(), Some(std::path::Path::new("/tmp/v")));
        }
    }

    #[test]
    fn dev_subcommands_parse() {
        let cli = Cli::try_parse_from(["sypherstore", "dev", "decrypt", "abc123"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Dev(DevCommand::Decrypt { .. })
        ));
    }

    #[test]
    fn a_missing_subcommand_is_an_error() {
        assert!(Cli::try_parse_from(["sypherstore"]).is_err());
    }
}
