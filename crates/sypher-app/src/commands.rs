//! Implementations of the CLI subcommands.
//!
//! These are thin: the interesting logic lives in `sypher-core`, and each
//! command here is mostly argument marshalling, one call into a `Session`, and
//! human-readable output.
//!
//! One rule is specific to this layer: a secret's plaintext must not be
//! printed, echoed, or left in an ordinary `String`. Input is read through
//! `rpassword` (no echo) into a buffer that is moved straight into a
//! `SecureBuf` and wiped. The single exception is `dev decrypt`, which exists
//! to prove the roundtrip and says so in its help text.

use std::io::{IsTerminal, Read, Write};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use uuid::Uuid;

use sypher_core::config::Config;
use sypher_core::model::{SecretMeta, SecretPayload};
use sypher_core::search::fuzzy::{SearchContext, Searcher};
use sypher_core::secure::SecureBuf;
use sypher_core::vault::db::Vault;
use sypher_core::vault::paths::VaultPaths;
use sypher_core::vault::session::Session;

use crate::cli::{
    AddArgs, Cli, Command, DeleteArgs, DevCommand, ListArgs, RecoveryCommand, RestoreCommand,
};
use crate::{doctor, hw};

/// Routes a parsed command to its implementation.
pub fn dispatch(args: Cli) -> Result<ExitCode> {
    let paths = VaultPaths::resolve(args.vault_dir.as_deref())
        .context("resolving the vault directory")?;

    match args.command {
        Command::Doctor => cmd_doctor(&paths),
        Command::Init => cmd_init(&paths),
        Command::Add(a) => cmd_add(&paths, a),
        Command::List(a) => cmd_list(&paths, a),
        Command::Delete(a) => cmd_delete(&paths, a),
        Command::Backup => cmd_backup(&paths),
        Command::Recovery(r) => cmd_recovery(&paths, r),
        Command::Restore(r) => cmd_restore(&paths, r),
        Command::Dev(d) => cmd_dev(&paths, d),
        Command::Daemon => cmd_daemon(&paths),
    }
}

fn cmd_doctor(paths: &VaultPaths) -> Result<ExitCode> {
    let report = doctor::run(paths);
    println!("{report}");
    Ok(if report.has_failures() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn cmd_init(paths: &VaultPaths) -> Result<ExitCode> {
    hw::warn_if_mock();

    if paths.is_initialized() {
        bail!(
            "a vault already exists at {}. Delete it first if you really mean to start over.",
            paths.root.display()
        );
    }

    let config = load_config(paths)?;
    let vault = Vault::open(paths).context("creating the vault database")?;

    if !hw::IS_MOCK {
        println!("Touch your YubiKey to register a credential for this vault...");
    }

    let session = Session::initialize(
        vault,
        hw::outer(paths).as_ref(),
        hw::inner(paths).as_ref(),
        config.unlock_timeout(),
    )
    .context("initializing the vault")?;
    drop(session);

    // Persist the defaults so the file exists and is editable.
    config
        .save(&paths.config())
        .context("writing the config file")?;

    println!("Vault created at {}", paths.root.display());
    println!("Next: `sypherstore add <name>` to store a secret.");
    Ok(ExitCode::SUCCESS)
}

fn cmd_add(paths: &VaultPaths, args: AddArgs) -> Result<ExitCode> {
    hw::warn_if_mock();
    let mut session = open_unlocked(paths)?;

    let mut meta = SecretMeta::new(args.name.trim(), args.secret_type);
    meta.domain = normalize_domain(args.domain.as_deref());
    meta.application = args.application.unwrap_or_default().trim().to_string();
    meta.username = args.username.unwrap_or_default().trim().to_string();
    meta.tags = args
        .tag
        .into_iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();

    let value = if args.stdin {
        read_secret_from_stdin()?
    } else {
        prompt_for_secret()?
    };
    if value.is_empty() {
        bail!("refusing to store an empty secret");
    }

    let payload = SecretPayload::new(value);
    session.add(&meta, &payload).context("storing the secret")?;

    println!("Added {} ({})", meta.name, short_id(&meta.id));
    Ok(ExitCode::SUCCESS)
}

fn cmd_list(paths: &VaultPaths, args: ListArgs) -> Result<ExitCode> {
    // Listing is a metadata-only operation, so it deliberately does not
    // unlock. The user should be able to see what they have without a touch.
    let vault = Vault::open(paths).context("opening the vault")?;
    let secrets = vault.list_meta().context("reading the vault")?;

    if secrets.is_empty() {
        println!("The vault is empty. Add one with `sypherstore add <name>`.");
        return Ok(ExitCode::SUCCESS);
    }

    let ctx = SearchContext {
        host: args.host.clone(),
        application: None,
    };
    let ranked = Searcher::new().rank(&secrets, args.query.as_deref().unwrap_or(""), &ctx);

    if ranked.is_empty() {
        println!("No secrets matched.");
        return Ok(ExitCode::SUCCESS);
    }

    let id_width = if args.long { 36 } else { 8 };
    println!(
        "{:<width$}  {:<28} {:<24} {:<18} {}",
        "ID",
        "NAME",
        "DOMAIN",
        "USERNAME",
        "TYPE",
        width = id_width
    );
    for r in &ranked {
        let id = if args.long {
            r.meta.id.to_string()
        } else {
            short_id(&r.meta.id)
        };
        println!(
            "{:<width$}  {:<28} {:<24} {:<18} {}",
            id,
            truncate(&r.meta.name, 28),
            truncate(&r.meta.domain, 24),
            truncate(&r.meta.username, 18),
            r.meta.secret_type.label(),
            width = id_width
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_delete(paths: &VaultPaths, args: DeleteArgs) -> Result<ExitCode> {
    let vault = Vault::open(paths).context("opening the vault")?;
    let secrets = vault.list_meta()?;
    let target = resolve_target(&secrets, &args.target)?;

    if !args.force {
        print!(
            "Delete {:?} ({})? This cannot be undone. [y/N] ",
            target.name,
            short_id(&target.id)
        );
        std::io::stdout().flush().ok();
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("Cancelled.");
            return Ok(ExitCode::SUCCESS);
        }
    }

    // Deleting needs no key, so this path never asks for a touch.
    let mut vault = Vault::open(paths)?;
    vault.delete(&target.id).context("deleting the secret")?;
    // With secure_delete on, VACUUM rewrites the file so the removed
    // ciphertext does not survive in a free page.
    vault.vacuum().context("compacting the vault")?;

    println!("Deleted {:?}", target.name);
    Ok(ExitCode::SUCCESS)
}

fn cmd_recovery(paths: &VaultPaths, cmd: RecoveryCommand) -> Result<ExitCode> {
    use sypher_core::vault::recovery;

    match cmd {
        RecoveryCommand::Export { out, force } => {
            let session = open_locked_only(paths)?;
            let key_text = recovery::encode(session.outer_key());

            if !force {
                eprintln!(
                    "\nThe recovery key removes this vault's binding to this machine.\n\
                     \n\
                     It does NOT open the vault on its own: reading a secret still\n\
                     requires a touch from your registered authenticator. But anyone\n\
                     holding BOTH this key and your YubiKey can read the vault on any\n\
                     computer. Store them in different places.\n\
                     \n\
                     Write it on paper. Do not put it in the same password manager it\n\
                     is meant to recover.\n"
                );
                print!("Show the recovery key? [y/N] ");
                std::io::stdout().flush().ok();
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                    println!("Cancelled. Nothing was written.");
                    return Ok(ExitCode::SUCCESS);
                }
            }

            match out {
                Some(path) => {
                    // A file avoids the terminal entirely, which matters
                    // because scrollback and session logs outlive the command.
                    sypher_core::vault::paths::write_private_atomic(
                        &path,
                        format!("{key_text}\n").as_bytes(),
                    )
                    .context("writing the recovery key")?;
                    println!("Recovery key written to {} (mode 0600).", path.display());
                    println!("Move it offline and delete this copy.");
                }
                None => {
                    println!("\n  {key_text}\n");
                    eprintln!(
                        "This is now in your terminal scrollback. Clear it when you are done."
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }

        RecoveryCommand::Adopt { force } => {
            if !paths.db().exists() {
                bail!(
                    "no vault database at {}. Copy the vault directory here first.",
                    paths.db().display()
                );
            }

            eprintln!(
                "This re-seals an existing vault to THIS machine's TPM.\n\
                 You will still need the authenticator the vault was created with.\n"
            );
            let key_text = rpassword::prompt_password("Recovery key: ")
                .context("reading the recovery key")?;
            let key = recovery::decode(&key_text).context("the recovery key was not accepted")?;

            if !force {
                print!(
                    "Seal this key to the TPM on this machine, replacing any existing seal at {}? [y/N] ",
                    paths.root.display()
                );
                std::io::stdout().flush().ok();
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                    println!("Cancelled.");
                    return Ok(ExitCode::SUCCESS);
                }
            }

            paths.ensure_dirs().context("creating the vault directory")?;
            hw::outer(paths)
                .provision_with(&key)
                .context("sealing the recovered key to this TPM")?;

            // Prove it worked now rather than at the next hotkey press.
            let session = open_locked_only(paths).context(
                "the key was sealed, but the vault still will not open. \
                 The recovery key may belong to a different vault.",
            )?;
            let count = session.list()?.len();

            println!("Vault adopted on this machine. {count} secret(s) available.");
            println!("Touch your authenticator to use them: `sypherstore dev unlock-test`.");
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Writes an encrypted snapshot.
///
/// Needs only the outer key, so no touch is required: a backup is a copy of
/// ciphertext, not a read of any secret.
fn cmd_backup(paths: &VaultPaths) -> Result<ExitCode> {
    let config = load_config(paths)?;
    let session = open_locked_only(paths)?;

    let archive = sypher_core::vault::backup::create(paths, session.outer_key())
        .context("writing the backup")?;
    let pruned = sypher_core::vault::backup::prune(paths, config.backup_retention)
        .context("pruning old backups")?;

    println!("Backup written to {}", archive.display());
    if pruned > 0 {
        println!("Pruned {pruned} older backup(s), keeping {}.", config.backup_retention);
    }
    println!(
        "\nNote: this archive is encrypted to this machine's TPM. It will not\n\
         restore on any other computer, and not on this one if the TPM is cleared."
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_restore(paths: &VaultPaths, cmd: RestoreCommand) -> Result<ExitCode> {
    match cmd {
        RestoreCommand::List => {
            let archives = sypher_core::vault::backup::list(paths)?;
            if archives.is_empty() {
                println!("No backups. Create one with `sypherstore backup`.");
                return Ok(ExitCode::SUCCESS);
            }
            println!("{:<44} {}", "ARCHIVE", "SIZE");
            for archive in archives {
                let size = std::fs::metadata(&archive).map(|m| m.len()).unwrap_or(0);
                let name = archive
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                println!("{name:<44} {size} bytes");
            }
            Ok(ExitCode::SUCCESS)
        }

        RestoreCommand::Apply { archive, force } => {
            let session = open_locked_only(paths)?;

            // Decrypt before touching the live vault, so a bad archive is
            // rejected while the current database is still intact.
            let restored = sypher_core::vault::backup::restore(&archive, session.outer_key())
                .context("decrypting the backup")?;

            if !force {
                print!(
                    "Replace the vault at {} with {}? [y/N] ",
                    paths.db().display(),
                    archive.display()
                );
                std::io::stdout().flush().ok();
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                    println!("Cancelled.");
                    return Ok(ExitCode::SUCCESS);
                }
            }

            // Snapshot the current state first: restoring the wrong archive
            // should not be the end of the story.
            let safety = sypher_core::vault::backup::create(paths, session.outer_key())
                .context("backing up the current vault before replacing it")?;
            drop(session);

            // The WAL and shared-memory files belong to the old database;
            // leaving them would corrupt the restored one.
            for suffix in ["-wal", "-shm"] {
                let path = paths.db().with_extension(format!("db{suffix}"));
                let _ = std::fs::remove_file(path);
            }
            sypher_core::vault::paths::write_private_atomic(&paths.db(), &restored)
                .context("writing the restored database")?;

            println!("Restored from {}", archive.display());
            println!("The previous vault was saved to {}", safety.display());
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn cmd_dev(paths: &VaultPaths, cmd: DevCommand) -> Result<ExitCode> {
    match cmd {
        DevCommand::Info => {
            let config = load_config(paths)?;
            println!("vault dir     {}", paths.root.display());
            println!("database      {}", paths.db().display());
            println!("config        {}", paths.config().display());
            println!(
                "log           {}",
                crate::logging::log_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(unavailable)".into())
            );
            println!("initialized   {}", paths.is_initialized());
            println!("build         {}", if hw::IS_MOCK { "MOCK HARDWARE" } else { "hardware-backed" });
            println!("timeout       {}s", config.unlock_timeout_secs);
            println!("hotkey        {}", config.hotkey);
            Ok(ExitCode::SUCCESS)
        }

        DevCommand::UnlockTest => {
            hw::warn_if_mock();
            let session = open_unlocked(paths)?;
            println!(
                "Unlock succeeded and the verification blob decrypted. \
                 {} secret(s) in the vault.",
                session.list()?.len()
            );
            Ok(ExitCode::SUCCESS)
        }

        DevCommand::Decrypt { target } => {
            hw::warn_if_mock();
            let mut session = open_unlocked(paths)?;
            let secrets = session.list()?;
            let meta = resolve_target(&secrets, &target)?;

            let payload = session.open(&meta.id).context("decrypting the secret")?;

            if std::io::stdout().is_terminal() {
                eprintln!("warning: printing a secret to the terminal.");
            }
            // Written as raw bytes rather than via a String, so the plaintext
            // is never copied into an unprotected owned allocation.
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(payload.value.as_slice())?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn cmd_daemon(paths: &VaultPaths) -> Result<ExitCode> {
    crate::daemon::run(paths)?;
    Ok(ExitCode::SUCCESS)
}

// ---- helpers ------------------------------------------------------------

fn load_config(paths: &VaultPaths) -> Result<Config> {
    Config::load(&paths.config()).context("loading the config file")
}

/// Opens the vault with the outer key only, no touch.
///
/// Enough for operations that move ciphertext around without reading it.
fn open_locked_only(paths: &VaultPaths) -> Result<Session> {
    if !paths.is_initialized() {
        bail!(
            "no vault at {}. Run `sypherstore init` first.",
            paths.root.display()
        );
    }
    let config = load_config(paths)?;
    let vault = Vault::open(paths).context("opening the vault")?;
    Session::open_locked(vault, hw::outer(paths).as_ref(), config.unlock_timeout())
        .context("recovering the machine key (is this the machine the vault was created on?)")
}

/// Opens the vault and unlocks it, prompting for a touch.
///
/// Every command that needs plaintext goes through here, so the touch prompt
/// and the "not initialized" guidance live in exactly one place.
fn open_unlocked(paths: &VaultPaths) -> Result<Session> {
    if !paths.is_initialized() {
        bail!(
            "no vault at {}. Run `sypherstore init` first.",
            paths.root.display()
        );
    }
    let config = load_config(paths)?;
    let vault = Vault::open(paths).context("opening the vault")?;
    let mut session = Session::open_locked(vault, hw::outer(paths).as_ref(), config.unlock_timeout())
        .context("recovering the machine key (is this the machine the vault was created on?)")?;

    if !hw::IS_MOCK {
        println!("Touch your YubiKey...");
    }
    session
        .unlock(hw::inner(paths).as_ref())
        .context("unlocking the vault")?;
    Ok(session)
}

/// Finds a secret by UUID, unique UUID prefix, or exact name.
///
/// Ambiguity is an error rather than a silent pick of the first match: acting
/// on the wrong secret is worse than making the user retype a longer prefix.
fn resolve_target<'a>(secrets: &'a [SecretMeta], target: &str) -> Result<&'a SecretMeta> {
    let target = target.trim();
    if target.is_empty() {
        bail!("no secret specified");
    }

    if let Ok(id) = Uuid::parse_str(target) {
        return secrets
            .iter()
            .find(|m| m.id == id)
            .with_context(|| format!("no secret with id {id}"));
    }

    let lower = target.to_ascii_lowercase();
    let by_prefix: Vec<&SecretMeta> = secrets
        .iter()
        .filter(|m| m.id.to_string().starts_with(&lower))
        .collect();
    let by_name: Vec<&SecretMeta> = secrets
        .iter()
        .filter(|m| m.name.eq_ignore_ascii_case(target))
        .collect();

    let matches = if by_name.is_empty() { by_prefix } else { by_name };
    match matches.len() {
        0 => bail!("no secret matching {target:?}. Try `sypherstore list`."),
        1 => Ok(matches[0]),
        n => {
            let names: Vec<String> = matches
                .iter()
                .take(5)
                .map(|m| format!("{} ({})", m.name, short_id(&m.id)))
                .collect();
            bail!(
                "{target:?} is ambiguous, matching {n} secrets: {}. Use a full id.",
                names.join(", ")
            )
        }
    }
}

/// Reads a secret twice from the terminal without echoing it.
///
/// The confirmation exists because a mistyped secret is stored encrypted and
/// is then indistinguishable from a correct one until it fails to log in
/// somewhere.
fn prompt_for_secret() -> Result<SecureBuf> {
    if !std::io::stdin().is_terminal() {
        bail!("stdin is not a terminal; use --stdin to pipe the secret in");
    }

    let mut first = rpassword::prompt_password("Secret: ").context("reading the secret")?;
    let mut second = rpassword::prompt_password("Confirm: ").context("reading the confirmation")?;

    // Compare before wiping, then wipe both regardless of the outcome.
    let matched = first == second;
    let out = SecureBuf::copy_from(first.as_bytes());
    zeroize::Zeroize::zeroize(&mut first);
    zeroize::Zeroize::zeroize(&mut second);

    if !matched {
        bail!("the two entries did not match");
    }
    Ok(out)
}

/// Reads a secret from stdin, stripping one trailing newline.
fn read_secret_from_stdin() -> Result<SecureBuf> {
    let mut raw = Vec::new();
    std::io::stdin()
        .read_to_end(&mut raw)
        .context("reading the secret from stdin")?;
    while raw.last() == Some(&b'\n') || raw.last() == Some(&b'\r') {
        raw.pop();
    }
    Ok(SecureBuf::take_from(&mut raw))
}

/// Normalizes a user-supplied domain to a bare hostname for storage.
///
/// Storing what the user typed would mean `https://github.com/login` never
/// matches a browser sitting on `github.com`.
fn normalize_domain(input: Option<&str>) -> String {
    input
        .and_then(sypher_core::search::domain::normalize_host)
        .unwrap_or_default()
}

/// First 8 characters of a UUID: enough to be unique in a personal vault and
/// short enough to retype.
fn short_id(id: &Uuid) -> String {
    id.to_string().chars().take(8).collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('\u{2026}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sypher_core::model::SecretType;

    fn corpus() -> Vec<SecretMeta> {
        let mut a = SecretMeta::new("GitHub", SecretType::Password);
        a.id = Uuid::parse_str("aaaaaaaa-0000-0000-0000-000000000001").unwrap();
        let mut b = SecretMeta::new("GitLab", SecretType::Password);
        b.id = Uuid::parse_str("bbbbbbbb-0000-0000-0000-000000000002").unwrap();
        let mut c = SecretMeta::new("GitHub", SecretType::ApiKey);
        c.id = Uuid::parse_str("aaaaaaaa-0000-0000-0000-000000000003").unwrap();
        vec![a, b, c]
    }

    #[test]
    fn resolves_by_full_uuid() {
        let secrets = corpus();
        let found = resolve_target(&secrets, "bbbbbbbb-0000-0000-0000-000000000002").unwrap();
        assert_eq!(found.name, "GitLab");
    }

    #[test]
    fn resolves_by_unique_prefix() {
        let secrets = corpus();
        assert_eq!(resolve_target(&secrets, "bbbb").unwrap().name, "GitLab");
    }

    #[test]
    fn an_ambiguous_prefix_is_refused() {
        // Both GitHub entries share the "aaaaaaaa" prefix. Picking one
        // silently could delete the wrong secret.
        let secrets = corpus();
        let err = resolve_target(&secrets, "aaaa").unwrap_err().to_string();
        assert!(err.contains("ambiguous"), "{err}");
    }

    #[test]
    fn an_ambiguous_name_is_refused() {
        let secrets = corpus();
        let err = resolve_target(&secrets, "GitHub").unwrap_err().to_string();
        assert!(err.contains("ambiguous"), "{err}");
    }

    #[test]
    fn resolves_by_exact_name_case_insensitively() {
        let secrets = corpus();
        assert_eq!(resolve_target(&secrets, "gitlab").unwrap().name, "GitLab");
    }

    #[test]
    fn an_unknown_target_suggests_listing() {
        let secrets = corpus();
        let err = resolve_target(&secrets, "nope").unwrap_err().to_string();
        assert!(err.contains("list"), "{err}");
    }

    #[test]
    fn an_empty_target_is_refused() {
        assert!(resolve_target(&corpus(), "   ").is_err());
    }

    #[test]
    fn domains_are_normalized_before_storage() {
        assert_eq!(normalize_domain(Some("https://www.GitHub.com/login")), "github.com");
        assert_eq!(normalize_domain(Some("github.com")), "github.com");
        assert_eq!(normalize_domain(None), "");
        assert_eq!(normalize_domain(Some("about:blank")), "");
    }

    #[test]
    fn truncation_is_unicode_safe() {
        // Byte slicing here would panic on a multi-byte boundary.
        assert_eq!(truncate("héllo wörld", 5), "héll\u{2026}");
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("🔐🔐🔐🔐", 2), "🔐\u{2026}");
    }

    #[test]
    fn short_ids_are_eight_characters() {
        let id = Uuid::parse_str("aaaaaaaa-0000-0000-0000-000000000001").unwrap();
        assert_eq!(short_id(&id), "aaaaaaaa");
    }
}
