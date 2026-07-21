//! Logging setup.
//!
//! The overriding constraint is that **no secret material may ever reach the
//! log**. That is enforced upstream by types rather than here: `SecureBuf` and
//! `Key` have redacted `Debug`, and `SecretPayload` contains only those types,
//! so a `tracing::info!(?payload)` prints placeholders. This module's job is
//! narrower: put events somewhere useful, and default to a level that logs
//! actions rather than data.
//!
//! Logs go to a file under `$XDG_STATE_HOME` and, when attached to a terminal,
//! also to stderr. The file is opened append-only with `0600`.

use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::{Context, Result};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

/// Environment variable for overriding the log level, e.g.
/// `SYPHERSTORE_LOG=debug`.
pub const ENV_LOG: &str = "SYPHERSTORE_LOG";

/// Initializes tracing. Call once, early in `main`.
///
/// `verbose` raises the default level to `debug`; the environment variable
/// wins over both. Returns the log file path for `doctor` to report.
pub fn init(verbose: bool) -> Result<Option<PathBuf>> {
    let level = std::env::var(ENV_LOG)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| if verbose { "debug".into() } else { "info".into() });

    // A bare level like `debug` is scoped to our own crates. Applying it
    // globally would bury every one of our lines under wgpu and naga shader
    // tracing, which is what made the first debug run unreadable. Anything
    // containing `=` is passed through as a full directive, so the escape
    // hatch for debugging a dependency is still there.
    let filter = if level.contains('=') {
        EnvFilter::new(level)
    } else {
        // zbus is pinned to `error` because ashpd's portal sessions always
        // provoke a "Failed to populate properties cache" warning: the portal
        // deletes the Request object as soon as it responds, so the property
        // fetch races it and loses. It is harmless and unactionable, and
        // logging it on every popup would train the user to ignore warnings.
        EnvFilter::new(format!(
            "warn,zbus=error,sypherstore={level},sypher_core={level},sypher_app={level}"
        ))
    };

    // A terminal layer is only useful when there is a terminal; the daemon
    // runs under systemd where stderr would be duplicated into the journal.
    let stderr_layer = std::io::stderr().is_terminal().then(|| {
        tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_target(false)
            .without_time()
            .compact()
    });

    let (file_layer, path) = match open_log_file() {
        Ok((file, path)) => (
            Some(
                tracing_subscriber::fmt::layer()
                    .with_writer(file)
                    .with_ansi(false)
                    .with_target(true),
            ),
            Some(path),
        ),
        Err(e) => {
            // A missing log file must not stop the daemon from running; the
            // user still gets stderr.
            eprintln!("sypherstore: could not open log file: {e:#}");
            (None, None)
        }
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(stderr_layer)
        .with(file_layer.map(|l| l.boxed()))
        .init();

    Ok(path)
}

/// Opens the append-only, owner-only log file.
fn open_log_file() -> Result<(std::fs::File, PathBuf)> {
    use std::os::unix::fs::OpenOptionsExt;

    let dir = sypher_core::vault::paths::log_dir()
        .context("resolving the log directory")?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join("sypherstore.log");

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    Ok((file, path))
}

/// Path the log file would be written to, without creating it.
pub fn log_path() -> Option<PathBuf> {
    sypher_core::vault::paths::log_dir()
        .ok()
        .map(|d| d.join("sypherstore.log"))
}
