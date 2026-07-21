//! Sypherstore: an offline, hardware-backed password and secret manager.
//!
//! The binary is both the daemon and the management CLI. `sypherstore daemon`
//! is the long-running process that owns the global hotkey and the popup;
//! every other subcommand is a one-shot operation on the vault.

mod browser;
mod cli;
mod commands;
mod daemon;
mod doctor;
mod hotkey;
mod hw;
mod logging;
mod paste;
mod pin;
mod state;
mod ui;

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    // Applied before anything else touches key material, so there is no window
    // in which a crash could dump a core containing secrets.
    sypher_core::secure::disable_core_dumps();

    let args = cli::Cli::parse();

    // Blocking ptrace also makes /proc/<pid> root-owned, which stops
    // xdg-desktop-portal from identifying us. The daemon needs the portals for
    // the hotkey and the paste engine, so it relies on Yama instead; see
    // `secure::disable_ptrace`. Every other command is short-lived and can
    // take the stronger setting.
    if !matches!(args.command, cli::Command::Daemon) {
        sypher_core::secure::disable_ptrace();
    }

    if let Err(e) = logging::init(args.verbose) {
        eprintln!("sypherstore: could not initialize logging: {e:#}");
    }

    match commands::dispatch(args) {
        Ok(code) => code,
        Err(e) => {
            // `{:#}` renders the whole anyhow context chain, which is where
            // the actionable part of most failures lives.
            eprintln!("sypherstore: {e:#}");
            tracing::error!(error = %format!("{e:#}"), "command failed");
            ExitCode::FAILURE
        }
    }
}
