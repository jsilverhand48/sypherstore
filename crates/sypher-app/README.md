# sypher-app

The `sypherstore` binary: the management CLI and (from M4) the background
daemon. This is where the platform lives, so everything that needs a TPM, a
YubiKey, DBus, a portal or a window is in this crate.

| Module | Responsibility |
| --- | --- |
| `main` | Process hardening, logging init, dispatch. |
| `cli` | Clap argument grammar, kept separate from the implementations. |
| `commands` | Subcommand implementations. Thin wrappers over `sypher-core`. |
| `doctor` | Environment diagnostics, each with a concrete remedy. |
| `logging` | Tracing to `$XDG_STATE_HOME/sypherstore/sypherstore.log` plus stderr. |
| `hw` | Selects the hardware providers. The one place the `mock-hw` decision is made. |
| `daemon` | Wires the Wayland shell (main thread) to the async worker (background thread). |
| `state` | The channel protocol between the two, and the shared lock state. |
| `hotkey` | The GlobalShortcuts portal, spoken directly over zbus. See below. |
| `paste` | Typing secrets via the RemoteDesktop portal; clipboard fallback. Uppercase ASCII is typed with an explicit Left Shift hold, because remote viewers (noVNC, Guacamole/guacd) re-encode raw key events and lose capitalization when the modifier is only inferred by the compositor. |
| `ui/shell` | The `zwlr_layer_shell_v1` surface hosting the popup, on wgpu + egui. |
| `ui/popup` | Popup state machine and drawing. Shell-agnostic. |
| `ui/editor` | The add/edit form. |
| `browser/kwin` | Active-window tracking via a KWin script and a D-Bus service. |
| `browser/url` | Focused-tab URL extraction over AT-SPI2. Best effort. |
| `pin` | Bridges the synchronous CTAP PIN callback to the asynchronous popup. |

`hw/fido.rs` opens each connected authenticator individually and picks its
target deliberately: unlock goes to the key that answers a silent CTAP2
pre-flight probe (an assertion with `up=false`, no PIN, no touch) for an
enrolled credential, and `enroll-key` registers on a connected key that does
NOT answer it. Two keys plugged in at once is the normal enrollment case, not
an error.

## Three decisions worth knowing before you edit

**The popup is a layer-shell surface, not a normal window.** `winit`'s Wayland
backend implements `set_visible` as a no-op, so a window created hidden can
never be shown. `zwlr_layer_shell_v1` maps on creation and unmaps on destroy,
and `KeyboardInteractivity::Exclusive` removes the focus-stealing problem
entirely. This is why `eframe` is not a dependency.

**The hotkey talks to D-Bus directly rather than through `ashpd`.** The portal
derives its session path from a caller-supplied token, and KDE uses that token
as the KGlobalAccel component name. `ashpd` randomizes it per session and does
not expose the field, so every restart registered a new component and only the
first one to claim the key kept it. A fixed token means one component that
survives restarts. See the module docs in `hotkey.rs`.

**Input translation in `ui/shell` is where UI bugs hide.** `popup.rs` is
tested against synthesised `Keys` and egui events, so its tests pass whether or
not the shell ever produces those events. Two things reached the user broken
this way: the shell had no `PointerHandler` at all, and `translate_keysym`
dropped every letter, which killed all four Ctrl chords because text is
suppressed while Ctrl is held. When a control does nothing, suspect the
translation before the state machine.

## Commands

| Command | Needs a touch? | Notes |
| --- | --- | --- |
| `doctor` | no | Environment checks. Exits non-zero on any failure. |
| `init` | yes | Creates the vault, seals the machine key, registers a credential. |
| `add <name>` | yes | Prompts for the secret without echo, or `--stdin`. |
| `list [query]` | yes | Metadata is encrypted, so listing unlocks. `--host` filters by site. |
| `delete <target>` | yes | Resolving a name needs an unlock; the touch is also the required reauth. `VACUUM`s afterwards. |
| `enroll-key [--label]` | yes | Enrolls a backup authenticator. Unlock with an enrolled key, then present the new one; both keys may stay connected, the new registration is directed at the un-enrolled key. |
| `dev decrypt <target>` | yes | Prints a secret. Development only. |
| `dev unlock-test` | yes | Verifies the keys without reading a secret. |
| `dev info` | no | Resolved paths and effective config. |
| `backup` | no | Encrypted snapshot. Moves ciphertext, so no touch. |
| `restore list` | no | Show snapshots. |
| `restore apply <archive>` | no | Replace the vault; snapshots the old one first. |
| `daemon` | on use | The background daemon: hotkey, popup, paste. |

`<target>` accepts a full UUID, a unique UUID prefix, or an exact name.
Ambiguous targets are refused rather than resolved to the first match, since
acting on the wrong secret is worse than retyping a longer prefix.

## Vault location

Resolved in this order:

1. `--vault-dir <path>`
2. `SYPHERSTORE_VAULT`
3. `$XDG_DATA_HOME/sypherstore/vault`

The override exists so development runs cannot touch the real vault. Export
`SYPHERSTORE_VAULT` to point a whole shell at a scratch vault.

## Feature flags

- `mock-hw` — fake both hardware layers. Every command in such a build prints a
  warning banner to stderr, on every invocation.
- `hw-tests` — enable tests that need a real TPM and YubiKey. They are
  `#[ignore]`d, so run them with `--features hw-tests -- --ignored`.

## Secret handling in this crate

Secrets are read with `rpassword` (no echo) into a buffer that is moved
straight into a `SecureBuf` and then wiped. Nothing prints a secret except
`dev decrypt`, which exists to prove the roundtrip and warns when stdout is a
terminal. `add` asks twice, because a mistyped secret is stored encrypted and
is then indistinguishable from a correct one until it fails to log in
somewhere.
