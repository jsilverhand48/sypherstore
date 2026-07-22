# Sypherstore

An offline password and secret manager for Arch Linux + KDE Plasma (Wayland),
written in Rust. Nothing ever leaves the machine: no sync, no cloud, no
network code at all.

Every secret is sealed twice. The outer layer is bound to this machine by the
TPM; the inner layer is bound to your FIDO2 authenticator and requires a
physical touch. Both must be present to decrypt anything, so a stolen
`vault.db` is useless on another machine, and a stolen machine is useless
without the YubiKey.

## Status

| Milestone | Scope | State |
| --- | --- | --- |
| M0 | Workspace, config, logging, `doctor` | Done |
| M1 | Envelope, storage, CRUD, search (mock hardware) | Done |
| M2 | TPM outer layer | Done, verified on hardware |
| M3 | FIDO2 inner layer | Done, verified on hardware |
| M4 | Daemon, global hotkey, popup | Done, verified on hardware |
| M5 | Paste engine | Done, verified on hardware |
| M6 | CRUD UI | Done |
| M7 | Browser-aware filtering | Window matching done; URL needs a11y |
| M8 | Hardening, backups, threat model | Done |

The default build is hardware-backed. A `mock-hw` build still exists for
development on machines without a TPM or an authenticator; it simulates both
layers with plain files and provides **no security**.

Setup needs one system change: `/dev/tpmrm0` is `root:tss`, so run
`sudo usermod -aG tss $USER` and log back in. `sypherstore doctor` reports
this and everything else it needs.

## What works today

With a `mock-hw` build and the daemon running:

- **Meta+Shift+V** opens a centered popup, with the keyboard grabbed
  exclusively so it always receives input. It starts **empty**: your secrets'
  names and sites are encrypted, so nothing is shown until you unlock.
- Touch your YubiKey and enter its **PIN** to unlock. The list then appears and
  you can fuzzy-search across name, site, username and tags; arrow keys move
  the selection; **Enter** decrypts the secret and types it into whatever had
  focus before the popup opened.
- **Ctrl+N** adds, **Ctrl+E** edits (demanding a fresh touch first),
  **Ctrl+D** deletes with a confirmation. **Esc** backs out of anything.
- **+ Add** in the header, or Ctrl+N, opens the editor; **Save** or Ctrl+S
  commits it. Each row has an **x** that asks for confirmation and then a
  fresh YubiKey touch and PIN before deleting.
- The vault relocks 60 seconds after the last use, zeroizing the inner key.
- A **PIN is required on every unlock**, as a second factor on top of the
  touch. A key with no PIN configured cannot be used.
- Enroll a **backup YubiKey** with `sypherstore enroll-key` so a lost primary
  does not lose the vault.

Both hardware layers are live: the outer key is sealed by the TPM and the
inner key comes from a FIDO2 `hmac-secret` assertion that requires a touch.
Verified against a real TPM 2.0 and a YubiKey 5: a vault whose sealed blob is
copied elsewhere, or altered by a single bit, is refused by the TPM with an
integrity failure.

## Layout

```
crates/sypher-core/   Hardware-free core: crypto, storage, search. Unit tested.
crates/sypher-app/    Binary `sypherstore`: CLI, daemon, hardware providers.
docs/                 Product spec and plan.
```

The split is load-bearing. `sypher-core` has no TPM, FIDO2, DBus or GUI
dependencies; the two hardware layers enter through the `OuterKeyProvider` and
`InnerKeyProvider` traits. That is what lets the security-critical logic (the
envelope, the lock state machine) be tested on any machine, including one with
no TPM attached.

## Installing

```sh
./install.sh
```

Builds a release binary, installs it and the systemd user unit, checks the
environment, creates the vault, and walks you through storing the recovery key.
Run it as your normal user; it uses sudo only for the `tss` group and the udev
rule, and asks first. It refuses to install a `mock-hw` build.

### Updating

```sh
./install.sh --update
```

Rebuilds and replaces only the binary and the systemd unit, restarting the
daemon if it was running. It never runs `init`, issues no TPM command, never
contacts the authenticator, and needs no sudo, so shipping a UI fix cannot
cost you your secrets. It tolerates a missing TPM for the same reason.

The one thing it does run is `doctor`, as the guard that refuses to install a
`mock-hw` build; that only stats paths and checks permissions.

## Building

```sh
# Real hardware (needs a TPM and a FIDO2 key)
cargo build --release

# Development build with both hardware layers mocked
cargo build --features mock-hw
```

## Trying it

```sh
export SYPHERSTORE_VAULT=/tmp/scratch-vault      # keep the real vault untouched
cargo run --features mock-hw -- doctor
cargo run --features mock-hw -- init
cargo run --features mock-hw -- add GitHub --domain github.com -u octocat
cargo run --features mock-hw -- list
cargo run --features mock-hw -- list --host https://github.com/settings
```

`doctor` checks everything the real build needs (TPM access, `tss` group
membership, hidraw permissions, portal backends, memlock headroom) and prints
a concrete remedy for anything that is not ready.

## Backups

```sh
sypherstore backup            # encrypted snapshot into vault/backups/
sypherstore restore list
sypherstore restore apply <archive>
```

Backups are encrypted to this machine's TPM key, so the archive leaks nothing
if it ends up somewhere less protected than the vault. The flip side is that
**a backup restores only on this machine**. It protects against your own
mistakes, not against hardware loss. There is no recovery phrase by design;
see [the threat model](docs/THREAT_MODEL.md).

## Recovery key

The outer key lives in this machine's TPM. If the TPM is cleared or the machine
dies, that key goes with it. The recovery key is an escape hatch:

```sh
sypherstore recovery export                    # print it, to write down
sypherstore recovery export --out ~/key.txt    # or write to a 0600 file
sypherstore recovery adopt                     # on a replacement machine
```

It **cannot read your secrets**: it strips only the machine binding, and every
secret still needs a touch from your authenticator. But anyone with both the
recovery key and your YubiKey can open the vault anywhere, so store them
separately.

Losing the *authenticator* is still unrecoverable. That is by design.

## Running as a service

```sh
mkdir -p ~/.config/systemd/user
cp crates/sypher-app/assets/sypherstore.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now sypherstore
```

A *user* unit, never a system one: the daemon needs your Wayland socket, your
session bus and your vault.

## Testing

```sh
cargo test --features mock-hw
```

Hardware-dependent tests are gated behind `--features hw-tests` and are
`#[ignore]`d by default, so the default suite runs anywhere.

## Security notes

- **Metadata is encrypted too.** Names, domains, usernames and tags are sealed
  in their own double envelope, so an attacker with the file learns only the
  number of rows, not which sites you have accounts on. The cost is that the
  popup shows nothing until you unlock.
- **A PIN is required on every unlock**, as a second factor on top of the
  touch, so a stolen-and-plugged key alone unlocks nothing.
- **A backup YubiKey can be enrolled** with `sypherstore enroll-key` (run from
  a vault unlocked by an already-enrolled key). Either key then opens the
  vault, and losing one no longer loses it.
- **The `mock-hw` feature is not a build flag to be casual about.** It writes
  key material to plain files in the vault directory. Every command in such a
  build prints a warning, and `doctor` reports it as a warning too.
- **Secrets in memory** live in `SecureBuf`: mlocked, zeroized on drop, with
  redacted `Debug`. The process sets `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0` at
  startup.
- **Root is outside the threat model.** So is a compromised kernel.
- **Lose every enrolled authenticator and the secrets are gone.** No passphrase
  fallback; it would be a second and much weaker way in. Enroll a backup key
  before you need it. A dead TPM is survivable via the recovery key above.

The full analysis, including the gaps, is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Requirements

- Arch Linux with KDE Plasma 6 on Wayland
- TPM 2.0 at `/dev/tpmrm0`, with your user in the `tss` group
- A FIDO2 authenticator supporting the `hmac-secret` extension
- `xdg-desktop-portal-kde`
