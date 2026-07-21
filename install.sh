#!/usr/bin/env bash
#
# Sypherstore installer.
#
#   ./install.sh            full install: build, install, check, create vault,
#                           store the recovery key.
#   ./install.sh --update   rebuild and replace the binary and unit ONLY.
#
# Update mode exists so that shipping a UI fix cannot cost anyone their
# secrets. It never runs `init`, never touches the vault directory, never
# talks to the TPM or the authenticator, and never asks for sudo. The only
# things it writes are the binary and the systemd unit.
#
# Runs as your normal user. Full install calls sudo only for the two things
# that genuinely need root (the tss group and the udev rule) and tells you
# before each one.

set -euo pipefail

MODE=install
for arg in "$@"; do
    case "$arg" in
        --update) MODE=update ;;
        -h|--help)
            sed -n '3,15p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            printf 'error: unknown argument %s (expected --update)\n' "$arg" >&2
            exit 1
            ;;
    esac
done

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${SYPHERSTORE_BIN_DIR:-$HOME/.local/bin}"
UNIT_DIR="$HOME/.config/systemd/user"
UDEV_RULE="/etc/udev/rules.d/70-sypherstore-fido.rules"

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
info()  { printf '  %s\n' "$*"; }
warn()  { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
err()   { printf '\033[31merror:\033[0m %s\n' "$*" >&2; }
step()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

die() { err "$*"; exit 1; }

confirm() {
    local prompt="$1" answer
    read -r -p "$prompt [y/N] " answer
    [[ "${answer,,}" == "y" || "${answer,,}" == "yes" ]]
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

# Running the whole thing as root would create the vault in /root, seal the
# TPM key under the wrong user, and leave files your account cannot read.
[[ ${EUID} -eq 0 ]] && die "do not run this as root. Run it as the user who will use Sypherstore."

step "Checking prerequisites"

if [[ "$MODE" == update ]]; then
    info "update mode: the vault, TPM and authenticator will not be touched"
fi

command -v cargo >/dev/null || die "cargo not found. Install rust: sudo pacman -S rust"
info "cargo: $(cargo --version)"

for lib in tss2-esys tss2-tctildr; do
    pkg-config --exists "$lib" \
        || die "$lib development files not found. Install them: sudo pacman -S tpm2-tss"
done
info "tpm2-tss: $(pkg-config --modversion tss2-esys)"

command -v pkg-config >/dev/null || die "pkg-config not found. Install it: sudo pacman -S pkgconf"

if [[ "${XDG_SESSION_TYPE:-}" != "wayland" ]]; then
    warn "XDG_SESSION_TYPE is '${XDG_SESSION_TYPE:-unset}', not 'wayland'."
    warn "The popup and paste engine need Wayland. The CLI will still work."
fi

# Update mode does not seal or unseal anything, so a TPM that is temporarily
# unavailable is no reason to refuse to ship a UI fix.
if [[ -e /dev/tpmrm0 ]]; then
    info "TPM: /dev/tpmrm0 present"
elif [[ "$MODE" == update ]]; then
    warn "no TPM at /dev/tpmrm0. Continuing: update mode does not use it."
else
    die "no TPM at /dev/tpmrm0. Check that it is enabled in UEFI setup."
fi

# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------

if [[ "$MODE" == update ]]; then
    step "Skipping device permissions"
    info "unchanged by an update; no sudo required"
else

step "Checking device permissions"

if [[ -r /dev/tpmrm0 && -w /dev/tpmrm0 ]]; then
    info "TPM is accessible"
else
    warn "/dev/tpmrm0 is not accessible to you. It is owned by root:tss."
    if confirm "Add $USER to the 'tss' group with sudo?"; then
        sudo usermod -aG tss "$USER"
        bold "You must log out and back in for the group change to take effect."
        bold "Re-run this installer afterwards."
        exit 0
    else
        die "Sypherstore cannot seal keys without TPM access."
    fi
fi

# The udev rule grants your session access to the authenticator. Most distros
# ship one via libfido2, so only add ours if nothing already works.
fido_accessible=false
for node in /dev/hidraw*; do
    [[ -r "$node" && -w "$node" ]] && fido_accessible=true && break
done

if [[ "$fido_accessible" == true ]]; then
    info "A hidraw node is accessible; FIDO2 rules look fine"
elif [[ -f "$UDEV_RULE" ]]; then
    info "Sypherstore udev rule already installed"
else
    warn "No accessible /dev/hidraw* node found. Your authenticator may be unreadable."
    if confirm "Install a udev rule for FIDO2 devices with sudo?"; then
        # TAG+="uaccess" hands the device to whoever is logged in at the seat,
        # which is narrower and safer than a world-writable mode.
        sudo tee "$UDEV_RULE" >/dev/null <<'RULE'
# Sypherstore: grant the active seat access to FIDO2 authenticators.
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", TAG+="uaccess"
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="096e", TAG+="uaccess"
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="2581", TAG+="uaccess"
RULE
        sudo udevadm control --reload
        sudo udevadm trigger
        info "udev rule installed. Unplug and replug your authenticator."
    fi
fi

fi  # end of full-install-only permissions section

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

step "Building release binary"

cd "$REPO_DIR"
# Explicitly without --features mock-hw. A mock build stores key material in
# plain files, and installing one as production would be catastrophic.
cargo build --release --locked 2>&1 | tail -5

BUILT="$REPO_DIR/target/release/sypherstore"
[[ -x "$BUILT" ]] || die "build did not produce $BUILT"

# Verify we really built the hardware-backed variant before installing it.
#
# Safe to run in update mode: `doctor` only stats paths, calls access(2) and
# reads /etc/group. It performs no TPM command, never opens the authenticator,
# and never reads the contents of vault.db.
if "$BUILT" doctor 2>/dev/null | grep -q "MOCK HARDWARE"; then
    die "refusing to install: this build has mock hardware enabled"
fi
info "built $(du -h "$BUILT" | cut -f1) binary, hardware-backed"

step "Installing"

# Replacing a running daemon's binary on disk leaves the old code running with
# a stale unit file, so stop it first and note whether to bring it back.
DAEMON_WAS_RUNNING=false
if systemctl --user is-active --quiet sypherstore 2>/dev/null; then
    DAEMON_WAS_RUNNING=true
    info "stopping the running daemon"
    systemctl --user stop sypherstore
fi

mkdir -p "$BIN_DIR"
install -m 0755 "$BUILT" "$BIN_DIR/sypherstore"
info "binary: $BIN_DIR/sypherstore"

mkdir -p "$UNIT_DIR"
install -m 0644 "$REPO_DIR/crates/sypher-app/assets/sypherstore.service" \
    "$UNIT_DIR/sypherstore.service"
info "unit:   $UNIT_DIR/sypherstore.service"
systemctl --user daemon-reload

if [[ "$DAEMON_WAS_RUNNING" == true ]]; then
    systemctl --user start sypherstore
    info "daemon restarted"
fi

if ! printf '%s' "$PATH" | tr ':' '\n' | grep -qx "$BIN_DIR"; then
    warn "$BIN_DIR is not on your PATH. Add it to your shell profile:"
    warn "  export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

# ---------------------------------------------------------------------------
# Update mode stops here
# ---------------------------------------------------------------------------

if [[ "$MODE" == update ]]; then
    step "Updated"
    cat <<EOF
The binary and systemd unit are up to date.

Nothing else was touched: no TPM command was issued, your authenticator was
never contacted, and no vault contents were read or written. Your secrets and
recovery key are exactly as they were.

(The build check runs \`doctor\`, which only stats paths and checks permissions.)

  $BIN_DIR/sypherstore
EOF
    if [[ "$DAEMON_WAS_RUNNING" == true ]]; then
        echo
        info "The daemon was restarted, so press Meta+Shift+V to confirm it came back."
    else
        echo
        info "Start the daemon with: systemctl --user start sypherstore"
    fi
    exit 0
fi

# ---------------------------------------------------------------------------
# Environment check
# ---------------------------------------------------------------------------

step "Environment check"
"$BIN_DIR/sypherstore" doctor || warn "doctor reported failures; see above"

# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------

VAULT_DIR="${SYPHERSTORE_VAULT:-$HOME/.local/share/sypherstore/vault}"

step "Vault"

if [[ -f "$VAULT_DIR/vault.db" ]]; then
    info "A vault already exists at $VAULT_DIR; leaving it alone."
    NEW_VAULT=false
else
    bold "Creating a new vault. Touch your authenticator when it blinks."
    info "This takes two touches: one to register, one to derive the key."
    echo
    "$BIN_DIR/sypherstore" init
    NEW_VAULT=true
fi

# ---------------------------------------------------------------------------
# Recovery key
# ---------------------------------------------------------------------------

step "Recovery key"

cat <<'EXPLAIN'
Your vault's outer key is sealed inside this machine's TPM. If the TPM is
cleared, the motherboard is replaced, or this machine dies, that key is gone
and every secret with it.

The recovery key is that key, written down, so a replacement machine can
adopt this vault.

What it is:      a way to move the vault to a new computer.
What it is NOT:  a way to read your secrets. Every secret is sealed twice,
                 and reading one still requires a touch from your registered
                 authenticator.

Anyone holding BOTH the recovery key and your YubiKey can read the vault on
any computer. Keep them in different places.

EXPLAIN

if confirm "Show the recovery key now so you can write it down?"; then
    echo
    # --force because the command's own warning would repeat what was just
    # explained above; the decision has already been made deliberately here.
    "$BIN_DIR/sypherstore" recovery export --force
    echo
    bold "Write this down and store it offline, away from your YubiKey."
    warn "It is now in your terminal scrollback. Clear it with: clear && printf '\\033[3J'"
    echo
    read -r -p "Press Enter once you have stored it safely. "
else
    info "Skipped. You can export it later with:"
    info "  sypherstore recovery export"
    info "  sypherstore recovery export --out ~/recovery.txt   # avoids scrollback"
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

step "Done"

cat <<EOF
Start the daemon:
  systemctl --user enable --now sypherstore

Then press Meta+Shift+V. The first press asks the portal for permission to
register the shortcut, and the first paste asks for permission to type.

Useful commands:
  sypherstore add <name>        store a secret
  sypherstore list              show what is in the vault (no touch needed)
  sypherstore backup            encrypted snapshot into the vault directory
  sypherstore doctor            re-check this machine
  sypherstore recovery export   print the recovery key again

Vault:  $VAULT_DIR
Log:    ${XDG_STATE_HOME:-$HOME/.local/state}/sypherstore/sypherstore.log
EOF

if [[ "${NEW_VAULT:-false}" == true ]]; then
    echo
    bold "Reminder: without the recovery key, losing this machine loses the vault."
fi
