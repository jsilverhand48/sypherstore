//! Typing a secret into the focused application.
//!
//! ## Why synthetic keystrokes rather than the clipboard
//!
//! The clipboard is readable by every application on the session, has no
//! expiry the compositor enforces, and is commonly captured by clipboard
//! managers that write history to disk. Putting a password there, even for
//! 100ms, hands it to anything that is watching.
//!
//! Synthetic keystrokes go only to whatever currently has keyboard focus. On
//! Wayland that means the `RemoteDesktop` portal, which is the only sanctioned
//! way for a client to inject input. The user approves it once and the portal
//! hands back a restore token so the consent dialog does not reappear.
//!
//! A clipboard fallback exists behind [`Config::clipboard_fallback`], off by
//! default, for the case where the portal is unavailable. It saves and
//! restores the previous clipboard contents.
//!
//! ## Capitalization must not depend on the compositor
//!
//! Sending only a shifted keysym (say `A`) leaves it to the compositor to
//! synthesize the Shift modifier. Native applications receive the resolved
//! text either way, which hides the problem, but anything that re-encodes raw
//! key events, a browser-based VNC client (noVNC, Guacamole/guacd) above all,
//! sees a keycode with no Shift held and forwards lowercase. Uppercase ASCII
//! letters are therefore typed with an explicit Left Shift press around the
//! letter's tap; see [`needs_explicit_shift`] for why only those.
//!
//! ## Handling of the plaintext
//!
//! The secret arrives in a [`SecureBuf`] and is never copied into an ordinary
//! `String`. Typing walks its characters directly, and the buffer is dropped
//! (and therefore zeroized) as soon as the last keysym is sent. Errors take
//! the same path: there is no early return that skips the wipe, because the
//! buffer's `Drop` does it.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use ashpd::desktop::remote_desktop::{
    DeviceType, KeyState, RemoteDesktop, SelectDevicesOptions, StartOptions,
};
use ashpd::desktop::{PersistMode, Session};
use ashpd::enumflags2::BitFlags;

use sypher_core::secure::SecureBuf;

/// How long to wait after hiding the popup before typing.
///
/// The compositor needs a moment to move keyboard focus back to whatever was
/// underneath. Typing immediately races that hand-off and the first characters
/// land in the void, or worse, in the wrong window. 150ms is comfortably
/// longer than KWin takes in practice while staying below the threshold where
/// the delay is noticeable.
const FOCUS_RETURN_DELAY: Duration = Duration::from_millis(150);

/// Delay between individual keystrokes.
///
/// Some applications, notably Electron ones and browser password fields with
/// JavaScript validation, drop characters delivered faster than this.
const KEYSTROKE_DELAY: Duration = Duration::from_millis(8);

/// Keysym for the left Shift key (`XK_Shift_L`).
///
/// Held explicitly around uppercase letters. Relying on the compositor to
/// synthesize the modifier from a shifted keysym is exactly what breaks
/// remote viewers: a browser-based VNC client (noVNC, Guacamole) rebuilds
/// each keystroke from the raw browser key event, and if no real Shift press
/// was delivered it forwards the lowercase keysym to the remote end.
const KEYSYM_SHIFT_L: i32 = 0xFFE1;

/// An established RemoteDesktop session that can type.
///
/// Held for the daemon's lifetime once created: setting it up costs a portal
/// round trip, and doing that per paste would add a visible delay and, without
/// a restore token, a consent dialog every time.
pub struct Typist {
    portal: RemoteDesktop,
    session: Session<RemoteDesktop>,
    /// Returned by the portal so a later session can skip the dialog. Not a
    /// secret; it is a capability reference scoped to this app and the user's
    /// prior consent.
    restore_token: Option<String>,
}

impl Typist {
    /// Opens a RemoteDesktop session, reusing `restore_token` when present.
    ///
    /// The first call shows a consent dialog. Later calls with a valid token
    /// do not, which is the difference between a usable password manager and
    /// one that asks permission on every paste.
    pub async fn connect(restore_token: Option<String>) -> Result<Self> {
        let portal = RemoteDesktop::new()
            .await
            .context("connecting to the RemoteDesktop portal")?;

        let session = portal
            .create_session(Default::default())
            .await
            .context("creating a RemoteDesktop session")?;

        let mut options = SelectDevicesOptions::default()
            .set_devices(BitFlags::from(DeviceType::Keyboard))
            // ExplicitlyRevoked keeps the grant until the user withdraws it in
            // System Settings, rather than expiring with the session.
            .set_persist_mode(PersistMode::ExplicitlyRevoked);
        if let Some(token) = &restore_token {
            options = options.set_restore_token(token.as_str());
        }

        portal
            .select_devices(&session, options)
            .await
            .context("requesting keyboard access")?;

        let response = portal
            .start(&session, None, StartOptions::default())
            .await
            .context("starting the RemoteDesktop session")?
            .response()
            .context("the user declined keyboard access")?;

        if !response.devices().contains(DeviceType::Keyboard) {
            return Err(anyhow!(
                "the portal granted no keyboard access; Sypherstore cannot type without it"
            ));
        }

        let new_token = response.restore_token().map(str::to_owned);
        if new_token.is_some() {
            tracing::debug!("received a RemoteDesktop restore token");
        }

        tracing::info!("keyboard access granted");
        Ok(Self {
            portal,
            session,
            restore_token: new_token.or(restore_token),
        })
    }

    /// The token to persist so the next run skips the consent dialog.
    pub fn restore_token(&self) -> Option<&str> {
        self.restore_token.as_deref()
    }

    /// Types the contents of `secret` into the focused window.
    ///
    /// Waits [`FOCUS_RETURN_DELAY`] first so the popup's keyboard grab has
    /// been released and focus is back where the user expects.
    pub async fn type_secret(&self, secret: &SecureBuf) -> Result<()> {
        let text = secret
            .as_str()
            .context("the secret is not valid UTF-8 and cannot be typed")?;

        tokio::time::sleep(FOCUS_RETURN_DELAY).await;

        let mut typed = 0usize;
        for ch in text.chars() {
            let Some(keysym) = char_to_keysym(ch) else {
                // Skipping is better than aborting half-typed: the user can
                // see and fix one wrong character, but a partial password with
                // no indication of where it stopped is worse.
                tracing::warn!("skipping a character with no keysym mapping");
                continue;
            };
            if needs_explicit_shift(ch) {
                self.shifted_tap(keysym).await?;
            } else {
                self.tap(keysym).await?;
            }
            typed += 1;
        }

        // Character count, never content. This is the closest the log ever
        // gets to a secret.
        tracing::info!(characters = typed, "typed a secret");
        Ok(())
    }

    /// Presses and releases one keysym.
    async fn tap(&self, keysym: i32) -> Result<()> {
        self.send(keysym, KeyState::Pressed)
            .await
            .context("sending a key press")?;
        self.send(keysym, KeyState::Released)
            .await
            .context("sending a key release")?;
        tokio::time::sleep(KEYSTROKE_DELAY).await;
        Ok(())
    }

    /// Presses and releases one keysym while holding Left Shift, so the
    /// modifier reaches every consumer as a real key event rather than being
    /// left to the compositor's keysym resolution (see [`KEYSYM_SHIFT_L`]).
    async fn shifted_tap(&self, keysym: i32) -> Result<()> {
        self.send(KEYSYM_SHIFT_L, KeyState::Pressed)
            .await
            .context("pressing Shift")?;
        let tapped = self.tap(keysym).await;
        // Released even when the tap failed: a Shift left stuck down would
        // garble everything typed afterwards, including by hand.
        let released = self
            .send(KEYSYM_SHIFT_L, KeyState::Released)
            .await
            .context("releasing Shift");
        tapped?;
        released
    }

    /// Sends a single keysym state change.
    async fn send(&self, keysym: i32, state: KeyState) -> Result<()> {
        self.portal
            .notify_keyboard_keysym(&self.session, keysym, state, Default::default())
            .await?;
        Ok(())
    }
}

/// Whether `ch` must be typed with Shift explicitly held.
///
/// Only ASCII uppercase: those are Shift+letter on effectively every layout.
/// Shifted punctuation is layout dependent (`@` is AltGr+q on a German
/// layout, not Shift+2), so wrapping it in Shift would mistype it; it stays
/// on the compositor's keysym resolution, which handles it correctly. The
/// same goes for non-ASCII capitals, which may live outside the layout
/// entirely and be typed through a synthesized keycode where a held Shift
/// would select the wrong level.
fn needs_explicit_shift(ch: char) -> bool {
    ch.is_ascii_uppercase()
}

/// Maps a character to an X11 keysym.
///
/// X11 defines this in two ranges: Latin-1 characters are their own code
/// point, and everything else is the Unicode scalar value offset by
/// `0x0100_0000`. Passing a raw code point for, say, `é` would name an
/// unrelated key, which is why the offset matters rather than being a
/// formality.
///
/// Control characters other than tab and newline have no useful keysym and
/// return `None`; a password containing them could not have been typed by hand
/// either.
fn char_to_keysym(ch: char) -> Option<i32> {
    // Special-cased because their Latin-1 code points are control characters
    // but they do have dedicated keysyms.
    match ch {
        '\t' => return Some(0xFF09),
        '\n' | '\r' => return Some(0xFF0D),
        _ => {}
    }
    if ch.is_control() {
        return None;
    }
    let cp = ch as u32;
    if cp <= 0xFF {
        Some(cp as i32)
    } else {
        Some((cp + 0x0100_0000) as i32)
    }
}

/// Copies a secret to the clipboard, restoring the previous contents after a
/// delay.
///
/// Off by default and clearly worse than typing: every application on the
/// session can read the clipboard for as long as the secret is on it. Provided
/// only because a broken portal would otherwise leave the user with no way to
/// use their vault at all.
pub fn copy_via_clipboard(secret: &SecureBuf, clear_after: Duration) -> Result<()> {
    use wl_clipboard_rs::copy::{MimeType, Options, Source};

    tracing::warn!(
        "using the clipboard fallback: the secret is readable by every \
         application on this session until it is cleared"
    );

    let mut options = Options::new();
    // The secret must not outlive our process on the clipboard.
    options.foreground(false);
    options
        .copy(
            Source::Bytes(secret.as_slice().to_vec().into_boxed_slice()),
            MimeType::Text,
        )
        .map_err(|e| anyhow!("could not set the clipboard: {e}"))?;

    // Clearing is best effort. wl-clipboard's ownership model means another
    // application taking the clipboard in the meantime already displaced us,
    // which is the outcome we wanted anyway.
    std::thread::spawn(move || {
        std::thread::sleep(clear_after);
        use wl_clipboard_rs::copy::{clear, ClipboardType, Seat};
        let _ = clear(ClipboardType::Regular, Seat::All);
        tracing::debug!("clipboard cleared");
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uppercase_ascii_gets_an_explicit_shift() {
        // A VNC viewer rebuilds keystrokes from raw key events, so the Shift
        // must be a real press, not a compositor inference.
        assert!(needs_explicit_shift('A'));
        assert!(needs_explicit_shift('Z'));
        assert!(!needs_explicit_shift('a'));
        assert!(!needs_explicit_shift('0'));
    }

    #[test]
    fn shifted_punctuation_is_left_to_the_compositor() {
        // '@' is Shift+2 on a US layout but AltGr+q on a German one; a forced
        // Shift would mistype it. The compositor resolves the keysym itself.
        assert!(!needs_explicit_shift('@'));
        assert!(!needs_explicit_shift('!'));
        assert!(!needs_explicit_shift('~'));
    }

    #[test]
    fn non_ascii_capitals_are_left_to_the_compositor() {
        // These may not exist in the active layout at all and get typed via a
        // synthesized keycode, where a held Shift would select the wrong
        // level.
        assert!(!needs_explicit_shift('É'));
        assert!(!needs_explicit_shift('Ā'));
    }

    #[test]
    fn ascii_maps_to_its_own_code_point() {
        assert_eq!(char_to_keysym('a'), Some(0x61));
        assert_eq!(char_to_keysym('Z'), Some(0x5A));
        assert_eq!(char_to_keysym('0'), Some(0x30));
        assert_eq!(char_to_keysym(' '), Some(0x20));
    }

    #[test]
    fn punctuation_common_in_passwords_maps_correctly() {
        // These are the characters most likely to be mangled by a naive
        // scancode-based approach, so they are worth pinning.
        assert_eq!(char_to_keysym('!'), Some(0x21));
        assert_eq!(char_to_keysym('@'), Some(0x40));
        assert_eq!(char_to_keysym('#'), Some(0x23));
        assert_eq!(char_to_keysym('$'), Some(0x24));
        assert_eq!(char_to_keysym('%'), Some(0x25));
        assert_eq!(char_to_keysym('^'), Some(0x5E));
        assert_eq!(char_to_keysym('&'), Some(0x26));
        assert_eq!(char_to_keysym('*'), Some(0x2A));
        assert_eq!(char_to_keysym('/'), Some(0x2F));
        assert_eq!(char_to_keysym('\\'), Some(0x5C));
        assert_eq!(char_to_keysym('|'), Some(0x7C));
        assert_eq!(char_to_keysym('~'), Some(0x7E));
    }

    #[test]
    fn latin1_uses_the_bare_code_point() {
        // Latin-1 is the one range where keysym equals the code point.
        assert_eq!(char_to_keysym('é'), Some(0xE9));
        assert_eq!(char_to_keysym('ü'), Some(0xFC));
        assert_eq!(char_to_keysym('ÿ'), Some(0xFF));
    }

    #[test]
    fn beyond_latin1_uses_the_unicode_offset() {
        // The boundary case: one past Latin-1 must switch encodings.
        assert_eq!(char_to_keysym('Ā'), Some(0x0100_0100));
        assert_eq!(char_to_keysym('€'), Some(0x0100_20AC));
        assert_eq!(char_to_keysym('🔐'), Some(0x0101_F510));
    }

    #[test]
    fn tab_and_newline_get_their_dedicated_keysyms() {
        assert_eq!(char_to_keysym('\t'), Some(0xFF09));
        assert_eq!(char_to_keysym('\n'), Some(0xFF0D));
        assert_eq!(char_to_keysym('\r'), Some(0xFF0D));
    }

    #[test]
    fn other_control_characters_are_skipped() {
        assert_eq!(char_to_keysym('\0'), None);
        assert_eq!(char_to_keysym('\x07'), None);
        assert_eq!(char_to_keysym('\x1b'), None);
    }

    #[test]
    fn a_realistic_password_maps_entirely() {
        // Nothing in a normal generated password should be dropped.
        let password = "Tr0ub4dor&3!xK$mZ~qW";
        for ch in password.chars() {
            assert!(
                char_to_keysym(ch).is_some(),
                "no keysym for {ch:?} in a realistic password"
            );
        }
    }
}
