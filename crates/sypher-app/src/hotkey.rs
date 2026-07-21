//! The global hotkey, via the GlobalShortcuts portal.
//!
//! On Wayland there is no way for an application to grab a global key
//! combination directly; the compositor owns all input. The
//! `org.freedesktop.portal.GlobalShortcuts` portal is the sanctioned route,
//! and Plasma 6 implements it natively. Binding through the portal has a
//! useful side effect: the shortcut shows up in System Settings under
//! Shortcuts, so the user can see it, change it, or remove it with the same
//! tools they use for everything else.
//!
//! ## Why this talks to D-Bus directly instead of using `ashpd`
//!
//! The portal derives the session's object path from a caller-supplied
//! `session_handle_token`, and `xdg-desktop-portal-kde` uses that token as the
//! component name it registers with KGlobalAccel. `ashpd` generates a fresh
//! random token per session and does not expose the field.
//!
//! That combination is quietly fatal for a daemon. Each restart registers a
//! brand-new component, and only the *first* one to claim the key combination
//! keeps it; every later registration is stored with an empty binding and
//! silently receives nothing at all. Worse, stale components are not removed
//! when the process dies, so a single crash permanently breaks the hotkey
//! until the user cleans out `kglobalshortcutsrc` by hand.
//!
//! This was observed in practice: after a handful of restarts, KGlobalAccel
//! held seven `token_ashpd_*` components for one shortcut, the first (long
//! dead) one owning `Meta+Shift+V` and the live one bound to nothing.
//!
//! A fixed token means there is exactly one component, reused across restarts,
//! which keeps its binding. The user's chosen shortcut then survives upgrades
//! and crashes.
//!
//! ## Trigger syntax
//!
//! The portal does not take Plasma's `Meta+Shift+V` notation. It uses the XDG
//! shortcuts specification, where modifiers are uppercase (`CTRL`, `ALT`,
//! `SHIFT`, `LOGO`) and the key is an XKB keysym name. [`to_portal_trigger`]
//! translates between the two so the config file can stay in the notation the
//! user recognizes.

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use futures_util::StreamExt;
use tokio::sync::mpsc;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::Connection;

/// Shortcut id used with the portal. Stable across runs: changing it would
/// orphan the user's existing binding.
pub const SHORTCUT_ID: &str = "open-popup";

/// Description shown in the portal dialog and in System Settings.
const SHORTCUT_DESCRIPTION: &str = "Open the Sypherstore popup";

/// Fixed session token. This is the whole point of the module: see above.
///
/// Changing this string orphans the user's existing shortcut registration and
/// they will have to approve the permission dialog again.
const SESSION_TOKEN: &str = "sypherstore";

/// A bound global shortcut, alive for as long as this value is held.
///
/// Dropping it drops the D-Bus connection, which closes the portal session and
/// unbinds the shortcut, so the daemon must keep it for its whole lifetime.
pub struct HotkeySession {
    _conn: Connection,
    _session: OwnedObjectPath,
}

#[zbus::proxy(
    interface = "org.freedesktop.portal.GlobalShortcuts",
    default_service = "org.freedesktop.portal.Desktop",
    default_path = "/org/freedesktop/portal/desktop"
)]
trait GlobalShortcuts {
    fn create_session(&self, options: HashMap<&str, Value<'_>>) -> zbus::Result<OwnedObjectPath>;

    fn bind_shortcuts(
        &self,
        session_handle: &ObjectPath<'_>,
        shortcuts: &[(&str, HashMap<&str, Value<'_>>)],
        parent_window: &str,
        options: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<OwnedObjectPath>;

    #[zbus(signal)]
    fn activated(
        &self,
        session_handle: OwnedObjectPath,
        shortcut_id: String,
        timestamp: u64,
        options: HashMap<String, OwnedValue>,
    ) -> zbus::Result<()>;
}

#[zbus::proxy(
    interface = "org.freedesktop.portal.Request",
    default_service = "org.freedesktop.portal.Desktop"
)]
trait Request {
    #[zbus(signal)]
    fn response(&self, response: u32, results: HashMap<String, OwnedValue>) -> zbus::Result<()>;
}

/// Registers the global shortcut and forwards each activation to `tx`.
///
/// Returns once the shortcut is bound; activations continue to arrive on a
/// spawned task. The returned handle must be kept alive.
///
/// This can block for a long time: `BindShortcuts` does not return until the
/// user answers the portal's permission dialog, and they may never answer it.
/// Callers must not await it on a path that needs to stay responsive.
pub async fn register(trigger: &str, tx: mpsc::UnboundedSender<()>) -> Result<HotkeySession> {
    let conn = Connection::session()
        .await
        .context("connecting to the session bus")?;

    let shortcuts = GlobalShortcutsProxy::new(&conn)
        .await
        .context("connecting to the GlobalShortcuts portal (is xdg-desktop-portal-kde running?)")?;

    // Every portal call replies asynchronously on a Request object whose path
    // we compute ourselves and must subscribe to *before* making the call: the
    // portal is free to reply before the method call returns, and a
    // subscription set up afterwards would miss it and wait forever.
    let sender = conn
        .unique_name()
        .ok_or_else(|| anyhow!("the D-Bus connection has no unique name"))?
        .trim_start_matches(':')
        .replace('.', "_");

    // --- CreateSession ---------------------------------------------------
    let create_token = "sypherstore_create";
    let create_proxy = RequestProxy::builder(&conn)
        .path(request_path(&sender, create_token)?)?
        .build()
        .await
        .context("subscribing to the CreateSession reply")?;
    let mut create_replies = create_proxy.receive_response().await?;

    let mut options: HashMap<&str, Value<'_>> = HashMap::new();
    options.insert("handle_token", Value::from(create_token));
    // The fixed token is what makes the registration survive restarts.
    options.insert("session_handle_token", Value::from(SESSION_TOKEN));
    shortcuts
        .create_session(options)
        .await
        .context("calling CreateSession")?;

    let reply = create_replies
        .next()
        .await
        .ok_or_else(|| anyhow!("the portal closed before answering CreateSession"))?;
    let args = reply.args().context("decoding the CreateSession reply")?;
    if args.response != 0 {
        return Err(anyhow!(
            "the portal refused to create a shortcuts session (response {})",
            args.response
        ));
    }
    let session = extract_session_handle(&args.results)?;
    tracing::debug!(session = %session.as_str(), "shortcuts session created");

    // --- BindShortcuts ---------------------------------------------------
    let portal_trigger = to_portal_trigger(trigger);
    tracing::info!(
        configured = trigger,
        portal = %portal_trigger,
        "requesting global shortcut"
    );

    let bind_token = "sypherstore_bind";
    let bind_proxy = RequestProxy::builder(&conn)
        .path(request_path(&sender, bind_token)?)?
        .build()
        .await
        .context("subscribing to the BindShortcuts reply")?;
    let mut bind_replies = bind_proxy.receive_response().await?;

    // Subscribe to activations before binding, for the same race reason.
    let mut activations = shortcuts
        .receive_activated()
        .await
        .context("subscribing to shortcut activations")?;

    let mut shortcut_meta: HashMap<&str, Value<'_>> = HashMap::new();
    shortcut_meta.insert("description", Value::from(SHORTCUT_DESCRIPTION));
    shortcut_meta.insert("preferred_trigger", Value::from(portal_trigger.as_str()));

    let mut bind_options: HashMap<&str, Value<'_>> = HashMap::new();
    bind_options.insert("handle_token", Value::from(bind_token));

    shortcuts
        .bind_shortcuts(
            &session.as_ref(),
            &[(SHORTCUT_ID, shortcut_meta)],
            "",
            bind_options,
        )
        .await
        .context("calling BindShortcuts")?;

    let reply = bind_replies
        .next()
        .await
        .ok_or_else(|| anyhow!("the portal closed before answering BindShortcuts"))?;
    let args = reply.args().context("decoding the BindShortcuts reply")?;
    if args.response != 0 {
        // 1 means the user cancelled; 2 means it ended some other way.
        return Err(anyhow!(
            "the shortcut request was refused (response {}). Check System Settings > Shortcuts.",
            args.response
        ));
    }
    tracing::info!("shortcut bound");

    tokio::spawn(async move {
        while let Some(activation) = activations.next().await {
            let Ok(args) = activation.args() else {
                continue;
            };
            if args.shortcut_id != SHORTCUT_ID {
                continue;
            }
            tracing::info!("hotkey activated");
            if tx.send(()).is_err() {
                // The receiver is gone, which means the daemon is shutting
                // down. Nothing left to deliver to.
                break;
            }
        }
        tracing::debug!("shortcut activation stream ended");
    });

    Ok(HotkeySession {
        _conn: conn,
        _session: session,
    })
}

/// Pulls the session handle out of a `CreateSession` reply.
///
/// The specification says this is an object path, but backends have shipped it
/// as a plain string, so both are accepted.
fn extract_session_handle(results: &HashMap<String, OwnedValue>) -> Result<OwnedObjectPath> {
    let value = results
        .get("session_handle")
        .ok_or_else(|| anyhow!("the portal returned no session_handle"))?;

    if let Ok(path) = OwnedObjectPath::try_from(value.clone()) {
        return Ok(path);
    }
    let text = String::try_from(value.clone())
        .map_err(|e| anyhow!("session_handle was neither a path nor a string: {e}"))?;
    ObjectPath::try_from(text.clone())
        .map(Into::into)
        .map_err(|e| anyhow!("session_handle {text:?} is not a valid object path: {e}"))
}

/// Builds the object path the portal will use for a request's reply.
///
/// The portal specifies this layout precisely so that callers can subscribe
/// before making the call, closing the race where the reply arrives first.
fn request_path(sender: &str, token: &str) -> Result<OwnedObjectPath> {
    let path = format!("/org/freedesktop/portal/desktop/request/{sender}/{token}");
    ObjectPath::try_from(path.clone())
        .map(Into::into)
        .map_err(|e| anyhow!("invalid request path {path}: {e}"))
}

/// Translates a Plasma-style accelerator into XDG shortcut syntax.
///
/// `Meta+Shift+V` becomes `LOGO+SHIFT+v`. Modifiers are uppercased and mapped
/// to the four the specification defines; the final key is lowercased, since
/// XKB keysym names for letters are lowercase and passing `V` would name a
/// different keysym than intended.
///
/// Unrecognized modifier names are passed through untouched rather than
/// dropped, so a user who knows the XDG syntax can write it directly in the
/// config and have it reach the portal unchanged.
pub fn to_portal_trigger(accelerator: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    let segments: Vec<&str> = accelerator
        .split('+')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    let Some((key, modifiers)) = segments.split_last() else {
        return String::new();
    };

    for m in modifiers {
        let mapped = match m.to_ascii_lowercase().as_str() {
            "meta" | "super" | "logo" | "win" => "LOGO",
            "ctrl" | "control" => "CTRL",
            "alt" => "ALT",
            "shift" => "SHIFT",
            _ => {
                parts.push((*m).to_string());
                continue;
            }
        };
        parts.push(mapped.to_string());
    }

    // Single characters become lowercase keysym names; multi-character names
    // like `F1`, `Space` or `Return` are already correct keysym names and must
    // keep their case.
    let key = if key.chars().count() == 1 {
        key.to_ascii_lowercase()
    } else {
        (*key).to_string()
    };
    parts.push(key);
    parts.join("+")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_the_default_hotkey() {
        assert_eq!(to_portal_trigger("Meta+Shift+V"), "LOGO+SHIFT+v");
    }

    #[test]
    fn accepts_the_common_modifier_spellings() {
        for input in ["Meta+V", "Super+V", "super+v", "WIN+V", "LOGO+v"] {
            assert_eq!(to_portal_trigger(input), "LOGO+v", "input {input}");
        }
        assert_eq!(to_portal_trigger("Ctrl+Alt+P"), "CTRL+ALT+p");
        assert_eq!(to_portal_trigger("Control+p"), "CTRL+p");
    }

    #[test]
    fn named_keys_keep_their_case() {
        // `F1` and `Space` are keysym names; lowercasing them would name a
        // different key or none at all.
        assert_eq!(to_portal_trigger("Meta+F1"), "LOGO+F1");
        assert_eq!(to_portal_trigger("Ctrl+Space"), "CTRL+Space");
        assert_eq!(to_portal_trigger("Meta+Shift+Return"), "LOGO+SHIFT+Return");
    }

    #[test]
    fn a_bare_key_needs_no_modifiers() {
        assert_eq!(to_portal_trigger("F12"), "F12");
    }

    #[test]
    fn whitespace_and_empty_segments_are_tolerated() {
        assert_eq!(to_portal_trigger(" Meta + Shift + V "), "LOGO+SHIFT+v");
        assert_eq!(to_portal_trigger("Meta++V"), "LOGO+v");
    }

    #[test]
    fn an_empty_accelerator_yields_an_empty_trigger() {
        assert_eq!(to_portal_trigger(""), "");
        assert_eq!(to_portal_trigger("+++"), "");
    }

    #[test]
    fn unknown_modifiers_pass_through_unchanged() {
        // Lets a user write raw XDG syntax in the config if they want to.
        assert_eq!(to_portal_trigger("HYPER+v"), "HYPER+v");
    }

    #[test]
    fn request_paths_follow_the_portal_layout() {
        let path = request_path("1_42", "sypherstore_create").unwrap();
        assert_eq!(
            path.as_str(),
            "/org/freedesktop/portal/desktop/request/1_42/sypherstore_create"
        );
    }

    #[test]
    fn the_session_token_is_fixed() {
        // The registration surviving restarts depends entirely on this being
        // constant. A test pins it so a future refactor cannot quietly
        // randomize it and reintroduce the orphaned-component bug.
        assert_eq!(SESSION_TOKEN, "sypherstore");
    }
}
