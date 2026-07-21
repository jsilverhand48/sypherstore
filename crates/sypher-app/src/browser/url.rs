//! Reading the focused browser's URL over AT-SPI2.
//!
//! ## Why the accessibility bus
//!
//! There is no Wayland protocol for "what URL is the focused tab showing", and
//! there should not be. The accessibility stack is the one interface browsers
//! already expose their document structure through, for screen readers. A
//! browser that reports its address to Orca reports it to us the same way.
//!
//! AT-SPI2 is plain D-Bus, so this talks to it directly rather than pulling in
//! a protocol crate: the surface actually needed is three method calls, and
//! hand-rolling them keeps the walk bounded and the failure modes visible.
//!
//! ## This is best effort, by design
//!
//! Every step here can fail for reasons outside our control:
//!
//! - The user may have accessibility support switched off entirely, in which
//!   case browsers publish nothing.
//! - Firefox historically needs `GNOME_ACCESSIBILITY=1` or an AT already
//!   running before it populates its tree.
//! - A browser may be mid-navigation and expose no document.
//!
//! So the whole pipeline runs under a hard timeout and any failure degrades to
//! `None`, which the caller turns into "show every secret". A filter that
//! occasionally shows too much is a minor annoyance; one that makes the user
//! wait, or hides the credential they need, is not.

use std::time::Duration;

use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue};
use zbus::Connection;

/// How deep to walk an application's accessibility tree.
///
/// A browser's document sits a handful of levels below the application root
/// (app -> window -> ... -> document). The limit stops a pathological or
/// cyclic tree from burning the whole time budget.
const MAX_DEPTH: usize = 6;

/// How many children to examine at each level.
///
/// A page can expose thousands of nodes. We only ever need the frame and
/// document near the top, so a wide sweep would be pure cost.
const MAX_BREADTH: usize = 24;

/// AT-SPI roles that carry a document URL.
const DOCUMENT_ROLES: [&str; 4] = [
    "document web",
    "document frame",
    "document",
    "embedded",
];

/// Looks up the URL of the focused document in `app_name`'s window.
///
/// Returns `None` on any failure, including the timeout. Never returns an
/// error, because there is nothing the caller could usefully do differently.
pub async fn focused_url(app_hint: &str, budget: Duration) -> Option<String> {
    match tokio::time::timeout(budget, find_url(app_hint)).await {
        Ok(Ok(Some(url))) => {
            tracing::debug!("resolved a URL from the accessibility tree");
            Some(url)
        }
        Ok(Ok(None)) => {
            tracing::debug!("no document URL exposed by the focused application");
            None
        }
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "accessibility lookup failed");
            None
        }
        Err(_) => {
            // Expected often enough not to be a warning: a cold a11y bus can
            // take longer than the budget on the first call.
            tracing::debug!(
                budget_ms = budget.as_millis(),
                "accessibility lookup timed out; showing all secrets"
            );
            None
        }
    }
}

/// The lookup proper, without the timeout wrapper.
async fn find_url(app_hint: &str) -> Result<Option<String>, zbus::Error> {
    let conn = a11y_connection().await?;

    // The registry's root lists one child per accessible application.
    let root = Accessible {
        bus: "org.a11y.atspi.Registry".to_string(),
        path: ObjectPath::try_from("/org/a11y/atspi/accessible/root")?.into(),
    };

    let hint = app_hint.to_ascii_lowercase();
    for app in root.children(&conn).await?.into_iter().take(MAX_BREADTH) {
        let name = app.name(&conn).await.unwrap_or_default().to_ascii_lowercase();
        // The a11y application name and the window class rarely match
        // exactly ("Firefox" vs "firefox", "Chromium" vs "Chromium-browser"),
        // so accept a substring match either way round.
        if name.is_empty() || !(name.contains(&hint) || hint.contains(&name)) {
            continue;
        }
        tracing::debug!(app = %name, "found the browser in the accessibility tree");
        if let Some(url) = app.find_document_url(&conn, 0).await {
            return Ok(Some(url));
        }
    }
    Ok(None)
}

/// Opens a connection to the accessibility bus.
///
/// This is a separate bus from the session bus, and its address has to be
/// fetched from `org.a11y.Bus` on the session bus first.
async fn a11y_connection() -> Result<Connection, zbus::Error> {
    let session = Connection::session().await?;
    let address: String = session
        .call_method(
            Some("org.a11y.Bus"),
            "/org/a11y/bus",
            Some("org.a11y.Bus"),
            "GetAddress",
            &(),
        )
        .await?
        .body()
        .deserialize()?;

    zbus::connection::Builder::address(address.as_str())?
        .build()
        .await
}

/// One node in the accessibility tree.
///
/// AT-SPI addresses objects by a pair of bus name and object path, so a plain
/// path is not enough to talk to one.
#[derive(Debug, Clone)]
struct Accessible {
    bus: String,
    path: OwnedObjectPath,
}

impl Accessible {
    /// This node's children.
    async fn children(&self, conn: &Connection) -> Result<Vec<Accessible>, zbus::Error> {
        let reply = conn
            .call_method(
                Some(self.bus.as_str()),
                &self.path,
                Some("org.a11y.atspi.Accessible"),
                "GetChildren",
                &(),
            )
            .await?;
        let raw: Vec<(String, OwnedObjectPath)> = reply.body().deserialize()?;
        Ok(raw
            .into_iter()
            .map(|(bus, path)| Accessible { bus, path })
            .collect())
    }

    /// The node's accessible name.
    async fn name(&self, conn: &Connection) -> Result<String, zbus::Error> {
        self.property(conn, "Name").await
    }

    /// The node's role, lowercased, e.g. `document web`.
    async fn role(&self, conn: &Connection) -> Result<String, zbus::Error> {
        let reply = conn
            .call_method(
                Some(self.bus.as_str()),
                &self.path,
                Some("org.a11y.atspi.Accessible"),
                "GetRoleName",
                &(),
            )
            .await?;
        let role: String = reply.body().deserialize()?;
        Ok(role.to_ascii_lowercase())
    }

    async fn property(&self, conn: &Connection, name: &str) -> Result<String, zbus::Error> {
        let reply = conn
            .call_method(
                Some(self.bus.as_str()),
                &self.path,
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &("org.a11y.atspi.Accessible", name),
            )
            .await?;
        let value: OwnedValue = reply.body().deserialize()?;
        Ok(String::try_from(value).unwrap_or_default())
    }

    /// Walks down looking for a document node and returns its URL.
    ///
    /// Depth-first with both depth and breadth capped; the document is near
    /// the top of a browser's tree, so a bounded search finds it or it is not
    /// there to find.
    fn find_document_url<'a>(
        &'a self,
        conn: &'a Connection,
        depth: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send + 'a>> {
        Box::pin(async move {
            if depth >= MAX_DEPTH {
                return None;
            }

            if let Ok(role) = self.role(conn).await {
                if DOCUMENT_ROLES.iter().any(|r| role.contains(r)) {
                    if let Some(url) = self.document_url(conn).await {
                        return Some(url);
                    }
                }
            }

            let children = self.children(conn).await.ok()?;
            for child in children.into_iter().take(MAX_BREADTH) {
                if let Some(url) = child.find_document_url(conn, depth + 1).await {
                    return Some(url);
                }
            }
            None
        })
    }

    /// Reads the URL from a document node's attributes.
    ///
    /// Browsers disagree on the key: Chromium uses `DocURL`, Firefox has used
    /// both `DocURL` and `URI`, so all the known spellings are tried.
    async fn document_url(&self, conn: &Connection) -> Option<String> {
        let reply = conn
            .call_method(
                Some(self.bus.as_str()),
                &self.path,
                Some("org.a11y.atspi.Document"),
                "GetAttributes",
                &(),
            )
            .await
            .ok()?;
        let attributes: std::collections::HashMap<String, String> =
            reply.body().deserialize().ok()?;

        for key in ["DocURL", "URI", "URL", "docurl", "uri"] {
            if let Some(value) = attributes.get(key) {
                if !value.is_empty() {
                    return Some(value.clone());
                }
            }
        }
        None
    }
}

/// Whether the accessibility stack looks usable.
///
/// Reported by `doctor` so a user whose browser filtering silently does
/// nothing can find out why.
pub fn accessibility_available() -> bool {
    std::path::Path::new("/run/user")
        .join(
            nix_uid()
                .map(|u| u.to_string())
                .unwrap_or_else(|| "0".into()),
        )
        .join("at-spi")
        .exists()
}

fn nix_uid() -> Option<u32> {
    Some(unsafe { libc::getuid() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_roles_cover_the_major_browsers() {
        // Chromium reports "document web"; Firefox has used "document frame".
        assert!(DOCUMENT_ROLES.contains(&"document web"));
        assert!(DOCUMENT_ROLES.contains(&"document frame"));
    }

    #[test]
    fn the_walk_is_bounded() {
        // These caps are what stop a pathological tree from eating the whole
        // time budget, so they are worth pinning against a careless edit.
        assert!(MAX_DEPTH <= 8, "a deeper walk risks blowing the budget");
        assert!(MAX_BREADTH <= 64, "a wider sweep risks blowing the budget");
    }

    #[tokio::test]
    async fn a_zero_budget_degrades_instead_of_hanging() {
        // The contract the popup depends on: never block, never error.
        let url = focused_url("firefox", Duration::from_millis(0)).await;
        assert!(url.is_none());
    }

    #[tokio::test]
    async fn an_unknown_application_yields_no_url() {
        let url = focused_url(
            "definitely-not-a-real-browser-xyz",
            Duration::from_millis(300),
        )
        .await;
        assert!(url.is_none());
    }
}
