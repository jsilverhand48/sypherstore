//! Tracking which window the user was in before the popup opened.
//!
//! Wayland gives clients no way to ask what has focus, by design. The
//! compositor does know, and KWin exposes its scripting API over D-Bus, so the
//! supported route is to load a small script into KWin that pushes activation
//! events out to us.
//!
//! The direction of the flow is the important part. Asking KWin at hotkey time
//! would put a D-Bus round trip between the keypress and the popup appearing.
//! Instead the script fires on every window activation and this module caches
//! the result, so the answer is already in memory when the hotkey arrives.
//!
//! Failure here is never fatal. If the script cannot be loaded (a different
//! compositor, a KWin API change, a locked-down session) the cache simply
//! stays empty and the popup shows every secret, which is the documented
//! degradation.

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use zbus::interface;

/// The window that had focus before the popup opened.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActiveWindow {
    /// `resourceClass`, e.g. `firefox`, `code`, `org.kde.konsole`.
    pub class: String,
    /// Window title. For a browser this usually contains the page title, and
    /// occasionally the URL, but it is not reliable enough to parse for one.
    pub caption: String,
}

impl ActiveWindow {
    /// Whether this looks like a web browser.
    ///
    /// Matched on a substring of the lowercased class because the real values
    /// vary by packaging: `firefox`, `Firefox`, `firefox-esr`,
    /// `Google-chrome`, `Chromium-browser`, `brave-browser` and so on.
    pub fn is_browser(&self) -> bool {
        let class = self.class.to_ascii_lowercase();
        const BROWSERS: [&str; 8] = [
            "firefox", "chrome", "chromium", "edge", "brave", "opera", "vivaldi", "librewolf",
        ];
        BROWSERS.iter().any(|b| class.contains(b))
    }

    /// A short application name for matching against a secret's
    /// `application` field, with packaging noise stripped.
    ///
    /// `org.kde.konsole` becomes `konsole`, `Google-chrome` becomes
    /// `google-chrome`, so a user can write the obvious thing in the editor.
    pub fn app_name(&self) -> String {
        self.class
            .rsplit('.')
            .next()
            .unwrap_or(&self.class)
            .to_ascii_lowercase()
    }
}

/// Shared cache written by the D-Bus service and read at hotkey time.
#[derive(Clone, Default)]
pub struct WindowTracker {
    current: Arc<Mutex<ActiveWindow>>,
}

impl WindowTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// The most recently activated non-Sypherstore window.
    pub fn current(&self) -> ActiveWindow {
        self.current
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn set(&self, window: ActiveWindow) {
        tracing::debug!(class = %window.class, "active window changed");
        *self.current.lock().unwrap_or_else(|e| e.into_inner()) = window;
    }
}

/// The D-Bus object KWin's script calls into.
struct DaemonService {
    tracker: WindowTracker,
}

#[interface(name = "org.sypherstore.Daemon1")]
impl DaemonService {
    /// Called by the KWin script on every window activation.
    fn set_active_window(&self, class: String, caption: String) {
        self.tracker.set(ActiveWindow { class, caption });
    }
}

/// Owns the D-Bus name and the loaded KWin script.
///
/// Dropping it releases the bus name; the script is unloaded explicitly by
/// [`Kwin::shutdown`] so KWin does not keep calling a service that is gone.
pub struct Kwin {
    connection: zbus::Connection,
    script_name: String,
}

/// Registers the D-Bus service and loads the KWin script.
///
/// Returns the tracker regardless of whether KWin cooperated: a tracker that
/// never updates is exactly the show-everything fallback.
pub async fn start(tracker: WindowTracker) -> Result<Kwin> {
    let connection = zbus::connection::Builder::session()
        .context("connecting to the session bus")?
        .name("org.sypherstore.Daemon1")
        .context("claiming the org.sypherstore.Daemon1 bus name")?
        .serve_at(
            "/org/sypherstore/Daemon1",
            DaemonService {
                tracker: tracker.clone(),
            },
        )
        .context("exporting the daemon service")?
        .build()
        .await
        .context("starting the daemon service")?;

    // A fresh name each run: KWin refuses to load a script whose name is
    // already registered, and a crashed daemon leaves its old one behind.
    let script_name = format!("sypherstore-{}", std::process::id());
    let script_path = write_script().await?;

    let kwin = KwinScriptingProxy::new(&connection)
        .await
        .context("connecting to KWin's scripting interface")?;

    let id = kwin
        .load_script(&script_path.to_string_lossy(), &script_name)
        .await
        .context("loading the active-window script into KWin")?;

    // KWin loads scripts in a stopped state; nothing happens until `run`.
    let script = KwinScriptProxy::builder(&connection)
        .path(format!("/Scripting/Script{id}"))?
        .build()
        .await
        .context("addressing the loaded script")?;
    script.run().await.context("starting the KWin script")?;

    tracing::info!(script = %script_name, "active-window tracking started");
    Ok(Kwin {
        connection,
        script_name,
    })
}

impl Kwin {
    /// Unloads the script so KWin stops calling a service that is going away.
    pub async fn shutdown(&self) {
        if let Ok(kwin) = KwinScriptingProxy::new(&self.connection).await {
            let _ = kwin.unload_script(&self.script_name).await;
            tracing::debug!("KWin script unloaded");
        }
    }
}

/// Writes the bundled script to a file KWin can read.
///
/// KWin's `loadScript` takes a path, not source, so the asset compiled into
/// the binary has to land on disk somewhere first.
async fn write_script() -> Result<std::path::PathBuf> {
    const SCRIPT: &str = include_str!("../../assets/active_window.js");

    let dir = dirs::runtime_dir()
        .or_else(dirs::cache_dir)
        .context("no runtime or cache directory for the KWin script")?
        .join("sypherstore");
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("creating {}", dir.display()))?;

    let path = dir.join("active_window.js");
    tokio::fs::write(&path, SCRIPT)
        .await
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

#[zbus::proxy(
    interface = "org.kde.kwin.Scripting",
    default_service = "org.kde.KWin",
    default_path = "/Scripting"
)]
trait KwinScripting {
    // KWin exposes Qt-style lowerCamelCase names. Without these attributes
    // zbus would derive `LoadScript`, which the interface does not have.
    #[zbus(name = "loadScript")]
    fn load_script(&self, file_path: &str, plugin_name: &str) -> zbus::Result<i32>;
    #[zbus(name = "unloadScript")]
    fn unload_script(&self, plugin_name: &str) -> zbus::Result<bool>;
}

#[zbus::proxy(interface = "org.kde.kwin.Script", default_service = "org.kde.KWin")]
trait KwinScript {
    #[zbus(name = "run")]
    fn run(&self) -> zbus::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(class: &str) -> ActiveWindow {
        ActiveWindow {
            class: class.into(),
            caption: String::new(),
        }
    }

    #[test]
    fn recognizes_the_browsers_people_actually_use() {
        for class in [
            "firefox",
            "Firefox",
            "firefox-esr",
            "Navigator.firefox",
            "google-chrome",
            "Google-chrome",
            "chromium",
            "Chromium-browser",
            "brave-browser",
            "microsoft-edge",
            "Vivaldi-stable",
            "librewolf",
        ] {
            assert!(window(class).is_browser(), "{class} should be a browser");
        }
    }

    #[test]
    fn does_not_mistake_other_applications_for_browsers() {
        for class in ["konsole", "org.kde.dolphin", "code", "slack", "kate", ""] {
            assert!(!window(class).is_browser(), "{class} is not a browser");
        }
    }

    #[test]
    fn app_name_strips_reverse_dns_prefixes() {
        // So a user can write "konsole" in the editor rather than the full
        // desktop-file id.
        assert_eq!(window("org.kde.konsole").app_name(), "konsole");
        assert_eq!(window("org.telegram.desktop").app_name(), "desktop");
        assert_eq!(window("Slack").app_name(), "slack");
        assert_eq!(window("code").app_name(), "code");
    }

    #[test]
    fn the_tracker_starts_empty_and_remembers_the_last_window() {
        let tracker = WindowTracker::new();
        assert_eq!(tracker.current(), ActiveWindow::default());

        tracker.set(window("firefox"));
        assert_eq!(tracker.current().class, "firefox");

        tracker.set(window("konsole"));
        assert_eq!(tracker.current().class, "konsole");
    }

    #[test]
    fn the_tracker_is_shared_between_clones() {
        // The D-Bus service holds one clone and the worker another; they must
        // observe the same value.
        let a = WindowTracker::new();
        let b = a.clone();
        a.set(window("firefox"));
        assert_eq!(b.current().class, "firefox");
    }
}
