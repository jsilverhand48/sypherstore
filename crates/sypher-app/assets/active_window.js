// KWin script: report the active window to the Sypherstore daemon.
//
// Why a KWin script at all: Wayland gives clients no way to ask "what window
// has focus?". That is deliberate, and it is the same isolation that makes
// Wayland worth using. The compositor does know, and KWin exposes its
// scripting API over D-Bus, so the supported route is to run a small script
// inside KWin that pushes the answer out to us.
//
// The push direction matters. Querying KWin at hotkey time would put a D-Bus
// round trip on the critical path between the keypress and the popup
// appearing. Instead this fires on every window activation and the daemon
// caches the last value, so by the time the user presses the hotkey the
// answer is already sitting in memory.
//
// Nothing here is security sensitive: window class and caption are already
// visible to every application on the session through the task manager.

function report(window) {
    if (!window) {
        return;
    }

    // Sypherstore's own popup must never overwrite the cached value, or
    // opening it would immediately forget which window the user came from.
    var cls = (window.resourceClass || "").toString();
    if (cls.toLowerCase().indexOf("sypherstore") !== -1) {
        return;
    }

    callDBus(
        "org.sypherstore.Daemon1",
        "/org/sypherstore/Daemon1",
        "org.sypherstore.Daemon1",
        "SetActiveWindow",
        cls,
        (window.caption || "").toString()
    );
}

// KWin 6 renamed the signal; support both so the script does not silently do
// nothing on one version or the other.
if (typeof workspace.windowActivated !== "undefined") {
    workspace.windowActivated.connect(report);
} else if (typeof workspace.clientActivated !== "undefined") {
    workspace.clientActivated.connect(report);
}

// Report whatever is focused right now, so the daemon is not blind until the
// user next switches windows.
if (typeof workspace.activeWindow !== "undefined") {
    report(workspace.activeWindow);
} else if (typeof workspace.activeClient !== "undefined") {
    report(workspace.activeClient);
}
