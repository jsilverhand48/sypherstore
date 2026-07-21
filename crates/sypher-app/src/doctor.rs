//! Environment diagnostics.
//!
//! Sypherstore depends on a fairly specific stack: a TPM the user can reach
//! without root, a FIDO2 authenticator whose hidraw node is accessible, a
//! Wayland session, and a working portal implementation. When any of those is
//! missing the failure usually surfaces much later as a confusing permission
//! error deep inside a C library.
//!
//! `doctor` front-loads those checks and, more importantly, tells the user how
//! to fix each one. Every failing check carries a concrete remedy, because a
//! diagnostic that only says "TPM not accessible" leaves the user no better
//! off than the original error did.

use std::fmt;
use std::path::Path;

use sypher_core::vault::paths::VaultPaths;

/// Outcome of a single check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Everything needed is present.
    Ok,
    /// Works, but degraded or not recommended.
    Warn,
    /// Sypherstore will not function until this is fixed.
    Fail,
}

impl Status {
    fn glyph(&self) -> &'static str {
        match self {
            Status::Ok => "[ ok ]",
            Status::Warn => "[warn]",
            Status::Fail => "[fail]",
        }
    }
}

/// One diagnostic result.
#[derive(Debug, Clone)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub detail: String,
    /// Shown only when the check did not pass.
    pub remedy: Option<String>,
}

impl Check {
    fn ok(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Ok,
            detail: detail.into(),
            remedy: None,
        }
    }

    fn warn(name: &str, detail: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Warn,
            detail: detail.into(),
            remedy: Some(remedy.into()),
        }
    }

    fn fail(name: &str, detail: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Fail,
            detail: detail.into(),
            remedy: Some(remedy.into()),
        }
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {:<22} {}", self.status.glyph(), self.name, self.detail)?;
        if let Some(remedy) = &self.remedy {
            write!(f, "\n       -> {remedy}")?;
        }
        Ok(())
    }
}

/// The full diagnostic report.
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    /// Whether any check failed outright.
    pub fn has_failures(&self) -> bool {
        self.checks.iter().any(|c| c.status == Status::Fail)
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let mut ok = 0;
        let mut warn = 0;
        let mut fail = 0;
        for c in &self.checks {
            match c.status {
                Status::Ok => ok += 1,
                Status::Warn => warn += 1,
                Status::Fail => fail += 1,
            }
        }
        (ok, warn, fail)
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in &self.checks {
            writeln!(f, "{c}")?;
        }
        let (ok, warn, fail) = self.counts();
        write!(f, "\n{ok} ok, {warn} warnings, {fail} failures")
    }
}

/// Runs every check against the current machine.
pub fn run(paths: &VaultPaths) -> Report {
    Report {
        checks: vec![
            check_session_type(),
            check_tpm(),
            check_tss_group(),
            check_fido_device(),
            check_portals(),
            check_memlock(),
            check_ptrace_scope(),
            check_accessibility(),
            check_vault_dir(paths),
            check_log_dir(),
            check_build_flavor(),
        ],
    }
}

/// Wayland is required: the hotkey and paste paths both go through portals
/// that have no X11 equivalent in this design.
fn check_session_type() -> Check {
    match std::env::var("XDG_SESSION_TYPE").as_deref() {
        Ok("wayland") => {
            let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
            Check::ok("session", format!("wayland ({desktop})"))
        }
        Ok(other) => Check::fail(
            "session",
            format!("XDG_SESSION_TYPE={other}"),
            "Sypherstore targets Wayland. Log into a Plasma (Wayland) session.",
        ),
        Err(_) => Check::warn(
            "session",
            "XDG_SESSION_TYPE is unset",
            "Expected in a graphical session; the CLI still works.",
        ),
    }
}

/// The kernel resource-manager device is preferred over `/dev/tpm0` because it
/// multiplexes access, so we do not fight other TPM users for the single
/// direct handle.
fn check_tpm() -> Check {
    let rm = Path::new("/dev/tpmrm0");
    let raw = Path::new("/dev/tpm0");

    if !rm.exists() && !raw.exists() {
        return Check::fail(
            "tpm device",
            "no /dev/tpmrm0 or /dev/tpm0",
            "No TPM 2.0 found. Check that it is enabled in UEFI setup.",
        );
    }
    if !rm.exists() {
        return Check::warn(
            "tpm device",
            "/dev/tpm0 exists but /dev/tpmrm0 does not",
            "The resource manager is preferred; check the tpm_crb/tpm_tis kernel modules.",
        );
    }
    match is_accessible(rm) {
        true => Check::ok("tpm device", "/dev/tpmrm0 readable and writable"),
        false => Check::fail(
            "tpm device",
            "/dev/tpmrm0 exists but is not writable by this user",
            "Add yourself to the 'tss' group: sudo usermod -aG tss $USER, then log out and back in.",
        ),
    }
}

/// Group membership is reported separately from device access because the two
/// can disagree: a fresh `usermod` does not affect the current session, which
/// is a confusing state to land in.
fn check_tss_group() -> Check {
    match group_members("tss") {
        None => Check::warn(
            "tss group",
            "no 'tss' group on this system",
            "Install tpm2-tss. Device permissions may be granted another way.",
        ),
        Some(members) => {
            let user = std::env::var("USER").unwrap_or_default();
            if members.iter().any(|m| *m == user) || in_supplementary_group("tss") {
                Check::ok("tss group", format!("{user} is a member"))
            } else {
                Check::warn(
                    "tss group",
                    format!("{user} is not in the 'tss' group"),
                    "sudo usermod -aG tss $USER, then log out and back in for it to take effect.",
                )
            }
        }
    }
}

/// A FIDO2 authenticator shows up as a `/dev/hidraw*` node. Being able to
/// enumerate one is necessary but not sufficient: the node must also be
/// readable, which on Arch is what the `u2f` udev rules provide.
fn check_fido_device() -> Check {
    let entries = match std::fs::read_dir("/dev") {
        Ok(e) => e,
        Err(e) => {
            return Check::warn("fido device", format!("cannot scan /dev: {e}"), "Unexpected; check permissions on /dev.")
        }
    };

    let mut found = 0usize;
    let mut accessible = 0usize;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("hidraw") {
            continue;
        }
        found += 1;
        if is_accessible(&entry.path()) {
            accessible += 1;
        }
    }

    if found == 0 {
        return Check::fail(
            "fido device",
            "no /dev/hidraw* nodes found",
            "Plug in your YubiKey. If it is plugged in, check `lsusb` for it.",
        );
    }
    if accessible == 0 {
        return Check::fail(
            "fido device",
            format!("{found} hidraw node(s), none accessible to this user"),
            concat!(
                "Install a udev rule granting access. Create ",
                "/etc/udev/rules.d/70-u2f.rules containing:\n",
                "          KERNEL==\"hidraw*\", SUBSYSTEM==\"hidraw\", ",
                "ATTRS{idVendor}==\"1050\", TAG+=\"uaccess\"\n",
                "          then: sudo udevadm control --reload && sudo udevadm trigger"
            ),
        );
    }
    Check::ok(
        "fido device",
        format!("{accessible} of {found} hidraw node(s) accessible"),
    )
}

/// The portals carry the global hotkey and the synthetic keystrokes. Their
/// presence is checked by looking for the service files rather than by
/// making a DBus call, so `doctor` stays dependency-free and fast.
fn check_portals() -> Check {
    let dirs = [
        "/usr/share/xdg-desktop-portal/portals",
        "/usr/local/share/xdg-desktop-portal/portals",
    ];
    let mut backends = Vec::new();
    for dir in dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                if let Some(name) = e.file_name().to_str() {
                    if let Some(stem) = name.strip_suffix(".portal") {
                        backends.push(stem.to_string());
                    }
                }
            }
        }
    }

    if backends.is_empty() {
        return Check::fail(
            "xdg portals",
            "no portal backends installed",
            "sudo pacman -S xdg-desktop-portal xdg-desktop-portal-kde",
        );
    }
    if !backends.iter().any(|b| b.contains("kde")) {
        return Check::warn(
            "xdg portals",
            format!("found: {}", backends.join(", ")),
            "The KDE backend provides GlobalShortcuts on Plasma: sudo pacman -S xdg-desktop-portal-kde",
        );
    }
    Check::ok("xdg portals", format!("found: {}", backends.join(", ")))
}

/// `mlock` needs `RLIMIT_MEMLOCK` headroom. The vault's needs are tiny (a few
/// keys and one plaintext at a time), but a 64 KiB limit on an older system
/// would silently degrade every `SecureBuf`.
fn check_memlock() -> Check {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) };
    if rc != 0 {
        return Check::warn(
            "memlock limit",
            "could not read RLIMIT_MEMLOCK",
            "Secrets may be pageable; check `ulimit -l`.",
        );
    }
    if lim.rlim_cur == libc::RLIM_INFINITY {
        return Check::ok("memlock limit", "unlimited");
    }
    let kib = lim.rlim_cur / 1024;
    if lim.rlim_cur < 256 * 1024 {
        Check::warn(
            "memlock limit",
            format!("{kib} KiB"),
            "Low. Raise it with a limits.conf entry so secrets cannot be swapped out.",
        )
    } else {
        Check::ok("memlock limit", format!("{kib} KiB"))
    }
}

/// Browser URL detection reads the focused page's address over AT-SPI. If the
/// accessibility stack is not running, that silently returns nothing and the
/// popup shows every secret, so it is worth saying so out loud.
fn check_accessibility() -> Check {
    if !crate::browser::url::accessibility_available() {
        return Check::warn(
            "accessibility",
            "no AT-SPI bus found",
            "Browser URL filtering will be skipped and the popup will show all secrets. \
             Install at-spi2-core to enable it.",
        );
    }
    // Firefox in particular only populates its tree when it believes an
    // assistive technology is present.
    let toolkit_on = std::env::var("QT_ACCESSIBILITY").is_ok_and(|v| v == "1")
        || std::env::var("GNOME_ACCESSIBILITY").is_ok_and(|v| v == "1");
    if toolkit_on {
        Check::ok("accessibility", "AT-SPI bus present, toolkit support enabled")
    } else {
        Check::warn(
            "accessibility",
            "AT-SPI bus present, but toolkit support is not switched on",
            "Firefox may not expose its URL. Set GNOME_ACCESSIBILITY=1 (and QT_ACCESSIBILITY=1) \
             in your session to enable per-site filtering.",
        )
    }
}

/// The daemon cannot mark itself non-dumpable without breaking the portals,
/// so Yama is what stops another same-uid process from attaching to it and
/// reading an unlocked key straight out of memory.
fn check_ptrace_scope() -> Check {
    match sypher_core::secure::yama_ptrace_scope() {
        None => Check::warn(
            "ptrace protection",
            "the Yama LSM is not available",
            "Any process running as you could attach to the daemon and read unlocked keys. \
             Enable CONFIG_SECURITY_YAMA, or accept the risk.",
        ),
        Some(0) => Check::warn(
            "ptrace protection",
            "kernel.yama.ptrace_scope = 0 (unrestricted)",
            "Any process running as you could read the daemon's memory. Set \
             kernel.yama.ptrace_scope=1 in /etc/sysctl.d/10-ptrace.conf.",
        ),
        Some(n) => Check::ok("ptrace protection", format!("kernel.yama.ptrace_scope = {n}")),
    }
}

/// Reports whether the vault exists and whether its permissions are sane. A
/// group- or world-readable vault directory leaks metadata even though the
/// secrets themselves stay encrypted.
fn check_vault_dir(paths: &VaultPaths) -> Check {
    use std::os::unix::fs::PermissionsExt;

    if !paths.root.exists() {
        return Check::warn(
            "vault",
            format!("{} does not exist", paths.root.display()),
            "Run `sypherstore init` to create it.",
        );
    }
    let mode = match std::fs::metadata(&paths.root) {
        Ok(m) => m.permissions().mode() & 0o777,
        Err(e) => {
            return Check::fail(
                "vault",
                format!("cannot stat {}: {e}", paths.root.display()),
                "Check ownership of the vault directory.",
            )
        }
    };
    if mode & 0o077 != 0 {
        return Check::fail(
            "vault",
            format!("{} is mode {mode:o}", paths.root.display()),
            "Other users can read your vault metadata: chmod 700 the vault directory.",
        );
    }
    let state = if paths.is_initialized() {
        "initialized"
    } else {
        "created but not initialized"
    };
    Check::ok("vault", format!("{} ({state})", paths.root.display()))
}

fn check_log_dir() -> Check {
    match crate::logging::log_path() {
        Some(p) => Check::ok("log", p.display().to_string()),
        None => Check::warn(
            "log",
            "no XDG state directory",
            "Set XDG_STATE_HOME; logging will fall back to stderr only.",
        ),
    }
}

/// The loudest check. A `mock-hw` build stores key material in plain files and
/// must never be mistaken for a real one.
fn check_build_flavor() -> Check {
    #[cfg(feature = "mock-hw")]
    {
        Check::warn(
            "build",
            "MOCK HARDWARE BUILD",
            "This build fakes the TPM and YubiKey with plain files. It provides NO protection. Do not store real secrets.",
        )
    }
    #[cfg(not(feature = "mock-hw"))]
    {
        Check::ok("build", "hardware-backed (TPM + FIDO2)")
    }
}

/// Whether the current process can open `path` for reading and writing.
///
/// Uses `access(2)` rather than inspecting the mode bits, so supplementary
/// groups and ACLs are accounted for.
fn is_accessible(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    unsafe { libc::access(c_path.as_ptr(), libc::R_OK | libc::W_OK) == 0 }
}

/// Members listed for `group` in `/etc/group`, or `None` if it does not exist.
///
/// Only reads the explicit member list, which misses users whose *primary*
/// group it is; [`in_supplementary_group`] covers the running process
/// properly, and this is a diagnostic, not an authorization decision.
fn group_members(group: &str) -> Option<Vec<String>> {
    let contents = std::fs::read_to_string("/etc/group").ok()?;
    for line in contents.lines() {
        let mut fields = line.split(':');
        if fields.next() == Some(group) {
            let members = fields.nth(2).unwrap_or("");
            return Some(
                members
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect(),
            );
        }
    }
    None
}

/// Whether the running process holds `group` among its supplementary groups.
fn in_supplementary_group(group: &str) -> bool {
    let Some(gid) = group_gid(group) else {
        return false;
    };
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count <= 0 {
        return false;
    }
    let mut gids = vec![0 as libc::gid_t; count as usize];
    let got = unsafe { libc::getgroups(count, gids.as_mut_ptr()) };
    if got < 0 {
        return false;
    }
    gids.truncate(got as usize);
    gids.contains(&gid)
}

fn group_gid(group: &str) -> Option<libc::gid_t> {
    let contents = std::fs::read_to_string("/etc/group").ok()?;
    for line in contents.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.first() == Some(&group) {
            return fields.get(2).and_then(|g| g.parse().ok());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failing_checks_carry_a_remedy() {
        // A diagnostic with no fix is only marginally better than the original
        // error, so the invariant is worth asserting.
        let paths = VaultPaths::at("/nonexistent/vault");
        let report = run(&paths);
        for c in &report.checks {
            if c.status != Status::Ok {
                assert!(
                    c.remedy.is_some(),
                    "check {:?} is not Ok but suggests no remedy",
                    c.name
                );
            }
        }
    }

    #[test]
    fn report_counts_add_up() {
        let paths = VaultPaths::at("/nonexistent/vault");
        let report = run(&paths);
        let (ok, warn, fail) = report.counts();
        assert_eq!(ok + warn + fail, report.checks.len());
        assert_eq!(report.has_failures(), fail > 0);
    }

    #[test]
    fn a_missing_vault_warns_rather_than_fails() {
        // A fresh install has no vault yet; that must not read as broken.
        let tmp = tempfile::tempdir().unwrap();
        let check = check_vault_dir(&VaultPaths::at(tmp.path().join("absent")));
        assert_eq!(check.status, Status::Warn);
        assert!(check.remedy.unwrap().contains("init"));
    }

    #[test]
    fn a_world_readable_vault_is_a_failure() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("vault");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();

        let check = check_vault_dir(&VaultPaths::at(&root));
        assert_eq!(check.status, Status::Fail);
    }

    #[test]
    fn a_private_initialized_vault_passes() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = VaultPaths::at(tmp.path().join("vault"));
        paths.ensure_dirs().unwrap();
        std::fs::write(paths.db(), b"").unwrap();

        let check = check_vault_dir(&paths);
        assert_eq!(check.status, Status::Ok);
        assert!(check.detail.contains("initialized"));
    }

    #[test]
    fn checks_render_with_their_remedy() {
        let c = Check::fail("thing", "is broken", "fix it like so");
        let rendered = c.to_string();
        assert!(rendered.contains("[fail]"));
        assert!(rendered.contains("fix it like so"));
    }

    #[test]
    fn group_lookup_handles_a_missing_group() {
        assert!(group_members("definitely-not-a-real-group-xyz").is_none());
    }
}
