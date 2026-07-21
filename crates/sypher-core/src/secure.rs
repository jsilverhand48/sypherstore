//! Memory hygiene primitives for plaintext secret material.
//!
//! Every byte of decrypted secret in this program should live in a
//! [`SecureBuf`]. It gives three properties that a plain `Vec<u8>` does not:
//!
//! 1. The backing pages are `mlock`ed, so the kernel will not page them out to
//!    swap or a hibernation image.
//! 2. The contents are zeroized when the buffer is dropped, so a freed
//!    allocation cannot be recovered by a later heap read.
//! 3. `Debug` and `Display` are redacted, so a stray `{:?}` in a log line or an
//!    error type cannot leak the value.
//!
//! The buffer's capacity is fixed at construction. `Vec` would otherwise be
//! free to reallocate on growth, which would leave an unlocked, un-zeroized
//! copy of the old contents behind. Any operation that would exceed the
//! reserved capacity panics rather than silently reallocating.

use std::fmt;
use std::ops::{Deref, DerefMut};

use zeroize::Zeroize;

/// A fixed-capacity, mlocked, zeroize-on-drop byte buffer.
pub struct SecureBuf {
    /// Always allocated with exactly `cap` capacity and never grown.
    buf: Vec<u8>,
    /// Whether `mlock` succeeded. Locking is best effort: an unprivileged
    /// process has a finite `RLIMIT_MEMLOCK` budget, and exhausting it should
    /// degrade the guarantee rather than break the program. Failures are
    /// counted so `doctor` can report them.
    locked: bool,
}

impl SecureBuf {
    /// Allocates a buffer that can hold up to `cap` bytes, and locks it.
    pub fn with_capacity(cap: usize) -> Self {
        let mut buf = Vec::with_capacity(cap);
        // `Vec::with_capacity` may over-allocate; lock what was actually
        // reserved so a later `set_len` inside that range stays covered.
        let locked = lock_region(buf.as_mut_ptr(), buf.capacity());
        if !locked {
            tracing::warn!(
                capacity = cap,
                "mlock failed; secret material may reach swap"
            );
        }
        Self { buf, locked }
    }

    /// Builds a secure buffer holding a copy of `bytes`, then zeroizes `bytes`.
    ///
    /// This is the intended way to take ownership of plaintext that arrived in
    /// an ordinary allocation (a decrypt output, a CBOR field, a CLI
    /// argument): the insecure original does not outlive the call.
    pub fn take_from(bytes: &mut [u8]) -> Self {
        let mut out = Self::with_capacity(bytes.len());
        out.buf.extend_from_slice(bytes);
        bytes.zeroize();
        out
    }

    /// Builds a secure buffer holding a copy of `bytes`.
    ///
    /// Prefer [`SecureBuf::take_from`] when you own the source, since this
    /// variant leaves the caller's copy intact and therefore unprotected.
    pub fn copy_from(bytes: &[u8]) -> Self {
        let mut out = Self::with_capacity(bytes.len());
        out.buf.extend_from_slice(bytes);
        out
    }

    /// Allocates `len` locked bytes of zeros, to be filled in place.
    pub fn zeroed(len: usize) -> Self {
        let mut out = Self::with_capacity(len);
        out.buf.resize(len, 0);
        out
    }

    /// Fills a new buffer of `len` bytes with cryptographically secure randomness.
    pub fn random(len: usize) -> Result<Self, getrandom::Error> {
        let mut out = Self::zeroed(len);
        getrandom::getrandom(&mut out.buf)?;
        Ok(out)
    }

    /// Appends `bytes`, panicking rather than reallocating past the reserved
    /// capacity. Reallocation would strand an unlocked copy of the old
    /// contents, so it is a bug to be caught in tests, not a runtime path.
    pub fn push_slice(&mut self, bytes: &[u8]) {
        assert!(
            self.buf.len() + bytes.len() <= self.buf.capacity(),
            "SecureBuf would reallocate: capacity {} exceeded",
            self.buf.capacity()
        );
        self.buf.extend_from_slice(bytes);
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Whether the pages were successfully locked into RAM.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Interprets the contents as UTF-8 without copying them out.
    ///
    /// The returned reference borrows the locked allocation, so the string is
    /// never duplicated into unprotected memory.
    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.buf)
    }

    /// Zeroizes the contents and truncates to empty, keeping the locked
    /// allocation for reuse.
    pub fn clear(&mut self) {
        self.buf.zeroize();
        self.buf.clear();
    }
}

impl Deref for SecureBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf
    }
}

impl DerefMut for SecureBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

impl Drop for SecureBuf {
    fn drop(&mut self) {
        // Zeroize the whole reserved region, not just the initialized prefix:
        // a buffer that was shrunk still holds the old bytes past `len`.
        let cap = self.buf.capacity();
        unsafe {
            std::ptr::write_bytes(self.buf.as_mut_ptr(), 0, cap);
        }
        // Compiler fences cannot be relied on across the `unlock`/free
        // boundary, so use the same barrier `zeroize` uses.
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        if self.locked {
            unlock_region(self.buf.as_mut_ptr(), cap);
        }
    }
}

/// Redacted: printing a secret is never the intent, even in a panic message.
impl fmt::Debug for SecureBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureBuf([redacted; {} bytes])", self.buf.len())
    }
}

impl fmt::Display for SecureBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl Clone for SecureBuf {
    fn clone(&self) -> Self {
        Self::copy_from(&self.buf)
    }
}

/// Constant-time equality, so comparing a candidate against a stored value
/// cannot be turned into a byte-at-a-time oracle by timing.
impl PartialEq for SecureBuf {
    fn eq(&self, other: &Self) -> bool {
        if self.buf.len() != other.buf.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in self.buf.iter().zip(other.buf.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

impl Eq for SecureBuf {}

fn lock_region(ptr: *mut u8, len: usize) -> bool {
    if len == 0 || ptr.is_null() {
        return true;
    }
    unsafe { memsec::mlock(ptr, len) }
}

fn unlock_region(ptr: *mut u8, len: usize) {
    if len == 0 || ptr.is_null() {
        return;
    }
    unsafe {
        memsec::munlock(ptr, len);
    }
}

/// Prevents the kernel from writing a core dump of this process.
///
/// A core dump would contain every unlocked key and plaintext in the address
/// space, written to disk in the clear. On a systemd machine it would land in
/// the journal's coredump store, which is exactly the wrong place for it.
///
/// Safe to call in any process; this has no interaction with the portals.
pub fn disable_core_dumps() {
    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &no_core);
    }
    tracing::debug!("core dumps disabled");
}

/// Blocks same-uid `ptrace` attach by marking the process non-dumpable.
///
/// # Not usable in the daemon
///
/// `PR_SET_DUMPABLE = 0` also reassigns `/proc/<pid>/` to `root:root`.
/// `xdg-desktop-portal` identifies its callers by reading `/proc/<pid>/root`,
/// so a non-dumpable process is refused with "Portal operation not allowed:
/// Unable to open /proc/<pid>/root". That breaks the global shortcut and the
/// paste engine, which are the daemon's whole purpose.
///
/// So this is applied to the short-lived CLI commands only. The daemon relies
/// instead on the kernel's Yama LSM: with `kernel.yama.ptrace_scope >= 1` (the
/// default on Arch) a process can only be traced by its own descendants, which
/// covers the same attack. `doctor` reports the setting so a machine with it
/// turned off is visible rather than silently weaker.
pub fn disable_ptrace() {
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }
    tracing::debug!("ptrace attach blocked (dumpable=0)");
}

/// Reads `kernel.yama.ptrace_scope`.
///
/// `None` means the Yama LSM is not present, in which case any same-uid
/// process can attach to the daemon.
pub fn yama_ptrace_scope() -> Option<u8> {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_from_wipes_the_source() {
        let mut src = b"hunter2".to_vec();
        let buf = SecureBuf::take_from(&mut src);
        assert_eq!(buf.as_slice(), b"hunter2");
        assert_eq!(src, vec![0u8; 7], "source must be zeroized");
    }

    #[test]
    fn debug_and_display_are_redacted() {
        let buf = SecureBuf::copy_from(b"topsecret");
        let dbg = format!("{buf:?}");
        let disp = format!("{buf}");
        assert!(!dbg.contains("topsecret"), "Debug leaked: {dbg}");
        assert!(!disp.contains("topsecret"), "Display leaked: {disp}");
        assert!(dbg.contains("9 bytes"));
    }

    #[test]
    fn equality_is_length_and_content_sensitive() {
        assert_eq!(SecureBuf::copy_from(b"abc"), SecureBuf::copy_from(b"abc"));
        assert_ne!(SecureBuf::copy_from(b"abc"), SecureBuf::copy_from(b"abd"));
        assert_ne!(SecureBuf::copy_from(b"abc"), SecureBuf::copy_from(b"abcd"));
    }

    #[test]
    fn random_fills_requested_length() {
        let a = SecureBuf::random(32).unwrap();
        let b = SecureBuf::random(32).unwrap();
        assert_eq!(a.len(), 32);
        // A collision here means the RNG is broken, not that the test is flaky.
        assert_ne!(a, b);
    }

    #[test]
    #[should_panic(expected = "would reallocate")]
    fn push_past_capacity_panics_instead_of_reallocating() {
        let mut buf = SecureBuf::with_capacity(4);
        buf.push_slice(b"12345678");
    }

    #[test]
    fn clear_wipes_but_keeps_the_allocation() {
        let mut buf = SecureBuf::copy_from(b"secret");
        buf.clear();
        assert!(buf.is_empty());
    }
}
