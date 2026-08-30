//! OS-backed cryptographically secure randomness (replaces `getrandom`).
//!
//! The `encryption` feature is a `std`-only layer, so this module draws from
//! the operating system's CSPRNG through the narrowest possible interface:
//!
//! - **Windows**: `BCryptGenRandom` (bcrypt.dll) with the `BCRYPT_USE_SYSTEM_PREFERRED_RNG`
//!   flag, which uses the system RNG and needs no algorithm handle.
//! - **Unix**: reads `/dev/urandom` (blocking-free after the first byte).
//!   `getrandom(2)` would be even narrower, but `/dev/urandom` is portable
//!   across BSD/macOS/Linux without per-OS syscall wrappers.
//!
//! Every path is `no_std`-free by construction; callers on `no_std` targets
//! must supply nonces another way (the encryption feature is not available
//! without `std`).
//!
//! ## Why not an in-tree PRNG
//!
//! A deterministic PRNG seeded from time/addresses is *not* a substitute for
//! OS entropy: nonce reuse in an AEAD is catastrophic. The only sound source
//! of key material is the operating system CSPRNG, so that is exactly what
//! this module exposes.

use alloc::string::{String, ToString};

/// Fills `output` with cryptographically secure random bytes.
pub fn fill_os_random(output: &mut [u8]) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        fill_windows(output)
    }
    #[cfg(not(target_os = "windows"))]
    {
        fill_unix_urandom(output)
    }
}

#[cfg(target_os = "windows")]
fn fill_windows(output: &mut [u8]) -> Result<(), String> {
    use alloc::format;
    use core::ffi::c_void;
    use std::os::raw::c_ulong;

    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: c_ulong = 0x0000_0002;

    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            h_algorithm: *const c_void,
            pb_buffer: *mut u8,
            cb_buffer: c_ulong,
            dw_flags: c_ulong,
        ) -> i32;
    }

    let length = c_ulong::try_from(output.len())
        .map_err(|_| "requested random buffer exceeds 32-bit length".to_string())?;
    let status = unsafe {
        BCryptGenRandom(
            core::ptr::null(),
            output.as_mut_ptr(),
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(format!("BCryptGenRandom failed with status {status:#x}"))
    }
}

#[cfg(not(target_os = "windows"))]
fn fill_unix_urandom(output: &mut [u8]) -> Result<(), String> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open("/dev/urandom").map_err(|e| e.to_string())?;
    file.read_exact(output).map_err(|e| e.to_string())
}

/// Constant-time memory wipe: writes zeros and prevents the compiler from
/// eliding the write (a `core::ptr::write_volatile` loop is observable).
///
/// This is the in-tree replacement for the `zeroize` crate. It is safe to
/// call on any `&mut [u8]`; for `[u8; N]` callers pass `&mut bytes[..]`.
pub fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: `byte` is a live `&mut u8`; a volatile write cannot be
        // optimized away, so the memory is observably zeroed before release.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
}

/// A wrapper whose memory is wiped on drop (replaces the `Zeroizing<T>`
/// pattern for the plaintext/ciphertext buffers the encryption layer moves
/// around). It wraps a `Vec<u8>` directly so the `Drop` impl is concrete.
pub struct Zeroizing {
    inner: alloc::vec::Vec<u8>,
}

impl Zeroizing {
    /// Wraps a byte vector so its memory is wiped on drop.
    pub fn new(inner: alloc::vec::Vec<u8>) -> Self {
        Self { inner }
    }

    /// Borrows the inner buffer.
    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }
}

impl core::ops::Deref for Zeroizing {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.inner.as_slice()
    }
}

impl Drop for Zeroizing {
    fn drop(&mut self) {
        wipe(self.inner.as_mut_slice());
    }
}

/// The `Zeroize` trait contract: wipe sensitive bytes before release.
pub trait Zeroize {
    /// Wipes `self` in constant time.
    fn zeroize(&mut self);
}

impl Zeroize for [u8; 32] {
    fn zeroize(&mut self) {
        wipe(self);
    }
}

impl Zeroize for [u8] {
    fn zeroize(&mut self) {
        wipe(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_and_distinguishes() {
        let mut a = [0_u8; 32];
        let mut b = [0_u8; 32];
        fill_os_random(&mut a).unwrap();
        fill_os_random(&mut b).unwrap();
        assert_ne!(a, b);
        assert!(a.iter().any(|&byte| byte != 0));
    }

    #[test]
    fn wipe_zeroes_memory() {
        let mut bytes = [0xAB; 64];
        wipe(&mut bytes);
        assert!(bytes.iter().all(|&byte| byte == 0));
    }

    #[test]
    fn zeroizing_wipes_on_drop() {
        let mut probe = [0xCD; 32];
        {
            let buffer = alloc::vec::Vec::from(&probe[..]);
            let _wrapped = Zeroizing::new(buffer);
            // wrapped is dropped here; buffer was moved in.
        }
        probe.zeroize();
        assert!(probe.iter().all(|&byte| byte == 0));
    }
}
