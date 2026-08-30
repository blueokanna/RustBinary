//! Read-only memory mapping without third-party dependencies (replaces
//! `memmap2`).
//!
//! The `archive` feature memory-maps immutable archive files for zero-copy
//! typed access. This module owns the narrow OS interface needed for that:
//!
//! - **Windows**: `CreateFileMappingW` + `MapViewOfFile` + `UnmapViewOfFile`
//!   + `CloseHandle` from `kernel32.dll`, mapped read-only.
//! - **Unix**: `mmap(2)` + `munmap(2)` from `libc` (declared via `extern`,
//!   no crate dependency), mapped `PROT_READ` / `MAP_PRIVATE`.
//!
//! `Mmap` derefs to `[u8]` and drops the mapping automatically. There is no
//! write mapping here because the archive format is immutable by design; a
//! future read-write layer can be added without touching the call sites.

use core::ops::Deref;
use std::fs::File;

/// A read-only memory mapping of a file.
pub struct Mmap {
    ptr: *mut u8,
    len: usize,
}

// A mapping is immutable: `&Mmap` and `Mmap` are both Send + Sync because
// there is no interior mutability. The OS keeps the pages valid until
// `munmap`/`UnmapViewOfFile`, which happens in `Drop`.
unsafe impl Send for Mmap {}
unsafe impl Sync for Mmap {}

impl Mmap {
    /// Maps `file` read-only into the address space.
    ///
    /// # Safety
    ///
    /// The file must not be truncated or modified for the lifetime of the
    /// returned mapping; the OS cannot express that requirement, so it is the
    /// caller's contract (same as `memmap2`).
    pub unsafe fn map(file: &File) -> std::io::Result<Self> {
        let len = file.metadata()?.len();
        let len = usize::try_from(len).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "file too large to map on this platform",
            )
        })?;
        #[cfg(windows)]
        {
            // SAFETY: caller guarantees file immutability for the mapping.
            unsafe { Self::map_windows(file, len) }
        }
        #[cfg(not(windows))]
        {
            // SAFETY: caller guarantees file immutability for the mapping.
            unsafe { Self::map_unix(file, len) }
        }
    }

    /// The mapped length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    #[cfg(windows)]
    unsafe fn map_windows(file: &File, len: usize) -> std::io::Result<Self> {
        use std::os::windows::io::AsRawHandle;

        #[link(name = "kernel32")]
        extern "system" {
            fn CreateFileMappingW(
                h_file: *mut core::ffi::c_void,
                lp_attributes: *const core::ffi::c_void,
                fl_protect: u32,
                dw_max_size_high: u32,
                dw_max_size_low: u32,
                lp_name: *const u16,
            ) -> *mut core::ffi::c_void;
            fn MapViewOfFile(
                h_file_mapping_object: *mut core::ffi::c_void,
                dw_desired_access: u32,
                dw_file_offset_high: u32,
                dw_file_offset_low: u32,
                dw_number_of_bytes_to_map: usize,
            ) -> *mut core::ffi::c_void;
            fn CloseHandle(h_object: *mut core::ffi::c_void) -> i32;
        }

        const PAGE_READONLY: u32 = 0x02;
        const FILE_MAP_READ: u32 = 0x0004;
        const INVALID_HANDLE_VALUE: *mut core::ffi::c_void = !0usize as *mut core::ffi::c_void;

        let raw = file.as_raw_handle();
        let len64 = len as u64;
        // SAFETY: `raw` is a valid handle for the live file; all pointer
        // arguments are null or valid constants.
        let mapping = unsafe {
            CreateFileMappingW(
                raw,
                core::ptr::null(),
                PAGE_READONLY,
                (len64 >> 32) as u32,
                (len64 & 0xffff_ffff) as u32,
                core::ptr::null(),
            )
        };
        if mapping.is_null() || mapping == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `mapping` is a valid handle returned above.
        let view = unsafe { MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0) };
        // The mapping handle is no longer needed once the view exists.
        // SAFETY: `mapping` is a valid open handle.
        unsafe { CloseHandle(mapping) };
        if view.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            ptr: view.cast::<u8>(),
            len,
        })
    }

    #[cfg(not(windows))]
    unsafe fn map_unix(file: &File, len: usize) -> std::io::Result<Self> {
        use std::os::unix::io::AsRawFd;

        // Minimal POSIX mmap interface; linked against the system libc.
        // `munmap` is declared locally in `Drop`, which owns the only unmap
        // call site, so it is not repeated here.
        extern "C" {
            fn mmap(
                addr: *mut core::ffi::c_void,
                length: usize,
                prot: i32,
                flags: i32,
                fd: i32,
                offset: i64,
            ) -> *mut core::ffi::c_void;
        }

        const PROT_READ: i32 = 0x1;
        const MAP_PRIVATE: i32 = 0x02;
        const MAP_FAILED: *mut core::ffi::c_void = !0usize as *mut core::ffi::c_void;

        if len == 0 {
            // An empty mapping: `mmap` with length 0 fails on most platforms.
            // Return a valid but empty mapping instead.
            return Ok(Self {
                ptr: core::ptr::NonNull::<u8>::dangling().as_ptr(),
                len: 0,
            });
        }
        // SAFETY: `mmap` is linked against the system libc and called with a
        // null address (kernel chooses), a real fd from the live file, and
        // read-only private flags. The returned pointer is checked against
        // `MAP_FAILED` and null before use.
        let mapped = unsafe {
            mmap(
                core::ptr::null_mut(),
                len,
                PROT_READ,
                MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if mapped == MAP_FAILED || mapped.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            ptr: mapped.cast::<u8>(),
            len,
        })
    }
}

impl Deref for Mmap {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        // SAFETY: `self.len` bytes are mapped at `self.ptr` and the file is
        // immutable for the mapping lifetime (caller contract).
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        #[cfg(windows)]
        unsafe {
            // SAFETY: `self.ptr` is a live view from `MapViewOfFile`.
            extern "system" {
                fn UnmapViewOfFile(lp_base_address: *const core::ffi::c_void) -> i32;
            }
            UnmapViewOfFile(self.ptr.cast_const().cast());
        }
        #[cfg(not(windows))]
        if self.len != 0 {
            // SAFETY: `self.ptr` is a live mapping of `self.len` bytes from
            // `mmap`.
            unsafe {
                extern "C" {
                    fn munmap(addr: *mut core::ffi::c_void, length: usize) -> i32;
                }
                munmap(self.ptr.cast(), self.len);
            }
        }
    }
}

/// Builder for read-only file mappings (the subset the archive needs).
pub struct MmapOptions;

impl MmapOptions {
    /// Creates a new options value.
    pub const fn new() -> Self {
        Self
    }

    /// Maps `file` read-only.
    ///
    /// # Safety
    ///
    /// Same contract as [`Mmap::map`].
    pub unsafe fn map(self, file: &File) -> std::io::Result<Mmap> {
        // SAFETY: contract forwarded from `Mmap::map`.
        unsafe { Mmap::map(file) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn maps_and_reads_file_contents() {
        let dir = std::env::temp_dir().join("rustbinary-mmap-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sample.bin");
        let payload = b"hello mapped world";
        {
            let mut file = std::fs::File::create(&path).unwrap();
            file.write_all(payload).unwrap();
        }
        // SAFETY: the file is immutable for the test mapping lifetime.
        let map = unsafe { MmapOptions::new().map(&File::open(&path).unwrap()) }.unwrap();
        assert_eq!(map.len(), payload.len());
        assert_eq!(&map[..], payload);
        assert_eq!(&*map, payload);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
