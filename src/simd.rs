//! Runtime-dispatched SIMD primitives used by codec hot paths.

/// SIMD implementation selected for byte-oriented codec operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SimdBackend {
    /// Portable scalar implementation.
    Scalar,
    /// 128-bit x86 SSE2 implementation.
    Sse2,
    /// 256-bit x86 AVX2 implementation.
    Avx2,
    /// 128-bit AArch64 NEON implementation.
    Neon,
}

/// Hardware features relevant to serialization workloads.
///
/// A capability can be present without being selected as [`SimdBackend`]. For
/// example, AVX-512, SVE, and SME do not currently have codec kernels because
/// wider state can reduce clock speed and SME is intended for matrix tiles.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HardwareCapabilities {
    /// x86 SSE2 support.
    pub sse2: bool,
    /// x86 AVX support, including operating-system extended-state support.
    pub avx: bool,
    /// x86 AVX2 support.
    pub avx2: bool,
    /// x86 AVX-512 foundation support.
    pub avx512f: bool,
    /// x86 AVX-512 byte/word support.
    pub avx512bw: bool,
    /// AArch64 NEON support.
    pub neon: bool,
    /// AArch64 scalable vector extension support.
    pub sve: bool,
    /// AArch64 scalable matrix extension support.
    pub sme: bool,
}

/// Detects hardware SIMD capabilities at runtime.
pub fn hardware_capabilities() -> HardwareCapabilities {
    let mut capabilities = HardwareCapabilities::default();
    #[cfg(target_arch = "x86_64")]
    {
        capabilities.sse2 = std::arch::is_x86_feature_detected!("sse2");
        capabilities.avx = std::arch::is_x86_feature_detected!("avx");
        capabilities.avx2 = std::arch::is_x86_feature_detected!("avx2");
        capabilities.avx512f = std::arch::is_x86_feature_detected!("avx512f");
        capabilities.avx512bw = std::arch::is_x86_feature_detected!("avx512bw");
    }
    #[cfg(target_arch = "aarch64")]
    {
        capabilities.neon = std::arch::is_aarch64_feature_detected!("neon");
        capabilities.sve = std::arch::is_aarch64_feature_detected!("sve");
        capabilities.sme = detect_sme();
    }
    capabilities
}

#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android")
))]
fn detect_sme() -> bool {
    use std::ffi::c_ulong;

    const AT_HWCAP2: c_ulong = 26;
    const HWCAP2_SME: c_ulong = 1 << 23;

    unsafe extern "C" {
        fn getauxval(kind: c_ulong) -> c_ulong;
    }

    // SAFETY: `getauxval` has no pointer arguments and is provided by libc on
    // Linux and Android. A missing capability is reported as a zero bit.
    unsafe { getauxval(AT_HWCAP2) & HWCAP2_SME != 0 }
}

#[cfg(all(
    target_arch = "aarch64",
    not(any(target_os = "linux", target_os = "android"))
))]
const fn detect_sme() -> bool {
    false
}

/// Returns the fastest implemented backend supported by the current process.
///
/// Runtime feature probing is performed once and cached: every codec hot-path
/// dispatch (`is_ascii`, `plain_varint_prefix`) reuses the result instead of
/// re-running CPU feature detection on each call.
pub fn simd_backend() -> SimdBackend {
    // `OnceLock` (1.70) instead of `LazyLock` (1.80) keeps the MSRV at 1.78.
    static BACKEND: std::sync::OnceLock<SimdBackend> = std::sync::OnceLock::new();
    *BACKEND.get_or_init(|| {
        let capabilities = hardware_capabilities();
        if capabilities.avx2 {
            SimdBackend::Avx2
        } else if capabilities.sse2 {
            SimdBackend::Sse2
        } else if capabilities.neon {
            SimdBackend::Neon
        } else {
            SimdBackend::Scalar
        }
    })
}

#[cfg(feature = "adaptive")]
pub(crate) fn is_ascii(bytes: &[u8]) -> bool {
    first_non_ascii(bytes) == bytes.len()
}

#[cfg(feature = "adaptive")]
pub(crate) fn plain_varint_prefix(bytes: &[u8]) -> usize {
    match simd_backend() {
        #[cfg(target_arch = "x86_64")]
        SimdBackend::Avx2 => {
            // SAFETY: runtime detection above proves AVX2 availability. The
            // kernel uses unaligned loads only within complete 32-byte chunks.
            unsafe { x86::plain_prefix_avx2(bytes) }
        }
        #[cfg(target_arch = "x86_64")]
        SimdBackend::Sse2 => {
            // SAFETY: SSE2 is checked at runtime and each load is in bounds.
            unsafe { x86::plain_prefix_sse2(bytes) }
        }
        #[cfg(target_arch = "aarch64")]
        SimdBackend::Neon => {
            // SAFETY: NEON is checked at runtime and each load is in bounds.
            unsafe { arm::plain_prefix_neon(bytes) }
        }
        _ => scalar_plain_prefix(bytes),
    }
}

#[cfg(feature = "adaptive")]
fn first_non_ascii(bytes: &[u8]) -> usize {
    match simd_backend() {
        #[cfg(target_arch = "x86_64")]
        SimdBackend::Avx2 => {
            // SAFETY: runtime feature detection and bounds are enforced here.
            unsafe { x86::ascii_prefix_avx2(bytes) }
        }
        #[cfg(target_arch = "x86_64")]
        SimdBackend::Sse2 => {
            // SAFETY: runtime feature detection and bounds are enforced here.
            unsafe { x86::ascii_prefix_sse2(bytes) }
        }
        #[cfg(target_arch = "aarch64")]
        SimdBackend::Neon => {
            // SAFETY: runtime feature detection and bounds are enforced here.
            unsafe { arm::ascii_prefix_neon(bytes) }
        }
        _ => scalar_ascii_prefix(bytes),
    }
}

#[cfg(feature = "adaptive")]
fn scalar_ascii_prefix(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .position(|byte| !byte.is_ascii())
        .unwrap_or(bytes.len())
}

#[cfg(feature = "adaptive")]
fn scalar_plain_prefix(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .position(|byte| *byte > 250)
        .unwrap_or(bytes.len())
}

#[cfg(all(feature = "adaptive", target_arch = "x86_64"))]
mod x86 {
    // The compute intrinsics (set1 / xor / cmpgt / movemask) are `unsafe fn` on
    // Rust 1.78 but safe to call in newer releases. The blocks below keep the
    // code compiling on both, and this allow silences the redundant-unsafe
    // warning that newer Rust would otherwise emit.
    #![allow(unused_unsafe)]
    use std::arch::x86_64::*;

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn ascii_prefix_avx2(bytes: &[u8]) -> usize {
        let mut offset = 0;
        while offset + 32 <= bytes.len() {
            // SAFETY: the loop proves that a complete unaligned vector is readable.
            let vector = unsafe { _mm256_loadu_si256(bytes.as_ptr().add(offset).cast()) };
            let mask = unsafe { _mm256_movemask_epi8(vector) } as u32;
            if mask != 0 {
                return offset + mask.trailing_zeros() as usize;
            }
            offset += 32;
        }
        offset + super::scalar_ascii_prefix(&bytes[offset..])
    }

    #[target_feature(enable = "sse2")]
    pub(super) unsafe fn ascii_prefix_sse2(bytes: &[u8]) -> usize {
        let mut offset = 0;
        while offset + 16 <= bytes.len() {
            // SAFETY: the loop proves that a complete unaligned vector is readable.
            let vector = unsafe { _mm_loadu_si128(bytes.as_ptr().add(offset).cast()) };
            let mask = unsafe { _mm_movemask_epi8(vector) } as u32;
            if mask != 0 {
                return offset + mask.trailing_zeros() as usize;
            }
            offset += 16;
        }
        offset + super::scalar_ascii_prefix(&bytes[offset..])
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn plain_prefix_avx2(bytes: &[u8]) -> usize {
        let mut offset = 0;
        let sign = unsafe { _mm256_set1_epi8(i8::MIN) };
        let threshold = unsafe { _mm256_set1_epi8(122) };
        while offset + 32 <= bytes.len() {
            // SAFETY: the loop proves that a complete unaligned vector is readable.
            let vector = unsafe { _mm256_loadu_si256(bytes.as_ptr().add(offset).cast()) };
            let unsigned_order = unsafe { _mm256_xor_si256(vector, sign) };
            let markers = unsafe { _mm256_cmpgt_epi8(unsigned_order, threshold) };
            let mask = unsafe { _mm256_movemask_epi8(markers) } as u32;
            if mask != 0 {
                return offset + mask.trailing_zeros() as usize;
            }
            offset += 32;
        }
        offset + super::scalar_plain_prefix(&bytes[offset..])
    }

    #[target_feature(enable = "sse2")]
    pub(super) unsafe fn plain_prefix_sse2(bytes: &[u8]) -> usize {
        let mut offset = 0;
        let sign = unsafe { _mm_set1_epi8(i8::MIN) };
        let threshold = unsafe { _mm_set1_epi8(122) };
        while offset + 16 <= bytes.len() {
            // SAFETY: the loop proves that a complete unaligned vector is readable.
            let vector = unsafe { _mm_loadu_si128(bytes.as_ptr().add(offset).cast()) };
            let unsigned_order = unsafe { _mm_xor_si128(vector, sign) };
            let markers = unsafe { _mm_cmpgt_epi8(unsigned_order, threshold) };
            let mask = unsafe { _mm_movemask_epi8(markers) } as u32;
            if mask != 0 {
                return offset + mask.trailing_zeros() as usize;
            }
            offset += 16;
        }
        offset + super::scalar_plain_prefix(&bytes[offset..])
    }
}

#[cfg(all(feature = "adaptive", target_arch = "aarch64"))]
mod arm {
    // See the `x86` module: NEON compute intrinsics are `unsafe fn` on Rust
    // 1.78 but safe in newer releases.
    #![allow(unused_unsafe)]
    use std::arch::aarch64::*;

    #[target_feature(enable = "neon")]
    pub(super) unsafe fn ascii_prefix_neon(bytes: &[u8]) -> usize {
        let mut offset = 0;
        let threshold = unsafe { vdupq_n_u8(127) };
        while offset + 16 <= bytes.len() {
            // SAFETY: the loop proves that a complete unaligned vector is readable.
            let vector = unsafe { vld1q_u8(bytes.as_ptr().add(offset)) };
            let compared = unsafe { vcgtq_u8(vector, threshold) };
            let mut lanes = [0u8; 16];
            // SAFETY: `lanes` has exactly one vector of writable storage.
            unsafe { vst1q_u8(lanes.as_mut_ptr(), compared) };
            if let Some(index) = lanes.iter().position(|lane| *lane != 0) {
                return offset + index;
            }
            offset += 16;
        }
        offset + super::scalar_ascii_prefix(&bytes[offset..])
    }

    #[target_feature(enable = "neon")]
    pub(super) unsafe fn plain_prefix_neon(bytes: &[u8]) -> usize {
        let mut offset = 0;
        let threshold = unsafe { vdupq_n_u8(250) };
        while offset + 16 <= bytes.len() {
            // SAFETY: the loop proves that a complete unaligned vector is readable.
            let vector = unsafe { vld1q_u8(bytes.as_ptr().add(offset)) };
            let compared = unsafe { vcgtq_u8(vector, threshold) };
            let mut lanes = [0u8; 16];
            // SAFETY: `lanes` has exactly one vector of writable storage.
            unsafe { vst1q_u8(lanes.as_mut_ptr(), compared) };
            if let Some(index) = lanes.iter().position(|lane| *lane != 0) {
                return offset + index;
            }
            offset += 16;
        }
        offset + super::scalar_plain_prefix(&bytes[offset..])
    }
}

#[cfg(all(test, feature = "adaptive"))]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn dispatched_scanners_match_scalar_at_vector_boundaries() {
        for length in 0..96 {
            let ascii = vec![b'a'; length];
            assert_eq!(first_non_ascii(&ascii), scalar_ascii_prefix(&ascii));
            assert_eq!(plain_varint_prefix(&ascii), scalar_plain_prefix(&ascii));

            for position in 0..length {
                let mut non_ascii = ascii.clone();
                non_ascii[position] = 0x80;
                assert_eq!(first_non_ascii(&non_ascii), position);

                let mut marker = ascii.clone();
                marker[position] = 251;
                assert_eq!(plain_varint_prefix(&marker), position);
            }
        }
    }

    #[test]
    fn plain_varint_scan_accepts_entire_single_byte_domain() {
        let values = (0..=250).map(|value| value as u8).collect::<Vec<_>>();
        assert_eq!(plain_varint_prefix(&values), values.len());
        for marker in 251..=255 {
            let mut input = values.clone();
            input.push(marker);
            assert_eq!(plain_varint_prefix(&input), values.len());
        }
    }
}
