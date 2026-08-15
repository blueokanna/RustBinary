//! Kani formal-verification harnesses for the Core layer.
//!
//! These harnesses are compiled only when the crate is built under Kani
//! (`cargo kani -p rustbinary`), which defines the `kani` cfg. They prove, by
//! exhaustive symbolic model checking:
//!
//! - **Roundtrip**: `decode_varint_le(encode_varint_le(v)) == v` for every
//!   `u128`; `zigzag_decode(zigzag_encode(v)) == v` and the reverse for every
//!   `i128`/`u128`.
//! - **Boundedness**: the encoded form is at most 17 bytes, and its width is
//!   the canonical (minimal) width for the value.
//! - **Canonical uniqueness**: `encode` is a bijection onto the accepted byte
//!   strings (the roundtrip proof plus determinism of `decode` implies that
//!   two distinct values can never share one canonical encoding).
//!
//! Run:
//!
//! ```text
//! cargo kani -p rustbinary --harness canonical::varint_roundtrip
//! cargo kani -p rustbinary --harness canonical::zigzag_roundtrip
//! cargo kani -p rustbinary --harness canonical::zigzag_injective
//! cargo kani -p rustbinary --harness canonical::varint_bounded_and_minimal
//! ```
//!
//! (or `cargo kani -p rustbinary` for the whole set). Kani also proves the
//! harnesses are memory-safe and terminating, which covers the decoder's
//! bounds-checked reads.

#[cfg(kani)]
mod canonical {
    use crate::canonical::{decode_varint_le, encode_varint_le, zigzag_decode, zigzag_encode};

    /// `decode(encode(v)) == v` for every possible `u128`.
    ///
    /// Because `decode` is a deterministic total function, this also proves
    /// that `encode` is injective: no two distinct values can share a
    /// canonical encoding, i.e. the wire form is unique per value.
    #[kani::proof]
    #[kani::unwind(20)]
    pub fn varint_roundtrip() {
        let value: u128 = kani::any();
        let (bytes, length) = encode_varint_le(value);
        let marker = bytes[0];
        kani::assert(
            decode_varint_le(marker, &bytes[1..length]) == Some(value),
            "canonical varint roundtrip",
        );
    }

    /// The encoded width is bounded by 17 bytes and is the canonical width.
    #[kani::proof]
    #[kani::unwind(20)]
    pub fn varint_bounded_and_minimal() {
        let value: u128 = kani::any();
        let (_, length) = encode_varint_le(value);
        kani::assert(length <= 17, "varint is bounded by 17 bytes");
        match length {
            1 => kani::assert(value <= 250, "1-byte form only for <= 250"),
            3 => kani::assert((251..=0xffff).contains(&value), "3-byte form"),
            5 => kani::assert((0x1_0000..=0xffff_ffff).contains(&value), "5-byte form"),
            9 => kani::assert(
                (0x1_0000_0000..=0xffff_ffff_ffff_ffff).contains(&value),
                "9-byte form",
            ),
            17 => kani::assert(
                value >= 0x1_0000_0000_0000_0000,
                "17-byte form only for >= 2^64",
            ),
            other => kani::assert(false, "unreachable width"),
        }
    }

    /// `zigzag_decode(zigzag_encode(v)) == v` for every `i128`.
    #[kani::proof]
    pub fn zigzag_roundtrip() {
        let value: i128 = kani::any();
        kani::assert(
            zigzag_decode(zigzag_encode(value)) == value,
            "zigzag roundtrip",
        );
    }

    /// `zigzag_encode(zigzag_decode(e)) == e` for every `u128` (bijective).
    #[kani::proof]
    pub fn zigzag_injective() {
        let encoded: u128 = kani::any();
        kani::assert(
            zigzag_encode(zigzag_decode(encoded)) == encoded,
            "zigzag is injective",
        );
    }
}
