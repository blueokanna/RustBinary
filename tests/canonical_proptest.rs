//! Property tests for the canonical little-endian varint/ZigZag primitives.
//!
//! These complement the Kani harnesses (`src/kani_proofs.rs`): Kani proves the
//! properties symbolically for the full `u128` domain; this file spot-checks
//! them with randomized inputs through the public codec API.

use proptest::prelude::*;

proptest! {
    /// The compact profile roundtrips every integer width.
    #[test]
    fn integer_roundtrip_via_codec(value in any::<u128>()) {
        let config = rustbinary::options();
        let frame = config.serialize(&value).unwrap();
        let decoded: u128 = config.deserialize(&frame).unwrap();
        prop_assert_eq!(decoded, value);
    }

    /// Signed integers roundtrip through the ZigZag profile.
    #[test]
    fn signed_roundtrip_via_codec(value in any::<i128>()) {
        let config = rustbinary::options();
        let frame = config.serialize(&value).unwrap();
        let decoded: i128 = config.deserialize(&frame).unwrap();
        prop_assert_eq!(decoded, value);
    }

    /// A serialized u128 is at most 17 bytes plus its tag.
    #[test]
    fn integer_frame_is_bounded(value in any::<u128>()) {
        let config = rustbinary::options();
        let frame = config.serialize(&value).unwrap();
        // tag (1) + canonical varint (<= 17).
        prop_assert!(frame.len() <= 1 + 17, "frame too large: {}", frame.len());
    }

    /// The decoder rejects non-canonical wide forms: encoding a small value
    /// with a wider marker must fail.
    #[test]
    fn decoder_rejects_wide_forms(small in 0u64..(u32::MAX as u64) + 1) {
        let config = rustbinary::options();
        // Hand-craft a u64 tag followed by a 4-byte marker-varint (marker
        // 252). A value below 2^16 in this form is non-canonical and must be
        // rejected; a value at or above 2^16 is the canonical width and
        // decodes.
        let mut frame = vec![0x03, 252];
        frame.extend_from_slice(&(small as u32).to_le_bytes());
        let result: Result<u64, _> = config.deserialize(&frame);
        if small < 0x1_0000 {
            prop_assert!(result.is_err(), "non-canonical form accepted for {small}");
        } else {
            prop_assert_eq!(result.unwrap(), small);
        }
    }
}
