//! Canonical little-endian marker-varint and ZigZag primitives.
//!
//! This module is the **single implementation** of the canonical integer
//! encoding for the little-endian variable-integer profile. Both the encoder
//! (`ser`) and the decoder (`decoder`) call these functions, so the two
//! directions cannot drift apart, and the Kani verification harnesses in
//! `kani_proofs.rs` prove the roundtrip, boundedness, and canonical-form
//! properties against these exact functions.
//!
//! Marker-varint canonical form (little endian):
//!
//! | marker | payload bytes | minimum value |
//! |--------|---------------|---------------|
//! | `0..=250` | none | 0 |
//! | `251` | 2 (LE u16) | 251 |
//! | `252` | 4 (LE u32) | 65,536 |
//! | `253` | 8 (LE u64) | 4,294,967,296 |
//! | `254` | 16 (LE u128) | 18,446,744,073,709,551,616 |
//! | `255` | reserved | never accepted |

use crate::tags::{MARKER_U128, MARKER_U16, MARKER_U32, MARKER_U64};

/// Worst-case encoded size: one marker byte plus a 128-bit payload.
pub(crate) const VARINT_MAX_BYTES: usize = 1 + 16;

/// Encodes `value` in canonical little-endian marker-varint form.
///
/// Returns the encoded bytes and their length. The form is canonical: a value
/// is always encoded with the narrowest payload that can represent it, so the
/// encoding is a bijection between `u128` and the accepted byte strings.
pub(crate) fn encode_varint_le(value: u128) -> ([u8; VARINT_MAX_BYTES], usize) {
    let mut bytes = [0_u8; VARINT_MAX_BYTES];
    let length = match value {
        0..=250 => {
            bytes[0] = value as u8;
            1
        }
        251..=0xffff => {
            bytes[0] = MARKER_U16;
            bytes[1..3].copy_from_slice(&(value as u16).to_le_bytes());
            3
        }
        0x1_0000..=0xffff_ffff => {
            bytes[0] = MARKER_U32;
            bytes[1..5].copy_from_slice(&(value as u32).to_le_bytes());
            5
        }
        0x1_0000_0000..=0xffff_ffff_ffff_ffff => {
            bytes[0] = MARKER_U64;
            bytes[1..9].copy_from_slice(&(value as u64).to_le_bytes());
            9
        }
        _ => {
            bytes[0] = MARKER_U128;
            bytes[1..17].copy_from_slice(&value.to_le_bytes());
            17
        }
    };
    (bytes, length)
}

/// Decodes one canonical little-endian marker-varint.
///
/// Returns `None` for an unknown marker, a truncated payload, or a
/// **non-canonical** form (a payload narrower than its minimum value).
pub(crate) fn decode_varint_le(marker: u8, payload: &[u8]) -> Option<u128> {
    let (value, minimum) = match marker {
        0..=250 => return Some(marker as u128),
        MARKER_U16 => (read_le16(payload)? as u128, 251),
        MARKER_U32 => (read_le32(payload)? as u128, 0x1_0000),
        MARKER_U64 => (read_le64(payload)? as u128, 0x1_0000_0000),
        MARKER_U128 => (read_le128(payload)?, 0x1_0000_0000_0000_0000),
        _ => return None,
    };
    if value < minimum {
        None
    } else {
        Some(value)
    }
}

/// ZigZag-encodes an `i128` into an unsigned `u128`.
pub(crate) const fn zigzag_encode(value: i128) -> u128 {
    ((value << 1) ^ (value >> 127)) as u128
}

/// ZigZag-decodes an unsigned `u128` back into an `i128`.
pub(crate) const fn zigzag_decode(encoded: u128) -> i128 {
    ((encoded >> 1) as i128) ^ -((encoded & 1) as i128)
}

fn read_le16(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < 2 {
        return None;
    }
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_le32(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 4 {
        return None;
    }
    let mut value = [0_u8; 4];
    value.copy_from_slice(&bytes[..4]);
    Some(u32::from_le_bytes(value))
}

fn read_le64(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 8 {
        return None;
    }
    let mut value = [0_u8; 8];
    value.copy_from_slice(&bytes[..8]);
    Some(u64::from_le_bytes(value))
}

fn read_le128(bytes: &[u8]) -> Option<u128> {
    if bytes.len() < 16 {
        return None;
    }
    let mut value = [0_u8; 16];
    value.copy_from_slice(&bytes[..16]);
    Some(u128::from_le_bytes(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_roundtrip_covers_all_widths() {
        let cases = [
            0u128,
            1,
            250,
            251,
            0xffff,
            0x1_0000,
            0xffff_ffff,
            0x1_0000_0000,
            0xffff_ffff_ffff_ffff,
            0x1_0000_0000_0000_0000,
            u128::MAX,
        ];
        for &value in &cases {
            let (bytes, length) = encode_varint_le(value);
            let marker = bytes[0];
            let payload = &bytes[1..length];
            assert_eq!(decode_varint_le(marker, payload), Some(value));
        }
    }

    #[test]
    fn non_canonical_forms_are_rejected() {
        // A 16-bit marker payload below 251 is non-canonical.
        assert_eq!(decode_varint_le(MARKER_U16, &[250, 0]), None);
        assert_eq!(decode_varint_le(MARKER_U16, &[251, 0]), Some(251));
        // A 32-bit marker payload below 2^16 is non-canonical.
        assert_eq!(decode_varint_le(MARKER_U32, &[0xff, 0xff, 0, 0]), None);
        assert_eq!(decode_varint_le(MARKER_U32, &[0, 0, 1, 0]), Some(0x1_0000));
        // Marker 255 is reserved.
        assert_eq!(decode_varint_le(255, &[]), None);
        // Truncated payloads are rejected.
        assert_eq!(decode_varint_le(MARKER_U64, &[1, 2, 3]), None);
    }

    #[test]
    fn zigzag_roundtrips() {
        for &value in &[
            i128::MIN,
            -1,
            0,
            1,
            i128::MAX,
            -123456789012345678901234567890,
        ] {
            assert_eq!(zigzag_decode(zigzag_encode(value)), value);
        }
        assert_eq!(zigzag_encode(0), 0);
        assert_eq!(zigzag_encode(-1), 1);
        assert_eq!(zigzag_encode(1), 2);
        assert_eq!(zigzag_decode(1), -1);
        assert_eq!(zigzag_decode(2), 1);
    }
}
