//! Wire-format constants shared by the encoder and decoder.
//!
//! This module is the single source of truth for the binary wire layout:
//! value tags, container terminators, and marker-varint prefixes. Both the
//! encoder (`ser`) and the decoder (`decoder`) import these instead of
//! re-declaring them, so the two directions can never drift apart.

/// `null` (unit / `Option::None`).
pub(crate) const TAG_NULL: u8 = 0x00;
/// `false`.
pub(crate) const TAG_FALSE: u8 = 0x01;
/// `true`.
pub(crate) const TAG_TRUE: u8 = 0x02;
/// `u64`.
pub(crate) const TAG_U64: u8 = 0x03;
/// `u128`.
pub(crate) const TAG_U128: u8 = 0x04;
/// `i64`.
pub(crate) const TAG_I64: u8 = 0x05;
/// `i128`.
pub(crate) const TAG_I128: u8 = 0x06;
/// `f64`.
pub(crate) const TAG_F64: u8 = 0x07;
/// `f32`.
pub(crate) const TAG_F32: u8 = 0x08;
/// String / char (length + UTF-8).
pub(crate) const TAG_STRING: u8 = 0x09;
/// Array (elements, then `TAG_END`).
pub(crate) const TAG_ARRAY: u8 = 0x0a;
/// Object (`key` + value pairs, then `TAG_END`).
pub(crate) const TAG_OBJECT: u8 = 0x0b;
/// End-of-container terminator. Never a valid value tag.
pub(crate) const TAG_END: u8 = 0xff;

/// Marker prefix for a 16-bit marker-varint payload (`251..=0xffff`).
pub(crate) const MARKER_U16: u8 = 251;
/// Marker prefix for a 32-bit marker-varint payload (`0x1_0000..=0xffff_ffff`).
pub(crate) const MARKER_U32: u8 = 252;
/// Marker prefix for a 64-bit marker-varint payload (`0x1_0000_0000..=0xffff_ffff_ffff_ffff`).
pub(crate) const MARKER_U64: u8 = 253;
/// Marker prefix for a 128-bit marker-varint payload (`>= 0x1_0000_0000_0000_0000`).
pub(crate) const MARKER_U128: u8 = 254;

/// Maximum container nesting depth enforced by both encoder and decoder.
///
/// This must be identical on both sides: it sizes the per-depth element-count
/// tables, so a drift would let one direction accept frames the other rejects
/// (or vice versa). Mirrors nextjson's default decode depth.
pub(crate) const MAX_DEPTH: usize = 128;
