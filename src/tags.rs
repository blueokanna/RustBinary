//! Wire-format tag constants shared by the encoder and decoder.

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
