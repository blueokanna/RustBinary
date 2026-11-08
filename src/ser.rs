//! Serialization: a self-describing binary encoder implementing
//! [`nextjson::FormatEncoder`].
//!
//! The wire format is a **type-tagged self-describing** binary stream driven
//! entirely by nextjson's format-neutral event contract. Every value carries a
//! one-byte type tag for `Value`, untagged enums and `peek_token`.
//! Options use nextjson's null representation; arrays and objects are terminator-delimited
//! (`0xff`), which keeps the encoder fully streaming with no length patching
//! and works for slice, vector and counting writers alike.
//!
//! Tags (one byte each):
//!
//! | tag | value |
//! |-----|-------|
//! | `0x00` | `null` (unit / `None`) |
//! | `0x01` / `0x02` | `false` / `true` |
//! | `0x03` / `0x04` | `u64` / `u128` |
//! | `0x05` / `0x06` | `i64` / `i128` |
//! | `0x07` / `0x08` | `f64` / `f32` |
//! | `0x09` | string / char (length + UTF-8) |
//! | `0x0a` | array (elements, then `0xff`) |
//! | `0x0b` | object (`key` + value pairs, then `0xff`) |
//!
//! Integer and length payloads reuse the existing fixed-width / marker-varint
//! machinery, so [`crate::Config`] endianness and integer profiles continue to
//! govern every scalar.

use nextjson::Error as NextjsonError;
use nextjson::Number;

use alloc::vec::Vec;

use crate::{
    canonical::{encode_varint_le, zigzag_encode},
    config::{Config, IntEncoding},
    encode_state::{EncodeState, Kind},
    error::{Error, Result},
    tags::{
        MARKER_U128, MARKER_U16, MARKER_U32, MARKER_U64, TAG_ARRAY, TAG_END, TAG_F32, TAG_F64,
        TAG_FALSE, TAG_I128, TAG_I64, TAG_NULL, TAG_OBJECT, TAG_STRING, TAG_TRUE, TAG_U128,
        TAG_U64,
    },
    writer::{CountWriter, EncodeWriter, SliceWriter},
};

type NextjsonResult<T> = core::result::Result<T, NextjsonError>;

/// Encodes `value` into a fresh vector.
pub(crate) fn to_vec<T: nextjson::NsonSerialize + ?Sized>(
    value: &T,
    config: Config,
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    to_writer(&mut output, value, config)?;
    Ok(output)
}

/// Encodes `value` into `writer`, returning the number of bytes written.
pub(crate) fn to_writer<W: EncodeWriter, T: nextjson::NsonSerialize + ?Sized>(
    writer: W,
    value: &T,
    config: Config,
) -> Result<u64> {
    let mut encoder = Encoder {
        writer,
        config,
        written: 0,
        state: EncodeState::new(config),
        wire_error: None,
    };
    nextjson::NsonSerialize::nextencode(value, &mut encoder).map_err(|error| {
        encoder
            .wire_error
            .take()
            .unwrap_or_else(|| Error::from_nextjson(error))
    })?;
    if let Some(error) = encoder.wire_error {
        return Err(error);
    }
    encoder.state.finish()?;
    Ok(encoder.written)
}

/// Encodes `value` into a caller-owned slice.
pub(crate) fn to_slice<T: nextjson::NsonSerialize + ?Sized>(
    output: &mut [u8],
    value: &T,
    config: Config,
) -> Result<usize> {
    let mut writer = SliceWriter::new(output);
    to_writer(&mut writer, value, config)?;
    writer.finish()
}

/// Computes the exact encoded size without retaining bytes.
pub(crate) fn size<T: nextjson::NsonSerialize + ?Sized>(value: &T, config: Config) -> Result<u64> {
    to_writer(CountWriter::new(), value, config)
}

/// Self-describing binary encoder driven by nextjson's event contract.
struct Encoder<W> {
    writer: W,
    config: Config,
    written: u64,
    state: EncodeState,
    wire_error: Option<Error>,
}

impl<W: EncodeWriter> Encoder<W> {
    /// Records the precise RustBinary error and returns a nextjson error for
    /// the `FormatEncoder` boundary. The original is recovered by the public
    /// API in [`to_writer`].
    fn fail(&mut self, error: Error) -> NextjsonError {
        if self.wire_error.is_none() {
            self.wire_error = Some(error);
        }
        NextjsonError::custom("rustbinary wire error")
    }

    fn emit(&mut self, bytes: &[u8]) -> Result<()> {
        if self.wire_error.is_some() {
            return Err(Error::Custom("encoder already failed".into()));
        }
        let amount =
            u64::try_from(bytes.len()).map_err(|_| Error::IntegerOverflow { target: "u64" })?;
        let next = self
            .written
            .checked_add(amount)
            .ok_or(Error::SizeLimit { limit: u64::MAX })?;
        if let Some(limit) = self.config.limit {
            if next > limit {
                return Err(Error::SizeLimit { limit });
            }
        }
        self.writer.write_all(bytes)?;
        self.written = next;
        Ok(())
    }

    fn emit_tag(&mut self, tag: u8) -> NextjsonResult<()> {
        self.emit(&[tag]).map_err(|error| self.fail(error))
    }

    fn fixed<const N: usize>(&mut self, little: [u8; N], big: [u8; N]) -> NextjsonResult<()> {
        self.emit(if self.config.endian.little() {
            &little
        } else {
            &big
        })
        .map_err(|error| self.fail(error))
    }

    fn unsigned(&mut self, value: u128, fixed_bytes: usize) -> NextjsonResult<()> {
        if self.config.integers == IntEncoding::Variable && fixed_bytes > 1 {
            return self.varint(value);
        }
        let little = value.to_le_bytes();
        let big = value.to_be_bytes();
        self.emit(if self.config.endian.little() {
            &little[..fixed_bytes]
        } else {
            &big[16 - fixed_bytes..]
        })
        .map_err(|error| self.fail(error))
    }

    fn signed(&mut self, value: i128, fixed_bytes: usize) -> NextjsonResult<()> {
        if self.config.integers == IntEncoding::Variable && fixed_bytes > 1 {
            // ZigZag: the signed value maps to an unsigned magnitude. Values
            // are widened to i128 by the caller, so the 128-bit canonical form
            // is identical to the width-specific shift.
            return self.varint(zigzag_encode(value));
        }
        let little = value.to_le_bytes();
        let big = value.to_be_bytes();
        self.emit(if self.config.endian.little() {
            &little[..fixed_bytes]
        } else {
            &big[16 - fixed_bytes..]
        })
        .map_err(|error| self.fail(error))
    }

    fn varint(&mut self, value: u128) -> NextjsonResult<()> {
        // The little-endian canonical path is the single implementation in
        // `canonical` (shared with the decoder and the Kani proofs).
        if self.config.endian.little() {
            let (encoded, length) = encode_varint_le(value);
            return self
                .emit(&encoded[..length])
                .map_err(|error| self.fail(error));
        }
        // Big-endian path (kept inline; only the canonical LE profile is
        // covered by the formal proofs).
        match value {
            0..=250 => self.emit_tag(value as u8),
            251..=0xffff => {
                let payload = (value as u16).to_be_bytes();
                let mut encoded = [0_u8; 3];
                encoded[0] = MARKER_U16;
                encoded[1..].copy_from_slice(&payload);
                self.emit(&encoded).map_err(|error| self.fail(error))
            }
            0x1_0000..=0xffff_ffff => {
                let payload = (value as u32).to_be_bytes();
                let mut encoded = [0_u8; 5];
                encoded[0] = MARKER_U32;
                encoded[1..].copy_from_slice(&payload);
                self.emit(&encoded).map_err(|error| self.fail(error))
            }
            0x1_0000_0000..=0xffff_ffff_ffff_ffff => {
                let payload = (value as u64).to_be_bytes();
                let mut encoded = [0_u8; 9];
                encoded[0] = MARKER_U64;
                encoded[1..].copy_from_slice(&payload);
                self.emit(&encoded).map_err(|error| self.fail(error))
            }
            _ => {
                let payload = value.to_be_bytes();
                let mut encoded = [0_u8; 17];
                encoded[0] = MARKER_U128;
                encoded[1..].copy_from_slice(&payload);
                self.emit(&encoded).map_err(|error| self.fail(error))
            }
        }
    }

    /// Writes a length payload. Strings are bounded by the byte limit; the
    /// collection limit applies to sequence/map element counts (`count_element`).
    fn length(&mut self, len: usize) -> NextjsonResult<()> {
        let len =
            u64::try_from(len).map_err(|_| self.fail(Error::IntegerOverflow { target: "u64" }))?;
        self.unsigned(len as u128, 8)
    }

    fn write_str_value(&mut self, value: &str) -> NextjsonResult<()> {
        self.emit_tag(TAG_STRING)?;
        self.length(value.len())?;
        self.emit(value.as_bytes())
            .map_err(|error| self.fail(error))
    }

    fn value(&mut self) -> NextjsonResult<()> {
        self.state.value().map_err(|error| self.fail(error))
    }
}

impl<W: EncodeWriter> nextjson::FormatEncoder for Encoder<W> {
    type Error = NextjsonError;

    fn begin_array(&mut self) -> NextjsonResult<()> {
        self.state
            .begin(Kind::Array)
            .map_err(|error| self.fail(error))?;
        self.emit_tag(TAG_ARRAY)
    }

    fn separator(&mut self) -> NextjsonResult<()> {
        self.state
            .entry(Kind::Array)
            .map_err(|error| self.fail(error))
    }

    fn end_array(&mut self) -> NextjsonResult<()> {
        self.state
            .end(Kind::Array)
            .map_err(|error| self.fail(error))?;
        self.emit_tag(TAG_END)
    }

    fn begin_object(&mut self) -> NextjsonResult<()> {
        self.state
            .begin(Kind::Object)
            .map_err(|error| self.fail(error))?;
        self.emit_tag(TAG_OBJECT)
    }

    fn key(&mut self, key: &str) -> NextjsonResult<()> {
        self.state
            .entry(Kind::Object)
            .map_err(|error| self.fail(error))?;
        self.write_str_value(key)
    }

    fn end_object(&mut self) -> NextjsonResult<()> {
        self.state
            .end(Kind::Object)
            .map_err(|error| self.fail(error))?;
        self.emit_tag(TAG_END)
    }

    fn write_null(&mut self) -> NextjsonResult<()> {
        self.value()?;
        self.emit_tag(TAG_NULL)
    }

    fn write_bool(&mut self, value: bool) -> NextjsonResult<()> {
        self.value()?;
        self.emit_tag(if value { TAG_TRUE } else { TAG_FALSE })
    }

    fn write_u64(&mut self, value: u64) -> NextjsonResult<()> {
        self.value()?;
        self.emit_tag(TAG_U64)?;
        self.unsigned(value as u128, 8)
    }

    fn write_u128(&mut self, value: u128) -> NextjsonResult<()> {
        self.value()?;
        self.emit_tag(TAG_U128)?;
        self.unsigned(value, 16)
    }

    fn write_i64(&mut self, value: i64) -> NextjsonResult<()> {
        self.value()?;
        self.emit_tag(TAG_I64)?;
        self.signed(value as i128, 8)
    }

    fn write_i128(&mut self, value: i128) -> NextjsonResult<()> {
        self.value()?;
        self.emit_tag(TAG_I128)?;
        self.signed(value, 16)
    }

    fn write_f64(&mut self, value: f64) -> NextjsonResult<()> {
        self.value()?;
        if !value.is_finite() {
            return Err(self.fail(Error::NonFiniteFloat));
        }
        self.emit_tag(TAG_F64)?;
        self.fixed(value.to_le_bytes(), value.to_be_bytes())
    }

    fn write_f32(&mut self, value: f32) -> NextjsonResult<()> {
        self.value()?;
        if !value.is_finite() {
            return Err(self.fail(Error::NonFiniteFloat));
        }
        self.emit_tag(TAG_F32)?;
        self.fixed(value.to_le_bytes(), value.to_be_bytes())
    }

    fn write_str(&mut self, value: &str) -> NextjsonResult<()> {
        self.value()?;
        self.write_str_value(value)
    }

    fn write_char(&mut self, value: char) -> NextjsonResult<()> {
        self.value()?;
        let mut buffer = [0_u8; 4];
        self.write_str_value(value.encode_utf8(&mut buffer))
    }

    fn write_number(&mut self, value: &Number) -> NextjsonResult<()> {
        match *value {
            Number::U64(value) => self.write_u64(value),
            Number::U128(value) => self.write_u128(value),
            Number::I64(value) => self.write_i64(value),
            Number::I128(value) => self.write_i128(value),
            Number::F64(value) => self.write_f64(value),
        }
    }

    fn is_human_readable(&self) -> bool {
        // RustBinary is a binary wire format; types that branch on this flag
        // (timestamps, identifiers, byte strings) must use their binary shape.
        false
    }
}
