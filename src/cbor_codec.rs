//! Streaming RFC 8949 CBOR codec implementing [`nextjson::FormatEncoder`]
//! and [`nextjson::FormatDecoder`] directly over the wire bytes.
//!
//! This module is RustBinary's own CBOR implementation. It is the native
//! `T -> events -> CBOR bytes` / `CBOR bytes -> events -> T` path: values are
//! decoded straight from the input slice into the requested type with no
//! intermediate value tree and no JSON text round-trip, so the memory peak of
//! a decoded value is the decoded value itself.
//!
//! # Wire profile
//!
//! The profile is deliberately small and follows the JSON-compatible
//! subset of RFC 8949 plus explicit native byte strings, matching what the
//! rest of the crate's cross-format surface accepts:
//!
//! - `null` → `0xf6`, `false`/`true` → `0xf4`/`0xf5`;
//! - integers encode with the shortest definite head (major 0/1); values
//!   beyond `u64`/`i64` use the RFC 8949 bignum tags `2`/`3`;
//! - `f32`/`f64` → `0xfa`/`0xfb`; half-precision `0xf9` decodes to `f64`;
//! - text strings → major 3, byte strings → major 2 (native byte-string wire
//!   type used by [`FormatEncoder::write_bytes`]);
//! - arrays and maps use the indefinite-length forms (`0x9f`/`0xbf` …
//!   `0xff`), matching the crate's streaming encoder (no length patching);
//! - object keys are text strings, matching the JSON data model;
//! - `Option` maps to the JSON shape: `None` → `null`, `Some` → payload.
//!
//! Decoding accepts both definite- and indefinite-length containers and text
//! strings. Non-`2/3` semantic tags are ignored (their payload is decoded),
//! matching RFC 8949's model that tags annotate, never replace, a value.
//!
//! # Resource limits
//!
//! The same [`crate::Config`] policies as the native codec apply: the byte
//! limit bounds every read/write, the collection limit bounds the element
//! count of one sequence or map (checked eagerly for definite containers),
//! and nesting is capped at [`crate::tags::MAX_DEPTH`].
//!
//! # Semantics of `bytes`
//!
//! [`FormatDecoder::bytes`] is overridden to read the native major-2 byte
//! string (or an array of `u8`, matching the JSON spelling). Because the
//! nextjson token model has no byte-string token, `peek_token`/`next_token`
//! reject a raw major-2 value as outside the JSON-compatible value model;
//! `bytes()` and `option_tag` inspect the wire directly so `Option<Bytes>`
//! style payloads keep working.

use alloc::borrow::Cow;
use alloc::borrow::ToOwned;
use alloc::vec::Vec;

use nextjson::de::Mark;
use nextjson::Error as NextjsonError;
use nextjson::{FormatDecoder, FormatEncoder, Number, OptionTag, Token};

use crate::{
    config::Config,
    error::{Error, Result},
    tags::MAX_DEPTH,
    writer::EncodeWriter,
};

type NextjsonResult<T> = core::result::Result<T, NextjsonError>;

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Streaming RFC 8949 CBOR encoder driven by nextjson's event contract.
pub(crate) struct CborEncoder<W: EncodeWriter> {
    writer: W,
    config: Config,
    written: u64,
    depth: usize,
    counts: [u64; MAX_DEPTH],
    wire_error: Option<Error>,
}

impl<W: EncodeWriter> CborEncoder<W> {
    /// Creates an encoder over `writer` with the resource policies of
    /// `config`. Only the byte and collection limits are honored; CBOR itself
    /// fixes byte order (big endian) and shortest-head integers, so
    /// `config`'s endian/integer profile does not apply here.
    pub(crate) fn new(writer: W, config: Config) -> Self {
        Self {
            writer,
            config,
            written: 0,
            depth: 0,
            counts: [0; MAX_DEPTH],
            wire_error: None,
        }
    }

    /// Encodes `value` and returns the number of bytes written.
    pub(crate) fn finish<T: nextjson::NsonSerialize + ?Sized>(mut self, value: &T) -> Result<u64> {
        nextjson::NsonSerialize::nextencode(value, &mut self).map_err(|error| {
            self.wire_error
                .take()
                .unwrap_or_else(|| Error::from_nextjson(error))
        })?;
        if self.depth != 0 {
            return Err(Error::Custom(
                "encoder finished inside an unclosed container".into(),
            ));
        }
        Ok(self.written)
    }

    fn fail(&mut self, error: Error) -> NextjsonError {
        self.wire_error = Some(error);
        NextjsonError::custom("rustbinary cbor wire error")
    }

    fn emit(&mut self, bytes: &[u8]) -> Result<()> {
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

    /// Writes the shortest RFC 8949 head for `(major, argument)`.
    fn head(&mut self, major: u8, argument: u64) -> NextjsonResult<()> {
        let prefix = major << 5;
        let mut buffer = [0_u8; 9];
        let len = if argument < 24 {
            buffer[0] = prefix | argument as u8;
            1
        } else if argument <= u8::MAX as u64 {
            buffer[0] = prefix | 24;
            buffer[1] = argument as u8;
            2
        } else if argument <= u16::MAX as u64 {
            buffer[0] = prefix | 25;
            buffer[1..3].copy_from_slice(&(argument as u16).to_be_bytes());
            3
        } else if argument <= u32::MAX as u64 {
            buffer[0] = prefix | 26;
            buffer[1..5].copy_from_slice(&(argument as u32).to_be_bytes());
            5
        } else {
            buffer[0] = prefix | 27;
            buffer[1..9].copy_from_slice(&argument.to_be_bytes());
            9
        };
        self.emit(&buffer[..len]).map_err(|error| self.fail(error))
    }

    fn unsigned(&mut self, value: u128) -> NextjsonResult<()> {
        match u64::try_from(value) {
            Ok(value) => self.head(0, value),
            Err(_) => self.bignum(2, value),
        }
    }

    fn signed(&mut self, value: i128) -> NextjsonResult<()> {
        if value >= 0 {
            return self.unsigned(value as u128);
        }
        let argument = (-1 - value) as u128;
        match u64::try_from(argument) {
            Ok(argument) => self.head(1, argument),
            Err(_) => self.bignum(3, argument),
        }
    }

    fn bignum(&mut self, tag: u64, value: u128) -> NextjsonResult<()> {
        self.head(6, tag)?;
        let bytes = value.to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        let magnitude = &bytes[first..];
        self.head(2, magnitude.len() as u64)?;
        self.emit(magnitude).map_err(|error| self.fail(error))
    }

    fn write_text(&mut self, value: &str) -> NextjsonResult<()> {
        self.head(3, value.len() as u64)?;
        self.emit(value.as_bytes())
            .map_err(|error| self.fail(error))
    }

    fn enter_container(&mut self) -> NextjsonResult<()> {
        if self.depth >= MAX_DEPTH {
            return Err(self.fail(Error::Custom("encoder nesting depth limit exceeded".into())));
        }
        self.depth += 1;
        Ok(())
    }

    fn exit_container(&mut self) -> NextjsonResult<()> {
        if self.depth == 0 {
            return Err(self.fail(Error::Custom("container end without matching start".into())));
        }
        self.depth -= 1;
        self.counts[self.depth] = 0;
        self.emit(&[0xff]).map_err(|error| self.fail(error))
    }

    fn count_element(&mut self) -> NextjsonResult<()> {
        let index = self
            .depth
            .checked_sub(1)
            .ok_or_else(|| self.fail(Error::Custom("element outside any container".into())))?;
        let count = self.counts[index]
            .checked_add(1)
            .ok_or_else(|| self.fail(Error::CollectionLimit { limit: u64::MAX }))?;
        if let Some(limit) = self.config.collection_limit {
            if count > limit {
                return Err(self.fail(Error::CollectionLimit { limit }));
            }
        }
        self.counts[index] = count;
        Ok(())
    }
}

impl<W: EncodeWriter> FormatEncoder for CborEncoder<W> {
    type Error = NextjsonError;

    fn begin_array(&mut self) -> NextjsonResult<()> {
        self.enter_container()?;
        self.emit(&[0x9f]).map_err(|error| self.fail(error))
    }

    fn separator(&mut self) -> NextjsonResult<()> {
        self.count_element()
    }

    fn end_array(&mut self) -> NextjsonResult<()> {
        self.exit_container()
    }

    fn begin_object(&mut self) -> NextjsonResult<()> {
        self.enter_container()?;
        self.emit(&[0xbf]).map_err(|error| self.fail(error))
    }

    fn key(&mut self, key: &str) -> NextjsonResult<()> {
        self.count_element()?;
        self.write_text(key)
    }

    fn end_object(&mut self) -> NextjsonResult<()> {
        self.exit_container()
    }

    fn write_null(&mut self) -> NextjsonResult<()> {
        self.emit(&[0xf6]).map_err(|error| self.fail(error))
    }

    fn write_bool(&mut self, value: bool) -> NextjsonResult<()> {
        self.emit(&[if value { 0xf5 } else { 0xf4 }])
            .map_err(|error| self.fail(error))
    }

    fn write_str(&mut self, value: &str) -> NextjsonResult<()> {
        self.write_text(value)
    }

    fn write_char(&mut self, value: char) -> NextjsonResult<()> {
        let mut buffer = [0_u8; 4];
        self.write_text(value.encode_utf8(&mut buffer))
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

    fn write_i64(&mut self, value: i64) -> NextjsonResult<()> {
        self.signed(value as i128)
    }

    fn write_u64(&mut self, value: u64) -> NextjsonResult<()> {
        self.unsigned(value as u128)
    }

    fn write_i128(&mut self, value: i128) -> NextjsonResult<()> {
        self.signed(value)
    }

    fn write_u128(&mut self, value: u128) -> NextjsonResult<()> {
        self.unsigned(value)
    }

    fn write_f64(&mut self, value: f64) -> NextjsonResult<()> {
        self.emit(&[0xfb]).map_err(|error| self.fail(error))?;
        self.emit(&value.to_bits().to_be_bytes())
            .map_err(|error| self.fail(error))
    }

    fn write_f32(&mut self, value: f32) -> NextjsonResult<()> {
        self.emit(&[0xfa]).map_err(|error| self.fail(error))?;
        self.emit(&value.to_bits().to_be_bytes())
            .map_err(|error| self.fail(error))
    }

    fn write_bytes(&mut self, value: &[u8]) -> NextjsonResult<()> {
        self.head(2, value.len() as u64)?;
        self.emit(value).map_err(|error| self.fail(error))
    }

    fn write_none(&mut self) -> NextjsonResult<()> {
        self.write_null()
    }

    fn write_some(&mut self) -> NextjsonResult<()> {
        Ok(())
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContainerKind {
    Array,
    Object,
}

#[derive(Clone, Copy, Debug)]
struct Frame {
    kind: ContainerKind,
    /// `Some(remaining)` for definite containers, `None` for indefinite ones.
    definite: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
enum HeadArg {
    Value(u64),
    /// Major type 7 `ai == 25`: IEEE 754 half-precision float.
    Float16,
    /// Major type 7 `ai == 26`: IEEE 754 single-precision float.
    Float32,
    /// Major type 7 `ai == 27`: IEEE 754 double-precision float.
    Float64,
    Indefinite,
}

impl HeadArg {
    fn value(self) -> u64 {
        match self {
            HeadArg::Value(value) => value,
            _ => unreachable!("non-value argument where a value is required"),
        }
    }
}

/// Streaming RFC 8949 CBOR decoder implementing [`nextjson::FormatDecoder`].
///
/// Pull-based: every read advances over the input slice directly, so decoded
/// text strings borrow from the input and no value tree is materialized.
pub(crate) struct CborDecoder<'de> {
    input: &'de [u8],
    cursor: usize,
    config: Config,
    depth: usize,
    counts: [u64; MAX_DEPTH],
    frames: Vec<Frame>,
    lookahead: Option<Token<'de>>,
    wire_error: Option<Error>,
    expecting: Option<&'static str>,
}

impl<'de> CborDecoder<'de> {
    pub(crate) fn new(input: &'de [u8], config: Config) -> Self {
        Self {
            input,
            cursor: 0,
            config,
            depth: 0,
            counts: [0; MAX_DEPTH],
            frames: Vec::new(),
            lookahead: None,
            wire_error: None,
            expecting: None,
        }
    }

    /// Decodes one value that may borrow from `input`, then validates the
    /// trailing-byte policy.
    pub(crate) fn decode<T: nextjson::NsonDeserialize<'de>>(mut self) -> Result<T> {
        let value = T::nextdecode(&mut self).map_err(|error| {
            self.wire_error
                .take()
                .unwrap_or_else(|| Error::from_nextjson(error))
        })?;
        if self.depth != 0 {
            return Err(Error::Custom(
                "decoder finished inside an unclosed container".into(),
            ));
        }
        if self.config.trailing == crate::config::TrailingBytes::Reject
            && self.cursor != self.input.len()
        {
            return Err(Error::TrailingBytes {
                remaining: self.input.len() - self.cursor,
            });
        }
        Ok(value)
    }

    fn fail(&mut self, error: Error) -> NextjsonError {
        self.wire_error = Some(error);
        NextjsonError::custom("rustbinary cbor wire error")
    }

    fn invalid_type(&self, expected: &'static str, found: &Token<'_>) -> NextjsonError {
        let expected = match (self.expecting, expected) {
            (Some(expecting), "an object" | "an array") => expecting,
            _ => expected,
        };
        NextjsonError::invalid_type(expected, token_name(found))
    }

    fn take(&mut self, len: usize) -> Result<&'de [u8]> {
        let end = self.cursor.checked_add(len).ok_or(Error::UnexpectedEnd)?;
        if let Some(limit) = self.config.limit {
            if end as u64 > limit {
                return Err(Error::SizeLimit { limit });
            }
        }
        let bytes = self
            .input
            .get(self.cursor..end)
            .ok_or(Error::UnexpectedEnd)?;
        self.cursor = end;
        Ok(bytes)
    }

    fn peek_byte(&mut self) -> Result<u8> {
        let byte = *self.input.get(self.cursor).ok_or(Error::UnexpectedEnd)?;
        if let Some(limit) = self.config.limit {
            if (self.cursor as u64).saturating_add(1) > limit {
                return Err(Error::SizeLimit { limit });
            }
        }
        Ok(byte)
    }

    /// Reads one RFC 8949 head (major type + argument), consuming it.
    ///
    /// Major type 7 is special: `ai` 25/26/27 denote the float types
    /// themselves (no argument follows), `ai` 24 stores a simple value in the
    /// next byte, and 20/21/22 are `false`/`true`/`null`.
    fn read_head(&mut self) -> NextjsonResult<(u8, HeadArg)> {
        let initial = self.take(1).map_err(|error| self.fail(error))?[0];
        let major = initial >> 5;
        let ai = initial & 0x1f;
        let argument = if major == 7 {
            match ai {
                0..=23 => HeadArg::Value(ai as u64),
                24 => HeadArg::Value(24),
                25 => HeadArg::Float16,
                26 => HeadArg::Float32,
                27 => HeadArg::Float64,
                28..=30 => {
                    return Err(self.fail(Error::Custom(
                        "reserved CBOR additional information value".into(),
                    )))
                }
                31 => HeadArg::Indefinite,
                _ => unreachable!("additional information is five bits"),
            }
        } else {
            match ai {
                0..=23 => HeadArg::Value(ai as u64),
                24 => HeadArg::Value(self.take(1).map_err(|error| self.fail(error))?[0] as u64),
                25 => {
                    let bytes: [u8; 2] = self
                        .take(2)
                        .map_err(|error| self.fail(error))?
                        .try_into()
                        .expect("two bytes");
                    HeadArg::Value(u16::from_be_bytes(bytes) as u64)
                }
                26 => {
                    let bytes: [u8; 4] = self
                        .take(4)
                        .map_err(|error| self.fail(error))?
                        .try_into()
                        .expect("four bytes");
                    HeadArg::Value(u32::from_be_bytes(bytes) as u64)
                }
                27 => {
                    let bytes: [u8; 8] = self
                        .take(8)
                        .map_err(|error| self.fail(error))?
                        .try_into()
                        .expect("eight bytes");
                    HeadArg::Value(u64::from_be_bytes(bytes))
                }
                28..=30 => {
                    return Err(self.fail(Error::Custom(
                        "reserved CBOR additional information value".into(),
                    )))
                }
                31 => HeadArg::Indefinite,
                _ => unreachable!("additional information is five bits"),
            }
        };
        Ok((major, argument))
    }

    /// Decrements the definite element counter of the current container.
    fn dec_remaining(&mut self) -> NextjsonResult<()> {
        let underflow = match self.frames.last_mut() {
            Some(frame) => match &mut frame.definite {
                Some(remaining) => match remaining.checked_sub(1) {
                    Some(next) => {
                        *remaining = next;
                        false
                    }
                    None => true,
                },
                None => false,
            },
            None => false,
        };
        if underflow {
            return Err(self.fail(Error::Custom("too many container elements".into())));
        }
        Ok(())
    }

    /// Pushes a container frame after validating nesting depth and, for
    /// definite containers, the collection limit.
    fn enter_container(
        &mut self,
        kind: ContainerKind,
        definite: Option<u64>,
    ) -> NextjsonResult<()> {
        if self.depth >= MAX_DEPTH {
            return Err(self.fail(Error::Custom("decoder nesting depth limit exceeded".into())));
        }
        if let Some(count) = definite {
            if let Some(limit) = self.config.collection_limit {
                if count > limit {
                    return Err(self.fail(Error::CollectionLimit { limit }));
                }
            }
        }
        self.frames.push(Frame { kind, definite });
        self.depth += 1;
        Ok(())
    }

    fn pop_frame(&mut self, expected: ContainerKind) -> NextjsonResult<()> {
        let frame = self.frames.last().copied().ok_or_else(|| {
            self.fail(Error::Custom("container end without matching start".into()))
        })?;
        if frame.kind != expected {
            return Err(self.fail(Error::Custom(
                "container end does not match its start".into(),
            )));
        }
        self.frames.pop();
        self.depth -= 1;
        self.counts[self.depth] = 0;
        Ok(())
    }

    fn count_element(&mut self) -> NextjsonResult<()> {
        let index = self
            .depth
            .checked_sub(1)
            .ok_or_else(|| self.fail(Error::Custom("separator outside any container".into())))?;
        let count = self.counts[index]
            .checked_add(1)
            .ok_or_else(|| self.fail(Error::CollectionLimit { limit: u64::MAX }))?;
        if let Some(limit) = self.config.collection_limit {
            if count > limit {
                return Err(self.fail(Error::CollectionLimit { limit }));
            }
        }
        self.counts[index] = count;
        Ok(())
    }

    /// Whether the current container still has elements (does not count).
    fn has_more(&mut self) -> NextjsonResult<bool> {
        if self.lookahead.is_some() {
            return Ok(true);
        }
        let frame = match self.frames.last().copied() {
            Some(frame) => frame,
            None => return Err(self.fail(Error::Custom("separator outside any container".into()))),
        };
        match frame.definite {
            Some(remaining) => Ok(remaining > 0),
            None => Ok(self.peek_byte().map_err(|error| self.fail(error))? != 0xff),
        }
    }

    /// Reads the next token, consuming it. Container heads push a frame; the
    /// indefinite break (`0xff`) returns an end token without popping (the
    /// `end_array`/`end_object` methods own the pop).
    fn read_token(&mut self) -> NextjsonResult<Token<'de>> {
        loop {
            let (major, argument) = self.read_head()?;
            match major {
                0 => {
                    self.dec_remaining()?;
                    return Ok(Token::Number(Number::U64(argument.value())));
                }
                1 => {
                    self.dec_remaining()?;
                    let negative = argument.value();
                    // Value = -1 - negative, widened to i128 so i64::MIN.. works
                    // and values below i64::MIN stay exact as i128.
                    if negative <= i64::MAX as u64 {
                        return Ok(Token::Number(Number::I64(-1 - negative as i64)));
                    }
                    return Ok(Token::Number(Number::I128(-1 - negative as i128)));
                }
                2 => {
                    // Byte strings are outside the JSON-compatible value
                    // model; `FormatDecoder::bytes` reads them directly.
                    return Err(self.fail(Error::Custom(
                        "byte string (major type 2) is outside the value model; use FormatDecoder::bytes"
                            .into(),
                    )));
                }
                3 => {
                    let token = self.read_text(argument)?;
                    self.dec_remaining()?;
                    return Ok(token);
                }
                4 => {
                    self.dec_remaining()?;
                    let definite = match argument {
                        HeadArg::Value(count) => Some(count),
                        HeadArg::Indefinite => None,
                        _ => return Err(self.fail(Error::Custom("invalid array length".into()))),
                    };
                    self.enter_container(ContainerKind::Array, definite)?;
                    return Ok(Token::BeginArray);
                }
                5 => {
                    self.dec_remaining()?;
                    let definite = match argument {
                        HeadArg::Value(count) => Some(count),
                        HeadArg::Indefinite => None,
                        _ => return Err(self.fail(Error::Custom("invalid object length".into()))),
                    };
                    self.enter_container(ContainerKind::Object, definite)?;
                    return Ok(Token::BeginObject);
                }
                6 => {
                    let tag = argument.value();
                    match tag {
                        2 => {
                            let token = self.read_bignum(false)?;
                            self.dec_remaining()?;
                            return Ok(token);
                        }
                        3 => {
                            let token = self.read_bignum(true)?;
                            self.dec_remaining()?;
                            return Ok(token);
                        }
                        // Other semantic tags annotate rather than replace a
                        // value: skip the tag and decode the payload.
                        _ => continue,
                    }
                }
                7 => match argument {
                    HeadArg::Value(20) => {
                        self.dec_remaining()?;
                        return Ok(Token::Bool(false));
                    }
                    HeadArg::Value(21) => {
                        self.dec_remaining()?;
                        return Ok(Token::Bool(true));
                    }
                    HeadArg::Value(22) => {
                        self.dec_remaining()?;
                        return Ok(Token::Null);
                    }
                    HeadArg::Value(23) => {
                        return Err(self.fail(Error::Custom(
                            "undefined (0xf7) is outside the value model".into(),
                        )))
                    }
                    HeadArg::Value(24) => {
                        // Simple value stored in the following byte; none of
                        // the defined simple values are in the JSON model.
                        let _ = self.take(1).map_err(|error| self.fail(error))?;
                        return Err(
                            self.fail(Error::Custom("unsupported CBOR simple value".into()))
                        );
                    }
                    HeadArg::Float16 => {
                        self.dec_remaining()?;
                        let bytes: [u8; 2] = self
                            .take(2)
                            .map_err(|error| self.fail(error))?
                            .try_into()
                            .expect("two bytes");
                        return Ok(Token::Number(Number::F64(half_to_f64(u16::from_be_bytes(
                            bytes,
                        )))));
                    }
                    HeadArg::Float32 => {
                        self.dec_remaining()?;
                        let bytes: [u8; 4] = self
                            .take(4)
                            .map_err(|error| self.fail(error))?
                            .try_into()
                            .expect("four bytes");
                        let value = f32::from_be_bytes(bytes);
                        return Ok(Token::Number(Number::F64(value as f64)));
                    }
                    HeadArg::Float64 => {
                        self.dec_remaining()?;
                        let bytes: [u8; 8] = self
                            .take(8)
                            .map_err(|error| self.fail(error))?
                            .try_into()
                            .expect("eight bytes");
                        return Ok(Token::Number(Number::F64(f64::from_be_bytes(bytes))));
                    }
                    HeadArg::Value(_) => {
                        return Err(self.fail(Error::Custom("unsupported CBOR simple value".into())))
                    }
                    // The indefinite break that terminates an indefinite
                    // container.
                    HeadArg::Indefinite => {
                        let kind = match self.frames.last().copied() {
                            Some(frame) => frame.kind,
                            None => {
                                return Err(self.fail(Error::Custom(
                                    "indefinite break outside any container".into(),
                                )))
                            }
                        };
                        return Ok(match kind {
                            ContainerKind::Array => Token::EndArray,
                            ContainerKind::Object => Token::EndObject,
                        });
                    }
                },
                _ => unreachable!("major type is three bits"),
            }
        }
    }

    /// Reads a text string whose head has already been consumed.
    fn read_text(&mut self, argument: HeadArg) -> NextjsonResult<Token<'de>> {
        match argument {
            HeadArg::Value(len) => {
                let bytes = self.take(len as usize).map_err(|error| self.fail(error))?;
                let text = core::str::from_utf8(bytes).map_err(|_| {
                    self.fail(Error::Custom("CBOR text string is not valid UTF-8".into()))
                })?;
                Ok(Token::Str(Cow::Borrowed(text)))
            }
            HeadArg::Indefinite => {
                // Chunked text string: definite-length chunks terminated by
                // 0xff. Decoded chunks must be materialized.
                let mut out = Vec::new();
                loop {
                    let byte = self.peek_byte().map_err(|error| self.fail(error))?;
                    if byte == 0xff {
                        self.cursor += 1;
                        break;
                    }
                    let (major, argument) = self.read_head()?;
                    if major != 3 {
                        return Err(self.fail(Error::Custom(
                            "indefinite text string contains a non-text chunk".into(),
                        )));
                    }
                    let len = match argument {
                        HeadArg::Value(len) => len,
                        _ => {
                            return Err(
                                self.fail(Error::Custom("invalid text string length".into()))
                            )
                        }
                    };
                    out.extend_from_slice(
                        self.take(len as usize).map_err(|error| self.fail(error))?,
                    );
                }
                let text = core::str::from_utf8(&out).map_err(|_| {
                    self.fail(Error::Custom("CBOR text string is not valid UTF-8".into()))
                })?;
                Ok(Token::Str(Cow::Owned(text.to_owned())))
            }
            _ => Err(self.fail(Error::Custom("invalid text string length".into()))),
        }
    }
    /// Reads an RFC 8949 bignum (tag 2 or 3). The tag head is already
    /// consumed; the payload is a major-2 byte string holding the big-endian
    /// magnitude.
    fn read_bignum(&mut self, negative: bool) -> NextjsonResult<Token<'de>> {
        let (major, argument) = self.read_head()?;
        if major != 2 {
            return Err(self.fail(Error::Custom("bignum payload must be a byte string".into())));
        }
        let len = match argument {
            HeadArg::Value(len) => len,
            HeadArg::Indefinite => {
                return Err(self.fail(Error::Custom(
                    "indefinite bignum payload is not supported".into(),
                )))
            }
            _ => {
                return Err(self.fail(Error::Custom("bignum payload must be a byte string".into())))
            }
        };
        let bytes = self.take(len as usize).map_err(|error| self.fail(error))?;
        if bytes.len() > 16 {
            return Err(self.fail(Error::Custom(
                "bignum wider than 128 bits is not supported".into(),
            )));
        }
        let mut magnitude = [0_u8; 16];
        magnitude[16 - bytes.len()..].copy_from_slice(bytes);
        let value = u128::from_be_bytes(magnitude);
        if negative {
            // -1 - value
            Ok(Token::Number(Number::I128(-1 - value as i128)))
        } else {
            Ok(Token::Number(Number::U128(value)))
        }
    }

    /// Reads the next token without consuming it (honoring any pending
    /// lookahead).
    fn peek_token_inner(&mut self) -> NextjsonResult<Token<'de>> {
        if self.lookahead.is_none() {
            self.lookahead = Some(self.read_token()?);
        }
        Ok(self.lookahead.clone().expect("lookahead initialized"))
    }

    /// Consumes and returns the next token.
    fn take_token(&mut self) -> NextjsonResult<Token<'de>> {
        match self.lookahead.take() {
            Some(token) => Ok(token),
            None => self.read_token(),
        }
    }

    /// Skips one complete value (used for unknown object fields).
    fn skip_value_inner(&mut self) -> NextjsonResult<()> {
        let saved_depth = self.depth;
        self.take_token()?;
        while self.depth > saved_depth {
            let frame = match self.frames.last().copied() {
                Some(frame) => frame,
                None => return Err(self.fail(Error::Custom("unbalanced container in skip".into()))),
            };
            let finished = match frame.definite {
                Some(0) => true,
                Some(_) => false,
                None => self.peek_byte().map_err(|error| self.fail(error))? == 0xff,
            };
            if finished {
                if frame.definite.is_none() {
                    self.cursor += 1;
                }
                self.pop_frame(frame.kind)?;
                continue;
            }
            self.take_token()?;
        }
        Ok(())
    }
}

impl<'de> FormatDecoder<'de> for CborDecoder<'de> {
    type Error = NextjsonError;

    fn begin_object(&mut self) -> NextjsonResult<()> {
        match self.take_token()? {
            Token::BeginObject => Ok(()),
            other => Err(self.invalid_type("an object", &other)),
        }
    }

    fn end_object(&mut self) -> NextjsonResult<()> {
        self.end_container(ContainerKind::Object)
    }

    fn object_key(&mut self) -> NextjsonResult<Option<Cow<'de, str>>> {
        if let Some(token) = self.lookahead.take() {
            return match token {
                Token::Str(key) => Ok(Some(key)),
                Token::EndObject => Ok(None),
                other => Err(self.invalid_type("an object key string", &other)),
            };
        }
        let frame = match self.frames.last().copied() {
            Some(frame) => frame,
            None => return Err(self.fail(Error::Custom("object key outside any object".into()))),
        };
        if frame.kind != ContainerKind::Object {
            return Err(self.fail(Error::Custom(
                "object key outside an object container".into(),
            )));
        }
        match frame.definite {
            Some(0) => return Ok(None),
            Some(_) => {}
            None => {
                if self.peek_byte().map_err(|error| self.fail(error))? == 0xff {
                    // Leave the break for `end_object`.
                    return Ok(None);
                }
            }
        }
        let (major, argument) = self.read_head()?;
        if major != 3 {
            let found = match major {
                0 | 1 | 7 => Token::Number(Number::U64(0)),
                4 => Token::BeginArray,
                5 => Token::BeginObject,
                _ => Token::Null,
            };
            return Err(self.invalid_type("an object key string", &found));
        }
        match self.read_text(argument)? {
            Token::Str(key) => Ok(Some(key)),
            _ => unreachable!("read_text always returns a string token"),
        }
    }

    fn object_entry_sep(&mut self) -> NextjsonResult<bool> {
        self.count_element()?;
        self.has_more()
    }

    fn begin_array(&mut self) -> NextjsonResult<()> {
        match self.take_token()? {
            Token::BeginArray => Ok(()),
            other => Err(self.invalid_type("an array", &other)),
        }
    }

    fn end_array(&mut self) -> NextjsonResult<()> {
        self.end_container(ContainerKind::Array)
    }

    fn array_has_more(&mut self) -> NextjsonResult<bool> {
        self.has_more()
    }

    fn array_entry_sep(&mut self) -> NextjsonResult<bool> {
        self.count_element()?;
        self.has_more()
    }

    fn unit(&mut self) -> NextjsonResult<()> {
        match self.take_token()? {
            Token::Null => Ok(()),
            other => Err(self.invalid_type("null", &other)),
        }
    }

    fn bool(&mut self) -> NextjsonResult<bool> {
        match self.take_token()? {
            Token::Bool(value) => Ok(value),
            other => Err(self.invalid_type("a boolean", &other)),
        }
    }

    fn number(&mut self) -> NextjsonResult<Number> {
        match self.take_token()? {
            Token::Number(value) => Ok(value),
            other => Err(self.invalid_type("a number", &other)),
        }
    }

    fn string(&mut self) -> NextjsonResult<Cow<'de, str>> {
        match self.take_token()? {
            Token::Str(value) => Ok(value),
            other => Err(self.invalid_type("a string", &other)),
        }
    }

    fn char(&mut self) -> NextjsonResult<char> {
        match self.take_token()? {
            Token::Str(value) => {
                let mut chars = value.chars();
                match (chars.next(), chars.next()) {
                    (Some(ch), None) => Ok(ch),
                    _ => Err(self.fail(Error::InvalidChar)),
                }
            }
            other => Err(self.invalid_type("a character", &other)),
        }
    }

    fn bytes(&mut self) -> NextjsonResult<Cow<'de, [u8]>> {
        // Inspect the wire directly (bypassing the token model, which has no
        // byte-string token): major 2 is the native byte string, major 3 the
        // JSON spelling (text), major 4 an array of bytes.
        let byte = self.peek_byte().map_err(|error| self.fail(error))?;
        let major = byte >> 5;
        match major {
            2 => {
                let (major2, argument) = self.read_head()?;
                debug_assert_eq!(major2, 2);
                match argument {
                    HeadArg::Value(len) => {
                        let bytes = self.take(len as usize).map_err(|error| self.fail(error))?;
                        Ok(Cow::Borrowed(bytes))
                    }
                    HeadArg::Indefinite => {
                        let mut out = Vec::new();
                        loop {
                            let next = self.peek_byte().map_err(|error| self.fail(error))?;
                            if next == 0xff {
                                self.cursor += 1;
                                break;
                            }
                            let (maj, arg) = self.read_head()?;
                            if maj != 2 {
                                return Err(self.fail(Error::Custom(
                                    "indefinite byte string contains a non-byte chunk".into(),
                                )));
                            }
                            let len = match arg {
                                HeadArg::Value(len) => len,
                                _ => {
                                    return Err(self
                                        .fail(Error::Custom("invalid byte string length".into())))
                                }
                            };
                            out.extend_from_slice(
                                self.take(len as usize).map_err(|error| self.fail(error))?,
                            );
                        }
                        Ok(Cow::Owned(out))
                    }
                    _ => unreachable!("byte string head cannot be a float"),
                }
            }
            3 => match self.string()? {
                Cow::Borrowed(text) => Ok(Cow::Borrowed(text.as_bytes())),
                Cow::Owned(text) => Ok(Cow::Owned(text.into_bytes())),
            },
            4 => {
                self.begin_array()?;
                let mut out = Vec::new();
                while self.array_has_more()? {
                    out.push(self.u8()?);
                    if !self.array_entry_sep()? {
                        break;
                    }
                }
                self.end_array()?;
                Ok(Cow::Owned(out))
            }
            _ => Err(self.fail(Error::Custom(
                "expected a byte string or an array of bytes".into(),
            ))),
        }
    }

    fn option_tag(&mut self) -> NextjsonResult<OptionTag> {
        // Direct wire probe so `Option<Bytes>` keeps working even though the
        // token model rejects raw byte strings.
        if self.lookahead.is_none() && self.peek_byte().map_err(|error| self.fail(error))? == 0xf6 {
            self.cursor += 1;
            return Ok(OptionTag::None);
        }
        if matches!(self.lookahead, Some(Token::Null)) {
            self.lookahead = None;
            return Ok(OptionTag::None);
        }
        Ok(OptionTag::Some)
    }

    fn skip_value(&mut self) -> NextjsonResult<()> {
        self.skip_value_inner()
    }

    fn peek_token(&mut self) -> NextjsonResult<Token<'de>> {
        self.peek_token_inner()
    }

    fn next_token(&mut self) -> NextjsonResult<Token<'de>> {
        self.take_token()
    }

    fn save(&self) -> Mark {
        Mark::new(self.cursor, self.depth as u32)
    }

    fn restore(&mut self, mark: Mark) {
        let depth = (mark.depth() as usize).min(self.counts.len());
        self.cursor = mark.pos();
        self.depth = depth;
        self.frames.truncate(depth);
        for slot in &mut self.counts[depth..] {
            *slot = 0;
        }
        self.lookahead = None;
        self.wire_error = None;
    }

    fn set_expecting(&mut self, expecting: &'static str) -> Option<&'static str> {
        self.expecting.replace(expecting)
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

impl<'de> CborDecoder<'de> {
    /// Shared container-close logic for `end_array` / `end_object`.
    ///
    /// Definite containers must have zero remaining elements (the caller
    /// drained them through the separators); indefinite containers consume the
    /// `0xff` break unless a pending lookahead already consumed it.
    fn end_container(&mut self, kind: ContainerKind) -> NextjsonResult<()> {
        match self.lookahead.take() {
            Some(Token::EndArray) | Some(Token::EndObject) => {}
            Some(Token::BeginArray) | Some(Token::BeginObject) => {}
            Some(_) => {
                return Err(self.fail(Error::Custom("container ended with unread elements".into())))
            }
            None => {
                let frame = match self.frames.last().copied() {
                    Some(frame) => frame,
                    None => {
                        return Err(
                            self.fail(Error::Custom("container end without matching start".into()))
                        )
                    }
                };
                if frame.definite.is_none() {
                    let byte = self.peek_byte().map_err(|error| self.fail(error))?;
                    if byte != 0xff {
                        return Err(
                            self.fail(Error::Custom("container ended with unread elements".into()))
                        );
                    }
                    self.cursor += 1;
                }
            }
        }
        let frame = match self.frames.last().copied() {
            Some(frame) => frame,
            None => {
                return Err(self.fail(Error::Custom("container end without matching start".into())))
            }
        };
        if let Some(remaining) = frame.definite {
            if remaining != 0 {
                return Err(self.fail(Error::Custom("container ended with unread elements".into())));
            }
        }
        self.pop_frame(kind)
    }
}

fn token_name(token: &Token<'_>) -> &'static str {
    match token {
        Token::Null => "null",
        Token::Bool(_) => "bool",
        Token::Number(_) => "number",
        Token::Str(_) => "string",
        Token::BeginObject => "object",
        Token::EndObject => "end of object",
        Token::BeginArray => "array",
        Token::EndArray => "end of array",
    }
}

/// 2^n for `-1022 <= n <= 1023`, exact and available without `std`.
///
/// Powers of two are exactly representable in `f64`, and their bit pattern is
/// `exponent = 1023 + n` in the IEEE 754 bias, so `from_bits` yields the value
/// directly (no `powi`, which is a `std`-only method; `from_bits` is not const
/// before Rust 1.83, so this stays a plain `fn`).
fn pow2f(exponent: i32) -> f64 {
    // `i64` preserves the sign before biasing; casting a negative `i32`
    // directly to `u64` would wrap and overflow the bias addition.
    f64::from_bits(((exponent as i64 + 1023) as u64) << 52)
}

/// Converts an IEEE 754 half-precision value to `f64` (no `std` needed).
fn half_to_f64(half: u16) -> f64 {
    let sign = if half & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exponent = ((half >> 10) & 0x1f) as i32;
    let fraction = (half & 0x03ff) as u32;
    match exponent {
        0 => {
            if fraction == 0 {
                sign * 0.0
            } else {
                // Subnormal: value = fraction * 2^-24.
                sign * (fraction as f64) * pow2f(-24)
            }
        }
        0x1f => {
            if fraction == 0 {
                sign * f64::INFINITY
            } else {
                f64::NAN
            }
        }
        _ => sign * (fraction as f64 + 1024.0) * pow2f(exponent - 25),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::string::{String, ToString};
    use alloc::vec;
    use nextjson::NsonDeserialize;

    fn encode<T: nextjson::NsonSerialize + ?Sized>(value: &T) -> Vec<u8> {
        let mut out = Vec::new();
        CborEncoder::new(&mut out, Config::standard())
            .finish(value)
            .expect("encode");
        out
    }

    fn decode<'de, T: nextjson::NsonDeserialize<'de>>(bytes: &'de [u8]) -> T {
        CborDecoder::new(bytes, Config::standard())
            .decode()
            .expect("decode")
    }

    fn decode_err(bytes: &[u8]) -> Error {
        CborDecoder::new(bytes, Config::standard())
            .decode::<nextjson::Value>()
            .expect_err("expected decode failure")
    }

    #[test]
    fn encodes_rfc_8949_vectors() {
        assert_eq!(encode(&0u8), [0x00]);
        assert_eq!(encode(&23u8), [0x17]);
        assert_eq!(encode(&24u8), [0x18, 0x18]);
        assert_eq!(encode(&255u8), [0x18, 0xff]);
        assert_eq!(encode(&256u16), [0x19, 0x01, 0x00]);
        assert_eq!(encode(&65536u32), [0x1a, 0x00, 0x01, 0x00, 0x00]);
        assert_eq!(
            encode(&u64::MAX),
            [0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
        assert_eq!(encode(&-1i64), [0x20]);
        assert_eq!(encode(&-24i64), [0x37]);
        assert_eq!(encode(&-25i64), [0x38, 0x18]);
        assert_eq!(encode(&-256i64), [0x38, 0xff]);
        assert_eq!(encode(&-257i64), [0x39, 0x01, 0x00]);
        assert_eq!(encode(&true), [0xf5]);
        assert_eq!(encode(&false), [0xf4]);
        assert_eq!(encode(&Option::<u8>::None), [0xf6]);
        assert_eq!(encode(&Option::Some(5u8)), [0x05]);
        assert_eq!(encode("a"), [0x61, b'a']);
        assert_eq!(encode("IETF"), [0x64, b'I', b'E', b'T', b'F']);
        assert_eq!(encode(&vec![1u8, 2, 3]), [0x9f, 0x01, 0x02, 0x03, 0xff]);
        assert_eq!(
            encode(&1.0f64),
            [0xfb, 0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(encode(&1.0f32), [0xfa, 0x3f, 0x80, 0x00, 0x00]);
        // Bignum: u128 beyond u64 uses tag 2.
        let big = encode(&u128::MAX);
        assert_eq!(big[0], 0xc2);
        // The magnitude byte string holds 16 bytes (0x50 = major 2, ai 16).
        assert_eq!(big[1], 0x50);
        assert_eq!(&big[2..], &[0xff; 16]);
        // Native byte strings use major 2.
        let bytes = encode(&nextjson::Bytes(b"xyz"));
        assert_eq!(bytes, [0x43, b'x', b'y', b'z']);
    }

    #[test]
    fn decodes_definite_and_indefinite_containers() {
        // Definite array of three.
        assert_eq!(decode::<Vec<u8>>(&[0x83, 0x01, 0x02, 0x03]), vec![1, 2, 3]);
        // Indefinite array.
        assert_eq!(
            decode::<Vec<u8>>(&[0x9f, 0x01, 0x02, 0x03, 0xff]),
            vec![1, 2, 3]
        );
        // Definite map.
        let map: BTreeMap<String, u8> = decode(&[0xa2, 0x61, b'a', 0x01, 0x61, b'b', 0x02]);
        assert_eq!(
            map,
            BTreeMap::from([("a".to_string(), 1), ("b".to_string(), 2)])
        );
        // Indefinite map.
        let map: BTreeMap<String, u8> = decode(&[0xbf, 0x61, b'a', 0x01, 0x61, b'b', 0x02, 0xff]);
        assert_eq!(
            map,
            BTreeMap::from([("a".to_string(), 1), ("b".to_string(), 2)])
        );
        // Indefinite text string (chunked).
        assert_eq!(
            decode::<String>(&[0x7f, 0x62, b'a', b'b', 0x61, b'c', 0xff]),
            "abc"
        );
        // Nested definite-in-indefinite.
        let nested: Vec<Vec<u8>> = decode(&[0x9f, 0x82, 0x01, 0x02, 0x81, 0x03, 0xff]);
        assert_eq!(nested, vec![vec![1, 2], vec![3]]);
    }

    #[test]
    fn roundtrips_values_across_formats() {
        let data = (
            7u64,
            "hello",
            vec![1i32, -2, 3],
            Some("x".to_string()),
            Option::<u8>::None,
            -42i128,
            true,
        );
        let encoded = encode(&data);
        let decoded: (
            u64,
            String,
            Vec<i32>,
            Option<String>,
            Option<u8>,
            i128,
            bool,
        ) = decode(&encoded);
        assert_eq!(
            decoded,
            (
                7,
                "hello".to_string(),
                vec![1, -2, 3],
                Some("x".to_string()),
                None,
                -42,
                true
            )
        );
    }

    #[test]
    fn decodes_half_precision_and_ignores_annotating_tags() {
        assert_eq!(decode::<f64>(&[0xf9, 0x3c, 0x00]), 1.0);
        assert_eq!(decode::<f64>(&[0xf9, 0xc0, 0x00]), -2.0);
        assert_eq!(decode::<f64>(&[0xf9, 0x7b, 0xff]), 65504.0);
        assert_eq!(decode::<f64>(&[0xf9, 0x00, 0x01]), 5.960464477539063e-8);
        // Tag 1 (epoch) annotates a number; the payload is decoded as-is.
        assert_eq!(
            decode::<u64>(&[0xc1, 0x1a, 0x51, 0x4b, 0xb6, 0x70]),
            1363916400
        );
        // Tag 0 (date-time) annotates a 20-byte text string.
        assert_eq!(
            decode::<String>(&[
                0xc0, 0x74, b'2', b'0', b'1', b'3', b'-', b'0', b'3', b'-', b'2', b'1', b'T', b'2',
                b'0', b':', b'0', b'4', b':', b'0', b'0', b'Z'
            ]),
            "2013-03-21T20:04:00Z"
        );
    }

    #[test]
    fn bignums_roundtrip_beyond_64_bits() {
        for value in [
            u128::MAX,
            u128::from(u64::MAX) + 1,
            0x1234_5678_9abc_def0_1122_3344_5566_7788,
        ] {
            let encoded = encode(&value);
            assert_eq!(decode::<u128>(&encoded), value);
        }
        for value in [
            i128::MIN,
            i128::from(i64::MIN) - 1,
            -0x1234_5678_9abc_def0_1122_3344_5566_7789i128,
        ] {
            let encoded = encode(&value);
            assert_eq!(decode::<i128>(&encoded), value);
        }
        // A 16-byte magnitude round-trips exactly.
        let encoded = encode(&0x8000_0000_0000_0000u128);
        assert_eq!(decode::<u128>(&encoded), 0x8000_0000_0000_0000);
    }

    #[test]
    fn bytes_reads_native_and_array_spellings() {
        let encoded = encode(&nextjson::Bytes(b"abc"));
        let out: nextjson::Bytes<'_> = decode(&encoded);
        assert_eq!(out.as_bytes(), b"abc");
        // Array-of-u8 spelling is also accepted by `bytes()`.
        assert_eq!(decode::<Vec<u8>>(&[0x83, 0x01, 0x02, 0x03]), vec![1, 2, 3]);
    }

    #[test]
    fn cross_checks_against_nextjson_relay() {
        use nextjson::formats::{Cbor, Format};
        // Our encoder -> nextjson relay decoder.
        let ours = encode(&("value", 42u64, vec![1u8, 2, 3]));
        let decoded: (String, u64, Vec<u8>) = Cbor.decode(&ours).expect("nextjson decodes ours");
        assert_eq!(decoded, ("value".to_string(), 42, vec![1, 2, 3]));
        // nextjson relay encoder -> our decoder (indefinite forms).
        let theirs = Cbor
            .encode(&("value", 42u64, vec![1u8, 2, 3]))
            .expect("nextjson encodes");
        let decoded: (String, u64, Vec<u8>) = decode(&theirs);
        assert_eq!(decoded, ("value".to_string(), 42, vec![1, 2, 3]));
    }

    #[test]
    fn rejects_malformed_and_truncated_input() {
        // Truncated definite array.
        assert!(matches!(
            decode_err(&[0x83, 0x01, 0x02]),
            Error::UnexpectedEnd
        ));
        // Invalid UTF-8 text.
        assert!(matches!(decode_err(&[0x62, 0xff, 0xfe]), Error::Custom(_)));
        // Break outside any container.
        assert!(matches!(decode_err(&[0xff]), Error::Custom(_)));
        // Reserved additional information.
        assert!(matches!(decode_err(&[0x1e]), Error::Custom(_)));
        // Byte string in the value model position.
        assert!(matches!(decode_err(&[0x41, 0x01]), Error::Custom(_)));
        // Undefined simple value.
        assert!(matches!(decode_err(&[0xf7]), Error::Custom(_)));
        // Simple value 0xf8 0x20.
        assert!(matches!(decode_err(&[0xf8, 0x20]), Error::Custom(_)));
        // Definite container ended early by the caller's type.
        assert!(matches!(decode_err(&[0x82, 0x01]), Error::UnexpectedEnd));
        // Bignum wider than 128 bits.
        let mut wide = vec![0xc2, 0x59, 0x00, 0x11];
        wide.extend_from_slice(&[0u8; 17]);
        assert!(matches!(decode_err(&wide), Error::Custom(_)));
    }

    #[test]
    fn enforces_byte_collection_and_depth_limits() {
        // Byte limit on decode.
        let err = CborDecoder::new(
            &[0x1b, 0, 0, 0, 0, 0, 0, 0, 0],
            Config::standard().with_limit(4),
        )
        .decode::<u64>()
        .expect_err("byte limit");
        assert!(matches!(err, Error::SizeLimit { .. }));
        // Collection limit on a definite container.
        let err = CborDecoder::new(&[0x98, 0x64], Config::standard().with_collection_limit(3))
            .decode::<Vec<u8>>()
            .expect_err("collection limit");
        assert!(matches!(err, Error::CollectionLimit { limit: 3 }));
        // Depth limit.
        let mut deep = Vec::new();
        #[allow(clippy::same_item_push)]
        for _ in 0..(crate::tags::MAX_DEPTH + 2) {
            deep.push(0x81);
        }
        deep.push(0x00);
        #[allow(clippy::same_item_push)]
        for _ in 0..(crate::tags::MAX_DEPTH + 2) {
            deep.push(0xff);
        }
        let err = CborDecoder::new(&deep, Config::standard())
            .decode::<Vec<u8>>()
            .expect_err("depth limit");
        assert!(matches!(err, Error::Custom(_)));
        // Byte limit on encode.
        let err = CborEncoder::new(&mut Vec::new(), Config::standard().with_limit(2))
            .finish(&vec![1u8, 2, 3])
            .expect_err("encode byte limit");
        assert!(matches!(err, Error::SizeLimit { limit: 2 }));
    }

    #[test]
    fn restore_supports_untagged_backtracking() {
        let bytes = encode(&("abc", 9u64));
        let mut decoder = CborDecoder::new(&bytes, Config::standard());
        // Enter the tuple's array, then fail one variant before restoring.
        decoder.begin_array().expect("array");
        let mark = decoder.save();
        assert!(u64::nextdecode(&mut decoder).is_err());
        decoder.restore(mark);
        let first: String = String::nextdecode(&mut decoder).expect("retry");
        assert_eq!(first, "abc");
        assert!(decoder.array_entry_sep().expect("sep"));
        let second: u64 = u64::nextdecode(&mut decoder).expect("second value");
        assert_eq!(second, 9);
        assert!(!decoder.array_entry_sep().expect("last sep"));
        decoder.end_array().expect("end");
    }
}
