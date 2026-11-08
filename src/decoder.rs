//! Deserialization: a self-describing binary decoder implementing
//! [`nextjson::FormatDecoder`].
//!
//! Mirrors [`crate::ser`]: every value starts with a one-byte type tag and
//! containers are terminator-delimited (`0xff`). The decoder keeps a
//! single-token lookahead so [`nextjson::FormatDecoder::peek_token`] supports
//! `Option`, `Value` and untagged-enum backtracking without consuming input.
//! Unescaped strings borrow directly from the input, preserving the codec's
//! zero-copy `#[njson(borrow)]` contract.

use alloc::borrow::Cow;
use core::str;

use nextjson::de::Mark;
use nextjson::Error as NextjsonError;
use nextjson::{FormatDecoder, Number, Token};

use crate::{
    canonical::{decode_varint_le, zigzag_decode},
    config::{Config, IntEncoding, TrailingBytes},
    error::{Error, Result},
    tags::{
        MARKER_U128, MARKER_U16, MARKER_U32, MARKER_U64, MAX_DEPTH, TAG_ARRAY, TAG_END, TAG_F32,
        TAG_F64, TAG_FALSE, TAG_I128, TAG_I64, TAG_NULL, TAG_OBJECT, TAG_STRING, TAG_TRUE,
        TAG_U128, TAG_U64,
    },
};

type NextjsonResult<T> = core::result::Result<T, NextjsonError>;

pub(crate) fn from_slice<'de, T: nextjson::NsonDeserialize<'de>>(
    input: &'de [u8],
    config: Config,
) -> Result<T> {
    let (value, consumed) = from_slice_with_consumed(input, config)?;
    if config.trailing == TrailingBytes::Reject && consumed != input.len() {
        return Err(Error::TrailingBytes {
            remaining: input.len() - consumed,
        });
    }
    Ok(value)
}

pub(crate) fn from_slice_with_consumed<'de, T: nextjson::NsonDeserialize<'de>>(
    input: &'de [u8],
    config: Config,
) -> Result<(T, usize)> {
    let (value, consumed, _, _) = from_slice_with_resources(input, config)?;
    Ok((value, consumed))
}

pub(crate) fn from_slice_with_resources<'de, T: nextjson::NsonDeserialize<'de>>(
    input: &'de [u8],
    config: Config,
) -> Result<(T, usize, u64, u64)> {
    let mut decoder = Decoder::new(input, config);
    let value = T::nextdecode(&mut decoder).map_err(|error| {
        decoder
            .wire_error
            .take()
            .unwrap_or_else(|| Error::from_nextjson(error))
    })?;
    if decoder.depth != 0 {
        return Err(Error::Custom(
            "decoder finished inside an unclosed container".into(),
        ));
    }
    // A speculative decoder must not swallow a resource failure and return
    // success after restoring a checkpoint.
    if let Some(error) = decoder.wire_error {
        return Err(error);
    }
    Ok((value, decoder.cursor, decoder.work, decoder.values))
}

pub(crate) fn probe(input: &[u8], config: Config) -> Result<crate::probe::Probe> {
    let mut decoder = Decoder::new(input, config);
    decoder.skip_value_inner().map_err(|error| {
        decoder
            .wire_error
            .take()
            .unwrap_or_else(|| Error::from_nextjson(error))
    })?;
    if config.trailing == TrailingBytes::Reject && decoder.cursor != input.len() {
        return Err(Error::TrailingBytes {
            remaining: input.len() - decoder.cursor,
        });
    }
    Ok(crate::probe::Probe::new(
        decoder.cursor,
        decoder.containers,
        decoder.elements,
        decoder.peak_depth,
        decoder.values,
        decoder.max_collection_len,
    ))
}

struct Decoder<'de> {
    input: &'de [u8],
    cursor: usize,
    config: Config,
    depth: usize,
    counts: [u64; MAX_DEPTH],
    lookahead: Option<Token<'de>>,
    wire_error: Option<Error>,
    /// Type description installed by [`nextjson::FormatDecoder::set_expecting`]
    /// (nextjson 0.1.3). Derived `NsonDeserialize` implementations call it with
    /// [`nextjson::NsonDeserialize::expecting`], so container type-mismatch
    /// errors can name the type the caller actually tried to decode.
    expecting: Option<&'static str>,
    work: u64,
    values: u64,
    lookahead_start: usize,
    containers: u64,
    elements: u64,
    peak_depth: usize,
    max_collection_len: u64,
}

impl<'de> Decoder<'de> {
    fn new(input: &'de [u8], config: Config) -> Self {
        Self {
            input,
            cursor: 0,
            config,
            depth: 0,
            counts: [0; MAX_DEPTH],
            lookahead: None,
            wire_error: None,
            expecting: None,
            work: 0,
            values: 0,
            lookahead_start: 0,
            containers: 0,
            elements: 0,
            peak_depth: 0,
            max_collection_len: 0,
        }
    }

    fn fail(&mut self, error: Error) -> NextjsonError {
        if !self
            .wire_error
            .as_ref()
            .is_some_and(Error::is_resource_limit)
        {
            self.wire_error = Some(error);
        }
        NextjsonError::custom("rustbinary wire error")
    }

    fn invalid_type(&self, expected: &'static str, found: &Token<'_>) -> NextjsonError {
        let expected = match (self.expecting, expected) {
            (Some(expecting), "an object" | "an array") => expecting,
            _ => expected,
        };
        NextjsonError::invalid_type(expected, token_name(found))
    }

    fn take(&mut self, len: usize) -> Result<&'de [u8]> {
        let work = self
            .work
            .checked_add(len as u64)
            .ok_or(Error::WorkLimit { limit: u64::MAX })?;
        if let Some(limit) = self.config.decode_work_limit {
            if work > limit {
                return Err(Error::WorkLimit { limit });
            }
        }
        self.work = work;
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

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn peek_byte(&self) -> Result<u8> {
        self.input
            .get(self.cursor)
            .copied()
            .ok_or(Error::UnexpectedEnd)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::UnexpectedEnd)
    }

    fn unsigned(&mut self, fixed_bytes: usize, target_max: u128) -> NextjsonResult<u128> {
        let value = if self.config.integers == IntEncoding::Variable && fixed_bytes > 1 {
            self.varint()?
        } else {
            let source = self.take(fixed_bytes).map_err(|error| self.fail(error))?;
            let mut bytes = [0; 16];
            if self.config.endian.little() {
                bytes[..fixed_bytes].copy_from_slice(source);
                u128::from_le_bytes(bytes)
            } else {
                bytes[16 - fixed_bytes..].copy_from_slice(source);
                u128::from_be_bytes(bytes)
            }
        };
        if value > target_max {
            Err(self.fail(Error::IntegerOverflow {
                target: unsigned_name(fixed_bytes),
            }))
        } else {
            Ok(value)
        }
    }

    fn signed(&mut self, fixed_bytes: usize, min: i128, max: i128) -> NextjsonResult<i128> {
        let value = if self.config.integers == IntEncoding::Variable && fixed_bytes > 1 {
            let encoded = self.varint()?;
            zigzag_decode(encoded)
        } else {
            let source = self.take(fixed_bytes).map_err(|error| self.fail(error))?;
            let fill = if source.first().is_some_and(|first| {
                if self.config.endian.little() {
                    source[fixed_bytes - 1] & 0x80 != 0
                } else {
                    first & 0x80 != 0
                }
            }) {
                0xff
            } else {
                0
            };
            let mut bytes = [fill; 16];
            if self.config.endian.little() {
                bytes[..fixed_bytes].copy_from_slice(source);
                i128::from_le_bytes(bytes)
            } else {
                bytes[16 - fixed_bytes..].copy_from_slice(source);
                i128::from_be_bytes(bytes)
            }
        };
        if value < min || value > max {
            Err(self.fail(Error::IntegerOverflow {
                target: signed_name(fixed_bytes),
            }))
        } else {
            Ok(value)
        }
    }

    fn varint(&mut self) -> NextjsonResult<u128> {
        let marker = self.byte().map_err(|error| self.fail(error))?;
        if self.config.endian.little() {
            let payload_len = match marker {
                0..=250 => return Ok(marker as u128),
                MARKER_U16 => 2,
                MARKER_U32 => 4,
                MARKER_U64 => 8,
                MARKER_U128 => 16,
                other => return Err(self.fail(Error::InvalidVarintMarker(other))),
            };
            let bytes = self.take(payload_len).map_err(|error| self.fail(error))?;
            return match decode_varint_le(marker, bytes) {
                Some(value) => Ok(value),
                None => Err(self.fail(Error::NonCanonicalVarint)),
            };
        }
        let (value, minimum) = match marker {
            0..=250 => return Ok(marker as u128),
            MARKER_U16 => (self.literal_u16()? as u128, 251),
            MARKER_U32 => (self.literal_u32()? as u128, 0x1_0000),
            MARKER_U64 => (self.literal_u64()? as u128, 0x1_0000_0000),
            MARKER_U128 => (self.literal_u128()?, 0x1_0000_0000_0000_0000),
            other => return Err(self.fail(Error::InvalidVarintMarker(other))),
        };
        if value < minimum {
            Err(self.fail(Error::NonCanonicalVarint))
        } else {
            Ok(value)
        }
    }

    fn literal_u16(&mut self) -> NextjsonResult<u16> {
        let bytes = self.fixed().map_err(|error| self.fail(error))?;
        Ok(if self.config.endian.little() {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        })
    }
    fn literal_u32(&mut self) -> NextjsonResult<u32> {
        let bytes = self.fixed().map_err(|error| self.fail(error))?;
        Ok(if self.config.endian.little() {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    }
    fn literal_u64(&mut self) -> NextjsonResult<u64> {
        let bytes = self.fixed().map_err(|error| self.fail(error))?;
        Ok(if self.config.endian.little() {
            u64::from_le_bytes(bytes)
        } else {
            u64::from_be_bytes(bytes)
        })
    }
    fn literal_u128(&mut self) -> NextjsonResult<u128> {
        let bytes = self.fixed().map_err(|error| self.fail(error))?;
        Ok(if self.config.endian.little() {
            u128::from_le_bytes(bytes)
        } else {
            u128::from_be_bytes(bytes)
        })
    }

    fn read_u64(&mut self) -> NextjsonResult<u64> {
        Ok(self.unsigned(8, u64::MAX as u128)? as u64)
    }
    fn read_u128(&mut self) -> NextjsonResult<u128> {
        self.unsigned(16, u128::MAX)
    }
    fn read_i64(&mut self) -> NextjsonResult<i64> {
        Ok(self.signed(8, i64::MIN as i128, i64::MAX as i128)? as i64)
    }
    fn read_i128(&mut self) -> NextjsonResult<i128> {
        self.signed(16, i128::MIN, i128::MAX)
    }
    fn read_f64(&mut self) -> NextjsonResult<f64> {
        let bytes = self.fixed().map_err(|error| self.fail(error))?;
        Ok(if self.config.endian.little() {
            f64::from_le_bytes(bytes)
        } else {
            f64::from_be_bytes(bytes)
        })
    }
    fn read_f32(&mut self) -> NextjsonResult<f32> {
        let bytes = self.fixed().map_err(|error| self.fail(error))?;
        Ok(if self.config.endian.little() {
            f32::from_le_bytes(bytes)
        } else {
            f32::from_be_bytes(bytes)
        })
    }

    fn length(&mut self) -> NextjsonResult<u64> {
        let value = self.unsigned(8, u64::MAX as u128)?;
        Ok(value as u64)
    }

    fn read_string(&mut self) -> NextjsonResult<Cow<'de, str>> {
        let len = usize::try_from(self.length()?)
            .map_err(|_| self.fail(Error::IntegerOverflow { target: "usize" }))?;
        let bytes = self.take(len).map_err(|error| self.fail(error))?;
        let value = str::from_utf8(bytes).map_err(|error| self.fail(Error::InvalidUtf8(error)))?;
        Ok(Cow::Borrowed(value))
    }

    fn read_token(&mut self) -> NextjsonResult<Token<'de>> {
        let values = self
            .values
            .checked_add(1)
            .ok_or_else(|| self.fail(Error::ValueLimit { limit: u64::MAX }))?;
        if let Some(limit) = self.config.value_limit {
            if values > limit {
                return Err(self.fail(Error::ValueLimit { limit }));
            }
        }
        self.values = values;
        let tag = self.byte().map_err(|error| self.fail(error))?;
        match tag {
            TAG_NULL => Ok(Token::Null),
            TAG_FALSE => Ok(Token::Bool(false)),
            TAG_TRUE => Ok(Token::Bool(true)),
            TAG_U64 => Ok(Token::Number(Number::U64(self.read_u64()?))),
            TAG_U128 => Ok(Token::Number(Number::U128(self.read_u128()?))),
            TAG_I64 => Ok(Token::Number(Number::I64(self.read_i64()?))),
            TAG_I128 => Ok(Token::Number(Number::I128(self.read_i128()?))),
            TAG_F64 => Ok(Token::Number(Number::F64(self.read_f64()?))),
            TAG_F32 => Ok(Token::Number(Number::F64(self.read_f32()? as f64))),
            TAG_STRING => Ok(Token::Str(self.read_string()?)),
            TAG_ARRAY => Ok(Token::BeginArray),
            TAG_OBJECT => Ok(Token::BeginObject),
            TAG_END => Err(self.fail(Error::Custom(
                "unexpected end-of-container terminator".into(),
            ))),
            _ => Err(self.fail(Error::Custom("invalid value tag".into()))),
        }
    }

    fn peek_token_inner(&mut self) -> NextjsonResult<Token<'de>> {
        if self.lookahead.is_none() {
            self.lookahead_start = self.cursor;
            self.lookahead = Some(self.read_token()?);
        }
        Ok(self.lookahead.clone().expect("lookahead initialized"))
    }

    fn take_token(&mut self) -> NextjsonResult<Token<'de>> {
        match self.lookahead.take() {
            Some(token) => Ok(token),
            None => self.read_token(),
        }
    }

    fn peek_end(&mut self) -> NextjsonResult<bool> {
        if self.lookahead.is_some() {
            return Ok(false);
        }
        Ok(self.peek_byte().map_err(|error| self.fail(error))? == TAG_END)
    }

    fn push_frame(&mut self) -> NextjsonResult<()> {
        if self.depth >= self.config.depth_limit {
            return Err(self.fail(Error::DepthLimit {
                limit: self.config.depth_limit,
            }));
        }
        self.depth += 1;
        self.containers += 1;
        self.peak_depth = self.peak_depth.max(self.depth);
        Ok(())
    }

    fn exit_container(&mut self) -> NextjsonResult<()> {
        if self.depth == 0 {
            return Err(self.fail(Error::Custom("container end without matching start".into())));
        }
        // The entry separators only probe for the terminator; consuming it is
        // this method's job (mirroring nextjson's `}` / `]` consumption).
        // `byte()` is `take(1)`, so the terminator counts against the byte
        // limit exactly as the encoder's `emit` does — keeping the consumed
        // byte count at or below the configured limit on both directions.
        let byte = self.byte().map_err(|error| self.fail(error))?;
        if byte != TAG_END {
            return Err(self.fail(Error::Custom("container end without terminator".into())));
        }
        self.depth -= 1;
        // Reset this container's element counter so sibling containers at the
        // same depth each get their own collection-limit budget.
        self.counts[self.depth] = 0;
        Ok(())
    }

    fn container_sep(&mut self) -> NextjsonResult<bool> {
        let index = self.depth.checked_sub(1).ok_or_else(|| {
            self.fail(Error::Custom(
                "container separator outside any container".into(),
            ))
        })?;
        let count = self.counts[index]
            .checked_add(1)
            .ok_or_else(|| self.fail(Error::CollectionLimit { limit: u64::MAX }))?;
        if let Some(limit) = self.config.collection_limit {
            if count > limit {
                return Err(self.fail(Error::CollectionLimit { limit }));
            }
        }
        self.counts[index] = count;
        self.max_collection_len = self.max_collection_len.max(count);
        self.elements += 1;
        let more = !self.peek_end()?;
        if more {
            self.check_next_element()?;
        }
        Ok(more)
    }

    fn check_next_element(&mut self) -> NextjsonResult<()> {
        if let (Some(index), Some(limit)) =
            (self.depth.checked_sub(1), self.config.collection_limit)
        {
            if self.counts[index] >= limit {
                return Err(self.fail(Error::CollectionLimit { limit }));
            }
        }
        Ok(())
    }

    fn skip_value_inner(&mut self) -> NextjsonResult<()> {
        match self.take_token()? {
            Token::BeginArray => {
                self.push_frame()?;
                while self.array_has_more()? {
                    self.skip_value_inner()?;
                    if !self.container_sep()? {
                        break;
                    }
                }
                self.exit_container()
            }
            Token::BeginObject => {
                self.push_frame()?;
                while self.object_key()?.is_some() {
                    self.skip_value_inner()?;
                    if !self.container_sep()? {
                        break;
                    }
                }
                self.exit_container()
            }
            _ => Ok(()),
        }
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

const fn unsigned_name(bytes: usize) -> &'static str {
    match bytes {
        2 => "u16",
        4 => "u32",
        8 => "u64",
        16 => "u128",
        _ => "unsigned integer",
    }
}
const fn signed_name(bytes: usize) -> &'static str {
    match bytes {
        2 => "i16",
        4 => "i32",
        8 => "i64",
        16 => "i128",
        _ => "signed integer",
    }
}

impl<'de> FormatDecoder<'de> for Decoder<'de> {
    type Error = NextjsonError;

    fn begin_object(&mut self) -> NextjsonResult<()> {
        match self.take_token()? {
            Token::BeginObject => {}
            other => return Err(self.invalid_type("an object", &other)),
        }
        self.push_frame()
    }

    fn end_object(&mut self) -> NextjsonResult<()> {
        self.exit_container()
    }

    fn object_key(&mut self) -> NextjsonResult<Option<Cow<'de, str>>> {
        if self.peek_end()? {
            return Ok(None);
        }
        self.check_next_element()?;
        match self.take_token()? {
            Token::Str(key) => Ok(Some(key)),
            other => Err(self.invalid_type("an object key string", &other)),
        }
    }

    fn object_entry_sep(&mut self) -> NextjsonResult<bool> {
        self.container_sep()
    }

    fn begin_array(&mut self) -> NextjsonResult<()> {
        match self.take_token()? {
            Token::BeginArray => {}
            other => return Err(self.invalid_type("an array", &other)),
        }
        self.push_frame()
    }

    fn end_array(&mut self) -> NextjsonResult<()> {
        self.exit_container()
    }

    fn array_has_more(&mut self) -> NextjsonResult<bool> {
        let more = !self.peek_end()?;
        if more {
            self.check_next_element()?;
        }
        Ok(more)
    }

    fn array_entry_sep(&mut self) -> NextjsonResult<bool> {
        self.container_sep()
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
        let cursor = if self.lookahead.is_some() {
            self.lookahead_start
        } else {
            self.cursor
        };
        Mark::new(cursor, self.depth as u32)
    }

    fn restore(&mut self, mark: Mark) {
        let depth = (mark.depth() as usize).min(self.counts.len());
        self.cursor = mark.pos().min(self.input.len());
        self.depth = depth;
        for slot in &mut self.counts[depth..] {
            *slot = 0;
        }
        self.lookahead = None;
        // Resource errors are sticky; retries cannot reset the global budget.
        if !self
            .wire_error
            .as_ref()
            .is_some_and(Error::is_resource_limit)
        {
            self.wire_error = None;
        }
    }

    fn set_expecting(&mut self, expecting: &'static str) -> Option<&'static str> {
        self.expecting.replace(expecting)
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}
