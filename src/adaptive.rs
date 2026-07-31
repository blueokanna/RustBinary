use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::{BitReader, BitWriter, Config, Error, Result, TrailingBytes};

const RAW_UTF8: u8 = 0;
const ASCII7: u8 = 1;
const RAW_INTEGERS: u8 = 0;
const DELTA_INTEGERS: u8 = 1;
const RLE_INTEGERS: u8 = 2;

/// Selected representation for one adaptively encoded string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StringStrategy {
    /// Original UTF-8 bytes.
    RawUtf8,
    /// Seven bits per ASCII scalar.
    Ascii7,
}

/// Selected representation for one adaptively encoded `i64` collection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectionStrategy {
    /// Independent ZigZag varints.
    Raw,
    /// First value followed by ZigZag deltas.
    Delta,
    /// ZigZag value and run-length pairs.
    RunLength,
}

/// Data-aware encoding configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdaptiveConfig {
    base: Config,
}

impl AdaptiveConfig {
    pub(crate) const fn new(base: Config) -> Self {
        Self { base }
    }

    /// Returns the variable-integer payload configuration.
    pub const fn base_config(self) -> Config {
        self.base
    }

    /// Uses value-width adaptive varints for a regular Serde payload.
    pub fn serialize<T: Serialize + ?Sized>(self, value: &T) -> Result<Vec<u8>> {
        self.base.serialize(value)
    }

    /// Decodes a regular value-width adaptive Serde payload.
    pub fn deserialize<'de, T: Deserialize<'de>>(self, input: &'de [u8]) -> Result<T> {
        self.base.deserialize(input)
    }

    /// Encodes a string using raw UTF-8 or 7-bit ASCII packing, whichever is smaller.
    pub fn encode_string(self, value: &str) -> Result<Vec<u8>> {
        let required = self.encoded_string_size(value)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(required)
            .map_err(|_| Error::SizeLimit { limit: u64::MAX })?;
        output.resize(required, 0);
        self.encode_string_into_slice(&mut output, value)?;
        Ok(output)
    }

    /// Returns the exact adaptive string frame size without allocating.
    pub fn encoded_string_size(self, value: &str) -> Result<usize> {
        self.enforce_collection_limit(value.len())?;
        let (_, _, required) = string_layout(value)?;
        self.enforce_byte_limit(required)?;
        Ok(required)
    }

    /// Encodes a string into caller-owned memory without allocating.
    ///
    /// The output is left untouched when it is too small.
    pub fn encode_string_into_slice(self, output: &mut [u8], value: &str) -> Result<usize> {
        self.enforce_collection_limit(value.len())?;
        let (strategy, payload_size, required) = string_layout(value)?;
        self.enforce_byte_limit(required)?;
        if output.len() < required {
            return Err(Error::BufferTooSmall {
                required,
                available: output.len(),
            });
        }
        let mut cursor = OutputCursor::new(&mut output[..required]);
        cursor.byte(match strategy {
            StringStrategy::RawUtf8 => RAW_UTF8,
            StringStrategy::Ascii7 => ASCII7,
        });
        cursor.varint(value.len() as u128);
        match strategy {
            StringStrategy::RawUtf8 => cursor.bytes(value.as_bytes()),
            StringStrategy::Ascii7 => {
                let packed = cursor.take_mut(payload_size);
                let mut writer = BitWriter::new(packed);
                for byte in value.bytes() {
                    writer.write(byte as u128, 7)?;
                }
            }
        }
        Ok(required)
    }

    /// Returns the strategy tag without decoding the string.
    pub fn string_strategy(self, input: &[u8]) -> Result<StringStrategy> {
        match input.first().copied().ok_or(Error::UnexpectedEnd)? {
            RAW_UTF8 => Ok(StringStrategy::RawUtf8),
            ASCII7 => Ok(StringStrategy::Ascii7),
            _ => Err(Error::Adaptive("unknown string strategy")),
        }
    }

    /// Decodes and validates an adaptively encoded string.
    pub fn decode_string(self, input: &[u8]) -> Result<String> {
        Ok(self.decode_string_borrowed(input)?.into_owned())
    }

    /// Decodes a string into caller-owned UTF-8 storage without allocating.
    ///
    /// The returned string borrows `output`. Raw UTF-8 is copied into the
    /// destination; use [`Self::decode_string_borrowed`] when borrowing the
    /// encoded frame directly is preferable. The output is left untouched
    /// when its capacity is smaller than the declared decoded length.
    pub fn decode_string_into_slice<'output>(
        self,
        output: &'output mut [u8],
        input: &[u8],
    ) -> Result<&'output str> {
        self.enforce_byte_limit(input.len())?;
        let mut cursor = Cursor::new(input);
        let strategy = cursor.byte()?;
        if !matches!(strategy, RAW_UTF8 | ASCII7) {
            return Err(Error::Adaptive("unknown string strategy"));
        }
        let length = cursor.usize_varint()?;
        self.enforce_collection_limit(length)?;
        if output.len() < length {
            return Err(Error::BufferTooSmall {
                required: length,
                available: output.len(),
            });
        }

        match strategy {
            RAW_UTF8 => {
                let bytes = cursor.take(length)?;
                std::str::from_utf8(bytes).map_err(Error::InvalidUtf8)?;
                output[..length].copy_from_slice(bytes);
            }
            ASCII7 => {
                let meaningful_bits = length
                    .checked_mul(7)
                    .ok_or(Error::Adaptive("ASCII7 length overflow"))?;
                let packed = meaningful_bits
                    .checked_add(7)
                    .ok_or(Error::Adaptive("ASCII7 length overflow"))?
                    / 8;
                let bytes = cursor.take(packed)?;
                let mut reader = BitReader::new(bytes);
                for slot in &mut output[..length] {
                    let scalar = reader.read(7)? as u8;
                    if !scalar.is_ascii() {
                        return Err(Error::Adaptive(
                            "ASCII7 payload contains a non-ASCII scalar",
                        ));
                    }
                    *slot = scalar;
                }
                validate_ascii_padding(bytes, meaningful_bits)?;
            }
            _ => return Err(Error::Adaptive("unknown string strategy")),
        }
        cursor.finish(self.base.trailing)?;
        std::str::from_utf8(&output[..length]).map_err(Error::InvalidUtf8)
    }

    /// Decodes a string while borrowing raw UTF-8 payloads directly from `input`.
    ///
    /// ASCII7 payloads require expansion and are therefore returned as owned
    /// strings. The returned [`Cow`] makes that distinction explicit.
    pub fn decode_string_borrowed<'a>(self, input: &'a [u8]) -> Result<Cow<'a, str>> {
        self.enforce_byte_limit(input.len())?;
        let mut cursor = Cursor::new(input);
        let strategy = cursor.byte()?;
        let length = cursor.usize_varint()?;
        self.enforce_collection_limit(length)?;
        let value = match strategy {
            RAW_UTF8 => {
                let bytes = cursor.take(length)?;
                Cow::Borrowed(std::str::from_utf8(bytes).map_err(Error::InvalidUtf8)?)
            }
            ASCII7 => {
                let meaningful_bits = length
                    .checked_mul(7)
                    .ok_or(Error::Adaptive("ASCII7 length overflow"))?;
                let packed = meaningful_bits
                    .checked_add(7)
                    .ok_or(Error::Adaptive("ASCII7 length overflow"))?
                    / 8;
                let bytes = cursor.take(packed)?;
                let mut reader = BitReader::new(bytes);
                let mut value = String::new();
                value
                    .try_reserve_exact(length)
                    .map_err(|_| Error::SizeLimit { limit: u64::MAX })?;
                for _ in 0..length {
                    let scalar = reader.read(7)? as u8;
                    if !scalar.is_ascii() {
                        return Err(Error::Adaptive(
                            "ASCII7 payload contains a non-ASCII scalar",
                        ));
                    }
                    value.push(scalar as char);
                }
                validate_ascii_padding(bytes, meaningful_bits)?;
                Cow::Owned(value)
            }
            _ => return Err(Error::Adaptive("unknown string strategy")),
        };
        cursor.finish(self.base.trailing)?;
        Ok(value)
    }

    /// Encodes an `i64` slice using raw, delta, or run-length varints.
    pub fn encode_i64_slice(self, values: &[i64]) -> Result<Vec<u8>> {
        let required = self.encoded_i64_slice_size(values)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(required)
            .map_err(|_| Error::SizeLimit { limit: u64::MAX })?;
        output.resize(required, 0);
        self.encode_i64_slice_into_slice(&mut output, values)?;
        Ok(output)
    }

    /// Returns the exact adaptive integer-collection frame size without allocating.
    pub fn encoded_i64_slice_size(self, values: &[i64]) -> Result<usize> {
        self.enforce_collection_limit(values.len())?;
        let (_, _, required) = collection_layout(values)?;
        self.enforce_byte_limit(required)?;
        Ok(required)
    }

    /// Encodes an integer collection into caller-owned memory without allocating.
    ///
    /// The output is left untouched when it is too small.
    pub fn encode_i64_slice_into_slice(self, output: &mut [u8], values: &[i64]) -> Result<usize> {
        self.enforce_collection_limit(values.len())?;
        let (strategy, _, required) = collection_layout(values)?;
        self.enforce_byte_limit(required)?;
        if output.len() < required {
            return Err(Error::BufferTooSmall {
                required,
                available: output.len(),
            });
        }
        let mut cursor = OutputCursor::new(&mut output[..required]);
        cursor.byte(match strategy {
            CollectionStrategy::Raw => RAW_INTEGERS,
            CollectionStrategy::Delta => DELTA_INTEGERS,
            CollectionStrategy::RunLength => RLE_INTEGERS,
        });
        cursor.varint(values.len() as u128);
        match strategy {
            CollectionStrategy::Raw => {
                for value in values {
                    cursor.varint(zigzag_i64(*value));
                }
            }
            CollectionStrategy::Delta => {
                if let Some(first) = values.first() {
                    cursor.varint(zigzag_i64(*first));
                    for pair in values.windows(2) {
                        cursor.varint(zigzag_i128(pair[1] as i128 - pair[0] as i128));
                    }
                }
            }
            CollectionStrategy::RunLength => {
                let mut start = 0;
                while start < values.len() {
                    let mut end = start + 1;
                    while end < values.len() && values[end] == values[start] {
                        end += 1;
                    }
                    cursor.varint(zigzag_i64(values[start]));
                    cursor.varint((end - start) as u128);
                    start = end;
                }
            }
        }
        Ok(required)
    }

    /// Returns the collection strategy tag without decoding all values.
    pub fn collection_strategy(self, input: &[u8]) -> Result<CollectionStrategy> {
        match input.first().copied().ok_or(Error::UnexpectedEnd)? {
            RAW_INTEGERS => Ok(CollectionStrategy::Raw),
            DELTA_INTEGERS => Ok(CollectionStrategy::Delta),
            RLE_INTEGERS => Ok(CollectionStrategy::RunLength),
            _ => Err(Error::Adaptive("unknown collection strategy")),
        }
    }

    /// Decodes an adaptive `i64` collection with checked delta reconstruction.
    pub fn decode_i64_vec(self, input: &[u8]) -> Result<Vec<i64>> {
        let length = self.decoded_i64_slice_len(input)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(length)
            .map_err(|_| Error::SizeLimit { limit: u64::MAX })?;
        values.resize(length, 0);
        self.decode_i64_slice_into(&mut values, input)?;
        Ok(values)
    }

    /// Returns the declared decoded element count after validating the frame header.
    pub fn decoded_i64_slice_len(self, input: &[u8]) -> Result<usize> {
        self.enforce_byte_limit(input.len())?;
        let mut cursor = Cursor::new(input);
        let strategy = cursor.byte()?;
        if !matches!(strategy, RAW_INTEGERS | DELTA_INTEGERS | RLE_INTEGERS) {
            return Err(Error::Adaptive("unknown collection strategy"));
        }
        let length = cursor.usize_varint()?;
        self.enforce_collection_limit(length)?;
        Ok(length)
    }

    /// Decodes an adaptive integer collection into caller-owned memory.
    ///
    /// This path performs no heap allocation. The output is left untouched
    /// when it is smaller than the decoded collection length.
    pub fn decode_i64_slice_into(self, output: &mut [i64], input: &[u8]) -> Result<usize> {
        self.enforce_byte_limit(input.len())?;
        let mut cursor = Cursor::new(input);
        let strategy = cursor.byte()?;
        if !matches!(strategy, RAW_INTEGERS | DELTA_INTEGERS | RLE_INTEGERS) {
            return Err(Error::Adaptive("unknown collection strategy"));
        }
        let length = cursor.usize_varint()?;
        self.enforce_collection_limit(length)?;
        if output.len() < length {
            return Err(Error::BufferTooSmall {
                required: length,
                available: output.len(),
            });
        }
        let mut written = 0usize;
        match strategy {
            RAW_INTEGERS => {
                while written < length {
                    let remaining_values = length - written;
                    let plain = crate::simd::plain_varint_prefix(cursor.remaining_slice())
                        .min(remaining_values);
                    for byte in cursor.take(plain)? {
                        output[written] = decode_i128(*byte as u128) as i64;
                        written += 1;
                    }
                    if written < length {
                        output[written] = decode_i64(cursor.varint()?)?;
                        written += 1;
                    }
                }
            }
            DELTA_INTEGERS => {
                if length != 0 {
                    output[0] = decode_i64(cursor.varint()?)?;
                    written = 1;
                    while written < length {
                        let delta = decode_i128(cursor.varint()?);
                        let next = (output[written - 1] as i128)
                            .checked_add(delta)
                            .and_then(|value| i64::try_from(value).ok())
                            .ok_or(Error::Adaptive("delta reconstruction overflow"))?;
                        output[written] = next;
                        written += 1;
                    }
                }
            }
            RLE_INTEGERS => {
                while written < length {
                    let value = decode_i64(cursor.varint()?)?;
                    let run = cursor.usize_varint()?;
                    if run == 0 || run > length - written {
                        return Err(Error::Adaptive("invalid run length"));
                    }
                    output[written..written + run].fill(value);
                    written += run;
                }
            }
            _ => unreachable!("strategy was validated above"),
        }
        cursor.finish(self.base.trailing)?;
        Ok(written)
    }

    fn enforce_byte_limit(self, length: usize) -> Result<()> {
        if let Some(limit) = self.base.limit {
            if length as u64 > limit {
                return Err(Error::SizeLimit { limit });
            }
        }
        Ok(())
    }

    fn enforce_collection_limit(self, length: usize) -> Result<()> {
        if let Some(limit) = self.base.collection_limit {
            if length as u64 > limit {
                return Err(Error::CollectionLimit { limit });
            }
        }
        Ok(())
    }
}

fn validate_ascii_padding(bytes: &[u8], meaningful_bits: usize) -> Result<()> {
    if !meaningful_bits.is_multiple_of(8)
        && bytes
            .last()
            .is_some_and(|last| last >> (meaningful_bits % 8) != 0)
    {
        return Err(Error::Adaptive("non-zero ASCII7 padding"));
    }
    Ok(())
}

fn string_layout(value: &str) -> Result<(StringStrategy, usize, usize)> {
    let raw_size = value.len();
    let packed_size = if crate::simd::is_ascii(value.as_bytes()) {
        Some(
            value
                .len()
                .checked_mul(7)
                .and_then(|bits| bits.checked_add(7))
                .ok_or(Error::Adaptive("encoded size overflow"))?
                / 8,
        )
    } else {
        None
    };
    let strategy = if packed_size.is_some_and(|size| size < raw_size) {
        StringStrategy::Ascii7
    } else {
        StringStrategy::RawUtf8
    };
    let payload_size = match strategy {
        StringStrategy::RawUtf8 => raw_size,
        StringStrategy::Ascii7 => packed_size.expect("selected only for ASCII"),
    };
    let required = 1usize
        .checked_add(varint_size(value.len() as u128))
        .and_then(|size| size.checked_add(payload_size))
        .ok_or(Error::Adaptive("encoded size overflow"))?;
    Ok((strategy, payload_size, required))
}

fn collection_layout(values: &[i64]) -> Result<(CollectionStrategy, usize, usize)> {
    let raw_size = values.iter().try_fold(0usize, |size, value| {
        size.checked_add(varint_size(zigzag_i64(*value)))
            .ok_or(Error::Adaptive("encoded size overflow"))
    })?;
    let delta_size = delta_size(values)?;
    let rle_size = rle_size(values)?;
    let strategy = if delta_size < raw_size && delta_size <= rle_size {
        CollectionStrategy::Delta
    } else if rle_size < raw_size {
        CollectionStrategy::RunLength
    } else {
        CollectionStrategy::Raw
    };
    let payload_size = match strategy {
        CollectionStrategy::Raw => raw_size,
        CollectionStrategy::Delta => delta_size,
        CollectionStrategy::RunLength => rle_size,
    };
    let required = 1usize
        .checked_add(varint_size(values.len() as u128))
        .and_then(|size| size.checked_add(payload_size))
        .ok_or(Error::Adaptive("encoded size overflow"))?;
    Ok((strategy, payload_size, required))
}

fn delta_size(values: &[i64]) -> Result<usize> {
    let Some(first) = values.first() else {
        return Ok(0);
    };
    values
        .windows(2)
        .try_fold(varint_size(zigzag_i64(*first)), |size, pair| {
            size.checked_add(varint_size(zigzag_i128(pair[1] as i128 - pair[0] as i128)))
                .ok_or(Error::Adaptive("encoded size overflow"))
        })
}

fn rle_size(values: &[i64]) -> Result<usize> {
    let mut size = 0usize;
    let mut start = 0;
    while start < values.len() {
        let mut end = start + 1;
        while end < values.len() && values[end] == values[start] {
            end += 1;
        }
        size = size
            .checked_add(varint_size(zigzag_i64(values[start])))
            .and_then(|size| size.checked_add(varint_size((end - start) as u128)))
            .ok_or(Error::Adaptive("encoded size overflow"))?;
        start = end;
    }
    Ok(size)
}

const fn zigzag_i64(value: i64) -> u128 {
    ((value << 1) ^ (value >> 63)) as u64 as u128
}

const fn zigzag_i128(value: i128) -> u128 {
    ((value << 1) ^ (value >> 127)) as u128
}

fn decode_i64(value: u128) -> Result<i64> {
    i64::try_from(decode_i128(value)).map_err(|_| Error::IntegerOverflow { target: "i64" })
}

const fn decode_i128(value: u128) -> i128 {
    ((value >> 1) as i128) ^ -((value & 1) as i128)
}

const fn varint_size(value: u128) -> usize {
    match value {
        0..=250 => 1,
        251..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        0x1_0000_0000..=0xffff_ffff_ffff_ffff => 9,
        _ => 17,
    }
}

struct OutputCursor<'a> {
    output: &'a mut [u8],
    position: usize,
}

impl<'a> OutputCursor<'a> {
    const fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            position: 0,
        }
    }

    fn byte(&mut self, value: u8) {
        self.output[self.position] = value;
        self.position += 1;
    }

    fn bytes(&mut self, value: &[u8]) {
        self.take_mut(value.len()).copy_from_slice(value);
    }

    fn take_mut(&mut self, length: usize) -> &mut [u8] {
        let start = self.position;
        self.position += length;
        &mut self.output[start..self.position]
    }

    fn varint(&mut self, value: u128) {
        match value {
            0..=250 => self.byte(value as u8),
            251..=0xffff => {
                self.byte(251);
                self.bytes(&(value as u16).to_le_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.byte(252);
                self.bytes(&(value as u32).to_le_bytes());
            }
            0x1_0000_0000..=0xffff_ffff_ffff_ffff => {
                self.byte(253);
                self.bytes(&(value as u64).to_le_bytes());
            }
            _ => {
                self.byte(254);
                self.bytes(&value.to_le_bytes());
            }
        }
    }
}

struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(Error::UnexpectedEnd)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(Error::UnexpectedEnd)?;
        self.position = end;
        Ok(bytes)
    }

    fn remaining_slice(&self) -> &'a [u8] {
        &self.input[self.position..]
    }

    fn varint(&mut self) -> Result<u128> {
        let marker = self.byte()?;
        let (value, minimum) = match marker {
            0..=250 => return Ok(marker as u128),
            251 => (
                u16::from_le_bytes(self.take(2)?.try_into().expect("fixed")) as u128,
                251,
            ),
            252 => (
                u32::from_le_bytes(self.take(4)?.try_into().expect("fixed")) as u128,
                0x1_0000,
            ),
            253 => (
                u64::from_le_bytes(self.take(8)?.try_into().expect("fixed")) as u128,
                0x1_0000_0000,
            ),
            254 => (
                u128::from_le_bytes(self.take(16)?.try_into().expect("fixed")),
                0x1_0000_0000_0000_0000,
            ),
            marker => return Err(Error::InvalidVarintMarker(marker)),
        };
        if value < minimum {
            Err(Error::NonCanonicalVarint)
        } else {
            Ok(value)
        }
    }

    fn usize_varint(&mut self) -> Result<usize> {
        usize::try_from(self.varint()?).map_err(|_| Error::IntegerOverflow { target: "usize" })
    }

    fn finish(self, trailing: TrailingBytes) -> Result<()> {
        if trailing == TrailingBytes::Reject && self.position != self.input.len() {
            return Err(Error::TrailingBytes {
                remaining: self.input.len() - self.position,
            });
        }
        Ok(())
    }
}
