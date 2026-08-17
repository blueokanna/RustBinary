#[cfg(feature = "alloc")]
use alloc::{borrow::Cow, string::String, vec::Vec};

use crate::{
    canonical::encode_varint_le, BitReader, BitWriter, Config, Error, Result, TrailingBytes,
};

const RAW_UTF8: u8 = 0;
const ASCII7: u8 = 1;
const RAW_INTEGERS: u8 = 0;
const DELTA_INTEGERS: u8 = 1;
const RLE_INTEGERS: u8 = 2;

/// Number of leading elements sampled by [`AdaptiveMode::Heuristic`] before
/// deciding whether delta / run-length coding is worth a full pass.
pub const HEURISTIC_SAMPLE: usize = 64;

/// How much analysis the adaptive codec performs before encoding.
///
/// The choice is **size-only**: every strategy is lossless, so a cheaper mode
/// never changes what decodes, only how many bytes the frame occupies and how
/// many scan passes the encoder performs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AdaptiveMode {
    /// Encode directly with the raw representation.
    ///
    /// Zero analysis passes — the low-latency default for online paths. Bytes
    /// are larger than `Heuristic`/`Exact` on compressible data, but the
    /// encoder never rescans the input to save a few bytes.
    #[default]
    Off,
    /// Sample the first [`HEURISTIC_SAMPLE`] elements to decide whether
    /// delta / run-length pays off, then take a single sizing pass over the
    /// chosen strategy.
    ///
    /// Integer collections are always safe to sample (the choice is size-only
    /// and lossless). Strings cannot be sampled safely — `ASCII7` requires
    /// every scalar to be ASCII, so they use the exact scan in this mode.
    Heuristic,
    /// Compare the complete raw / delta / run-length sizes and pick the
    /// smallest. Optimal size at the cost of extra full scans; best for
    /// offline compression.
    Exact,
}

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
    mode: AdaptiveMode,
}

impl AdaptiveConfig {
    pub(crate) const fn new(base: Config) -> Self {
        Self {
            base,
            mode: AdaptiveMode::Off,
        }
    }

    /// Returns the variable-integer payload configuration.
    pub const fn base_config(self) -> Config {
        self.base
    }

    /// Selects how much analysis the adaptive encoder performs.
    ///
    /// [`AdaptiveMode::Off`] (the default) encodes directly with no extra
    /// scans; [`AdaptiveMode::Heuristic`] samples a bounded prefix;
    /// [`AdaptiveMode::Exact`] compares complete encodings.
    pub const fn with_adaptive_mode(mut self, mode: AdaptiveMode) -> Self {
        self.mode = mode;
        self
    }

    /// Returns the configured analysis mode.
    pub const fn mode(self) -> AdaptiveMode {
        self.mode
    }

    /// Uses value-width adaptive varints for a regular nextjson payload.
    #[cfg(feature = "alloc")]
    pub fn serialize<T: nextjson::NsonSerialize + ?Sized>(self, value: &T) -> Result<Vec<u8>> {
        self.base.serialize(value)
    }

    /// Decodes a regular value-width adaptive nextjson payload.
    pub fn deserialize<'de, T: nextjson::NsonDeserialize<'de>>(
        self,
        input: &'de [u8],
    ) -> Result<T> {
        self.base.deserialize(input)
    }

    /// Encodes a string using raw UTF-8 or 7-bit ASCII packing, whichever is smaller.
    #[cfg(feature = "alloc")]
    pub fn encode_string(self, value: &str) -> Result<Vec<u8>> {
        if self.mode == AdaptiveMode::Off {
            // Direct raw UTF-8 with no ASCII scan: the low-latency default.
            let required = 1usize
                .checked_add(varint_size(value.len() as u128))
                .and_then(|size| size.checked_add(value.len()))
                .ok_or(Error::Adaptive("encoded size overflow"))?;
            self.enforce_byte_limit(required)?;
            let mut output = Vec::with_capacity(required);
            output.push(RAW_UTF8);
            push_varint(&mut output, value.len() as u128);
            output.extend_from_slice(value.as_bytes());
            return Ok(output);
        }
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
        let (_, _, required) = string_layout(value, self.mode)?;
        self.enforce_byte_limit(required)?;
        Ok(required)
    }

    /// Encodes a string into caller-owned memory without allocating.
    ///
    /// The output is left untouched when it is too small.
    pub fn encode_string_into_slice(self, output: &mut [u8], value: &str) -> Result<usize> {
        let (strategy, payload_size, required) = string_layout(value, self.mode)?;
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
    #[cfg(feature = "alloc")]
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
        if output.len() < length {
            return Err(Error::BufferTooSmall {
                required: length,
                available: output.len(),
            });
        }

        match strategy {
            RAW_UTF8 => {
                let bytes = cursor.take(length)?;
                core::str::from_utf8(bytes).map_err(Error::InvalidUtf8)?;
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
                    *slot = reader.read(7)? as u8;
                }
                validate_ascii_padding(bytes, meaningful_bits)?;
            }
            _ => return Err(Error::Adaptive("unknown string strategy")),
        }
        cursor.finish(self.base.trailing)?;
        core::str::from_utf8(&output[..length]).map_err(Error::InvalidUtf8)
    }

    /// Decodes a string while borrowing raw UTF-8 payloads directly from `input`.
    ///
    /// ASCII7 payloads require expansion and are therefore returned as owned
    /// strings. The returned [`Cow`] makes that distinction explicit.
    #[cfg(feature = "alloc")]
    pub fn decode_string_borrowed<'a>(self, input: &'a [u8]) -> Result<Cow<'a, str>> {
        self.enforce_byte_limit(input.len())?;
        let mut cursor = Cursor::new(input);
        let strategy = cursor.byte()?;
        let length = cursor.usize_varint()?;
        let value = match strategy {
            RAW_UTF8 => {
                let bytes = cursor.take(length)?;
                Cow::Borrowed(core::str::from_utf8(bytes).map_err(Error::InvalidUtf8)?)
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
                    // A 7-bit read is always 0..=127, so every scalar is ASCII
                    // by construction; truncation is the only failure mode.
                    value.push(reader.read(7)? as u8 as char);
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
    #[cfg(feature = "alloc")]
    pub fn encode_i64_slice(self, values: &[i64]) -> Result<Vec<u8>> {
        if self.mode == AdaptiveMode::Off {
            // Direct raw encoding with a single growing pass: the low-latency
            // default never rescans the input to save a few bytes.
            self.enforce_collection_limit(values.len())?;
            let mut output = Vec::with_capacity(values.len().saturating_add(1));
            output.push(RAW_INTEGERS);
            push_varint(&mut output, values.len() as u128);
            for value in values {
                push_varint(&mut output, zigzag_i64(*value));
            }
            self.enforce_byte_limit(output.len())?;
            return Ok(output);
        }
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
        let (_, _, required) = collection_layout(values, self.mode)?;
        self.enforce_byte_limit(required)?;
        Ok(required)
    }

    /// Encodes an integer collection into caller-owned memory without allocating.
    ///
    /// The output is left untouched when it is too small.
    pub fn encode_i64_slice_into_slice(self, output: &mut [u8], values: &[i64]) -> Result<usize> {
        self.enforce_collection_limit(values.len())?;
        let (strategy, _, required) = collection_layout(values, self.mode)?;
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
    #[cfg(feature = "alloc")]
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
                    let plain = plain_varint_prefix(cursor.remaining_slice()).min(remaining_values);
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

fn string_layout(value: &str, mode: AdaptiveMode) -> Result<(StringStrategy, usize, usize)> {
    let raw_size = value.len();
    // ASCII7 requires every scalar to be ASCII, so the scan cannot be sampled
    // safely; `Off` skips the scan entirely and writes raw UTF-8.
    let packed_size = if mode == AdaptiveMode::Off {
        None
    } else if is_ascii(value.as_bytes()) {
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
    let (strategy, payload_size) = match packed_size {
        Some(size) if size < raw_size => (StringStrategy::Ascii7, size),
        _ => (StringStrategy::RawUtf8, raw_size),
    };
    let required = 1usize
        .checked_add(varint_size(value.len() as u128))
        .and_then(|size| size.checked_add(payload_size))
        .ok_or(Error::Adaptive("encoded size overflow"))?;
    Ok((strategy, payload_size, required))
}

fn is_ascii(input: &[u8]) -> bool {
    #[cfg(feature = "simd")]
    return crate::simd::is_ascii(input);
    #[cfg(not(feature = "simd"))]
    input.is_ascii()
}

fn plain_varint_prefix(input: &[u8]) -> usize {
    #[cfg(feature = "simd")]
    return crate::simd::plain_varint_prefix(input);
    #[cfg(not(feature = "simd"))]
    input.iter().take_while(|&&byte| byte <= 250).count()
}

/// Exact byte size of the independent-ZigZag encoding of `values`.
fn raw_size(values: &[i64]) -> Result<usize> {
    values.iter().try_fold(0usize, |size, value| {
        size.checked_add(varint_size(zigzag_i64(*value)))
            .ok_or(Error::Adaptive("encoded size overflow"))
    })
}

/// Exact byte size of the delta encoding of `values`.
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

/// Exact byte size of the run-length encoding of `values`.
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

/// Picks the smallest complete encoding from precomputed sizes.
fn best_strategy(raw: usize, delta: usize, rle: usize) -> (CollectionStrategy, usize) {
    if delta < raw && delta <= rle {
        (CollectionStrategy::Delta, delta)
    } else if rle < raw {
        (CollectionStrategy::RunLength, rle)
    } else {
        (CollectionStrategy::Raw, raw)
    }
}

fn collection_layout(
    values: &[i64],
    mode: AdaptiveMode,
) -> Result<(CollectionStrategy, usize, usize)> {
    let (strategy, payload_size) = match mode {
        // Direct raw encoding: no analysis at all.
        AdaptiveMode::Off => (CollectionStrategy::Raw, raw_size(values)?),
        // Compare the whole collection exactly.
        AdaptiveMode::Exact => {
            let raw = raw_size(values)?;
            let delta = delta_size(values)?;
            let rle = rle_size(values)?;
            best_strategy(raw, delta, rle)
        }
        // The sample covers everything: the comparison is exact and cheap.
        AdaptiveMode::Heuristic if values.len() <= HEURISTIC_SAMPLE => {
            let raw = raw_size(values)?;
            let delta = delta_size(values)?;
            let rle = rle_size(values)?;
            best_strategy(raw, delta, rle)
        }
        // Sample a bounded prefix to pick a strategy, then take one full
        // sizing pass under the chosen strategy.
        AdaptiveMode::Heuristic => {
            let sample = &values[..HEURISTIC_SAMPLE];
            let raw = raw_size(sample)?;
            let delta = delta_size(sample)?;
            let rle = rle_size(sample)?;
            let (chosen, _) = best_strategy(raw, delta, rle);
            let payload = match chosen {
                CollectionStrategy::Raw => raw_size(values)?,
                CollectionStrategy::Delta => delta_size(values)?,
                CollectionStrategy::RunLength => rle_size(values)?,
            };
            (chosen, payload)
        }
    };
    let required = 1usize
        .checked_add(varint_size(values.len() as u128))
        .and_then(|size| size.checked_add(payload_size))
        .ok_or(Error::Adaptive("encoded size overflow"))?;
    Ok((strategy, payload_size, required))
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
        // Single source of truth: the canonical little-endian marker-varint
        // (also used by the compact profile and the Kani proofs).
        let (bytes, len) = encode_varint_le(value);
        self.bytes(&bytes[..len]);
    }
}

/// Appends a canonical little-endian marker-varint to a growing vector.
///
/// Used by the `Off` owned-encode fast paths, which avoid a sizing pass by
/// letting the output buffer grow.
fn push_varint(output: &mut Vec<u8>, value: u128) {
    let (bytes, len) = encode_varint_le(value);
    output.extend_from_slice(&bytes[..len]);
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

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::UnexpectedEnd)
    }

    fn varint(&mut self) -> Result<u128> {
        let marker = self.byte()?;
        let (value, minimum) = match marker {
            0..=250 => return Ok(marker as u128),
            251 => (u16::from_le_bytes(self.take_array()?) as u128, 251),
            252 => (u32::from_le_bytes(self.take_array()?) as u128, 0x1_0000),
            253 => (
                u64::from_le_bytes(self.take_array()?) as u128,
                0x1_0000_0000,
            ),
            254 => (
                u128::from_le_bytes(self.take_array()?),
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
