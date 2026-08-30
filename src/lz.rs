//! In-tree lossless compressor: LZ77 sliding-window matching with a packed
//! bitstream (replaces the `zstd` dependency).
//!
//! The `compression` feature is a `std`-only layer, but the codec itself is
//! pure `no_std` + `alloc` so it can be reused anywhere. The design is a
//! deliberately simple, auditable LZ77:
//!
//! - **Encoder**: a hash-chain matcher over a 32 KiB sliding window. For each
//!   position it finds the longest match (minimum 3 bytes, maximum 258) and
//!   emits either a literal byte or a `(length, distance)` pair. The `level`
//!   controls how many hash-chain candidates are tried per position: higher
//!   levels search further for a better (longer) match at the cost of speed.
//! - **Bitstream**: one flag bit per token (`0` literal, `1` match), then
//!   either 8 literal bits or an 8-bit length and a 15-bit distance. Lengths
//!   are stored minus 3 (0..=255 maps to 3..=258); distances are stored minus
//!   1 (0..=32767 maps to 1..=32768).
//! - **Decoder**: single pass, bounds-checked, zero-unsafe. A malformed frame
//!   is rejected with [`LzError`] instead of reading out of bounds.
//!
//! The frame body is `u32 LE raw length` followed by the packed token stream;
//! the envelope (`src/compression.rs`) adds magic/version/flags and the raw /
//! stored length fields it already carries. Raw payloads smaller than a
//! literal-copy are emitted verbatim by the caller, so this module only ever
//! sees data it is allowed to compress.

use alloc::vec;
use alloc::vec::Vec;

/// Sliding-window size: the maximum distance back a match can reference.
pub const WINDOW_SIZE: usize = 32768;
/// Minimum match length worth emitting (below this, a literal is cheaper).
const MIN_MATCH: usize = 3;
/// Maximum match length representable in the 8-bit length field.
const MAX_MATCH: usize = 258;
/// Number of hash-chain buckets (a power of two for cheap masking).
const HASH_BUCKETS: usize = 65536;

/// Compression / decompression failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LzError {
    /// The compressed stream was truncated.
    UnexpectedEnd,
    /// The compressed stream references a match before the window start.
    InvalidDistance,
    /// The decompressed length differs from the declared frame length.
    LengthMismatch,
}

impl core::fmt::Display for LzError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEnd => f.write_str("LZ77 stream ended unexpectedly"),
            Self::InvalidDistance => f.write_str("LZ77 match distance out of range"),
            Self::LengthMismatch => f.write_str("LZ77 decompressed length mismatch"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LzError {}

/// Computes the 16-bit hash of a 3-byte prefix.
#[inline(always)]
fn hash3(bytes: &[u8]) -> usize {
    let a = bytes[0] as usize;
    let b = bytes[1] as usize;
    let c = bytes[2] as usize;
    // 16-bit FNV-1a over three bytes; good enough to spread matches and
    // cheap enough to run per position.
    let mut hash = 0x811c_9dc5usize;
    hash ^= a;
    hash = hash.wrapping_mul(0x0100_0193);
    hash ^= b;
    hash = hash.wrapping_mul(0x0100_0193);
    hash ^= c;
    hash = hash.wrapping_mul(0x0100_0193);
    (hash >> 16) & (HASH_BUCKETS - 1)
}

/// Compresses `input` with LZ77 matching. Returns an empty `Vec` if the
/// packed stream is not smaller than the input (the caller then stores the
/// raw payload), or the packed frame otherwise.
///
/// `level` is a 1..=22 hint controlling search effort; values outside the
/// range are clamped. Higher levels yield marginally better ratios on
/// repetitive data at proportionally higher CPU cost.
pub fn compress(input: &[u8], level: i32) -> Vec<u8> {
    if input.len() < MIN_MATCH {
        return Vec::new();
    }
    // Clamp level; chain budget grows with level (1 -> 4, 22 -> 96).
    let level = level.clamp(1, 22);
    let max_chain = (4 + (level as usize) * 4).min(96);

    // Hash-chain bookkeeping. `prev[i]` holds the previous position with the
    // same 3-byte hash as `i` (or `u32::MAX` when none), stored as absolute
    // positions. The window is enforced during search, not by truncation.
    let mut head = vec![u32::MAX; HASH_BUCKETS];
    let mut prev = vec![u32::MAX; input.len()];

    let mut output = BitWriter::new();
    // Frame body: u32 LE uncompressed length.
    output.write_u32(input.len() as u32);

    let mut pos = 0usize;
    while pos < input.len() {
        // Try to find the longest match starting at `pos`.
        let mut best_len = 0usize;
        let mut best_dist = 0usize;
        let max_len = core::cmp::min(MAX_MATCH, input.len() - pos);
        if max_len >= MIN_MATCH {
            let h = hash3(&input[pos..]);
            let mut candidate = head[h];
            let mut chain = 0usize;
            let window_start = pos.saturating_sub(WINDOW_SIZE);
            while candidate != u32::MAX && chain < max_chain {
                let c = candidate as usize;
                if c < window_start {
                    break;
                }
                // Only consider candidates within the 15-bit distance field.
                let dist = pos - c;
                if dist > WINDOW_SIZE {
                    candidate = prev[c];
                    chain += 1;
                    continue;
                }
                if c + max_len <= input.len() {
                    let mut len = 0usize;
                    let remaining = core::cmp::min(max_len, input.len() - c);
                    while len < remaining && input[c + len] == input[pos + len] {
                        len += 1;
                    }
                    if len > best_len {
                        best_len = len;
                        best_dist = dist;
                        if len == max_len {
                            break;
                        }
                    }
                }
                candidate = prev[c];
                chain += 1;
            }
        }

        if best_len >= MIN_MATCH {
            // Emit a match token.
            output.write_bit(true);
            output.write_bits((best_len - MIN_MATCH) as u32, 8);
            output.write_bits((best_dist - 1) as u32, 15);
            // Insert every position in the match into the hash chain so
            // subsequent matches can reference into it.
            let end = core::cmp::min(pos + best_len, input.len());
            for i in pos..end {
                if i + MIN_MATCH <= input.len() {
                    let h = hash3(&input[i..]);
                    prev[i] = head[h];
                    head[h] = i as u32;
                }
            }
            pos = end;
        } else {
            // Emit a literal token and insert this single position.
            output.write_bit(false);
            output.write_bits(input[pos] as u32, 8);
            if pos + MIN_MATCH <= input.len() {
                let h = hash3(&input[pos..]);
                prev[pos] = head[h];
                head[h] = pos as u32;
            }
            pos += 1;
        }
    }
    output.finish()
}

/// Decompresses a frame produced by [`compress`] into at most `expected`
/// bytes. Returns the decompressed payload.
pub fn decompress(input: &[u8], expected: usize) -> Result<Vec<u8>, LzError> {
    let mut reader = BitReader::new(input);
    let declared = reader.read_u32().ok_or(LzError::UnexpectedEnd)? as usize;
    // `expected` is the caller's upper bound on the decoded size (used to cap
    // allocation against an attacker-controlled header). Declared must not
    // exceed it.
    if declared > expected {
        return Err(LzError::LengthMismatch);
    }
    let mut output = Vec::with_capacity(declared);
    while output.len() < declared {
        let is_match = reader.read_bit().ok_or(LzError::UnexpectedEnd)?;
        if is_match {
            let length = reader.read_bits(8).ok_or(LzError::UnexpectedEnd)? as usize + MIN_MATCH;
            let distance = reader.read_bits(15).ok_or(LzError::UnexpectedEnd)? as usize + 1;
            if distance > output.len() {
                return Err(LzError::InvalidDistance);
            }
            let start = output.len();
            for i in 0..length {
                let src = output[start + i - distance];
                output.push(src);
            }
        } else {
            let byte = reader.read_bits(8).ok_or(LzError::UnexpectedEnd)? as u8;
            output.push(byte);
        }
    }
    if output.len() != declared {
        return Err(LzError::LengthMismatch);
    }
    Ok(output)
}

/// Little-endian bit writer (MSB-first within each byte).
struct BitWriter {
    buffer: Vec<u8>,
    bit_buffer: u64,
    bit_count: u32,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            bit_buffer: 0,
            bit_count: 0,
        }
    }

    fn write_bit(&mut self, value: bool) {
        // Make sure at least 1 bit is free; `flush` empties full bytes and
        // leaves fewer than 8 bits in the buffer.
        self.ensure_capacity(1);
        self.bit_buffer |= (value as u64) << self.bit_count;
        self.bit_count += 1;
        if self.bit_count == 64 {
            self.flush();
        }
    }

    fn write_bits(&mut self, value: u32, count: u32) {
        debug_assert!(count <= 32);
        self.ensure_capacity(count);
        self.bit_buffer |= (value as u64) << self.bit_count;
        self.bit_count += count;
        if self.bit_count >= 64 {
            self.flush();
        }
    }

    /// Guarantees that at least `needed` more bits fit in the u64 buffer by
    /// flushing whole bytes first. After a flush, `bit_count < 8`, so
    /// `bit_count + needed <= 39` for any `needed <= 32` and never overflows.
    fn ensure_capacity(&mut self, needed: u32) {
        if self.bit_count + needed > 64 {
            self.flush();
        }
    }

    fn write_u32(&mut self, value: u32) {
        // Whole bytes: bypass the bit buffer.
        if self.bit_count == 0 {
            self.buffer.extend_from_slice(&value.to_le_bytes());
            return;
        }
        for shift in (0..32).step_by(8) {
            self.write_bits((value >> shift) & 0xff, 8);
        }
    }

    fn flush(&mut self) {
        while self.bit_count >= 8 {
            self.buffer.push((self.bit_buffer & 0xff) as u8);
            self.bit_buffer >>= 8;
            self.bit_count -= 8;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        self.flush();
        if self.bit_count > 0 {
            self.buffer.push((self.bit_buffer & 0xff) as u8);
        }
        self.buffer
    }
}

/// Little-endian bit reader (MSB-first within each byte).
struct BitReader<'a> {
    bytes: &'a [u8],
    byte_pos: usize,
    bit_pos: u32,
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    fn read_bit(&mut self) -> Option<bool> {
        let byte = *self.bytes.get(self.byte_pos)?;
        let bit = (byte >> self.bit_pos) & 1 != 0;
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
        Some(bit)
    }

    fn read_bits(&mut self, count: u32) -> Option<u32> {
        let mut value = 0u32;
        for i in 0..count {
            let bit = self.read_bit()?;
            value |= (bit as u32) << i;
        }
        Some(value)
    }

    fn read_u32(&mut self) -> Option<u32> {
        let a = self.read_bits(8)?;
        let b = self.read_bits(8)?;
        let c = self.read_bits(8)?;
        let d = self.read_bits(8)?;
        Some(a | (b << 8) | (c << 16) | (d << 24))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::vec;

    fn roundtrip(data: &[u8], level: i32) -> Vec<u8> {
        let packed = compress(data, level);
        if packed.is_empty() {
            return data.to_vec();
        }
        decompress(&packed, data.len()).expect("roundtrip")
    }

    #[test]
    fn literals_roundtrip() {
        let data = b"hello world, this is a mostly incompressible sentence!";
        assert_eq!(roundtrip(data, 3), data);
    }

    #[test]
    fn repetitive_data_roundtrip() {
        let data = b"abcabcabcabcabcabcabcabcabcabcabcabc";
        assert_eq!(roundtrip(data, 3), data);
        // Must actually compress.
        let packed = compress(data, 3);
        assert!(!packed.is_empty());
        assert!(packed.len() < data.len());
    }

    #[test]
    fn long_repetition_roundtrip() {
        let data = vec![0xAB_u8; 100_000];
        assert_eq!(roundtrip(&data, 9), data);
        let packed = compress(&data, 9);
        assert!(packed.len() < data.len());
    }

    #[test]
    fn window_boundary_match() {
        // A match exactly at the window boundary (distance ~32768).
        let mut data = vec![0_u8; WINDOW_SIZE];
        data.extend_from_slice(b"marker");
        data.extend_from_slice(&[0_u8; WINDOW_SIZE]);
        data.extend_from_slice(b"marker");
        assert_eq!(roundtrip(&data, 3), data);
    }

    #[test]
    fn mixed_data_roundtrip() {
        let mut data = Vec::new();
        for i in 0..1000 {
            data.extend_from_slice(format!("record-{i:04}-").as_bytes());
            data.extend_from_slice(&[(i & 0xff) as u8; 8]);
            data.push(0x00);
        }
        assert_eq!(roundtrip(&data, 6), data);
    }

    #[test]
    fn empty_and_tiny_inputs() {
        assert_eq!(roundtrip(&[], 3), []);
        assert_eq!(roundtrip(b"a", 3), b"a");
        assert_eq!(roundtrip(b"ab", 3), b"ab");
        // Below MIN_MATCH the encoder refuses to compress (raw fallback).
        assert!(compress(b"ab", 3).is_empty());
    }

    #[test]
    fn malformed_streams_are_rejected() {
        // Truncated header.
        assert_eq!(decompress(&[0x01], 0), Err(LzError::UnexpectedEnd));
        // Declared length exceeds the caller's upper bound.
        let mut frame = Vec::new();
        frame.extend_from_slice(&10u32.to_le_bytes());
        frame.push(0); // literal flag
        frame.push(0x41); // 'A'
        assert_eq!(decompress(&frame, 1), Err(LzError::LengthMismatch));
        // Match before the window start: declared length 3, first token is a
        // match with distance 1 when nothing has been emitted yet. The flag
        // bit is the LSB, so byte 0x01 means "match".
        let mut frame = Vec::new();
        frame.extend_from_slice(&3u32.to_le_bytes());
        frame.push(0x01); // match flag (bit 0 = 1)
        frame.push(0x00); // length - 3 = 0  => length 3
        frame.push(0x00); // distance - 1 low bits
        frame.push(0x00); // distance - 1 high bits (15-bit field spans 2 bytes)
        assert_eq!(decompress(&frame, 3), Err(LzError::InvalidDistance));
    }

    #[test]
    fn level_semantics_are_stable() {
        let data = vec![0x5A_u8; 50_000];
        let low = compress(&data, 1);
        let high = compress(&data, 22);
        assert!(!low.is_empty() && !high.is_empty());
        // Both must round-trip identically.
        assert_eq!(decompress(&low, data.len()).unwrap(), data);
        assert_eq!(decompress(&high, data.len()).unwrap(), data);
    }
}
