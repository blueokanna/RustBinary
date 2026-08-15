//! Differential frames for gossip and consensus state exchange.
//!
//! When a receiver already holds a baseline state `S`, sending the full new
//! state wastes bandwidth. This module provides two complementary mechanisms:
//!
//! - **Integer deltas against a negotiable baseline.** [`DeltaConfig::encode_delta`]
//!   encodes `value - base` as a canonical ZigZag varint, so a receiver that
//!   holds the base only receives the difference. The base is negotiated out
//!   of band (e.g., the hash of the last committed state) and never repeated.
//! - **HPACK-style dynamic tables.** [`crate::DeltaTable`] is a deterministic FIFO
//!   table of previously seen byte strings. [`DeltaConfig::encode_updates`]
//!   writes a literal only when a value is absent from the table and a table
//!   reference otherwise. Both sides run the identical insert/evict rule, so
//!   the table state is a pure function of the update stream — no table is
//!   ever transmitted.
//!
//! Both mechanisms are deterministic, allocation-aware, and `no_std` + `alloc`.
//! For unordered sets, pair this module with [`crate::ibl`] (IBLT set
//! reconciliation) to approach the information-theoretic lower bound of a
//! two-way diff.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::{Config, Error, Result};

const MAGIC: [u8; 4] = *b"RBDL";
const FORMAT_VERSION: u16 = 1;
const FLAG_RESET_TABLE: u16 = 0x0001;
const HEADER_LEN: usize = 16;
/// Entry tag: a reference into the dynamic table (index varint follows).
const TAG_REF: u8 = 0x00;
/// Entry tag: a literal value (length varint + bytes follow).
const TAG_LITERAL: u8 = 0x01;

/// Deterministic FIFO dynamic table of recently seen byte strings.
///
/// This is the HPACK-style table: newest entries first, oldest evicted when
/// the capacity is exceeded. Both encoder and decoder maintain identical
/// tables by processing the same update stream, so table state is a pure
/// function of the stream and is never transmitted.
#[derive(Clone, Debug)]
pub struct DeltaTable {
    entries: VecDeque<Vec<u8>>,
    max_entries: usize,
}

impl DeltaTable {
    /// Creates an empty table with room for `max_entries` values.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            max_entries,
        }
    }

    /// Number of values currently held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table holds no values.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Maximum number of values the table holds.
    pub const fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Returns the index of `value` (0 = newest) if present.
    pub fn lookup(&self, value: &[u8]) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.as_slice() == value)
    }

    /// Returns the value at `index` (0 = newest).
    pub fn get(&self, index: usize) -> Option<&[u8]> {
        self.entries.get(index).map(|entry| entry.as_slice())
    }

    /// Inserts `value` at the front, evicting the oldest entry when full.
    ///
    /// Returns the index the value landed at (0 = newest). The eviction rule
    /// is deterministic FIFO, identical on both sides of a link.
    pub fn insert(&mut self, value: Vec<u8>) -> usize {
        if self.max_entries == 0 {
            return 0;
        }
        self.entries.push_front(value);
        while self.entries.len() > self.max_entries {
            self.entries.pop_back();
        }
        0
    }

    /// Clears the table (both sides must do this together).
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Differential-frame profile wrapping a [`Config`].
///
/// `DeltaConfig` keeps the base resource policies and adds framed,
/// deterministic differential encoding for ordered state exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeltaConfig {
    base: Config,
}

impl DeltaConfig {
    pub(crate) const fn new(base: Config) -> Self {
        Self { base }
    }

    /// Returns the underlying resource profile.
    pub const fn base_config(self) -> Config {
        self.base
    }

    /// Encodes `value - base` as a canonical ZigZag varint.
    ///
    /// The receiver already holds `base` (negotiated out of band), so only the
    /// difference crosses the wire. The difference is computed with checked
    /// arithmetic; an overflow is a protocol error.
    pub fn encode_delta(self, base: i128, value: i128) -> Result<Vec<u8>> {
        let delta = value
            .checked_sub(base)
            .ok_or(Error::Delta("delta overflows i128"))?;
        let mut output = Vec::new();
        self.write_zigzag(&mut output, delta)?;
        Ok(output)
    }

    /// Decodes a value from `base + encoded_delta`.
    pub fn decode_delta(self, base: i128, input: &[u8]) -> Result<i128> {
        let mut cursor = DeltaCursor::new(input);
        let delta = cursor.zigzag()?;
        cursor.finish()?;
        base.checked_add(delta)
            .ok_or(Error::Delta("reconstructed value overflows i128"))
    }

    /// Encodes a batch of byte-string updates into one differential frame.
    ///
    /// Values already present in `table` are emitted as table references;
    /// literals are emitted in full and then inserted into `table`. The table
    /// must be in the same state on the receiving side.
    pub fn encode_updates(self, table: &mut DeltaTable, updates: &[&[u8]]) -> Result<Vec<u8>> {
        let mut payload = Vec::new();
        for &value in updates {
            match table.lookup(value) {
                Some(index) => {
                    payload.push(TAG_REF);
                    self.write_varint(&mut payload, index as u128)?;
                }
                None => {
                    payload.push(TAG_LITERAL);
                    self.write_varint(&mut payload, value.len() as u128)?;
                    payload.extend_from_slice(value);
                    table.insert(value.to_vec());
                }
            }
        }
        let total = HEADER_LEN
            .checked_add(payload.len())
            .ok_or(Error::SizeLimit { limit: u64::MAX })?;
        self.enforce_byte_limit(total)?;
        let mut frame = Vec::with_capacity(total);
        frame.extend_from_slice(&MAGIC);
        frame.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        frame.extend_from_slice(&0u16.to_le_bytes());
        frame.extend_from_slice(&(updates.len() as u64).to_le_bytes());
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    /// Decodes a differential frame and replays the table updates.
    ///
    /// The returned values are the original updates in order. The table is
    /// mutated exactly as the encoder mutated its own, so both sides stay in
    /// sync.
    pub fn decode_updates(self, table: &mut DeltaTable, input: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.enforce_byte_limit(input.len())?;
        let header = input.get(..HEADER_LEN).ok_or(Error::UnexpectedEnd)?;
        if header[..4] != MAGIC {
            return Err(Error::InvalidFrame("delta magic does not match"));
        }
        if u16::from_le_bytes([header[4], header[5]]) != FORMAT_VERSION {
            return Err(Error::InvalidFrame("unsupported delta format version"));
        }
        let flags = u16::from_le_bytes([header[6], header[7]]);
        if flags & !FLAG_RESET_TABLE != 0 {
            return Err(Error::InvalidFrame("unknown delta frame flags"));
        }
        if flags & FLAG_RESET_TABLE != 0 {
            table.clear();
        }
        let count = u64::from_le_bytes(header[8..16].try_into().expect("fixed header width"));
        let count = usize::try_from(count)
            .map_err(|_| Error::Delta("delta frame count does not fit usize"))?;
        let mut cursor = DeltaCursor::new(&input[HEADER_LEN..]);
        let mut updates = Vec::with_capacity(count);
        for _ in 0..count {
            let tag = cursor.byte()?;
            match tag {
                TAG_REF => {
                    let index = usize::try_from(cursor.varint()?)
                        .map_err(|_| Error::Delta("delta table index does not fit usize"))?;
                    let value = table
                        .get(index)
                        .ok_or(Error::Delta("delta table reference out of range"))?
                        .to_vec();
                    updates.push(value);
                }
                TAG_LITERAL => {
                    let length = cursor.usize_varint()?;
                    let value = cursor.take(length)?.to_vec();
                    table.insert(value.clone());
                    updates.push(value);
                }
                _ => return Err(Error::Delta("unknown delta entry tag")),
            }
        }
        cursor.finish()?;
        Ok(updates)
    }

    fn write_zigzag(self, output: &mut Vec<u8>, value: i128) -> Result<()> {
        let encoded = ((value << 1) ^ (value >> 127)) as u128;
        self.write_varint(output, encoded)
    }

    fn write_varint(self, output: &mut Vec<u8>, mut value: u128) -> Result<()> {
        // Canonical marker varints mirror the core codec.
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                output.push(byte);
                return Ok(());
            }
            output.push(byte | 0x80);
        }
    }

    fn enforce_byte_limit(self, length: usize) -> Result<()> {
        if let Some(limit) = self.base.limit {
            if length as u64 > limit {
                return Err(Error::SizeLimit { limit });
            }
        }
        Ok(())
    }
}

struct DeltaCursor<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> DeltaCursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    fn byte(&mut self) -> Result<u8> {
        let byte = *self.input.get(self.pos).ok_or(Error::UnexpectedEnd)?;
        self.pos += 1;
        Ok(byte)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(length)
            .ok_or(Error::Delta("delta length overflows"))?;
        let bytes = self.input.get(self.pos..end).ok_or(Error::UnexpectedEnd)?;
        self.pos = end;
        Ok(bytes)
    }

    fn varint(&mut self) -> Result<u128> {
        let mut value = 0u128;
        let mut shift = 0u32;
        loop {
            let byte = self.byte()?;
            // The final group may carry fewer than 7 meaningful bits (only
            // bits 126..=127 of a u128 remain at shift 126); reject any group
            // whose bits would overflow the type.
            if shift >= 128 {
                return Err(Error::Delta("delta varint overflows u128"));
            }
            let remaining = 128 - shift;
            let low = byte & 0x7f;
            if remaining < 7 && (low >> remaining) != 0 {
                return Err(Error::Delta("delta varint overflows u128"));
            }
            value |= u128::from(low) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }

    fn usize_varint(&mut self) -> Result<usize> {
        let value = self.varint()?;
        usize::try_from(value).map_err(|_| Error::Delta("delta varint does not fit usize"))
    }

    fn zigzag(&mut self) -> Result<i128> {
        let encoded = self.varint()?;
        let value = ((encoded >> 1) as i128) ^ -((encoded & 1) as i128);
        Ok(value)
    }

    fn finish(self) -> Result<()> {
        if self.pos != self.input.len() {
            return Err(Error::TrailingBytes {
                remaining: self.input.len() - self.pos,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_delta_roundtrips_against_a_base() {
        let config = DeltaConfig::new(Config::standard());
        let base = 1_000_000i128;
        for &value in &[base, base + 1, base - 1, 0, base + 12345] {
            let encoded = config.encode_delta(base, value).unwrap();
            assert_eq!(config.decode_delta(base, &encoded).unwrap(), value);
        }
        // The full i128 range roundtrips against a zero base (MIN..MAX fits
        // in a ZigZag u128, so no delta overflow is possible).
        for &value in &[i128::MIN, i128::MAX, 0] {
            let encoded = config.encode_delta(0, value).unwrap();
            assert_eq!(config.decode_delta(0, &encoded).unwrap(), value);
        }
        // Identical values produce the smallest delta (zero); a larger delta
        // needs more varint bytes.
        let zero = config.encode_delta(base, base).unwrap();
        let one = config.encode_delta(base, base + 1000).unwrap();
        assert!(zero.len() < one.len());
        // A delta that cannot fit in i128 is a protocol error.
        assert!(config.encode_delta(1, i128::MIN).is_err());
    }

    #[test]
    fn dynamic_table_reuses_recent_values() {
        let config = DeltaConfig::new(Config::standard());
        let mut encoder_table = DeltaTable::new(8);
        let mut decoder_table = DeltaTable::new(8);

        let updates: Vec<Vec<u8>> = vec![
            b"height/42".to_vec(),
            b"height/43".to_vec(),
            b"height/44".to_vec(),
            b"height/42".to_vec(), // repeated -> table reference
            b"height/43".to_vec(), // repeated -> table reference
        ];
        let refs: Vec<&[u8]> = updates.iter().map(|u| u.as_slice()).collect();
        let frame = config.encode_updates(&mut encoder_table, &refs).unwrap();
        let decoded = config.decode_updates(&mut decoder_table, &frame).unwrap();
        assert_eq!(decoded, updates);
        // Both tables converged to the identical state.
        assert_eq!(encoder_table.len(), decoder_table.len());
        assert!(encoder_table.get(0) == decoder_table.get(0));

        // The frame is smaller than the concatenated literals because of the
        // two table references.
        let all_literals: usize = updates.iter().map(|u| u.len() + 2).sum();
        assert!(frame.len() < HEADER_LEN + all_literals);
    }

    #[test]
    fn dynamic_table_evicts_oldest_deterministically() {
        let mut table = DeltaTable::new(3);
        for value in [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()] {
            table.insert(value);
        }
        assert_eq!(table.len(), 3);
        assert_eq!(table.get(0), Some(&b"c"[..]));
        assert_eq!(table.get(2), Some(&b"a"[..]));
        // Inserting a fourth value evicts "a" (FIFO).
        table.insert(b"d".to_vec());
        assert_eq!(table.len(), 3);
        assert!(table.lookup(b"a").is_none());
        assert!(table.lookup(b"d").is_some());
        // Table state is deterministic across identical insert sequences.
        let mut replay = DeltaTable::new(3);
        for value in [b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()] {
            replay.insert(value);
        }
        assert_eq!(table.get(0), replay.get(0));
        assert_eq!(table.get(1), replay.get(1));
        assert_eq!(table.get(2), replay.get(2));
    }

    #[test]
    fn delta_frames_reject_corruption_and_malformed_entries() {
        let config = DeltaConfig::new(Config::standard());
        let mut table = DeltaTable::new(8);
        let updates: Vec<&[u8]> = vec![b"alpha".as_slice(), b"beta".as_slice()];
        let frame = config.encode_updates(&mut table, &updates).unwrap();

        let mut wrong_magic = frame.clone();
        wrong_magic[0] = b'X';
        assert!(matches!(
            config.decode_updates(&mut DeltaTable::new(8), &wrong_magic),
            Err(Error::InvalidFrame(_))
        ));

        let mut truncated = frame.clone();
        truncated.pop();
        assert!(config
            .decode_updates(&mut DeltaTable::new(8), &truncated)
            .is_err());

        // A table reference without a matching entry is rejected.
        let mut crafted = Vec::new();
        crafted.extend_from_slice(&MAGIC);
        crafted.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        crafted.extend_from_slice(&0u16.to_le_bytes());
        crafted.extend_from_slice(&1u64.to_le_bytes());
        crafted.push(TAG_REF);
        crafted.push(0); // index 0 into an empty table
        assert!(config
            .decode_updates(&mut DeltaTable::new(8), &crafted)
            .is_err());
    }
}
