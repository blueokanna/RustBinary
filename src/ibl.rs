//! Invertible Bloom Lookup Tables (IBLT) for set reconciliation.
//!
//! An IBLT encodes a set into a fixed-size array of cells. Two peers encode
//! their sets, exchange the tables (or their difference), and one side
//! subtracts and peels the difference to recover exactly the elements in
//! `mine \ theirs` and `theirs \ mine`. Unlike delta frames, which assume an
//! ordered stream and a shared baseline, IBLT reconciles **unordered sets**
//! and needs only the difference table on the wire.
//!
//! This is a from-scratch implementation (Goodrich & Mitzenmacher, 2011) with
//! three deterministic splitmix64 hash functions; it is `no_std` + `alloc` and
//! has no external dependencies. The difference-set size must be small
//! relative to the table size for decoding to complete; an undersized table
//! reports [`Error::Iblt`] with `"decode incomplete"`.
//!
//! Combine IBLT with [`crate::delta`] to cover both unordered set diffs and
//! ordered baseline-relative frames in one gossip layer.

use alloc::vec;
use alloc::vec::Vec;

use crate::{Error, Result};

/// Number of hash functions (cell positions per key).
const HASH_COUNT: usize = 3;
/// Seeds for the three cell-position hashes.
const POSITION_SEEDS: [u64; HASH_COUNT] = [
    0x9e37_79b9_7f4a_7c15,
    0xbf58_476d_1ce4_e5b9,
    0x94d0_49bb_1331_11eb,
];

/// Deterministic splitmix64: a strong, dependency-free integer hash.
pub fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// One IBLT cell: an XOR-accumulating bucket.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Cell {
    /// Insertions minus deletions landing in this cell.
    pub count: i32,
    /// XOR of all keys landing in this cell.
    pub key_sum: u64,
    /// XOR of all values landing in this cell.
    pub value_sum: u64,
    /// XOR of all key hashes landing in this cell.
    pub hash_sum: u64,
}

/// One recovered difference entry from [`Iblt::decode`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IbltEntry {
    /// The key of the recovered element.
    pub key: u64,
    /// The associated value (an application payload for the key).
    pub value: u64,
    /// `true` if the element was in `self` but not the subtracted table.
    pub present_in_self: bool,
}

/// Invertible Bloom Lookup Table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Iblt {
    cells: Vec<Cell>,
}

impl Iblt {
    /// Creates an empty table with `num_cells` cells.
    ///
    /// Decoding completes when the difference-set size is a small fraction of
    /// `num_cells` (practically up to ~`num_cells / 3` differences with three
    /// hash functions).
    pub fn new(num_cells: usize) -> Self {
        Self {
            cells: vec![Cell::default(); num_cells.max(1)],
        }
    }

    /// Number of cells in the table.
    pub fn num_cells(&self) -> usize {
        self.cells.len()
    }

    /// Number of cells with a non-zero count (an estimate of the set size).
    pub fn occupied(&self) -> usize {
        self.cells.iter().filter(|cell| cell.count != 0).count()
    }

    /// Whether every cell is empty.
    pub fn is_empty(&self) -> bool {
        self.cells.iter().all(|cell| cell.count == 0)
    }

    /// Inserts `(key, value)` into the table.
    pub fn insert(&mut self, key: u64, value: u64) {
        let hash = splitmix64(key);
        for seed in POSITION_SEEDS {
            let position = (splitmix64(key ^ seed) as usize) % self.cells.len();
            let cell = &mut self.cells[position];
            cell.count += 1;
            cell.key_sum ^= key;
            cell.value_sum ^= value;
            cell.hash_sum ^= hash;
        }
    }

    /// Deletes `(key, value)` from the table (must have been inserted).
    pub fn delete(&mut self, key: u64, value: u64) {
        let hash = splitmix64(key);
        for seed in POSITION_SEEDS {
            let position = (splitmix64(key ^ seed) as usize) % self.cells.len();
            let cell = &mut self.cells[position];
            cell.count -= 1;
            cell.key_sum ^= key;
            cell.value_sum ^= value;
            cell.hash_sum ^= hash;
        }
    }

    /// Subtracts `other` in place. Both tables must have the same size.
    ///
    /// The result encodes `self \ other` (positive cells) and `other \ self`
    /// (negative cells) when `other` covers a disjoint difference set.
    pub fn subtract(&mut self, other: &Iblt) -> Result<()> {
        if self.cells.len() != other.cells.len() {
            return Err(Error::Iblt("IBLT size mismatch in subtract"));
        }
        for (left, right) in self.cells.iter_mut().zip(&other.cells) {
            left.count -= right.count;
            left.key_sum ^= right.key_sum;
            left.value_sum ^= right.value_sum;
            left.hash_sum ^= right.hash_sum;
        }
        Ok(())
    }

    /// Peels the table and recovers the difference set.
    ///
    /// Returns the recovered entries, or an error when the table cannot be
    /// fully decoded (too many differences for the table size, or a corrupt
    /// cell whose hash does not verify).
    pub fn decode(&self) -> Result<Vec<IbltEntry>> {
        let mut table = self.clone();
        let mut entries = Vec::new();
        loop {
            let mut progress = false;
            for position in 0..table.cells.len() {
                let count = table.cells[position].count;
                if count == 1 || count == -1 {
                    let key = table.cells[position].key_sum;
                    let value = table.cells[position].value_sum;
                    if splitmix64(key) != table.cells[position].hash_sum {
                        return Err(Error::Iblt("IBLT cell hash does not verify"));
                    }
                    if count == 1 {
                        table.delete(key, value);
                        entries.push(IbltEntry {
                            key,
                            value,
                            present_in_self: true,
                        });
                    } else {
                        table.insert(key, value);
                        entries.push(IbltEntry {
                            key,
                            value,
                            present_in_self: false,
                        });
                    }
                    progress = true;
                    break;
                }
            }
            if !progress {
                break;
            }
        }
        if !table.is_empty() {
            return Err(Error::Iblt("IBLT decode incomplete (table too small?)"));
        }
        Ok(entries)
    }

    /// Returns the raw cells (for serialization over the wire).
    pub fn cells(&self) -> &[Cell] {
        &self.cells
    }
}

/// Encodes a set of `(key, value)` pairs into a table of `num_cells` cells.
pub fn encode_set(entries: &[(u64, u64)], num_cells: usize) -> Iblt {
    let mut table = Iblt::new(num_cells);
    for &(key, value) in entries {
        table.insert(key, value);
    }
    table
}

/// Reconciles two tables and returns the difference set.
///
/// `mine` and `theirs` are expected to share a large common subset. The
/// returned entries carry `present_in_self = true` for `mine \ theirs` and
/// `false` for `theirs \ mine`.
pub fn reconcile(mine: &Iblt, theirs: &Iblt) -> Result<Vec<IbltEntry>> {
    let mut difference = mine.clone();
    difference.subtract(theirs)?;
    difference.decode()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_pairs(seed: u64, count: usize) -> Vec<(u64, u64)> {
        let mut state = seed;
        let mut pairs = Vec::with_capacity(count);
        for index in 0..count {
            state = splitmix64(state);
            let key = state ^ (index as u64).wrapping_mul(0x9e37_79b9);
            pairs.push((key, state.wrapping_mul(3) + index as u64));
        }
        pairs
    }

    #[test]
    fn insert_delete_roundtrips_and_decodes_empty() {
        let mut table = Iblt::new(16);
        let pairs = random_pairs(0x1234, 8);
        for &(key, value) in &pairs {
            table.insert(key, value);
        }
        assert!(!table.is_empty());
        for &(key, value) in &pairs {
            table.delete(key, value);
        }
        assert!(table.is_empty());
        assert_eq!(table.decode().unwrap(), Vec::new());
    }

    #[test]
    fn reconcile_recovers_exact_difference() {
        let common = random_pairs(0xabcd, 200);
        let mut mine_set = common.clone();
        mine_set.extend(random_pairs(0x1111, 10));
        let mut theirs_set = common.clone();
        theirs_set.extend(random_pairs(0x2222, 7));

        let mine = encode_set(&mine_set, 256);
        let theirs = encode_set(&theirs_set, 256);
        let difference = reconcile(&mine, &theirs).unwrap();

        let only_mine: Vec<(u64, u64)> = difference
            .iter()
            .filter(|entry| entry.present_in_self)
            .map(|entry| (entry.key, entry.value))
            .collect();
        let only_theirs: Vec<(u64, u64)> = difference
            .iter()
            .filter(|entry| !entry.present_in_self)
            .map(|entry| (entry.key, entry.value))
            .collect();

        let mut expected_mine = random_pairs(0x1111, 10);
        expected_mine.sort_unstable();
        let mut expected_theirs = random_pairs(0x2222, 7);
        expected_theirs.sort_unstable();
        let mut actual_mine = only_mine;
        actual_mine.sort_unstable();
        let mut actual_theirs = only_theirs;
        actual_theirs.sort_unstable();
        assert_eq!(actual_mine, expected_mine);
        assert_eq!(actual_theirs, expected_theirs);
    }

    #[test]
    fn undersized_table_reports_incomplete_decode() {
        // 30 differences in an 8-cell table cannot be peeled.
        let mine_set = random_pairs(0x3333, 30);
        let theirs_set: Vec<(u64, u64)> = Vec::new();
        let mine = encode_set(&mine_set, 8);
        let theirs = encode_set(&theirs_set, 8);
        assert!(matches!(
            reconcile(&mine, &theirs),
            Err(Error::Iblt("IBLT decode incomplete (table too small?)"))
        ));
    }

    #[test]
    fn identical_sets_reconcile_to_empty() {
        let pairs = random_pairs(0x5555, 64);
        let mine = encode_set(&pairs, 128);
        let theirs = encode_set(&pairs, 128);
        assert!(reconcile(&mine, &theirs).unwrap().is_empty());
    }
}
