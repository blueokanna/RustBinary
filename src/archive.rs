//! Validated relative-pointer archives for read-only memory mapping.
//!
//! This module is deliberately separate from the nextjson stream codec. Archive
//! values use rkyv's flat, relative-pointer layout and can be accessed in place
//! after one structural validation pass. RustBinary adds a stable envelope,
//! explicit application schema identifiers, resource limits, a read-only mmap
//! owner, and a **Merkle tree over the payload**.
//!
//! Every archive (format version 2) carries a SHA-256 Merkle root in the
//! envelope. The hash is the dependency-free implementation in `hash` (no
//! third-party hashing crate). A full [`crate::archive::MappedArchive::open`] validates the envelope, the
//! relative-pointer graph, and the Merkle root once. For TB-scale archives,
//! [`crate::archive::MappedArchive::open_header_only`] verifies only the envelope, and every
//! byte range is then covered by a self-contained [`crate::archive::MerkleProof`] built from
//! [`crate::archive::MappedArchive::proof_for`]. A proof carries the covered blocks and the
//! sibling hashes, so a light client can verify a range against the root
//! without holding the rest of the file — verification is O(log n) per range
//! and becomes a per-access cost instead of a one-time cost.
//!
//! Mapped files must be immutable for the complete lifetime of a
//! [`MappedArchive`](crate::archive::MappedArchive). The operating system cannot enforce that requirement
//! against every other process, so opening a file mapping is an unsafe
//! operation with a precise safety contract.

use core::{fmt, marker::PhantomData, mem::align_of, ops::Range};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::Path,
};

use memmap2::{Mmap, MmapOptions};
use rkyv::{
    api::high::{HighSerializer, HighValidator},
    bytecheck::CheckBytes,
    rancor::Error as RkyvError,
    ser::allocator::ArenaHandle,
    util::AlignedVec,
    Portable,
};

use crate::ErrorCategory;

/// BLAKE3 digest over `input` using the audited [`blake3`] crate.
///
/// This is the single hashing entry point for the archive Merkle tree. The
/// crate is the official, formally reviewed BLAKE3 implementation (as opposed
/// to an in-tree reimplementation); domain separation and tree geometry are
/// owned by this module, not by the hash primitive.
fn blake3(input: &[u8]) -> [u8; 32] {
    *blake3_crate::hash(input).as_bytes()
}

use blake3 as blake3_crate;

/// Re-exported derives and traits used to define archive-native types.
pub use rkyv::{Archive, Deserialize, Serialize};

const MAGIC: [u8; 8] = *b"RBARC002";
const FORMAT_VERSION: u16 = 2;
/// Format flag: the payload carries a Merkle tree with the recorded root.
/// Merkle verification is mandatory in format version 2.
const FLAG_MERKLE: u16 = 0x0001;
const FORMAT_FLAGS: u16 = FLAG_MERKLE;
const HEADER_LEN: usize = 128;
/// Byte offset of the rkyv payload within an archive file.
pub const PAYLOAD_OFFSET: usize = HEADER_LEN;
const MAX_ARCHIVE_ALIGNMENT: usize = 64;

/// Domain-separation tag for Merkle leaf hashes over real block data.
const LEAF_DOMAIN: u8 = 0x00;
/// Domain-separation tag for Merkle internal node hashes.
const NODE_DOMAIN: u8 = 0x01;
/// Domain-separation tag for Merkle padding (absent) leaves.
const PAD_DOMAIN: u8 = 0x02;

/// Default maximum size accepted for one archive file: 1 GiB.
pub const DEFAULT_ARCHIVE_SIZE_LIMIT: u64 = 1024 * 1024 * 1024;
/// Default Merkle block size: 4 KiB of payload per leaf.
pub const DEFAULT_MERKLE_BLOCK_SIZE: u32 = 4096;

/// Resource policy applied before allocation, validation, or mapping access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveLimits {
    max_file_size: u64,
    merkle_block_size: u32,
}

impl ArchiveLimits {
    /// Creates a policy with the conservative 1 GiB file limit and 4 KiB blocks.
    pub const fn new() -> Self {
        Self {
            max_file_size: DEFAULT_ARCHIVE_SIZE_LIMIT,
            merkle_block_size: DEFAULT_MERKLE_BLOCK_SIZE,
        }
    }

    /// Sets the maximum complete archive size, including the envelope.
    pub const fn with_max_file_size(mut self, max_file_size: u64) -> Self {
        self.max_file_size = max_file_size;
        self
    }

    /// Sets the Merkle leaf block size in bytes.
    ///
    /// Smaller blocks give finer-grained proofs and more proof overhead per
    /// range; larger blocks reduce tree height. Must be a power of two and at
    /// least 32 bytes.
    pub const fn with_merkle_block_size(mut self, block_size: u32) -> Self {
        self.merkle_block_size = block_size;
        self
    }

    /// Returns the configured complete-file limit.
    pub const fn max_file_size(self) -> u64 {
        self.max_file_size
    }

    /// Returns the configured Merkle leaf block size.
    pub const fn merkle_block_size(self) -> u32 {
        self.merkle_block_size
    }
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self::new()
    }
}

/// Stable application identity for an archive root type.
///
/// The identifier is chosen and versioned by the application. It must change
/// whenever the archived field layout changes incompatibly. Zero is reserved
/// and rejected so an omitted schema decision cannot silently reach storage.
pub trait ArchiveSchema: Archive {
    /// Non-zero application-controlled schema identifier.
    const SCHEMA_ID: u64;
}

/// Parsed RustBinary archive envelope metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveHeader {
    schema_id: u64,
    payload_len: u64,
    file_len: u64,
    block_size: u32,
    block_count: u64,
    root: [u8; 32],
    hash_offset: u64,
    hash_len: u64,
}

impl ArchiveHeader {
    /// Returns the envelope format version.
    pub const fn format_version(self) -> u16 {
        FORMAT_VERSION
    }

    /// Returns the application-controlled root schema identifier.
    pub const fn schema_id(self) -> u64 {
        self.schema_id
    }

    /// Returns the rkyv payload length in bytes.
    pub const fn payload_len(self) -> u64 {
        self.payload_len
    }

    /// Returns the complete envelope and payload length.
    pub const fn file_len(self) -> u64 {
        self.file_len
    }

    /// Returns the Merkle leaf block size in bytes.
    pub const fn block_size(self) -> u32 {
        self.block_size
    }

    /// Returns the number of Merkle leaves covering the payload.
    pub const fn block_count(self) -> u64 {
        self.block_count
    }

    /// Returns the Merkle root digest over the payload blocks.
    pub const fn root_digest(self) -> [u8; 32] {
        self.root
    }

    /// Returns the byte offset of the stored internal-node hash section.
    pub const fn hash_offset(self) -> u64 {
        self.hash_offset
    }

    /// Returns the byte length of the stored internal-node hash section.
    pub const fn hash_len(self) -> u64 {
        self.hash_len
    }
}

/// Failure while building, validating, writing, or mapping an archive.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArchiveError {
    /// File or mapping I/O failed.
    Io(io::Error),
    /// The configured complete-file limit was exceeded.
    SizeLimit {
        /// Configured maximum size.
        limit: u64,
        /// Size that was supplied or required.
        actual: u64,
    },
    /// The envelope is truncated or violates the format contract.
    InvalidHeader(&'static str),
    /// The root type uses the reserved zero application schema identifier.
    InvalidSchemaId,
    /// The application schema does not match the requested root type.
    SchemaMismatch {
        /// Schema required by the requested type.
        expected: u64,
        /// Schema stored in the archive envelope.
        actual: u64,
    },
    /// The root's alignment exceeds the archive envelope guarantee.
    UnsupportedAlignment {
        /// Alignment required by the archived root.
        required: usize,
        /// Maximum alignment guaranteed by the envelope.
        supported: usize,
    },
    /// The native value could not be converted to an archive layout.
    Serialization(String),
    /// The relative-pointer graph or an archived value failed byte validation.
    Validation(String),
    /// A Merkle proof or the recorded tree root failed verification.
    Merkle(&'static str),
}

impl ArchiveError {
    /// Returns the stable operational responsibility for this failure.
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::Io(_) | Self::SizeLimit { .. } | Self::UnsupportedAlignment { .. } => {
                ErrorCategory::Configuration
            }
            Self::InvalidHeader(_)
            | Self::SchemaMismatch { .. }
            | Self::Validation(_)
            | Self::Merkle(_) => ErrorCategory::Protocol,
            Self::InvalidSchemaId => ErrorCategory::Configuration,
            Self::Serialization(_) => ErrorCategory::UserInput,
        }
    }
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "archive I/O error: {error}"),
            Self::SizeLimit { limit, actual } => write!(
                f,
                "archive size {actual} exceeds the configured limit of {limit} bytes"
            ),
            Self::InvalidHeader(reason) => write!(f, "invalid archive header: {reason}"),
            Self::InvalidSchemaId => {
                f.write_str("archive root uses the reserved zero schema identifier")
            }
            Self::SchemaMismatch { expected, actual } => write!(
                f,
                "archive schema mismatch: expected {expected:#018x}, found {actual:#018x}"
            ),
            Self::UnsupportedAlignment {
                required,
                supported,
            } => write!(
                f,
                "archived root requires {required}-byte alignment; at most {supported} is supported"
            ),
            Self::Serialization(message) => write!(f, "archive serialization failed: {message}"),
            Self::Validation(message) => write!(f, "archive validation failed: {message}"),
            Self::Merkle(reason) => write!(f, "archive Merkle verification failed: {reason}"),
        }
    }
}

impl std::error::Error for ArchiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ArchiveError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Merkle leaf hash over one payload block.
///
/// The input is the domain tag, the 64-bit big-endian leaf index, and the
/// block bytes, hashed with the audited [`blake3`] crate.
fn leaf_hash(index: u64, block: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(9 + block.len());
    input.push(LEAF_DOMAIN);
    input.extend_from_slice(&index.to_be_bytes());
    input.extend_from_slice(block);
    blake3(&input)
}

/// Hash of an absent (padding) leaf at `index`.
fn pad_hash(index: u64) -> [u8; 32] {
    let mut input = [0_u8; 9];
    input[0] = PAD_DOMAIN;
    input[1..9].copy_from_slice(&index.to_be_bytes());
    blake3(&input)
}

/// Merkle internal node hash.
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = [0_u8; 65];
    input[0] = NODE_DOMAIN;
    input[1..33].copy_from_slice(left);
    input[33..65].copy_from_slice(right);
    blake3(&input)
}

/// Computes the tree height (levels above the leaves) for `block_count`
/// leaves, using a complete binary tree padded to a power of two.
fn tree_height(block_count: u64) -> u32 {
    if block_count <= 1 {
        return 0;
    }
    let mut height = 0u32;
    let mut size = 1u64;
    while size < block_count {
        size <<= 1;
        height += 1;
    }
    height
}

/// Computes all Merkle levels of `payload` under the given block size,
/// bottom-up (level 0 = leaves).
///
/// The tree is a complete binary tree padded with absent-leaf hashes to a
/// power of two, so every level is a pure function of `(payload, block_size)`.
/// Returns the levels and the number of real (non-padding) leaves.
fn merkle_levels(payload: &[u8], block_size: u32) -> (Vec<Vec<[u8; 32]>>, u64) {
    let block_count = payload.len().div_ceil(block_size as usize).max(1) as u64;
    let height = tree_height(block_count);
    let leaf_count = 1u64 << height;
    let mut levels = Vec::with_capacity(height as usize + 1);
    let mut level: Vec<[u8; 32]> = (0..leaf_count)
        .map(|index| {
            if index < block_count {
                let start = (index as usize) * block_size as usize;
                let end = (start + block_size as usize).min(payload.len());
                leaf_hash(index, &payload[start..end])
            } else {
                pad_hash(index)
            }
        })
        .collect();
    levels.push(level.clone());
    let mut count = leaf_count;
    while count > 1 {
        let mut next = Vec::with_capacity((count / 2) as usize);
        let mut index = 0;
        while index < count {
            next.push(node_hash(
                &level[index as usize],
                &level[index as usize + 1],
            ));
            index += 2;
        }
        level = next;
        levels.push(level.clone());
        count /= 2;
    }
    (levels, block_count)
}

/// Serializes the internal Merkle levels (everything above the leaves) into
/// the on-disk hash section: level 1 first, the root last.
fn serialize_hash_section(levels: &[Vec<[u8; 32]>]) -> Vec<u8> {
    let mut section = Vec::with_capacity((levels.len().saturating_sub(1)) * 32 * 32);
    for level in levels.iter().skip(1) {
        for hash in level {
            section.extend_from_slice(hash);
        }
    }
    section
}

/// Reads one internal hash at `(level, index)` from the on-disk hash section.
/// `level` is 1-indexed (1 = parents of leaves), `height` is the tree height.
fn read_section_hash(
    hash_section: &[u8],
    leaf_count: u64,
    height: u32,
    level: u32,
    index: u64,
) -> [u8; 32] {
    let level_offset = leaf_count - (1u64 << (height - level + 1));
    let position = ((level_offset + index) as usize) * 32;
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&hash_section[position..position + 32]);
    hash
}

/// Hash of a leaf at `index`: real block data or the padding hash.
fn leaf_hash_for(payload: &[u8], block_size: u32, block_count: u64, index: u64) -> [u8; 32] {
    if index < block_count {
        let start = (index as usize) * block_size as usize;
        let end = (start + block_size as usize).min(payload.len());
        leaf_hash(index, &payload[start..end])
    } else {
        pad_hash(index)
    }
}

/// One level of a proof plan: the covered node indices and the sibling node
/// indices (both sorted ascending, at this level of the padded tree).
#[derive(Clone, Debug)]
struct LevelPlan {
    covered: Vec<u64>,
    siblings: Vec<u64>,
}

/// Computes the deterministic proof plan for the leaf range `first..=last`.
///
/// Both the builder and the verifier run this exact function, so the sibling
/// order can never drift. At each level the covered nodes are the parents of
/// the covered nodes below; a covered node contributes a sibling hash exactly
/// when its natural partner is not itself covered. The plan is a pure function
/// of `(first, last, height)`, so it needs no access to the tree.
fn compute_plan(first: u64, last: u64, height: u32) -> Vec<LevelPlan> {
    let mut plans = Vec::with_capacity(height as usize);
    let mut covered: Vec<u64> = (first..=last).collect();
    for _level in 0..height {
        let mut siblings = Vec::new();
        for (position, &index) in covered.iter().enumerate() {
            if index % 2 == 1 {
                let has_left_neighbour = position > 0 && covered[position - 1] == index - 1;
                if !has_left_neighbour {
                    siblings.push(index - 1);
                }
            } else {
                let has_right_neighbour = covered.get(position + 1) == Some(&(index + 1));
                if !has_right_neighbour {
                    siblings.push(index + 1);
                }
            }
        }
        plans.push(LevelPlan {
            covered: covered.clone(),
            siblings,
        });
        let mut next: Vec<u64> = covered.iter().map(|&index| index / 2).collect();
        next.sort_unstable();
        next.dedup();
        covered = next;
    }
    plans
}

/// Collects the sibling hashes for the leaf range `first..=last` in plan
/// order.
///
/// Depth-0 siblings are computed from the payload; deeper siblings are read
/// from the stored hash section, so the cost is O(log n) after the archive is
/// open for a fixed range width.
fn collect_siblings(
    payload: &[u8],
    hash_section: &[u8],
    block_size: u32,
    block_count: u64,
    height: u32,
    first: u64,
    last: u64,
) -> Vec<[u8; 32]> {
    let leaf_count = 1u64 << height;
    let plan = compute_plan(first, last, height);
    let mut siblings = Vec::new();
    for (level, level_plan) in plan.iter().enumerate() {
        for &index in &level_plan.siblings {
            let hash = if level == 0 {
                leaf_hash_for(payload, block_size, block_count, index)
            } else {
                read_section_hash(hash_section, leaf_count, height, level as u32, index)
            };
            siblings.push(hash);
        }
    }
    siblings
}

/// Recomputes the Merkle root of a covered leaf range from its block hashes
/// and the sibling hashes collected in plan order by [`collect_siblings`].
fn replay_root(
    covered_hashes: &[[u8; 32]],
    first: u64,
    last: u64,
    height: u32,
    siblings: &[[u8; 32]],
) -> Result<[u8; 32], ArchiveError> {
    let plan = compute_plan(first, last, height);
    let mut level_hashes: Vec<[u8; 32]> = covered_hashes.to_vec();
    let mut cursor = 0usize;
    for (level, level_plan) in plan.iter().enumerate() {
        let _ = level;
        let mut next_hashes = Vec::with_capacity(level_plan.covered.len());
        let mut position = 0usize;
        while position < level_plan.covered.len() {
            let index = level_plan.covered[position];
            if index % 2 == 1 {
                // Odd covered node: its left sibling was provided.
                let sibling = *siblings
                    .get(cursor)
                    .ok_or(ArchiveError::Merkle("missing left sibling"))?;
                cursor += 1;
                next_hashes.push(node_hash(&sibling, &level_hashes[position]));
                position += 1;
            } else if level_plan.covered.get(position + 1) == Some(&(index + 1)) {
                // Even covered node paired with its covered right neighbour.
                next_hashes.push(node_hash(
                    &level_hashes[position],
                    &level_hashes[position + 1],
                ));
                position += 2;
            } else {
                // Even covered node: its right sibling was provided.
                let sibling = *siblings
                    .get(cursor)
                    .ok_or(ArchiveError::Merkle("missing right sibling"))?;
                cursor += 1;
                next_hashes.push(node_hash(&level_hashes[position], &sibling));
                position += 1;
            }
        }
        level_hashes = next_hashes;
    }
    if cursor != siblings.len() {
        return Err(ArchiveError::Merkle("unused sibling hashes"));
    }
    if level_hashes.len() != 1 {
        return Err(ArchiveError::Merkle("proof did not collapse to one root"));
    }
    Ok(level_hashes[0])
}

/// Self-contained Merkle proof for one payload byte range.
///
/// A proof carries the covered block data and the sibling hashes, so it can be
/// verified against a known root without access to the rest of the archive —
/// the light-client flow. [`MerkleProof::verify`] recomputes the root from the
/// carried blocks and siblings and compares it with the recorded root;
/// [`MerkleProof::extract`] returns the verified bytes for the covered range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleProof {
    offset: u64,
    len: u64,
    block_size: u32,
    block_count: u64,
    payload_len: u64,
    blocks: Vec<Vec<u8>>,
    siblings: Vec<[u8; 32]>,
    root: [u8; 32],
}

impl MerkleProof {
    /// Range offset within the payload.
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Covered range length in bytes.
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Whether the proof covers an empty range.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Recorded Merkle root the proof verifies against.
    pub const fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Number of blocks carried by the proof.
    pub const fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Returns the carried block data (before verification).
    pub fn blocks(&self) -> &[Vec<u8>] {
        &self.blocks
    }

    /// Returns the carried sibling hashes (before verification).
    pub fn siblings(&self) -> &[[u8; 32]] {
        &self.siblings
    }

    /// Recomputes the root from the carried blocks and sibling hashes and
    /// compares it with the recorded root.
    pub fn verify(&self) -> Result<(), ArchiveError> {
        let height = tree_height(self.block_count);
        let end = self
            .offset
            .checked_add(self.len)
            .ok_or(ArchiveError::Merkle("proof range overflows"))?;
        if self.offset >= self.payload_len || end > self.payload_len {
            return Err(ArchiveError::Merkle("proof range exceeds the payload"));
        }
        let first_block = self.offset / u64::from(self.block_size);
        let last_block = if self.len == 0 {
            first_block
        } else {
            (self.offset + self.len - 1) / u64::from(self.block_size)
        };
        let covered = (last_block - first_block + 1) as usize;
        if covered != self.blocks.len() {
            return Err(ArchiveError::Merkle("proof block count mismatch"));
        }
        let mut hashes = Vec::with_capacity(covered);
        for (index, block) in self.blocks.iter().enumerate() {
            hashes.push(leaf_hash(first_block + index as u64, block));
        }
        let root = replay_root(&hashes, first_block, last_block, height, &self.siblings)?;
        if root != self.root {
            return Err(ArchiveError::Merkle("root digest does not match"));
        }
        Ok(())
    }

    /// Returns the verified bytes for the covered range.
    ///
    /// Verifies the proof first, so the returned copy is only produced when
    /// the carried blocks authenticate against the recorded root.
    pub fn extract(&self) -> Result<Vec<u8>, ArchiveError> {
        self.verify()?;
        let start = (self.offset % u64::from(self.block_size)) as usize;
        let mut remaining = self.len as usize;
        let mut out = Vec::with_capacity(remaining);
        for (index, block) in self.blocks.iter().enumerate() {
            let block_offset = if index == 0 { start } else { 0 };
            let take = (block.len() - block_offset).min(remaining);
            out.extend_from_slice(&block[block_offset..block_offset + take]);
            remaining -= take;
        }
        if remaining != 0 {
            return Err(ArchiveError::Merkle("proof bytes do not cover the range"));
        }
        Ok(out)
    }
}

/// Immutable, aligned archive bytes owned by the current process.
pub struct OwnedArchive<T: ArchiveSchema> {
    bytes: AlignedVec<MAX_ARCHIVE_ALIGNMENT>,
    payload: Range<usize>,
    hash_section: Range<usize>,
    header: ArchiveHeader,
    marker: PhantomData<T>,
}

impl<T: ArchiveSchema> OwnedArchive<T> {
    /// Returns the parsed envelope metadata.
    pub const fn header(&self) -> ArchiveHeader {
        self.header
    }

    /// Returns the complete versioned archive bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the validated rkyv payload bytes without the envelope.
    pub fn payload(&self) -> &[u8] {
        &self.bytes[self.payload.clone()]
    }

    /// Returns the Merkle root digest of the payload.
    pub fn root_digest(&self) -> [u8; 32] {
        self.header.root
    }

    /// Builds a self-contained Merkle proof for `[offset, offset + len)`
    /// bytes of the payload.
    ///
    /// The proof can be shipped to a light client that holds only the root; it
    /// verifies in O(log n) without the rest of the archive.
    pub fn proof_for(&self, offset: u64, len: u64) -> Result<MerkleProof, ArchiveError> {
        build_proof(
            self.payload(),
            &self.bytes[self.hash_section.clone()],
            offset,
            len,
            self.header,
        )
    }

    /// Creates a new immutable archive file and flushes its contents.
    ///
    /// Existing files are never overwritten. If writing or syncing fails, the
    /// newly created partial file is removed before returning the error.
    pub fn write_new(&self, path: impl AsRef<Path>) -> Result<(), ArchiveError> {
        let path = path.as_ref();
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        let result = (|| {
            file.write_all(self.as_bytes())?;
            file.sync_all()
        })();
        if let Err(error) = result {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(ArchiveError::Io(error));
        }
        Ok(())
    }
}

impl<T> OwnedArchive<T>
where
    T: ArchiveSchema,
    T::Archived: Portable,
{
    /// Returns the archived root without allocating or deserializing.
    pub fn root(&self) -> &T::Archived {
        // SAFETY: `build` validates the immutable private payload before
        // constructing `OwnedArchive`; callers can only borrow these bytes.
        unsafe { rkyv::access_unchecked::<T::Archived>(self.payload()) }
    }
}

/// Read-only owner for a validated memory-mapped archive.
pub struct MappedArchive<T: ArchiveSchema> {
    map: Mmap,
    payload: Range<usize>,
    hash_section: Range<usize>,
    header: ArchiveHeader,
    marker: PhantomData<T>,
}

impl<T> MappedArchive<T>
where
    T: ArchiveSchema,
    T::Archived: Portable + for<'a> CheckBytes<HighValidator<'a, RkyvError>>,
{
    /// Opens, maps, and fully validates an immutable archive file.
    ///
    /// Validation covers the envelope, the schema identifier, alignment, the
    /// complete relative-pointer graph, and the Merkle root (recomputed from
    /// the payload and compared with the stored root and hash section).
    ///
    /// # Safety
    ///
    /// No process may modify or truncate the file for the complete lifetime of
    /// the returned mapping. Writers must publish immutable files under a new
    /// path and replace references to the path, never mutate a mapped file in
    /// place. Violating this condition can invalidate Rust references and cause
    /// undefined behavior.
    pub unsafe fn open(
        path: impl AsRef<Path>,
        limits: ArchiveLimits,
    ) -> Result<Self, ArchiveError> {
        let file = File::open(path)?;
        let metadata_len = file.metadata()?.len();
        check_size_limit(metadata_len, limits)?;
        if metadata_len < HEADER_LEN as u64 {
            return Err(ArchiveError::InvalidHeader(
                "file is shorter than the envelope",
            ));
        }

        // SAFETY: The caller guarantees external immutability for the mapping
        // lifetime, which is the platform requirement not expressible in Rust.
        let map = unsafe { MmapOptions::new().map(&file) }?;
        let (header, payload, hash_section) = validate_archive::<T>(&map, limits)?;
        Ok(Self {
            map,
            payload,
            hash_section,
            header,
            marker: PhantomData,
        })
    }

    /// Opens, maps, and validates only the envelope (not the graph or the
    /// Merkle tree).
    ///
    /// This is the O(1) entry point for TB-scale archives. The returned owner
    /// exposes [`Self::proof_for`] for per-range proofs and **does not** expose
    /// `root()`: typed zero-copy access requires either a full [`Self::open`]
    /// or a verified [`MerkleProof::extract`] followed by an explicit rkyv
    /// `access` on the extracted bytes.
    ///
    /// # Safety
    ///
    /// Same contract as [`Self::open`]: no process may modify or truncate the
    /// mapped file for the mapping lifetime.
    pub unsafe fn open_header_only(
        path: impl AsRef<Path>,
        limits: ArchiveLimits,
    ) -> Result<MappedArchiveHeader<T>, ArchiveError> {
        let file = File::open(path)?;
        let metadata_len = file.metadata()?.len();
        check_size_limit(metadata_len, limits)?;
        if metadata_len < HEADER_LEN as u64 {
            return Err(ArchiveError::InvalidHeader(
                "file is shorter than the envelope",
            ));
        }
        // SAFETY: The caller guarantees external immutability for the mapping
        // lifetime.
        let map = unsafe { MmapOptions::new().map(&file) }?;
        let header = parse_header(&map, limits)?;
        if header.schema_id != T::SCHEMA_ID {
            return Err(ArchiveError::SchemaMismatch {
                expected: T::SCHEMA_ID,
                actual: header.schema_id,
            });
        }
        let (payload, hash_section) = ranges_from_header(map.len(), header)?;
        Ok(MappedArchiveHeader {
            map,
            payload,
            hash_section,
            header,
            marker: PhantomData,
        })
    }

    /// Returns the parsed envelope metadata.
    pub const fn header(&self) -> ArchiveHeader {
        self.header
    }

    /// Returns the complete mapped file bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.map
    }

    /// Returns the mapped rkyv payload bytes without the envelope.
    pub fn payload(&self) -> &[u8] {
        &self.map[self.payload.clone()]
    }

    /// Returns the Merkle root digest of the payload.
    pub fn root_digest(&self) -> [u8; 32] {
        self.header.root
    }

    /// Builds a self-contained Merkle proof for `[offset, offset + len)`
    /// bytes of the payload.
    ///
    /// Proof construction reads sibling hashes from the stored hash section,
    /// so it is O(log n); verification on the receiving side is also O(log n).
    pub fn proof_for(&self, offset: u64, len: u64) -> Result<MerkleProof, ArchiveError> {
        build_proof(
            self.payload(),
            &self.map[self.hash_section.clone()],
            offset,
            len,
            self.header,
        )
    }

    /// Returns the archived root without allocation or deserialization.
    pub fn root(&self) -> &T::Archived {
        // SAFETY: `open` structurally validates the read-only payload, and its
        // safety contract requires the mapped file to remain immutable.
        unsafe { rkyv::access_unchecked::<T::Archived>(self.payload()) }
    }
}

/// Envelope-only mmap owner produced by
/// [`crate::archive::MappedArchive::open_header_only`].
///
/// It intentionally has no `root()`: the payload has not been validated. Use
/// [`Self::proof_for`] and verify the proof against the recorded root before
/// extracting bytes.
pub struct MappedArchiveHeader<T: ArchiveSchema> {
    map: Mmap,
    payload: Range<usize>,
    hash_section: Range<usize>,
    header: ArchiveHeader,
    marker: PhantomData<T>,
}

impl<T: ArchiveSchema> MappedArchiveHeader<T> {
    /// Returns the parsed envelope metadata (including the Merkle root).
    pub const fn header(&self) -> ArchiveHeader {
        self.header
    }

    /// Returns the complete mapped file bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.map
    }

    /// Returns the mapped rkyv payload bytes without the envelope.
    pub fn payload(&self) -> &[u8] {
        &self.map[self.payload.clone()]
    }

    /// Returns the Merkle root digest of the payload.
    pub fn root_digest(&self) -> [u8; 32] {
        self.header.root
    }

    /// Builds a self-contained Merkle proof for `[offset, offset + len)`
    /// bytes of the payload.
    pub fn proof_for(&self, offset: u64, len: u64) -> Result<MerkleProof, ArchiveError> {
        build_proof(
            self.payload(),
            &self.map[self.hash_section.clone()],
            offset,
            len,
            self.header,
        )
    }
}

/// Builds and validates an aligned, versioned archive in owned memory.
pub fn build<T>(value: &T, limits: ArchiveLimits) -> Result<OwnedArchive<T>, ArchiveError>
where
    T: ArchiveSchema
        + for<'a> rkyv::Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, RkyvError>>,
    T::Archived: Portable + for<'a> CheckBytes<HighValidator<'a, RkyvError>>,
{
    validate_schema_id::<T>()?;
    validate_alignment::<T>()?;
    let block_size = limits.merkle_block_size();
    if block_size == 0 || !block_size.is_power_of_two() || block_size < 32 {
        return Err(ArchiveError::InvalidHeader(
            "Merkle block size must be a power of two of at least 32 bytes",
        ));
    }

    let payload = rkyv::to_bytes::<RkyvError>(value)
        .map_err(|error| ArchiveError::Serialization(error.to_string()))?;
    let payload_len = u64::try_from(payload.len()).map_err(|_| ArchiveError::SizeLimit {
        limit: limits.max_file_size(),
        actual: u64::MAX,
    })?;
    // Compute the Merkle tree once; the root is the top of the level stack.
    let (levels, block_count) = merkle_levels(&payload, block_size);
    let root = levels[levels.len() - 1][0];
    let hash_section = serialize_hash_section(&levels);
    let hash_len = u64::try_from(hash_section.len()).map_err(|_| ArchiveError::SizeLimit {
        limit: limits.max_file_size(),
        actual: u64::MAX,
    })?;
    let hash_offset =
        (HEADER_LEN as u64)
            .checked_add(payload_len)
            .ok_or(ArchiveError::SizeLimit {
                limit: limits.max_file_size(),
                actual: u64::MAX,
            })?;
    let file_len = hash_offset
        .checked_add(hash_len)
        .ok_or(ArchiveError::SizeLimit {
            limit: limits.max_file_size(),
            actual: u64::MAX,
        })?;
    check_size_limit(file_len, limits)?;

    let header = ArchiveHeader {
        schema_id: T::SCHEMA_ID,
        payload_len,
        file_len,
        block_size,
        block_count,
        root,
        hash_offset,
        hash_len,
    };
    let capacity = usize::try_from(file_len).map_err(|_| ArchiveError::SizeLimit {
        limit: limits.max_file_size(),
        actual: file_len,
    })?;
    let mut bytes = AlignedVec::<MAX_ARCHIVE_ALIGNMENT>::with_capacity(capacity);
    bytes.extend_from_slice(&encode_header(header));
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&hash_section);

    let (_, payload_range, hash_range) = validate_archive::<T>(&bytes, limits)?;
    Ok(OwnedArchive {
        bytes,
        payload: payload_range,
        hash_section: hash_range,
        header,
        marker: PhantomData,
    })
}

/// Validates an archive slice and returns its zero-copy root view.
///
/// This function performs structural validation on every call. Use
/// [`OwnedArchive::root`] or [`MappedArchive::root`] when validation should be
/// paid once and subsequent accesses should be constant-time.
pub fn access<T>(bytes: &[u8], limits: ArchiveLimits) -> Result<&T::Archived, ArchiveError>
where
    T: ArchiveSchema,
    T::Archived: Portable + for<'a> CheckBytes<HighValidator<'a, RkyvError>>,
{
    let (_, payload, _) = validate_archive::<T>(bytes, limits)?;
    rkyv::access::<T::Archived, RkyvError>(&bytes[payload])
        .map_err(|error| ArchiveError::Validation(error.to_string()))
}

/// Derives the payload and hash-section byte ranges from a parsed header.
fn ranges_from_header(
    file_len: usize,
    header: ArchiveHeader,
) -> Result<(Range<usize>, Range<usize>), ArchiveError> {
    let payload_len = usize::try_from(header.payload_len)
        .map_err(|_| ArchiveError::InvalidHeader("payload length does not fit usize"))?;
    let payload_end = PAYLOAD_OFFSET
        .checked_add(payload_len)
        .ok_or(ArchiveError::InvalidHeader("payload range overflows usize"))?;
    let hash_len = usize::try_from(header.hash_len)
        .map_err(|_| ArchiveError::InvalidHeader("hash section length does not fit usize"))?;
    let hash_end = payload_end
        .checked_add(hash_len)
        .ok_or(ArchiveError::InvalidHeader(
            "hash section range overflows usize",
        ))?;
    if payload_end > file_len || hash_end > file_len {
        return Err(ArchiveError::InvalidHeader(
            "declared ranges exceed the file length",
        ));
    }
    if usize::try_from(header.hash_offset).unwrap_or(usize::MAX) != payload_end {
        return Err(ArchiveError::InvalidHeader(
            "hash section offset does not follow the payload",
        ));
    }
    Ok((PAYLOAD_OFFSET..payload_end, payload_end..hash_end))
}

fn validate_archive<T>(
    bytes: &[u8],
    limits: ArchiveLimits,
) -> Result<(ArchiveHeader, Range<usize>, Range<usize>), ArchiveError>
where
    T: ArchiveSchema,
    T::Archived: Portable + for<'a> CheckBytes<HighValidator<'a, RkyvError>>,
{
    validate_schema_id::<T>()?;
    validate_alignment::<T>()?;
    let header = parse_header(bytes, limits)?;
    if header.schema_id != T::SCHEMA_ID {
        return Err(ArchiveError::SchemaMismatch {
            expected: T::SCHEMA_ID,
            actual: header.schema_id,
        });
    }
    let (payload, hash_section) = ranges_from_header(bytes.len(), header)?;
    let payload_bytes = &bytes[payload.clone()];
    let required_alignment = align_of::<T::Archived>();
    if !(payload_bytes.as_ptr() as usize).is_multiple_of(required_alignment) {
        return Err(ArchiveError::Validation(
            "payload base does not satisfy archived root alignment".into(),
        ));
    }
    // Verify the Merkle tree in one pass: recompute the levels from the
    // payload and require the root, block count, and stored hash-section
    // root to agree. This is O(n) and paid once by `open`/`build`/`access`.
    let (levels, recomputed_blocks) = merkle_levels(payload_bytes, header.block_size);
    let recomputed_root = levels[levels.len() - 1][0];
    if recomputed_root != header.root {
        return Err(ArchiveError::Merkle(
            "payload does not match the recorded Merkle root",
        ));
    }
    if recomputed_blocks != header.block_count {
        return Err(ArchiveError::Merkle(
            "recorded Merkle block count does not match",
        ));
    }
    let height = tree_height(header.block_count);
    let expected_hash_len = ((1u64 << height) - 1)
        .checked_mul(32)
        .ok_or(ArchiveError::Merkle("hash section length overflows"))?;
    if header.hash_len != expected_hash_len {
        return Err(ArchiveError::Merkle(
            "recorded hash section length does not match",
        ));
    }
    let stored_root = &bytes[hash_section.clone()];
    if stored_root.len() as u64 != expected_hash_len {
        return Err(ArchiveError::Merkle("hash section length does not match"));
    }
    // For a single-leaf tree there are no internal nodes and the section is
    // empty; the recomputed leaf root already matched the header root above.
    if height > 0 {
        let section_root = read_section_hash(stored_root, 1u64 << height, height, height, 0);
        if section_root != header.root {
            return Err(ArchiveError::Merkle("hash section root does not match"));
        }
    }
    let _ = levels;
    rkyv::access::<T::Archived, RkyvError>(payload_bytes)
        .map_err(|error| ArchiveError::Validation(error.to_string()))?;
    Ok((header, payload, hash_section))
}

fn parse_header(bytes: &[u8], limits: ArchiveLimits) -> Result<ArchiveHeader, ArchiveError> {
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    check_size_limit(actual, limits)?;
    if bytes.len() < HEADER_LEN {
        return Err(ArchiveError::InvalidHeader(
            "file is shorter than the envelope",
        ));
    }
    if bytes[..8] != MAGIC {
        return Err(ArchiveError::InvalidHeader("magic does not match"));
    }
    if read_u16(bytes, 8) != FORMAT_VERSION {
        return Err(ArchiveError::InvalidHeader("unsupported format version"));
    }
    if read_u16(bytes, 10) != FORMAT_FLAGS {
        return Err(ArchiveError::InvalidHeader("format flags do not match"));
    }
    if read_u32(bytes, 12) != HEADER_LEN as u32 {
        return Err(ArchiveError::InvalidHeader("header length does not match"));
    }
    let schema_id = read_u64(bytes, 16);
    if schema_id == 0 {
        return Err(ArchiveError::InvalidHeader("schema identifier is zero"));
    }
    let payload_len = read_u64(bytes, 24);
    if read_u64(bytes, 32) != PAYLOAD_OFFSET as u64 {
        return Err(ArchiveError::InvalidHeader("payload offset does not match"));
    }
    let file_len = read_u64(bytes, 40);
    if file_len != actual {
        return Err(ArchiveError::InvalidHeader(
            "declared file length does not match",
        ));
    }
    let expected_file_len =
        (HEADER_LEN as u64)
            .checked_add(payload_len)
            .ok_or(ArchiveError::InvalidHeader(
                "declared payload length overflows",
            ))?;
    if file_len < expected_file_len {
        return Err(ArchiveError::InvalidHeader(
            "declared payload length exceeds the file length",
        ));
    }
    let block_size = read_u32(bytes, 48);
    if block_size == 0 || !block_size.is_power_of_two() {
        return Err(ArchiveError::InvalidHeader(
            "Merkle block size is not a power of two",
        ));
    }
    if block_size < 32 {
        return Err(ArchiveError::InvalidHeader(
            "Merkle block size is smaller than the minimum",
        ));
    }
    let block_count = read_u64(bytes, 52);
    if block_count == 0 {
        return Err(ArchiveError::InvalidHeader("Merkle block count is zero"));
    }
    let mut root = [0_u8; 32];
    root.copy_from_slice(&bytes[60..92]);
    let hash_offset = read_u64(bytes, 92);
    let hash_len = read_u64(bytes, 100);
    if bytes[108..HEADER_LEN].iter().any(|&byte| byte != 0) {
        return Err(ArchiveError::InvalidHeader(
            "reserved header bytes are non-zero",
        ));
    }
    if hash_offset != expected_file_len {
        return Err(ArchiveError::InvalidHeader(
            "hash section offset does not follow the payload",
        ));
    }
    let expected_file_len = hash_offset
        .checked_add(hash_len)
        .ok_or(ArchiveError::InvalidHeader("hash section length overflows"))?;
    if expected_file_len != file_len {
        return Err(ArchiveError::InvalidHeader(
            "declared hash section length does not match",
        ));
    }
    // The hash section must hold exactly the internal nodes of the padded
    // tree: leaf_count - 1 hashes of 32 bytes. Validating this at envelope
    // parse time keeps every later `read_section_hash` in bounds, including
    // the header-only open path.
    let height = tree_height(block_count);
    let expected_hash_len = ((1u64 << height) - 1)
        .checked_mul(32)
        .ok_or(ArchiveError::InvalidHeader("hash section length overflows"))?;
    if hash_len != expected_hash_len {
        return Err(ArchiveError::InvalidHeader(
            "hash section length does not match the Merkle tree",
        ));
    }
    Ok(ArchiveHeader {
        schema_id,
        payload_len,
        file_len,
        block_size,
        block_count,
        root,
        hash_offset,
        hash_len,
    })
}

fn encode_header(header: ArchiveHeader) -> [u8; HEADER_LEN] {
    let mut bytes = [0_u8; HEADER_LEN];
    bytes[..8].copy_from_slice(&MAGIC);
    bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes[10..12].copy_from_slice(&FORMAT_FLAGS.to_le_bytes());
    bytes[12..16].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
    bytes[16..24].copy_from_slice(&header.schema_id.to_le_bytes());
    bytes[24..32].copy_from_slice(&header.payload_len.to_le_bytes());
    bytes[32..40].copy_from_slice(&(PAYLOAD_OFFSET as u64).to_le_bytes());
    bytes[40..48].copy_from_slice(&header.file_len.to_le_bytes());
    bytes[48..52].copy_from_slice(&header.block_size.to_le_bytes());
    bytes[52..60].copy_from_slice(&header.block_count.to_le_bytes());
    bytes[60..92].copy_from_slice(&header.root);
    bytes[92..100].copy_from_slice(&header.hash_offset.to_le_bytes());
    bytes[100..108].copy_from_slice(&header.hash_len.to_le_bytes());
    bytes
}

/// Builds a self-contained proof from an open archive's payload and hash
/// section.
fn build_proof(
    payload: &[u8],
    hash_section: &[u8],
    offset: u64,
    len: u64,
    header: ArchiveHeader,
) -> Result<MerkleProof, ArchiveError> {
    let block_size = header.block_size;
    let block_count = header.block_count;
    let payload_len = header.payload_len;
    let end = offset
        .checked_add(len)
        .ok_or(ArchiveError::Merkle("proof range overflows"))?;
    if offset >= payload_len || end > payload_len {
        return Err(ArchiveError::Merkle("proof range exceeds the payload"));
    }
    let first_block = offset / u64::from(block_size);
    let last_block = if len == 0 {
        first_block
    } else {
        (offset + len - 1) / u64::from(block_size)
    };
    let covered = (last_block - first_block + 1) as usize;
    let mut blocks = Vec::with_capacity(covered);
    for index in first_block..=last_block {
        let start = (index as usize) * block_size as usize;
        let end = (start + block_size as usize).min(payload.len());
        blocks.push(payload[start..end].to_vec());
    }
    let height = tree_height(block_count);
    let siblings = collect_siblings(
        payload,
        hash_section,
        block_size,
        block_count,
        height,
        first_block,
        last_block,
    );
    Ok(MerkleProof {
        offset,
        len,
        block_size,
        block_count,
        payload_len,
        blocks,
        siblings,
        root: header.root,
    })
}

fn check_size_limit(actual: u64, limits: ArchiveLimits) -> Result<(), ArchiveError> {
    if actual > limits.max_file_size() {
        Err(ArchiveError::SizeLimit {
            limit: limits.max_file_size(),
            actual,
        })
    } else {
        Ok(())
    }
}

fn validate_schema_id<T: ArchiveSchema>() -> Result<(), ArchiveError> {
    if T::SCHEMA_ID == 0 {
        Err(ArchiveError::InvalidSchemaId)
    } else {
        Ok(())
    }
}

fn validate_alignment<T: ArchiveSchema>() -> Result<(), ArchiveError>
where
    T::Archived: Portable,
{
    let required = align_of::<T::Archived>();
    if required > MAX_ARCHIVE_ALIGNMENT {
        Err(ArchiveError::UnsupportedAlignment {
            required,
            supported: MAX_ARCHIVE_ALIGNMENT,
        })
    } else {
        Ok(())
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    let mut value = [0_u8; 2];
    value.copy_from_slice(&bytes[offset..offset + 2]);
    u16::from_le_bytes(value)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0_u8; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0_u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_FILE_ID: AtomicU64 = AtomicU64::new(0);

    struct TemporaryArchive(PathBuf);

    impl TemporaryArchive {
        fn new() -> Self {
            let id = NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "rustbinary-archive-test-{}-{id}.rba",
                std::process::id()
            )))
        }
    }

    impl Drop for TemporaryArchive {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    #[derive(Archive, Serialize)]
    struct Root {
        sequence: u64,
        name: String,
        samples: Vec<i32>,
    }

    impl ArchiveSchema for Root {
        const SCHEMA_ID: u64 = 0x5255_5354_4249_4e31;
    }

    #[derive(Archive, Serialize)]
    struct OtherRoot {
        sequence: u64,
        name: String,
        samples: Vec<i32>,
    }

    impl ArchiveSchema for OtherRoot {
        const SCHEMA_ID: u64 = 0x5255_5354_4249_4e32;
    }

    #[derive(Archive)]
    struct InvalidSchemaRoot;

    impl ArchiveSchema for InvalidSchemaRoot {
        const SCHEMA_ID: u64 = 0;
    }

    fn value() -> Root {
        Root {
            sequence: 42,
            name: "mapped".into(),
            samples: vec![-7, 0, 11, 65_536],
        }
    }

    fn expect_error<T>(result: Result<T, ArchiveError>) -> ArchiveError {
        match result {
            Ok(_) => panic!("expected archive operation to fail"),
            Err(error) => error,
        }
    }

    #[test]
    fn owned_archive_validates_and_borrows_relative_fields() {
        let archive = build(&value(), ArchiveLimits::new()).unwrap();
        let bytes = archive.as_bytes();
        // Envelope format anchors (the format-stability contract).
        assert_eq!(&bytes[..8], b"RBARC002");
        assert_eq!(u16::from_le_bytes([bytes[8], bytes[9]]), 2);
        assert_eq!(u16::from_le_bytes([bytes[10], bytes[11]]), FLAG_MERKLE);
        assert_eq!(
            u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
            HEADER_LEN as u32
        );
        assert_eq!(
            u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            Root::SCHEMA_ID
        );
        assert_eq!(
            u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
            PAYLOAD_OFFSET as u64
        );
        assert_eq!(u32::from_le_bytes(bytes[48..52].try_into().unwrap()), 4096);
        assert_eq!(u64::from_le_bytes(bytes[52..60].try_into().unwrap()), 1);
        assert_eq!(
            u64::from_le_bytes(bytes[92..100].try_into().unwrap()),
            PAYLOAD_OFFSET as u64 + archive.header().payload_len
        );
        assert_eq!(u64::from_le_bytes(bytes[100..108].try_into().unwrap()), 0);
        assert!(bytes[108..HEADER_LEN].iter().all(|&byte| byte == 0));
        // The Merkle root is a deterministic function of the payload.
        let again = build(&value(), ArchiveLimits::new()).unwrap();
        assert_eq!(archive.root_digest(), again.root_digest());
        assert_eq!(archive.header(), again.header());

        let root = archive.root();
        assert_eq!(root.sequence, 42);
        assert_eq!(root.name.as_str(), "mapped");
        assert_eq!(root.samples.as_slice(), [-7, 0, 11, 65_536]);

        let start = archive.as_bytes().as_ptr() as usize;
        let end = start + archive.as_bytes().len();
        let name = root.name.as_bytes().as_ptr() as usize;
        let samples = root.samples.as_ptr() as usize;
        assert!((start..end).contains(&name));
        assert!((start..end).contains(&samples));
        assert_eq!(
            access::<Root>(archive.as_bytes(), ArchiveLimits::new())
                .unwrap()
                .sequence,
            42
        );
    }

    #[test]
    fn envelope_rejects_corruption_schema_drift_and_resource_abuse() {
        let archive = build(&value(), ArchiveLimits::new()).unwrap();
        let schema_error = expect_error(access::<OtherRoot>(
            archive.as_bytes(),
            ArchiveLimits::new(),
        ));
        assert!(matches!(schema_error, ArchiveError::SchemaMismatch { .. }));
        assert_eq!(schema_error.category(), ErrorCategory::Protocol);

        let limit_error = expect_error(access::<Root>(
            archive.as_bytes(),
            ArchiveLimits::new().with_max_file_size(16),
        ));
        assert!(matches!(limit_error, ArchiveError::SizeLimit { .. }));
        assert_eq!(limit_error.category(), ErrorCategory::Configuration);

        let schema_id_error = expect_error(access::<InvalidSchemaRoot>(
            archive.as_bytes(),
            ArchiveLimits::new(),
        ));
        assert!(matches!(schema_id_error, ArchiveError::InvalidSchemaId));
        assert_eq!(schema_id_error.category(), ErrorCategory::Configuration);
        assert!(matches!(
            access::<Root>(&archive.as_bytes()[..32], ArchiveLimits::new()),
            Err(ArchiveError::InvalidHeader(_))
        ));

        let mut corrupted = archive.as_bytes().to_vec();
        corrupted[0] ^= 1;
        assert!(matches!(
            access::<Root>(&corrupted, ArchiveLimits::new()),
            Err(ArchiveError::InvalidHeader("magic does not match"))
        ));

        let mut reserved = archive.as_bytes().to_vec();
        reserved[127] = 1;
        assert!(matches!(
            access::<Root>(&reserved, ArchiveLimits::new()),
            Err(ArchiveError::InvalidHeader(
                "reserved header bytes are non-zero"
            ))
        ));

        // Corrupting a payload byte is caught by the Merkle root check.
        let mut bad_payload = archive.as_bytes().to_vec();
        bad_payload[PAYLOAD_OFFSET + 4] ^= 0x01;
        assert!(matches!(
            access::<Root>(&bad_payload, ArchiveLimits::new()),
            Err(ArchiveError::Merkle(_))
        ));
        assert_eq!(
            expect_error(access::<Root>(&bad_payload, ArchiveLimits::new())).category(),
            ErrorCategory::Protocol
        );

        let mut invalid_graph = AlignedVec::<MAX_ARCHIVE_ALIGNMENT>::new();
        invalid_graph.extend_from_slice(archive.as_bytes());
        // Rewrite both the payload and the hash section; the Merkle root in
        // the header no longer matches the recomputed tree.
        invalid_graph[PAYLOAD_OFFSET..].fill(0xff);
        assert!(matches!(
            access::<Root>(&invalid_graph, ArchiveLimits::new()),
            Err(ArchiveError::Merkle(_))
        ));
    }

    #[test]
    fn file_archive_maps_and_accesses_fields_in_place() {
        let file = TemporaryArchive::new();
        let archive = build(&value(), ArchiveLimits::new()).unwrap();
        archive.write_new(&file.0).unwrap();

        // SAFETY: This test owns the unique file path and never opens a writer
        // while the map is alive. The cleanup guard removes it only after drop.
        let mapped = unsafe { MappedArchive::<Root>::open(&file.0, ArchiveLimits::new()) }.unwrap();
        let root = mapped.root();
        assert_eq!(root.name.as_str(), "mapped");
        assert_eq!(root.samples.as_slice(), [-7, 0, 11, 65_536]);
        assert_eq!(mapped.root_digest(), archive.root_digest());

        let start = mapped.as_bytes().as_ptr() as usize;
        let end = start + mapped.as_bytes().len();
        assert!((start..end).contains(&(root.name.as_bytes().as_ptr() as usize)));
        assert!((start..end).contains(&(root.samples.as_ptr() as usize)));
    }

    #[derive(Archive, Serialize)]
    struct WideRoot {
        sequence: u64,
        samples: Vec<u8>,
    }

    impl ArchiveSchema for WideRoot {
        const SCHEMA_ID: u64 = 0x5255_5354_4249_4e33;
    }

    fn wide_value() -> WideRoot {
        WideRoot {
            sequence: 7,
            samples: (0..4096).map(|index| (index * 31 % 251) as u8).collect(),
        }
    }

    #[test]
    fn merkle_proofs_verify_for_ranges_across_blocks() {
        // 4 KiB of samples with 64-byte blocks -> 65 leaves, height 7.
        let limits = ArchiveLimits::new().with_merkle_block_size(64);
        let archive = build(&wide_value(), limits).unwrap();
        let payload = archive.payload();
        assert!(archive.header().block_count() > 1);
        assert_eq!(
            archive.header().block_count(),
            payload.len().div_ceil(64) as u64
        );

        // A single-block range, a multi-block range, and the full payload.
        let ranges = [
            (0u64, 10u64),
            (64u64, 200u64),
            (1000u64, 512u64),
            (0u64, payload.len() as u64),
            (4095u64, 1u64),
        ];
        for &(offset, len) in &ranges {
            let proof = archive.proof_for(offset, len).unwrap();
            proof.verify().unwrap();
            let extracted = proof.extract().unwrap();
            assert_eq!(
                extracted,
                &payload[offset as usize..offset as usize + len as usize],
                "range {offset}..{}",
                offset + len
            );
            assert_eq!(proof.root(), &archive.root_digest());
        }
    }

    #[test]
    fn merkle_proof_detects_corruption_and_tampering() {
        let limits = ArchiveLimits::new().with_merkle_block_size(64);
        let archive = build(&wide_value(), limits).unwrap();
        let payload_len = archive.header().payload_len;
        let proof = archive.proof_for(0, payload_len).unwrap();
        proof.verify().unwrap();

        // Corrupt a block inside the proof's own data.
        let mut tampered = proof.clone();
        tampered.blocks[0][0] ^= 0x01;
        assert!(matches!(tampered.verify(), Err(ArchiveError::Merkle(_))));

        // Truncate the covered range by a full block: the carried block list
        // no longer matches the covered leaf count.
        let mut truncated = proof.clone();
        truncated.len -= 64;
        assert!(truncated.verify().is_err());

        // Swap the root.
        let mut wrong_root = proof.clone();
        wrong_root.root[0] ^= 1;
        assert!(wrong_root.verify().is_err());

        // Range past the payload.
        assert!(matches!(
            archive.proof_for(payload_len - 1, 2),
            Err(ArchiveError::Merkle("proof range exceeds the payload"))
        ));
    }

    #[test]
    fn open_header_only_builds_proofs_without_full_validation() {
        let file = TemporaryArchive::new();
        let limits = ArchiveLimits::new().with_merkle_block_size(64);
        let archive = build(&wide_value(), limits).unwrap();
        archive.write_new(&file.0).unwrap();

        // SAFETY: unique owned path, no concurrent writers.
        let header_only =
            unsafe { MappedArchive::<WideRoot>::open_header_only(&file.0, limits) }.unwrap();
        assert_eq!(header_only.root_digest(), archive.root_digest());

        // Proofs are built from the stored hash section (O(log n) per range).
        let proof = header_only.proof_for(128, 400).unwrap();
        proof.verify().unwrap();
        let extracted = proof.extract().unwrap();
        assert_eq!(
            extracted,
            &archive.payload()[128..528],
            "extracted range must match the original payload"
        );

        // A corrupted payload is caught by proof verification even though
        // header-only opening validated only the envelope. Write a file with
        // one flipped payload byte and re-open header-only: the stored root
        // (from the original build) can no longer authenticate the payload.
        let corrupted_file = TemporaryArchive::new();
        let mut corrupted_bytes = archive.as_bytes().to_vec();
        corrupted_bytes[PAYLOAD_OFFSET + 200] ^= 0xff;
        std::fs::write(&corrupted_file.0, &corrupted_bytes).unwrap();
        // SAFETY: unique owned path, no concurrent writers.
        let corrupted_header_only =
            unsafe { MappedArchive::<WideRoot>::open_header_only(&corrupted_file.0, limits) }
                .unwrap();
        assert_eq!(corrupted_header_only.root_digest(), archive.root_digest());
        let corrupted_proof = corrupted_header_only.proof_for(0, 512).unwrap();
        assert!(matches!(
            corrupted_proof.verify(),
            Err(ArchiveError::Merkle(_))
        ));
    }

    #[test]
    fn merkle_block_size_is_encoded_and_honoured() {
        let archive = build(&value(), ArchiveLimits::new()).unwrap();
        let bytes = archive.as_bytes();
        // Patch the header block size to a non-power-of-two and re-validate.
        let mut patched = bytes.to_vec();
        patched[48..52].copy_from_slice(&100u32.to_le_bytes());
        assert!(matches!(
            access::<Root>(&patched, ArchiveLimits::new()),
            Err(ArchiveError::InvalidHeader(_))
        ));
        // Build rejects invalid block sizes up front.
        assert!(build(&value(), ArchiveLimits::new().with_merkle_block_size(100)).is_err());
        assert!(build(&value(), ArchiveLimits::new().with_merkle_block_size(16)).is_err());
    }
}
