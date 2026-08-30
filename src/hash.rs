//! BLAKE3 hash — a from-scratch implementation of the BLAKE3 algorithm
//! (draft-irtf-cfrg-blake3).
//!
//! This crate ships no third-party dependencies, so the archive Merkle tree
//! and the projection proofs hash with this in-tree implementation. The
//! implementation follows the published reference algorithm: BLAKE2s-style
//! 7-round compression, 1024-byte chunks, a lazy left-balanced binary tree,
//! and domain-separated chaining values. It is `no_std` + `alloc` and
//! byte-for-byte compatible with the official `blake3` crate (verified below
//! against the published test vectors).
//!
//! ## Security posture
//!
//! This is a correctness-focused implementation of a published, formally
//! analyzed hash function. It has not been through an independent
//! implementation-level security audit and does not claim constant-time
//! behavior (BLAKE3 is not secret-dependent in the ways that matter here:
//! the archive hashes public payload bytes). The tree geometry and domain
//! separation are owned by the calling module, not by this primitive.

use alloc::vec::Vec;
use core::cmp;

/// BLAKE3 initial state (same IV as BLAKE2s).
const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

/// Number of bytes per chunk (leaf subtree).
const CHUNK_LEN: usize = 1024;
/// Number of bytes per compression block.
const BLOCK_LEN: usize = 64;
/// Digest length in bytes.
const OUT_LEN: usize = 32;

/// Flag: this block is the first block of a chunk.
const CHUNK_START: u32 = 1 << 0;
/// Flag: this block is the last block of a chunk.
const CHUNK_END: u32 = 1 << 1;
/// Flag: this compression operates on a parent (tree) block.
const PARENT: u32 = 1 << 2;
/// Flag: this is the root compression of the tree.
const ROOT: u32 = 1 << 3;

/// BLAKE3 message schedule: the fixed 16-word permutation applied between
/// rounds.
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// The BLAKE3 mixing function `G`.
#[inline(always)]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

/// One BLAKE3 round: column step followed by diagonal step.
#[inline(always)]
fn round(state: &mut [u32; 16], message: &[u32; 16]) {
    g(state, 0, 4, 8, 12, message[0], message[1]);
    g(state, 1, 5, 9, 13, message[2], message[3]);
    g(state, 2, 6, 10, 14, message[4], message[5]);
    g(state, 3, 7, 11, 15, message[6], message[7]);
    g(state, 0, 5, 10, 15, message[8], message[9]);
    g(state, 1, 6, 11, 12, message[10], message[11]);
    g(state, 2, 7, 8, 13, message[12], message[13]);
    g(state, 3, 4, 9, 14, message[14], message[15]);
}

/// Permutes a 16-word message block using the BLAKE3 schedule.
#[inline(always)]
fn permute(message: &mut [u32; 16]) {
    let mut permuted = [0_u32; 16];
    for (i, &index) in MSG_PERMUTATION.iter().enumerate() {
        permuted[i] = message[index];
    }
    *message = permuted;
}

/// The BLAKE3 compression function.
///
/// Returns the full 16-word output. The first 8 words form the chaining
/// value; the full output is used for extended (XOF) root output.
fn compress(
    chaining_value: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let counter_low = counter as u32;
    let counter_high = (counter >> 32) as u32;
    #[rustfmt::skip]
    let mut state = [
        chaining_value[0], chaining_value[1], chaining_value[2], chaining_value[3],
        chaining_value[4], chaining_value[5], chaining_value[6], chaining_value[7],
        IV[0], IV[1], IV[2], IV[3],
        counter_low, counter_high, block_len, flags,
    ];
    let mut block = *block_words;

    round(&mut state, &block); // round 1
    permute(&mut block);
    round(&mut state, &block); // round 2
    permute(&mut block);
    round(&mut state, &block); // round 3
    permute(&mut block);
    round(&mut state, &block); // round 4
    permute(&mut block);
    round(&mut state, &block); // round 5
    permute(&mut block);
    round(&mut state, &block); // round 6
    permute(&mut block);
    round(&mut state, &block); // round 7

    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= chaining_value[i];
    }
    state
}

/// Reads a little-endian `u32` word from a byte slice.
#[inline(always)]
fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Converts a byte slice to 16 little-endian words (padded with zeros).
fn words_from_bytes(bytes: &[u8]) -> [u32; 16] {
    let mut words = [0_u32; 16];
    for (i, word) in words.iter_mut().enumerate() {
        let offset = 4 * i;
        if offset + 4 <= bytes.len() {
            *word = read_u32_le(bytes, offset);
        } else {
            let mut tail = [0_u8; 4];
            let copy = bytes.len() - offset;
            tail[..copy].copy_from_slice(&bytes[offset..]);
            *word = u32::from_le_bytes(tail);
        }
    }
    words
}

/// Captures the state just prior to choosing between a chaining value and a
/// root digest, exactly as in the BLAKE3 reference implementation.
#[derive(Clone, Copy)]
struct Output {
    input_chaining_value: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    /// The 8-word chaining value of this node (compression without `ROOT`).
    fn chaining_value(&self) -> [u32; 8] {
        let output = compress(
            &self.input_chaining_value,
            &self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        );
        output[0..8].try_into().expect("8-word chaining value")
    }

    /// The 32-byte digest of this node (compression with `ROOT`).
    fn root_hash(&self) -> [u8; 32] {
        debug_assert_eq!(self.counter, 0);
        let output = compress(
            &self.input_chaining_value,
            &self.block_words,
            0,
            self.block_len,
            self.flags | ROOT,
        );
        let mut hash = [0_u8; OUT_LEN];
        for (i, word) in output[0..8].iter().enumerate() {
            hash[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
        }
        hash
    }
}

/// A parent node output: `left_cv || right_cv` with `PARENT` semantics.
fn parent_output(left_child_cv: [u32; 8], right_child_cv: [u32; 8]) -> Output {
    let mut block_words = [0_u32; 16];
    block_words[..8].copy_from_slice(&left_child_cv);
    block_words[8..].copy_from_slice(&right_child_cv);
    Output {
        input_chaining_value: IV,
        block_words,
        counter: 0,                  // Always 0 for parent nodes.
        block_len: BLOCK_LEN as u32, // Always BLOCK_LEN (64) for parent nodes.
        flags: PARENT,
    }
}

/// State for the chunk currently being absorbed.
struct ChunkState {
    /// Chaining value accumulated from already-compressed blocks.
    chaining_value: [u32; 8],
    /// Index of this chunk in the input stream.
    chunk_counter: u64,
    /// Buffered bytes of the current block (at most [`BLOCK_LEN`]).
    block: [u8; BLOCK_LEN],
    /// Number of buffered bytes.
    block_len: u8,
    /// Number of full blocks already compressed into `chaining_value`.
    blocks_compressed: u8,
}

impl ChunkState {
    fn new(chunk_counter: u64) -> Self {
        Self {
            chaining_value: IV,
            chunk_counter,
            block: [0; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
        }
    }

    /// Total number of input bytes absorbed by this chunk so far.
    fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed as usize + self.block_len as usize
    }

    /// `CHUNK_START` is set only on the first block of the chunk.
    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    /// Absorbs input bytes, compressing full blocks as they arrive.
    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            // The block buffer is full: compress it into the chaining value.
            if self.block_len as usize == BLOCK_LEN {
                let block_words = words_from_bytes(&self.block);
                self.chaining_value = compress(
                    &self.chaining_value,
                    &block_words,
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    self.start_flag(),
                )[0..8]
                    .try_into()
                    .expect("8-word chaining value");
                self.blocks_compressed += 1;
                self.block = [0; BLOCK_LEN];
                self.block_len = 0;
            }
            let want = BLOCK_LEN - self.block_len as usize;
            let take = cmp::min(want, input.len());
            self.block[self.block_len as usize..][..take].copy_from_slice(&input[..take]);
            self.block_len += take as u8;
            input = &input[take..];
        }
    }

    /// The `Output` of this chunk: compress the final block with `CHUNK_END`.
    fn output(&self) -> Output {
        let block_words = words_from_bytes(&self.block);
        Output {
            input_chaining_value: self.chaining_value,
            block_words,
            counter: self.chunk_counter,
            block_len: self.block_len as u32,
            flags: self.start_flag() | CHUNK_END,
        }
    }
}

/// Streaming BLAKE3 hasher.
pub struct Hasher {
    chunk_state: ChunkState,
    /// Stack of completed subtree chaining values (left to right).
    cv_stack: Vec<[u32; 8]>,
}

impl Hasher {
    /// Creates a fresh hasher in the standard (unkeyed) mode.
    pub fn new() -> Self {
        Self {
            chunk_state: ChunkState::new(0),
            cv_stack: Vec::new(),
        }
    }

    /// Absorbs `input` into the hash.
    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            // The current chunk is full: finalize it, merge into the tree, and
            // start the next chunk.
            if self.chunk_state.len() == CHUNK_LEN {
                let chunk_cv = self.chunk_state.output().chaining_value();
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.add_chunk_chaining_value(chunk_cv, total_chunks);
                self.chunk_state = ChunkState::new(total_chunks);
            }
            let want = CHUNK_LEN - self.chunk_state.len();
            let take = cmp::min(want, input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
    }

    /// Merges a completed chunk's chaining value into the lazy left-balanced
    /// tree. `total_chunks` is the count of chunks finalized so far.
    fn add_chunk_chaining_value(&mut self, mut new_cv: [u32; 8], mut total_chunks: u64) {
        // While the total chunk count is even, the new CV pairs with the most
        // recent subtree root; merge them and continue up the tree.
        while total_chunks & 1 == 0 {
            let left = self.cv_stack.pop().expect("BLAKE3 tree stack underflow");
            new_cv = parent_output(left, new_cv).chaining_value();
            total_chunks >>= 1;
        }
        self.cv_stack.push(new_cv);
    }

    /// Finalizes the hash and returns the 32-byte digest.
    pub fn finalize(&self) -> [u8; 32] {
        // Start with the current chunk's Output, then merge up the right edge
        // of the tree through every completed subtree on the stack (from the
        // top of the stack, i.e. the newest subtree, down to the root).
        let mut output = self.chunk_state.output();
        let mut remaining = self.cv_stack.len();
        while remaining > 0 {
            remaining -= 1;
            output = parent_output(self.cv_stack[remaining], output.chaining_value());
        }
        output.root_hash()
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot BLAKE3 digest of `input`.
///
/// This is the single hash entry point used by the archive Merkle tree and
/// the projection proofs.
pub fn blake3(input: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(input);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Converts a hex string to bytes (test helper).
    fn hex(encoded: &str) -> Vec<u8> {
        (0..encoded.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    #[test]
    fn official_empty_vector() {
        assert_eq!(
            blake3(b""),
            hex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")[..]
        );
    }

    #[test]
    fn official_abc_vector() {
        assert_eq!(
            blake3(b"abc"),
            hex("6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")[..]
        );
    }

    #[test]
    fn official_digits_vector() {
        assert_eq!(
            blake3(b"0123456789"),
            hex("53b63a6fc8605d0c0ce559317a00177d72adb24d669235e4c914f443a8831ca1")[..]
        );
    }

    #[test]
    fn chunk_boundary_single_chunk() {
        // Exactly CHUNK_LEN bytes: a single chunk, no parent nodes.
        let input = [0x00_u8; CHUNK_LEN];
        assert_eq!(
            blake3(&input),
            hex("d6fd9de5bccf223f523b316c9cd1cf9a9d87ea42473d68e011dad13f09bf8917")[..]
        );
    }

    #[test]
    fn chunk_boundary_two_chunks() {
        // Exactly 2 * CHUNK_LEN bytes: two chunks joined by one parent.
        let input = [0x00_u8; 2 * CHUNK_LEN];
        assert_eq!(
            blake3(&input),
            hex("be2a8de3dcf46c94ce85cdc8e07ac308f4d8a95490d956c38d780fd610db0813")[..]
        );
    }

    #[test]
    fn chunk_boundary_two_chunks_plus_one() {
        // 2 * CHUNK_LEN + 1: crosses into a third, partial chunk.
        let mut input = vec![0x00_u8; 2 * CHUNK_LEN + 1];
        input[2 * CHUNK_LEN] = 0x01;
        assert_eq!(
            blake3(&input),
            hex("e37332cc463623e4b297369aedab253ae49258e09b43c8443914180aba3a7aea")[..]
        );
    }

    #[test]
    fn official_fox_vector() {
        assert_eq!(
            blake3(b"The quick brown fox jumps over the lazy dog"),
            hex("2f1514181aadccd913abd94cfa592701a5686ab23f8df1dff1b74710febc6d4a")[..]
        );
    }

    #[test]
    fn hasher_matches_one_shot() {
        let input = b"The quick brown fox jumps over the lazy dog";
        let mut hasher = Hasher::new();
        // Feed in awkward chunk sizes to exercise block buffering.
        hasher.update(&input[..7]);
        hasher.update(&input[7..31]);
        hasher.update(&input[31..]);
        assert_eq!(hasher.finalize(), blake3(input));
    }

    #[test]
    fn hasher_streams_across_chunk_boundaries() {
        let input = vec![0xAB_u8; 3000];
        let mut hasher = Hasher::new();
        hasher.update(&input[..1000]);
        hasher.update(&input[1000..2048]);
        hasher.update(&input[2048..]);
        assert_eq!(hasher.finalize(), blake3(&input));

        let mut longer = input.clone();
        longer.extend_from_slice(&[0xFF; 64]);
        assert_ne!(blake3(&input), blake3(&longer));
    }
}
