//! Dependency-free BLAKE3 (draft-irtf-cfrg-blake3) used by the archive Merkle
//! tree.
//!
//! This module exists because the crate's constraint is to avoid third-party
//! hashing dependencies, and the archive feature needs a cryptographic hash
//! for its Merkle root. It is an **internal implementation detail**, not a
//! product feature: the codebase does not treat "we wrote BLAKE3 ourselves"
//! as a selling point.
//!
//! Read this before relying on it in a security-sensitive deployment:
//!
//! - Passing the official BLAKE3 test vectors is a *necessary* correctness
//!   check, not an implementation-level audit. The unit tests cover the
//!   published digest for many lengths (single block, chunk boundary, and
//!   multi-chunk trees), but this module has not been through a formal
//!   side-channel or implementation review.
//! - It is an **integrity** hash, not a MAC and not authentication. The
//!   archive Merkle root detects accidental corruption; it does not prove
//!   authorship. Anyone who can rewrite the archive can rewrite the root.
//! - If your threat model requires a fully audited BLAKE3, replace this
//!   module's `blake3` function with a vetted crate (the callers only depend
//!   on `blake3(&[u8]) -> [u8; 32]`). The archive layout itself is unchanged
//!   by that swap.

/// BLAKE3 initial state (identical to BLAKE2s).
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// BLAKE3 compression flags.
const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;

const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

/// Message word schedule: the permutation applied before each round
/// (BLAKE3 spec, fixed seven-round schedule).
const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

/// Computes the BLAKE3 digest of `input` (32 bytes, unkeyed, default 1024-byte
/// chunks).
pub(crate) fn blake3(input: &[u8]) -> [u8; 32] {
    if input.is_empty() {
        // A single empty chunk: compress the zero block as both the first and
        // last block of the (root) chunk.
        return words_to_bytes32(&compress(
            &IV,
            &[0; 16],
            0,
            0,
            CHUNK_START | CHUNK_END | ROOT,
        ));
    }
    let chunks: Vec<&[u8]> = input.chunks(CHUNK_LEN).collect();
    if chunks.len() == 1 {
        // The only chunk is the root: its last block is compressed with ROOT.
        return chunk_output(0, chunks[0]).root_bytes();
    }
    // Complete chunks enter the lazy-merge CV stack; a trailing partial chunk
    // stays in the "current chunk" slot and is merged last (it is the
    // rightmost leaf). Mirror of the reference implementation: each stack CV
    // covers a power-of-two number of chunks, kept smaller-above-larger, and
    // the number of CVs that must remain after the merge is the popcount of
    // the chunk counter.
    let full_count = if input.len().is_multiple_of(CHUNK_LEN) {
        chunks.len()
    } else {
        chunks.len() - 1
    };
    let mut stack: Vec<[u8; 32]> = Vec::with_capacity(full_count.ilog2() as usize + 1);
    for (index, chunk) in chunks[..full_count].iter().enumerate() {
        let post_merge_len = (index as u64).count_ones() as usize;
        while stack.len() > post_merge_len {
            let right = stack.pop().unwrap();
            let left = stack.pop().unwrap();
            stack.push(parent_cv(&left, &right));
        }
        stack.push(chunk_output(index as u64, chunk).cv);
    }
    // Finalize: merge the stack into one root. All merges except the final
    // one are plain parents; the final merge carries PARENT | ROOT.
    let mut output;
    if full_count == chunks.len() {
        // No trailing partial chunk: the stack's top two CVs start the merge.
        let mut num_remaining = stack.len();
        let left = stack[num_remaining - 2];
        let right = stack[num_remaining - 1];
        num_remaining -= 2;
        if num_remaining == 0 {
            return root_parent_cv(&left, &right);
        }
        output = parent_cv(&left, &right);
        while num_remaining > 0 {
            let left = stack[num_remaining - 1];
            output = if num_remaining == 1 {
                root_parent_cv(&left, &output)
            } else {
                parent_cv(&left, &output)
            };
            num_remaining -= 1;
        }
    } else {
        // A trailing partial chunk is the rightmost leaf. First perform the
        // early stack merge the reference implementation runs when partial
        // data enters the chunk state (the stack collapses to the popcount of
        // the chunk counter), then merge the stack under the partial chunk,
        // top CV first.
        let post_merge_len = (full_count as u64).count_ones() as usize;
        while stack.len() > post_merge_len {
            let right = stack.pop().unwrap();
            let left = stack.pop().unwrap();
            stack.push(parent_cv(&left, &right));
        }
        output = chunk_output(full_count as u64, chunks[full_count]).cv;
        let mut num_remaining = stack.len();
        while num_remaining > 0 {
            let left = stack[num_remaining - 1];
            output = if num_remaining == 1 {
                root_parent_cv(&left, &output)
            } else {
                parent_cv(&left, &output)
            };
            num_remaining -= 1;
        }
    }
    output
}

/// Output bookkeeping for one chunk: the last block's compression inputs plus
/// the chunk's chaining value (last block compressed without ROOT).
struct ChunkOutput {
    /// State before the last block (all earlier blocks compressed).
    input_cv: [u32; 8],
    /// The last block's message words.
    block_words: [u32; 16],
    /// The chunk's index (every block in a chunk is compressed with it).
    counter: u64,
    /// Valid bytes in the last block.
    block_len: u32,
    /// Whether the last block is also the chunk's first block.
    chunk_start: bool,
    /// The chunk's chaining value (last block compressed without ROOT).
    cv: [u8; 32],
}

impl ChunkOutput {
    /// The chunk's root output: last block compressed with ROOT.
    fn root_bytes(&self) -> [u8; 32] {
        let mut flags = CHUNK_END;
        if self.chunk_start {
            flags |= CHUNK_START;
        }
        flags |= ROOT;
        words_to_bytes32(&compress(
            &self.input_cv,
            &self.block_words,
            self.counter,
            self.block_len,
            flags,
        ))
    }
}

/// Processes one chunk (at most 1024 bytes) into its output bookkeeping.
/// `chunk_index` is the 0-based ordinal of the chunk in the whole input; every
/// block of a chunk is compressed with that counter (BLAKE3 chunk semantics).
fn chunk_output(chunk_index: u64, chunk: &[u8]) -> ChunkOutput {
    debug_assert!(chunk.len() <= CHUNK_LEN);
    let blocks: Vec<&[u8]> = chunk.chunks(BLOCK_LEN).collect();
    let mut cv = IV;
    for (index, block) in blocks.iter().enumerate() {
        let last = index + 1 == blocks.len();
        let mut flags = 0u32;
        if index == 0 {
            flags |= CHUNK_START;
        }
        let words = words_from_block(block);
        if last {
            let compressed = compress(
                &cv,
                &words,
                chunk_index,
                block.len() as u32,
                flags | CHUNK_END,
            );
            return ChunkOutput {
                input_cv: cv,
                block_words: words,
                counter: chunk_index,
                block_len: block.len() as u32,
                chunk_start: index == 0,
                cv: words_to_bytes32(&compressed),
            };
        }
        cv = words_to_cv8(&compress(&cv, &words, chunk_index, BLOCK_LEN as u32, flags));
    }
    unreachable!("a chunk has at least one block");
}

/// Hash of one parent node: compress the two child chaining values.
fn parent_cv(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    words_to_bytes32(&compress(
        &IV,
        &cv_pair_words(left, right),
        0,
        BLOCK_LEN as u32,
        PARENT,
    ))
}

/// Hash of the root parent node: like [`parent_cv`] but with the ROOT flag.
fn root_parent_cv(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    words_to_bytes32(&compress(
        &IV,
        &cv_pair_words(left, right),
        0,
        BLOCK_LEN as u32,
        PARENT | ROOT,
    ))
}

/// Builds the 16 message words of a parent block from two child CVs.
fn cv_pair_words(left: &[u8; 32], right: &[u8; 32]) -> [u32; 16] {
    let mut words = [0u32; 16];
    for (word, bytes) in words[..8].iter_mut().zip(left.chunks_exact(4)) {
        *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    for (word, bytes) in words[8..].iter_mut().zip(right.chunks_exact(4)) {
        *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    words
}

/// Interprets a block (possibly shorter than 64 bytes) as 16 little-endian
/// words, zero-padding the tail.
fn words_from_block(block: &[u8]) -> [u32; 16] {
    let mut words = [0u32; 16];
    for (index, out) in words.iter_mut().enumerate() {
        let start = index * 4;
        let end = (start + 4).min(block.len());
        if start < block.len() {
            let mut bytes = [0u8; 4];
            bytes[..end - start].copy_from_slice(&block[start..end]);
            *out = u32::from_le_bytes(bytes);
        }
    }
    words
}

/// BLAKE3 compression function: 7 rounds over the 16-word state.
fn compress(
    cv: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    // Unlike BLAKE2s, BLAKE3 stores the counter/block_len/flags directly in
    // the last four state words (no XOR with IV[4..8]).
    let mut state = [0u32; 16];
    state[..8].copy_from_slice(cv);
    state[8..12].copy_from_slice(&IV[..4]);
    state[12] = counter as u32;
    state[13] = (counter >> 32) as u32;
    state[14] = block_len;
    state[15] = flags;

    for &s in &MSG_SCHEDULE {
        // Column step.
        g(
            &mut state,
            0,
            4,
            8,
            12,
            block_words[s[0]],
            block_words[s[1]],
        );
        g(
            &mut state,
            1,
            5,
            9,
            13,
            block_words[s[2]],
            block_words[s[3]],
        );
        g(
            &mut state,
            2,
            6,
            10,
            14,
            block_words[s[4]],
            block_words[s[5]],
        );
        g(
            &mut state,
            3,
            7,
            11,
            15,
            block_words[s[6]],
            block_words[s[7]],
        );
        // Diagonal step.
        g(
            &mut state,
            0,
            5,
            10,
            15,
            block_words[s[8]],
            block_words[s[9]],
        );
        g(
            &mut state,
            1,
            6,
            11,
            12,
            block_words[s[10]],
            block_words[s[11]],
        );
        g(
            &mut state,
            2,
            7,
            8,
            13,
            block_words[s[12]],
            block_words[s[13]],
        );
        g(
            &mut state,
            3,
            4,
            9,
            14,
            block_words[s[14]],
            block_words[s[15]],
        );
    }

    let mut out = [0u32; 16];
    for index in 0..8 {
        out[index] = state[index] ^ state[index + 8];
        out[index + 8] = state[index + 8] ^ cv[index];
    }
    out
}

/// The BLAKE3 round function `G`.
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

fn words_to_bytes32(words: &[u32; 16]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (slot, word) in out.chunks_exact_mut(4).zip(&words[..8]) {
        slot.copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn words_to_cv8(words: &[u32; 16]) -> [u32; 8] {
    let mut cv = [0u32; 8];
    cv.copy_from_slice(&words[..8]);
    cv
}

#[cfg(test)]
mod tests {
    use super::blake3;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Official BLAKE3 digests (verified against `blake3` crate 1.x).
    #[test]
    fn matches_official_vectors() {
        let cases: &[(&str, &[u8])] = &[
            ("empty", &[]),
            ("one_zero", &[0u8]),
            ("one_a", b"a"),
            ("abc", b"abc"),
            ("fox", b"The quick brown fox jumps over the lazy dog"),
        ];
        let expected = [
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
            "17762fddd969a453925d65717ac3eea21320b66b54342fde15128d6caf21215f",
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
            "2f1514181aadccd913abd94cfa592701a5686ab23f8df1dff1b74710febc6d4a",
        ];
        for ((name, data), expected) in cases.iter().zip(expected.iter()) {
            assert_eq!(hex(&blake3(data)), *expected, "vector {name}");
        }
    }

    #[test]
    fn matches_block_and_chunk_boundary_vectors() {
        let cases: &[(usize, &str)] = &[
            (
                63,
                "a7e074f51bfb27ef13a4d51ca7c6149c6d38dc8e6c1f0fe6d8af355ed486caa4",
            ),
            (
                64,
                "79feec55b606024eb02ae9e304fc0176f3d8c4a85fc7fc94a4abff08c96e3e8a",
            ),
            (
                65,
                "84e9c75776beb9cd06812dd261164a1ac9484a74701cd6a2327ca6c67bad8058",
            ),
            (
                1023,
                "e9f2f425ba87823e50970153b8bed7bd7c6c322ad91c71984f7d5540764fefc0",
            ),
            (
                1024,
                "f6d80a7f842a8e1f8432df29fff969ea519a9a92c257ad7b2b51c7af4176ff11",
            ),
            (
                1025,
                "5810d8e502b356ac15934cbeed7ae98ece5a3de5d73f5a41623417bdba4751f0",
            ),
            (
                2048,
                "0620916b07ddd7d41b6ee9d1e82d3b40e336ae12dfb63e2faf70f99878755017",
            ),
            (
                2049,
                "ffb42bb14edaa3dd58690877d25967e6bf75a5fc5ded19df2b3ed8de75185fd5",
            ),
            (
                4096,
                "db7e3b25d50971860c8e4b4ed89fa5dfa2d393f23a4aae430c32f190438dae50",
            ),
            (
                8192,
                "f7029ababe7351c15560e65ddfeeb6afcb1d9e897ad47976128bbeda6cb608c9",
            ),
            (
                8193,
                "df9edef3efc75865d6d0ef67d733bba531ca6353836f58ea06e853e0a06cf266",
            ),
            (
                12288,
                "ddfd5cc9d4968f3d8c5b05164ab0dcec66651487195ea23d77eb87ddcb4f686c",
            ),
            (
                100_000,
                "23079bd7c0d4b3daaa81de0ca02ac709fabf6a9d45c4bf5c1d46d29b2194394f",
            ),
        ];
        for (len, expected) in cases {
            let data = vec![0x5a_u8; *len];
            assert_eq!(hex(&blake3(&data)), *expected, "length {len}");
        }
    }

    #[test]
    fn block_boundary_lengths_are_stable() {
        for length in [1usize, 63, 64, 65, 1023, 1024, 1025, 2047, 2048, 2049] {
            let data = vec![0x5a_u8; length];
            let digest = blake3(&data);
            assert_eq!(blake3(&data), digest, "length {length} stable");
            assert_ne!(
                hex(&digest),
                hex(&blake3(&[])),
                "length {length} differs from empty"
            );
        }
    }
}
