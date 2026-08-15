//! Dependency-free SHA-256 (FIPS 180-4) for the archive Merkle tree.
//!
//! The `archive` feature needs a cryptographic hash for its Merkle root, and
//! the crate avoids third-party hashing dependencies, so this module provides
//! a compact, self-contained SHA-256. It is pure Rust, `no_std`-compatible,
//! and verified against the NIST FIPS 180-2 test vectors in the unit tests.
//!
//! SHA-256 is a public, standardized function with published test vectors —
//! unlike secret-key primitives, its correctness is fully checkable against
//! those vectors, which the tests do. This is an integrity tree hash, not a
//! MAC: it detects accidental corruption, and the archive Merkle root is an
//! integrity check, never an authentication mechanism.

/// Round constants (the first 32 bits of the fractional parts of the cube
/// roots of the first 64 primes).
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Computes the SHA-256 digest of `input`.
///
/// Straightforward block-at-a-time FIPS 180-4: the message is padded
/// (`0x80`, zero bytes, then the 64-bit big-endian bit length) so the padded
/// length is a multiple of 64 bytes, then each 512-bit block is processed
/// through 64 rounds. The length field always starts at byte offset 56 of its
/// block by construction of the padding.
pub(crate) fn sha256(input: &[u8]) -> [u8; 32] {
    // Initial hash values: the first 32 bits of the fractional parts of the
    // square roots of the first 8 primes.
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (input.len() as u64).wrapping_mul(8);
    // `length_field_start` is the byte offset of the 64-bit length field;
    // by construction it is always at offset 56 within its block.
    let length_field_start = input.len() + 1 + padding_zeroes(input.len());
    debug_assert_eq!(length_field_start % 64, 56);
    let field_block = length_field_start / 64;

    let mut block = [0_u8; 64];
    for block_index in 0..=field_block {
        let base = block_index * 64;
        for (index, slot) in block.iter_mut().enumerate() {
            let position = base + index;
            *slot = if position < input.len() {
                input[position]
            } else if position == input.len() {
                0x80
            } else {
                0
            };
        }
        if block_index == field_block {
            block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        }
        compress(&mut h, &block);
    }

    let mut out = [0_u8; 32];
    for (slot, value) in out.chunks_exact_mut(4).zip(h) {
        slot.copy_from_slice(&value.to_be_bytes());
    }
    out
}

/// Number of zero bytes between the `0x80` byte and the 8-byte length field.
fn padding_zeroes(message_len: usize) -> usize {
    // The length field must start at byte offset 56 of its block:
    // (message_len + 1 + zeroes) % 64 == 56. The +64 keeps the subtraction
    // non-negative for every residue.
    let residue = (message_len + 1) % 64;
    (56 + 64 - residue) % 64
}

/// Processes one 512-bit block into the hash state.
fn compress(h: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0_u32; 64];
    for (slot, chunk) in w.iter_mut().zip(block.chunks_exact(4)) {
        *slot = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for index in 16..64 {
        let s0 =
            w[index - 15].rotate_right(7) ^ w[index - 15].rotate_right(18) ^ (w[index - 15] >> 3);
        let s1 =
            w[index - 2].rotate_right(17) ^ w[index - 2].rotate_right(19) ^ (w[index - 2] >> 10);
        w[index] = w[index - 16]
            .wrapping_add(s0)
            .wrapping_add(w[index - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for index in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[index])
            .wrapping_add(w[index]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

#[cfg(test)]
mod tests {
    use super::sha256;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// NIST FIPS 180-2 / FIPS 180-4 test vectors.
    #[test]
    fn matches_nist_test_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(&sha256(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
    }

    #[test]
    fn one_million_a_matches_known_digest() {
        let data = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&sha256(&data)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn block_boundary_lengths_are_stable() {
        // Lengths around the 56-byte padding boundary must not be affected by
        // padding layout.
        for length in [55usize, 56, 63, 64, 65, 119, 120, 127, 128] {
            let data = vec![0x5a_u8; length];
            let digest = sha256(&data);
            // Spot consistency: hashing the same bytes twice is stable and
            // the digest differs from the empty digest.
            assert_eq!(sha256(&data), digest);
            assert_ne!(hex(&digest), hex(&sha256(b"")));
        }
    }
}
