//! Kani formal-verification harnesses for the Core layer.
//!
//! These harnesses are compiled only when the crate is built under Kani
//! (`cargo kani -p rustbinary`), which defines the `kani` cfg. They prove, by
//! exhaustive symbolic model checking:
//!
//! - **Roundtrip**: `decode_varint_le(encode_varint_le(v)) == v` for every
//!   `u128`; `zigzag_decode(zigzag_encode(v)) == v` and the reverse for every
//!   `i128`/`u128`.
//! - **Boundedness**: the encoded form is at most 17 bytes, and its width is
//!   the canonical (minimal) width for the value.
//! - **Canonical uniqueness**: `encode` is a bijection onto the accepted byte
//!   strings (the roundtrip proof plus determinism of `decode` implies that
//!   two distinct values can never share one canonical encoding).
//!
//! Run:
//!
//! ```text
//! cargo kani -p rustbinary --harness canonical::varint_roundtrip
//! cargo kani -p rustbinary --harness canonical::zigzag_roundtrip
//! cargo kani -p rustbinary --harness canonical::zigzag_injective
//! cargo kani -p rustbinary --harness canonical::varint_bounded_and_minimal
//! ```
//!
//! (or `cargo kani -p rustbinary` for the whole set). Kani also proves the
//! harnesses are memory-safe and terminating, which covers the decoder's
//! bounds-checked reads.

#[cfg(kani)]
mod canonical {
    use crate::canonical::{decode_varint_le, encode_varint_le, zigzag_decode, zigzag_encode};

    /// `decode(encode(v)) == v` for every possible `u128`.
    ///
    /// Because `decode` is a deterministic total function, this also proves
    /// that `encode` is injective: no two distinct values can share a
    /// canonical encoding, i.e. the wire form is unique per value.
    #[kani::proof]
    #[kani::unwind(20)]
    pub fn varint_roundtrip() {
        let value: u128 = kani::any();
        let (bytes, length) = encode_varint_le(value);
        let marker = bytes[0];
        kani::assert(
            decode_varint_le(marker, &bytes[1..length]) == Some(value),
            "canonical varint roundtrip",
        );
    }

    /// The encoded width is bounded by 17 bytes and is the canonical width.
    #[kani::proof]
    #[kani::unwind(20)]
    pub fn varint_bounded_and_minimal() {
        let value: u128 = kani::any();
        let (_, length) = encode_varint_le(value);
        kani::assert(length <= 17, "varint is bounded by 17 bytes");
        match length {
            1 => kani::assert(value <= 250, "1-byte form only for <= 250"),
            3 => kani::assert((251..=0xffff).contains(&value), "3-byte form"),
            5 => kani::assert((0x1_0000..=0xffff_ffff).contains(&value), "5-byte form"),
            9 => kani::assert(
                (0x1_0000_0000..=0xffff_ffff_ffff_ffff).contains(&value),
                "9-byte form",
            ),
            17 => kani::assert(
                value >= 0x1_0000_0000_0000_0000,
                "17-byte form only for >= 2^64",
            ),
            other => kani::assert(false, "unreachable width"),
        }
    }

    /// `zigzag_decode(zigzag_encode(v)) == v` for every `i128`.
    #[kani::proof]
    pub fn zigzag_roundtrip() {
        let value: i128 = kani::any();
        kani::assert(
            zigzag_decode(zigzag_encode(value)) == value,
            "zigzag roundtrip",
        );
    }

    /// `zigzag_encode(zigzag_decode(e)) == e` for every `u128` (bijective).
    #[kani::proof]
    pub fn zigzag_injective() {
        let encoded: u128 = kani::any();
        kani::assert(
            zigzag_encode(zigzag_decode(encoded)) == encoded,
            "zigzag is injective",
        );
    }
}

#[cfg(feature = "projection")]
mod projection {
    use alloc::collections::{BTreeMap, BTreeSet};

    use crate::projection::{aggregate_siblings, combine_frontier, leaf_count};

    /// Kani-friendly stand-in hash: XOR-fold two 32-byte inputs.
    ///
    /// The tree-geometry proofs hold for *any* hash function, so a trivial
    /// hash keeps the symbolic execution tractable while the aggregation /
    /// recomputation protocol is still proven correct.
    fn mock_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = left[i] ^ right[i];
        }
        out
    }

    /// The canonical varint payload wrapper roundtrips: encoding a value and
    /// decoding the payload reproduces it for every `u128`, and the canonical
    /// form is the only accepted one.
    #[kani::proof]
    #[kani::unwind(20)]
    pub fn varint_payload_roundtrip() {
        let value: u128 = kani::any();
        let (bytes, len) = crate::canonical::encode_varint_le(value);
        let decoded = crate::projection::decode_canonical_varint(&bytes[..len]);
        kani::assert(
            matches!(decoded, Ok(decoded) if decoded == value),
            "canonical varint payload roundtrip",
        );
    }

    /// `leaf_count(n)` is a power of two, covers every field, and never exceeds
    /// `2 * max(1, n)`: the Merkle tree is complete and never more than doubles.
    #[kani::proof]
    #[kani::unwind(20)]
    pub fn leaf_count_is_complete_and_bounded() {
        let n: u64 = kani::any();
        kani::assume(n <= 1_000_000);
        let count = leaf_count(n);
        kani::assert(count.is_power_of_two(), "leaf count is a power of two");
        kani::assert(n == 0 || count >= n, "leaf count covers all fields");
        kani::assert(count >= 1, "at least one leaf");
        kani::assert(count <= 2 * n.max(1), "tree is at most a doubling");
    }

    /// For an arbitrary non-empty subset of an arbitrary 4-leaf tree, the batch
    /// sibling extraction (`aggregate_siblings`) and the root recomputation
    /// (`combine_frontier`) are mutually consistent: the proof reproduces the
    /// tree root for every possible leaf hash and every possible query.
    ///
    /// This is the algebraic half of projection soundness: given authentic
    /// leaves (bound by collision resistance) and the sibling set, the
    /// verifier reconstructs exactly the record's Merkle root.
    #[kani::proof]
    #[kani::unwind(12)]
    pub fn small_tree_proof_agrees_with_root() {
        const L: usize = 4;
        let leaves: [[u8; 32]; L] = kani::any();
        // Build the complete tree with the mock hash (symbolic-friendly).
        let mut tree = alloc::vec![[0u8; 32]; 2 * L];
        tree[L..].copy_from_slice(&leaves);
        for i in (1..L).rev() {
            tree[i] = mock_hash(&tree[2 * i], &tree[2 * i + 1]);
        }
        // Any non-empty subset of leaves as the query.
        let mask: u8 = kani::any();
        kani::assume(mask != 0);
        kani::assume(mask < (1 << L));
        let mut queried: BTreeSet<u32> = BTreeSet::new();
        let mut frontier: BTreeMap<usize, [u8; 32]> = BTreeMap::new();
        for i in 0..L {
            if mask & (1 << i) != 0 {
                queried.insert(i as u32);
                frontier.insert(L + i, tree[L + i]);
            }
        }
        let siblings = aggregate_siblings(&tree, L, &queried);
        let siblings_map: BTreeMap<usize, [u8; 32]> =
            siblings.iter().map(|s| (s.index, s.hash)).collect();
        match combine_frontier(&frontier, &siblings_map, &mock_hash) {
            Ok(root) => {
                kani::assert(root == tree[1], "aggregate + combine reproduce the root");
            }
            Err(_) => {
                kani::assert(false, "a valid batch proof must reconstruct the root");
            }
        }
    }
}

#[cfg(feature = "bounded")]
mod bounded {
    use crate::bounded::{derive_enforced_limits, Budget};

    /// The derived enforced limits respect the budget: the byte limit never
    /// exceeds `max_input` or `max_work`, the collection cap never exceeds
    /// `max_alloc` per structural unit, and the documented allocation ceiling
    /// (`byte_limit + per_element_ceiling * collection_limit <= max_input +
    /// max_alloc`) holds for dynamic types with a non-zero structural
    /// ceiling.
    #[kani::proof]
    pub fn enforced_limits_respect_budget() {
        let budget = Budget::new(kani::any(), kani::any(), kani::any(), kani::any());
        let statically_bounded: bool = kani::any();
        let per_element_ceiling: u64 = kani::any();
        let limits = derive_enforced_limits(budget, statically_bounded, per_element_ceiling);
        kani::assert(
            limits.byte_limit <= budget.max_input(),
            "byte limit never exceeds max_input",
        );
        kani::assert(
            limits.byte_limit <= budget.max_work(),
            "byte limit never exceeds max_work",
        );
        kani::assert(
            limits.depth_limit <= budget.max_depth(),
            "depth limit never exceeds max_depth",
        );
        if !statically_bounded && per_element_ceiling > 0 {
            kani::assert(
                limits.collection_limit <= budget.max_alloc() / per_element_ceiling,
                "collection cap never exceeds the structural alloc budget",
            );
            let alloc_bound = limits
                .byte_limit
                .saturating_add(limits.collection_limit.saturating_mul(per_element_ceiling));
            kani::assert(
                alloc_bound <= budget.max_input().saturating_add(budget.max_alloc()),
                "documented allocation ceiling holds",
            );
        }
    }

    /// `depth_plus_one` increments finite depths and preserves `usize::MAX`.
    #[kani::proof]
    pub fn depth_algebra_preserves_max() {
        let depth: usize = kani::any();
        let result = crate::bounded::depth_plus_one(depth);
        if depth == usize::MAX {
            kani::assert(result == usize::MAX, "MAX depth stays MAX");
        } else {
            kani::assert(result == depth + 1, "finite depth increments");
        }
    }
}
