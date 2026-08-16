//! Property tests for resource-bounded decoding.
//!
//! These randomize values and budgets through the public API and assert the
//! documented guarantees:
//!
//! - `decode_bounded` with a sufficient budget agrees with the plain codec on
//!   the decoded value and on the exact bytes read.
//! - For statically bounded types the measured `read`, `alloc`, `depth`, and
//!   `work` never exceed the compile-time algebra.
//! - The reported allocation bound always covers the bytes read.

#![cfg(all(feature = "bounded", feature = "alloc"))]

use proptest::prelude::*;

use rustbinary::{decode_bounded, Budget, DecodeBounded};

/// A dynamic record: the algebra reports `usize::MAX` for content-dependent
/// resources, and the runtime budget enforces the caller's limits.
#[derive(
    Debug, PartialEq, nextjson::NsonSerialize, nextjson::NsonDeserialize, rustbinary::DecodeBounded,
)]
struct Packet {
    id: u64,
    seq: i32,
    tags: Vec<u8>,
    label: String,
}

/// A statically bounded record: every constant is finite and exact.
#[derive(
    Debug, PartialEq, nextjson::NsonSerialize, nextjson::NsonDeserialize, rustbinary::DecodeBounded,
)]
struct StaticP {
    a: u8,
    b: i64,
    c: bool,
    d: [i32; 3],
}

proptest! {
    /// A dynamic decode under a generous budget equals the plain codec and
    /// reports the exact bytes read plus a sound allocation ceiling.
    #[test]
    fn dynamic_decode_matches_plain_codec(
        id in any::<u64>(),
        seq in any::<i32>(),
        tags in prop::collection::vec(any::<u8>(), 0..64),
        label in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        let label = String::from_utf8_lossy(&label).into_owned();
        let value = Packet { id, seq, tags, label };
        let bytes = rustbinary::options().serialize(&value).unwrap();
        let len = bytes.len() as u64;
        let budget = Budget::default()
            .with_max_input(len + 8)
            .with_max_alloc(1 << 20);
        let decoded = decode_bounded::<Packet>(&bytes, budget).unwrap();
        prop_assert_eq!(decoded.value, value);
        prop_assert_eq!(decoded.use_.read, len);
        prop_assert!(decoded.use_.read <= budget.max_input());
        prop_assert!(decoded.use_.read <= budget.max_work());
        // Allocation ceiling is sound: it covers the bytes read, and stays
        // within the documented max_input + max_alloc.
        prop_assert!(decoded.use_.alloc_bound >= len);
        prop_assert!(decoded.use_.alloc_bound <= budget.max_input() + budget.max_alloc());
        // Depth equals the type's derived constant.
        prop_assert_eq!(decoded.use_.depth_bound, Packet::MAX_DEPTH);
        // Work for dynamic types is the consumed byte count.
        prop_assert_eq!(decoded.use_.work_bound, len);
    }

    /// A statically bounded decode never exceeds its compile-time algebra.
    #[test]
    fn static_decode_respects_algebra(
        a in any::<u8>(),
        b in any::<i64>(),
        c in any::<bool>(),
        d in prop::array::uniform3(any::<i32>()),
    ) {
        const {
            assert!(StaticP::STATICALLY_BOUNDED);
        };
        let value = StaticP { a, b, c, d };
        let bytes = rustbinary::options().serialize(&value).unwrap();
        let decoded = decode_bounded::<StaticP>(&bytes, Budget::from_type::<StaticP>()).unwrap();
        prop_assert_eq!(decoded.value, value);
        prop_assert!(decoded.use_.read as usize <= StaticP::MAX_INPUT);
        prop_assert_eq!(decoded.use_.alloc_bound, 0);
        prop_assert_eq!(decoded.use_.depth_bound, StaticP::MAX_DEPTH);
        prop_assert!(decoded.use_.work_bound as usize <= StaticP::MAX_WORK);
    }

    /// An input budget that is one byte short always fails, while the exact
    /// budget succeeds: the boundary is exact.
    #[test]
    fn input_budget_boundary_is_exact(
        id in any::<u64>(),
        seq in any::<i32>(),
        tags in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        let value = Packet { id, seq, tags, label: String::new() };
        let bytes = rustbinary::options().serialize(&value).unwrap();
        let len = bytes.len() as u64;
        prop_assert!(len > 0);
        let exact = Budget::default().with_max_input(len).with_max_alloc(1 << 20);
        let decoded = decode_bounded::<Packet>(&bytes, exact).unwrap();
        prop_assert_eq!(decoded.use_.read, len);
        let tight = Budget::default()
            .with_max_input(len - 1)
            .with_max_alloc(1 << 20);
        prop_assert!(decode_bounded::<Packet>(&bytes, tight).is_err());
    }
}
