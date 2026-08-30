//! Security-focused regression tests for the Compact V1 binary codec.
//!
//! These tests lock down invariants that matter at trust boundaries:
//! hostile nesting, malformed frames, backtracking state, and resource-limit
//! semantics. Every case must return an error or a correct value; none may
//! panic, overflow the stack, or bypass a configured limit.
//!
//! Every test drives round-trips through the owned `Config::serialize` API,
//! Every test drives round-trips through the owned `Config::serialize` API.
//! The crate is always `no_std` + `alloc`, so owned APIs are always available;
//! the `no_std` slice core is covered separately by `tests/core_profiles.rs`.

// ---------------------------------------------------------------------------
// Resource limits
// ---------------------------------------------------------------------------

// The collection limit applies per collection, not cumulatively across
// sibling containers at the same nesting depth.
#[test]
fn collection_limit_is_per_collection_not_cumulative() {
    let value = (vec![1u8, 2, 3], vec![4u8, 5, 6]);
    let config = rustbinary::options().with_collection_limit(5);
    let bytes = config.serialize(&value).unwrap();
    assert_eq!(
        config.deserialize::<(Vec<u8>, Vec<u8>)>(&bytes).unwrap(),
        value
    );

    // A single collection of 6 elements must still be rejected.
    let single = vec![1u8, 2, 3, 4, 5, 6];
    assert!(matches!(
        config.serialize(&single),
        Err(rustbinary::Error::CollectionLimit { limit: 5 })
    ));
}

// The collection limit bounds element counts, not string byte length; strings
// are bounded by the byte limit.
#[test]
fn large_strings_round_trip_under_byte_limit() {
    let big = "x".repeat(1_100_000); // > the default 1,000,000 collection limit
    let config = rustbinary::options().with_limit(4 * 1024 * 1024);
    let bytes = config.serialize(&big).unwrap();
    assert_eq!(config.deserialize::<String>(&bytes).unwrap(), big);
}

// Decompression is always bounded, even when no byte limit is configured: a
// hostile frame header declaring a huge decompressed size must be rejected.
#[cfg(feature = "compression")]
#[test]
fn decompression_is_bounded_even_without_a_configured_limit() {
    let mut hostile = Vec::from(*b"RBZ1");
    hostile.extend_from_slice(&1u16.to_le_bytes()); // format version
    hostile.extend_from_slice(&1u16.to_le_bytes()); // flags: compressed
    hostile.extend_from_slice(&u64::MAX.to_le_bytes()); // raw_len: huge
    hostile.extend_from_slice(&1u64.to_le_bytes()); // stored_len: tiny

    for config in [
        rustbinary::legacy_options().with_compression(3),
        rustbinary::options().with_no_limit().with_compression(3),
    ] {
        assert!(
            matches!(
                config.deserialize::<Vec<u8>>(&hostile),
                Err(rustbinary::Error::SizeLimit { .. })
            ),
            "decompression must be bounded without a configured limit"
        );
    }
}

// ---------------------------------------------------------------------------
// Hostile input: panics and stack safety
// ---------------------------------------------------------------------------

// Deterministic pseudo-random byte frames and every truncation must decode
// without panicking (errors are expected and fine).
#[test]
fn random_and_truncated_inputs_never_panic() {
    let mut state = 0x853c_49e6_748f_ea9bu64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..2_000 {
        let len = (next() % 64) as usize;
        let input = (0..len).map(|_| (next() & 0xff) as u8).collect::<Vec<_>>();
        for cut in [0usize, len / 2, len.saturating_sub(1), len] {
            assert!(
                std::panic::catch_unwind(|| {
                    rustbinary::options().deserialize::<nextjson::Value>(&input[..cut])
                })
                .is_ok(),
                "random input of length {len} truncated at {cut} panicked"
            );
        }
    }
}

// A deeply nested hostile frame is rejected by the depth limit without
// overflowing the stack or panicking.
#[test]
fn hostile_deep_nesting_is_rejected_without_stack_overflow() {
    for depth in [129usize, 1_000, 100_000] {
        let mut input = vec![0x0a; depth];
        input.push(0xff);
        let result = std::panic::catch_unwind(|| {
            rustbinary::options().deserialize::<nextjson::Value>(&input)
        });
        assert!(result.is_ok(), "depth {depth} caused a panic");
        let error = result.unwrap().unwrap_err();
        assert!(
            matches!(error, rustbinary::Error::Custom(_)),
            "depth {depth}: expected depth-limit error, got {error:?}"
        );
    }
}

// nextjson::Value must round-trip through the binary codec losslessly.
#[test]
fn value_round_trips_losslessly() {
    let value = nextjson::json!({
        "code": 200,
        "ok": true,
        "nested": { "a": [1, 2.5, null], "b": false },
        "list": ["x", "y"],
    });
    let bytes = rustbinary::options().serialize(&value).unwrap();
    let decoded: nextjson::Value = rustbinary::options().deserialize(&bytes).unwrap();
    assert_eq!(decoded, value);
}

// Untagged enums rely on save/restore backtracking; hostile variant shapes
// and every truncation must fail cleanly without corrupting decoder state.
#[test]
fn untagged_enum_backtracking_handles_hostile_input() {
    #[derive(Debug, PartialEq, nextjson::NsonDeserialize, nextjson::NsonSerialize)]
    #[njson(untagged)]
    enum Shape {
        Point { x: i64, y: i64 },
        Label(String),
    }

    let point = Shape::Point { x: 1, y: 2 };
    let bytes = rustbinary::options().serialize(&point).unwrap();
    assert_eq!(
        rustbinary::options().deserialize::<Shape>(&bytes).unwrap(),
        point
    );

    let label = Shape::Label("hi".into());
    let bytes = rustbinary::options().serialize(&label).unwrap();
    assert_eq!(
        rustbinary::options().deserialize::<Shape>(&bytes).unwrap(),
        label
    );

    // A point-shaped frame with a wrong field type must fail cleanly.
    let hostile = rustbinary::options()
        .serialize(&nextjson::json!({ "x": "not-a-number", "y": 2 }))
        .unwrap();
    let result = std::panic::catch_unwind(|| rustbinary::options().deserialize::<Shape>(&hostile));
    assert!(result.is_ok());
    assert!(result.unwrap().is_err());

    // Truncated hostile frames must never panic.
    for len in 0..hostile.len() {
        let truncated = &hostile[..len];
        assert!(
            std::panic::catch_unwind(|| { rustbinary::options().deserialize::<Shape>(truncated) })
                .is_ok(),
            "truncation at {len} panicked"
        );
    }
}

// ---------------------------------------------------------------------------
// Value-domain correctness
// ---------------------------------------------------------------------------

// The CBOR relay materializes a value tree, so its per-container element
// counts must be enforced against the configured collection limit.
#[cfg(feature = "cbor")]
#[test]
fn cbor_decode_enforces_collection_limit() {
    let config = rustbinary::options()
        .with_collection_limit(4)
        .with_cbor_format();

    // A valid 4-element array round-trips.
    let bytes = config.serialize(&vec![1u32, 2, 3, 4]).unwrap();
    assert_eq!(
        config.deserialize::<Vec<u32>>(&bytes).unwrap(),
        vec![1, 2, 3, 4]
    );

    // A single oversized container is rejected before typed conversion.
    let mut hostile = vec![0x9f]; // indefinite-length array
    hostile.extend(std::iter::repeat(0x01).take(5)); // five elements
    hostile.push(0xff);
    assert!(matches!(
        config.deserialize::<Vec<u32>>(&hostile),
        Err(rustbinary::Error::CollectionLimit { limit: 4 })
    ));

    // A nested oversized container is also rejected.
    let nested = [0x9f, 0x01, 0x9f, 0x01, 0x01, 0x01, 0x01, 0x01, 0xff, 0xff];
    assert!(matches!(
        config.deserialize::<nextjson::Value>(&nested),
        Err(rustbinary::Error::CollectionLimit { limit: 4 })
    ));
}

// ---------------------------------------------------------------------------
// Value-domain correctness
// ---------------------------------------------------------------------------

#[test]
fn i128_min_encodes_without_panic() {
    let bytes = rustbinary::options().serialize(&i128::MIN).unwrap();
    assert_eq!(
        rustbinary::options().deserialize::<i128>(&bytes).unwrap(),
        i128::MIN
    );
}

#[test]
fn f32_typed_round_trip_is_lossless() {
    for value in [
        1.5f32,
        -0.0,
        f32::MAX,
        f32::MIN_POSITIVE,
        std::f32::consts::PI,
    ] {
        let bytes = rustbinary::options().serialize(&value).unwrap();
        let decoded: f32 = rustbinary::options().deserialize(&bytes).unwrap();
        assert_eq!(decoded.to_bits(), value.to_bits(), "f32 {value} lost bits");
    }
}

#[test]
fn option_round_trips_through_null_tag() {
    let none: Option<u32> = None;
    let some: Option<u32> = Some(42);
    assert_eq!(
        rustbinary::options()
            .deserialize::<Option<u32>>(&rustbinary::options().serialize(&none).unwrap())
            .unwrap(),
        None
    );
    assert_eq!(
        rustbinary::options()
            .deserialize::<Option<u32>>(&rustbinary::options().serialize(&some).unwrap())
            .unwrap(),
        Some(42)
    );
}

// nextjson::Bytes: the unified token model has no byte-string token, so Bytes
// encodes as an array of tagged u8 (matching nextjson's own JSON spelling) and
// cannot be decoded back — a documented nextjson limitation, not a codec bug.
#[test]
fn nextjson_bytes_encodes_as_array_spelling() {
    let value = nextjson::Bytes(b"\x00\x01binary");
    let encoded = rustbinary::options().serialize(&value).unwrap();
    // Tag 0x0a (array) + each byte as tagged u8 (0x03) + 0xff terminator.
    assert_eq!(encoded[0], 0x0a);
    assert_eq!(*encoded.last().unwrap(), 0xff);
    // The same payload via Vec<u8> produces an identical array spelling.
    assert_eq!(
        rustbinary::options()
            .serialize(&value.as_bytes().to_vec())
            .unwrap(),
        encoded
    );
    // Decoding into Vec<u8> (the lossless path) round-trips.
    assert_eq!(
        rustbinary::options()
            .deserialize::<Vec<u8>>(&encoded)
            .unwrap(),
        b"\x00\x01binary"
    );
}
