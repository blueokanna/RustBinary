//! Integration tests for the schema-guided compact profile (`CompactBinary`
//! derive + `CompactConfig`).
//!
//! These tests exercise the derive-generated `CompactEncode`/`CompactDecode`
//! implementations, zero-copy borrowing, generic types, enums, recursion
//! limits, and the byte-level wire layout (no tags, no field names,
//! length-prefixed containers). The whole file is gated on the `derive`
//! feature; run with `cargo test --features derive`.

#![cfg(all(feature = "compact", feature = "derive"))]

use rustbinary::{compact::CompactConfig, CompactBinary, Error, NsonDeserialize, NsonSerialize};

fn compact() -> CompactConfig {
    rustbinary::options().with_compact_format()
}

#[derive(Debug, PartialEq, CompactBinary)]
struct Packet {
    sequence: u64,
    payload: Vec<u8>,
    label: String,
    enabled: bool,
}

#[derive(Debug, PartialEq, CompactBinary)]
struct Tuple(u16, i32, f32);

#[derive(Debug, PartialEq, CompactBinary)]
struct Unit;

#[derive(Debug, PartialEq, CompactBinary)]
enum Event {
    Idle,
    Data(u64),
    Point { x: i64, y: i64 },
}

#[derive(Debug, PartialEq, CompactBinary)]
struct Generic<T> {
    value: T,
    tag: u8,
}

#[derive(Debug, PartialEq, CompactBinary)]
struct Borrowed<'a> {
    name: &'a str,
    payload: &'a [u8],
    owned: Vec<u8>,
}

#[derive(Debug, PartialEq, CompactBinary)]
enum Json {
    Null,
    Integer(u64),
    Array(Vec<Json>),
}

#[test]
fn derived_struct_roundtrips() {
    let packet = Packet {
        sequence: 42,
        payload: vec![0, 251, 255],
        label: "telemetry".to_string(),
        enabled: true,
    };
    let bytes = compact().serialize(&packet).unwrap();
    assert_eq!(compact().deserialize::<Packet>(&bytes).unwrap(), packet);
}

#[test]
fn derived_struct_writes_no_tags_or_field_names() {
    let packet = Packet {
        sequence: 7,
        payload: vec![1, 2, 3],
        label: String::new(),
        enabled: false,
    };
    let bytes = compact().serialize(&packet).unwrap();
    // sequence=7 (varint) | payload len=3 + [1,2,3] | label len=0 | enabled=false
    assert_eq!(bytes, &[7, 3, 1, 2, 3, 0, 0]);
}

#[test]
fn derived_tuple_and_unit_roundtrip() {
    let tuple = Tuple(0x0102, -7, 1.5);
    let bytes = compact().serialize(&tuple).unwrap();
    assert_eq!(compact().deserialize::<Tuple>(&bytes).unwrap(), tuple);
    assert_eq!(compact().serialize(&Unit).unwrap(), &[]);
    assert_eq!(compact().deserialize::<Unit>(&[]).unwrap(), Unit);
}

#[test]
fn derived_enum_roundtrips_all_shapes() {
    for event in [
        Event::Idle,
        Event::Data(u64::MAX),
        Event::Point { x: -9, y: 17 },
    ] {
        let bytes = compact().serialize(&event).unwrap();
        assert_eq!(compact().deserialize::<Event>(&bytes).unwrap(), event);
    }
}

#[test]
fn derived_enum_uses_compact_discriminants() {
    assert_eq!(compact().serialize(&Event::Idle).unwrap(), &[0]);
    // Discriminant 1, then payload 7.
    assert_eq!(compact().serialize(&Event::Data(7)).unwrap(), &[1, 7]);
    // Discriminant 2, zigzag(-1) = 1, zigzag(2) = 4.
    assert_eq!(
        compact().serialize(&Event::Point { x: -1, y: 2 }).unwrap(),
        &[2, 1, 4]
    );
    // Unknown discriminants are rejected.
    let error = compact().deserialize::<Event>(&[9]).unwrap_err();
    assert!(matches!(error, Error::Custom(_)));
}

#[test]
fn generic_struct_roundtrips() {
    let value = Generic {
        value: vec![1u32, 2, 3],
        tag: 9,
    };
    let bytes = compact().serialize(&value).unwrap();
    let decoded: Generic<Vec<u32>> = compact().deserialize(&bytes).unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn borrowed_fields_point_into_the_frame() {
    let value = Borrowed {
        name: "edge-07",
        payload: &[1, 2, 3],
        owned: vec![4],
    };
    let bytes = compact().serialize(&value).unwrap();
    let decoded: Borrowed<'_> = compact().deserialize(&bytes).unwrap();
    assert_eq!(decoded, value);

    let start = bytes.as_ptr() as usize;
    let end = start + bytes.len();
    for borrowed in [decoded.name.as_bytes(), decoded.payload] {
        let pointer = borrowed.as_ptr() as usize;
        assert!(pointer >= start && pointer + borrowed.len() <= end);
    }
}

#[test]
fn recursive_type_depth_is_bounded() {
    let mut value = Json::Integer(1);
    for _ in 0..100 {
        value = Json::Array(vec![value]);
    }
    let bytes = compact().serialize(&value).unwrap();
    // The default depth cap (128) accepts a 100-level frame.
    assert_eq!(compact().deserialize::<Json>(&bytes).unwrap(), value);
    // A shallow cap rejects the same frame.
    let config = rustbinary::options()
        .with_depth_limit(8)
        .with_compact_format();
    let error = config.deserialize::<Json>(&bytes).unwrap_err();
    assert!(matches!(error, Error::Custom(_)));
}

#[derive(Debug, PartialEq, NsonSerialize, NsonDeserialize, CompactBinary)]
struct Both {
    id: u64,
    samples: Vec<i32>,
    status: Option<u8>,
}

#[test]
fn compact_and_self_describing_roundtrip_the_same_value() {
    let value = Both {
        id: 9,
        samples: (0..16).map(|i| i * 37 - 100).collect(),
        status: Some(10),
    };
    let sdes = rustbinary::options().serialize(&value).unwrap();
    assert_eq!(
        rustbinary::options().deserialize::<Both>(&sdes).unwrap(),
        value
    );
    let compact_bytes = compact().serialize(&value).unwrap();
    assert_eq!(
        compact().deserialize::<Both>(&compact_bytes).unwrap(),
        value
    );
    // No field names or per-value tags ⇒ the compact frame is strictly smaller.
    assert!(compact_bytes.len() < sdes.len());
}

#[test]
fn size_accounting_and_slice_writes() {
    let packet = Packet {
        sequence: 42,
        payload: vec![0, 251, 255],
        label: "telemetry".to_string(),
        enabled: true,
    };
    let bytes = compact().serialize(&packet).unwrap();
    assert_eq!(
        compact().serialized_size(&packet).unwrap() as usize,
        bytes.len()
    );

    let mut output = [0u8; 64];
    let written = compact()
        .serialize_into_slice(&mut output, &packet)
        .unwrap();
    assert_eq!(&output[..written], &bytes[..]);

    let mut tiny = [0u8; 3];
    let error = compact()
        .serialize_into_slice(&mut tiny, &packet)
        .unwrap_err();
    assert!(matches!(error, Error::BufferTooSmall { .. }));
}

#[test]
fn compact_profile_is_reported() {
    assert_eq!(
        rustbinary::options().profile(),
        rustbinary::BinaryProfile::SelfDescribing
    );
    assert_eq!(
        compact().profile(),
        rustbinary::BinaryProfile::CompactSchema
    );
}

// ---------------------------------------------------------------------------
// Trust-boundary regressions (mirroring `tests/security_audit.rs`)
// ---------------------------------------------------------------------------

// The collection limit applies per collection, not cumulatively across
// sibling containers at the same nesting depth.
#[test]
fn collection_limit_is_per_collection_not_cumulative() {
    let config = rustbinary::options()
        .with_collection_limit(5)
        .with_compact_format();
    let value = (vec![1u8, 2, 3], vec![4u8, 5, 6]);
    let bytes = config.serialize(&value).unwrap();
    assert_eq!(
        config.deserialize::<(Vec<u8>, Vec<u8>)>(&bytes).unwrap(),
        value
    );
    let single = vec![1u8, 2, 3, 4, 5, 6];
    assert!(matches!(
        config.deserialize::<Vec<u8>>(&config.serialize(&single).unwrap()),
        Err(Error::CollectionLimit { limit: 5 })
    ));
}

// Every truncation of a valid frame must fail cleanly (never panic).
#[test]
fn every_truncation_fails_cleanly() {
    let packet = Packet {
        sequence: 42,
        payload: vec![0, 251, 255],
        label: "telemetry".to_string(),
        enabled: true,
    };
    let bytes = compact().serialize(&packet).unwrap();
    for cut in 0..bytes.len() {
        assert!(
            compact().deserialize::<Packet>(&bytes[..cut]).is_err(),
            "prefix of length {cut} must fail"
        );
    }
}

// Arbitrary bytes under tight limits must only ever return `Ok` or `Err` —
// never panic, never overrun limits, never loop.
#[test]
fn arbitrary_bytes_never_panic_with_limits() {
    let config = rustbinary::options()
        .with_limit(1 << 16)
        .with_collection_limit(1024)
        .with_compact_format();
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state as u8
    };
    for _ in 0..4096 {
        let mut frame = [0u8; 64];
        for byte in &mut frame {
            *byte = next();
        }
        let _ = config.deserialize::<Packet>(&frame);
    }
}

// ---------------------------------------------------------------------------
// Coverage sweeps
// ---------------------------------------------------------------------------

// Every integer width round-trips its exact boundaries and the varint width
// cut points (250 / 251, 2^16, 2^32, 2^64), in both fixed and borrowed forms.
#[test]
fn exhaustive_integer_boundaries_roundtrip() {
    let unsigned = [
        0u128,
        1,
        250,
        251,
        0xffff,
        0x1_0000,
        0xffff_ffff,
        0x1_0000_0000,
        u64::MAX as u128 + 1,
        u128::MAX,
    ];
    for value in unsigned {
        let bytes = compact().serialize(&value).unwrap();
        assert_eq!(compact().deserialize::<u128>(&bytes).unwrap(), value);
    }
    for value in [
        i128::MIN,
        i64::MIN as i128,
        -251,
        -1,
        0,
        1,
        251,
        i64::MAX as i128,
        i128::MAX,
    ] {
        let bytes = compact().serialize(&value).unwrap();
        assert_eq!(compact().deserialize::<i128>(&bytes).unwrap(), value);
    }
    // Each primitive width round-trips its own boundaries, so the fixed-width
    // forms (`u8`/`i8` raw bytes) and the width-specific overflow checks are
    // exercised per type rather than through one widened value.
    macro_rules! width_roundtrip {
        ($ty:ty, $($value:expr),+ $(,)?) => {$(
            let value: $ty = $value;
            let bytes = compact().serialize(&value).unwrap();
            assert_eq!(compact().deserialize::<$ty>(&bytes).unwrap(), value);
        )+};
    }
    width_roundtrip!(u8, u8::MIN, 0, 1, 250, 251, u8::MAX);
    width_roundtrip!(u16, u16::MIN, 250, 251, u16::MAX);
    width_roundtrip!(u32, u32::MIN, 250, 251, 0x1_0000, u32::MAX);
    width_roundtrip!(u64, u64::MIN, 250, 251, 0x1_0000_0000, u64::MAX);
    width_roundtrip!(i8, i8::MIN, -1, 0, 1, i8::MAX);
    width_roundtrip!(i16, i16::MIN, -251, -1, 0, 1, 251, i16::MAX);
    width_roundtrip!(i32, i32::MIN, -251, -1, 1, 251, 0x1_0000, i32::MAX);
    width_roundtrip!(i64, i64::MIN, -251, -1, 1, 251, 0x1_0000_0000, i64::MAX);
}

// The bulk varint reader must be byte-exact across plain runs, multi-byte
// runs, and their interleaving (a wrong run length would desynchronize).
#[test]
fn bulk_varint_path_handles_plain_and_multi_byte_runs() {
    let mut values = Vec::new();
    // A long plain run (all ≤ 250).
    values.extend(0..300u64);
    // A run of multi-byte varints (251..=u16::MAX).
    values.extend(251..1000u64);
    // Wide values (u32/u64 widths).
    values.push(0x1_0000);
    values.push(0xffff_ffff);
    values.push(0x1_0000_0000);
    values.push(u64::MAX);
    // Interleaved plain / multi-byte pattern.
    values.extend((0..128).map(|i| if i % 2 == 0 { i } else { 300 + i }));

    let bytes = compact().serialize(&values).unwrap();
    let decoded: Vec<u64> = compact().deserialize(&bytes).unwrap();
    assert_eq!(decoded, values);
    // The payload must be exactly one length prefix plus per-value varints.
    assert_eq!(
        compact().serialized_size(&values).unwrap() as usize,
        bytes.len()
    );
}

#[cfg(feature = "std")]
#[test]
fn std_collections_roundtrip() {
    use std::collections::{HashMap, VecDeque};

    let mut map = HashMap::new();
    map.insert("alpha".to_string(), 1u64);
    map.insert("beta".to_string(), 2);
    map.insert("gamma".to_string(), 3);
    let bytes = compact().serialize(&map).unwrap();
    assert_eq!(
        compact()
            .deserialize::<HashMap<String, u64>>(&bytes)
            .unwrap(),
        map
    );

    let mut deque = VecDeque::new();
    for i in 0..300i32 {
        deque.push_back(i);
    }
    let bytes = compact().serialize(&deque).unwrap();
    assert_eq!(
        compact().deserialize::<VecDeque<i32>>(&bytes).unwrap(),
        deque
    );
}

// Every error family reachable from a compact decode must surface as the
// documented variant (never a panic, never a wrong category).
#[test]
fn every_reachable_error_is_well_typed() {
    // Invalid bool tag.
    assert!(matches!(
        compact().deserialize::<bool>(&[2]),
        Err(Error::InvalidBool(2))
    ));
    // Invalid marker varint.
    assert!(matches!(
        compact().deserialize::<u64>(&[255]),
        Err(Error::InvalidVarintMarker(255))
    ));
    // Non-canonical varint (marker 251 with a payload below 251).
    assert!(matches!(
        compact().deserialize::<u64>(&[251, 5, 0]),
        Err(Error::NonCanonicalVarint)
    ));
    // Integer overflow when the wire exceeds the target width: marker 253
    // carries a u64 payload of 2^32, which overflows `u16` but fits `u64`.
    assert!(matches!(
        compact().deserialize::<u16>(&[253, 0, 0, 0, 0, 1, 0, 0, 0]),
        Err(Error::IntegerOverflow { target: "u16" })
    ));
    assert_eq!(
        compact()
            .deserialize::<u64>(&[253, 0, 0, 0, 0, 1, 0, 0, 0])
            .unwrap(),
        0x1_0000_0000
    );
    // Truncated input.
    assert!(matches!(
        compact().deserialize::<Vec<u64>>(&[10]),
        Err(Error::UnexpectedEnd)
    ));
    // Invalid UTF-8 in a string payload.
    assert!(matches!(
        compact().deserialize::<String>(&[2, 0xff, 0xfe]),
        Err(Error::InvalidUtf8(_))
    ));
    // Invalid char scalar (a UTF-16 surrogate code point is not a char).
    assert!(matches!(
        compact().deserialize::<char>(&[251, 0, 0xd8]),
        Err(Error::InvalidChar)
    ));
    // Trailing bytes are rejected by default.
    let mut frame = compact().serialize(&1u64).unwrap();
    frame.push(0);
    assert!(matches!(
        compact().deserialize::<u64>(&frame),
        Err(Error::TrailingBytes { remaining: 1 })
    ));
    // Byte limit: a 3-byte varint with a 1-byte cap is rejected at read time.
    let config = rustbinary::options().with_limit(1).with_compact_format();
    assert!(matches!(
        config.deserialize::<u64>(&[251, 4, 5]),
        Err(Error::SizeLimit { limit: 1 })
    ));
}

// The compact and self-describing profiles must agree on the same logical
// values across a broad shape sweep.
#[test]
fn compact_and_self_describing_parity_across_values() {
    let values: Vec<Both> = (0..24)
        .map(|i| Both {
            id: i as u64 * 251,
            samples: (0..(i as usize % 9)).map(|j| j as i32 * 37 - 100).collect(),
            status: if i % 3 == 0 {
                None
            } else {
                Some((i * 7) as u8)
            },
        })
        .collect();
    for value in &values {
        let sdes = rustbinary::options().serialize(value).unwrap();
        let compact_bytes = compact().serialize(value).unwrap();
        assert_eq!(
            rustbinary::options().deserialize::<Both>(&sdes).unwrap(),
            *value
        );
        assert_eq!(
            compact().deserialize::<Both>(&compact_bytes).unwrap(),
            *value
        );
        // The compact profile is never larger than the self-describing one
        // for these records.
        assert!(compact_bytes.len() <= sdes.len());
    }
}

// The bulk varint reader must enforce the byte limit at run granularity and
// fail cleanly on truncation, exactly like the per-element reader.
#[test]
fn bulk_varint_path_respects_limits_and_truncation() {
    // A `Vec<u64>` declaring 200 single-byte elements under a 16-byte cap:
    // the first plain run already crosses the limit and is rejected. The
    // collection cap is raised so the byte limit is what fires.
    let mut frame = vec![200u8];
    frame.extend(std::iter::repeat(1u8).take(200));
    let config = rustbinary::options()
        .with_limit(16)
        .with_collection_limit(1000)
        .with_compact_format();
    assert!(matches!(
        config.deserialize::<Vec<u64>>(&frame),
        Err(Error::SizeLimit { limit: 16 })
    ));

    // A run truncated mid-way (declared 200, only 5 payload bytes present).
    let mut truncated = vec![200u8];
    truncated.extend_from_slice(&[1, 2, 3, 4, 5]);
    assert!(matches!(
        compact().deserialize::<Vec<u64>>(&truncated),
        Err(Error::UnexpectedEnd)
    ));

    // Multi-byte varints interleaved with plain runs fail cleanly when the
    // final element is missing.
    let mut mixed = vec![4u8];
    mixed.extend_from_slice(&[1, 251, 0, 1, 2]); // 1, 256, 2 — one short
    assert!(matches!(
        compact().deserialize::<Vec<u64>>(&mixed),
        Err(Error::UnexpectedEnd)
    ));

    // The bulk reader must never over-consume: a valid frame decodes exactly.
    let values: Vec<u64> = (0..300).collect();
    let bytes = compact().serialize(&values).unwrap();
    assert_eq!(compact().deserialize::<Vec<u64>>(&bytes).unwrap(), values);
}
