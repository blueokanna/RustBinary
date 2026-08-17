//! Schema-guided compact profile: the bincode-class wire path for statically
//! typed values.
//!
//! `#[derive(rustbinary::CompactBinary)]` generates a dedicated
//! `CompactEncode` / `CompactDecode` codec that bypasses the self-describing
//! event path: no per-value type tags, no field names, length-prefixed
//! containers, and memcpy / bulk-endian fast paths for byte strings and float
//! arrays. `Value`, untagged enums and `FormatEncoder`-driven types stay on
//! the self-describing profile and do not slow down this path.
//!
//! Run with `cargo run --example compact_profile --features derive`.

use nextjson::{NsonDeserialize, NsonSerialize};

/// Derives both the generic nextjson path (for dynamic/self-describing use)
/// and the schema-known compact path.
#[derive(Debug, PartialEq, NsonSerialize, NsonDeserialize, rustbinary::CompactBinary)]
struct Packet {
    sequence: u64,
    topic: String,
    payload: Vec<u8>,
    samples: Vec<f64>,
    status: Option<u8>,
}

#[derive(Debug, PartialEq, rustbinary::CompactBinary)]
enum Event {
    Idle,
    Data(u64),
    Point { x: i64, y: i64 },
}

fn main() -> rustbinary::Result<()> {
    let compact = rustbinary::options()
        .with_limit(1 << 20)
        .with_compact_format();

    let packet = Packet {
        sequence: 42,
        topic: "telemetry/temperature".to_string(),
        payload: (0..1024).map(|i| (i * 7) as u8).collect(),
        samples: (0..64).map(|i| i as f64 * 0.25).collect(),
        status: Some(0x0a),
    };

    let bytes = compact.serialize(&packet)?;
    let decoded: Packet = compact.deserialize(&bytes)?;
    assert_eq!(decoded, packet);
    println!(
        "compact packet: {} bytes (self-describing would be ~{} bytes)",
        bytes.len(),
        rustbinary::options().serialize(&packet)?.len()
    );

    // Exact-size, caller-owned output with no codec heap allocation.
    let required = compact.serialized_size(&packet)? as usize;
    let mut storage = vec![0_u8; required];
    let written = compact.serialize_into_slice(&mut storage, &packet)?;
    assert_eq!(&storage[..written], &bytes[..]);

    // Enums write only a compact variant discriminant.
    for event in [
        Event::Idle,
        Event::Data(u64::MAX),
        Event::Point { x: -9, y: 17 },
    ] {
        let encoded = compact.serialize(&event)?;
        let decoded: Event = compact.deserialize(&encoded)?;
        assert_eq!(decoded, event);
        println!("compact enum: {} bytes", encoded.len());
    }

    // Resource policies (limits, collection caps, depth) apply to the compact
    // profile exactly as they do to the self-describing profile.
    let tight = rustbinary::options()
        .with_collection_limit(16)
        .with_compact_format();
    let error = tight.deserialize::<Packet>(&bytes).unwrap_err();
    println!("oversized collection rejected: {error}");

    Ok(())
}
