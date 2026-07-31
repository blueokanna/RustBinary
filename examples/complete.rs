use serde::{Deserialize, Serialize};

use rustbinary::{hardware_capabilities, options, EncryptionKey, Reflect, StaticSize, TypeShape};

#[derive(
    Clone,
    Debug,
    PartialEq,
    Serialize,
    Deserialize,
    rustbinary::Fingerprint,
    rustbinary::Reflect,
    rustbinary::StaticSize,
)]
struct Telemetry {
    sequence: u64,
    healthy: bool,
    samples: [i16; 4],
}

#[derive(Debug, PartialEq, rustbinary::BitPacked)]
struct WireFlags {
    #[bits = 3]
    kind: u8,
    urgent: bool,
    #[bits = 12]
    sequence: u16,
}

fn main() -> rustbinary::Result<()> {
    let protocol = options()
        .with_little_endian()
        .with_varint_encoding()
        .with_limit(1 << 20)
        .with_collection_limit(100_000)
        .reject_trailing_bytes();

    let value = Telemetry {
        sequence: 42,
        healthy: true,
        samples: [-3, 5, 8, 13],
    };

    // Exact-size, caller-owned output. The codec performs no heap allocation.
    let required = protocol.serialized_size(&value)? as usize;
    let mut storage = vec![0_u8; required];
    let written = protocol.serialize_into_slice(&mut storage, &value)?;
    let decoded: Telemetry = protocol.deserialize(&storage[..written])?;
    assert_eq!(decoded, value);

    // The frame binds the type shape and complete wire configuration. This is
    // compatibility detection, not cryptographic authentication.
    let fingerprinted = protocol.with_fingerprint();
    let frame = fingerprinted.serialize(&value)?;
    assert_eq!(fingerprinted.deserialize::<Telemetry>(&frame)?, value);
    println!(
        "fingerprint: {:#018x}",
        fingerprinted.fingerprint::<Telemetry>()
    );

    // Generated static bounds and reflection metadata require no registry.
    println!("static maximum: {} bytes", Telemetry::MAX_SIZE);
    if let TypeShape::Struct(fields) = Telemetry::SHAPE {
        println!("{} has {} fields", Telemetry::TYPE_NAME, fields.len());
    }

    let flags = WireFlags {
        kind: 5,
        urgent: true,
        sequence: 2047,
    };
    let packed = protocol.with_bit_packing().serialize(&flags)?;
    assert_eq!(
        protocol
            .with_bit_packing()
            .deserialize::<WireFlags>(&packed)?,
        flags
    );

    let adaptive = protocol.with_adaptive_encoding();
    let values = [1000, 1001, 1002, 1003, 1004];
    let encoded = adaptive.encode_i64_slice(&values)?;
    assert_eq!(adaptive.decode_i64_vec(&encoded)?, values);
    let mut decoded_values = [0_i64; 5];
    adaptive.decode_i64_slice_into(&mut decoded_values, &encoded)?;
    assert_eq!(decoded_values, values);
    let text = adaptive.encode_string("telemetry/primary/healthy")?;
    assert_eq!(adaptive.decode_string(&text)?, "telemetry/primary/healthy");
    let mut decoded_text = [0_u8; 64];
    assert_eq!(
        adaptive.decode_string_into_slice(&mut decoded_text, &text)?,
        "telemetry/primary/healthy"
    );

    // Deterministic CBOR can be compressed before authenticated encryption.
    let secure = protocol
        .with_cbor_format()
        .with_deterministic_encoding()
        .with_zstd_compression(3)
        .with_compression_threshold(64)
        .with_encryption(EncryptionKey::new([0xA5; 32]));
    let encrypted = secure.serialize(&value)?;
    assert_eq!(secure.deserialize::<Telemetry>(&encrypted)?, value);

    let batch = protocol.with_parallel_serialization();
    let batch_frame = batch.serialize_batch(&[&value, &value])?;
    let batch_values: Vec<Telemetry> = batch.deserialize_batch(&batch_frame)?;
    assert_eq!(batch_values, vec![value.clone(), value]);

    println!(
        "SIMD: {:?} ({:?})",
        rustbinary::simd_backend(),
        hardware_capabilities()
    );
    Ok(())
}
