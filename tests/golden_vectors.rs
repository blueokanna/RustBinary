#[test]
fn core_compact_and_legacy_vectors_are_stable() {
    let value = (251_u64, -2_i32, "A");
    let compact = [
        0x0a, // tuple array
        3, 251, 251, 0, // u64 251 (tag + marker varint)
        5, 3, // i32 -2 (tag + zigzag)
        9, 1, b'A', // "A"
        0xff, // tuple end
    ];
    let legacy = [
        0x0a, // tuple array
        3, 251, 0, 0, 0, 0, 0, 0, 0, // u64 251 (fixed width)
        5, 254, 255, 255, 255, 255, 255, 255, 255, // i32 -2 (fixed width)
        9, 1, 0, 0, 0, 0, 0, 0, 0, b'A', // "A" (fixed-u64 length)
        0xff, // tuple end
    ];

    let mut compact_output = [0_u8; 32];
    let compact_written = rustbinary::core::options()
        .serialize_into_slice(&mut compact_output, &value)
        .unwrap();
    assert_eq!(&compact_output[..compact_written], compact);
    assert_eq!(
        rustbinary::core::options()
            .deserialize::<(u64, i32, String)>(&compact)
            .unwrap(),
        (251, -2, "A".to_owned())
    );
    let mut legacy_output = [0_u8; 32];
    let legacy_written = rustbinary::core::legacy_options()
        .serialize_into_slice(&mut legacy_output, &value)
        .unwrap();
    assert_eq!(&legacy_output[..legacy_written], legacy);
    assert_eq!(
        rustbinary::core::legacy_options()
            .deserialize::<(u64, i32, String)>(&legacy)
            .unwrap(),
        (251, -2, "A".to_owned())
    );
}

#[cfg(all(feature = "derive", feature = "bit-packing"))]
#[derive(Debug, PartialEq, rustbinary::protocol::BitPacked)]
struct PackedHeader {
    active: bool,
    #[bits = 3]
    mode: u8,
    #[bits = 12]
    sequence: u16,
}

#[cfg(all(feature = "derive", feature = "bit-packing"))]
#[test]
fn protocol_bit_packed_vector_is_stable() {
    let value = PackedHeader {
        active: true,
        mode: 5,
        sequence: 0xabc,
    };
    let golden = [0xcb, 0xab];
    let config = rustbinary::options().with_bit_packing();
    assert_eq!(config.serialize(&value).unwrap(), golden);
    assert_eq!(config.deserialize::<PackedHeader>(&golden).unwrap(), value);
}

#[cfg(feature = "adaptive")]
#[test]
fn protocol_adaptive_delta_vector_is_stable() {
    let values = [1_000_i64, 1_001, 1_002, 1_003];
    let golden = [1, 4, 251, 208, 7, 2, 2, 2];
    let config = rustbinary::options().with_adaptive_encoding();
    let mut encoded = [0_u8; 16];
    let written = config
        .encode_i64_slice_into_slice(&mut encoded, &values)
        .unwrap();
    assert_eq!(&encoded[..written], golden);

    let mut decoded = [0_i64; 4];
    assert_eq!(
        config.decode_i64_slice_into(&mut decoded, &golden).unwrap(),
        values.len()
    );
    assert_eq!(decoded, values);
}

#[cfg(all(feature = "derive", feature = "fingerprint"))]
#[derive(nextjson::NsonDeserialize, rustbinary::protocol::Fingerprint, nextjson::NsonSerialize)]
struct FingerprintedRecord {
    id: u16,
    active: bool,
}

#[cfg(all(feature = "derive", feature = "fingerprint"))]
#[test]
fn protocol_fingerprint_vector_is_stable() {
    let value = FingerprintedRecord {
        id: 251,
        active: true,
    };
    let frame = rustbinary::options()
        .with_fingerprint()
        .serialize(&value)
        .unwrap();
    let golden = [
        b'R', b'B', b'F', b'P', 1, 0, 0, 0, 78, 190, 14, 153, 0, 102, 91, 209,  // header
        0x0b, // object
        9, 2, b'i', b'd', 3, 251, 251, 0, // id = 251
        9, 6, b'a', b'c', b't', b'i', b'v', b'e', 2,    // active = true
        0xff, // object end
    ];
    assert_eq!(frame, golden);
    rustbinary::options()
        .with_fingerprint()
        .deserialize::<FingerprintedRecord>(&golden)
        .unwrap();
}

#[cfg(feature = "schema-evolution")]
#[derive(Debug, PartialEq)]
struct EvolvingRecord {
    active: bool,
    id: u16,
}

#[cfg(feature = "schema-evolution")]
impl rustbinary::protocol::SchemaEncode for EvolvingRecord {
    const SCHEMA_ID: u64 = 0x0102_0304_0506_0708;
    const SCHEMA_VERSION: u32 = 2;

    fn encode_fields(
        &self,
        encoder: &mut rustbinary::protocol::FieldEncoder,
    ) -> rustbinary::Result<()> {
        encoder.field(2, &self.id)?;
        encoder.field(1, &self.active)
    }
}

#[cfg(feature = "schema-evolution")]
impl<'de> rustbinary::protocol::SchemaDecode<'de> for EvolvingRecord {
    const SCHEMA_ID: u64 = <Self as rustbinary::protocol::SchemaEncode>::SCHEMA_ID;

    fn decode_fields(
        decoder: &mut rustbinary::protocol::FieldDecoder<'de>,
        encoded_version: u32,
    ) -> rustbinary::Result<Self> {
        if encoded_version != 2 {
            return Err(rustbinary::Error::SchemaEvolution(
                "unsupported test schema revision",
            ));
        }
        Ok(Self {
            active: decoder.required(1)?,
            id: decoder.required(2)?,
        })
    }
}

#[cfg(feature = "schema-evolution")]
#[test]
fn protocol_evolution_vector_is_stable() {
    let value = EvolvingRecord {
        active: true,
        id: 0x0102,
    };
    // Field payloads use the self-describing binary format: active = [2],
    // id 0x0102 = [3, 251, 2, 1].
    let golden = [
        b'R', b'B', b'E', b'1', 1, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1, 2, 0, 0, 0, 2, 0, 0, 0,
        // field 1: active = true
        1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, // field 2: id = 0x0102
        2, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 3, 251, 2, 1,
    ];
    let config = rustbinary::options().with_schema_evolution();
    assert_eq!(config.serialize(&value).unwrap(), golden);
    assert_eq!(
        config.deserialize::<EvolvingRecord>(&golden).unwrap(),
        value
    );
}

#[cfg(feature = "cbor")]
#[test]
fn pipeline_deterministic_cbor_vector_is_stable() {
    let value = (1_u8, "A");
    // nextjson relays JSON-compatible events into indefinite-length CBOR.
    let golden = [0x9f, 0x01, 0x61, b'A', 0xff];
    let config: rustbinary::pipeline::CborConfig = rustbinary::options()
        .with_cbor_format()
        .with_deterministic_encoding();
    assert_eq!(config.serialize(&value).unwrap(), golden);
    assert_eq!(
        config.deserialize::<(u8, String)>(&golden).unwrap(),
        (1, "A".to_owned())
    );
}

#[cfg(feature = "compression")]
#[test]
fn pipeline_raw_compression_vector_is_stable() {
    // The uncompressed payload of 7u8 is [3, 7] (tag + varint).
    let golden = [
        b'R', b'B', b'Z', b'1', 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 7,
    ];
    let config: rustbinary::pipeline::CompressedConfig =
        rustbinary::options().with_zstd_compression(3);
    assert_eq!(config.serialize(&7_u8).unwrap(), golden);
    assert_eq!(config.deserialize::<u8>(&golden).unwrap(), 7);
}

#[cfg(feature = "parallel")]
#[test]
fn pipeline_parallel_vector_is_stable() {
    // Element payloads are [3, 1] and [3, 251, 251, 0] under the compact profile.
    let golden = [
        b'R', b'B', b'P', b'1', 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 4, 0,
        0, 0, 0, 0, 0, 0, // length table
        3, 1, // 1u16
        3, 251, 251, 0, // 251u16
    ];
    let config: rustbinary::pipeline::ParallelConfig =
        rustbinary::options().with_parallel_serialization();
    assert_eq!(config.serialize_batch(&[1_u16, 251]).unwrap(), golden);
    assert_eq!(config.deserialize_batch::<u16>(&golden).unwrap(), [1, 251]);
}

#[cfg(feature = "encryption")]
#[test]
fn pipeline_encryption_decoder_vector_is_stable() {
    let key = rustbinary::EncryptionKey::new([0x42; 32]);
    let config = rustbinary::options().with_encryption(key);
    // Plaintext is the self-describing encoding of 7u8: [3, 7].
    let golden = [
        82, 66, 88, 49, 1, 0, 1, 0, 164, 151, 179, 104, 196, 1, 210, 153, 150, 34, 206, 174, 95,
        128, 33, 17, 249, 19, 52, 173, 208, 104, 36, 210, 2, 0, 0, 0, 0, 0, 0, 0, 18, 0, 0, 0, 0,
        0, 0, 0, 29, 51, 248, 74, 186, 101, 55, 63, 223, 65, 162, 99, 27, 56, 149, 10, 35, 15,
    ];
    assert_eq!(config.deserialize::<u8>(&golden).unwrap(), 7);

    let fresh = config.serialize(&7_u8).unwrap();
    assert_ne!(
        fresh, golden,
        "fresh encryption must not reuse the golden nonce"
    );
    assert_eq!(config.deserialize::<u8>(&fresh).unwrap(), 7);
}
