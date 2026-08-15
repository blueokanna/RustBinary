#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

//! `RustBinary` is a bounded **nextjson** binary codec with explicit wire
//! profiles.
//!
//! Serialization is driven entirely by nextjson's format-neutral contracts
//! ([`nextjson::NsonSerialize`] / [`nextjson::NsonDeserialize`] +
//! [`nextjson::FormatEncoder`] / [`nextjson::FormatDecoder`]), replacing the
//! former Serde dependency. The binary wire format is a type-tagged,
//! self-describing stream: every value carries a one-byte type tag and
//! containers are terminator-delimited, so `Option`, `Value`, untagged enums
//! and borrowed strings all round-trip unambiguously.
//!
//! The top-level functions and [`options`] select the strict compact profile:
//! canonical marker varints, ZigZag signed integers, bounded input, and
//! rejected trailing bytes. [`legacy_options`] explicitly selects the old
//! fixed-width, unbounded migration profile. Format-changing systems are
//! explicit wrappers, so enabling a Cargo feature never silently changes an
//! existing payload.
//!
//! # Quick start
//!
//! ```
//! use nextjson::{NsonDeserialize, NsonSerialize};
//!
//! #[derive(Debug, PartialEq, NsonSerialize, NsonDeserialize)]
//! struct Packet<'a> {
//!     sequence: u64,
//!     topic: &'a str,
//!     #[njson(borrow)]
//!     note: &'a str,
//! }
//!
//! let config = rustbinary::options()
//!     .with_limit(4096)
//!     .with_collection_limit(256);
//! let packet = Packet {
//!     sequence: 42,
//!     topic: "telemetry/temperature",
//!     note: "ok",
//! };
//!
//! let mut frame = [0_u8; 256];
//! let written = config.serialize_into_slice(&mut frame, &packet)?;
//! let decoded: Packet<'_> = config.deserialize(&frame[..written])?;
//! assert_eq!(decoded, packet);
//! # Ok::<(), rustbinary::Error>(())
//! ```
//!
//! Borrowed strings point into the input frame. Owned targets such as
//! `String` and `Vec<T>` may allocate as required by their type.
//!
//! # Format selection
//!
//! - [`Config`] is the core binary profile.
//! - `adaptive` contains canonical cost-selected string and integer frames.
//! - `bitpack` provides generated bit-level layouts.
//! - `cbor` provides RFC 8949 payloads and deterministic map ordering.
//! - `evolution` provides stable-field-ID schema evolution.
//! - `compression` and `encryption` form an ordered transform pipeline.
//! - `parallel` encodes independent records into deterministic batch frames.
//!
//! # Untrusted input
//!
//! Always set both [`Config::with_limit`] and
//! [`Config::with_collection_limit`] at trust boundaries. Encryption authenticates
//! bytes but does not replace resource limits. Schema fingerprints detect
//! accidental type/configuration drift; they are not cryptographic hashes.

extern crate self as rustbinary;

// nextjson's `FormatDecoder` contract returns `Cow<'de, str>`, so the core
// always links `alloc` (matching nextjson, which is `no_std` + `alloc`).
// The `alloc` Cargo feature remains as a compatibility marker.
extern crate alloc;

#[cfg(feature = "std")]
/// Bridges between the slice-based core and `std::io` readers and writers.
pub mod adapters;

#[cfg(feature = "adaptive")]
/// Canonical data-aware encodings for strings and integer collections.
pub mod adaptive;
#[cfg(feature = "archive")]
/// Validated relative-pointer archives for read-only memory mapping.
pub mod archive;
#[cfg(feature = "bit-packing")]
/// Bit-level caller-buffer codecs and the [`BitPack`] contract.
pub mod bitpack;
/// Canonical little-endian varint/ZigZag primitives (single source of truth).
mod canonical;
#[cfg(feature = "cbor")]
/// RFC 8949 CBOR configuration and deterministic encoding.
pub mod cbor;
#[cfg(feature = "compression")]
/// Adaptive Zstandard framing.
pub mod compression;
/// Core wire-profile configuration.
pub mod config;
/// Minimal stable binary codec product surface.
pub mod core;
mod decoder;
#[cfg(feature = "reconcile")]
/// Baseline-relative differential frames for ordered state.
pub mod delta;
#[cfg(feature = "encryption")]
/// Authenticated XChaCha20-Poly1305 framing.
pub mod encryption;
/// Codec result and error types.
pub mod error;
#[cfg(feature = "schema-evolution")]
/// Stable-field-ID schema evolution.
pub mod evolution;
#[cfg(feature = "fingerprint")]
mod frame;
/// Dependency-free SHA-256 for the archive Merkle tree.
#[cfg(feature = "archive")]
mod hash;
#[cfg(feature = "reconcile")]
/// Invertible Bloom Lookup Tables for unordered set reconciliation.
pub mod ibl;
#[cfg(kani)]
/// Kani formal-verification harnesses for the Core layer.
mod kani_proofs;
#[cfg(feature = "parallel")]
/// Ordered multi-core batch encoding and decoding.
pub mod parallel;
/// Optional transform product surface.
pub mod pipeline;
/// Schema and wire-governance product surface.
pub mod protocol;
#[cfg(feature = "entropy")]
/// Static-model rANS entropy coding driven by schema metadata.
pub mod rans;
#[cfg(feature = "reflection")]
/// Allocation-free structural metadata generated by [`Reflect`].
pub mod reflection;
#[cfg(feature = "fingerprint")]
/// Compile-time schema identity and fingerprinted frame support.
pub mod schema;
mod ser;
#[cfg(feature = "simd")]
pub mod simd;
#[cfg(feature = "static-size")]
/// Compile-time upper bounds for statically sized data.
pub mod static_size;
/// Shared wire-format tag constants.
mod tags;
#[cfg(feature = "trust")]
/// Type-level trust calculus and session state machine.
pub mod trust;
/// Core output sinks for caller-owned and counting serialization.
pub mod writer;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::io::{Read, Write};

#[cfg(feature = "adaptive")]
pub use adaptive::{AdaptiveConfig, CollectionStrategy, StringStrategy};
#[cfg(feature = "bit-packing")]
pub use bitpack::{BitPack, BitPackedConfig, BitReader, BitValue, BitWriter};
#[cfg(feature = "cbor")]
pub use cbor::CborConfig;
#[cfg(all(feature = "cbor", feature = "fingerprint"))]
pub use cbor::FingerprintedCborConfig;
#[cfg(feature = "compression")]
pub use compression::CompressedConfig;
pub use config::{
    Config, Endian, IntEncoding, Options, TrailingBytes, DEFAULT_COLLECTION_LIMIT,
    DEFAULT_SIZE_LIMIT,
};
#[cfg(feature = "reconcile")]
pub use delta::{DeltaConfig, DeltaTable};
#[cfg(feature = "encryption")]
pub use encryption::{EncryptedConfig, EncryptionKey};
pub use error::{Error, ErrorCategory, Result};
#[cfg(feature = "schema-evolution")]
pub use evolution::{
    EvolutionConfig, FieldDecoder, FieldEncoder, SchemaDecode, SchemaEncode, UnknownField,
};
#[cfg(feature = "reconcile")]
pub use ibl::{encode_set, reconcile, splitmix64, Cell, Iblt, IbltEntry};
#[cfg(feature = "parallel")]
pub use parallel::ParallelConfig;
#[cfg(feature = "entropy")]
pub use rans::{EntropyConfig, FieldModel, Model, RansDecoder, RansEncoder, SchemaModel, RANS_M};
#[cfg(feature = "reflection")]
pub use reflection::{FieldInfo, Reflect, TypeShape, VariantInfo};
#[cfg(feature = "fingerprint")]
pub use schema::{Fingerprint, FingerprintedConfig};
#[cfg(feature = "simd")]
pub use simd::{hardware_capabilities, simd_backend, HardwareCapabilities, SimdBackend};
#[cfg(feature = "static-size")]
pub use static_size::StaticSize;
#[cfg(feature = "trust")]
pub use trust::{
    AuthLevel, Authenticated, Closed, Codec, Handshake, Session, TrustedConfig, Untrusted,
    Verified, Verifier,
};
pub use writer::{CountWriter, EncodeWriter, SliceWriter};

#[cfg(all(feature = "derive", feature = "bit-packing"))]
pub use rustbinary_derive::BitPacked;

#[cfg(feature = "bit-packing")]
#[doc(hidden)]
pub const fn __bitpack_max(left: usize, right: usize) -> usize {
    if left > right {
        left
    } else {
        right
    }
}
#[cfg(all(feature = "derive", feature = "fingerprint"))]
pub use rustbinary_derive::Fingerprint;
#[cfg(all(feature = "derive", feature = "reflection"))]
pub use rustbinary_derive::Reflect;
#[cfg(all(feature = "derive", feature = "static-size"))]
pub use rustbinary_derive::StaticSize;

/// Re-exports nextjson's format-neutral serialization contracts.
///
/// `NsonSerialize` and `NsonDeserialize` are both traits and derive macros, so
/// `#[derive(rustbinary::NsonSerialize, rustbinary::NsonDeserialize)]` works.
/// Generated code refers to the `::nextjson` crate, so applications must also
/// depend on `nextjson` (the framework this codec is built on).
#[cfg(feature = "derive")]
pub use nextjson::{NsonDeserialize, NsonSchema, NsonSerialize};

/// Returns the standard compact profile.
pub const fn options() -> Config {
    Config::standard()
}

/// Returns the fixed-width compatibility profile used by the top-level API.
pub const fn legacy_options() -> Config {
    Config::legacy()
}

/// Serializes a value with the bounded compact Core profile.
#[cfg(feature = "alloc")]
pub fn serialize<T: nextjson::NsonSerialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    Config::standard().serialize(value)
}

/// Serializes a value directly into a writer with the bounded compact Core profile.
#[cfg(feature = "std")]
pub fn serialize_into<W: Write, T: nextjson::NsonSerialize + ?Sized>(
    writer: W,
    value: &T,
) -> Result<()> {
    Config::standard().serialize_into(writer, value)
}

/// Serializes into a caller-owned slice without codec-owned heap allocation.
///
/// Returns the initialized byte count. [`Error::BufferTooSmall`] contains the
/// exact required capacity when `output` is undersized. User-defined
/// [`nextjson::NsonSerialize`] implementations remain responsible for their own
/// allocations.
pub fn serialize_into_slice<T: nextjson::NsonSerialize + ?Sized>(
    output: &mut [u8],
    value: &T,
) -> Result<usize> {
    Config::standard().serialize_into_slice(output, value)
}

/// Computes the exact serialized byte count without allocating an output buffer.
pub fn serialized_size<T: nextjson::NsonSerialize + ?Sized>(value: &T) -> Result<u64> {
    Config::standard().serialized_size(value)
}

/// Deserializes from a slice with the bounded compact Core profile.
///
/// The returned value may borrow strings from `input`.
pub fn deserialize<'de, T: nextjson::NsonDeserialize<'de>>(input: &'de [u8]) -> Result<T> {
    Config::standard().deserialize(input)
}

/// Deserializes an owned value from a reader with the bounded compact Core profile.
#[cfg(feature = "std")]
pub fn deserialize_from<R: Read, T: for<'de> nextjson::NsonDeserialize<'de>>(
    reader: R,
) -> Result<T> {
    Config::standard().deserialize_from(reader)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use std::{
        cell::Cell,
        collections::BTreeMap,
        io::{self, Cursor, Write},
    };

    #[cfg(feature = "cbor")]
    use std::collections::HashMap;

    use super::*;

    #[derive(Debug, PartialEq, nextjson::NsonSerialize, nextjson::NsonDeserialize)]
    struct Record<'a> {
        id: u64,
        delta: i32,
        #[njson(borrow)]
        name: &'a str,
        payload: Vec<u8>,
        enabled: Option<bool>,
    }

    #[derive(Debug, PartialEq, nextjson::NsonSerialize, nextjson::NsonDeserialize)]
    struct BorrowedEnvelope<'a> {
        #[njson(borrow)]
        name: &'a str,
        #[njson(borrow)]
        payload: &'a str,
        nested: BorrowedMetadata<'a>,
    }

    #[derive(Debug, PartialEq, nextjson::NsonSerialize, nextjson::NsonDeserialize)]
    struct BorrowedMetadata<'a> {
        #[njson(borrow)]
        source: &'a str,
    }

    #[derive(Debug, PartialEq, nextjson::NsonSerialize, nextjson::NsonDeserialize)]
    enum Event {
        Idle,
        Data(u16),
        Point { x: i64, y: i64 },
    }

    #[cfg(all(
        feature = "fingerprint",
        feature = "reflection",
        feature = "static-size"
    ))]
    #[derive(
        Debug,
        nextjson::NsonSerialize,
        nextjson::NsonDeserialize,
        crate::Fingerprint,
        crate::Reflect,
        crate::StaticSize,
    )]
    struct ProtocolRecord {
        enabled: bool,
        count: u16,
        coordinates: [i32; 2],
    }

    #[cfg(all(
        feature = "fingerprint",
        feature = "reflection",
        feature = "static-size"
    ))]
    #[derive(nextjson::NsonSerialize, nextjson::NsonDeserialize, crate::Fingerprint)]
    struct ChangedProtocolRecord {
        count: u16,
        enabled: bool,
        coordinates: [i32; 2],
    }

    #[cfg(all(feature = "reflection", feature = "derive"))]
    #[derive(crate::Reflect)]
    enum ReflectedEvent {
        Empty,
        Tuple(u8, bool),
        Named { code: u16 },
    }

    #[cfg(all(feature = "bit-packing", feature = "static-size"))]
    #[derive(Debug, PartialEq, crate::BitPacked, crate::StaticSize)]
    struct PackedHeader {
        #[bits = 3]
        mode: u8,
        enabled: bool,
        #[bits = 7]
        delta: i16,
    }

    #[cfg(feature = "bit-packing")]
    #[derive(Debug, PartialEq, crate::BitPacked)]
    enum PackedEvent {
        Empty,
        Flag(bool),
        Code(#[bits = 4] u8),
    }

    #[cfg(feature = "schema-evolution")]
    #[derive(Debug, PartialEq)]
    struct SchemaV1 {
        name: String,
        count: u32,
    }

    #[cfg(feature = "schema-evolution")]
    impl SchemaEncode for SchemaV1 {
        const SCHEMA_ID: u64 = 0x4859_5048_454e_0001;
        const SCHEMA_VERSION: u32 = 1;

        fn encode_fields(&self, encoder: &mut FieldEncoder) -> Result<()> {
            // Deliberately submitted out of order; the frame must canonicalize IDs.
            encoder.field(2, &self.count)?;
            encoder.field(1, &self.name)
        }
    }

    #[cfg(feature = "schema-evolution")]
    impl<'de> SchemaDecode<'de> for SchemaV1 {
        const SCHEMA_ID: u64 = <Self as SchemaEncode>::SCHEMA_ID;

        fn decode_fields(decoder: &mut FieldDecoder<'de>, _version: u32) -> Result<Self> {
            Ok(Self {
                name: decoder.required(1)?,
                count: decoder.required(2)?,
            })
        }
    }

    #[cfg(feature = "schema-evolution")]
    #[derive(Debug, PartialEq)]
    struct SchemaV2<'a> {
        title: &'a str,
        count: u32,
        active: bool,
        source_version: u32,
    }

    #[cfg(feature = "schema-evolution")]
    impl SchemaEncode for SchemaV2<'_> {
        const SCHEMA_ID: u64 = <SchemaV1 as SchemaEncode>::SCHEMA_ID;
        const SCHEMA_VERSION: u32 = 2;

        fn encode_fields(&self, encoder: &mut FieldEncoder) -> Result<()> {
            encoder.field(1, self.title)?;
            encoder.field(2, &self.count)?;
            encoder.field(3, &self.active)
        }
    }

    #[cfg(feature = "schema-evolution")]
    impl<'de> SchemaDecode<'de> for SchemaV2<'de> {
        const SCHEMA_ID: u64 = <SchemaV1 as SchemaEncode>::SCHEMA_ID;

        fn decode_fields(decoder: &mut FieldDecoder<'de>, version: u32) -> Result<Self> {
            Ok(Self {
                title: decoder.required(1)?,
                count: decoder.required(2)?,
                active: decoder.or_default(3)?,
                source_version: version,
            })
        }
    }

    #[cfg(feature = "schema-evolution")]
    struct OtherSchema;

    #[cfg(feature = "schema-evolution")]
    impl<'de> SchemaDecode<'de> for OtherSchema {
        const SCHEMA_ID: u64 = 0xdead_beef;

        fn decode_fields(_decoder: &mut FieldDecoder<'de>, _version: u32) -> Result<Self> {
            Ok(Self)
        }
    }

    #[cfg(all(feature = "bit-packing", feature = "static-size"))]
    #[test]
    fn bit_packed_struct_and_enum_round_trip_within_static_bounds() {
        let config = options().with_bit_packing();
        for header in [
            PackedHeader {
                mode: 0,
                enabled: false,
                delta: -1,
            },
            PackedHeader {
                mode: 7,
                enabled: true,
                delta: 63,
            },
        ] {
            let bytes = config.serialize(&header).unwrap();
            assert_eq!(config.deserialize::<PackedHeader>(&bytes).unwrap(), header);
            assert!(bytes.len() <= PackedHeader::PACKED_MAX_SIZE);
        }
        const { assert!(PackedHeader::MAX_SIZE > 0) };
        const { assert!(PackedHeader::PACKED_MAX_BITS > 0) };

        for event in [
            PackedEvent::Empty,
            PackedEvent::Flag(true),
            PackedEvent::Code(15),
        ] {
            let bytes = config.serialize(&event).unwrap();
            assert_eq!(config.deserialize::<PackedEvent>(&bytes).unwrap(), event);
        }
    }

    #[cfg(feature = "schema-evolution")]
    #[test]
    fn schema_evolution_is_forward_compatible_and_rejects_foreign_ids() {
        let config = options().with_schema_evolution();

        // V1 frame (fields submitted out of order; frame canonicalizes IDs).
        let v1 = SchemaV1 {
            name: "alpha".into(),
            count: 7,
        };
        let v1_bytes = config.serialize(&v1).unwrap();

        // V2 decodes a V1 frame: the new `active` field defaults and the
        // encoded revision is reported for explicit migrations.
        let decoded_v2: SchemaV2<'_> = config.deserialize(&v1_bytes).unwrap();
        assert_eq!(
            decoded_v2,
            SchemaV2 {
                title: "alpha",
                count: 7,
                active: false,
                source_version: SchemaV1::SCHEMA_VERSION,
            }
        );

        // V2 round-trips its own frame with the encoded revision reported.
        let v2 = SchemaV2 {
            title: "beta",
            count: 9,
            active: true,
            source_version: 0,
        };
        let v2_bytes = config.serialize(&v2).unwrap();
        assert_eq!(
            config.deserialize::<SchemaV2<'_>>(&v2_bytes).unwrap(),
            SchemaV2 {
                title: "beta",
                count: 9,
                active: true,
                source_version: SchemaV2::SCHEMA_VERSION,
            }
        );

        // A schema with a different stable ID must reject the frame.
        assert!(matches!(
            config.deserialize::<OtherSchema>(&v1_bytes),
            Err(Error::SchemaMismatch {
                expected: 0xdead_beef,
                actual: <SchemaV1 as SchemaEncode>::SCHEMA_ID
            })
        ));
    }

    #[test]
    fn legacy_fixed_vector_is_stable() {
        let legacy = legacy_options();
        let bytes = legacy
            .serialize(&(0x0102u16, -2i32, "A", Event::Data(9)))
            .unwrap();
        // Fixed-width integers are always written at u64 width in the unified
        // nextjson data model; lengths are also fixed u64.
        assert_eq!(
            bytes,
            [
                0x0a, // tuple array
                0x03, 0x02, 0x01, 0, 0, 0, 0, 0, 0, // u16 0x0102 as fixed u64 LE
                0x05, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, // i32 -2 as fixed i64 LE
                0x09, 1, 0, 0, 0, 0, 0, 0, 0, b'A', // "A": fixed u64 length
                0x0b, // external enum object
                0x09, 4, 0, 0, 0, 0, 0, 0, 0, b'D', b'a', b't', b'a', // "Data"
                0x03, 9, 0, 0, 0, 0, 0, 0, 0,    // Data(9): fixed u64 LE
                0xff, // enum object end
                0xff, // tuple end
            ]
        );
        assert_eq!(
            legacy
                .deserialize::<(u16, i32, String, Event)>(&bytes)
                .unwrap(),
            (0x0102, -2, "A".into(), Event::Data(9))
        );
    }

    #[test]
    fn compact_varints_cover_boundaries_and_signed_values() {
        let config = options();
        for value in [
            0u128,
            250,
            251,
            u16::MAX as u128,
            u16::MAX as u128 + 1,
            u32::MAX as u128 + 1,
            u64::MAX as u128 + 1,
            u128::MAX,
        ] {
            let bytes = config.serialize(&value).unwrap();
            assert_eq!(config.deserialize::<u128>(&bytes).unwrap(), value);
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
            let bytes = config.serialize(&value).unwrap();
            assert_eq!(config.deserialize::<i128>(&bytes).unwrap(), value);
        }
        assert_eq!(config.serialize(&250u64).unwrap(), [3, 250]);
        assert_eq!(config.serialize(&251u64).unwrap(), [3, 251, 251, 0]);
    }

    #[test]
    fn compact_v1_golden_vectors_are_stable() {
        let compact = options();
        let unsigned: &[(u64, &[u8])] = &[
            (0, &[3, 0]),
            (250, &[3, 250]),
            (251, &[3, 251, 251, 0]),
            (65_535, &[3, 251, 255, 255]),
            (65_536, &[3, 252, 0, 0, 1, 0]),
            (4_294_967_296, &[3, 253, 0, 0, 0, 0, 1, 0, 0, 0]),
        ];
        for &(value, golden) in unsigned {
            assert_eq!(compact.serialize(&value).unwrap(), golden);
            assert_eq!(compact.deserialize::<u64>(golden).unwrap(), value);
        }

        let record = Record {
            id: 42,
            delta: -7,
            name: "zero-copy",
            payload: vec![0, 1, 255],
            enabled: Some(true),
        };
        let golden = [
            0x0b, // object
            0x09, 2, b'i', b'd', 0x03, 42, // id = 42
            0x09, 5, b'd', b'e', b'l', b't', b'a', 0x05, 13, // delta = -7 (zigzag)
            0x09, 4, b'n', b'a', b'm', b'e', 0x09, 9, b'z', b'e', b'r', b'o', b'-', b'c', b'o',
            b'p', b'y', // name = "zero-copy"
            0x09, 7, b'p', b'a', b'y', b'l', b'o', b'a', b'd', 0x0a, // payload array
            0x03, 0, 0x03, 1, 0x03, 251, 255, 0,    // [0, 1, 255]
            0xff, // payload end
            0x09, 7, b'e', b'n', b'a', b'b', b'l', b'e', b'd', 0x02, // enabled = true
            0xff, // object end
        ];
        assert_eq!(compact.serialize(&record).unwrap(), golden);
        assert_eq!(compact.deserialize::<Record<'_>>(&golden).unwrap(), record);

        let big_fixed = compact.with_big_endian().with_fixint_encoding();
        assert_eq!(
            big_fixed.serialize(&(0x0102u16, -2i32, 1.5f32)).unwrap(),
            [
                0x0a, // tuple array
                0x03, 0, 0, 0, 0, 0, 0, 1, 2, // u16 0x0102 as fixed u64 BE
                0x05, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xfe, // i32 -2 as fixed i64 BE
                0x08, 0x3f, 0xc0, 0x00, 0x00, // f32 1.5, big endian
                0xff, // tuple end
            ]
        );
    }

    #[test]
    fn round_trips_full_data_model_and_borrows_strings() {
        let record = Record {
            id: 42,
            delta: -7,
            name: "zero-copy",
            payload: vec![0, 1, 255],
            enabled: Some(true),
        };
        let bytes = options().serialize(&record).unwrap();
        let decoded: Record<'_> = options().deserialize(&bytes).unwrap();
        assert_eq!(decoded, record);
        let start = bytes.as_ptr() as usize;
        assert!((start..start + bytes.len()).contains(&(decoded.name.as_ptr() as usize)));

        for event in [
            Event::Idle,
            Event::Data(65535),
            Event::Point { x: -9, y: 17 },
        ] {
            let encoded = options().serialize(&event).unwrap();
            assert_eq!(options().deserialize::<Event>(&encoded).unwrap(), event);
        }
    }

    #[test]
    fn nested_borrowed_fields_point_into_the_input_frame() {
        let value = BorrowedEnvelope {
            name: "zero-copy",
            payload: "borrowed-payload",
            nested: BorrowedMetadata { source: "edge-07" },
        };
        let config = options().with_limit(1024);
        let frame = config.serialize(&value).unwrap();
        let decoded: BorrowedEnvelope<'_> = config.deserialize(&frame).unwrap();
        assert_eq!(decoded, value);

        let start = frame.as_ptr() as usize;
        let end = start + frame.len();
        for borrowed in [
            decoded.name.as_bytes(),
            decoded.payload.as_bytes(),
            decoded.nested.source.as_bytes(),
        ] {
            let pointer = borrowed.as_ptr() as usize;
            assert!(pointer >= start && pointer + borrowed.len() <= end);
        }
    }

    #[test]
    fn supports_endianness_floats_chars_maps_and_non_finite_values() {
        assert_eq!(
            options()
                .with_big_endian()
                .with_fixint_encoding()
                .serialize(&0x0102u16)
                .unwrap(),
            [3, 0, 0, 0, 0, 0, 0, 1, 2]
        );
        for value in ['a', 'é', '汉', '🚀'] {
            let bytes = options().serialize(&value).unwrap();
            assert_eq!(options().deserialize::<char>(&bytes).unwrap(), value);
        }
        let map = BTreeMap::from([
            ("one".to_owned(), "1".to_owned()),
            ("two".to_owned(), "2".to_owned()),
        ]);
        let bytes = options().serialize(&map).unwrap();
        assert_eq!(
            options()
                .deserialize::<BTreeMap<String, String>>(&bytes)
                .unwrap(),
            map
        );
        let nan = f64::NAN;
        assert!(options()
            .deserialize::<f64>(&options().serialize(&nan).unwrap())
            .unwrap()
            .is_nan());
    }

    #[test]
    fn streaming_size_limits_and_trailing_policy_are_enforced() {
        let value = vec![1u32, 2, 3, 65_536];
        let config = options().with_limit(64);
        let mut stream = Vec::new();
        config.serialize_into(&mut stream, &value).unwrap();
        assert_eq!(config.serialized_size(&value).unwrap(), stream.len() as u64);
        assert_eq!(
            config
                .deserialize_from::<_, Vec<u32>>(Cursor::new(&stream))
                .unwrap(),
            value
        );
        assert!(matches!(
            options().with_limit(2).serialize(&u64::MAX),
            Err(Error::SizeLimit { limit: 2 })
        ));

        let mut trailing = options().serialize(&7u8).unwrap();
        trailing.push(8);
        assert!(matches!(
            options().deserialize::<u8>(&trailing),
            Err(Error::TrailingBytes { remaining: 1 })
        ));
        assert_eq!(
            options()
                .allow_trailing_bytes()
                .deserialize::<u8>(&trailing)
                .unwrap(),
            7
        );
    }

    #[test]
    fn malformed_inputs_are_rejected_without_panics() {
        // A raw bool tag is unambiguous in the self-describing format.
        assert!(options().deserialize::<bool>(&[2]).unwrap());
        assert!(matches!(
            options().deserialize::<Option<u8>>(&[3]),
            Err(Error::UnexpectedEnd)
        ));
        assert!(matches!(
            options().deserialize::<u64>(&[255]),
            Err(Error::Custom(_))
        ));
        assert!(matches!(
            options().deserialize::<u64>(&[251, 1, 0]),
            Err(Error::Custom(_))
        ));
        assert!(matches!(
            options().deserialize::<char>(&[0x09, 2, b'a', b'b']),
            Err(Error::InvalidChar)
        ));
        // An array of 65 unit values exceeds the collection limit.
        let mut hostile = vec![0x0a];
        hostile.extend(std::iter::repeat_n(0x00, 65));
        hostile.push(0xff);
        assert!(matches!(
            legacy_options()
                .with_collection_limit(64)
                .deserialize::<Vec<()>>(&hostile),
            Err(Error::CollectionLimit { limit: 64 })
        ));

        for len in 0..48 {
            for fill in [0, 1, 0x7f, 0xfb, 0xff] {
                let input = vec![fill; len];
                assert!(
                    std::panic::catch_unwind(|| options().deserialize::<Record<'_>>(&input))
                        .is_ok()
                );
            }
        }
    }

    struct Stateful<'a>(&'a Cell<u8>);

    impl nextjson::NsonSchema for Stateful<'_> {
        const SCHEMA: nextjson::TypeSchema = nextjson::TypeSchema::U8;
    }
    impl nextjson::NsonSerialize for Stateful<'_> {
        fn nextencode<E: nextjson::FormatEncoder>(
            &self,
            encoder: &mut E,
        ) -> ::core::result::Result<(), E::Error> {
            let next = self.0.get() + 1;
            self.0.set(next);
            encoder.write_u64(next as u64)
        }
    }

    struct UnbalancedContainer;

    impl nextjson::NsonSchema for UnbalancedContainer {
        const SCHEMA: nextjson::TypeSchema = nextjson::TypeSchema::Seq(&nextjson::TypeSchema::Unit);
    }
    impl nextjson::NsonSerialize for UnbalancedContainer {
        fn nextencode<E: nextjson::FormatEncoder>(
            &self,
            encoder: &mut E,
        ) -> ::core::result::Result<(), E::Error> {
            // Emits a container end without a matching start.
            encoder.end_array()
        }
    }

    struct FailingWriter {
        remaining: usize,
    }

    #[cfg(any(feature = "compression", feature = "encryption"))]
    struct HeaderOnlyReader {
        header: Cursor<Vec<u8>>,
    }

    #[cfg(any(feature = "compression", feature = "encryption"))]
    impl Read for HeaderOnlyReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.header.position() == self.header.get_ref().len() as u64 {
                panic!("frame body must not be read after a rejected header");
            }
            self.header.read(output)
        }
    }

    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "test writer"));
            }
            let written = self.remaining.min(bytes.len());
            self.remaining -= written;
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn serializer_runs_once_and_io_failures_are_preserved() {
        let calls = Cell::new(0);
        assert_eq!(options().serialize(&Stateful(&calls)).unwrap(), [3, 1]);
        assert_eq!(calls.get(), 1);
        assert!(matches!(
            options().serialize(&UnbalancedContainer),
            Err(Error::Custom(_))
        ));
        let failure = options().serialize_into(FailingWriter { remaining: 2 }, &u64::MAX);
        assert!(
            matches!(failure, Err(Error::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe)
        );
    }

    #[test]
    fn slice_serialization_is_single_pass_and_allocation_free() {
        let value = (513u16, "zero allocation", vec![1u8, 2, 3]);
        let expected = options().serialize(&value).unwrap();
        let mut exact = [0u8; 64];
        let written = options().serialize_into_slice(&mut exact, &value).unwrap();
        assert_eq!(&exact[..written], expected);

        let calls = Cell::new(0);
        let mut two = [0u8; 2];
        assert_eq!(
            options()
                .serialize_into_slice(&mut two, &Stateful(&calls))
                .unwrap(),
            2
        );
        assert_eq!(calls.get(), 1);

        let mut short = [0u8; 3];
        assert!(matches!(
            options().serialize_into_slice(&mut short, &value),
            Err(Error::BufferTooSmall {
                required,
                available: 3
            }) if required == expected.len()
        ));
        assert_eq!(&short, &expected[..3]);
    }

    #[cfg(all(
        feature = "fingerprint",
        feature = "reflection",
        feature = "static-size"
    ))]
    #[test]
    fn derives_produce_checked_schema_bounds_and_reflection() {
        let value = ProtocolRecord {
            enabled: true,
            count: 513,
            coordinates: [-1, i32::MAX],
        };
        assert!(options().serialize(&value).unwrap().len() <= ProtocolRecord::MAX_SIZE);
        assert!(legacy_options().serialize(&value).unwrap().len() <= ProtocolRecord::MAX_SIZE);
        const { assert!(ProtocolRecord::MAX_SIZE > 0) };
        const { assert!(ProtocolRecord::PACKED_MAX_BITS > 0) };

        let TypeShape::Struct(fields) = ProtocolRecord::SHAPE else {
            panic!("record must reflect as a struct");
        };
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].name, "enabled");
        assert_eq!(fields[1].type_name, "u16");
        assert_eq!(fields[2].index, 2);

        let TypeShape::Enum(variants) = ReflectedEvent::SHAPE else {
            panic!("event must reflect as an enum");
        };
        let _constructed = (
            ReflectedEvent::Empty,
            ReflectedEvent::Tuple(1, true),
            ReflectedEvent::Named { code: 2 },
        );
        let ReflectedEvent::Tuple(tuple_number, tuple_flag) = _constructed.1 else {
            unreachable!()
        };
        let ReflectedEvent::Named { code: named_code } = _constructed.2 else {
            unreachable!()
        };
        assert_eq!((tuple_number, tuple_flag, named_code), (1, true, 2));
        assert_eq!(variants[1].name, "Tuple");
        assert_eq!(variants[1].fields[0].name, "0");
        assert_eq!(variants[2].fields[0].type_name, "u16");

        assert_ne!(
            ProtocolRecord::TYPE_FINGERPRINT,
            ChangedProtocolRecord::TYPE_FINGERPRINT
        );
        assert_ne!(
            ProtocolRecord::fingerprint(options()),
            ProtocolRecord::fingerprint(options().with_big_endian())
        );
        assert_ne!(
            ProtocolRecord::fingerprint(options()),
            ProtocolRecord::fingerprint(options().with_fixint_encoding())
        );
    }

    #[cfg(all(
        feature = "fingerprint",
        feature = "reflection",
        feature = "static-size"
    ))]
    #[test]
    fn fingerprint_frames_reject_schema_and_configuration_drift() {
        let value = ProtocolRecord {
            enabled: true,
            count: 7,
            coordinates: [2, 3],
        };
        let framed = options().with_fingerprint().serialize(&value).unwrap();
        let decoded: ProtocolRecord = options().with_fingerprint().deserialize(&framed).unwrap();
        assert_eq!(decoded.count, value.count);

        assert!(matches!(
            options()
                .with_fingerprint()
                .deserialize::<ChangedProtocolRecord>(&framed),
            Err(Error::SchemaMismatch { .. })
        ));
        assert!(matches!(
            options()
                .with_big_endian()
                .with_fingerprint()
                .deserialize::<ProtocolRecord>(&framed),
            Err(Error::SchemaMismatch { .. })
        ));

        let mut output = [0u8; 128];
        let written = options()
            .with_fingerprint()
            .serialize_into_slice(&mut output, &value)
            .unwrap();
        assert_eq!(&output[..written], framed);
        assert_eq!(
            options()
                .with_fingerprint()
                .serialized_size(&value)
                .unwrap(),
            written as u64
        );

        let mut corrupt = framed.clone();
        corrupt[0] = 0;
        assert!(matches!(
            options()
                .with_fingerprint()
                .deserialize::<ProtocolRecord>(&corrupt),
            Err(Error::InvalidFrame("bad fingerprint magic"))
        ));
    }

    #[cfg(feature = "cbor")]
    #[test]
    fn cbor_matches_rfc_vectors_and_deterministic_map_order() {
        // nextjson relays JSON-compatible events into CBOR; arrays and maps use
        // RFC 8949 indefinite-length forms (0x9f / 0xbf ... break 0xff).
        assert_eq!(
            options().with_cbor_format().serialize(&0u8).unwrap(),
            [0x00]
        );
        assert_eq!(
            options().with_cbor_format().serialize(&24u8).unwrap(),
            [0x18, 0x18]
        );
        assert_eq!(
            options().with_cbor_format().serialize("a").unwrap(),
            [0x61, b'a']
        );
        assert_eq!(
            options()
                .with_cbor_format()
                .serialize(&vec![1u8, 2, 3])
                .unwrap(),
            [0x9f, 0x01, 0x02, 0x03, 0xff]
        );

        let first = HashMap::from([("aa", 1u8), ("b", 2)]);
        let second = HashMap::from([("b", 2u8), ("aa", 1)]);
        let deterministic = options().with_cbor_format().with_deterministic_encoding();
        let encoded = deterministic.serialize(&first).unwrap();
        assert_eq!(encoded, deterministic.serialize(&second).unwrap());
        assert_eq!(
            encoded,
            [0xbf, 0x61, b'b', 0x02, 0x62, b'a', b'a', 0x01, 0xff]
        );
        assert_eq!(
            deterministic
                .deserialize::<HashMap<String, u8>>(&encoded)
                .unwrap(),
            HashMap::from([("aa".into(), 1), ("b".into(), 2)])
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            deterministic.deserialize::<HashMap<String, u8>>(&trailing),
            Err(Error::Cbor(_))
        ));
        assert!(matches!(
            deterministic.deserialize_from::<_, HashMap<String, u8>>(Cursor::new(&trailing)),
            Err(Error::Cbor(_))
        ));
        assert_eq!(
            options()
                .with_limit(1)
                .with_cbor_format()
                .deserialize_from::<_, u8>(Cursor::new([0x00]))
                .unwrap(),
            0
        );
        assert!(matches!(
            options()
                .with_limit(2)
                .with_cbor_format()
                .serialize(&vec![1u8, 2, 3]),
            Err(Error::SizeLimit { limit: 2 })
        ));
    }

    #[cfg(all(
        feature = "cbor",
        feature = "fingerprint",
        feature = "reflection",
        feature = "static-size"
    ))]
    #[test]
    fn cbor_fingerprint_covers_format_and_determinism() {
        let value = ProtocolRecord {
            enabled: false,
            count: 9,
            coordinates: [4, 5],
        };
        let binary = ProtocolRecord::fingerprint(options());
        let regular = options().with_cbor_format();
        let deterministic = regular.with_deterministic_encoding();
        assert_ne!(binary, regular.fingerprint::<ProtocolRecord>());
        assert_ne!(
            regular.fingerprint::<ProtocolRecord>(),
            deterministic.fingerprint::<ProtocolRecord>()
        );

        let frame = deterministic.with_fingerprint().serialize(&value).unwrap();
        let decoded: ProtocolRecord = deterministic
            .with_fingerprint()
            .deserialize(&frame)
            .unwrap();
        assert_eq!(decoded.coordinates, value.coordinates);
        assert!(matches!(
            regular
                .with_fingerprint()
                .deserialize::<ProtocolRecord>(&frame),
            Err(Error::SchemaMismatch { .. })
        ));
    }

    #[cfg(feature = "compression")]
    #[test]
    fn compression_is_adaptive_bounded_and_round_trips() {
        // In the tagged format each u8 costs a tag byte, so a 2000-element
        // array serializes to ~4000 bytes, comfortably under the limit.
        let repeated = vec![0u8; 2000];
        let compressed = options()
            .with_limit(8192)
            .with_zstd_compression(3)
            .with_compression_threshold(128);
        let frame = compressed.serialize(&repeated).unwrap();
        assert_eq!(&frame[..4], b"RBZ1");
        assert_eq!(u16::from_le_bytes([frame[6], frame[7]]), 1);
        assert!(frame.len() < repeated.len() / 4);
        assert_eq!(compressed.deserialize::<Vec<u8>>(&frame).unwrap(), repeated);

        let small = options().with_zstd_compression(3).serialize(&7u8).unwrap();
        assert_eq!(u16::from_le_bytes([small[6], small[7]]), 0);
        assert_eq!(
            options()
                .with_zstd_compression(3)
                .deserialize::<u8>(&small)
                .unwrap(),
            7
        );

        let mut hostile = frame.clone();
        hostile[8..16].copy_from_slice(&8193u64.to_le_bytes());
        assert!(matches!(
            compressed.deserialize::<Vec<u8>>(&hostile),
            Err(Error::SizeLimit { limit: 8192 })
        ));
        assert!(matches!(
            compressed.deserialize::<Vec<u8>>(&frame[..frame.len() - 1]),
            Err(Error::UnexpectedEnd)
        ));
    }

    #[cfg(feature = "compression")]
    #[test]
    fn compressed_stream_rejects_oversized_header_before_reading_body() {
        let mut header = Vec::from(*b"RBZ1");
        header.extend_from_slice(&1u16.to_le_bytes());
        header.extend_from_slice(&1u16.to_le_bytes());
        header.extend_from_slice(&1025u64.to_le_bytes());
        header.extend_from_slice(&1u64.to_le_bytes());
        let reader = HeaderOnlyReader {
            header: Cursor::new(header),
        };

        assert!(matches!(
            options()
                .with_limit(1024)
                .with_zstd_compression(3)
                .deserialize_from::<_, Vec<u8>>(reader),
            Err(Error::SizeLimit { limit: 1024 })
        ));
    }

    #[cfg(all(feature = "compression", feature = "cbor"))]
    #[test]
    fn deterministic_cbor_can_be_compressed_as_one_pipeline() {
        let value = BTreeMap::from([("payload".to_owned(), "x".repeat(2048))]);
        let config = options()
            .with_cbor_format()
            .with_deterministic_encoding()
            .with_zstd_compression(5)
            .with_compression_threshold(64);
        let frame = config.serialize(&value).unwrap();
        assert_eq!(
            config
                .deserialize::<BTreeMap<String, String>>(&frame)
                .unwrap(),
            value
        );
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn authenticated_encryption_uses_random_nonces_and_rejects_tampering() {
        let value = (42u64, "classified".to_owned(), vec![7u8; 512]);
        let config = options()
            .with_limit(4096)
            .with_encryption(EncryptionKey::new([0x42; 32]));
        assert_eq!(
            format!("{:?}", EncryptionKey::new([0x42; 32])),
            "EncryptionKey([REDACTED])"
        );

        let first = config.serialize(&value).unwrap();
        let second = config.serialize(&value).unwrap();
        assert_eq!(&first[..4], b"RBX1");
        assert_ne!(&first[8..32], &second[8..32]);
        assert_ne!(first, second);
        assert_eq!(
            config
                .deserialize::<(u64, String, Vec<u8>)>(&first)
                .unwrap(),
            value
        );

        let mut tampered = first.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(matches!(
            config.deserialize::<(u64, String, Vec<u8>)>(&tampered),
            Err(Error::Encryption)
        ));
        let wrong_key = options()
            .with_limit(4096)
            .with_encryption(EncryptionKey::new([0x24; 32]));
        assert!(matches!(
            wrong_key.deserialize::<(u64, String, Vec<u8>)>(&first),
            Err(Error::Encryption)
        ));

        let mut hostile = first.clone();
        hostile[32..40].copy_from_slice(&4097u64.to_le_bytes());
        hostile[40..48].copy_from_slice(&4113u64.to_le_bytes());
        assert!(matches!(
            config.deserialize::<(u64, String, Vec<u8>)>(&hostile),
            Err(Error::SizeLimit { limit: 4096 })
        ));

        let mut stream = Cursor::new([first.as_slice(), b"next-frame"].concat());
        assert_eq!(
            config
                .deserialize_from::<_, (u64, String, Vec<u8>)>(&mut stream)
                .unwrap(),
            value
        );
        assert_eq!(stream.position(), first.len() as u64);
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn encrypted_stream_rejects_oversized_header_before_reading_body() {
        // A full 48-byte header whose declared plaintext length exceeds the
        // limit; deserialization must reject it before reading the body.
        let mut header = Vec::from(*b"RBX1");
        header.extend_from_slice(&1u16.to_le_bytes());
        header.extend_from_slice(&1u16.to_le_bytes());
        header.extend_from_slice(&[0u8; 24]); // nonce
        header.extend_from_slice(&1025u64.to_le_bytes()); // plaintext length
        header.extend_from_slice(&1041u64.to_le_bytes()); // ciphertext length
        let reader = HeaderOnlyReader {
            header: Cursor::new(header),
        };

        assert!(matches!(
            options()
                .with_limit(1024)
                .with_encryption(EncryptionKey::new([0x42; 32]))
                .deserialize_from::<_, (u64, String, Vec<u8>)>(reader),
            Err(Error::SizeLimit { limit: 1024 })
        ));
    }
}
