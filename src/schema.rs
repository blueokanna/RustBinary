use alloc::{
    collections::{BTreeMap, BTreeSet, LinkedList, VecDeque},
    string::String,
    vec::Vec,
};

#[cfg(feature = "std")]
use std::{
    collections::{HashMap, HashSet},
    hash::BuildHasher,
    io::{Read, Write},
};

use crate::{
    frame::{encode_header, validate_header, HEADER_LEN},
    Config, Endian, Error, IntEncoding, Result, TrailingBytes,
};

/// Initial state for the stable FNV-1a schema hash.
pub const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
const FRAME_MAGIC: [u8; 4] = *b"RBFP";

/// Extends a schema hash with an exact byte sequence.
pub const fn hash_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    let mut index = 0;
    while index < bytes.len() {
        hash ^= bytes[index] as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        index += 1;
    }
    hash
}

/// Extends a schema hash with one little-endian `u64` domain value.
pub const fn hash_u64(hash: u64, value: u64) -> u64 {
    hash_bytes(hash, &value.to_le_bytes())
}

const fn tagged(tag: &str) -> u64 {
    hash_bytes(FNV_OFFSET, tag.as_bytes())
}

/// Stable structural identity for a serializable Rust type.
pub trait Fingerprint {
    /// Hash of names, types, declaration order, and enum variant order.
    const TYPE_FINGERPRINT: u64;

    /// Combines the type identity with every active codec configuration field.
    fn fingerprint(config: Config) -> u64 {
        config_fingerprint(Self::TYPE_FINGERPRINT, config)
    }
}

pub(crate) const fn config_fingerprint(mut hash: u64, config: Config) -> u64 {
    hash = hash_u64(hash, 0x7275_7374_6269_6e01);
    hash = hash_u64(
        hash,
        match config.endian {
            Endian::Little => 1,
            Endian::Big => 2,
            Endian::Native if cfg!(target_endian = "little") => 3,
            Endian::Native => 4,
        },
    );
    hash = hash_u64(
        hash,
        match config.integers {
            IntEncoding::Fixed => 1,
            IntEncoding::Variable => 2,
        },
    );
    hash = hash_u64(
        hash,
        match config.trailing {
            TrailingBytes::Allow => 1,
            TrailingBytes::Reject => 2,
        },
    );
    hash = hash_u64(hash, option_value(config.limit));
    hash_u64(hash, option_value(config.collection_limit))
}

const fn option_value(value: Option<u64>) -> u64 {
    match value {
        Some(value) => value ^ (1 << 63),
        None => 0,
    }
}

macro_rules! primitive_fingerprints {
    ($($ty:ty => $name:literal),+ $(,)?) => {$(
        impl Fingerprint for $ty {
            const TYPE_FINGERPRINT: u64 = tagged($name);
        }
    )+};
}

primitive_fingerprints! {
    () => "unit", bool => "bool", char => "char", str => "str", String => "String",
    i8 => "i8", i16 => "i16", i32 => "i32", i64 => "i64", i128 => "i128",
    u8 => "u8", u16 => "u16", u32 => "u32", u64 => "u64", u128 => "u128",
    f32 => "f32", f64 => "f64"
}

impl<T: Fingerprint + ?Sized> Fingerprint for &T {
    const TYPE_FINGERPRINT: u64 = hash_u64(tagged("ref"), T::TYPE_FINGERPRINT);
}

macro_rules! unary_fingerprint {
    ($container:ident, $tag:literal) => {
        impl<T: Fingerprint> Fingerprint for $container<T> {
            const TYPE_FINGERPRINT: u64 = hash_u64(tagged($tag), T::TYPE_FINGERPRINT);
        }
    };
}

unary_fingerprint!(Option, "Option");
unary_fingerprint!(Vec, "Vec");
unary_fingerprint!(VecDeque, "VecDeque");
unary_fingerprint!(LinkedList, "LinkedList");
unary_fingerprint!(BTreeSet, "BTreeSet");

impl<T: Fingerprint, const N: usize> Fingerprint for [T; N] {
    const TYPE_FINGERPRINT: u64 =
        hash_u64(hash_u64(tagged("array"), T::TYPE_FINGERPRINT), N as u64);
}

impl<K: Fingerprint, V: Fingerprint> Fingerprint for BTreeMap<K, V> {
    const TYPE_FINGERPRINT: u64 = hash_u64(
        hash_u64(tagged("BTreeMap"), K::TYPE_FINGERPRINT),
        V::TYPE_FINGERPRINT,
    );
}

#[cfg(feature = "std")]
impl<T: Fingerprint, S: BuildHasher> Fingerprint for HashSet<T, S> {
    const TYPE_FINGERPRINT: u64 = hash_u64(tagged("HashSet"), T::TYPE_FINGERPRINT);
}

#[cfg(feature = "std")]
impl<K: Fingerprint, V: Fingerprint, S: BuildHasher> Fingerprint for HashMap<K, V, S> {
    const TYPE_FINGERPRINT: u64 = hash_u64(
        hash_u64(tagged("HashMap"), K::TYPE_FINGERPRINT),
        V::TYPE_FINGERPRINT,
    );
}

macro_rules! tuple_fingerprint {
    ($($name:ident),+) => {
        impl<$($name: Fingerprint),+> Fingerprint for ($($name,)+) {
            const TYPE_FINGERPRINT: u64 = {
                let mut hash = tagged("tuple");
                $(hash = hash_u64(hash, $name::TYPE_FINGERPRINT);)+
                hash
            };
        }
    };
}

tuple_fingerprint!(A);
tuple_fingerprint!(A, B);
tuple_fingerprint!(A, B, C);
tuple_fingerprint!(A, B, C, D);
tuple_fingerprint!(A, B, C, D, E);
tuple_fingerprint!(A, B, C, D, E, F);
tuple_fingerprint!(A, B, C, D, E, F, G);
tuple_fingerprint!(A, B, C, D, E, F, G, H);

/// A configuration that prefixes values with a versioned schema fingerprint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FingerprintedConfig {
    config: Config,
}

impl FingerprintedConfig {
    pub(crate) const fn new(config: Config) -> Self {
        Self { config }
    }

    /// Returns the underlying payload configuration.
    pub const fn payload_config(self) -> Config {
        self.config
    }

    /// Returns the exact fingerprint expected for `T`.
    pub fn fingerprint<T: Fingerprint + ?Sized>(self) -> u64 {
        T::fingerprint(self.config)
    }

    /// Serializes a fingerprint header followed by the configured binary payload.
    pub fn serialize<T: nextjson::NsonSerialize + Fingerprint + ?Sized>(
        self,
        value: &T,
    ) -> Result<Vec<u8>> {
        let payload = self.config.serialize(value)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(HEADER_LEN.saturating_add(payload.len()))
            .map_err(|_| Error::SizeLimit { limit: u64::MAX })?;
        output.extend_from_slice(&encode_header(FRAME_MAGIC, T::fingerprint(self.config)));
        output.extend_from_slice(&payload);
        Ok(output)
    }

    /// Writes a fingerprint header and payload directly into `writer`.
    #[cfg(feature = "std")]
    pub fn serialize_into<W: Write, T: nextjson::NsonSerialize + Fingerprint + ?Sized>(
        self,
        mut writer: W,
        value: &T,
    ) -> Result<()> {
        writer.write_all(&encode_header(FRAME_MAGIC, T::fingerprint(self.config)))?;
        self.config.serialize_into(writer, value)
    }

    /// Writes a fingerprinted frame into caller-owned memory.
    pub fn serialize_into_slice<T: nextjson::NsonSerialize + Fingerprint + ?Sized>(
        self,
        output: &mut [u8],
        value: &T,
    ) -> Result<usize> {
        if output.len() < HEADER_LEN {
            let payload = self.config.serialized_size(value)?;
            let payload =
                usize::try_from(payload).map_err(|_| Error::IntegerOverflow { target: "usize" })?;
            return Err(Error::BufferTooSmall {
                required: HEADER_LEN.saturating_add(payload),
                available: output.len(),
            });
        }
        output[..HEADER_LEN]
            .copy_from_slice(&encode_header(FRAME_MAGIC, T::fingerprint(self.config)));
        match self
            .config
            .serialize_into_slice(&mut output[HEADER_LEN..], value)
        {
            Ok(written) => Ok(HEADER_LEN + written),
            Err(Error::BufferTooSmall {
                required,
                available: _,
            }) => Err(Error::BufferTooSmall {
                required: HEADER_LEN.saturating_add(required),
                available: output.len(),
            }),
            Err(error) => Err(error),
        }
    }

    /// Validates the header and decodes a value that may borrow from the payload.
    pub fn deserialize<'de, T: nextjson::NsonDeserialize<'de> + Fingerprint>(
        self,
        input: &'de [u8],
    ) -> Result<T> {
        let payload = validate_header(FRAME_MAGIC, input, T::fingerprint(self.config))?;
        self.config.deserialize(payload)
    }

    /// Reads, validates, and decodes an owned fingerprinted value.
    #[cfg(feature = "std")]
    pub fn deserialize_from<R: Read, T: for<'de> nextjson::NsonDeserialize<'de> + Fingerprint>(
        self,
        mut reader: R,
    ) -> Result<T> {
        let mut frame_header = [0; HEADER_LEN];
        reader.read_exact(&mut frame_header)?;
        validate_header(FRAME_MAGIC, &frame_header, T::fingerprint(self.config))?;
        self.config.deserialize_from(reader)
    }

    /// Computes the complete framed size.
    pub fn serialized_size<T: nextjson::NsonSerialize + Fingerprint + ?Sized>(
        self,
        value: &T,
    ) -> Result<u64> {
        self.config
            .serialized_size(value)?
            .checked_add(HEADER_LEN as u64)
            .ok_or(Error::SizeLimit { limit: u64::MAX })
    }
}
