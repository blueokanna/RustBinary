use serde::{Deserialize, Serialize};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use serde::de::DeserializeOwned;
#[cfg(feature = "std")]
use std::io::{Read, Write};

use crate::{decoder, error::Result, ser};

/// Conservative default byte limit for one encoded or decoded Core value.
pub const DEFAULT_SIZE_LIMIT: u64 = 64 * 1024 * 1024;

/// Conservative default element limit for one sequence or map.
pub const DEFAULT_COLLECTION_LIMIT: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
/// Byte order for fixed-width values and varint payloads.
pub enum Endian {
    /// Least-significant byte first.
    #[default]
    Little,
    /// Most-significant byte first.
    Big,
    /// The compilation target's byte order.
    Native,
}

impl Endian {
    pub(crate) const fn little(self) -> bool {
        match self {
            Self::Little => true,
            Self::Big => false,
            Self::Native => cfg!(target_endian = "little"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
/// Integer representation used by the codec.
pub enum IntEncoding {
    /// Always use the integer type's full width.
    Fixed,
    /// Use compact marker-prefixed widths and ZigZag signed values.
    #[default]
    Variable,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
/// Policy for bytes following a decoded top-level value.
pub enum TrailingBytes {
    /// Leave unread bytes untouched.
    Allow,
    /// Report unread bytes as an error.
    #[default]
    Reject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Copyable configuration describing a complete wire profile.
pub struct Config {
    pub(crate) endian: Endian,
    pub(crate) integers: IntEncoding,
    pub(crate) trailing: TrailingBytes,
    pub(crate) limit: Option<u64>,
    pub(crate) collection_limit: Option<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Self::standard()
    }
}

impl Config {
    /// Creates the compact profile: variable integers, little endian, and strict trailing bytes.
    pub const fn standard() -> Self {
        Self {
            endian: Endian::Little,
            integers: IntEncoding::Variable,
            trailing: TrailingBytes::Reject,
            limit: Some(DEFAULT_SIZE_LIMIT),
            collection_limit: Some(DEFAULT_COLLECTION_LIMIT),
        }
    }
    /// Creates the historical unbounded fixed-width RustBinary profile.
    pub const fn legacy() -> Self {
        Self {
            endian: Endian::Little,
            integers: IntEncoding::Fixed,
            trailing: TrailingBytes::Allow,
            limit: None,
            collection_limit: None,
        }
    }
    /// Selects little endian.
    pub const fn with_little_endian(mut self) -> Self {
        self.endian = Endian::Little;
        self
    }
    /// Selects big endian.
    pub const fn with_big_endian(mut self) -> Self {
        self.endian = Endian::Big;
        self
    }
    /// Selects the compilation target's native byte order.
    pub const fn with_native_endian(mut self) -> Self {
        self.endian = Endian::Native;
        self
    }
    /// Selects fixed-width integer encoding.
    pub const fn with_fixint_encoding(mut self) -> Self {
        self.integers = IntEncoding::Fixed;
        self
    }
    /// Selects variable-width integer encoding.
    pub const fn with_varint_encoding(mut self) -> Self {
        self.integers = IntEncoding::Variable;
        self
    }
    /// Limits one encoded or decoded value to `limit` consumed bytes.
    pub const fn with_limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self.collection_limit = Some(match self.collection_limit {
            Some(current) if current < limit => current,
            _ => limit,
        });
        self
    }
    /// Removes the consumed-byte limit.
    pub const fn with_no_limit(mut self) -> Self {
        self.limit = None;
        self
    }
    /// Limits the number of elements in one sequence or map.
    pub const fn with_collection_limit(mut self, limit: u64) -> Self {
        self.collection_limit = Some(limit);
        self
    }
    /// Removes the collection element limit.
    pub const fn with_no_collection_limit(mut self) -> Self {
        self.collection_limit = None;
        self
    }
    /// Adds a versioned schema fingerprint header to every value.
    #[cfg(feature = "fingerprint")]
    pub const fn with_fingerprint(self) -> crate::FingerprintedConfig {
        crate::FingerprintedConfig::new(self)
    }
    /// Switches to the RFC 8949 CBOR format while retaining resource policies.
    #[cfg(feature = "cbor")]
    pub const fn with_cbor_format(self) -> crate::CborConfig {
        crate::CborConfig::new(self)
    }
    /// Wraps binary payloads in an adaptive Zstandard compression frame.
    #[cfg(feature = "compression")]
    pub const fn with_zstd_compression(self, level: i32) -> crate::CompressedConfig {
        crate::CompressedConfig::binary(self, level)
    }
    /// Encrypts binary payloads using XChaCha20-Poly1305 and random nonces.
    #[cfg(feature = "encryption")]
    pub fn with_encryption(self, key: crate::EncryptionKey) -> crate::EncryptedConfig {
        crate::EncryptedConfig::binary(self, key)
    }
    /// Selects the generated bit-packed representation for [`crate::BitPack`] types.
    #[cfg(feature = "bit-packing")]
    pub const fn with_bit_packing(self) -> crate::BitPackedConfig {
        crate::BitPackedConfig::new(self)
    }
    /// Enables data-aware integer, string, and numeric-collection encodings.
    #[cfg(feature = "adaptive")]
    pub const fn with_adaptive_encoding(self) -> crate::AdaptiveConfig {
        crate::AdaptiveConfig::new(self.with_varint_encoding().with_little_endian())
    }
    /// Enables ordered parallel batch serialization and deserialization.
    #[cfg(feature = "parallel")]
    pub fn with_parallel_serialization(self) -> crate::ParallelConfig {
        crate::ParallelConfig::new(self)
    }
    /// Wraps values in a stable-field-ID schema evolution frame.
    #[cfg(feature = "schema-evolution")]
    pub const fn with_schema_evolution(self) -> crate::EvolutionConfig {
        crate::EvolutionConfig::new(self)
    }
    /// Rejects bytes left after a top-level value.
    pub const fn reject_trailing_bytes(mut self) -> Self {
        self.trailing = TrailingBytes::Reject;
        self
    }
    /// Allows bytes left after a top-level value.
    pub const fn allow_trailing_bytes(mut self) -> Self {
        self.trailing = TrailingBytes::Allow;
        self
    }
    /// Serializes a value into a new vector.
    #[cfg(feature = "alloc")]
    pub fn serialize<T: Serialize + ?Sized>(self, value: &T) -> Result<Vec<u8>> {
        ser::to_vec(value, self)
    }
    /// Serializes a value directly into `writer`.
    #[cfg(feature = "std")]
    pub fn serialize_into<W: Write, T: Serialize + ?Sized>(
        self,
        writer: W,
        value: &T,
    ) -> Result<()> {
        crate::adapters::serialize_into(self, writer, value)
    }
    /// Serializes into a caller-owned slice without codec-owned heap allocation.
    ///
    /// If capacity is insufficient, the error reports the exact required size.
    /// The prefix that fits in `output` is written before that error is returned.
    /// A user-provided [`Serialize`] implementation may still allocate internally.
    pub fn serialize_into_slice<T: Serialize + ?Sized>(
        self,
        output: &mut [u8],
        value: &T,
    ) -> Result<usize> {
        ser::to_slice(output, value, self)
    }
    /// Calculates the exact encoded size without retaining encoded bytes.
    pub fn serialized_size<T: Serialize + ?Sized>(self, value: &T) -> Result<u64> {
        ser::size(value, self)
    }
    /// Deserializes a value that may borrow from `input`.
    pub fn deserialize<'de, T: Deserialize<'de>>(self, input: &'de [u8]) -> Result<T> {
        decoder::from_slice(input, self)
    }
    /// Reads and deserializes an owned value.
    #[cfg(feature = "std")]
    pub fn deserialize_from<R: Read, T: DeserializeOwned>(self, reader: R) -> Result<T> {
        crate::adapters::deserialize_from(self, reader)
    }
}

/// Fluent compatibility facade implemented by concrete option values.
#[allow(missing_docs)]
pub trait Options: Sized {
    fn config(self) -> Config;
    fn with_little_endian(self) -> Config {
        self.config().with_little_endian()
    }
    fn with_big_endian(self) -> Config {
        self.config().with_big_endian()
    }
    fn with_native_endian(self) -> Config {
        self.config().with_native_endian()
    }
    fn with_fixint_encoding(self) -> Config {
        self.config().with_fixint_encoding()
    }
    fn with_varint_encoding(self) -> Config {
        self.config().with_varint_encoding()
    }
    fn with_limit(self, limit: u64) -> Config {
        self.config().with_limit(limit)
    }
    fn with_no_limit(self) -> Config {
        self.config().with_no_limit()
    }
    fn with_collection_limit(self, limit: u64) -> Config {
        self.config().with_collection_limit(limit)
    }
    fn with_no_collection_limit(self) -> Config {
        self.config().with_no_collection_limit()
    }
    fn reject_trailing_bytes(self) -> Config {
        self.config().reject_trailing_bytes()
    }
    fn allow_trailing_bytes(self) -> Config {
        self.config().allow_trailing_bytes()
    }
    #[cfg(feature = "alloc")]
    fn serialize<T: Serialize + ?Sized>(self, value: &T) -> Result<Vec<u8>> {
        self.config().serialize(value)
    }
    #[cfg(feature = "std")]
    fn serialize_into<W: Write, T: Serialize + ?Sized>(self, writer: W, value: &T) -> Result<()> {
        self.config().serialize_into(writer, value)
    }
    fn serialize_into_slice<T: Serialize + ?Sized>(
        self,
        output: &mut [u8],
        value: &T,
    ) -> Result<usize> {
        self.config().serialize_into_slice(output, value)
    }
    fn serialized_size<T: Serialize + ?Sized>(self, value: &T) -> Result<u64> {
        self.config().serialized_size(value)
    }
    fn deserialize<'de, T: Deserialize<'de>>(self, input: &'de [u8]) -> Result<T> {
        self.config().deserialize(input)
    }
    #[cfg(feature = "std")]
    fn deserialize_from<R: Read, T: DeserializeOwned>(self, reader: R) -> Result<T> {
        self.config().deserialize_from(reader)
    }
}

impl Options for Config {
    fn config(self) -> Config {
        self
    }
}
