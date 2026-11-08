//! CBOR configuration over the native streaming codec.
//! Supports the JSON-compatible RFC 8949 subset, native byte strings and bignums.
//! Byte, per-collection and configured depth limits apply; trailing bytes are
//! rejected by default. Custom trait allocations are outside these limits.
//!
//! Stable map ordering materializes an intermediate value tree and is not
//! RFC 8949 deterministic encoding; see `with_deterministic_encoding`.

#[cfg(feature = "std")]
use std::io::{Read, Write};

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use nextjson::Value;

use crate::cbor_codec::{CborDecoder, CborEncoder};
use crate::writer::{CountWriter, EncodeWriter, SliceWriter};
use crate::{Config, Error, Result};

#[cfg(feature = "fingerprint")]
use crate::{
    frame::{encode_header, validate_header, HEADER_LEN},
    schema::{config_fingerprint, hash_bytes, hash_u64, Fingerprint},
};

#[cfg(feature = "fingerprint")]
const FRAME_MAGIC: [u8; 4] = *b"RBCF";

/// RFC 8949 CBOR configuration derived from the common resource policies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CborConfig {
    base: Config,
    deterministic: bool,
}

impl CborConfig {
    pub(crate) const fn new(base: Config) -> Self {
        Self {
            base,
            deterministic: false,
        }
    }

    /// Enables stable recursive map ordering by encoded-key length and bytes.
    ///
    /// This is not RFC 8949 section 4.2 deterministic encoding: containers
    /// remain indefinite-length and floats are not reduced to shortest width.
    /// This mode materializes a value tree before encoding; byte limits do not
    /// bound that intermediate allocation.
    pub const fn with_deterministic_encoding(mut self) -> Self {
        self.deterministic = true;
        self
    }

    /// Disables deterministic map reordering and preserves serializer order.
    pub const fn with_preserved_map_order(mut self) -> Self {
        self.deterministic = false;
        self
    }

    /// Returns whether recursive deterministic normalization is active.
    pub const fn is_deterministic(self) -> bool {
        self.deterministic
    }

    /// Returns the common resource and trailing-byte policies.
    pub const fn base_config(self) -> Config {
        self.base
    }

    /// Computes a schema identity covering CBOR format and deterministic mode.
    #[cfg(feature = "fingerprint")]
    pub fn fingerprint<T: Fingerprint + ?Sized>(self) -> u64 {
        let hash = config_fingerprint(T::TYPE_FINGERPRINT, self.base);
        let hash = hash_bytes(hash, b"format:rfc8949-cbor");
        hash_u64(hash, self.deterministic as u64)
    }

    /// Adds a versioned schema fingerprint header to the CBOR payload.
    #[cfg(feature = "fingerprint")]
    pub const fn with_fingerprint(self) -> FingerprintedCborConfig {
        FingerprintedCborConfig { config: self }
    }

    /// Wraps CBOR payloads in an in-tree LZ77 compression frame.
    #[cfg(feature = "compression")]
    pub const fn with_compression(self, level: i32) -> crate::CompressedConfig {
        crate::CompressedConfig::cbor(self, level)
    }
    /// Legacy name for [`CborConfig::with_compression`].
    #[cfg(feature = "compression")]
    #[deprecated(note = "use `with_compression`; the frame is the in-tree LZ77 codec")]
    pub const fn with_zstd_compression(self, level: i32) -> crate::CompressedConfig {
        crate::CompressedConfig::cbor(self, level)
    }

    /// Encrypts CBOR payloads using XChaCha20-Poly1305 and random nonces.
    #[cfg(feature = "encryption")]
    pub fn with_encryption(self, key: crate::EncryptionKey) -> crate::EncryptedConfig {
        crate::EncryptedConfig::cbor(self, key)
    }

    /// Encodes a value as CBOR.
    pub fn serialize<T: nextjson::NsonSerialize + ?Sized>(self, value: &T) -> Result<Vec<u8>> {
        self.encode_value(value)
    }

    /// Encodes CBOR directly into a writer.
    ///
    /// The payload is produced by the crate's streaming CBOR encoder, so no
    /// complete output buffer is retained. Stable map ordering still builds
    /// its documented value tree. On failure the writer may contain a prefix;
    /// the original I/O or codec error is returned.
    #[cfg(feature = "std")]
    pub fn serialize_into<W: Write, T: nextjson::NsonSerialize + ?Sized>(
        self,
        writer: W,
        value: &T,
    ) -> Result<()> {
        self.encode_to_writer(crate::adapters::IoWriter(writer), value)
            .map(|_| ())
    }

    fn encode_value<T: nextjson::NsonSerialize + ?Sized>(self, value: &T) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        self.encode_to_writer(&mut output, value)?;
        Ok(output)
    }

    fn encode_to_writer<W: EncodeWriter, T: nextjson::NsonSerialize + ?Sized>(
        self,
        writer: W,
        value: &T,
    ) -> Result<u64> {
        if self.deterministic {
            // Deterministic map ordering must retain and sort object keys, so
            // this mode materializes a normalized value tree first. It is
            // explicitly opt-in; the default path streams without it.
            let value = nextjson::to_value(value).map_err(cbor_error)?;
            let value = canonicalize(value)?;
            CborEncoder::new(writer, self.base).finish(&value)
        } else {
            CborEncoder::new(writer, self.base).finish(value)
        }
    }

    fn enforce_byte_limit(self, length: usize) -> Result<()> {
        if let Some(limit) = self.base.limit {
            if length as u64 > limit {
                return Err(Error::SizeLimit { limit });
            }
        }
        Ok(())
    }

    /// Computes the exact CBOR size.
    pub fn serialized_size<T: nextjson::NsonSerialize + ?Sized>(self, value: &T) -> Result<u64> {
        self.encode_to_writer(CountWriter::new(), value)
    }

    /// Encodes CBOR into caller-owned storage and reports the required capacity
    /// on overflow. Preserved map order does not allocate an output buffer.
    pub fn serialize_into_slice<T: nextjson::NsonSerialize + ?Sized>(
        self,
        output: &mut [u8],
        value: &T,
    ) -> Result<usize> {
        let mut writer = SliceWriter::new(output);
        self.encode_to_writer(&mut writer, value)?;
        writer.finish()
    }

    /// Decodes one CBOR value, borrowing definite strings and byte strings
    /// directly from the input when the target type supports borrowing.
    ///
    /// Values are decoded straight from the input into `T` by the crate's
    /// streaming CBOR decoder: no value tree and no JSON text is materialized,
    /// and the byte/collection/depth limits are enforced inline.
    pub fn deserialize<'de, T: nextjson::NsonDeserialize<'de>>(
        self,
        input: &'de [u8],
    ) -> Result<T> {
        self.enforce_byte_limit(input.len())?;
        CborDecoder::new(input, self.base).decode()
    }

    /// Decodes one owned CBOR value from a reader.
    #[cfg(feature = "std")]
    pub fn deserialize_from<R: Read, T: for<'de> nextjson::NsonDeserialize<'de>>(
        self,
        mut reader: R,
    ) -> Result<T> {
        let max = self.base.limit.unwrap_or(u64::MAX);
        let read_cap = max.saturating_add(1);
        let mut bytes = Vec::new();
        reader.by_ref().take(read_cap).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > max {
            return Err(Error::SizeLimit { limit: max });
        }
        self.deserialize(&bytes)
    }
}

/// Fingerprinted RFC 8949 CBOR configuration.
#[cfg(feature = "fingerprint")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FingerprintedCborConfig {
    config: CborConfig,
}

#[cfg(feature = "fingerprint")]
impl FingerprintedCborConfig {
    /// Returns the underlying CBOR configuration.
    pub const fn payload_config(self) -> CborConfig {
        self.config
    }

    /// Serializes a fingerprinted CBOR frame.
    pub fn serialize<T: nextjson::NsonSerialize + Fingerprint + ?Sized>(
        self,
        value: &T,
    ) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        output.extend_from_slice(&encode_header(FRAME_MAGIC, self.config.fingerprint::<T>()));
        output.extend_from_slice(&self.config.encode_value(value)?);
        Ok(output)
    }

    /// Writes a fingerprinted CBOR frame directly into a writer.
    #[cfg(feature = "std")]
    pub fn serialize_into<W: Write, T: nextjson::NsonSerialize + Fingerprint + ?Sized>(
        self,
        mut writer: W,
        value: &T,
    ) -> Result<()> {
        writer.write_all(&encode_header(FRAME_MAGIC, self.config.fingerprint::<T>()))?;
        self.config.serialize_into(writer, value)
    }

    /// Validates the CBOR schema frame and decodes its payload, allowing borrows.
    pub fn deserialize<'de, T: nextjson::NsonDeserialize<'de> + Fingerprint>(
        self,
        input: &'de [u8],
    ) -> Result<T> {
        let payload = validate_header(FRAME_MAGIC, input, self.config.fingerprint::<T>())?;
        self.config.deserialize(payload)
    }

    /// Reads and validates one fingerprinted CBOR value.
    #[cfg(feature = "std")]
    pub fn deserialize_from<R: Read, T: for<'de> nextjson::NsonDeserialize<'de> + Fingerprint>(
        self,
        mut reader: R,
    ) -> Result<T> {
        let mut header = [0; HEADER_LEN];
        reader.read_exact(&mut header)?;
        validate_header(FRAME_MAGIC, &header, self.config.fingerprint::<T>())?;
        self.config.deserialize_from(reader)
    }

    /// Computes the complete fingerprinted CBOR size.
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

/// Recursively sorts object keys with RFC 8949 canonical ordering (shorter
/// keys first, then bytewise).
fn canonicalize(value: Value) -> Result<Value> {
    match value {
        Value::Array(items) => items
            .into_iter()
            .map(canonicalize)
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map
                .into_iter()
                .map(|(key, value)| Ok((key, canonicalize(value)?)))
                .collect::<Result<_>>()?;
            entries.sort_by(|left, right| canonical_cmp(left.0.as_bytes(), right.0.as_bytes()));
            if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(Error::Cbor(
                    "deterministic maps cannot contain duplicate canonical keys".into(),
                ));
            }
            let mut out = nextjson::Map::new();
            for (key, value) in entries {
                out.insert(key, value);
            }
            Ok(Value::Object(out))
        }
        scalar => Ok(scalar),
    }
}

fn canonical_cmp(left: &[u8], right: &[u8]) -> core::cmp::Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn cbor_error(error: nextjson::Error) -> Error {
    Error::Cbor(error.to_string())
}
