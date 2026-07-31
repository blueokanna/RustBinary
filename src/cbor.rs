use std::io::{self, Cursor, Read, Write};

use ciborium::value::{CanonicalValue, Value};
use serde::{de::DeserializeOwned, Serialize};

#[cfg(feature = "fingerprint")]
use crate::{
    frame::{encode_header, validate_header, HEADER_LEN},
    schema::{config_fingerprint, hash_bytes, hash_u64, Fingerprint},
};
use crate::{Config, Error, Result, TrailingBytes};

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

    /// Enables RFC 8949 deterministic map ordering and preferred encoding.
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

    /// Wraps CBOR payloads in an adaptive Zstandard compression frame.
    #[cfg(feature = "compression")]
    pub const fn with_zstd_compression(self, level: i32) -> crate::CompressedConfig {
        crate::CompressedConfig::cbor(self, level)
    }

    /// Encrypts CBOR payloads using XChaCha20-Poly1305 and random nonces.
    #[cfg(feature = "encryption")]
    pub fn with_encryption(self, key: crate::EncryptionKey) -> crate::EncryptedConfig {
        crate::EncryptedConfig::cbor(self, key)
    }

    /// Encodes a value as CBOR.
    pub fn serialize<T: Serialize + ?Sized>(self, value: &T) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        self.serialize_into(&mut output, value)?;
        Ok(output)
    }

    /// Encodes CBOR directly into a writer.
    ///
    /// Deterministic mode allocates a normalized value tree because arbitrary
    /// Serde maps cannot be sorted without retaining their encoded keys.
    pub fn serialize_into<W: Write, T: Serialize + ?Sized>(
        self,
        writer: W,
        value: &T,
    ) -> Result<()> {
        let mut writer = LimitedWriter::new(writer, self.base.limit);
        let result = if self.deterministic {
            let normalized = normalize(Value::serialized(value).map_err(cbor_error)?)?;
            ciborium::into_writer(&normalized, &mut writer)
        } else {
            ciborium::into_writer(value, &mut writer)
        };
        match result {
            Ok(()) => Ok(()),
            Err(_) if writer.exceeded => Err(Error::SizeLimit {
                limit: self.base.limit.expect("exceeded only with a limit"),
            }),
            Err(error) => Err(cbor_error(error)),
        }
    }

    /// Computes the exact CBOR size with a counting writer.
    pub fn serialized_size<T: Serialize + ?Sized>(self, value: &T) -> Result<u64> {
        let mut counter = Counter { written: 0 };
        self.serialize_into(&mut counter, value)?;
        Ok(counter.written)
    }

    /// Decodes one owned CBOR value from a slice.
    pub fn deserialize<T: DeserializeOwned>(self, input: &[u8]) -> Result<T> {
        if let Some(limit) = self.base.limit {
            if input.len() as u64 > limit {
                return Err(Error::SizeLimit { limit });
            }
        }
        let mut cursor = Cursor::new(input);
        let value = ciborium::from_reader(&mut cursor).map_err(cbor_error)?;
        if self.base.trailing == TrailingBytes::Reject && cursor.position() != input.len() as u64 {
            return Err(Error::TrailingBytes {
                remaining: input.len() - cursor.position() as usize,
            });
        }
        Ok(value)
    }

    /// Decodes one owned CBOR value from a reader.
    pub fn deserialize_from<R: Read, T: DeserializeOwned>(self, reader: R) -> Result<T> {
        let mut reader = LimitedReader::new(reader, self.base.limit);
        match ciborium::from_reader(&mut reader) {
            Ok(value) => {
                if self.base.trailing == TrailingBytes::Reject {
                    let trailing = reader.drain_remaining()?;
                    if trailing != 0 {
                        return Err(Error::TrailingBytes {
                            remaining: trailing,
                        });
                    }
                }
                Ok(value)
            }
            Err(_) if reader.exceeded => Err(Error::SizeLimit {
                limit: self.base.limit.expect("exceeded only with a limit"),
            }),
            Err(error) => Err(cbor_error(error)),
        }
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
    pub fn serialize<T: Serialize + Fingerprint + ?Sized>(self, value: &T) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        self.serialize_into(&mut output, value)?;
        Ok(output)
    }

    /// Writes a fingerprinted CBOR frame directly into a writer.
    pub fn serialize_into<W: Write, T: Serialize + Fingerprint + ?Sized>(
        self,
        mut writer: W,
        value: &T,
    ) -> Result<()> {
        writer.write_all(&encode_header(FRAME_MAGIC, self.config.fingerprint::<T>()))?;
        self.config.serialize_into(writer, value)
    }

    /// Validates the CBOR schema frame and decodes its owned payload.
    pub fn deserialize<T: DeserializeOwned + Fingerprint>(self, input: &[u8]) -> Result<T> {
        let payload = validate_header(FRAME_MAGIC, input, self.config.fingerprint::<T>())?;
        self.config.deserialize(payload)
    }

    /// Reads and validates one fingerprinted CBOR value.
    pub fn deserialize_from<R: Read, T: DeserializeOwned + Fingerprint>(
        self,
        mut reader: R,
    ) -> Result<T> {
        let mut header = [0; HEADER_LEN];
        reader.read_exact(&mut header)?;
        validate_header(FRAME_MAGIC, &header, self.config.fingerprint::<T>())?;
        self.config.deserialize_from(reader)
    }

    /// Computes the complete fingerprinted CBOR size.
    pub fn serialized_size<T: Serialize + Fingerprint + ?Sized>(self, value: &T) -> Result<u64> {
        self.config
            .serialized_size(value)?
            .checked_add(HEADER_LEN as u64)
            .ok_or(Error::SizeLimit { limit: u64::MAX })
    }
}

fn normalize(value: Value) -> Result<Value> {
    match value {
        Value::Array(values) => values
            .into_iter()
            .map(normalize)
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        Value::Map(entries) => {
            let mut entries = entries
                .into_iter()
                .map(|(key, value)| Ok((normalize(key)?, normalize(value)?)))
                .collect::<Result<Vec<_>>>()?;
            entries.sort_by(|left, right| canonical_cmp(&left.0, &right.0));
            if entries
                .windows(2)
                .any(|pair| canonical_cmp(&pair[0].0, &pair[1].0).is_eq())
            {
                return Err(Error::Cbor(
                    "deterministic maps cannot contain duplicate canonical keys".into(),
                ));
            }
            Ok(Value::Map(entries))
        }
        Value::Tag(tag, value) => Ok(Value::Tag(tag, Box::new(normalize(*value)?))),
        scalar => Ok(scalar),
    }
}

fn canonical_cmp(left: &Value, right: &Value) -> std::cmp::Ordering {
    CanonicalValue::from(left.clone()).cmp(&CanonicalValue::from(right.clone()))
}

fn cbor_error(error: impl std::fmt::Display) -> Error {
    Error::Cbor(error.to_string())
}

struct LimitedWriter<W> {
    inner: W,
    limit: Option<u64>,
    written: u64,
    exceeded: bool,
}

impl<W> LimitedWriter<W> {
    const fn new(inner: W, limit: Option<u64>) -> Self {
        Self {
            inner,
            limit,
            written: 0,
            exceeded: false,
        }
    }
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let amount = u64::try_from(bytes.len())
            .map_err(|_| io::Error::other("CBOR write length exceeds u64"))?;
        let next = self
            .written
            .checked_add(amount)
            .ok_or_else(|| io::Error::other("CBOR write length overflow"))?;
        if self.limit.is_some_and(|limit| next > limit) {
            self.exceeded = true;
            return Err(io::Error::other("CBOR size limit exceeded"));
        }
        let written = self.inner.write(bytes)?;
        self.written = self
            .written
            .checked_add(written as u64)
            .ok_or_else(|| io::Error::other("CBOR write length overflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct LimitedReader<R> {
    inner: R,
    limit: Option<u64>,
    read: u64,
    exceeded: bool,
}

impl<R> LimitedReader<R> {
    const fn new(inner: R, limit: Option<u64>) -> Self {
        Self {
            inner,
            limit,
            read: 0,
            exceeded: false,
        }
    }
}

impl<R: Read> LimitedReader<R> {
    fn drain_remaining(&mut self) -> Result<usize> {
        let mut trailing = 0usize;
        let mut buffer = [0u8; 8 * 1024];
        loop {
            let read = self.inner.read(&mut buffer)?;
            if read == 0 {
                return Ok(trailing);
            }
            trailing = trailing
                .checked_add(read)
                .ok_or(Error::SizeLimit { limit: u64::MAX })?;
            self.read = self
                .read
                .checked_add(read as u64)
                .ok_or(Error::SizeLimit { limit: u64::MAX })?;
            if let Some(limit) = self.limit {
                if self.read > limit {
                    self.exceeded = true;
                    return Err(Error::SizeLimit { limit });
                }
            }
        }
    }
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let allowed = match self.limit {
            Some(limit) if self.read >= limit => {
                self.exceeded = true;
                return Err(io::Error::other("CBOR size limit exceeded"));
            }
            Some(limit) => usize::try_from((limit - self.read).min(output.len() as u64))
                .map_err(|_| io::Error::other("CBOR read length exceeds usize"))?,
            None => output.len(),
        };
        let read = self.inner.read(&mut output[..allowed])?;
        self.read += read as u64;
        Ok(read)
    }
}

struct Counter {
    written: u64,
}

impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.written = self
            .written
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("CBOR size overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
