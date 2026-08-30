use alloc::string::ToString;
use alloc::vec::Vec;
use std::io::{Read, Write};

#[cfg(feature = "cbor")]
use crate::CborConfig;
use crate::{lz, Config, Error, Result, TrailingBytes};

const MAGIC: [u8; 4] = *b"RBZ1";
const VERSION: u16 = 1;
const COMPRESSED: u16 = 1;
const HEADER_LEN: usize = 24;
const DEFAULT_THRESHOLD: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PayloadFormat {
    Binary(Config),
    #[cfg(feature = "cbor")]
    Cbor(CborConfig),
}

/// Adaptive LZ77 compression integrated with a RustBinary payload format.
///
/// The compressor is the in-tree LZ77 implementation (`src/lz.rs`): a
/// 32 KiB sliding-window matcher with a packed bitstream. The `level` is a
/// search-effort hint (1..=22); higher levels find longer matches at higher
/// CPU cost. The `threshold` is the minimum raw payload size worth
/// compressing at all.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompressedConfig {
    payload: PayloadFormat,
    level: i32,
    threshold: usize,
}

impl CompressedConfig {
    pub(crate) const fn binary(config: Config, level: i32) -> Self {
        Self {
            payload: PayloadFormat::Binary(config),
            level,
            threshold: DEFAULT_THRESHOLD,
        }
    }

    #[cfg(feature = "cbor")]
    pub(crate) const fn cbor(config: CborConfig, level: i32) -> Self {
        Self {
            payload: PayloadFormat::Cbor(config),
            level,
            threshold: DEFAULT_THRESHOLD,
        }
    }

    /// Sets the minimum uncompressed payload size considered for compression.
    pub const fn with_compression_threshold(mut self, threshold: usize) -> Self {
        self.threshold = threshold;
        self
    }

    /// Returns the configured compression level (a 1..=22 search-effort hint).
    pub const fn compression_level(self) -> i32 {
        self.level
    }

    /// Returns the minimum payload size considered for compression.
    pub const fn compression_threshold(self) -> usize {
        self.threshold
    }

    /// Encrypts the complete compression frame after compression selection.
    #[cfg(feature = "encryption")]
    pub fn with_encryption(self, key: crate::EncryptionKey) -> crate::EncryptedConfig {
        crate::EncryptedConfig::compressed(self, key)
    }

    /// Serializes and adaptively compresses a framed payload.
    pub fn serialize<T: nextjson::NsonSerialize + ?Sized>(self, value: &T) -> Result<Vec<u8>> {
        let raw = self.serialize_payload(value)?;
        let compressed = if raw.len() >= self.threshold {
            let packed = lz::compress(&raw, self.level);
            if packed.is_empty() {
                None
            } else {
                Some(packed)
            }
        } else {
            None
        };
        let (flags, stored) = match compressed.as_deref() {
            Some(bytes) if bytes.len() < raw.len() => (COMPRESSED, bytes),
            _ => (0, raw.as_slice()),
        };
        let mut output = Vec::new();
        output
            .try_reserve_exact(HEADER_LEN.saturating_add(stored.len()))
            .map_err(|_| Error::SizeLimit { limit: u64::MAX })?;
        output.extend_from_slice(&header(flags, raw.len(), stored.len())?);
        output.extend_from_slice(stored);
        Ok(output)
    }

    /// Serializes a compression frame into a writer.
    pub fn serialize_into<W: Write, T: nextjson::NsonSerialize + ?Sized>(
        self,
        mut writer: W,
        value: &T,
    ) -> Result<()> {
        writer.write_all(&self.serialize(value)?)?;
        Ok(())
    }

    /// Deserializes an adaptively compressed frame.
    pub fn deserialize<T: for<'de> nextjson::NsonDeserialize<'de>>(
        self,
        input: &[u8],
    ) -> Result<T> {
        let header = input.get(..HEADER_LEN).ok_or(Error::UnexpectedEnd)?;
        let (_, declared_raw_len, _) = parse_header(header)?;
        self.enforce_raw_limit(declared_raw_len)?;
        let (flags, raw_len, stored_len, stored) = parse_frame(input, self.trailing_policy())?;
        let payload = if flags & COMPRESSED != 0 {
            let cap = raw_len
                .checked_add(1)
                .ok_or(Error::SizeLimit { limit: u64::MAX })?;
            let payload = lz::decompress(stored, cap as usize)
                .map_err(|error| Error::Compression(error.to_string()))?;
            if payload.len() as u64 != raw_len {
                return Err(Error::InvalidFrame(
                    "decompressed length does not match compression header",
                ));
            }
            payload
        } else {
            if stored_len != raw_len {
                return Err(Error::InvalidFrame(
                    "raw compression frame has inconsistent lengths",
                ));
            }
            stored.to_vec()
        };
        self.deserialize_payload(&payload)
    }

    /// Reads and deserializes one complete compression frame.
    pub fn deserialize_from<R: Read, T: for<'de> nextjson::NsonDeserialize<'de>>(
        self,
        mut reader: R,
    ) -> Result<T> {
        let mut header = [0; HEADER_LEN];
        reader.read_exact(&mut header)?;
        let (_, raw_len, stored_len) = parse_header(&header)?;
        self.enforce_raw_limit(raw_len)?;
        let stored_len =
            usize::try_from(stored_len).map_err(|_| Error::IntegerOverflow { target: "usize" })?;
        let frame_len = HEADER_LEN
            .checked_add(stored_len)
            .ok_or(Error::InvalidFrame("compression frame size overflow"))?;
        let mut frame = Vec::new();
        frame
            .try_reserve_exact(frame_len)
            .map_err(|_| Error::SizeLimit { limit: u64::MAX })?;
        frame.extend_from_slice(&header);
        let mut stored = reader.take(stored_len as u64);
        stored.read_to_end(&mut frame)?;
        if frame.len() != HEADER_LEN + stored_len {
            return Err(Error::UnexpectedEnd);
        }
        self.deserialize(&frame)
    }

    fn serialize_payload<T: nextjson::NsonSerialize + ?Sized>(self, value: &T) -> Result<Vec<u8>> {
        match self.payload {
            PayloadFormat::Binary(config) => config.serialize(value),
            #[cfg(feature = "cbor")]
            PayloadFormat::Cbor(config) => config.serialize(value),
        }
    }

    fn deserialize_payload<T: for<'de> nextjson::NsonDeserialize<'de>>(
        self,
        payload: &[u8],
    ) -> Result<T> {
        match self.payload {
            PayloadFormat::Binary(config) => config.deserialize(payload),
            #[cfg(feature = "cbor")]
            PayloadFormat::Cbor(config) => config.deserialize(payload),
        }
    }

    const fn trailing_policy(self) -> TrailingBytes {
        match self.payload {
            PayloadFormat::Binary(config) => config.trailing,
            #[cfg(feature = "cbor")]
            PayloadFormat::Cbor(config) => config.base_config().trailing,
        }
    }

    fn enforce_raw_limit(self, raw_len: u64) -> Result<()> {
        let limit = match self.payload {
            PayloadFormat::Binary(config) => config.limit,
            #[cfg(feature = "cbor")]
            PayloadFormat::Cbor(config) => config.base_config().limit,
        };
        let bound = limit.unwrap_or(crate::DEFAULT_SIZE_LIMIT);
        if raw_len > bound {
            return Err(Error::SizeLimit { limit: bound });
        }
        Ok(())
    }

    #[cfg(feature = "encryption")]
    pub(crate) const fn resource_limit(self) -> Option<u64> {
        let limit = match self.payload {
            PayloadFormat::Binary(config) => config.limit,
            #[cfg(feature = "cbor")]
            PayloadFormat::Cbor(config) => config.base_config().limit,
        };
        let bound = match limit {
            Some(limit) => limit,
            None => crate::DEFAULT_SIZE_LIMIT,
        };
        Some(bound.saturating_add(HEADER_LEN as u64))
    }

    #[cfg(feature = "encryption")]
    pub(crate) const fn trailing_policy_for_envelope(self) -> TrailingBytes {
        self.trailing_policy()
    }
}

fn header(flags: u16, raw_len: usize, stored_len: usize) -> Result<[u8; HEADER_LEN]> {
    let raw_len = u64::try_from(raw_len).map_err(|_| Error::IntegerOverflow { target: "u64" })?;
    let stored_len =
        u64::try_from(stored_len).map_err(|_| Error::IntegerOverflow { target: "u64" })?;
    let mut header = [0; HEADER_LEN];
    header[..4].copy_from_slice(&MAGIC);
    header[4..6].copy_from_slice(&VERSION.to_le_bytes());
    header[6..8].copy_from_slice(&flags.to_le_bytes());
    header[8..16].copy_from_slice(&raw_len.to_le_bytes());
    header[16..24].copy_from_slice(&stored_len.to_le_bytes());
    Ok(header)
}

fn parse_header(header: &[u8]) -> Result<(u16, u64, u64)> {
    if header.len() != HEADER_LEN {
        return Err(Error::InvalidFrame("invalid compression header length"));
    }
    if header[..4] != MAGIC {
        return Err(Error::InvalidFrame("bad compression magic"));
    }
    if u16::from_le_bytes(header[4..6].try_into().expect("fixed header field")) != VERSION {
        return Err(Error::InvalidFrame("unsupported compression frame version"));
    }
    let flags = u16::from_le_bytes(header[6..8].try_into().expect("fixed header field"));
    if flags & !COMPRESSED != 0 {
        return Err(Error::InvalidFrame("unknown compression frame flags"));
    }
    let raw_len = u64::from_le_bytes(header[8..16].try_into().expect("fixed header field"));
    let stored_len = u64::from_le_bytes(header[16..24].try_into().expect("fixed header field"));
    match flags & COMPRESSED != 0 {
        true if stored_len >= raw_len => {
            return Err(Error::InvalidFrame(
                "compressed payload must be smaller than its raw payload",
            ));
        }
        false if stored_len != raw_len => {
            return Err(Error::InvalidFrame(
                "raw compression frame has inconsistent lengths",
            ));
        }
        _ => {}
    }
    Ok((flags, raw_len, stored_len))
}

fn parse_frame(input: &[u8], trailing: TrailingBytes) -> Result<(u16, u64, u64, &[u8])> {
    let header = input.get(..HEADER_LEN).ok_or(Error::UnexpectedEnd)?;
    let (flags, raw_len, stored_len) = parse_header(header)?;
    let stored_len =
        usize::try_from(stored_len).map_err(|_| Error::IntegerOverflow { target: "usize" })?;
    let end = HEADER_LEN
        .checked_add(stored_len)
        .ok_or(Error::UnexpectedEnd)?;
    let stored = input.get(HEADER_LEN..end).ok_or(Error::UnexpectedEnd)?;
    if trailing == TrailingBytes::Reject && end != input.len() {
        return Err(Error::TrailingBytes {
            remaining: input.len() - end,
        });
    }
    Ok((flags, raw_len, stored_len as u64, stored))
}
