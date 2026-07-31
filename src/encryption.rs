use std::{fmt, io::Read};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use serde::{de::DeserializeOwned, Serialize};
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "cbor")]
use crate::CborConfig;
#[cfg(feature = "compression")]
use crate::CompressedConfig;
use crate::{Config, Error, Result, TrailingBytes};

const MAGIC: [u8; 4] = *b"RBX1";
const VERSION: u16 = 1;
const ALGORITHM_XCHACHA20_POLY1305: u16 = 1;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 48;

/// A 256-bit XChaCha20-Poly1305 key which is cleared when dropped.
pub struct EncryptionKey([u8; 32]);

impl EncryptionKey {
    /// Takes ownership of exactly 256 bits of key material.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn as_key(&self) -> &Key {
        self.0.as_slice().try_into().expect("fixed key length")
    }
}

impl Clone for EncryptionKey {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncryptionKey([REDACTED])")
    }
}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

enum PayloadFormat {
    Binary(Config),
    #[cfg(feature = "cbor")]
    Cbor(CborConfig),
    #[cfg(feature = "compression")]
    Compressed(CompressedConfig),
}

/// Authenticated encryption applied after serialization and optional compression.
pub struct EncryptedConfig {
    payload: PayloadFormat,
    key: EncryptionKey,
    plaintext_limit: Option<u64>,
}

impl fmt::Debug for EncryptedConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedConfig")
            .field("payload", &self.payload_name())
            .field("key", &"[REDACTED]")
            .field("plaintext_limit", &self.plaintext_limit)
            .finish()
    }
}

impl EncryptedConfig {
    pub(crate) fn binary(config: Config, key: EncryptionKey) -> Self {
        Self {
            payload: PayloadFormat::Binary(config),
            key,
            plaintext_limit: config.limit,
        }
    }

    #[cfg(feature = "cbor")]
    pub(crate) fn cbor(config: CborConfig, key: EncryptionKey) -> Self {
        Self {
            payload: PayloadFormat::Cbor(config),
            key,
            plaintext_limit: config.base_config().limit,
        }
    }

    #[cfg(feature = "compression")]
    pub(crate) fn compressed(config: CompressedConfig, key: EncryptionKey) -> Self {
        Self {
            payload: PayloadFormat::Compressed(config),
            key,
            plaintext_limit: config.resource_limit(),
        }
    }

    /// Overrides the maximum authenticated plaintext frame size.
    pub const fn with_plaintext_limit(mut self, limit: u64) -> Self {
        self.plaintext_limit = Some(limit);
        self
    }

    /// Serializes and encrypts a value with a fresh random 192-bit nonce.
    pub fn serialize<T: Serialize + ?Sized>(&self, value: &T) -> Result<Vec<u8>> {
        let plaintext = Zeroizing::new(self.serialize_payload(value)?);
        self.enforce_plaintext_limit(plaintext.len() as u64)?;
        let mut nonce_bytes = [0; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).map_err(|error| Error::Randomness(error.to_string()))?;
        let nonce: &XNonce = nonce_bytes
            .as_slice()
            .try_into()
            .expect("fixed nonce length");
        let ciphertext_len = plaintext
            .len()
            .checked_add(TAG_LEN)
            .ok_or(Error::SizeLimit { limit: u64::MAX })?;
        let header = header(nonce, plaintext.len(), ciphertext_len)?;
        let cipher = XChaCha20Poly1305::new(self.key.as_key());
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| Error::Encryption)?;
        if ciphertext.len() != ciphertext_len {
            return Err(Error::InvalidFrame("AEAD ciphertext length mismatch"));
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(HEADER_LEN.saturating_add(ciphertext.len()))
            .map_err(|_| Error::SizeLimit { limit: u64::MAX })?;
        output.extend_from_slice(&header);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Decrypts, authenticates, and deserializes a complete frame.
    pub fn deserialize<T: DeserializeOwned>(&self, input: &[u8]) -> Result<T> {
        let header = input.get(..HEADER_LEN).ok_or(Error::UnexpectedEnd)?;
        let (_, declared_plaintext_len, _) = parse_header(header)?;
        self.enforce_plaintext_limit(declared_plaintext_len)?;
        let (nonce, plaintext_len, ciphertext) = parse_frame(input, self.trailing_policy())?;
        let cipher = XChaCha20Poly1305::new(self.key.as_key());
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: ciphertext,
                        aad: header,
                    },
                )
                .map_err(|_| Error::Encryption)?,
        );
        if plaintext.len() as u64 != plaintext_len {
            return Err(Error::InvalidFrame("AEAD plaintext length mismatch"));
        }
        self.deserialize_payload(&plaintext)
    }

    /// Reads exactly one encrypted frame and leaves subsequent frames unread.
    pub fn deserialize_from<R: Read, T: DeserializeOwned>(&self, mut reader: R) -> Result<T> {
        let mut header = [0; HEADER_LEN];
        reader.read_exact(&mut header)?;
        let (_, plaintext_len, ciphertext_len) = parse_header(&header)?;
        self.enforce_plaintext_limit(plaintext_len)?;
        let ciphertext_len = usize::try_from(ciphertext_len)
            .map_err(|_| Error::IntegerOverflow { target: "usize" })?;
        let frame_len = HEADER_LEN
            .checked_add(ciphertext_len)
            .ok_or(Error::InvalidFrame("encryption frame size overflow"))?;
        let mut frame = Vec::new();
        frame
            .try_reserve_exact(frame_len)
            .map_err(|_| Error::SizeLimit { limit: u64::MAX })?;
        frame.extend_from_slice(&header);
        reader.take(ciphertext_len as u64).read_to_end(&mut frame)?;
        if frame.len() != HEADER_LEN + ciphertext_len {
            return Err(Error::UnexpectedEnd);
        }
        self.deserialize(&frame)
    }

    fn serialize_payload<T: Serialize + ?Sized>(&self, value: &T) -> Result<Vec<u8>> {
        match self.payload {
            PayloadFormat::Binary(config) => config.serialize(value),
            #[cfg(feature = "cbor")]
            PayloadFormat::Cbor(config) => config.serialize(value),
            #[cfg(feature = "compression")]
            PayloadFormat::Compressed(config) => config.serialize(value),
        }
    }

    fn deserialize_payload<T: DeserializeOwned>(&self, payload: &[u8]) -> Result<T> {
        match self.payload {
            PayloadFormat::Binary(config) => config.deserialize(payload),
            #[cfg(feature = "cbor")]
            PayloadFormat::Cbor(config) => config.deserialize(payload),
            #[cfg(feature = "compression")]
            PayloadFormat::Compressed(config) => config.deserialize(payload),
        }
    }

    const fn trailing_policy(&self) -> TrailingBytes {
        match self.payload {
            PayloadFormat::Binary(config) => config.trailing,
            #[cfg(feature = "cbor")]
            PayloadFormat::Cbor(config) => config.base_config().trailing,
            #[cfg(feature = "compression")]
            PayloadFormat::Compressed(config) => config.trailing_policy_for_envelope(),
        }
    }

    fn enforce_plaintext_limit(&self, length: u64) -> Result<()> {
        if let Some(limit) = self.plaintext_limit {
            if length > limit {
                return Err(Error::SizeLimit { limit });
            }
        }
        Ok(())
    }

    const fn payload_name(&self) -> &'static str {
        match self.payload {
            PayloadFormat::Binary(_) => "binary",
            #[cfg(feature = "cbor")]
            PayloadFormat::Cbor(_) => "cbor",
            #[cfg(feature = "compression")]
            PayloadFormat::Compressed(_) => "compressed",
        }
    }
}

fn header(nonce: &XNonce, plaintext_len: usize, ciphertext_len: usize) -> Result<[u8; HEADER_LEN]> {
    let plaintext_len =
        u64::try_from(plaintext_len).map_err(|_| Error::IntegerOverflow { target: "u64" })?;
    let ciphertext_len =
        u64::try_from(ciphertext_len).map_err(|_| Error::IntegerOverflow { target: "u64" })?;
    let mut header = [0; HEADER_LEN];
    header[..4].copy_from_slice(&MAGIC);
    header[4..6].copy_from_slice(&VERSION.to_le_bytes());
    header[6..8].copy_from_slice(&ALGORITHM_XCHACHA20_POLY1305.to_le_bytes());
    header[8..32].copy_from_slice(nonce);
    header[32..40].copy_from_slice(&plaintext_len.to_le_bytes());
    header[40..48].copy_from_slice(&ciphertext_len.to_le_bytes());
    Ok(header)
}

fn parse_header(header: &[u8]) -> Result<(&XNonce, u64, u64)> {
    if header.len() != HEADER_LEN || header[..4] != MAGIC {
        return Err(Error::InvalidFrame("bad encryption header"));
    }
    if u16::from_le_bytes(header[4..6].try_into().expect("fixed header field")) != VERSION {
        return Err(Error::InvalidFrame("unsupported encryption frame version"));
    }
    if u16::from_le_bytes(header[6..8].try_into().expect("fixed header field"))
        != ALGORITHM_XCHACHA20_POLY1305
    {
        return Err(Error::InvalidFrame("unsupported encryption algorithm"));
    }
    let nonce: &XNonce = header[8..8 + NONCE_LEN]
        .try_into()
        .expect("fixed nonce field");
    let plaintext_len = u64::from_le_bytes(header[32..40].try_into().expect("fixed header field"));
    let ciphertext_len = u64::from_le_bytes(header[40..48].try_into().expect("fixed header field"));
    if plaintext_len.checked_add(TAG_LEN as u64) != Some(ciphertext_len) {
        return Err(Error::InvalidFrame(
            "AEAD ciphertext length does not match plaintext length",
        ));
    }
    Ok((nonce, plaintext_len, ciphertext_len))
}

fn parse_frame(input: &[u8], trailing: TrailingBytes) -> Result<(&XNonce, u64, &[u8])> {
    let header = input.get(..HEADER_LEN).ok_or(Error::UnexpectedEnd)?;
    let (nonce, plaintext_len, ciphertext_len) = parse_header(header)?;
    let ciphertext_len =
        usize::try_from(ciphertext_len).map_err(|_| Error::IntegerOverflow { target: "usize" })?;
    let end = HEADER_LEN
        .checked_add(ciphertext_len)
        .ok_or(Error::UnexpectedEnd)?;
    let ciphertext = input.get(HEADER_LEN..end).ok_or(Error::UnexpectedEnd)?;
    if trailing == TrailingBytes::Reject && end != input.len() {
        return Err(Error::TrailingBytes {
            remaining: input.len() - end,
        });
    }
    Ok((nonce, plaintext_len, ciphertext))
}
