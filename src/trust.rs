//! Type-level trust calculus: unauthenticated deserialization is
//! unrepresentable.
//!
//! The existing `Config -> CborConfig -> CompressedConfig -> EncryptedConfig`
//! chain encodes *transform order* in the type. This module generalizes the
//! idea into an *authentication state machine*:
//!
//! - [`crate::TrustedConfig<C, Untrusted>`] can deserialize, but only through the
//!   explicitly named [`crate::TrustedConfig::deserialize_untrusted`]. There is no
//!   path from `Untrusted` to `Authenticated` except
//!   [`crate::TrustedConfig::authenticate`], which demands a [`crate::Verifier`].
//! - [`crate::TrustedConfig<C, Authenticated>`] exposes the plain `deserialize`
//!   name; it is the only configuration that can deserialize by default.
//!   [`crate::TrustedConfig::deserialize_verified`] additionally wraps the result in
//!   [`crate::Verified`], whose only constructor is the authenticated path.
//! - [`crate::Session`] lifts the same state machine to a full duplex protocol: a
//!   session in the [`crate::Handshake`] state has **no `recv` method at all**, so
//!   receiving unauthenticated data cannot be expressed. Receiving only
//!   becomes available after [`crate::Session::authenticate`] moves the session to
//!   the [`crate::Authenticated`] state, and [`crate::Session::close`] moves it to the
//!   terminal [`crate::Closed`] state which exposes nothing.
//!
//! The `EncryptedConfig` (XChaCha20-Poly1305) from the `encryption` feature
//! is the built-in [`crate::Codec`] that authenticates every frame as part of
//! deserialization; application-specific verifiers (MACs, signatures, keyed
//! handshakes) implement [`crate::Verifier`].

#[cfg(feature = "std")]
use std::io::{Read, Write};

use alloc::boxed::Box;
#[cfg(feature = "std")]
use alloc::vec;
use alloc::vec::Vec;

use core::marker::PhantomData;

use crate::{Config, Result};

/// A codec that can serialize and deserialize whole frames.
///
/// This is the abstraction the trust calculus is generic over, so it applies
/// to any configuration in the transform chain, not just [`Config`].
pub trait Codec {
    /// Serializes a value into a standalone frame.
    fn serialize_frame<T: nextjson::NsonSerialize + ?Sized>(&self, value: &T) -> Result<Vec<u8>>;
    /// Deserializes one value from a standalone frame.
    fn deserialize_frame<T: for<'a> nextjson::NsonDeserialize<'a>>(
        &self,
        input: &[u8],
    ) -> Result<T>;
}

impl Codec for Config {
    fn serialize_frame<T: nextjson::NsonSerialize + ?Sized>(&self, value: &T) -> Result<Vec<u8>> {
        self.serialize(value)
    }
    fn deserialize_frame<T: for<'a> nextjson::NsonDeserialize<'a>>(
        &self,
        input: &[u8],
    ) -> Result<T> {
        self.deserialize(input)
    }
}

#[cfg(feature = "cbor")]
impl Codec for crate::CborConfig {
    fn serialize_frame<T: nextjson::NsonSerialize + ?Sized>(&self, value: &T) -> Result<Vec<u8>> {
        self.serialize(value)
    }
    fn deserialize_frame<T: for<'a> nextjson::NsonDeserialize<'a>>(
        &self,
        input: &[u8],
    ) -> Result<T> {
        self.deserialize(input)
    }
}

#[cfg(feature = "compression")]
impl Codec for crate::CompressedConfig {
    fn serialize_frame<T: nextjson::NsonSerialize + ?Sized>(&self, value: &T) -> Result<Vec<u8>> {
        self.serialize(value)
    }
    fn deserialize_frame<T: for<'a> nextjson::NsonDeserialize<'a>>(
        &self,
        input: &[u8],
    ) -> Result<T> {
        self.deserialize(input)
    }
}

#[cfg(feature = "encryption")]
impl Codec for crate::EncryptedConfig {
    fn serialize_frame<T: nextjson::NsonSerialize + ?Sized>(&self, value: &T) -> Result<Vec<u8>> {
        self.serialize(value)
    }
    fn deserialize_frame<T: for<'a> nextjson::NsonDeserialize<'a>>(
        &self,
        input: &[u8],
    ) -> Result<T> {
        self.deserialize(input)
    }
}

/// Marker for a configuration whose data has **not** been authenticated.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Untrusted;

/// Marker for a configuration whose data **has** been authenticated.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Authenticated;

/// Marker for the terminal, closed session state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Closed;

/// Authentication state marker.
pub trait AuthLevel {}
impl AuthLevel for Untrusted {}
impl AuthLevel for Authenticated {}

/// A value produced only by an authenticated deserialization path.
///
/// The only way to obtain a [`Verified<T>`] is through an authenticated
/// codec (e.g. [`TrustedConfig::deserialize_verified`] or
/// [`Session::recv_verified`]), and the only way to unwrap it is
/// [`Verified::into_inner`].
#[derive(Debug)]
pub struct Verified<T>(T);

impl<T> Verified<T> {
    /// Unwraps the authenticated value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

/// Boxed verification predicate over one frame's bytes.
type VerifyFn = dyn Fn(&[u8]) -> Result<()>;

/// Application-defined verification (MAC, signature, handshake proof).
///
/// A verifier is a pure function over a frame's bytes: it returns `Ok(())`
/// when the bytes are authentic and an error otherwise. The trust calculus
/// treats passing a [`crate::Verifier`] as the *only* transition into the
/// authenticated state.
pub struct Verifier(Box<VerifyFn>);

impl Verifier {
    /// Wraps a verification function.
    pub fn new(verify: impl Fn(&[u8]) -> Result<()> + 'static) -> Self {
        Self(Box::new(verify))
    }

    fn check(&self, bytes: &[u8]) -> Result<()> {
        (self.0)(bytes)
    }
}

/// A configuration whose authentication state is tracked in the type.
///
/// `C` is any [`crate::Codec`] in the transform chain. The `A` parameter is either
/// [`Untrusted`] or [`Authenticated`], and it can only move forward through
/// [`TrustedConfig::authenticate`] — there is no `Into`/`From` conversion,
/// so forgetting to authenticate is a compile error, not a runtime surprise.
pub struct TrustedConfig<C, A: AuthLevel> {
    inner: C,
    verifier: Option<Verifier>,
    marker: PhantomData<A>,
}

impl<C: Codec, A: AuthLevel> TrustedConfig<C, A> {
    /// Serializes a frame (authentication applies on the receiving side, so
    /// serialization is available in every state).
    pub fn serialize<T: nextjson::NsonSerialize + ?Sized>(&self, value: &T) -> Result<Vec<u8>> {
        self.inner.serialize_frame(value)
    }
}

impl<C: Codec> TrustedConfig<C, Untrusted> {
    /// Wraps an unauthenticated codec.
    pub fn unauthenticated(config: C) -> Self {
        Self {
            inner: config,
            verifier: None,
            marker: PhantomData,
        }
    }

    /// Deserializes data that has **not** been authenticated.
    ///
    /// This is intentionally the only deserialization method on an
    /// unauthenticated configuration, and its name forces the caller to
    /// acknowledge the decision at every call site.
    pub fn deserialize_untrusted<T: for<'a> nextjson::NsonDeserialize<'a>>(
        &self,
        input: &[u8],
    ) -> Result<T> {
        self.inner.deserialize_frame(input)
    }

    /// The only transition into the authenticated state.
    ///
    /// `verify` must authenticate `input` (or the transport it arrived on)
    /// before the configuration is allowed to deserialize by default.
    pub fn authenticate(self, verifier: Verifier) -> TrustedConfig<C, Authenticated> {
        TrustedConfig {
            inner: self.inner,
            verifier: Some(verifier),
            marker: PhantomData,
        }
    }
}

impl<C: Codec> TrustedConfig<C, Authenticated> {
    /// Verifies the frame and then deserializes it.
    ///
    /// The plain name is reserved for the authenticated state: this method
    /// does not exist on [`TrustedConfig<C, Untrusted>`].
    pub fn deserialize<T: for<'a> nextjson::NsonDeserialize<'a>>(&self, input: &[u8]) -> Result<T> {
        self.verifier
            .as_ref()
            .ok_or(crate::Error::Trust(
                "authenticated config lost its verifier",
            ))?
            .check(input)?;
        self.inner.deserialize_frame(input)
    }

    /// Verifies the frame and returns the value wrapped in [`crate::Verified`].
    pub fn deserialize_verified<T: for<'a> nextjson::NsonDeserialize<'a>>(
        &self,
        input: &[u8],
    ) -> Result<Verified<T>> {
        self.deserialize(input).map(Verified)
    }

    /// Returns the wrapped codec.
    pub fn into_inner(self) -> C {
        self.inner
    }
}

/// Session state marker trait.
///
/// The duplex [`Session`] machinery requires byte-level I/O and is therefore
/// only available with the `std` feature; the [`TrustedConfig`] type-level
/// calculus above it is `no_std`.
#[cfg(feature = "std")]
pub trait SessionState {}
#[cfg(feature = "std")]
impl SessionState for Handshake {}
#[cfg(feature = "std")]
impl SessionState for Authenticated {}
#[cfg(feature = "std")]
impl SessionState for Closed {}

/// Marker for the initial session state: no receiving is possible.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Handshake;

/// A length-prefixed, state-tracked duplex session.
///
/// `Session<C, Handshake, R>` has no `recv` method — receiving unauthenticated
/// data is unrepresentable. After [`Session::authenticate`] the session is in
/// the [`Authenticated`] state and can receive verified values; after
/// [`Session::close`] it is in the terminal [`Closed`] state and exposes
/// nothing. The session is generic over any [`Codec`], so it composes with
/// every configuration in the transform chain, not just [`Config`].
#[cfg(feature = "std")]
pub struct Session<C: Codec, S: SessionState, R> {
    codec: C,
    max_frame_len: Option<u64>,
    verifier: Option<Verifier>,
    reader: R,
    marker: PhantomData<S>,
}

#[cfg(feature = "std")]
impl<C: Codec, R: Read> Session<C, Handshake, R> {
    /// Starts a handshake session over `reader`.
    pub fn new(codec: C, reader: R) -> Self {
        Self {
            codec,
            max_frame_len: Some(crate::DEFAULT_SIZE_LIMIT),
            verifier: None,
            reader,
            marker: PhantomData,
        }
    }

    /// Bounds the length of one received frame.
    ///
    /// Defaults to [`crate::DEFAULT_SIZE_LIMIT`]; pass `None` only for trusted
    /// transports that already enforce framing.
    pub fn with_max_frame_len(mut self, limit: Option<u64>) -> Self {
        self.max_frame_len = limit;
        self
    }

    /// Authenticates the channel and moves the session to the receiving
    /// state.
    pub fn authenticate(self, verifier: Verifier) -> Session<C, Authenticated, R> {
        Session {
            codec: self.codec,
            max_frame_len: self.max_frame_len,
            verifier: Some(verifier),
            reader: self.reader,
            marker: PhantomData,
        }
    }
}

#[cfg(feature = "std")]
impl<C: Codec, R: Read> Session<C, Authenticated, R> {
    /// Reads one length-prefixed frame, authenticates it, and deserializes.
    pub fn recv<T: for<'a> nextjson::NsonDeserialize<'a>>(&mut self) -> Result<T> {
        self.recv_verified().map(Verified::into_inner)
    }

    /// Reads one length-prefixed frame and returns the value as [`crate::Verified`].
    ///
    /// The frame layout is `u64 little-endian length` followed by the codec
    /// bytes. The verifier checks the codec bytes before deserialization.
    pub fn recv_verified<T: for<'a> nextjson::NsonDeserialize<'a>>(
        &mut self,
    ) -> Result<Verified<T>> {
        let mut length_bytes = [0_u8; 8];
        self.reader.read_exact(&mut length_bytes)?;
        let length = u64::from_le_bytes(length_bytes);
        let length = usize::try_from(length)
            .map_err(|_| crate::Error::Trust("session frame length does not fit usize"))?;
        if let Some(limit) = self.max_frame_len {
            if length as u64 > limit {
                return Err(crate::Error::SizeLimit { limit });
            }
        }
        let mut frame = vec![0_u8; length];
        self.reader.read_exact(&mut frame)?;
        self.verifier
            .as_ref()
            .ok_or(crate::Error::Trust(
                "authenticated session lost its verifier",
            ))?
            .check(&frame)?;
        self.codec.deserialize_frame(&frame).map(Verified)
    }

    /// Serializes one length-prefixed frame for transmission.
    pub fn send<W: Write, T: nextjson::NsonSerialize + ?Sized>(
        &self,
        writer: &mut W,
        value: &T,
    ) -> Result<()> {
        let payload = self.codec.serialize_frame(value)?;
        let length = u64::try_from(payload.len())
            .map_err(|_| crate::Error::Trust("session frame too large"))?;
        writer.write_all(&length.to_le_bytes())?;
        writer.write_all(&payload)?;
        Ok(())
    }

    /// Closes the session and moves it to the terminal state.
    pub fn close(self) -> Session<C, Closed, R> {
        Session {
            codec: self.codec,
            max_frame_len: self.max_frame_len,
            verifier: None,
            reader: self.reader,
            marker: PhantomData,
        }
    }
}

/// The terminal session state: no methods are exposed.
#[cfg(feature = "std")]
impl<C: Codec, R> Session<C, Closed, R> {}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use alloc::string::String;
    use std::io::Cursor;

    #[derive(Debug, PartialEq, nextjson::NsonSerialize, nextjson::NsonDeserialize)]
    struct Message {
        id: u64,
        body: String,
    }

    #[test]
    fn unauthenticated_config_requires_explicit_call() {
        let config = TrustedConfig::<Config, Untrusted>::unauthenticated(Config::standard());
        let value = Message {
            id: 1,
            body: "hello".into(),
        };
        let frame = config.serialize(&value).unwrap();
        // The only deserialization method is the explicitly named one.
        let decoded: Message = config.deserialize_untrusted(&frame).unwrap();
        assert_eq!(decoded, value);
    }

    /// A verifier that accepts exactly one known-good frame (a MAC-like
    /// exact-match check, sufficient to exercise the trust calculus).
    fn frame_verifier(known_good: Vec<u8>) -> Verifier {
        Verifier::new(move |bytes| {
            if bytes == known_good.as_slice() {
                Ok(())
            } else {
                Err(crate::Error::Trust(
                    "frame does not match the authenticated original",
                ))
            }
        })
    }

    #[test]
    fn authenticated_config_verifies_before_deserializing() {
        let message = Message {
            id: 7,
            body: "verified".into(),
        };
        let frame = {
            let unauthenticated =
                TrustedConfig::<Config, Untrusted>::unauthenticated(Config::standard());
            unauthenticated.serialize(&message).unwrap()
        };

        // A verifier that recognizes the exact frame passes.
        let authenticated = TrustedConfig::<Config, Untrusted>::unauthenticated(Config::standard())
            .authenticate(frame_verifier(frame.clone()));
        let decoded: Message = authenticated.deserialize(&frame).unwrap();
        assert_eq!(decoded.body, "verified");
        let verified: Verified<Message> = authenticated.deserialize_verified(&frame).unwrap();
        assert_eq!(verified.into_inner().id, 7);

        // A verifier that rejects the frame blocks deserialization.
        let rejecting = TrustedConfig::<Config, Untrusted>::unauthenticated(Config::standard())
            .authenticate(Verifier::new(|_| {
                Err(crate::Error::Trust("rejected by policy"))
            }));
        assert!(rejecting.deserialize::<Message>(&frame).is_err());

        // Corrupting the frame is caught by the verifier.
        let mut corrupted = frame.clone();
        corrupted[0] ^= 1;
        assert!(authenticated.deserialize::<Message>(&corrupted).is_err());
    }

    #[test]
    fn session_receives_only_after_authentication() {
        // Build a stream of two length-prefixed frames.
        let codec = Config::standard();
        let message = Message {
            id: 3,
            body: "stream".into(),
        };
        let payload = codec.serialize(&message).unwrap();
        let mut stream = Vec::new();
        stream.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        stream.extend_from_slice(&payload);
        stream.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        stream.extend_from_slice(&payload);

        // The handshake session cannot receive; authenticate first. The
        // verifier models an established authenticated channel.
        let mut session =
            Session::new(codec, Cursor::new(stream)).authenticate(Verifier::new(|_| Ok(())));
        // `recv` does not exist on Session<Handshake, _>; this is a compile
        // time property. After authentication, receive works.
        let first: Verified<Message> = session.recv_verified().unwrap();
        assert_eq!(first.into_inner().body, "stream");
        let second: Message = session.recv().unwrap();
        assert_eq!(second.body, "stream");

        // Closing terminates the session (nothing left to do).
        let _closed = session.close();
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn encrypted_config_is_an_authenticated_codec() {
        // With the encryption feature, EncryptedConfig is the built-in
        // authenticating codec: serialize then wrap in the trust surface.
        let key = crate::EncryptionKey::new([0x42; 32]);
        let encrypted = crate::options().with_encryption(key);
        let value = Message {
            id: 9,
            body: "aead".into(),
        };
        let frame = encrypted.serialize(&value).unwrap();
        let decoded: Message = encrypted.deserialize(&frame).unwrap();
        assert_eq!(decoded, value);
    }
}
