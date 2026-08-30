use core::{fmt, str::Utf8Error};

use alloc::string::{String, ToString};
#[cfg(feature = "std")]
use std::io;

/// Result type returned by all codec operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Stable responsibility category for a codec failure.
///
/// Applications can use this value for metrics and response policy without
/// matching the evolving, non-exhaustive [`Error`] enum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorCategory {
    /// The supplied bytes or value are invalid, incomplete, or disallowed.
    UserInput,
    /// The bytes violate a selected RustBinary protocol or schema contract.
    Protocol,
    /// The caller's limits, buffer, I/O, or selected operation cannot satisfy the request.
    Configuration,
    /// RustBinary or a worker violated an internal invariant.
    InternalBug,
}

/// Diagnostic text supplied by custom serializers or external formats.
#[derive(Debug)]
#[doc(hidden)]
pub struct CustomMessage {
    message: String,
}

impl CustomMessage {
    fn from_display(message: impl fmt::Display) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

impl From<&str> for CustomMessage {
    fn from(message: &str) -> Self {
        Self::from_display(message)
    }
}

impl fmt::Display for CustomMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// Serialization, deserialization, validation, or I/O failure.
#[derive(Debug)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum Error {
    #[cfg(feature = "std")]
    Io(io::Error),
    SizeLimit {
        limit: u64,
    },
    CollectionLimit {
        limit: u64,
    },
    BufferTooSmall {
        required: usize,
        available: usize,
    },
    InvalidFrame(&'static str),
    SchemaMismatch {
        expected: u64,
        actual: u64,
    },
    #[cfg(feature = "cbor")]
    Cbor(String),
    #[cfg(feature = "compression")]
    Compression(String),
    #[cfg(feature = "encryption")]
    Encryption,
    #[cfg(feature = "encryption")]
    Randomness(String),
    BitPacking(&'static str),
    Adaptive(&'static str),
    #[cfg(feature = "entropy")]
    Entropy(&'static str),
    #[cfg(feature = "reconcile")]
    Delta(&'static str),
    #[cfg(feature = "reconcile")]
    Iblt(&'static str),
    #[cfg(feature = "trust")]
    Trust(&'static str),
    #[cfg(feature = "parallel")]
    ParallelWorkerPanic,
    SchemaEvolution(&'static str),
    UnexpectedEnd,
    TrailingBytes {
        remaining: usize,
    },
    InvalidBool(u8),
    InvalidOption(u8),
    InvalidChar,
    NonFiniteFloat,
    InvalidUtf8(Utf8Error),
    IntegerOverflow {
        target: &'static str,
    },
    InvalidVarintMarker(u8),
    NonCanonicalVarint,
    SequenceMustHaveLength,
    Unsupported(&'static str),
    Custom(CustomMessage),
}

impl Error {
    /// Returns the stable responsibility category for this error.
    pub const fn category(&self) -> ErrorCategory {
        match self {
            #[cfg(feature = "std")]
            Self::Io(_) => ErrorCategory::Configuration,
            Self::SizeLimit { .. }
            | Self::CollectionLimit { .. }
            | Self::BufferTooSmall { .. }
            | Self::SequenceMustHaveLength
            | Self::Unsupported(_) => ErrorCategory::Configuration,
            Self::InvalidFrame(_)
            | Self::SchemaMismatch { .. }
            | Self::BitPacking(_)
            | Self::Adaptive(_)
            | Self::SchemaEvolution(_)
            | Self::NonCanonicalVarint => ErrorCategory::Protocol,
            #[cfg(feature = "entropy")]
            Self::Entropy(_) => ErrorCategory::Protocol,
            #[cfg(feature = "reconcile")]
            Self::Delta(_) => ErrorCategory::Protocol,
            #[cfg(feature = "reconcile")]
            Self::Iblt(_) => ErrorCategory::Protocol,
            #[cfg(feature = "trust")]
            Self::Trust(_) => ErrorCategory::Protocol,
            #[cfg(feature = "cbor")]
            Self::Cbor(_) => ErrorCategory::Protocol,
            #[cfg(feature = "compression")]
            Self::Compression(_) => ErrorCategory::Protocol,
            #[cfg(feature = "encryption")]
            Self::Randomness(_) => ErrorCategory::Configuration,
            #[cfg(feature = "encryption")]
            Self::Encryption => ErrorCategory::UserInput,
            #[cfg(feature = "parallel")]
            Self::ParallelWorkerPanic => ErrorCategory::InternalBug,
            Self::UnexpectedEnd
            | Self::TrailingBytes { .. }
            | Self::InvalidBool(_)
            | Self::InvalidOption(_)
            | Self::InvalidChar
            | Self::NonFiniteFloat
            | Self::InvalidUtf8(_)
            | Self::IntegerOverflow { .. }
            | Self::InvalidVarintMarker(_)
            | Self::Custom(_) => ErrorCategory::UserInput,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "std")]
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::SizeLimit { limit } => write!(f, "codec size limit of {limit} bytes exceeded"),
            Self::CollectionLimit { limit } => {
                write!(f, "collection element limit of {limit} exceeded")
            }
            Self::BufferTooSmall {
                required,
                available,
            } => write!(
                f,
                "output buffer requires {required} bytes but only {available} are available"
            ),
            Self::InvalidFrame(reason) => write!(f, "invalid rustbinary frame: {reason}"),
            Self::SchemaMismatch { expected, actual } => write!(
                f,
                "schema fingerprint mismatch: expected {expected:#018x}, found {actual:#018x}"
            ),
            #[cfg(feature = "cbor")]
            Self::Cbor(message) => write!(f, "CBOR error: {message}"),
            #[cfg(feature = "compression")]
            Self::Compression(message) => write!(f, "compression error: {message}"),
            #[cfg(feature = "encryption")]
            Self::Encryption => f.write_str("authenticated encryption failed"),
            #[cfg(feature = "encryption")]
            Self::Randomness(message) => write!(f, "system randomness error: {message}"),
            Self::BitPacking(message) => write!(f, "bit-packing error: {message}"),
            Self::Adaptive(message) => write!(f, "adaptive encoding error: {message}"),
            #[cfg(feature = "entropy")]
            Self::Entropy(message) => write!(f, "entropy coding error: {message}"),
            #[cfg(feature = "reconcile")]
            Self::Delta(message) => write!(f, "delta frame error: {message}"),
            #[cfg(feature = "reconcile")]
            Self::Iblt(message) => write!(f, "IBLT reconciliation error: {message}"),
            #[cfg(feature = "trust")]
            Self::Trust(message) => write!(f, "trust calculus error: {message}"),
            #[cfg(feature = "parallel")]
            Self::ParallelWorkerPanic => f.write_str("parallel codec worker panicked"),
            Self::SchemaEvolution(message) => write!(f, "schema evolution error: {message}"),
            Self::UnexpectedEnd => f.write_str("unexpected end of input"),
            Self::TrailingBytes { remaining } => {
                write!(f, "{remaining} trailing byte(s) after decoded value")
            }
            Self::InvalidBool(value) => write!(f, "invalid boolean tag {value}; expected 0 or 1"),
            Self::InvalidOption(value) => write!(f, "invalid option tag {value}; expected 0 or 1"),
            Self::InvalidChar => f.write_str("invalid UTF-8 character encoding"),
            Self::NonFiniteFloat => {
                f.write_str("non-finite float values (NaN or infinity) are rejected")
            }
            Self::InvalidUtf8(error) => write!(f, "invalid UTF-8 string: {error}"),
            Self::IntegerOverflow { target } => write!(f, "decoded integer does not fit {target}"),
            Self::InvalidVarintMarker(marker) => write!(f, "invalid varint marker {marker:#04x}"),
            Self::NonCanonicalVarint => f.write_str("non-canonical varint encoding"),
            Self::SequenceMustHaveLength => {
                f.write_str("binary sequences and maps must declare their length")
            }
            Self::Unsupported(operation) => write!(f, "unsupported operation: {operation}"),
            Self::Custom(message) => fmt::Display::fmt(message, f),
        }
    }
}

// `core::error::Error` is not stable before Rust 1.81, so the no_std build on
// the MSRV 1.78 line has no `core::error::Error` impl; the `std` build gets
// the standard `Error` trait. no_std consumers that need `dyn Error` on
// 1.81+ toolchains can map through their own wrapper.
#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidUtf8(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(feature = "std")]
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl Error {
    /// Converts a nextjson error (surfaced by a `FormatEncoder` / `FormatDecoder`
    /// implementation) into a RustBinary [`Error`].
    pub(crate) fn from_nextjson(error: nextjson::Error) -> Self {
        Self::Custom(CustomMessage::from_display(error))
    }
}

/// Builds an `Error::Custom` from a static message.
///
/// Used by `rustbinary-derive`-generated code; not part of the public API.
#[doc(hidden)]
pub fn __custom_message(message: &'static str) -> CustomMessage {
    CustomMessage::from_display(message)
}
