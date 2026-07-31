use std::{error, fmt, io, str::Utf8Error};

/// Result type returned by all codec operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Serialization, deserialization, validation, or I/O failure.
#[derive(Debug)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum Error {
    Io(io::Error),
    SizeLimit { limit: u64 },
    CollectionLimit { limit: u64 },
    BufferTooSmall { required: usize, available: usize },
    InvalidFrame(&'static str),
    SchemaMismatch { expected: u64, actual: u64 },
    Cbor(String),
    Compression(String),
    Encryption,
    Randomness(String),
    BitPacking(&'static str),
    Adaptive(&'static str),
    ParallelWorkerPanic,
    SchemaEvolution(&'static str),
    UnexpectedEnd,
    TrailingBytes { remaining: usize },
    InvalidBool(u8),
    InvalidOption(u8),
    InvalidChar,
    InvalidUtf8(Utf8Error),
    IntegerOverflow { target: &'static str },
    InvalidVarintMarker(u8),
    NonCanonicalVarint,
    SequenceMustHaveLength,
    Unsupported(&'static str),
    Custom(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
            Self::Cbor(message) => write!(f, "CBOR error: {message}"),
            Self::Compression(message) => write!(f, "compression error: {message}"),
            Self::Encryption => f.write_str("authenticated encryption failed"),
            Self::Randomness(message) => write!(f, "system randomness error: {message}"),
            Self::BitPacking(message) => write!(f, "bit-packing error: {message}"),
            Self::Adaptive(message) => write!(f, "adaptive encoding error: {message}"),
            Self::ParallelWorkerPanic => f.write_str("parallel codec worker panicked"),
            Self::SchemaEvolution(message) => write!(f, "schema evolution error: {message}"),
            Self::UnexpectedEnd => f.write_str("unexpected end of input"),
            Self::TrailingBytes { remaining } => {
                write!(f, "{remaining} trailing byte(s) after decoded value")
            }
            Self::InvalidBool(value) => write!(f, "invalid boolean tag {value}; expected 0 or 1"),
            Self::InvalidOption(value) => write!(f, "invalid option tag {value}; expected 0 or 1"),
            Self::InvalidChar => f.write_str("invalid UTF-8 character encoding"),
            Self::InvalidUtf8(error) => write!(f, "invalid UTF-8 string: {error}"),
            Self::IntegerOverflow { target } => write!(f, "decoded integer does not fit {target}"),
            Self::InvalidVarintMarker(marker) => write!(f, "invalid varint marker {marker:#04x}"),
            Self::NonCanonicalVarint => f.write_str("non-canonical varint encoding"),
            Self::SequenceMustHaveLength => {
                f.write_str("binary sequences and maps must declare their length")
            }
            Self::Unsupported(operation) => write!(f, "unsupported Serde operation: {operation}"),
            Self::Custom(message) => f.write_str(message),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidUtf8(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl serde::ser::Error for Error {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self::Custom(message.to_string())
    }
}

impl serde::de::Error for Error {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self::Custom(message.to_string())
    }
}
