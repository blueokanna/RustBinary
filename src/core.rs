//! Minimal stable binary format and resource-policy API.
//!
//! This surface has no dependency on protocol governance or transform
//! features. `std` adds owned vectors and I/O adapters; disabling default
//! features retains caller-buffer encode/decode and `no_std` support.

pub use crate::config::{
    Config, Endian, IntEncoding, Options, TrailingBytes, DEFAULT_COLLECTION_LIMIT,
    DEFAULT_SIZE_LIMIT,
};
pub use crate::error::{Error, ErrorCategory, Result};
pub use crate::writer::{CountWriter, EncodeWriter, SliceWriter};
pub use crate::{deserialize, legacy_options, options, serialize_into_slice, serialized_size};

pub use crate::serialize;
#[cfg(feature = "std")]
pub use crate::{deserialize_from, serialize_into};
