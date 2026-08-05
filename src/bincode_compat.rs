//! RustBinary's independent implementation of the bincode standard profile.
//!
//! This module intentionally does not accept [`crate::Config`]. RustBinary
//! framing, adaptive representations, fingerprints, and processing extensions
//! cannot be mixed into this profile.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::{decoder, ser, Config, Result};

const fn profile() -> Config {
    Config::standard()
        .with_no_collection_limit()
        .allow_trailing_bytes()
}

/// RustBinary's isolated bincode-compatible standard wire profile.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BincodeCompat;

/// Returns the isolated bincode-compatible standard wire profile.
pub const fn bincode_compat() -> BincodeCompat {
    BincodeCompat
}

impl BincodeCompat {
    /// Encodes a Serde value into owned memory.
    #[cfg(feature = "alloc")]
    pub fn serialize<T: Serialize + ?Sized>(self, value: &T) -> Result<Vec<u8>> {
        ser::to_vec(value, profile())
    }

    /// Encodes into caller-owned memory without codec allocation.
    pub fn serialize_into_slice<T: Serialize + ?Sized>(
        self,
        output: &mut [u8],
        value: &T,
    ) -> Result<usize> {
        ser::to_slice(output, value, profile())
    }

    /// Computes the exact encoded size without retaining bytes.
    pub fn serialized_size<T: Serialize + ?Sized>(self, value: &T) -> Result<u64> {
        ser::size(value, profile())
    }

    /// Decodes a value, including borrowed fields, and reports consumed bytes.
    pub fn deserialize<'de, T: Deserialize<'de>>(self, input: &'de [u8]) -> Result<(T, usize)> {
        decoder::from_slice_with_consumed(input, profile())
    }
}
