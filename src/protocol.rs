//! Opt-in schema, compatibility, and compact-layout governance APIs.
//!
//! Enable the `protocol` feature for the complete layer, or select individual
//! capabilities to keep compile time and public API smaller.

#[cfg(feature = "static-size")]
pub use crate::StaticSize;
#[cfg(feature = "adaptive")]
pub use crate::{AdaptiveConfig, CollectionStrategy, StringStrategy};
#[cfg(feature = "bit-packing")]
pub use crate::{BitPack, BitPackedConfig, BitReader, BitValue, BitWriter};
#[cfg(feature = "schema-evolution")]
pub use crate::{
    EvolutionConfig, FieldDecoder, FieldEncoder, SchemaDecode, SchemaEncode, UnknownField,
};
#[cfg(feature = "reflection")]
pub use crate::{FieldInfo, Reflect, TypeShape, VariantInfo};
#[cfg(feature = "fingerprint")]
pub use crate::{Fingerprint, FingerprintedConfig};

#[cfg(all(feature = "derive", feature = "bit-packing"))]
pub use rustbinary_derive::BitPacked;
