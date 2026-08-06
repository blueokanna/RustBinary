//! Opt-in CBOR, compression, encryption, and parallel transform APIs.
//!
//! Enable the `pipeline` feature for the complete layer, or select only the
//! transforms used by the application. Transform order remains explicit in
//! the configuration type chain.

#[cfg(feature = "cbor")]
pub use crate::CborConfig;
#[cfg(feature = "compression")]
pub use crate::CompressedConfig;
#[cfg(all(feature = "cbor", feature = "fingerprint"))]
pub use crate::FingerprintedCborConfig;
#[cfg(feature = "parallel")]
pub use crate::ParallelConfig;
#[cfg(feature = "encryption")]
pub use crate::{EncryptedConfig, EncryptionKey};
