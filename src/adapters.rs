//! Standard-library adapters around the `no_std` Compact V1 core.

use crate::{decoder, ser, Config, EncodeWriter, Error, Result};
use std::io::{Read, Write};

struct IoWriter<W>(W);

impl<W: Write> EncodeWriter for IoWriter<W> {
    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.0.write_all(bytes).map_err(Error::from)
    }
}

/// Serializes a value into a standard I/O writer.
pub fn serialize_into<W: Write, T: nextjson::NsonSerialize + ?Sized>(
    config: Config,
    writer: W,
    value: &T,
) -> Result<()> {
    ser::to_writer(IoWriter(writer), value, config).map(|_| ())
}

/// Reads bounded input and decodes one owned value.
pub fn deserialize_from<R: Read, T: for<'de> nextjson::NsonDeserialize<'de>>(
    config: Config,
    mut reader: R,
) -> Result<T> {
    let max = config.limit.unwrap_or(u64::MAX);
    let read_cap = max.saturating_add(1);
    let mut bytes = alloc::vec::Vec::new();
    reader.by_ref().take(read_cap).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(Error::SizeLimit { limit: max });
    }
    decoder::from_slice(&bytes, config)
}

#[cfg(feature = "compression")]
#[doc(inline)]
pub use crate::compression as zstd;
#[cfg(feature = "encryption")]
#[doc(inline)]
pub use crate::encryption;
#[cfg(feature = "parallel")]
#[doc(inline)]
pub use crate::parallel;
#[cfg(feature = "simd")]
#[doc(inline)]
pub use crate::simd as runtime_simd;
