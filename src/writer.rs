use crate::{Error, Result};

/// Minimal byte sink used by the core encoder.
///
/// Unlike [`std::io::Write`], this trait is available without `std` and models
/// the codec's actual requirement: accepting a complete byte slice.
///
/// The optional container hooks let bounded writers track nesting depth
/// exactly like the self-describing encoder does. Defaults are no-ops, so
/// plain sinks (vectors, slices, counters) keep their zero-overhead behavior
/// and external implementations remain source-compatible.
pub trait EncodeWriter {
    /// Accepts all bytes or returns a codec error.
    fn write_all(&mut self, bytes: &[u8]) -> Result<()>;

    /// Records that a length-prefixed container is being entered.
    ///
    /// The compact profile calls this once per collection so a bounded writer
    /// can reject pathological nesting on encode (mirroring the decoder's
    /// depth guard). The default does nothing.
    fn enter_container(&mut self) -> Result<()> {
        Ok(())
    }

    /// Records that a length-prefixed container has been left.
    ///
    /// Always balances a preceding [`enter_container`](EncodeWriter::enter_container).
    fn exit_container(&mut self) {}
}

impl<W: EncodeWriter + ?Sized> EncodeWriter for &mut W {
    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        (**self).write_all(bytes)
    }

    fn enter_container(&mut self) -> Result<()> {
        (**self).enter_container()
    }

    fn exit_container(&mut self) {
        (**self).exit_container()
    }
}

/// A writer that copies into caller-owned memory while counting the full size.
///
/// Writes past the end are counted but discarded. Call [`SliceWriter::finish`]
/// after encoding to obtain either the initialized length or the exact required
/// capacity.
#[derive(Debug)]
pub struct SliceWriter<'a> {
    output: &'a mut [u8],
    required: usize,
}

impl<'a> SliceWriter<'a> {
    /// Creates a writer over `output`.
    pub fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            required: 0,
        }
    }

    /// Returns the total byte count presented to this writer.
    pub const fn required_len(&self) -> usize {
        self.required
    }

    /// Returns the initialized prefix length.
    pub fn written_len(&self) -> usize {
        self.required.min(self.output.len())
    }

    /// Completes the write and validates caller-provided capacity.
    pub fn finish(self) -> Result<usize> {
        if self.required > self.output.len() {
            Err(Error::BufferTooSmall {
                required: self.required,
                available: self.output.len(),
            })
        } else {
            Ok(self.required)
        }
    }
}

impl EncodeWriter for SliceWriter<'_> {
    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        let start = self.required.min(self.output.len());
        let writable = (self.output.len() - start).min(bytes.len());
        self.output[start..start + writable].copy_from_slice(&bytes[..writable]);
        self.required = self
            .required
            .checked_add(bytes.len())
            .ok_or(Error::SizeLimit { limit: u64::MAX })?;
        Ok(())
    }
}

/// A writer that retains no bytes and reports the encoded size.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CountWriter {
    written: u64,
}

impl CountWriter {
    /// Creates an empty counting writer.
    pub const fn new() -> Self {
        Self { written: 0 }
    }

    /// Returns the number of bytes accepted so far.
    pub const fn written(&self) -> u64 {
        self.written
    }
}

impl EncodeWriter for CountWriter {
    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        let amount =
            u64::try_from(bytes.len()).map_err(|_| Error::IntegerOverflow { target: "u64" })?;
        self.written = self
            .written
            .checked_add(amount)
            .ok_or(Error::SizeLimit { limit: u64::MAX })?;
        Ok(())
    }
}

#[cfg(feature = "alloc")]
impl EncodeWriter for alloc::vec::Vec<u8> {
    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}
