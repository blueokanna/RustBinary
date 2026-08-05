use crate::{Config, Error, Result, TrailingBytes};

#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};

/// Bit-level output over caller-owned memory, least-significant bit first.
pub struct BitWriter<'a> {
    output: &'a mut [u8],
    position: usize,
}

impl<'a> BitWriter<'a> {
    /// Creates a writer and clears the output so padding is canonical zero.
    pub fn new(output: &'a mut [u8]) -> Self {
        output.fill(0);
        Self {
            output,
            position: 0,
        }
    }

    /// Writes the low `width` bits of `value`.
    pub fn write(&mut self, value: u128, width: usize) -> Result<()> {
        if width > 128 {
            return Err(Error::BitPacking("field width exceeds 128 bits"));
        }
        if width < 128 && value >> width != 0 {
            return Err(Error::BitPacking("field value does not fit declared width"));
        }
        let end = self
            .position
            .checked_add(width)
            .ok_or(Error::BitPacking("bit position overflow"))?;
        if end > self.output.len().saturating_mul(8) {
            return Err(Error::BufferTooSmall {
                required: bytes_for_bits(end),
                available: self.output.len(),
            });
        }
        let mut bit = 0;
        while bit < width {
            let source = ((value >> bit) & 1) as u8;
            let position = self.position + bit;
            self.output[position / 8] |= source << (position % 8);
            bit += 1;
        }
        self.position = end;
        Ok(())
    }

    /// Number of meaningful bits written.
    pub const fn bits_written(&self) -> usize {
        self.position
    }

    /// Number of bytes containing meaningful bits or canonical padding.
    pub const fn bytes_written(&self) -> usize {
        bytes_for_bits(self.position)
    }
}

/// Bit-level reader matching [`BitWriter`].
pub struct BitReader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> BitReader<'a> {
    /// Creates a reader over an encoded bit-packed payload.
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    /// Reads `width` bits into the low bits of a `u128`.
    pub fn read(&mut self, width: usize) -> Result<u128> {
        if width > 128 {
            return Err(Error::BitPacking("field width exceeds 128 bits"));
        }
        let end = self
            .position
            .checked_add(width)
            .ok_or(Error::BitPacking("bit position overflow"))?;
        if end > self.input.len().saturating_mul(8) {
            return Err(Error::UnexpectedEnd);
        }
        let mut value = 0u128;
        let mut bit = 0;
        while bit < width {
            let position = self.position + bit;
            value |= (((self.input[position / 8] >> (position % 8)) & 1) as u128) << bit;
            bit += 1;
        }
        self.position = end;
        Ok(value)
    }

    /// Number of meaningful bits consumed.
    pub const fn bits_read(&self) -> usize {
        self.position
    }

    fn validate_end(&self, trailing: TrailingBytes) -> Result<()> {
        let used = bytes_for_bits(self.position);
        if !self.position.is_multiple_of(8) && used != 0 {
            let used_bits = self.position % 8;
            if self.input[used - 1] >> used_bits != 0 {
                return Err(Error::BitPacking("non-zero bit padding"));
            }
        }
        if trailing == TrailingBytes::Reject && self.input.len() != used {
            return Err(Error::TrailingBytes {
                remaining: self.input.len() - used,
            });
        }
        Ok(())
    }
}

/// Conversion contract for fields with an explicit `#[bits = N]` width.
pub trait BitValue: Copy {
    /// Encodes and validates this value against `width`.
    fn encode_bits(self, width: usize) -> Result<u128>;
    /// Decodes and validates this value from `width` bits.
    fn decode_bits(value: u128, width: usize) -> Result<Self>;
}

/// Generated or handwritten bit-packed representation.
pub trait BitPack: Sized {
    /// Worst-case meaningful bits for this type.
    const MAX_BITS: usize;
    /// Packs this value into an existing writer.
    fn pack(&self, writer: &mut BitWriter<'_>) -> Result<()>;
    /// Unpacks this value from an existing reader.
    fn unpack(reader: &mut BitReader<'_>) -> Result<Self>;
}

/// Configuration for [`BitPack`] values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BitPackedConfig {
    base: Config,
}

impl BitPackedConfig {
    pub(crate) const fn new(base: Config) -> Self {
        Self { base }
    }

    /// Returns the common resource and trailing-byte policy.
    pub const fn base_config(self) -> Config {
        self.base
    }

    /// Packs a value into an exactly sized vector.
    #[cfg(feature = "alloc")]
    pub fn serialize<T: BitPack>(self, value: &T) -> Result<Vec<u8>> {
        let maximum = bytes_for_bits(T::MAX_BITS);
        if self.base.limit.is_some_and(|limit| maximum as u64 > limit) {
            return Err(Error::SizeLimit {
                limit: self.base.limit.expect("checked as some"),
            });
        }
        let mut output = vec![0; maximum];
        let written = self.serialize_into_slice(&mut output, value)?;
        output.truncate(written);
        Ok(output)
    }

    /// Packs into caller-owned memory without allocation.
    pub fn serialize_into_slice<T: BitPack>(self, output: &mut [u8], value: &T) -> Result<usize> {
        let maximum = bytes_for_bits(T::MAX_BITS);
        if output.len() < maximum {
            return Err(Error::BufferTooSmall {
                required: maximum,
                available: output.len(),
            });
        }
        let mut writer = BitWriter::new(output);
        value.pack(&mut writer)?;
        let written = writer.bytes_written();
        if self.base.limit.is_some_and(|limit| written as u64 > limit) {
            return Err(Error::SizeLimit {
                limit: self.base.limit.expect("checked as some"),
            });
        }
        Ok(written)
    }

    /// Unpacks and validates canonical padding and trailing bytes.
    pub fn deserialize<T: BitPack>(self, input: &[u8]) -> Result<T> {
        if self
            .base
            .limit
            .is_some_and(|limit| input.len() as u64 > limit)
        {
            return Err(Error::SizeLimit {
                limit: self.base.limit.expect("checked as some"),
            });
        }
        let mut reader = BitReader::new(input);
        let value = T::unpack(&mut reader)?;
        reader.validate_end(self.base.trailing)?;
        Ok(value)
    }
}

/// Returns the minimum byte capacity required to store `bits` bits.
///
/// The calculation saturates when `bits + 7` would overflow.
pub const fn bytes_for_bits(bits: usize) -> usize {
    bits.saturating_add(7) / 8
}

impl BitValue for bool {
    fn encode_bits(self, width: usize) -> Result<u128> {
        if width != 1 {
            return Err(Error::BitPacking("boolean fields require exactly one bit"));
        }
        Ok(self as u128)
    }

    fn decode_bits(value: u128, width: usize) -> Result<Self> {
        if width != 1 || value > 1 {
            return Err(Error::BitPacking("invalid packed boolean"));
        }
        Ok(value != 0)
    }
}

macro_rules! unsigned_value {
    ($($ty:ty),+ $(,)?) => {$(
        impl BitValue for $ty {
            fn encode_bits(self, width: usize) -> Result<u128> {
                if width == 0 || width > <$ty>::BITS as usize {
                    return Err(Error::BitPacking("invalid unsigned field width"));
                }
                let value = self as u128;
                if width < 128 && value >= (1u128 << width) {
                    return Err(Error::BitPacking("unsigned field value is out of range"));
                }
                Ok(value)
            }

            fn decode_bits(value: u128, width: usize) -> Result<Self> {
                if width == 0 || width > <$ty>::BITS as usize || value > <$ty>::MAX as u128 {
                    return Err(Error::BitPacking("invalid packed unsigned value"));
                }
                Ok(value as $ty)
            }
        }
    )+};
}

macro_rules! signed_value {
    ($($ty:ty),+ $(,)?) => {$(
        impl BitValue for $ty {
            fn encode_bits(self, width: usize) -> Result<u128> {
                if width == 0 || width > <$ty>::BITS as usize {
                    return Err(Error::BitPacking("invalid signed field width"));
                }
                let value = self as i128;
                let (minimum, maximum) = if width == 128 {
                    (i128::MIN, i128::MAX)
                } else {
                    (-(1i128 << (width - 1)), (1i128 << (width - 1)) - 1)
                };
                if value < minimum || value > maximum {
                    return Err(Error::BitPacking("signed field value is out of range"));
                }
                let mask = if width == 128 { u128::MAX } else { (1u128 << width) - 1 };
                Ok((value as u128) & mask)
            }

            fn decode_bits(value: u128, width: usize) -> Result<Self> {
                if width == 0 || width > <$ty>::BITS as usize {
                    return Err(Error::BitPacking("invalid packed signed width"));
                }
                let signed = if width == 128 {
                    value as i128
                } else if value & (1u128 << (width - 1)) != 0 {
                    (value | (!0u128 << width)) as i128
                } else {
                    value as i128
                };
                if signed < <$ty>::MIN as i128 || signed > <$ty>::MAX as i128 {
                    return Err(Error::BitPacking("invalid packed signed value"));
                }
                Ok(signed as $ty)
            }
        }
    )+};
}

unsigned_value!(u8, u16, u32, u64, u128);
signed_value!(i8, i16, i32, i64, i128);

macro_rules! primitive_pack {
    ($($ty:ty),+ $(,)?) => {$(
        impl BitPack for $ty {
            const MAX_BITS: usize = <$ty>::BITS as usize;
            fn pack(&self, writer: &mut BitWriter<'_>) -> Result<()> {
                writer.write(<$ty as BitValue>::encode_bits(*self, Self::MAX_BITS)?, Self::MAX_BITS)
            }
            fn unpack(reader: &mut BitReader<'_>) -> Result<Self> {
                <$ty as BitValue>::decode_bits(reader.read(Self::MAX_BITS)?, Self::MAX_BITS)
            }
        }
    )+};
}

primitive_pack!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

impl BitPack for bool {
    const MAX_BITS: usize = 1;
    fn pack(&self, writer: &mut BitWriter<'_>) -> Result<()> {
        writer.write(*self as u128, 1)
    }
    fn unpack(reader: &mut BitReader<'_>) -> Result<Self> {
        Ok(reader.read(1)? != 0)
    }
}
