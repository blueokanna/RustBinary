use serde::de::{
    self, value::U32Deserializer, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess,
    Visitor,
};
use serde::Deserialize;

use crate::{
    config::{Config, IntEncoding, TrailingBytes},
    error::{Error, Result},
};

const U16_MARKER: u8 = 251;
const U32_MARKER: u8 = 252;
const U64_MARKER: u8 = 253;
const U128_MARKER: u8 = 254;

pub(crate) fn from_slice<'de, T: Deserialize<'de>>(input: &'de [u8], config: Config) -> Result<T> {
    let (value, consumed) = from_slice_with_consumed(input, config)?;
    if config.trailing == TrailingBytes::Reject && consumed != input.len() {
        return Err(Error::TrailingBytes {
            remaining: input.len() - consumed,
        });
    }
    Ok(value)
}

pub(crate) fn from_slice_with_consumed<'de, T: Deserialize<'de>>(
    input: &'de [u8],
    config: Config,
) -> Result<(T, usize)> {
    let mut decoder = Decoder {
        input,
        cursor: 0,
        config,
    };
    let value = T::deserialize(&mut decoder)?;
    Ok((value, decoder.cursor))
}

struct Decoder<'de> {
    input: &'de [u8],
    cursor: usize,
    config: Config,
}

impl<'de> Decoder<'de> {
    fn take(&mut self, len: usize) -> Result<&'de [u8]> {
        let end = self.cursor.checked_add(len).ok_or(Error::UnexpectedEnd)?;
        if let Some(limit) = self.config.limit {
            if end as u64 > limit {
                return Err(Error::SizeLimit { limit });
            }
        }
        let bytes = self
            .input
            .get(self.cursor..end)
            .ok_or(Error::UnexpectedEnd)?;
        self.cursor = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::UnexpectedEnd)
    }

    fn unsigned(&mut self, fixed_bytes: usize, target_max: u128) -> Result<u128> {
        let value = if self.config.integers == IntEncoding::Variable && fixed_bytes > 1 {
            self.varint()?
        } else {
            let source = self.take(fixed_bytes)?;
            let mut bytes = [0; 16];
            if self.config.endian.little() {
                bytes[..fixed_bytes].copy_from_slice(source);
                u128::from_le_bytes(bytes)
            } else {
                bytes[16 - fixed_bytes..].copy_from_slice(source);
                u128::from_be_bytes(bytes)
            }
        };
        if value > target_max {
            Err(Error::IntegerOverflow {
                target: unsigned_name(fixed_bytes),
            })
        } else {
            Ok(value)
        }
    }

    fn signed(&mut self, fixed_bytes: usize, min: i128, max: i128) -> Result<i128> {
        let value = if self.config.integers == IntEncoding::Variable && fixed_bytes > 1 {
            let encoded = self.varint()?;
            ((encoded >> 1) as i128) ^ -((encoded & 1) as i128)
        } else {
            let source = self.take(fixed_bytes)?;
            let fill = if source.first().is_some_and(|first| {
                if self.config.endian.little() {
                    source[fixed_bytes - 1] & 0x80 != 0
                } else {
                    first & 0x80 != 0
                }
            }) {
                0xff
            } else {
                0
            };
            let mut bytes = [fill; 16];
            if self.config.endian.little() {
                bytes[..fixed_bytes].copy_from_slice(source);
                i128::from_le_bytes(bytes)
            } else {
                bytes[16 - fixed_bytes..].copy_from_slice(source);
                i128::from_be_bytes(bytes)
            }
        };
        if value < min || value > max {
            Err(Error::IntegerOverflow {
                target: signed_name(fixed_bytes),
            })
        } else {
            Ok(value)
        }
    }

    fn varint(&mut self) -> Result<u128> {
        let marker = self.byte()?;
        let (value, minimum) = match marker {
            0..=250 => return Ok(marker as u128),
            U16_MARKER => (self.literal_u16()? as u128, 251),
            U32_MARKER => (self.literal_u32()? as u128, 0x1_0000),
            U64_MARKER => (self.literal_u64()? as u128, 0x1_0000_0000),
            U128_MARKER => (self.literal_u128()?, 0x1_0000_0000_0000_0000),
            other => return Err(Error::InvalidVarintMarker(other)),
        };
        if value < minimum {
            Err(Error::NonCanonicalVarint)
        } else {
            Ok(value)
        }
    }

    fn literal_u16(&mut self) -> Result<u16> {
        let b = self.fixed()?;
        Ok(if self.config.endian.little() {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    }
    fn literal_u32(&mut self) -> Result<u32> {
        let b = self.fixed()?;
        Ok(if self.config.endian.little() {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }
    fn literal_u64(&mut self) -> Result<u64> {
        let b = self.fixed()?;
        Ok(if self.config.endian.little() {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        })
    }
    fn literal_u128(&mut self) -> Result<u128> {
        let b = self.fixed()?;
        Ok(if self.config.endian.little() {
            u128::from_le_bytes(b)
        } else {
            u128::from_be_bytes(b)
        })
    }

    fn length(&mut self) -> Result<usize> {
        let value = self.unsigned(8, u64::MAX as u128)?;
        if let Some(limit) = self.config.collection_limit {
            if value > limit as u128 {
                return Err(Error::CollectionLimit { limit });
            }
        }
        usize::try_from(value).map_err(|_| Error::IntegerOverflow { target: "usize" })
    }

    fn sequence<V: Visitor<'de>>(&mut self, len: usize, visitor: V) -> Result<V::Value> {
        let mut access = Sequence {
            decoder: self,
            remaining: len,
        };
        let value = visitor.visit_seq(&mut access)?;
        if access.remaining != 0 {
            return Err(Error::Custom(
                "sequence ended before all elements were decoded".into(),
            ));
        }
        Ok(value)
    }
}

const fn unsigned_name(bytes: usize) -> &'static str {
    match bytes {
        2 => "u16",
        4 => "u32",
        8 => "u64",
        16 => "u128",
        _ => "unsigned integer",
    }
}
const fn signed_name(bytes: usize) -> &'static str {
    match bytes {
        2 => "i16",
        4 => "i32",
        8 => "i64",
        16 => "i128",
        _ => "signed integer",
    }
}

struct Sequence<'a, 'de> {
    decoder: &'a mut Decoder<'de>,
    remaining: usize,
}

impl<'de> SeqAccess<'de> for &mut Sequence<'_, 'de> {
    type Error = Error;
    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        seed.deserialize(&mut *self.decoder).map(Some)
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.remaining)
    }
}

struct Map<'a, 'de> {
    decoder: &'a mut Decoder<'de>,
    remaining: usize,
    value_pending: bool,
}

impl<'de> MapAccess<'de> for &mut Map<'_, 'de> {
    type Error = Error;
    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        if self.value_pending {
            return Err(Error::Custom("map requested a key before its value".into()));
        }
        let key = seed.deserialize(&mut *self.decoder)?;
        self.value_pending = true;
        Ok(Some(key))
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value> {
        if !self.value_pending {
            return Err(Error::Custom("map requested a value without a key".into()));
        }
        let value = seed.deserialize(&mut *self.decoder)?;
        self.value_pending = false;
        self.remaining -= 1;
        Ok(value)
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.remaining)
    }
}

macro_rules! number {
    ($method:ident, $visit:ident, unsigned, $ty:ty, $bytes:expr) => {
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
            visitor.$visit(self.unsigned($bytes, <$ty>::MAX as u128)? as $ty)
        }
    };
    ($method:ident, $visit:ident, signed, $ty:ty, $bytes:expr) => {
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
            visitor.$visit(self.signed($bytes, <$ty>::MIN as i128, <$ty>::MAX as i128)? as $ty)
        }
    };
}

impl<'de> de::Deserializer<'de> for &mut Decoder<'de> {
    type Error = Error;
    fn deserialize_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Unsupported("deserialize_any"))
    }
    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.byte()? {
            0 => visitor.visit_bool(false),
            1 => visitor.visit_bool(true),
            value => Err(Error::InvalidBool(value)),
        }
    }
    fn deserialize_i8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_i8(self.byte()? as i8)
    }
    number!(deserialize_i16, visit_i16, signed, i16, 2);
    number!(deserialize_i32, visit_i32, signed, i32, 4);
    number!(deserialize_i64, visit_i64, signed, i64, 8);
    number!(deserialize_i128, visit_i128, signed, i128, 16);
    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_u8(self.byte()?)
    }
    number!(deserialize_u16, visit_u16, unsigned, u16, 2);
    number!(deserialize_u32, visit_u32, unsigned, u32, 4);
    number!(deserialize_u64, visit_u64, unsigned, u64, 8);
    number!(deserialize_u128, visit_u128, unsigned, u128, 16);
    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let b = self.fixed()?;
        visitor.visit_f32(if self.config.endian.little() {
            f32::from_le_bytes(b)
        } else {
            f32::from_be_bytes(b)
        })
    }
    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let b = self.fixed()?;
        visitor.visit_f64(if self.config.endian.little() {
            f64::from_le_bytes(b)
        } else {
            f64::from_be_bytes(b)
        })
    }
    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let first = self.byte()?;
        let width = match first {
            0x00..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => return Err(Error::InvalidChar),
        };
        let mut bytes = [0; 4];
        bytes[0] = first;
        if width > 1 {
            bytes[1..width].copy_from_slice(self.take(width - 1).map_err(|_| Error::InvalidChar)?);
        }
        let text = core::str::from_utf8(&bytes[..width]).map_err(|_| Error::InvalidChar)?;
        let value = text.chars().next().ok_or(Error::InvalidChar)?;
        visitor.visit_char(value)
    }
    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let len = self.length()?;
        let bytes = self.take(len)?;
        let value = core::str::from_utf8(bytes).map_err(Error::InvalidUtf8)?;
        visitor.visit_borrowed_str(value)
    }
    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_str(visitor)
    }
    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let len = self.length()?;
        visitor.visit_borrowed_bytes(self.take(len)?)
    }
    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_bytes(visitor)
    }
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.byte()? {
            0 => visitor.visit_none(),
            1 => visitor.visit_some(self),
            value => Err(Error::InvalidOption(value)),
        }
    }
    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_unit()
    }
    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_unit()
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_newtype_struct(self)
    }
    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let len = self.length()?;
        self.sequence(len, visitor)
    }
    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value> {
        self.sequence(len, visitor)
    }
    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value> {
        self.sequence(len, visitor)
    }
    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let len = self.length()?;
        let mut access = Map {
            decoder: self,
            remaining: len,
            value_pending: false,
        };
        let value = visitor.visit_map(&mut access)?;
        if access.remaining != 0 || access.value_pending {
            return Err(Error::Custom(
                "map ended before all entries were decoded".into(),
            ));
        }
        Ok(value)
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        self.sequence(fields.len(), visitor)
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        let variant = self.unsigned(4, u32::MAX as u128)? as u32;
        visitor.visit_enum(Variant {
            decoder: self,
            index: variant,
        })
    }
    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_str(visitor)
    }
    fn deserialize_ignored_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Unsupported("deserialize_ignored_any"))
    }
}

struct Variant<'a, 'de> {
    decoder: &'a mut Decoder<'de>,
    index: u32,
}

impl<'de> EnumAccess<'de> for Variant<'_, 'de> {
    type Error = Error;
    type Variant = Self;
    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, Self)> {
        let index = seed.deserialize(U32Deserializer::<Error>::new(self.index))?;
        Ok((index, self))
    }
}

impl<'de> VariantAccess<'de> for Variant<'_, 'de> {
    type Error = Error;
    fn unit_variant(self) -> Result<()> {
        Ok(())
    }
    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value> {
        seed.deserialize(self.decoder)
    }
    fn tuple_variant<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value> {
        de::Deserializer::deserialize_tuple(self.decoder, len, visitor)
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        de::Deserializer::deserialize_tuple(self.decoder, fields.len(), visitor)
    }
}
