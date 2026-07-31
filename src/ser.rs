use std::io::{self, Write};

use serde::ser::{
    self, Serialize, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant,
    SerializeTuple, SerializeTupleStruct, SerializeTupleVariant,
};

use crate::{
    config::{Config, IntEncoding},
    error::{Error, Result},
};

const U16_MARKER: u8 = 251;
const U32_MARKER: u8 = 252;
const U64_MARKER: u8 = 253;
const U128_MARKER: u8 = 254;

pub(crate) fn to_vec<T: Serialize + ?Sized>(value: &T, config: Config) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    to_writer(&mut output, value, config)?;
    Ok(output)
}

pub(crate) fn to_writer<W: Write, T: Serialize + ?Sized>(
    writer: W,
    value: &T,
    config: Config,
) -> Result<u64> {
    let mut encoder = Encoder {
        writer,
        config,
        written: 0,
    };
    value.serialize(&mut encoder)?;
    Ok(encoder.written)
}

pub(crate) fn to_slice<T: Serialize + ?Sized>(
    output: &mut [u8],
    value: &T,
    config: Config,
) -> Result<usize> {
    let available = output.len();
    let mut sink = SliceSink {
        output,
        required: 0,
    };
    let encoded = to_writer(&mut sink, value, config)?;
    let required =
        usize::try_from(encoded).map_err(|_| Error::IntegerOverflow { target: "usize" })?;
    if required > available {
        Err(Error::BufferTooSmall {
            required,
            available,
        })
    } else {
        Ok(required)
    }
}

pub(crate) fn size<T: Serialize + ?Sized>(value: &T, config: Config) -> Result<u64> {
    to_writer(Counter, value, config)
}

struct Counter;

impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct SliceSink<'a> {
    output: &'a mut [u8],
    required: usize,
}

impl Write for SliceSink<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let start = self.required.min(self.output.len());
        let writable = (self.output.len() - start).min(bytes.len());
        self.output[start..start + writable].copy_from_slice(&bytes[..writable]);
        self.required = self
            .required
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("encoded length exceeds usize"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Encoder<W> {
    writer: W,
    config: Config,
    written: u64,
}

impl<W: Write> Encoder<W> {
    fn emit(&mut self, bytes: &[u8]) -> Result<()> {
        let amount =
            u64::try_from(bytes.len()).map_err(|_| Error::IntegerOverflow { target: "u64" })?;
        let next = self
            .written
            .checked_add(amount)
            .ok_or(Error::SizeLimit { limit: u64::MAX })?;
        if let Some(limit) = self.config.limit {
            if next > limit {
                return Err(Error::SizeLimit { limit });
            }
        }
        self.writer.write_all(bytes)?;
        self.written = next;
        Ok(())
    }

    fn fixed<const N: usize>(&mut self, little: [u8; N], big: [u8; N]) -> Result<()> {
        self.emit(if self.config.endian.little() {
            &little
        } else {
            &big
        })
    }

    fn unsigned(&mut self, value: u128, fixed_bytes: usize) -> Result<()> {
        if self.config.integers == IntEncoding::Variable && fixed_bytes > 1 {
            return self.varint(value);
        }
        let little = value.to_le_bytes();
        let big = value.to_be_bytes();
        if self.config.endian.little() {
            self.emit(&little[..fixed_bytes])
        } else {
            self.emit(&big[16 - fixed_bytes..])
        }
    }

    fn signed(&mut self, value: i128, fixed_bytes: usize) -> Result<()> {
        if self.config.integers == IntEncoding::Variable && fixed_bytes > 1 {
            let bits = (fixed_bytes * 8) - 1;
            return self.varint(((value << 1) ^ (value >> bits)) as u128);
        }
        let little = value.to_le_bytes();
        let big = value.to_be_bytes();
        if self.config.endian.little() {
            self.emit(&little[..fixed_bytes])
        } else {
            self.emit(&big[16 - fixed_bytes..])
        }
    }

    fn varint(&mut self, value: u128) -> Result<()> {
        match value {
            0..=250 => self.emit(&[value as u8]),
            251..=0xffff => {
                self.emit(&[U16_MARKER])?;
                self.fixed((value as u16).to_le_bytes(), (value as u16).to_be_bytes())
            }
            0x1_0000..=0xffff_ffff => {
                self.emit(&[U32_MARKER])?;
                self.fixed((value as u32).to_le_bytes(), (value as u32).to_be_bytes())
            }
            0x1_0000_0000..=0xffff_ffff_ffff_ffff => {
                self.emit(&[U64_MARKER])?;
                self.fixed((value as u64).to_le_bytes(), (value as u64).to_be_bytes())
            }
            _ => {
                self.emit(&[U128_MARKER])?;
                self.fixed(value.to_le_bytes(), value.to_be_bytes())
            }
        }
    }

    fn length(&mut self, len: usize) -> Result<()> {
        let len = u64::try_from(len).map_err(|_| Error::IntegerOverflow { target: "u64" })?;
        if let Some(limit) = self.config.collection_limit {
            if len > limit {
                return Err(Error::CollectionLimit { limit });
            }
        }
        self.unsigned(len as u128, 8)
    }
}

struct Compound<'a, W> {
    encoder: &'a mut Encoder<W>,
    remaining: usize,
    map_value_pending: bool,
}

impl<W: Write> Compound<'_, W> {
    fn item<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        if self.remaining == 0 {
            return Err(Error::Custom("too many compound elements".into()));
        }
        self.remaining -= 1;
        value.serialize(&mut *self.encoder)
    }

    fn finish(self) -> Result<()> {
        if self.remaining == 0 && !self.map_value_pending {
            Ok(())
        } else {
            Err(Error::Custom(
                "compound ended before all elements were written".into(),
            ))
        }
    }
}

macro_rules! primitive {
    ($method:ident, $ty:ty, $body:expr) => {
        fn $method(self, value: $ty) -> Result<()> {
            $body(self, value)
        }
    };
}

impl<'a, W: Write> ser::Serializer for &'a mut Encoder<W> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = Compound<'a, W>;
    type SerializeTuple = Compound<'a, W>;
    type SerializeTupleStruct = Compound<'a, W>;
    type SerializeTupleVariant = Compound<'a, W>;
    type SerializeMap = Compound<'a, W>;
    type SerializeStruct = Compound<'a, W>;
    type SerializeStructVariant = Compound<'a, W>;

    fn serialize_bool(self, value: bool) -> Result<()> {
        self.emit(&[u8::from(value)])
    }
    primitive!(serialize_i8, i8, |this: &mut Encoder<W>, value: i8| this
        .emit(&value.to_le_bytes()));
    primitive!(serialize_i16, i16, |this: &mut Encoder<W>, value: i16| this
        .signed(value as i128, 2));
    primitive!(serialize_i32, i32, |this: &mut Encoder<W>, value: i32| this
        .signed(value as i128, 4));
    primitive!(serialize_i64, i64, |this: &mut Encoder<W>, value: i64| this
        .signed(value as i128, 8));
    primitive!(
        serialize_i128,
        i128,
        |this: &mut Encoder<W>, value: i128| this.signed(value, 16)
    );
    primitive!(serialize_u8, u8, |this: &mut Encoder<W>, value: u8| this
        .emit(&[value]));
    primitive!(serialize_u16, u16, |this: &mut Encoder<W>, value: u16| this
        .unsigned(value as u128, 2));
    primitive!(serialize_u32, u32, |this: &mut Encoder<W>, value: u32| this
        .unsigned(value as u128, 4));
    primitive!(serialize_u64, u64, |this: &mut Encoder<W>, value: u64| this
        .unsigned(value as u128, 8));
    primitive!(
        serialize_u128,
        u128,
        |this: &mut Encoder<W>, value: u128| this.unsigned(value, 16)
    );
    fn serialize_f32(self, value: f32) -> Result<()> {
        self.fixed(value.to_le_bytes(), value.to_be_bytes())
    }
    fn serialize_f64(self, value: f64) -> Result<()> {
        self.fixed(value.to_le_bytes(), value.to_be_bytes())
    }
    fn serialize_char(self, value: char) -> Result<()> {
        let mut bytes = [0; 4];
        self.emit(value.encode_utf8(&mut bytes).as_bytes())
    }
    fn serialize_str(self, value: &str) -> Result<()> {
        self.length(value.len())?;
        self.emit(value.as_bytes())
    }
    fn serialize_bytes(self, value: &[u8]) -> Result<()> {
        self.length(value.len())?;
        self.emit(value)
    }
    fn serialize_none(self) -> Result<()> {
        self.emit(&[0])
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<()> {
        self.emit(&[1])?;
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<()> {
        Ok(())
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        Ok(())
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant_name: &'static str,
    ) -> Result<()> {
        self.serialize_u32(variant_index)
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<()> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant_name: &'static str,
        value: &T,
    ) -> Result<()> {
        self.serialize_u32(variant_index)?;
        value.serialize(self)
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq> {
        let len = len.ok_or(Error::SequenceMustHaveLength)?;
        self.length(len)?;
        Ok(Compound {
            encoder: self,
            remaining: len,
            map_value_pending: false,
        })
    }
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple> {
        Ok(Compound {
            encoder: self,
            remaining: len,
            map_value_pending: false,
        })
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        self.serialize_tuple(len)
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant_name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        self.serialize_u32(variant_index)?;
        self.serialize_tuple(len)
    }
    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap> {
        let len = len.ok_or(Error::SequenceMustHaveLength)?;
        self.length(len)?;
        Ok(Compound {
            encoder: self,
            remaining: len,
            map_value_pending: false,
        })
    }
    fn serialize_struct(self, _name: &'static str, len: usize) -> Result<Self::SerializeStruct> {
        self.serialize_tuple(len)
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant_name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        self.serialize_u32(variant_index)?;
        self.serialize_tuple(len)
    }
}

macro_rules! compound_trait {
    ($trait:ident, $method:ident) => {
        impl<W: Write> $trait for Compound<'_, W> {
            type Ok = ();
            type Error = Error;
            fn $method<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
                self.item(value)
            }
            fn end(self) -> Result<()> {
                self.finish()
            }
        }
    };
}
compound_trait!(SerializeSeq, serialize_element);
compound_trait!(SerializeTuple, serialize_element);
compound_trait!(SerializeTupleStruct, serialize_field);
compound_trait!(SerializeTupleVariant, serialize_field);

impl<W: Write> SerializeMap for Compound<'_, W> {
    type Ok = ();
    type Error = Error;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<()> {
        if self.remaining == 0 || self.map_value_pending {
            return Err(Error::Custom("invalid map key/value order".into()));
        }
        key.serialize(&mut *self.encoder)?;
        self.map_value_pending = true;
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        if !self.map_value_pending {
            return Err(Error::Custom("map value has no preceding key".into()));
        }
        value.serialize(&mut *self.encoder)?;
        self.map_value_pending = false;
        self.remaining -= 1;
        Ok(())
    }
    fn end(self) -> Result<()> {
        self.finish()
    }
}

impl<W: Write> SerializeStruct for Compound<'_, W> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        _key: &'static str,
        value: &T,
    ) -> Result<()> {
        self.item(value)
    }
    fn end(self) -> Result<()> {
        self.finish()
    }
}

impl<W: Write> SerializeStructVariant for Compound<'_, W> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        _key: &'static str,
        value: &T,
    ) -> Result<()> {
        self.item(value)
    }
    fn end(self) -> Result<()> {
        self.finish()
    }
}
