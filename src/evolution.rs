use alloc::vec::Vec;

use crate::{Config, Error, Result, TrailingBytes};

const MAGIC: &[u8; 4] = b"RBE1";
const FORMAT_VERSION: u16 = 1;
const HEADER_SIZE: usize = 24;
const FIELD_HEADER_SIZE: usize = 12;

/// Encoding contract for a type with stable field identifiers.
pub trait SchemaEncode {
    /// Stable identity shared by compatible revisions of this schema.
    const SCHEMA_ID: u64;
    /// Revision written into new frames.
    const SCHEMA_VERSION: u32;

    /// Adds this revision's fields to `encoder`.
    fn encode_fields(&self, encoder: &mut FieldEncoder) -> Result<()>;
}

/// Decoding contract for a type that accepts compatible schema revisions.
pub trait SchemaDecode<'de>: Sized {
    /// Stable identity shared by compatible revisions of this schema.
    const SCHEMA_ID: u64;

    /// Constructs a value from stable-ID fields.
    ///
    /// `encoded_version` is available for explicit migrations. Unknown fields
    /// remain accessible through [`FieldDecoder::unknown_fields`].
    fn decode_fields(decoder: &mut FieldDecoder<'de>, encoded_version: u32) -> Result<Self>;
}

/// Configuration for stable-field-ID schema evolution frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvolutionConfig {
    base: Config,
}

impl EvolutionConfig {
    pub(crate) const fn new(base: Config) -> Self {
        Self { base }
    }

    /// Returns the underlying field-payload configuration.
    pub const fn base_config(self) -> Config {
        self.base
    }

    /// Always [`crate::BinaryProfile::Evolution`].
    pub const fn profile(self) -> crate::BinaryProfile {
        crate::BinaryProfile::Evolution
    }

    /// Serializes a value with schema identity, revision, and stable field IDs.
    pub fn serialize<T: SchemaEncode + ?Sized>(self, value: &T) -> Result<Vec<u8>> {
        let mut encoder = FieldEncoder::new(self.base);
        value.encode_fields(&mut encoder)?;
        encoder.finish::<T>()
    }

    /// Deserializes a value, allowing its implementation to default or migrate fields.
    pub fn deserialize<'de, T: SchemaDecode<'de>>(self, input: &'de [u8]) -> Result<T> {
        self.enforce_byte_limit(input.len())?;
        let mut cursor = Cursor::new(input);
        if cursor.take(4)? != MAGIC {
            return Err(Error::InvalidFrame("bad schema evolution magic"));
        }
        if cursor.u16()? != FORMAT_VERSION {
            return Err(Error::InvalidFrame(
                "unsupported schema evolution format version",
            ));
        }
        if cursor.u16()? != 0 {
            return Err(Error::InvalidFrame("unsupported schema evolution flags"));
        }
        let schema_id = cursor.u64()?;
        if schema_id != T::SCHEMA_ID {
            return Err(Error::SchemaMismatch {
                expected: T::SCHEMA_ID,
                actual: schema_id,
            });
        }
        let schema_version = cursor.u32()?;
        let field_count = usize::try_from(cursor.u32()?)
            .map_err(|_| Error::IntegerOverflow { target: "usize" })?;
        self.enforce_collection_limit(field_count)?;

        let minimum_headers = field_count
            .checked_mul(FIELD_HEADER_SIZE)
            .ok_or(Error::InvalidFrame("schema field table overflow"))?;
        if minimum_headers > cursor.remaining() {
            return Err(Error::UnexpectedEnd);
        }
        let mut fields = Vec::new();
        fields
            .try_reserve_exact(field_count)
            .map_err(|_| Error::SizeLimit { limit: u64::MAX })?;
        let mut previous = None;
        for _ in 0..field_count {
            let id = cursor.u32()?;
            if previous.is_some_and(|last| id <= last) {
                return Err(Error::SchemaEvolution(
                    "field IDs must be unique and strictly increasing",
                ));
            }
            previous = Some(id);
            let length = usize::try_from(cursor.u64()?)
                .map_err(|_| Error::IntegerOverflow { target: "usize" })?;
            let payload = cursor.take(length)?;
            fields.push(Field {
                id,
                payload,
                consumed: false,
            });
        }
        cursor.finish(self.base.trailing)?;

        let mut decoder = FieldDecoder {
            base: self.base,
            fields,
        };
        T::decode_fields(&mut decoder, schema_version)
    }

    fn enforce_byte_limit(self, length: usize) -> Result<()> {
        if let Some(limit) = self.base.limit {
            if length as u64 > limit {
                return Err(Error::SizeLimit { limit });
            }
        }
        Ok(())
    }

    fn enforce_collection_limit(self, length: usize) -> Result<()> {
        if let Some(limit) = self.base.collection_limit {
            if length as u64 > limit {
                return Err(Error::CollectionLimit { limit });
            }
        }
        Ok(())
    }
}

struct EncodedField {
    id: u32,
    payload: Vec<u8>,
}

/// Builder used by [`SchemaEncode`] implementations.
pub struct FieldEncoder {
    base: Config,
    fields: Vec<EncodedField>,
}

impl FieldEncoder {
    fn new(base: Config) -> Self {
        Self {
            base,
            fields: Vec::new(),
        }
    }

    /// Serializes one field under its permanent numeric identifier.
    pub fn field<T: nextjson::NsonSerialize + ?Sized>(&mut self, id: u32, value: &T) -> Result<()> {
        if self.fields.iter().any(|field| field.id == id) {
            return Err(Error::SchemaEvolution("duplicate field ID"));
        }
        let payload = self.base.serialize(value)?;
        self.fields.push(EncodedField { id, payload });
        Ok(())
    }

    fn finish<T: SchemaEncode + ?Sized>(mut self) -> Result<Vec<u8>> {
        self.fields.sort_unstable_by_key(|field| field.id);
        if let Some(limit) = self.base.collection_limit {
            if self.fields.len() as u64 > limit {
                return Err(Error::CollectionLimit { limit });
            }
        }
        let mut required = HEADER_SIZE;
        for field in &self.fields {
            required = required
                .checked_add(FIELD_HEADER_SIZE)
                .and_then(|size| size.checked_add(field.payload.len()))
                .ok_or(Error::InvalidFrame("schema evolution frame size overflow"))?;
        }
        if let Some(limit) = self.base.limit {
            if required as u64 > limit {
                return Err(Error::SizeLimit { limit });
            }
        }
        let field_count = u32::try_from(self.fields.len())
            .map_err(|_| Error::IntegerOverflow { target: "u32" })?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(required)
            .map_err(|_| Error::SizeLimit { limit: u64::MAX })?;
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&T::SCHEMA_ID.to_le_bytes());
        output.extend_from_slice(&T::SCHEMA_VERSION.to_le_bytes());
        output.extend_from_slice(&field_count.to_le_bytes());
        for field in self.fields {
            output.extend_from_slice(&field.id.to_le_bytes());
            output.extend_from_slice(&(field.payload.len() as u64).to_le_bytes());
            output.extend_from_slice(&field.payload);
        }
        debug_assert_eq!(output.len(), required);
        Ok(output)
    }
}

struct Field<'de> {
    id: u32,
    payload: &'de [u8],
    consumed: bool,
}

/// Borrowed unknown field exposed for forwarding or application migrations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnknownField<'de> {
    /// Stable numeric identifier.
    pub id: u32,
    /// Encoded field payload under the frame's base configuration.
    pub payload: &'de [u8],
}

/// Stable-ID field access used by [`SchemaDecode`] implementations.
pub struct FieldDecoder<'de> {
    base: Config,
    fields: Vec<Field<'de>>,
}

impl<'de> FieldDecoder<'de> {
    /// Decodes a required field and reports a missing-field error.
    pub fn required<T: nextjson::NsonDeserialize<'de>>(&mut self, id: u32) -> Result<T> {
        self.optional(id)?
            .ok_or(Error::SchemaEvolution("required field is missing"))
    }

    /// Decodes an optional field, returning `None` when it is absent.
    pub fn optional<T: nextjson::NsonDeserialize<'de>>(&mut self, id: u32) -> Result<Option<T>> {
        let Ok(index) = self.fields.binary_search_by_key(&id, |field| field.id) else {
            return Ok(None);
        };
        let field = &mut self.fields[index];
        if field.consumed {
            return Err(Error::SchemaEvolution("field decoded more than once"));
        }
        field.consumed = true;
        self.base.deserialize(field.payload).map(Some)
    }

    /// Decodes a field or returns its type's default when absent.
    pub fn or_default<T: nextjson::NsonDeserialize<'de> + Default>(
        &mut self,
        id: u32,
    ) -> Result<T> {
        Ok(self.optional(id)?.unwrap_or_default())
    }

    /// Returns fields that have not been consumed by this schema revision.
    pub fn unknown_fields(&self) -> impl Iterator<Item = UnknownField<'de>> + '_ {
        self.fields
            .iter()
            .filter(|field| !field.consumed)
            .map(|field| UnknownField {
                id: field.id,
                payload: field.payload,
            })
    }
}

struct Cursor<'de> {
    input: &'de [u8],
    position: usize,
}

impl<'de> Cursor<'de> {
    const fn new(input: &'de [u8]) -> Self {
        Self { input, position: 0 }
    }

    const fn remaining(&self) -> usize {
        self.input.len() - self.position
    }

    fn take(&mut self, length: usize) -> Result<&'de [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(Error::UnexpectedEnd)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(Error::UnexpectedEnd)?;
        self.position = end;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("fixed width"),
        ))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("fixed width"),
        ))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("fixed width"),
        ))
    }

    fn finish(self, trailing: TrailingBytes) -> Result<()> {
        if trailing == TrailingBytes::Reject && self.position != self.input.len() {
            return Err(Error::TrailingBytes {
                remaining: self.input.len() - self.position,
            });
        }
        Ok(())
    }
}
