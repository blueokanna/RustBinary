/// Description of one struct, tuple, or enum-variant field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldInfo {
    /// Declared field name, or its tuple index.
    pub name: &'static str,
    /// Canonical token representation of the declared Rust type.
    pub type_name: &'static str,
    /// Zero-based declaration index.
    pub index: usize,
    /// Exact symbol-alphabet size for entropy coding, or `0` when unknown.
    pub symbols: u32,
}

/// Description of one enum variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VariantInfo {
    /// Declared variant name.
    pub name: &'static str,
    /// Zero-based discriminant used by the default nextjson representation.
    pub index: usize,
    /// Variant fields in declaration order.
    pub fields: &'static [FieldInfo],
}

/// Static structural shape generated for a reflected type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypeShape {
    /// A struct or tuple struct.
    Struct(&'static [FieldInfo]),
    /// An enum and all its variants.
    Enum(&'static [VariantInfo]),
}

/// Compile-time structural reflection without runtime registration or allocation.
pub trait Reflect {
    /// Fully qualified declared type name.
    const TYPE_NAME: &'static str;
    /// Static structural metadata.
    const SHAPE: TypeShape;
}
