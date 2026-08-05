#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Procedural derives used by `rustbinary`.
//!
//! Applications normally enable the matching `rustbinary` feature and use the
//! derives re-exported by the main crate. Generated paths intentionally refer
//! to `::rustbinary`, keeping the runtime traits and wire implementation owned
//! by one crate.
//! The procedural macro runs on the host with `std`, but generated code uses
//! only core syntax and the selected RustBinary runtime traits, so consumers
//! may expand these derives in `no_std` crates.
//!
//! # Macro selection
//!
//! - [`Fingerprint`](derive@Fingerprint) generates a compatibility identifier
//!   for type structure and codec configuration.
//! - [`StaticSize`](derive@StaticSize) generates finite normal and bit-packed
//!   size bounds for statically sized values.
//! - [`Reflect`](derive@Reflect) generates allocation-free structural metadata.
//! - [`BitPacked`](derive@BitPacked) generates a checked bit-level codec for
//!   bounded fields and nested `BitPack` values.
//!
//! The generated implementations are not a replacement for Serde derives.
//! Add `Serialize` and `Deserialize` when the value also crosses a normal
//! `rustbinary` or CBOR wire profile. For the complete syntax and production
//! constraints, see the package README and the re-exported runtime traits.

use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::{
    parse_macro_input, parse_quote, Data, DataEnum, DataStruct, DeriveInput, Expr, Fields,
    Generics, Lit, Meta, Type,
};

#[proc_macro_derive(Fingerprint)]
/// Derives `rustbinary::Fingerprint` from structural type metadata.
///
/// Struct field names/types and enum variant names/order participate in the
/// identifier. Unions are rejected. Generic type parameters receive the
/// corresponding `Fingerprint` bound.
pub fn derive_fingerprint(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    fingerprint_impl(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[proc_macro_derive(StaticSize, attributes(bits))]
/// Derives compile-time normal and bit-packed size bounds.
///
/// Fields must implement `rustbinary::StaticSize`. An optional `#[bits = N]`
/// attribute contributes the explicit packed width. Dynamic collections do not
/// provide a finite `StaticSize` implementation.
pub fn derive_static_size(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    static_size_impl(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[proc_macro_derive(Reflect)]
/// Derives allocation-free structural reflection metadata.
///
/// Generated metadata contains the declared type name, fields, field type
/// tokens, declaration indexes, and enum variants. No registry or runtime
/// initialization is generated.
pub fn derive_reflect(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    reflect_impl(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[proc_macro_derive(BitPacked, attributes(bits))]
/// Derives `rustbinary::BitPack` for structs and enums.
///
/// Fields with `#[bits = N]` use `BitValue` range validation. Other fields
/// recursively use `BitPack`. Enum tags use the minimum bit width and unknown
/// decoded tags are rejected.
pub fn derive_bit_packed(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    bit_packed_impl(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn add_bound(mut generics: Generics, bound: syn::Path) -> Generics {
    for parameter in generics.type_params_mut() {
        parameter.bounds.push(parse_quote!(#bound));
    }
    generics
}

fn field_name(index: usize, field: &syn::Field) -> String {
    field
        .ident
        .as_ref()
        .map_or_else(|| index.to_string(), ToString::to_string)
}

fn hash_field(index: usize, field: &syn::Field) -> proc_macro2::TokenStream {
    let name = field_name(index, field);
    let ty = &field.ty;
    quote! {
        hash = ::rustbinary::schema::hash_bytes(hash, #name.as_bytes());
        hash = ::rustbinary::schema::hash_u64(hash, <#ty as ::rustbinary::Fingerprint>::TYPE_FINGERPRINT);
    }
}

fn fingerprint_impl(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let name = &input.ident;
    let generics = add_bound(
        input.generics.clone(),
        parse_quote!(::rustbinary::Fingerprint),
    );
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();
    let body = match &input.data {
        Data::Struct(data) => {
            let fields = data
                .fields
                .iter()
                .enumerate()
                .map(|(index, field)| hash_field(index, field));
            quote! {
                let mut hash = ::rustbinary::schema::hash_bytes(
                    ::rustbinary::schema::FNV_OFFSET,
                    concat!(module_path!(), "::", stringify!(#name), "|struct").as_bytes(),
                );
                #(#fields)*
                hash
            }
        }
        Data::Enum(data) => fingerprint_enum(name, data),
        Data::Union(_) => {
            return Err(syn::Error::new_spanned(
                input,
                "Fingerprint cannot be derived for unions",
            ))
        }
    };
    Ok(quote! {
        impl #impl_generics ::rustbinary::Fingerprint for #name #type_generics #where_clause {
            const TYPE_FINGERPRINT: u64 = { #body };
        }
    })
}

fn fingerprint_enum(name: &syn::Ident, data: &DataEnum) -> proc_macro2::TokenStream {
    let variants = data
        .variants
        .iter()
        .enumerate()
        .map(|(variant_index, variant)| {
            let variant_name = variant.ident.to_string();
            let index = variant_index as u64;
            let fields = variant
                .fields
                .iter()
                .enumerate()
                .map(|(field_index, field)| hash_field(field_index, field));
            quote! {
                hash = ::rustbinary::schema::hash_u64(hash, #index);
                hash = ::rustbinary::schema::hash_bytes(hash, #variant_name.as_bytes());
                #(#fields)*
            }
        });
    quote! {
        let mut hash = ::rustbinary::schema::hash_bytes(
            ::rustbinary::schema::FNV_OFFSET,
            concat!(module_path!(), "::", stringify!(#name), "|enum").as_bytes(),
        );
        #(#variants)*
        hash
    }
}

fn static_field_size(field: &syn::Field, packed: bool) -> proc_macro2::TokenStream {
    let ty = &field.ty;
    if packed {
        quote!(<#ty as ::rustbinary::StaticSize>::PACKED_MAX_SIZE)
    } else {
        quote!(<#ty as ::rustbinary::StaticSize>::MAX_SIZE)
    }
}

fn static_field_bits(field: &syn::Field) -> syn::Result<proc_macro2::TokenStream> {
    let ty = &field.ty;
    Ok(match declared_bits(field)? {
        Some(width) => quote!(#width),
        None => quote!(<#ty as ::rustbinary::StaticSize>::PACKED_MAX_BITS),
    })
}

fn sum_field_bits(fields: &Fields) -> syn::Result<proc_macro2::TokenStream> {
    let mut sum = quote!(0usize);
    for field in fields {
        let bits = static_field_bits(field)?;
        sum = quote!(::rustbinary::static_size::saturating_add(#sum, #bits));
    }
    Ok(sum)
}

fn sum_fields(fields: &Fields, packed: bool) -> proc_macro2::TokenStream {
    fields.iter().fold(quote!(0usize), |sum, field| {
        let size = static_field_size(field, packed);
        quote!(::rustbinary::static_size::saturating_add(#sum, #size))
    })
}

fn max_variants(data: &DataEnum, packed: bool) -> proc_macro2::TokenStream {
    data.variants
        .iter()
        .fold(quote!(0usize), |maximum, variant| {
            let size = sum_fields(&variant.fields, packed);
            quote!(::rustbinary::static_size::max(#maximum, #size))
        })
}

fn static_size_impl(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let name = &input.ident;
    let generics = add_bound(
        input.generics.clone(),
        parse_quote!(::rustbinary::StaticSize),
    );
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();
    let (maximum, packed_bits) = match &input.data {
        Data::Struct(data) => (
            sum_fields(&data.fields, false),
            sum_field_bits(&data.fields)?,
        ),
        Data::Enum(data) => {
            let maximum = max_variants(data, false);
            let tag_bits = if data.variants.len() <= 1 {
                0usize
            } else {
                (usize::BITS - (data.variants.len() - 1).leading_zeros()) as usize
            };
            let mut packed_payload = quote!(0usize);
            for variant in &data.variants {
                let bits = sum_field_bits(&variant.fields)?;
                packed_payload = quote!(::rustbinary::static_size::max(#packed_payload, #bits));
            }
            (
                quote!(::rustbinary::static_size::saturating_add(5, #maximum)),
                quote!(::rustbinary::static_size::saturating_add(#tag_bits, #packed_payload)),
            )
        }
        Data::Union(_) => {
            return Err(syn::Error::new_spanned(
                input,
                "StaticSize cannot be derived for unions",
            ))
        }
    };
    Ok(quote! {
        impl #impl_generics ::rustbinary::StaticSize for #name #type_generics #where_clause {
            const MAX_SIZE: usize = #maximum;
            const PACKED_MAX_BITS: usize = #packed_bits;
            const PACKED_MAX_SIZE: usize = ::rustbinary::static_size::bytes_for_bits(#packed_bits);
        }
    })
}

fn type_name(ty: &Type) -> String {
    ty.to_token_stream().to_string().replace(' ', "")
}

fn reflect_fields(fields: &Fields) -> proc_macro2::TokenStream {
    let descriptors = fields.iter().enumerate().map(|(index, field)| {
        let name = field_name(index, field);
        let ty = type_name(&field.ty);
        quote!(::rustbinary::FieldInfo { name: #name, type_name: #ty, index: #index })
    });
    quote!(&[#(#descriptors),*])
}

fn reflect_impl(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let name = &input.ident;
    let generics = input.generics.clone();
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();
    let shape = match &input.data {
        Data::Struct(DataStruct { fields, .. }) => {
            let fields = reflect_fields(fields);
            quote!(::rustbinary::TypeShape::Struct(#fields))
        }
        Data::Enum(data) => {
            let variants = data.variants.iter().enumerate().map(|(index, variant)| {
                let variant_name = variant.ident.to_string();
                let fields = reflect_fields(&variant.fields);
                quote!(::rustbinary::VariantInfo { name: #variant_name, index: #index, fields: #fields })
            });
            quote!(::rustbinary::TypeShape::Enum(&[#(#variants),*]))
        }
        Data::Union(_) => {
            return Err(syn::Error::new_spanned(
                input,
                "Reflect cannot be derived for unions",
            ))
        }
    };
    Ok(quote! {
        impl #impl_generics ::rustbinary::Reflect for #name #type_generics #where_clause {
            const TYPE_NAME: &'static str = concat!(module_path!(), "::", stringify!(#name));
            const SHAPE: ::rustbinary::TypeShape = #shape;
        }
    })
}

fn declared_bits(field: &syn::Field) -> syn::Result<Option<usize>> {
    let mut attributes = field
        .attrs
        .iter()
        .filter(|attribute| attribute.path().is_ident("bits"));
    let Some(attribute) = attributes.next() else {
        return Ok(None);
    };
    if let Some(duplicate) = attributes.next() {
        return Err(syn::Error::new_spanned(
            duplicate,
            "duplicate #[bits] attribute",
        ));
    }
    let value = match &attribute.meta {
        Meta::NameValue(name_value) => match &name_value.value {
            Expr::Lit(expression) => match &expression.lit {
                Lit::Int(value) => value.base10_parse()?,
                _ => {
                    return Err(syn::Error::new_spanned(
                        expression,
                        "bits must be an integer",
                    ))
                }
            },
            expression => {
                return Err(syn::Error::new_spanned(
                    expression,
                    "bits must be an integer",
                ))
            }
        },
        Meta::List(_) => attribute.parse_args::<syn::LitInt>()?.base10_parse()?,
        Meta::Path(_) => return Err(syn::Error::new_spanned(attribute, "use #[bits = N]")),
    };
    if value == 0 || value > 128 {
        return Err(syn::Error::new_spanned(
            attribute,
            "bit width must be between 1 and 128",
        ));
    }
    Ok(Some(value))
}

fn add_bit_bounds(
    mut generics: Generics,
    fields: impl Iterator<Item = syn::Field>,
) -> syn::Result<Generics> {
    let where_clause = generics.make_where_clause();
    for field in fields {
        let has_declared_bits = declared_bits(&field)?.is_some();
        let ty = field.ty;
        if has_declared_bits {
            where_clause
                .predicates
                .push(parse_quote!(#ty: ::rustbinary::BitValue));
        } else {
            where_clause
                .predicates
                .push(parse_quote!(#ty: ::rustbinary::BitPack));
        }
    }
    Ok(generics)
}

fn bit_count(fields: &Fields) -> syn::Result<proc_macro2::TokenStream> {
    let mut total = quote!(0usize);
    for field in fields {
        let ty = &field.ty;
        let bits = match declared_bits(field)? {
            Some(width) => quote!(#width),
            None => quote!(<#ty as ::rustbinary::BitPack>::MAX_BITS),
        };
        total = quote!(#total.saturating_add(#bits));
    }
    Ok(total)
}

fn pack_statement(
    field: &syn::Field,
    value: proc_macro2::TokenStream,
    borrowed: bool,
) -> syn::Result<proc_macro2::TokenStream> {
    let ty = &field.ty;
    Ok(match declared_bits(field)? {
        Some(width) => {
            let value = if borrowed { quote!(*#value) } else { value };
            quote! {
                writer.write(<#ty as ::rustbinary::BitValue>::encode_bits(#value, #width)?, #width)?;
            }
        }
        None => quote! {
            <#ty as ::rustbinary::BitPack>::pack(#value, writer)?;
        },
    })
}

fn unpack_expression(field: &syn::Field) -> syn::Result<proc_macro2::TokenStream> {
    let ty = &field.ty;
    Ok(match declared_bits(field)? {
        Some(width) => quote! {
            <#ty as ::rustbinary::BitValue>::decode_bits(reader.read(#width)?, #width)?
        },
        None => quote! {
            <#ty as ::rustbinary::BitPack>::unpack(reader)?
        },
    })
}

fn bit_packed_impl(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let name = &input.ident;
    let fields = match &input.data {
        Data::Struct(data) => data.fields.iter().cloned().collect::<Vec<_>>(),
        Data::Enum(data) => data
            .variants
            .iter()
            .flat_map(|variant| variant.fields.iter().cloned())
            .collect(),
        Data::Union(_) => {
            return Err(syn::Error::new_spanned(
                input,
                "BitPacked cannot be derived for unions",
            ))
        }
    };
    let generics = add_bit_bounds(input.generics.clone(), fields.into_iter())?;
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();
    let (maximum, pack, unpack) = match &input.data {
        Data::Struct(data) => bit_packed_struct(name, data)?,
        Data::Enum(data) => bit_packed_enum(name, data)?,
        Data::Union(_) => unreachable!(),
    };
    Ok(quote! {
        impl #impl_generics ::rustbinary::BitPack for #name #type_generics #where_clause {
            const MAX_BITS: usize = #maximum;
            fn pack(&self, writer: &mut ::rustbinary::BitWriter<'_>) -> ::rustbinary::Result<()> {
                #pack
                Ok(())
            }
            fn unpack(reader: &mut ::rustbinary::BitReader<'_>) -> ::rustbinary::Result<Self> {
                #unpack
            }
        }
    })
}

fn bit_packed_struct(
    name: &syn::Ident,
    data: &DataStruct,
) -> syn::Result<(
    proc_macro2::TokenStream,
    proc_macro2::TokenStream,
    proc_macro2::TokenStream,
)> {
    let maximum = bit_count(&data.fields)?;
    let mut packs = Vec::new();
    let mut values = Vec::new();
    for (index, field) in data.fields.iter().enumerate() {
        let member = field
            .ident
            .clone()
            .map(syn::Member::Named)
            .unwrap_or_else(|| syn::Member::Unnamed(syn::Index::from(index)));
        packs.push(pack_statement(field, quote!(&self.#member), true)?);
        values.push(unpack_expression(field)?);
    }
    let construct = match &data.fields {
        Fields::Named(fields) => {
            let names = fields
                .named
                .iter()
                .map(|field| field.ident.as_ref().expect("named"));
            quote!(#name { #(#names: #values),* })
        }
        Fields::Unnamed(_) => quote!(#name(#(#values),*)),
        Fields::Unit => quote!(#name),
    };
    Ok((maximum, quote!(#(#packs)*), quote!(Ok(#construct))))
}

fn bit_packed_enum(
    name: &syn::Ident,
    data: &DataEnum,
) -> syn::Result<(
    proc_macro2::TokenStream,
    proc_macro2::TokenStream,
    proc_macro2::TokenStream,
)> {
    if data.variants.is_empty() {
        return Err(syn::Error::new_spanned(
            name,
            "empty enums cannot be bit-packed",
        ));
    }
    let tag_bits = if data.variants.len() <= 1 {
        0usize
    } else {
        (usize::BITS - (data.variants.len() - 1).leading_zeros()) as usize
    };
    let mut maximum = quote!(0usize);
    let mut pack_arms = Vec::new();
    let mut unpack_arms = Vec::new();
    for (variant_index, variant) in data.variants.iter().enumerate() {
        let variant_name = &variant.ident;
        let payload_bits = bit_count(&variant.fields)?;
        maximum = quote!(::rustbinary::__bitpack_max(#maximum, #payload_bits));
        let bindings = (0..variant.fields.len())
            .map(|index| syn::Ident::new(&format!("field_{index}"), variant.ident.span()))
            .collect::<Vec<_>>();
        let pattern = match &variant.fields {
            Fields::Named(fields) => {
                let names = fields
                    .named
                    .iter()
                    .map(|field| field.ident.as_ref().expect("named"));
                quote!(Self::#variant_name { #(#names: #bindings),* })
            }
            Fields::Unnamed(_) => quote!(Self::#variant_name(#(#bindings),*)),
            Fields::Unit => quote!(Self::#variant_name),
        };
        let packs = variant
            .fields
            .iter()
            .zip(&bindings)
            .map(|(field, binding)| pack_statement(field, quote!(#binding), true))
            .collect::<syn::Result<Vec<_>>>()?;
        pack_arms.push(quote! {
            #pattern => {
                writer.write(#variant_index as u128, #tag_bits)?;
                #(#packs)*
            }
        });
        let values = variant
            .fields
            .iter()
            .map(unpack_expression)
            .collect::<syn::Result<Vec<_>>>()?;
        let construct = match &variant.fields {
            Fields::Named(fields) => {
                let names = fields
                    .named
                    .iter()
                    .map(|field| field.ident.as_ref().expect("named"));
                quote!(Self::#variant_name { #(#names: #values),* })
            }
            Fields::Unnamed(_) => quote!(Self::#variant_name(#(#values),*)),
            Fields::Unit => quote!(Self::#variant_name),
        };
        unpack_arms.push(quote!(#variant_index => Ok(#construct)));
    }
    Ok((
        quote!((#tag_bits).saturating_add(#maximum)),
        quote!(match self { #(#pack_arms),* }),
        quote! {
            match reader.read(#tag_bits)? as usize {
                #(#unpack_arms,)*
                _ => Err(::rustbinary::Error::BitPacking("unknown packed enum variant")),
            }
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::declared_bits;
    use syn::parse_quote;

    #[test]
    fn bits_attribute_accepts_supported_forms() {
        let named: syn::Field = parse_quote!(#[bits = 7] value: u8);
        let listed: syn::Field = parse_quote!(#[bits(9)] value: u16);
        assert_eq!(declared_bits(&named).unwrap(), Some(7));
        assert_eq!(declared_bits(&listed).unwrap(), Some(9));
    }

    #[test]
    fn bits_attribute_rejects_duplicates() {
        let field: syn::Field = parse_quote!(#[bits = 3] #[bits = 4] value: u8);
        let error = declared_bits(&field).unwrap_err();
        assert!(error.to_string().contains("duplicate #[bits] attribute"));
    }
}
