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
//! - [`CompactBinary`](derive@CompactBinary) generates the schema-guided
//!   compact profile codec (`CompactEncode` + `CompactDecode`).
//!
//! The generated implementations are not a replacement for the nextjson
//! derives. Add `NsonSerialize` and `NsonDeserialize` when the value also
//! crosses a normal `rustbinary` or CBOR wire profile. For the complete syntax
//! and production constraints, see the package README and the re-exported
//! runtime traits.

use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::spanned::Spanned;
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

#[proc_macro_derive(DecodeBounded)]
/// Derives `rustbinary::DecodeBounded`, the schema-derived resource cost
/// algebra `(B, A, D, W)` = (max input bytes, max allocation, max nesting
/// depth, max work) that mirrors the parser structure.
///
/// Fields must implement `rustbinary::DecodeBounded`. Named fields contribute
/// their object-key bytes, containers contribute a nesting level, and dynamic
/// collections/strings report `usize::MAX` for content-dependent resources.
/// Unions are rejected.
pub fn derive_decode_bounded(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    decode_bounded_impl(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[proc_macro_derive(Reflect, attributes(bits, entropy))]
/// Derives allocation-free structural reflection metadata.
///
/// Generated metadata contains the declared type name, fields, field type
/// tokens, declaration indexes, and enum variants. No registry or runtime
/// initialization is generated.
///
/// Field alphabet sizes feed the static-model entropy coder. The derive
/// records `symbols` from an explicit `#[entropy(symbols = N)]` (1..=32768),
/// from a `#[bits = N]` range, or from primitive alphabets (`bool` → 2,
/// `u8`/`i8` → 256); otherwise the field reports `0` and is coded
/// byte-by-byte.
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

#[proc_macro_derive(CompactBinary, attributes(njson))]
/// Derives `rustbinary::compact::CompactEncode` and
/// `rustbinary::compact::CompactDecode` — the schema-guided compact binary
/// profile.
///
/// Struct fields encode in declaration order with **no field names**; enums
/// write only a compact variant discriminant; containers are length-prefixed.
/// The generated codec bypasses the generic nextjson event path entirely, so
/// the hot loop carries no type tags, no field-name handling and no dynamic
/// dispatch. `#[njson(borrow)]` is accepted for nextjson compatibility and is
/// otherwise ignored: borrowing follows the field type, so `&'a str` and
/// `&'a [u8]` fields decode as zero-copy references into the input when
/// `'de: 'a` holds. Unions are rejected.
pub fn derive_compact_binary(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    compact_binary_impl(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn compact_binary_impl(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let encode = compact_encode_impl(input)?;
    let decode = compact_decode_impl(input)?;
    Ok(quote!(#encode #decode))
}

fn compact_encode_impl(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let name = &input.ident;
    let generics = add_bound(
        input.generics.clone(),
        parse_quote!(::rustbinary::compact::CompactEncode),
    );
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();
    let body = match &input.data {
        Data::Struct(data) => compact_encode_struct(data),
        Data::Enum(data) => compact_encode_enum(data),
        Data::Union(_) => {
            return Err(syn::Error::new_spanned(
                input,
                "CompactBinary cannot be derived for unions",
            ))
        }
    }?;
    Ok(quote! {
        impl #impl_generics ::rustbinary::compact::CompactEncode for #name #type_generics #where_clause {
            fn encode_compact<W: ::rustbinary::writer::EncodeWriter + ?Sized>(
                &self,
                writer: &mut W,
            ) -> ::rustbinary::Result<()> {
                #body
                Ok(())
            }
        }
    })
}

fn compact_encode_struct(data: &DataStruct) -> syn::Result<proc_macro2::TokenStream> {
    let statements = data.fields.iter().enumerate().map(|(index, field)| {
        let member = field
            .ident
            .clone()
            .map(syn::Member::Named)
            .unwrap_or_else(|| syn::Member::Unnamed(syn::Index::from(index)));
        let ty = &field.ty;
        quote! {
            <#ty as ::rustbinary::compact::CompactEncode>::encode_compact(&self.#member, writer)?;
        }
    });
    Ok(quote!(#(#statements)*))
}

fn compact_encode_enum(data: &DataEnum) -> syn::Result<proc_macro2::TokenStream> {
    let mut arms = Vec::new();
    for (index, variant) in data.variants.iter().enumerate() {
        let variant_name = &variant.ident;
        let discriminant = proc_macro2::Literal::u32_suffixed(index as u32);
        let pattern = match &variant.fields {
            Fields::Named(fields) => {
                let names = fields
                    .named
                    .iter()
                    .map(|field| field.ident.as_ref().expect("named"));
                quote!(Self::#variant_name { #(#names),* })
            }
            Fields::Unnamed(_) => {
                let bindings = (0..variant.fields.len())
                    .map(|i| syn::Ident::new(&format!("field_{i}"), variant.ident.span()))
                    .collect::<Vec<_>>();
                quote!(Self::#variant_name(#(#bindings),*))
            }
            Fields::Unit => quote!(Self::#variant_name),
        };
        let payload = compact_variant_encode(&variant.fields)?;
        arms.push(quote! {
            #pattern => {
                ::rustbinary::compact::encode_variant_index(writer, #discriminant)?;
                #payload
            }
        });
    }
    Ok(quote!(match self { #(#arms),* }))
}

fn compact_variant_encode(fields: &Fields) -> syn::Result<proc_macro2::TokenStream> {
    let statements = fields.iter().enumerate().map(|(index, field)| {
        let binding: syn::Ident = match fields {
            Fields::Named(_) => field.ident.clone().expect("named"),
            _ => syn::Ident::new(&format!("field_{index}"), field.ty.span()),
        };
        let ty = &field.ty;
        quote! {
            <#ty as ::rustbinary::compact::CompactEncode>::encode_compact(#binding, writer)?;
        }
    });
    Ok(quote!(#(#statements)*))
}

fn compact_decode_impl(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let name = &input.ident;

    // `impl` generics: `'de` first, `CompactDecode<'de>` bounds on every type
    // parameter, and `'de: 'a` predicates so borrowed fields can borrow input.
    let mut impl_generics = input.generics.clone();
    impl_generics.params.insert(0, parse_quote!('de));
    for parameter in impl_generics.type_params_mut() {
        parameter
            .bounds
            .push(parse_quote!(::rustbinary::compact::CompactDecode<'de>));
    }
    let original_lifetimes: Vec<syn::Lifetime> = input
        .generics
        .lifetimes()
        .map(|param| param.lifetime.clone())
        .collect();
    if !original_lifetimes.is_empty() {
        let where_clause = impl_generics.make_where_clause();
        for lifetime in &original_lifetimes {
            where_clause.predicates.push(parse_quote!('de: #lifetime));
        }
    }

    // Type generics come from the *original* generics: the type itself has no
    // `'de` parameter.
    let (_, type_generics, _) = input.generics.split_for_impl();
    let (impl_generics, _, where_clause) = impl_generics.split_for_impl();

    let body = match &input.data {
        Data::Struct(data) => compact_decode_struct(name, data)?,
        Data::Enum(data) => compact_decode_enum(data)?,
        Data::Union(_) => unreachable!(),
    };
    Ok(quote! {
        impl #impl_generics ::rustbinary::compact::CompactDecode<'de> for #name #type_generics #where_clause {
            fn decode_compact(
                cursor: &mut ::rustbinary::compact::CompactCursor<'de>,
            ) -> ::rustbinary::Result<Self> {
                #body
            }
        }
    })
}

fn compact_decode_struct(
    name: &syn::Ident,
    data: &DataStruct,
) -> syn::Result<proc_macro2::TokenStream> {
    match &data.fields {
        Fields::Unit => Ok(quote!(Ok(#name))),
        Fields::Named(fields) => {
            let decodes = fields.named.iter().map(|field| {
                let ident = field.ident.as_ref().expect("named");
                let ty = &field.ty;
                quote! {
                    let #ident = <#ty as ::rustbinary::compact::CompactDecode<'de>>::decode_compact(cursor)?;
                }
            });
            let names = fields
                .named
                .iter()
                .map(|field| field.ident.as_ref().expect("named"));
            Ok(quote! {
                #(#decodes)*
                Ok(#name { #(#names),* })
            })
        }
        Fields::Unnamed(fields) => {
            let names = (0..fields.unnamed.len())
                .map(|i| syn::Ident::new(&format!("field_{i}"), name.span()))
                .collect::<Vec<_>>();
            let decodes = fields.unnamed.iter().zip(&names).map(|(field, ident)| {
                let ty = &field.ty;
                quote! {
                    let #ident = <#ty as ::rustbinary::compact::CompactDecode<'de>>::decode_compact(cursor)?;
                }
            });
            Ok(quote! {
                #(#decodes)*
                Ok(#name(#(#names),*))
            })
        }
    }
}

fn compact_decode_enum(data: &DataEnum) -> syn::Result<proc_macro2::TokenStream> {
    let arms = data
        .variants
        .iter()
        .enumerate()
        .map(|(index, variant)| {
            let variant_name = &variant.ident;
            let discriminant = proc_macro2::Literal::u32_suffixed(index as u32);
            match &variant.fields {
                Fields::Unit => quote!(#discriminant => Ok(Self::#variant_name)),
                Fields::Unnamed(fields) => {
                    let names = (0..fields.unnamed.len())
                        .map(|i| syn::Ident::new(&format!("field_{i}"), variant.ident.span()))
                        .collect::<Vec<_>>();
                    let decodes = fields.unnamed.iter().zip(&names).map(|(field, ident)| {
                        let ty = &field.ty;
                        quote! {
                            let #ident = <#ty as ::rustbinary::compact::CompactDecode<'de>>::decode_compact(cursor)?;
                        }
                    });
                    quote! {
                        #discriminant => {
                            #(#decodes)*
                            Ok(Self::#variant_name(#(#names),*))
                        }
                    }
                }
                Fields::Named(fields) => {
                    let names = fields
                        .named
                        .iter()
                        .map(|field| field.ident.as_ref().expect("named"))
                        .collect::<Vec<_>>();
                    let decodes = fields.named.iter().map(|field| {
                        let ident = field.ident.as_ref().expect("named");
                        let ty = &field.ty;
                        quote! {
                            let #ident = <#ty as ::rustbinary::compact::CompactDecode<'de>>::decode_compact(cursor)?;
                        }
                    });
                    quote! {
                        #discriminant => {
                            #(#decodes)*
                            Ok(Self::#variant_name { #(#names),* })
                        }
                    }
                }
            }
        });
    Ok(quote! {
        match ::rustbinary::compact::decode_variant_index(cursor)? {
            #(#arms,)*
            _ => Err(::rustbinary::compact::__err_static("unknown compact enum variant")),
        }
    })
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

/// Worst-case serialized bytes of one named object key. Length prefixes are
/// fixed-u64 in the fixed-width profile (9 + len) and marker-varint elsewhere
/// (2 + len), so the worst case is the fixed-width form.
fn key_size(name: &str) -> proc_macro2::TokenStream {
    let len = name.len();
    quote!(9usize + #len)
}

/// Sum of field sizes; named fields additionally contribute their key bytes.
fn sum_fields(fields: &Fields, packed: bool) -> proc_macro2::TokenStream {
    fields
        .iter()
        .enumerate()
        .fold(quote!(0usize), |sum, (index, field)| {
            let size = static_field_size(field, packed);
            if field.ident.is_some() {
                let key = key_size(&field_name(index, field));
                quote!(::rustbinary::static_size::saturating_add(
                    #sum,
                    ::rustbinary::static_size::saturating_add(#size, #key),
                ))
            } else {
                quote!(::rustbinary::static_size::saturating_add(#sum, #size))
            }
        })
}

/// Container overhead (tag + terminator, or a single null for unit shapes).
fn shape_overhead(fields: &Fields) -> proc_macro2::TokenStream {
    match fields {
        Fields::Unit => quote!(1usize),
        Fields::Unnamed(_) | Fields::Named(_) => quote!(2usize),
    }
}

/// Worst-case serialized content of one enum variant (excluding the variant
/// key, which is added by [`max_variants`]).
fn variant_content_size(fields: &Fields, packed: bool) -> proc_macro2::TokenStream {
    match fields {
        // A newtype variant writes its payload directly.
        Fields::Unnamed(f) if f.unnamed.len() == 1 => static_field_size(&f.unnamed[0], packed),
        other => {
            let payload = sum_fields(fields, packed);
            let overhead = shape_overhead(other);
            quote!(::rustbinary::static_size::saturating_add(#payload, #overhead))
        }
    }
}

fn max_variants(data: &DataEnum, packed: bool) -> proc_macro2::TokenStream {
    data.variants
        .iter()
        .fold(quote!(0usize), |maximum, variant| {
            let key = key_size(&variant.ident.to_string());
            let content = variant_content_size(&variant.fields, packed);
            let size = quote!(::rustbinary::static_size::saturating_add(#key, #content));
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
        Data::Struct(data) => {
            let payload = sum_fields(&data.fields, false);
            let overhead = shape_overhead(&data.fields);
            (
                quote!(::rustbinary::static_size::saturating_add(#payload, #overhead)),
                sum_field_bits(&data.fields)?,
            )
        }
        Data::Enum(data) => {
            // External nextjson enums encode as an object with one variant key.
            let variants = max_variants(data, false);
            let maximum = quote!(::rustbinary::static_size::saturating_add(
                ::rustbinary::static_size::saturating_add(1usize, #variants),
                1usize,
            ));
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
                maximum,
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

// ---------------------------------------------------------------------------
// DecodeBounded: schema-derived resource cost algebra (B/A/D/W).
// ---------------------------------------------------------------------------

fn bounded_field_input(field: &syn::Field) -> proc_macro2::TokenStream {
    let ty = &field.ty;
    quote!(<#ty as ::rustbinary::DecodeBounded>::MAX_INPUT)
}

fn bounded_field_alloc(field: &syn::Field) -> proc_macro2::TokenStream {
    let ty = &field.ty;
    quote!(<#ty as ::rustbinary::DecodeBounded>::MAX_ALLOC)
}

fn bounded_field_depth(field: &syn::Field) -> proc_macro2::TokenStream {
    let ty = &field.ty;
    quote!(<#ty as ::rustbinary::DecodeBounded>::MAX_DEPTH)
}

fn bounded_field_work(field: &syn::Field) -> proc_macro2::TokenStream {
    let ty = &field.ty;
    quote!(<#ty as ::rustbinary::DecodeBounded>::MAX_WORK)
}

fn bounded_field_structural(field: &syn::Field) -> proc_macro2::TokenStream {
    let ty = &field.ty;
    quote!(<#ty as ::rustbinary::DecodeBounded>::MAX_STRUCTURAL_ELEMENT)
}

/// Maximum per-element structural allocation across a field list.
fn max_bounded_structural(fields: &Fields) -> proc_macro2::TokenStream {
    fields.iter().fold(quote!(0usize), |maximum, field| {
        let structural = bounded_field_structural(field);
        quote!(::rustbinary::bounded::max(#maximum, #structural))
    })
}

/// Sum of field input bounds; named fields additionally contribute their key
/// bytes (mirroring the encoder's object-key cost).
fn sum_bounded_input(fields: &Fields) -> proc_macro2::TokenStream {
    fields
        .iter()
        .enumerate()
        .fold(quote!(0usize), |sum, (index, field)| {
            let input = bounded_field_input(field);
            if field.ident.is_some() {
                let key = key_size(&field_name(index, field));
                quote!(::rustbinary::bounded::saturating_add(
                    #sum,
                    ::rustbinary::bounded::saturating_add(#input, #key),
                ))
            } else {
                quote!(::rustbinary::bounded::saturating_add(#sum, #input))
            }
        })
}

/// Sum of field allocation bounds.
fn sum_bounded_alloc(fields: &Fields) -> proc_macro2::TokenStream {
    fields.iter().fold(quote!(0usize), |sum, field| {
        let alloc = bounded_field_alloc(field);
        quote!(::rustbinary::bounded::saturating_add(#sum, #alloc))
    })
}

/// One container level over the maximum field depth.
fn max_bounded_depth(fields: &Fields) -> proc_macro2::TokenStream {
    let maximum = fields.iter().fold(quote!(0usize), |maximum, field| {
        let depth = bounded_field_depth(field);
        quote!(::rustbinary::bounded::max(#maximum, #depth))
    });
    quote!(::rustbinary::bounded::depth_plus_one(#maximum))
}

/// Sum of field work bounds; named fields additionally contribute their key
/// bytes.
fn sum_bounded_work(fields: &Fields) -> proc_macro2::TokenStream {
    fields
        .iter()
        .enumerate()
        .fold(quote!(0usize), |sum, (index, field)| {
            let work = bounded_field_work(field);
            if field.ident.is_some() {
                let key = key_size(&field_name(index, field));
                quote!(::rustbinary::bounded::saturating_add(
                    #sum,
                    ::rustbinary::bounded::saturating_add(#work, #key),
                ))
            } else {
                quote!(::rustbinary::bounded::saturating_add(#sum, #work))
            }
        })
}

/// Variant content bounds, excluding the variant key added by the enum
/// wrapper.
fn variant_bounded_input(variant: &syn::Variant) -> proc_macro2::TokenStream {
    match &variant.fields {
        Fields::Unit => quote!(1usize),
        Fields::Unnamed(f) if f.unnamed.len() == 1 => bounded_field_input(&f.unnamed[0]),
        other => {
            let payload = sum_bounded_input(other);
            quote!(::rustbinary::bounded::saturating_add(#payload, 2usize))
        }
    }
}

fn variant_bounded_alloc(variant: &syn::Variant) -> proc_macro2::TokenStream {
    match &variant.fields {
        Fields::Unit => quote!(0usize),
        Fields::Unnamed(f) if f.unnamed.len() == 1 => bounded_field_alloc(&f.unnamed[0]),
        other => sum_bounded_alloc(other),
    }
}

fn variant_bounded_depth(variant: &syn::Variant) -> proc_macro2::TokenStream {
    match &variant.fields {
        Fields::Unit => quote!(0usize),
        Fields::Unnamed(f) if f.unnamed.len() == 1 => bounded_field_depth(&f.unnamed[0]),
        other => max_bounded_depth(other),
    }
}

fn variant_bounded_work(variant: &syn::Variant) -> proc_macro2::TokenStream {
    match &variant.fields {
        Fields::Unit => quote!(1usize),
        Fields::Unnamed(f) if f.unnamed.len() == 1 => bounded_field_work(&f.unnamed[0]),
        other => {
            let payload = sum_bounded_work(other);
            quote!(::rustbinary::bounded::saturating_add(#payload, 2usize))
        }
    }
}

fn variant_bounded_structural(variant: &syn::Variant) -> proc_macro2::TokenStream {
    match &variant.fields {
        Fields::Unit => quote!(0usize),
        Fields::Unnamed(f) if f.unnamed.len() == 1 => bounded_field_structural(&f.unnamed[0]),
        other => max_bounded_structural(other),
    }
}

fn decode_bounded_impl(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let name = &input.ident;
    let generics = add_bound(
        input.generics.clone(),
        parse_quote!(::rustbinary::DecodeBounded),
    );
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();
    let (max_input, max_alloc, max_depth, max_work, max_structural) = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Unit => (
                quote!(1usize),
                quote!(0usize),
                quote!(0usize),
                quote!(1usize),
                quote!(0usize),
            ),
            Fields::Unnamed(_) | Fields::Named(_) => {
                let input = sum_bounded_input(&data.fields);
                let alloc = sum_bounded_alloc(&data.fields);
                let depth = max_bounded_depth(&data.fields);
                let work = sum_bounded_work(&data.fields);
                let structural = max_bounded_structural(&data.fields);
                (
                    quote!(::rustbinary::bounded::saturating_add(#input, 2usize)),
                    alloc,
                    depth,
                    quote!(::rustbinary::bounded::saturating_add(#work, 2usize)),
                    structural,
                )
            }
        },
        Data::Enum(data) => {
            // External nextjson enums encode as an object with one variant key.
            let mut input = quote!(0usize);
            let mut alloc = quote!(0usize);
            let mut depth = quote!(0usize);
            let mut work = quote!(0usize);
            let mut structural = quote!(0usize);
            for variant in &data.variants {
                let key = key_size(&variant.ident.to_string());
                let vinput = variant_bounded_input(variant);
                let valloc = variant_bounded_alloc(variant);
                let vdepth = variant_bounded_depth(variant);
                let vwork = variant_bounded_work(variant);
                let vstructural = variant_bounded_structural(variant);
                input = quote!(::rustbinary::bounded::max(
                    #input,
                    ::rustbinary::bounded::saturating_add(#key, #vinput),
                ));
                alloc = quote!(::rustbinary::bounded::max(#alloc, #valloc));
                depth = quote!(::rustbinary::bounded::max(#depth, #vdepth));
                work = quote!(::rustbinary::bounded::max(
                    #work,
                    ::rustbinary::bounded::saturating_add(#key, #vwork),
                ));
                structural = quote!(::rustbinary::bounded::max(#structural, #vstructural));
            }
            (
                quote!(::rustbinary::bounded::saturating_add(
                    ::rustbinary::bounded::saturating_add(1usize, #input),
                    1usize,
                )),
                alloc,
                quote!(::rustbinary::bounded::depth_plus_one(#depth)),
                quote!(::rustbinary::bounded::saturating_add(
                    ::rustbinary::bounded::saturating_add(1usize, #work),
                    1usize,
                )),
                structural,
            )
        }
        Data::Union(_) => {
            return Err(syn::Error::new_spanned(
                input,
                "DecodeBounded cannot be derived for unions",
            ))
        }
    };
    Ok(quote! {
        impl #impl_generics ::rustbinary::DecodeBounded for #name #type_generics #where_clause {
            const MAX_INPUT: usize = #max_input;
            const MAX_ALLOC: usize = #max_alloc;
            const MAX_DEPTH: usize = #max_depth;
            const MAX_WORK: usize = #max_work;
            const MAX_STRUCTURAL_ELEMENT: usize = #max_structural;
        }
    })
}

/// Explicit `#[entropy(symbols = N)]` alphabet declaration, if present.
fn declared_symbols(field: &syn::Field) -> syn::Result<Option<u32>> {
    let mut attributes = field
        .attrs
        .iter()
        .filter(|attribute| attribute.path().is_ident("entropy"));
    let Some(attribute) = attributes.next() else {
        return Ok(None);
    };
    if let Some(duplicate) = attributes.next() {
        return Err(syn::Error::new_spanned(
            duplicate,
            "duplicate #[entropy] attribute",
        ));
    }
    let Meta::List(list) = &attribute.meta else {
        return Err(syn::Error::new_spanned(
            attribute,
            "use #[entropy(symbols = N)]",
        ));
    };
    // Parse and validate in one pass; the parsed value is the result.
    let mut count = None;
    list.parse_nested_meta(|meta| {
        if meta.path.is_ident("symbols") {
            let value: syn::LitInt = meta.value()?.parse()?;
            let parsed: u32 = value.base10_parse()?;
            // The rANS alphabet is capped by the total frequency M = 2^15.
            if parsed == 0 || parsed > 1 << 15 {
                return Err(meta.error("symbols must be in 1..=32768"));
            }
            count = Some(parsed);
            Ok(())
        } else {
            Err(meta.error("unsupported entropy option"))
        }
    })?;
    Ok(count)
}

/// Symbol alphabet for a field's declared `#[bits = N]` range, when it fits
/// the rANS alphabet cap.
fn bits_symbols(field: &syn::Field) -> syn::Result<Option<u32>> {
    match declared_bits(field)? {
        Some(bits) if bits <= 15 => Ok(Some(1u32 << bits)),
        _ => Ok(None),
    }
}

/// Symbol alphabet for known primitive field types, when single-symbol
/// encodable. Wide integers are not single-symbol encodable in rANS
/// (alphabet is capped at `2^15`), so they report `0` and the caller codes
/// their bytes individually.
fn primitive_symbols(ty: &Type) -> u32 {
    match ty {
        Type::Path(path) => {
            let last = path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
                .unwrap_or_default();
            match last.as_str() {
                "bool" => 2,
                "u8" | "i8" => 1 << 8,
                _ => 0,
            }
        }
        _ => 0,
    }
}

/// Deterministic schema-derived symbol count for one field.
fn field_symbols(field: &syn::Field) -> syn::Result<u32> {
    if let Some(count) = declared_symbols(field)? {
        return Ok(count);
    }
    if let Some(count) = bits_symbols(field)? {
        return Ok(count);
    }
    Ok(primitive_symbols(&field.ty))
}

fn reflect_fields(fields: &Fields) -> syn::Result<proc_macro2::TokenStream> {
    let descriptors: Vec<syn::Result<proc_macro2::TokenStream>> = fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let name = field_name(index, field);
            let ty = type_name(&field.ty);
            let symbols = field_symbols(field)?;
            Ok(quote!(::rustbinary::FieldInfo {
                name: #name,
                type_name: #ty,
                index: #index,
                symbols: #symbols,
            }))
        })
        .collect();
    let mut items = Vec::new();
    for descriptor in descriptors {
        items.push(descriptor?);
    }
    Ok(quote!(&[#(#items),*]))
}

fn reflect_impl(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let name = &input.ident;
    let generics = input.generics.clone();
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();
    let shape = match &input.data {
        Data::Struct(DataStruct { fields, .. }) => {
            let fields = reflect_fields(fields)?;
            quote!(::rustbinary::TypeShape::Struct(#fields))
        }
        Data::Enum(data) => {
            let variants = data.variants.iter().enumerate().map(|(index, variant)| {
                let variant_name = variant.ident.to_string();
                let fields = reflect_fields(&variant.fields);
                match fields {
                    Ok(fields) => quote!(::rustbinary::VariantInfo {
                        name: #variant_name,
                        index: #index,
                        fields: #fields,
                    }),
                    Err(error) => error.to_compile_error(),
                }
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
