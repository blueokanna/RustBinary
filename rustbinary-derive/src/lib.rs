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

#[proc_macro_derive(Archive, attributes(archive))]
/// Derives the zero-copy archived mirror used by
/// `rustbinary::archive::build` / `OwnedArchive` / `MappedArchive`.
///
/// For a named struct, `Archive` generates:
///
/// - the `Archived{Name}` mirror (`#[repr(C)]`, derived `Clone` + `Copy`)
///   whose fields are the archived forms of the source fields,
/// - the `rustbinary::archive_codec::Archive` impl,
/// - the `rustbinary::archive_codec::ArchivedValue` marker,
/// - the `rustbinary::archive_codec::CheckBytes` structural validator that
///   bounds-checks every relative offset, length, and range in one pass.
///
/// Supported field types: scalar primitives (`u8`…`f64`, no `bool`),
/// `String`, `Vec<T>` of a scalar or of a nested archived struct, and a
/// nested archived struct field. `bool` is rejected: it has no
/// `ArchivedValue` (not every byte pattern is a valid `bool`) and would make
/// zero-copy element slices unsound. Generic type parameters, enums, unions,
/// `Vec<String>`, and nested `Vec<Vec<…>>` are rejected with a compile
/// error rather than generating subtly wrong code.
pub fn derive_archive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    archive_impl(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[proc_macro_derive(Serialize)]
/// Derives `rustbinary::archive_codec::ArchiveWrite`, the two-phase archive
/// serializer (skeleton pass then bodies pass).
///
/// Apply together with `#[derive(Archive)]` on the same named struct. The
/// supported field types and rejections match the `Archive` derive.
pub fn derive_serialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    serialize_impl(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// `Archive` and `Serialize` shared field-type guards.
fn reject_unsupported_archive_fields(fields: &Fields, what: &str) -> syn::Result<()> {
    for field in fields {
        let ty = &field.ty;
        if is_bool(ty) {
            return Err(syn::Error::new_spanned(
                ty,
                format!("{what} does not support `bool` fields (no ArchivedValue; use `u8` with 0/1 or a manual archive implementation)"),
            ));
        }
        if let Some(inner) = vec_element(ty) {
            if is_bool(inner) {
                return Err(syn::Error::new_spanned(
                    ty,
                    format!(
                        "{what} does not support `Vec<bool>` fields (bool has no ArchivedValue)"
                    ),
                ));
            }
            if is_string(inner) {
                return Err(syn::Error::new_spanned(
                    ty,
                    format!("{what} does not support `Vec<String>` fields yet"),
                ));
            }
        }
        if is_string(ty) || is_bool(ty) {
            continue;
        }
        if vec_element(ty).is_some() {
            continue;
        }
        if is_scalar(ty) {
            continue;
        }
    }
    Ok(())
}

/// Whether the type names the `bool` primitive.
fn is_bool(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Path(type_path) if type_path.qself.is_none() => type_path
            .path
            .segments
            .last()
            .map(|segment| segment.ident == "bool")
            .unwrap_or(false),
        _ => false,
    }
}

/// Whether the type is a scalar primitive supported by the archive codec.
fn is_scalar(ty: &syn::Type) -> bool {
    scalar_write_method(ty).is_some()
}

/// The serializer write method for a scalar primitive, if supported.
fn scalar_write_method(ty: &syn::Type) -> Option<&'static str> {
    let path = match ty {
        syn::Type::Path(type_path) if type_path.qself.is_none() => &type_path.path,
        _ => return None,
    };
    let ident = path.segments.last()?.ident.to_string();
    match ident.as_str() {
        "u8" => Some("write_u8"),
        "u16" => Some("write_u16"),
        "u32" => Some("write_u32"),
        "u64" => Some("write_u64"),
        "i8" => Some("write_i8"),
        "i16" => Some("write_i16"),
        "i32" => Some("write_i32"),
        "i64" => Some("write_i64"),
        "f32" => Some("write_f32"),
        "f64" => Some("write_f64"),
        _ => None,
    }
}

/// Whether the type is `String` under any leading path.
fn is_string(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Path(type_path) if type_path.qself.is_none() => type_path
            .path
            .segments
            .last()
            .map(|segment| segment.ident == "String")
            .unwrap_or(false),
        _ => false,
    }
}

/// If the type is `Vec<T>`, returns the element type.
fn vec_element(ty: &syn::Type) -> Option<&syn::Type> {
    let path = match ty {
        syn::Type::Path(type_path) if type_path.qself.is_none() => &type_path.path,
        _ => return None,
    };
    if path.segments.len() != 1 || path.segments[0].ident != "Vec" {
        return None;
    }
    match &path.segments[0].arguments {
        syn::PathArguments::AngleBracketed(args) if args.args.len() == 1 => match &args.args[0] {
            syn::GenericArgument::Type(inner) => Some(inner),
            _ => None,
        },
        _ => None,
    }
}

/// The archived mirror field type for a source field type.
fn archived_field_type(ty: &syn::Type) -> syn::Result<proc_macro2::TokenStream> {
    if is_scalar(ty) {
        Ok(quote!(#ty))
    } else if is_string(ty) {
        Ok(quote!(::rustbinary::archive_codec::ArchivedString))
    } else if let Some(inner) = vec_element(ty) {
        if is_scalar(inner) {
            Ok(quote!(::rustbinary::archive_codec::ArchivedVec<#inner>))
        } else {
            let archived_inner = quote!(<#inner as ::rustbinary::archive_codec::Archive>::Archived);
            Ok(quote!(::rustbinary::archive_codec::ArchivedVec<#archived_inner>))
        }
    } else {
        Ok(quote!(<#ty as ::rustbinary::archive_codec::Archive>::Archived))
    }
}

/// Alignment of the archived mirror field for a source field type. This is
/// the alignment the `#[repr(C)]` mirror assigns to the field, which the
/// serializer and validator replicate with `align_to` / `align_up`.
fn archived_field_align(ty: &syn::Type) -> proc_macro2::TokenStream {
    if is_scalar(ty) {
        quote!(::core::mem::align_of::<#ty>())
    } else if is_string(ty) {
        quote!(::core::mem::align_of::<
            ::rustbinary::archive_codec::ArchivedString,
        >())
    } else if let Some(inner) = vec_element(ty) {
        let archived_inner = if is_scalar(inner) {
            quote!(#inner)
        } else {
            quote!(<#inner as ::rustbinary::archive_codec::Archive>::Archived)
        };
        quote!(
            ::core::mem::align_of::<::rustbinary::archive_codec::ArchivedVec<#archived_inner>>()
        )
    } else {
        let archived_ty = quote!(<#ty as ::rustbinary::archive_codec::Archive>::Archived);
        quote!(::core::mem::align_of::<#archived_ty>())
    }
}

/// Size of the archived mirror field for a source field type.
fn archived_field_size(ty: &syn::Type) -> proc_macro2::TokenStream {
    if is_scalar(ty) {
        quote!(::core::mem::size_of::<#ty>())
    } else if is_string(ty) {
        quote!(::core::mem::size_of::<
            ::rustbinary::archive_codec::ArchivedString,
        >())
    } else if let Some(inner) = vec_element(ty) {
        let archived_inner = if is_scalar(inner) {
            quote!(#inner)
        } else {
            quote!(<#inner as ::rustbinary::archive_codec::Archive>::Archived)
        };
        quote!(
            ::core::mem::size_of::<::rustbinary::archive_codec::ArchivedVec<#archived_inner>>()
        )
    } else {
        let archived_ty = quote!(<#ty as ::rustbinary::archive_codec::Archive>::Archived);
        quote!(::core::mem::size_of::<#archived_ty>())
    }
}

fn archive_impl(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let name = &input.ident;
    let archived_name = syn::Ident::new(&format!("Archived{name}"), name.span());

    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.generics,
            "the Archive derive does not support generic type parameters",
        ));
    }
    let fields = match &input.data {
        Data::Struct(data) => &data.fields,
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                "the Archive derive only supports structs (enums and unions are rejected)",
            ))
        }
    };
    reject_unsupported_archive_fields(fields, "the Archive derive")?;

    let archived_fields: Vec<proc_macro2::TokenStream> = fields
        .iter()
        .map(|field| {
            let ident = field.ident.as_ref().expect("named archive field");
            let ty = &field.ty;
            let archived = archived_field_type(ty)?;
            Ok(quote!(#ident: #archived))
        })
        .collect::<syn::Result<_>>()?;
    let check_body = archive_check_body(fields)?;

    Ok(quote! {
        #[doc = "Archived mirror of `"]
        #[doc = stringify!(#name)]
        #[doc = "`, generated by the `Archive` derive."]
        #[derive(Clone, Copy)]
        #[repr(C)]
        pub struct #archived_name {
            #(#archived_fields,)*
        }

        impl ::rustbinary::archive_codec::Archive for #name {
            type Archived = #archived_name;
        }

        unsafe impl ::rustbinary::archive_codec::ArchivedValue for #archived_name {}

        impl ::rustbinary::archive_codec::CheckBytes for #archived_name {
            fn check_at(
                bytes: &[u8],
                base: usize,
            ) -> ::core::result::Result<(), ::std::string::String> {
                #check_body
            }
        }
    })
}

/// Structural validator body for the archived mirror of `fields`.
///
/// The archived mirror is `#[repr(C)]`, so every field sits at the C-ABI
/// offset: the size of the previous fields rounded up to the field's
/// alignment. The generated code reproduces that exact algorithm with
/// `align_up(offset, align)` and advances by `size_of`, then validates
/// variable-width fields. Because both sides run the same algorithm, the
/// validator always walks the same offsets the mirror uses for access.
fn archive_check_body(fields: &Fields) -> syn::Result<proc_macro2::TokenStream> {
    let mut statements = Vec::new();
    for field in fields {
        let ty = &field.ty;
        let align = archived_field_align(ty);
        let size = archived_field_size(ty);
        if is_scalar(ty) {
            statements.push(quote! {
                offset = (offset + ((#align) - (offset % (#align))) % (#align));
                offset += #size;
            });
        } else if is_string(ty) {
            statements.push(quote! {
                offset = (offset + ((#align) - (offset % (#align))) % (#align));
                ::rustbinary::archive_codec::check_string_field(bytes, offset)?;
                offset += #size;
            });
        } else if let Some(inner) = vec_element(ty) {
            if is_scalar(inner) {
                statements.push(quote! {
                    offset = (offset + ((#align) - (offset % (#align))) % (#align));
                    ::rustbinary::archive_codec::check_vec_field(
                        bytes,
                        offset,
                        ::core::mem::size_of::<#inner>(),
                        ::core::mem::align_of::<#inner>(),
                    )?;
                    offset += #size;
                });
            } else {
                let archived_inner =
                    quote!(<#inner as ::rustbinary::archive_codec::Archive>::Archived);
                statements.push(quote! {
                    offset = (offset + ((#align) - (offset % (#align))) % (#align));
                    ::rustbinary::archive_codec::check_vec_nested::<#archived_inner>(
                        bytes,
                        offset,
                        ::core::mem::size_of::<#archived_inner>(),
                        ::core::mem::align_of::<#archived_inner>(),
                    )?;
                    offset += #size;
                });
            }
        } else {
            let archived_ty = quote!(<#ty as ::rustbinary::archive_codec::Archive>::Archived);
            statements.push(quote! {
                offset = (offset + ((#align) - (offset % (#align))) % (#align));
                <#archived_ty as ::rustbinary::archive_codec::CheckBytes>::check_at(
                    bytes,
                    offset,
                )?;
                offset += #size;
            });
        }
    }
    Ok(quote! {
        let mut offset = base;
        #(#statements)*
        Ok(())
    })
}

fn serialize_impl(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let name = &input.ident;

    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.generics,
            "the Serialize derive does not support generic type parameters",
        ));
    }
    let fields = match &input.data {
        Data::Struct(data) => &data.fields,
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                "the Serialize derive only supports structs (enums and unions are rejected)",
            ))
        }
    };
    reject_unsupported_archive_fields(fields, "the Serialize derive")?;

    let skeleton = serialize_skeleton_body(fields)?;
    let bodies = serialize_bodies_body(fields)?;

    Ok(quote! {
        impl ::rustbinary::archive_codec::ArchiveWrite for #name {
            fn write_skeleton(
                &self,
                serializer: &mut ::rustbinary::archive_codec::ArchiveSerializer,
                positions: &mut ::std::collections::VecDeque<usize>,
            ) {
                #skeleton
            }

            fn write_bodies(
                &self,
                serializer: &mut ::rustbinary::archive_codec::ArchiveSerializer,
                positions: &mut ::std::collections::VecDeque<usize>,
            ) -> ::core::result::Result<(), ::std::string::String> {
                #bodies
                Ok(())
            }
        }
    })
}

/// Skeleton phase: write inline scalars (C-aligned), reserve a `RelPtr`
/// placeholder for every variable-width field, and recurse into direct nested
/// structs. Every field is preceded by `align_to` so the buffer matches the
/// `#[repr(C)]` mirror byte for byte.
fn serialize_skeleton_body(fields: &Fields) -> syn::Result<proc_macro2::TokenStream> {
    let mut statements = Vec::new();
    for field in fields {
        let member = field.ident.as_ref().expect("named archive field");
        let ty = &field.ty;
        let align = archived_field_align(ty);
        if let Some(method) = scalar_write_method(ty) {
            let method = syn::Ident::new(method, ty.span());
            statements.push(quote! {
                serializer.align_to(#align);
                serializer.#method(self.#member);
            });
        } else if is_string(ty) || vec_element(ty).is_some() {
            statements.push(quote! {
                serializer.align_to(#align);
                positions.push_back(serializer.reserve_ptr());
            });
        } else {
            statements.push(quote! {
                serializer.align_to(#align);
                ::rustbinary::archive_codec::ArchiveWrite::write_skeleton(
                    &self.#member,
                    serializer,
                    positions,
                );
            });
        }
    }
    Ok(quote!(#(#statements)*))
}

/// Bodies phase: write string/vec data and patch placeholders, or recurse
/// into direct nested structs. `Vec<T>` of a scalar uses the Pod fast path;
/// `Vec<T>` of a nested struct writes all element skeletons contiguously
/// first (so the element array is a run of fixed-size mirrors) and then all
/// element bodies.
fn serialize_bodies_body(fields: &Fields) -> syn::Result<proc_macro2::TokenStream> {
    let mut statements = Vec::new();
    for field in fields {
        let member = field.ident.as_ref().expect("named archive field");
        let ty = &field.ty;
        if is_scalar(ty) {
            // Inline scalar: nothing to do in the bodies phase.
        } else if is_string(ty) {
            statements.push(quote! {
                {
                    let field_pos = positions
                        .pop_front()
                        .ok_or("archive: missing string body position")?;
                    serializer.write_string_at(field_pos, &self.#member);
                }
            });
        } else if let Some(inner) = vec_element(ty) {
            if is_scalar(inner) {
                statements.push(quote! {
                    {
                        let field_pos = positions
                            .pop_front()
                            .ok_or("archive: missing vec body position")?;
                        serializer.write_vec_at(field_pos, &self.#member);
                    }
                });
            } else {
                let archived_inner =
                    quote!(<#inner as ::rustbinary::archive_codec::Archive>::Archived);
                statements.push(quote! {
                    {
                        let field_pos = positions
                            .pop_front()
                            .ok_or("archive: missing vec body position")?;
                        let data_pos = serializer.len();
                        serializer.write_u32(
                            ::core::convert::TryInto::try_into(self.#member.len())
                                .unwrap_or(::core::u32::MAX),
                        );
                        serializer.align_to(::core::mem::align_of::<#archived_inner>());
                        for element in &self.#member {
                            ::rustbinary::archive_codec::ArchiveWrite::write_skeleton(
                                element,
                                serializer,
                                positions,
                            );
                        }
                        for element in &self.#member {
                            ::rustbinary::archive_codec::ArchiveWrite::write_bodies(
                                element,
                                serializer,
                                positions,
                            )?;
                        }
                        serializer.patch_ptr(field_pos, data_pos);
                    }
                });
            }
        } else {
            statements.push(quote! {
                ::rustbinary::archive_codec::ArchiveWrite::write_bodies(
                    &self.#member,
                    serializer,
                    positions,
                )?;
            });
        }
    }
    Ok(quote!(#(#statements)*))
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

    let mut count = None;
    list.parse_nested_meta(|meta| {
        if meta.path.is_ident("symbols") {
            let value: syn::LitInt = meta.value()?.parse()?;
            let parsed: u32 = value.base10_parse()?;
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
