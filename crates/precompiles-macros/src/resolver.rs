//! Code generation for the `metadata_for` resolver method.
//!
//! This module generates a `metadata_for` method for each contract that allows
//! runtime resolution of storage field metadata by field name.

use crate::{
    FieldKind,
    packing::{LayoutField, PackingConstants},
};
use quote::{format_ident, quote};
use syn::{Ident, Type};

/// Generate a `metadata_for` method for resolving storage field metadata by field name.
///
/// This method is feature-gated behind `test-utils` and allows runtime
/// resolution of storage metadata for testing and debugging purposes.
pub(crate) fn gen_metadata_for_fn(
    name: &Ident,
    allocated_fields: &[LayoutField<'_>],
) -> proc_macro2::TokenStream {
    let match_arms = allocated_fields.iter().map(|field| {
        let field_name = field.name.to_string();
        let consts = PackingConstants::new(field.name);
        let slot_const = consts.slot();
        let offset_const = format_ident!("{}_OFFSET", slot_const);
        let bytes_const = format_ident!("{}_BYTES", slot_const);

        match &field.kind {
            FieldKind::Direct(ty) => {
                let seed_fn = gen_seed_fn_expr(ty);
                quote! {
                    #field_name => Ok(crate::resolver::FieldMetadata {
                        slot: slots::#slot_const,
                        offset: slots::#offset_const,
                        bytes: slots::#bytes_const,
                        is_mapping: false,
                        nesting_depth: 0,
                        seed: #seed_fn,
                    }),
                }
            }
            FieldKind::Mapping { key, value } => gen_mapping_metadata_arm(
                &field_name,
                &slot_const,
                &offset_const,
                &bytes_const,
                key,
                value,
            ),
        }
    });

    quote! {
        impl #name {
            #[cfg(any(test, feature = "test-utils"))]
            pub fn metadata_for(field: &str, keys: &[&str]) -> ::core::result::Result<crate::resolver::FieldMetadata, crate::resolver::ResolverError> {
                use crate::storage::StorageKey as _;

                match field {
                    #(#match_arms)*
                    _ => Err(crate::resolver::ResolverError::UnknownField(field.to_string())),
                }
            }
        }
    }
}

/// Generate a seed function expression for a given type.
///
/// Returns the appropriate seed function based on the type:
/// - `String` -> `ShortString::seed`
/// - `Vec<T>` -> `VecLen::seed`
/// - `[T; N]` (arrays) -> `struct_seed_unsupported`
/// - All other types -> `<T as Seedable>::seed_fn()`
///
/// The `Seedable` trait has a blanket impl for primitives (types implementing
/// `SeedFromJson + FromWord`) and is explicitly implemented for structs via
/// the `#[derive(Storable)]` macro.
fn gen_seed_fn_expr(ty: &Type) -> proc_macro2::TokenStream {
    if is_string_type(ty) {
        quote! { crate::resolver::ShortString::seed }
    } else if is_vec_type(ty) {
        quote! { crate::resolver::VecLen::seed }
    } else if is_array_type(ty) {
        // Arrays don't implement Seedable - use the fallback
        quote! { crate::resolver::struct_seed_unsupported }
    } else {
        // Use the Seedable trait - primitives get the blanket impl,
        // structs get the impl from #[derive(Storable)]
        quote! { <#ty as crate::resolver::Seedable>::seed_fn() }
    }
}

/// Check if a type is a fixed-size array `[T; N]`.
fn is_array_type(ty: &Type) -> bool {
    matches!(ty, Type::Array(_))
}

/// Check if a type is `String`.
fn is_string_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            return segment.ident == "String";
        }
    }
    false
}

/// Check if a type is `Vec<T>`.
fn is_vec_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            return segment.ident == "Vec";
        }
    }
    false
}

/// Get the innermost value type of a possibly nested mapping.
fn get_innermost_value_type(ty: &Type) -> &Type {
    if let Some((_, inner_value)) = crate::utils::extract_mapping_types(ty) {
        get_innermost_value_type(inner_value)
    } else {
        ty
    }
}

/// Generate the match arm for a mapping field, handling nested mappings recursively.
fn gen_mapping_metadata_arm(
    field_name: &str,
    slot_const: &Ident,
    offset_const: &Ident,
    bytes_const: &Ident,
    key_ty: &syn::Type,
    value_ty: &syn::Type,
) -> proc_macro2::TokenStream {
    let nesting_depth = count_mapping_nesting(value_ty);
    let nesting_depth_u8 = nesting_depth as u8;
    let innermost_ty = get_innermost_value_type(value_ty);
    let seed_fn = gen_seed_fn_expr(innermost_ty);

    if nesting_depth == 1 {
        quote! {
            #field_name => {
                if keys.is_empty() {
                    return Err(crate::resolver::ResolverError::MissingKey(0));
                }
                let k0 = <#key_ty as crate::storage::StorageKey>::parse_key(keys[0])
                    .map_err(|_| crate::resolver::ResolverError::InvalidKey(keys[0].to_string()))?;
                Ok(crate::resolver::FieldMetadata {
                    slot: k0.mapping_slot(slots::#slot_const),
                    offset: slots::#offset_const,
                    bytes: slots::#bytes_const,
                    is_mapping: true,
                    nesting_depth: #nesting_depth_u8,
                    seed: #seed_fn,
                })
            }
        }
    } else {
        let key_types: Vec<_> = (0..nesting_depth)
            .map(|i| get_key_type_at_depth(key_ty, value_ty, i))
            .collect();

        let key_parses: Vec<proc_macro2::TokenStream> = key_types
            .iter()
            .enumerate()
            .map(|(i, ty)| {
                let key_var = format_ident!("k{}", i);
                quote! {
                    let #key_var = <#ty as crate::storage::StorageKey>::parse_key(keys[#i])
                        .map_err(|_| crate::resolver::ResolverError::InvalidKey(keys[#i].to_string()))?;
                }
            })
            .collect();

        let slot_computation = gen_nested_slot_computation(slot_const, nesting_depth);

        quote! {
            #field_name => {
                if keys.len() < #nesting_depth {
                    return Err(crate::resolver::ResolverError::MissingKey(keys.len()));
                }
                #(#key_parses)*
                #slot_computation
                Ok(crate::resolver::FieldMetadata {
                    slot,
                    offset: slots::#offset_const,
                    bytes: slots::#bytes_const,
                    is_mapping: true,
                    nesting_depth: #nesting_depth_u8,
                    seed: #seed_fn,
                })
            }
        }
    }
}

/// Count the nesting depth of a mapping type.
fn count_mapping_nesting(value_ty: &syn::Type) -> usize {
    if let Some((_, inner_value)) = crate::utils::extract_mapping_types(value_ty) {
        1 + count_mapping_nesting(inner_value)
    } else {
        1
    }
}

/// Get the key type at a specific nesting depth.
fn get_key_type_at_depth<'a>(
    key_ty: &'a syn::Type,
    value_ty: &'a syn::Type,
    depth: usize,
) -> &'a syn::Type {
    if depth == 0 {
        key_ty
    } else if let Some((inner_key, inner_value)) = crate::utils::extract_mapping_types(value_ty) {
        get_key_type_at_depth(inner_key, inner_value, depth - 1)
    } else {
        key_ty
    }
}

/// Generate nested slot computation for multi-level mappings.
fn gen_nested_slot_computation(slot_const: &Ident, depth: usize) -> proc_macro2::TokenStream {
    let mut tokens = quote! {
        let mut slot = k0.mapping_slot(slots::#slot_const);
    };

    for i in 1..depth {
        let key_var = quote::format_ident!("k{}", i);
        tokens.extend(quote! {
            slot = #key_var.mapping_slot(slot);
        });
    }

    tokens
}
