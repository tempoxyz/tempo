//! Code generation for the `metadata_for` resolver method.
//!
//! This module generates a `metadata_for` method for each contract that allows
//! runtime resolution of storage field metadata by field name.

use crate::{
    FieldKind,
    packing::{LayoutField, PackingConstants},
};
use quote::{format_ident, quote};
use syn::Ident;

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
            FieldKind::Direct(_ty) => {
                quote! {
                    #field_name => Ok(crate::resolver::FieldMetadata {
                        slot: slots::#slot_const,
                        offset: slots::#offset_const,
                        bytes: slots::#bytes_const,
                        is_mapping: false,
                        nesting_depth: 0,
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
