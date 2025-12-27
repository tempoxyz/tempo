//! `#[derive(SolStruct)]` procedural macro for generating Alloy-compatible struct types.
//!
//! This macro transforms a Rust struct with named fields into a type that implements
//! the `SolType`, `SolValue`, `SolStruct`, and `EventTopic` traits from alloy-sol-types.
//!
//! # Example
//!
//! ```ignore
//! #[derive(SolStruct, Clone, Debug, PartialEq)]
//! pub struct RewardStream {
//!     pub funder: Address,
//!     pub start_time: u64,
//!     pub end_time: u64,
//!     pub rate_per_second_scaled: U256,
//!     pub amount_total: U256,
//! }
//! ```
//!
//! Generates implementations for:
//! - `SolValue` - marker trait
//! - `SolType` - ABI encoding/decoding
//! - `SolStruct` - EIP-712 typed data
//! - `EventTopic` - event topic encoding

use alloy_sol_macro_expander::{Eip712Options, SolStructData};
use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::{DeriveInput, Fields};

use crate::utils::{SolType, to_camel_case};

/// Main implementation for SolStruct derive
pub(crate) fn derive_impl(input: DeriveInput) -> syn::Result<TokenStream> {
    let struct_name = &input.ident;

    // Extract named fields
    let fields = match &input.data {
        syn::Data::Struct(data) => match &data.fields {
            Fields::Named(named) => &named.named,
            Fields::Unit => {
                return Err(syn::Error::new_spanned(
                    &input,
                    "SolStruct can only be derived for structs with named fields",
                ))
            }
            Fields::Unnamed(_) => {
                return Err(syn::Error::new_spanned(
                    &input,
                    "SolStruct can only be derived for structs with named fields, not tuple structs",
                ))
            }
        },
        syn::Data::Enum(_) => {
            return Err(syn::Error::new_spanned(
                &input,
                "SolStruct cannot be derived for enums",
            ))
        }
        syn::Data::Union(_) => {
            return Err(syn::Error::new_spanned(
                &input,
                "SolStruct cannot be derived for unions",
            ))
        }
    };

    // Build field info vectors
    let field_names: Vec<Ident> = fields
        .iter()
        .map(|f| f.ident.clone().expect("named field must have ident"))
        .collect();

    let rust_types: Vec<TokenStream> = fields
        .iter()
        .map(|f| {
            let ty = &f.ty;
            quote! { #ty }
        })
        .collect();

    // Convert types once for both sol_types and EIP-712 signature
    let converted: syn::Result<Vec<_>> = fields.iter().map(|f| SolType::from_syn(&f.ty)).collect();
    let converted = converted?;
    let sol_types: Vec<TokenStream> = converted.iter().map(|t| t.to_sol_data()).collect();

    // Build EIP-712 signature using the already-converted types
    let eip712_signature = build_eip712_signature(struct_name, fields, &converted);

    // Build ABI tuple signature for SolTupleSignature trait
    let abi_tuple_impl = build_abi_tuple_impl(fields, &converted);

    // Collect struct dependencies for EIP-712 components
    let struct_deps: Vec<_> = converted
        .iter()
        .flat_map(|t| t.collect_struct_idents())
        .collect();

    // Generate EIP-712 components_impl if we have nested struct dependencies
    let components_impl = if struct_deps.is_empty() {
        None
    } else {
        // Deduplicate struct idents (same struct may appear multiple times)
        let unique_deps: Vec<_> = {
            let mut seen = std::collections::HashSet::new();
            struct_deps
                .into_iter()
                .filter(|ident| seen.insert(ident.to_string()))
                .collect()
        };

        Some(quote! {
            {
                let mut components = alloy_sol_types::private::Vec::new();
                // Recursively collect components from nested structs
                #(
                    components.extend(<#unique_deps as alloy_sol_types::SolStruct>::eip712_components());
                    components.push(<#unique_deps as alloy_sol_types::SolStruct>::eip712_root_type());
                )*
                // Sort and deduplicate for canonical ordering
                components.sort();
                components.dedup();
                components
            }
        })
    };

    // Generate the SolStruct implementation using the shared helper
    let sol_struct_impl = SolStructData {
        field_names,
        rust_types,
        sol_types,
        eip712: Eip712Options {
            signature: eip712_signature,
            components_impl,
            encode_type_impl: None,
        },
    }
    .expand(struct_name);

    // Generate SolTupleSignature implementation
    let sol_tuple_sig_impl = quote! {
        impl tempo_precompiles::SolTupleSignature for #struct_name {
            const ABI_TUPLE: &'static str = #abi_tuple_impl;
        }
    };

    Ok(quote! {
        #sol_struct_impl
        #sol_tuple_sig_impl
    })
}

/// Build ABI tuple signature implementation for SolTupleSignature trait.
///
/// For structs with only primitive fields, returns a literal string like `"(address,uint256)"`.
/// For structs with nested struct fields, returns a `concatcp!` expression that
/// composes the signature at compile time using the nested struct's `ABI_TUPLE`.
fn build_abi_tuple_impl<'a>(
    fields: impl IntoIterator<Item = &'a syn::Field>,
    sol_types: &[SolType],
) -> TokenStream {
    let field_types: Vec<_> = fields.into_iter().map(|f| &f.ty).collect();

    // Check if any field is a struct type (requires const composition)
    let has_struct_fields = sol_types.iter().any(|t| t.contains_struct());

    if has_struct_fields {
        // Generate const_format::concatcp! expression for compile-time composition
        let parts: Vec<TokenStream> = sol_types
            .iter()
            .zip(field_types.iter())
            .enumerate()
            .flat_map(|(i, (sol_ty, ty))| {
                let mut tokens = Vec::new();
                if i > 0 {
                    tokens.push(quote! { "," });
                }
                tokens.push(sol_ty.to_abi_signature_expr(ty));
                tokens
            })
            .collect();

        quote! {
            tempo_precompiles::const_format::concatcp!("(", #(#parts,)* ")")
        }
    } else {
        // All primitive types - can use a simple literal string
        let mut sig = String::from("(");
        for (i, sol_ty) in sol_types.iter().enumerate() {
            if i > 0 {
                sig.push(',');
            }
            sig.push_str(&sol_ty.sol_name());
        }
        sig.push(')');
        quote! { #sig }
    }
}

/// Build EIP-712 type signature from struct name, fields, and pre-converted SolTypes
fn build_eip712_signature<'a>(
    name: &Ident,
    fields: impl IntoIterator<Item = &'a syn::Field>,
    sol_types: &[SolType],
) -> String {
    let mut sig = name.to_string();
    sig.push('(');

    for (i, (field, sol_ty)) in fields.into_iter().zip(sol_types).enumerate() {
        if i > 0 {
            sig.push(',');
        }
        let field_name = to_camel_case(&field.ident.as_ref().unwrap().to_string());
        sig.push_str(&sol_ty.sol_name());
        sig.push(' ');
        sig.push_str(&field_name);
    }

    sig.push(')');
    sig
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::format_ident;

    #[test]
    fn test_build_eip712_signature_simple() -> syn::Result<()> {
        let name = format_ident!("TestStruct");
        let field1: syn::Field = syn::parse_quote! { pub owner: Address };
        let field2: syn::Field = syn::parse_quote! { pub value: U256 };
        let fields = [&field1, &field2];
        let sol_types: syn::Result<Vec<_>> =
            fields.iter().map(|f| SolType::from_syn(&f.ty)).collect();

        let sig = build_eip712_signature(&name, fields, &sol_types?);
        assert_eq!(sig, "TestStruct(address owner,uint256 value)");
        Ok(())
    }

    #[test]
    fn test_build_eip712_signature_snake_case_conversion() -> syn::Result<()> {
        let name = format_ident!("RewardStream");
        let field1: syn::Field = syn::parse_quote! { pub start_time: u64 };
        let field2: syn::Field = syn::parse_quote! { pub rate_per_second: U256 };
        let fields = [&field1, &field2];
        let sol_types: syn::Result<Vec<_>> =
            fields.iter().map(|f| SolType::from_syn(&f.ty)).collect();

        let sig = build_eip712_signature(&name, fields, &sol_types?);
        assert_eq!(sig, "RewardStream(uint64 startTime,uint256 ratePerSecond)");
        Ok(())
    }

    #[test]
    fn test_sol_type_primitives() -> syn::Result<()> {
        assert_eq!(SolType::from_syn(&syn::parse_quote!(Address))?.sol_name(), "address");
        assert_eq!(SolType::from_syn(&syn::parse_quote!(U256))?.sol_name(), "uint256");
        assert_eq!(SolType::from_syn(&syn::parse_quote!(u64))?.sol_name(), "uint64");
        assert_eq!(SolType::from_syn(&syn::parse_quote!(bool))?.sol_name(), "bool");
        Ok(())
    }

    #[test]
    fn test_sol_type_arrays() -> syn::Result<()> {
        assert_eq!(SolType::from_syn(&syn::parse_quote!(Vec<Address>))?.sol_name(), "address[]");
        assert_eq!(SolType::from_syn(&syn::parse_quote!([U256; 3]))?.sol_name(), "uint256[3]");
        Ok(())
    }
}
