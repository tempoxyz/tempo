//! Enum code generation for the `#[solidity]` module macro.
//!
//! Handles two types of enums:
//! - **Unit enums**: Encoded as `uint8`, like Solidity's `enum Status { Pending, Filled }`
//! - **Variant enums**: Error and Event enums with fields

use alloy_sol_macro_expander::{
    EventFieldInfo, SolErrorData, SolEventData, expand_from_into_tuples_simple,
    expand_tokenize_simple,
};
use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};

use crate::utils::{SolType, to_snake_case};

use super::common;
use super::parser::{EnumVariantDef, SolEnumDef, UnitEnumDef};
use super::registry::TypeRegistry;

// ============================================================================
// Unit Enum Generation
// ============================================================================

/// Generate code for a unit enum definition (uint8-encoded).
pub(super) fn generate_unit_enum(def: &UnitEnumDef) -> TokenStream {
    let enum_name = &def.name;
    let vis = &def.vis;
    let attrs = &def.attrs;

    let variants_with_discriminants: Vec<TokenStream> = def
        .variants
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let idx = i as u8;
            quote! { #v = #idx }
        })
        .collect();

    let from_u8_arms: Vec<TokenStream> = def
        .variants
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let idx = i as u8;
            quote! { #idx => Ok(Self::#v) }
        })
        .collect();

    let enum_def = quote! {
        #(#attrs)*
        #[repr(u8)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #vis enum #enum_name {
            #(#variants_with_discriminants),*
        }
    };

    let trait_impls = expand_unit_enum_traits(
        enum_name,
        def.variants.len() as u8,
        &from_u8_arms,
        def.variants.first(),
    );

    quote! {
        #enum_def
        #trait_impls
    }
}

/// Generate all trait implementations for a unit enum (uint8-encoded).
fn expand_unit_enum_traits(
    enum_name: &Ident,
    variant_count: u8,
    from_u8_arms: &[TokenStream],
    first_variant: Option<&Ident>,
) -> TokenStream {
    let from_impl = quote! {
        #[automatically_derived]
        impl ::core::convert::From<#enum_name> for u8 {
            #[inline]
            fn from(value: #enum_name) -> u8 {
                value as u8
            }
        }
    };

    let try_from_impl = quote! {
        #[automatically_derived]
        impl ::core::convert::TryFrom<u8> for #enum_name {
            type Error = ();

            #[inline]
            fn try_from(value: u8) -> ::core::result::Result<Self, ()> {
                match value {
                    #(#from_u8_arms,)*
                    _ => Err(()),
                }
            }
        }
    };

    let sol_type_impl = quote! {
        #[automatically_derived]
        impl alloy_sol_types::SolType for #enum_name {
            type RustType = Self;
            type Token<'a> = <alloy_sol_types::sol_data::Uint<8> as alloy_sol_types::SolType>::Token<'a>;

            const SOL_NAME: &'static str = "uint8";
            const ENCODED_SIZE: Option<usize> = Some(32);
            const PACKED_ENCODED_SIZE: Option<usize> = Some(1);

            #[inline]
            fn valid_token(token: &Self::Token<'_>) -> bool {
                let value: u8 = token.0.to();
                value < #variant_count
            }

            #[inline]
            fn detokenize(token: Self::Token<'_>) -> Self::RustType {
                let value: u8 = token.0.to();
                // SAFETY: Returns default variant for invalid values (defensive, should not occur with valid_token check)
                Self::try_from(value).unwrap_or_default()
            }
        }
    };

    let sol_type_value_impl = quote! {
        #[automatically_derived]
        impl alloy_sol_types::private::SolTypeValue<#enum_name> for #enum_name {
            #[inline]
            fn stv_to_tokens(&self) -> <#enum_name as alloy_sol_types::SolType>::Token<'_> {
                alloy_sol_types::Word::from(alloy::primitives::U256::from(*self as u8))
            }

            #[inline]
            fn stv_abi_encode_packed_to(&self, out: &mut alloy_sol_types::private::Vec<u8>) {
                out.push(*self as u8);
            }

            #[inline]
            fn stv_eip712_data_word(&self) -> alloy_sol_types::Word {
                <alloy_sol_types::sol_data::Uint<8> as alloy_sol_types::SolType>::tokenize(&(*self as u8)).0
            }
        }
    };

    let sol_value_impl = quote! {
        #[automatically_derived]
        impl alloy_sol_types::SolValue for #enum_name {
            type SolType = Self;
        }
    };

    let default_impl = first_variant.map(|fv| {
        quote! {
            #[automatically_derived]
            impl ::core::default::Default for #enum_name {
                #[inline]
                fn default() -> Self {
                    Self::#fv
                }
            }
        }
    });

    quote! {
        #from_impl
        #try_from_impl
        #sol_type_impl
        #sol_type_value_impl
        #sol_value_impl
        #default_impl
    }
}

// ============================================================================
// Variant Enum Generation (Error/Event)
// ============================================================================

/// Kind of variant enum being generated.
#[derive(Clone, Copy)]
pub(super) enum VariantEnumKind {
    Error,
    Event,
}

/// Generate code for Error or Event enum.
pub(super) fn generate_variant_enum(
    def: &SolEnumDef,
    registry: &TypeRegistry,
    kind: VariantEnumKind,
) -> syn::Result<TokenStream> {
    let variant_impls: syn::Result<Vec<TokenStream>> = def
        .variants
        .iter()
        .map(|v| generate_variant(v, registry, kind))
        .collect();
    let variant_impls = variant_impls?;

    let container_name = match kind {
        VariantEnumKind::Error => format_ident!("Error"),
        VariantEnumKind::Event => format_ident!("Event"),
    };

    let container = match kind {
        VariantEnumKind::Error => common::generate_error_container(&def.variants, registry)?,
        VariantEnumKind::Event => common::generate_event_container(&def.variants),
    };

    let constructors = generate_constructors(&container_name, &def.variants);

    Ok(quote! {
        #(#variant_impls)*
        #container
        #constructors
    })
}

/// Generate code for a single variant (Error or Event).
fn generate_variant(
    variant: &EnumVariantDef,
    registry: &TypeRegistry,
    kind: VariantEnumKind,
) -> syn::Result<TokenStream> {
    let struct_name = &variant.name;
    let signature =
        registry.compute_signature_from_fields(&variant.name.to_string(), &variant.fields)?;
    let field_names = variant.field_names();
    let field_types = variant.field_types();

    let doc_kind = match kind {
        VariantEnumKind::Error => "Custom error",
        VariantEnumKind::Event => "Event",
    };
    let doc = common::signature_doc(doc_kind, &signature);
    let field_pairs: Vec<_> = variant.fields.iter().map(|f| (&f.name, &f.ty)).collect();
    let variant_struct = common::generate_simple_struct(struct_name, &field_pairs, &doc);
    let from_tuple = expand_from_into_tuples_simple(struct_name, &field_names, &field_types);

    let trait_impl = match kind {
        VariantEnumKind::Error => generate_sol_error_impl(variant, &signature)?,
        VariantEnumKind::Event => generate_sol_event_impl(variant, &signature)?,
    };

    Ok(quote! {
        #variant_struct
        #from_tuple
        #trait_impl
    })
}

/// Generate SolError trait implementation.
fn generate_sol_error_impl(variant: &EnumVariantDef, signature: &str) -> syn::Result<TokenStream> {
    let struct_name = &variant.name;
    let field_names = variant.field_names();
    let sol_types = common::types_to_sol_types(&variant.raw_types())?;
    let param_tuple = common::make_param_tuple(&sol_types);
    let tokenize_impl = expand_tokenize_simple(&field_names, &sol_types);

    Ok(SolErrorData {
        param_tuple,
        tokenize_impl,
    }
    .expand(struct_name, signature))
}

/// Generate SolEvent trait implementation.
fn generate_sol_event_impl(variant: &EnumVariantDef, signature: &str) -> syn::Result<TokenStream> {
    let struct_name = &variant.name;

    let fields: syn::Result<Vec<EventFieldInfo>> = variant
        .fields
        .iter()
        .map(|f| {
            let sol_ty = SolType::from_syn(&f.ty)?;
            Ok(EventFieldInfo {
                name: f.name.clone(),
                sol_type: sol_ty.to_sol_data(),
                is_indexed: f.indexed,
                indexed_as_hash: f.indexed && sol_ty.is_dynamic(),
            })
        })
        .collect();

    Ok(SolEventData {
        anonymous: false,
        fields: fields?,
    }
    .expand(struct_name, signature))
}

/// Generate constructor methods for container enum.
fn generate_constructors(container: &Ident, variants: &[EnumVariantDef]) -> TokenStream {
    let constructors: Vec<TokenStream> = variants
        .iter()
        .map(|v| {
            let variant_name = &v.name;
            let fn_name = format_ident!("{}", to_snake_case(&v.name.to_string()));

            if v.fields.is_empty() {
                quote! {
                    #[doc = concat!("Creates a new `", stringify!(#variant_name), "`.")]
                    pub const fn #fn_name() -> Self {
                        Self::#variant_name(#variant_name)
                    }
                }
            } else {
                let param_names: Vec<_> = v.fields.iter().map(|f| &f.name).collect();
                let param_types: Vec<_> = v.fields.iter().map(|f| &f.ty).collect();

                quote! {
                    #[doc = concat!("Creates a new `", stringify!(#variant_name), "`.")]
                    pub fn #fn_name(#(#param_names: #param_types),*) -> Self {
                        Self::#variant_name(#variant_name { #(#param_names),* })
                    }
                }
            }
        })
        .collect();

    quote! {
        impl #container {
            #(#constructors)*
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solidity::test_utils::{
        empty_module, make_error_enum, make_event_enum, make_field, make_field_indexed,
        make_unit_enum, make_variant,
    };
    use syn::parse_quote;

    #[test]
    fn test_generate_unit_enum() {
        let def = make_unit_enum("OrderStatus", vec!["Pending", "Filled", "Cancelled"]);
        let tokens = generate_unit_enum(&def);
        let code = tokens.to_string();

        assert!(code.contains("repr"));
        assert!(code.contains("u8"));
        assert!(code.contains("enum OrderStatus"));
        assert!(code.contains("Pending"));
        assert!(code.contains("Filled"));
        assert!(code.contains("Cancelled"));
        assert!(code.contains("From"));
        assert!(code.contains("TryFrom"));
        assert!(code.contains("SolType"));
    }

    #[test]
    fn test_generate_unit_enum_single_variant() {
        let def = make_unit_enum("SingleVariant", vec!["Only"]);
        let tokens = generate_unit_enum(&def);
        let code = tokens.to_string();

        assert!(code.contains("Only = 0u8"));
        assert!(code.contains("value < 1u8"));
    }

    #[test]
    fn test_generate_error_and_event_enums() -> syn::Result<()> {
        let module = empty_module();
        let registry = TypeRegistry::from_module(&module)?;

        // Error enum
        let error_def = make_error_enum(vec![
            make_variant("Unauthorized", vec![]),
            make_variant(
                "InsufficientBalance",
                vec![
                    make_field("available", parse_quote!(U256)),
                    make_field("required", parse_quote!(U256)),
                ],
            ),
        ]);
        let error_code =
            generate_variant_enum(&error_def, &registry, VariantEnumKind::Error)?.to_string();
        assert!(
            error_code.contains("struct Unauthorized")
                && error_code.contains("struct InsufficientBalance")
        );
        assert!(error_code.contains("enum Error") && error_code.contains("fn unauthorized"));

        // Event enum
        let event_def = make_event_enum(vec![make_variant(
            "Transfer",
            vec![
                make_field_indexed("from", parse_quote!(Address), true),
                make_field_indexed("to", parse_quote!(Address), true),
                make_field_indexed("amount", parse_quote!(U256), false),
            ],
        )]);
        let event_code =
            generate_variant_enum(&event_def, &registry, VariantEnumKind::Event)?.to_string();
        assert!(event_code.contains("struct Transfer") && event_code.contains("enum Event"));
        assert!(event_code.contains("IntoLogData") && event_code.contains("fn transfer"));
        Ok(())
    }
}
