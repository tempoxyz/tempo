//! Enum code generation for the `#[solidity]` module macro.
//!
//! Handles two types of enums:
//! - **Unit enums**: Encoded as `uint8`, like Solidity's `enum Status { Pending, Filled }`
//! - **Variant enums**: Error and Event enums with fields

use alloy_sol_macro_expander::{
    EventFieldInfo, SolErrorData, SolEventData, expand_from_into_tuples_simple,
};
use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};

use crate::utils::to_snake_case;

use super::{
    common::{self, SynSolType},
    parser::{EnumVariantDef, FieldAccessors, SolEnumDef, UnitEnumDef},
    registry::TypeRegistry,
};

/// Generate code for a unit enum definition (uint8-encoded).
pub(super) fn generate_unit_enum(def: &UnitEnumDef) -> TokenStream {
    let enum_name = &def.name;
    let vis = &def.vis;
    let attrs = &def.attrs;

    let (variants_with_discriminants, from_u8_arms): (Vec<_>, Vec<_>) = def
        .variants
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let idx = i as u8;
            (quote! { #v = #idx }, quote! { #idx => Ok(Self::#v) })
        })
        .unzip();

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
                let value: u8 = alloy::primitives::U256::from_be_bytes(token.0.0).to::<u8>();
                value < #variant_count
            }

            #[inline]
            fn detokenize(token: Self::Token<'_>) -> Self::RustType {
                let value: u8 = alloy::primitives::U256::from_be_bytes(token.0.0).to::<u8>();
                debug_assert!(
                    value < #variant_count,
                    "invalid {} discriminant: {}",
                    stringify!(#enum_name),
                    value
                );
                Self::try_from(value).unwrap_or_default()
            }
        }
    };

    let sol_type_value_impl = quote! {
        #[automatically_derived]
        impl alloy_sol_types::private::SolTypeValue<#enum_name> for #enum_name {
            #[inline]
            fn stv_to_tokens(&self) -> <#enum_name as alloy_sol_types::SolType>::Token<'_> {
                <alloy_sol_types::sol_data::Uint<8> as alloy_sol_types::SolType>::tokenize(&(*self as u8))
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
    let variant_impls = def
        .variants
        .iter()
        .map(|v| generate_variant(v, registry, kind))
        .collect::<syn::Result<Vec<_>>>()?;

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
    let field_pairs: Vec<_> = variant.fields().collect();
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
    let common::EncodedParams {
        param_tuple,
        tokenize_impl,
    } = common::encode_params(&variant.field_names(), &variant.field_raw_types())?;

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
            let sol_ty = SynSolType::parse(&f.ty)?;
            Ok(EventFieldInfo {
                name: f.name.clone(),
                sol_type: sol_ty.to_sol_data(),
                is_indexed: f.indexed,
                indexed_as_hash: f.indexed && !sol_ty.is_value_type(),
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
