//! Unit enum code generation for the `#[solidity]` module macro.
//!
//! Generates Solidity-compatible unit enums that encode as `uint8`.
//! These correspond to Solidity enums like `enum Status { Pending, Filled, Cancelled }`.
//!
//! # Generated Code
//!
//! For each unit enum:
//! - `#[repr(u8)]` with explicit discriminants (0, 1, 2, ...)
//! - `From<Enum> for u8`
//! - `TryFrom<u8> for Enum`
//! - `SolType` implementation (encodes as uint8)
//! - `SolTypeValue` implementation

use proc_macro2::TokenStream;
use quote::quote;

use super::parser::UnitEnumDef;

/// Generate code for a unit enum definition.
pub(super) fn generate_unit_enum(def: &UnitEnumDef) -> TokenStream {
    let enum_name = &def.name;
    let vis = &def.vis;
    let attrs = &def.attrs;
    let variant_count = def.variants.len();

    let variants_with_discriminants: Vec<TokenStream> = def
        .variants
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let idx = i as u8;
            quote! { #v = #idx }
        })
        .collect();

    let _variant_names = &def.variants;

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

    let variant_count_u8 = variant_count as u8;

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
                value < #variant_count_u8
            }

            #[inline]
            fn detokenize(token: Self::Token<'_>) -> Self::RustType {
                let value: u8 = token.0.to();
                Self::try_from(value).expect("invalid enum value")
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

    let default_impl = if !def.variants.is_empty() {
        let first_variant = &def.variants[0];
        quote! {
            #[automatically_derived]
            impl ::core::default::Default for #enum_name {
                #[inline]
                fn default() -> Self {
                    Self::#first_variant
                }
            }
        }
    } else {
        quote! {}
    };

    quote! {
        #enum_def
        #from_impl
        #try_from_impl
        #sol_type_impl
        #sol_type_value_impl
        #sol_value_impl
        #default_impl
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proc_macro2::Span;
    use quote::format_ident;
    use syn::Visibility;

    fn make_unit_enum(name: &str, variants: Vec<&str>) -> UnitEnumDef {
        UnitEnumDef {
            name: format_ident!("{}", name),
            variants: variants.iter().map(|v| format_ident!("{}", v)).collect(),
            attrs: vec![],
            vis: Visibility::Public(syn::token::Pub {
                span: Span::call_site(),
            }),
        }
    }

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
}
