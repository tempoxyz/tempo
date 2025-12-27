//! Event enum code generation for the `#[solidity]` module macro.
//!
//! Generates `SolEvent` implementations for event variants and a container
//! `Event` enum with `IntoLogData` implementation.

use alloy_sol_macro_expander::{
    EventFieldInfo, SolEventData, expand_from_into_tuples_simple, selector,
};
use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};

use crate::utils::{to_snake_case, SolType};

use super::parser::{EnumVariantDef, SolEnumDef};
use super::registry::TypeRegistry;

/// Generate code for the Event enum.
pub(super) fn generate_event_enum(
    def: &SolEnumDef,
    registry: &TypeRegistry,
) -> syn::Result<TokenStream> {
    let variant_impls: syn::Result<Vec<TokenStream>> = def
        .variants
        .iter()
        .map(|v| generate_event_variant(v, registry))
        .collect();
    let variant_impls = variant_impls?;

    let container = generate_event_container(&def.variants);

    let constructors = generate_constructors(&def.variants);

    let from_impls: Vec<TokenStream> = def
        .variants
        .iter()
        .map(generate_from_impl)
        .collect();

    Ok(quote! {
        #(#variant_impls)*
        #container
        #constructors
        #(#from_impls)*
    })
}

/// Generate code for a single event variant.
fn generate_event_variant(
    variant: &EnumVariantDef,
    registry: &TypeRegistry,
) -> syn::Result<TokenStream> {
    let struct_name = &variant.name;
    let signature = generate_variant_signature(variant, registry)?;

    let field_names: Vec<Ident> = variant.fields.iter().map(|f| f.name.clone()).collect();

    let sel = selector(&signature);
    let doc = format!(
        "Event with signature `{}` and selector `0x{}`.",
        signature,
        hex::encode(sel)
    );

    let variant_struct = if variant.fields.is_empty() {
        quote! {
            #[doc = #doc]
            #[derive(Clone, Debug, PartialEq, Eq)]
            pub struct #struct_name;
        }
    } else {
        let names = &field_names;
        let types: Vec<_> = variant.fields.iter().map(|f| &f.ty).collect();
        quote! {
            #[doc = #doc]
            #[derive(Clone, Debug, PartialEq, Eq)]
            pub struct #struct_name {
                #(pub #names: #types),*
            }
        }
    };

    let field_type_tokens: Vec<TokenStream> = variant
        .fields
        .iter()
        .map(|f| {
            let ty = &f.ty;
            quote! { #ty }
        })
        .collect();
    let from_tuple = expand_from_into_tuples_simple(struct_name, &field_names, &field_type_tokens);

    let trait_impl = generate_event_trait_impl(variant, &signature)?;

    Ok(quote! {
        #variant_struct
        #from_tuple
        #trait_impl
    })
}

/// Generate the SolEvent trait implementation for an event variant.
fn generate_event_trait_impl(
    variant: &EnumVariantDef,
    signature: &str,
) -> syn::Result<TokenStream> {
    let struct_name = &variant.name;

    let fields: syn::Result<Vec<EventFieldInfo>> = variant
        .fields
        .iter()
        .map(|f| {
            let sol_ty = SolType::from_syn(&f.ty)?;
            let indexed_as_hash = f.indexed && sol_ty.is_dynamic();
            Ok(EventFieldInfo {
                name: f.name.clone(),
                sol_type: sol_ty.to_sol_data(),
                is_indexed: f.indexed,
                indexed_as_hash,
            })
        })
        .collect();

    let data = SolEventData {
        anonymous: false,
        fields: fields?,
    };

    Ok(data.expand(struct_name, signature))
}

/// Generate the Solidity signature for a variant using the registry.
fn generate_variant_signature(
    variant: &EnumVariantDef,
    registry: &TypeRegistry,
) -> syn::Result<String> {
    let param_types: Vec<_> = variant.fields.iter().map(|f| f.ty.clone()).collect();
    registry.compute_signature(&variant.name.to_string(), &param_types)
}

/// Generate the container Event enum with IntoLogData.
fn generate_event_container(variants: &[EnumVariantDef]) -> TokenStream {
    let variant_names: Vec<&Ident> = variants.iter().map(|v| &v.name).collect();
    let variant_names2 = variant_names.clone();
    let variant_names3 = variant_names.clone();

    quote! {
        /// Container enum for all event types.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum Event {
            #(
                #[allow(missing_docs)]
                #variant_names(#variant_names),
            )*
        }

        #[automatically_derived]
        impl ::alloy::primitives::IntoLogData for Event {
            fn to_log_data(&self) -> ::alloy::primitives::LogData {
                match self {
                    #(
                        Self::#variant_names2(inner) => inner.to_log_data(),
                    )*
                }
            }

            fn into_log_data(self) -> ::alloy::primitives::LogData {
                match self {
                    #(
                        Self::#variant_names3(inner) => inner.into_log_data(),
                    )*
                }
            }
        }
    }
}

/// Generate snake_case constructor methods.
fn generate_constructors(variants: &[EnumVariantDef]) -> TokenStream {
    let constructors: Vec<TokenStream> = variants
        .iter()
        .map(|v| {
            let variant_name = &v.name;
            let fn_name = format_ident!("{}", to_snake_case(&v.name.to_string()));

            if v.fields.is_empty() {
                quote! {
                    #[doc = concat!("Creates a new `", stringify!(#variant_name), "`.")]
                    pub fn #fn_name() -> Self {
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
        impl Event {
            #(#constructors)*
        }
    }
}

/// Generate From impl for converting individual variant to container enum.
fn generate_from_impl(variant: &EnumVariantDef) -> TokenStream {
    let variant_name = &variant.name;

    quote! {
        #[automatically_derived]
        impl ::core::convert::From<#variant_name> for Event {
            #[inline]
            fn from(value: #variant_name) -> Self {
                Self::#variant_name(value)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solidity::parser::{FieldDef, SolEnumDef, SolidityModule};
    use proc_macro2::Span;
    use quote::format_ident;
    use syn::{parse_quote, Visibility};

    fn make_field(name: &str, ty: syn::Type, indexed: bool) -> FieldDef {
        FieldDef {
            name: format_ident!("{}", name),
            ty,
            indexed,
            vis: Visibility::Public(syn::token::Pub {
                span: Span::call_site(),
            }),
        }
    }

    fn make_variant(name: &str, fields: Vec<FieldDef>) -> EnumVariantDef {
        EnumVariantDef {
            name: format_ident!("{}", name),
            fields,
        }
    }

    fn make_event_enum(variants: Vec<EnumVariantDef>) -> SolEnumDef {
        SolEnumDef {
            name: format_ident!("Event"),
            variants,
            attrs: vec![],
            vis: Visibility::Public(syn::token::Pub {
                span: Span::call_site(),
            }),
        }
    }

    fn empty_module() -> SolidityModule {
        SolidityModule {
            name: format_ident!("test"),
            vis: Visibility::Public(syn::token::Pub {
                span: Span::call_site(),
            }),
            imports: vec![],
            structs: vec![],
            unit_enums: vec![],
            error: None,
            event: None,
            interface: None,
            other_items: vec![],
        }
    }

    #[test]
    fn test_generate_event_enum() -> syn::Result<()> {
        let module = empty_module();
        let registry = TypeRegistry::from_module(&module)?;

        let def = make_event_enum(vec![make_variant(
            "Transfer",
            vec![
                make_field("from", parse_quote!(Address), true),
                make_field("to", parse_quote!(Address), true),
                make_field("amount", parse_quote!(U256), false),
            ],
        )]);

        let tokens = generate_event_enum(&def, &registry)?;
        let code = tokens.to_string();

        assert!(code.contains("struct Transfer"));
        assert!(code.contains("enum Event"));
        assert!(code.contains("fn transfer"));
        assert!(code.contains("IntoLogData"));

        Ok(())
    }

    #[test]
    fn test_generate_variant_signature() -> syn::Result<()> {
        let module = empty_module();
        let registry = TypeRegistry::from_module(&module)?;

        let variant = make_variant(
            "Transfer",
            vec![
                make_field("from", parse_quote!(Address), true),
                make_field("to", parse_quote!(Address), true),
                make_field("amount", parse_quote!(U256), false),
            ],
        );

        let sig = generate_variant_signature(&variant, &registry)?;
        assert_eq!(sig, "Transfer(address,address,uint256)");

        Ok(())
    }
}
