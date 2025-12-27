//! Error enum code generation for the `#[solidity]` module macro.
//!
//! Generates `SolError` implementations for error variants and a container
//! `Error` enum with `SolInterface` implementation.

use alloy_sol_macro_expander::{
    SolErrorData, SolInterfaceData, SolInterfaceKind, expand_from_into_tuples_simple,
    expand_sol_interface, expand_tokenize_simple, selector,
};
use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};

use crate::utils::{to_snake_case, SolType};

use super::parser::{EnumVariantDef, SolEnumDef};
use super::registry::TypeRegistry;

/// Generate code for the Error enum.
pub(super) fn generate_error_enum(
    def: &SolEnumDef,
    registry: &TypeRegistry,
) -> syn::Result<TokenStream> {
    let variant_impls: syn::Result<Vec<TokenStream>> = def
        .variants
        .iter()
        .map(|v| generate_error_variant(v, registry))
        .collect();
    let variant_impls = variant_impls?;

    let container = generate_error_container(&def.variants, registry)?;

    let constructors = generate_constructors(&def.variants);

    Ok(quote! {
        #(#variant_impls)*
        #container
        #constructors
    })
}

/// Generate code for a single error variant.
fn generate_error_variant(
    variant: &EnumVariantDef,
    registry: &TypeRegistry,
) -> syn::Result<TokenStream> {
    let struct_name = &variant.name;
    let signature = generate_variant_signature(variant, registry)?;

    let field_names: Vec<Ident> = variant.fields.iter().map(|f| f.name.clone()).collect();

    let field_sol_types: syn::Result<Vec<TokenStream>> = variant
        .fields
        .iter()
        .map(|f| Ok(SolType::from_syn(&f.ty)?.to_sol_data()))
        .collect();
    let field_sol_types = field_sol_types?;

    let sel = selector(&signature);
    let doc = format!(
        "Custom error with signature `{}` and selector `0x{}`.",
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

    let param_tuple = if field_sol_types.is_empty() {
        quote! { () }
    } else {
        quote! { (#(#field_sol_types,)*) }
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

    let tokenize_impl = expand_tokenize_simple(&field_names, &field_sol_types);
    let trait_impl = SolErrorData {
        param_tuple,
        tokenize_impl,
    }
    .expand(struct_name, &signature);

    Ok(quote! {
        #variant_struct
        #from_tuple
        #trait_impl
    })
}

/// Generate the Solidity signature for a variant using the registry.
fn generate_variant_signature(
    variant: &EnumVariantDef,
    registry: &TypeRegistry,
) -> syn::Result<String> {
    let param_types: Vec<_> = variant.fields.iter().map(|f| f.ty.clone()).collect();
    registry.compute_signature(&variant.name.to_string(), &param_types)
}

/// Generate the container Error enum with SolInterface.
fn generate_error_container(
    variants: &[EnumVariantDef],
    registry: &TypeRegistry,
) -> syn::Result<TokenStream> {
    let variant_names: Vec<Ident> = variants.iter().map(|v| v.name.clone()).collect();
    let types: Vec<Ident> = variants.iter().map(|v| v.name.clone()).collect();

    let signatures: syn::Result<Vec<String>> = variants
        .iter()
        .map(|v| generate_variant_signature(v, registry))
        .collect();
    let signatures = signatures?;

    let data = SolInterfaceData {
        name: format_ident!("Error"),
        variants: variant_names,
        types,
        selectors: signatures.iter().map(|s| selector(s)).collect(),
        min_data_len: variants
            .iter()
            .map(|v| v.fields.len() * 32)
            .min()
            .unwrap_or(0),
        signatures,
        kind: SolInterfaceKind::Error,
    };

    Ok(expand_sol_interface(data))
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
        impl Error {
            #(#constructors)*
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

    fn make_field(name: &str, ty: syn::Type) -> FieldDef {
        FieldDef {
            name: format_ident!("{}", name),
            ty,
            indexed: false,
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

    fn make_error_enum(variants: Vec<EnumVariantDef>) -> SolEnumDef {
        SolEnumDef {
            name: format_ident!("Error"),
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
    fn test_generate_error_enum() -> syn::Result<()> {
        let module = empty_module();
        let registry = TypeRegistry::from_module(&module)?;

        let def = make_error_enum(vec![
            make_variant("Unauthorized", vec![]),
            make_variant(
                "InsufficientBalance",
                vec![
                    make_field("available", parse_quote!(U256)),
                    make_field("required", parse_quote!(U256)),
                ],
            ),
        ]);

        let tokens = generate_error_enum(&def, &registry)?;
        let code = tokens.to_string();

        assert!(code.contains("struct Unauthorized"));
        assert!(code.contains("struct InsufficientBalance"));
        assert!(code.contains("enum Error"));
        assert!(code.contains("fn unauthorized"));
        assert!(code.contains("fn insufficient_balance"));

        Ok(())
    }

    #[test]
    fn test_generate_variant_signature() -> syn::Result<()> {
        let module = empty_module();
        let registry = TypeRegistry::from_module(&module)?;

        let variant = make_variant(
            "InsufficientBalance",
            vec![
                make_field("available", parse_quote!(U256)),
                make_field("required", parse_quote!(U256)),
            ],
        );

        let sig = generate_variant_signature(&variant, &registry)?;
        assert_eq!(sig, "InsufficientBalance(uint256,uint256)");

        Ok(())
    }
}
