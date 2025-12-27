//! Interface trait code generation for the `#[solidity]` module macro.
//!
//! Generates `SolCall` structs for each method and a container `InterfaceCalls`
//! enum with `SolInterface` implementation.
//!
//! Also transforms the trait to inject `msg_sender: Address` for mutable methods.

use alloy_sol_macro_expander::{
    ReturnInfo, SolCallData, SolInterfaceData, SolInterfaceKind, expand_from_into_tuples_simple,
    expand_sol_interface, expand_tokenize_simple, selector,
};
use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};


use crate::utils::SolType;

use super::parser::{InterfaceDef, MethodDef};
use super::registry::TypeRegistry;

/// Generate code for the Interface trait.
pub(super) fn generate_interface(
    def: &InterfaceDef,
    registry: &TypeRegistry,
) -> syn::Result<TokenStream> {
    let method_impls: syn::Result<Vec<TokenStream>> = def
        .methods
        .iter()
        .map(|m| generate_method_code(m, registry))
        .collect();
    let method_impls = method_impls?;

    let calls_enum = generate_calls_enum(&def.methods, registry)?;

    let transformed_trait = generate_transformed_trait(def);

    Ok(quote! {
        #transformed_trait
        #(#method_impls)*
        #calls_enum
    })
}

/// Generate the transformed trait with msg_sender injection.
fn generate_transformed_trait(def: &InterfaceDef) -> TokenStream {
    let trait_name = &def.name;
    let vis = &def.vis;
    let attrs = &def.attrs;

    let methods: Vec<TokenStream> = def
        .methods
        .iter()
        .map(|m| {
            let name = &m.name;
            let params: Vec<TokenStream> = m
                .params
                .iter()
                .map(|(n, ty)| quote! { #n: #ty })
                .collect();

            let return_type = if let Some(ref ty) = m.return_type {
                quote! { -> Result<#ty> }
            } else {
                quote! { -> Result<()> }
            };

            if m.is_mutable {
                quote! {
                    fn #name(&mut self, msg_sender: Address, #(#params),*) #return_type;
                }
            } else {
                quote! {
                    fn #name(&self, #(#params),*) #return_type;
                }
            }
        })
        .collect();

    quote! {
        #(#attrs)*
        #vis trait #trait_name {
            #(#methods)*
        }
    }
}

/// Generate code for a single method.
fn generate_method_code(method: &MethodDef, registry: &TypeRegistry) -> syn::Result<TokenStream> {
    let call_name = format_ident!("{}Call", method.sol_name);
    let return_name = format_ident!("{}Return", method.sol_name);

    let param_names: Vec<Ident> = method.params.iter().map(|(n, _)| n.clone()).collect();
    let param_types: Vec<TokenStream> = method
        .params
        .iter()
        .map(|(_, ty)| quote! { #ty })
        .collect();

    let param_sol_types: syn::Result<Vec<TokenStream>> = method
        .params
        .iter()
        .map(|(_, ty)| Ok(SolType::from_syn(ty)?.to_sol_data()))
        .collect();
    let param_sol_types = param_sol_types?;

    let signature = registry.compute_signature(
        &method.sol_name,
        &method.params.iter().map(|(_, ty)| ty.clone()).collect::<Vec<_>>(),
    )?;

    let sel = selector(&signature);
    let doc = format!(
        "Function with signature `{}` and selector `0x{}`.",
        signature,
        hex::encode(sel)
    );

    let call_struct = if method.params.is_empty() {
        quote! {
            #[doc = #doc]
            #[derive(Clone, Debug, PartialEq, Eq)]
            pub struct #call_name;
        }
    } else {
        let names = &param_names;
        let types: Vec<_> = method.params.iter().map(|(_, ty)| ty).collect();
        quote! {
            #[doc = #doc]
            #[derive(Clone, Debug, PartialEq, Eq)]
            pub struct #call_name {
                #(pub #names: #types),*
            }
        }
    };

    let (return_struct, return_from_tuple, return_sol_tuple, return_info) =
        if let Some(ref ret_ty) = method.return_type {
            let ret_sol = SolType::from_syn(ret_ty)?.to_sol_data();
            let field_name = format_ident!("_0");
            let return_field_names = vec![field_name.clone()];
            let return_field_types = vec![quote! { #ret_ty }];
            (
                quote! {
                    #[derive(Clone, Debug, PartialEq, Eq)]
                    pub struct #return_name {
                        pub _0: #ret_ty,
                    }
                },
                expand_from_into_tuples_simple(
                    &return_name,
                    &return_field_names,
                    &return_field_types,
                ),
                quote! { (#ret_sol,) },
                ReturnInfo::Single {
                    sol_type: ret_sol,
                    rust_type: quote! { #ret_ty },
                    field_name,
                    return_name: return_name.clone(),
                },
            )
        } else {
            (
                quote! {
                    #[derive(Clone, Debug, PartialEq, Eq)]
                    pub struct #return_name;
                },
                expand_from_into_tuples_simple(&return_name, &[], &[]),
                quote! { () },
                ReturnInfo::Empty {
                    return_name: return_name.clone(),
                },
            )
        };

    let param_tuple = if param_sol_types.is_empty() {
        quote! { () }
    } else {
        quote! { (#(#param_sol_types,)*) }
    };

    let from_tuple = expand_from_into_tuples_simple(&call_name, &param_names, &param_types);
    let tokenize_impl = expand_tokenize_simple(&param_names, &param_sol_types);

    let sol_call_data = SolCallData {
        param_tuple,
        return_tuple: return_sol_tuple,
        tokenize_impl,
        return_info,
    };
    let sol_call_impl = sol_call_data.expand(&call_name, &signature);

    Ok(quote! {
        #call_struct
        #return_struct
        #from_tuple
        #return_from_tuple
        #sol_call_impl
    })
}

/// Generate the container enum for all calls.
fn generate_calls_enum(
    methods: &[MethodDef],
    registry: &TypeRegistry,
) -> syn::Result<TokenStream> {
    let variants: Vec<Ident> = methods
        .iter()
        .map(|m| format_ident!("{}", m.sol_name))
        .collect();
    let types: Vec<Ident> = methods
        .iter()
        .map(|m| format_ident!("{}Call", m.sol_name))
        .collect();

    let signatures: syn::Result<Vec<String>> = methods
        .iter()
        .map(|m| {
            registry.compute_signature(
                &m.sol_name,
                &m.params.iter().map(|(_, ty)| ty.clone()).collect::<Vec<_>>(),
            )
        })
        .collect();
    let signatures = signatures?;

    let data = SolInterfaceData {
        name: format_ident!("InterfaceCalls"),
        variants,
        types,
        selectors: signatures.iter().map(|s| selector(s)).collect(),
        min_data_len: methods
            .iter()
            .map(|m| m.params.len() * 32)
            .min()
            .unwrap_or(0),
        signatures,
        kind: SolInterfaceKind::Call,
    };

    Ok(expand_sol_interface(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solidity::parser::{InterfaceDef, MethodDef, SolidityModule};
    use proc_macro2::Span;
    use quote::format_ident;
    use syn::{parse_quote, Visibility};

    fn make_method(
        name: &str,
        sol_name: &str,
        params: Vec<(Ident, syn::Type)>,
        return_type: Option<syn::Type>,
        is_mutable: bool,
    ) -> MethodDef {
        MethodDef {
            name: format_ident!("{}", name),
            sol_name: sol_name.to_string(),
            params,
            return_type,
            is_mutable,
        }
    }

    fn make_interface(methods: Vec<MethodDef>) -> InterfaceDef {
        InterfaceDef {
            name: format_ident!("Interface"),
            methods,
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
    fn test_generate_interface() -> syn::Result<()> {
        let module = empty_module();
        let registry = TypeRegistry::from_module(&module)?;

        let def = make_interface(vec![
            make_method(
                "balance_of",
                "balanceOf",
                vec![(format_ident!("account"), parse_quote!(Address))],
                Some(parse_quote!(U256)),
                false,
            ),
            make_method(
                "transfer",
                "transfer",
                vec![
                    (format_ident!("to"), parse_quote!(Address)),
                    (format_ident!("amount"), parse_quote!(U256)),
                ],
                None,
                true,
            ),
        ]);

        let tokens = generate_interface(&def, &registry)?;
        let code = tokens.to_string();

        assert!(code.contains("trait Interface"));
        assert!(code.contains("struct balanceOfCall"));
        assert!(code.contains("struct transferCall"));
        assert!(code.contains("enum InterfaceCalls"));
        assert!(code.contains("msg_sender : Address"));

        Ok(())
    }

    #[test]
    fn test_generate_transformed_trait() {
        let def = make_interface(vec![
            make_method(
                "view_method",
                "viewMethod",
                vec![(format_ident!("x"), syn::parse_quote!(U256))],
                Some(syn::parse_quote!(bool)),
                false,
            ),
            make_method(
                "mutate_method",
                "mutateMethod",
                vec![(format_ident!("y"), syn::parse_quote!(U256))],
                None,
                true,
            ),
        ]);

        let tokens = generate_transformed_trait(&def);
        let code = tokens.to_string();

        assert!(code.contains("fn view_method (& self"));
        assert!(code.contains("fn mutate_method (& mut self , msg_sender : Address"));
    }
}
