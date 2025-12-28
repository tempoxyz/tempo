//! Interface trait code generation for the `#[solidity]` module macro.
//!
//! Generates `SolCall` structs for each method and a container `Calls`
//! enum with `SolInterface` implementation.
//!
//! Also transforms the trait to inject `msg_sender: Address` for mutable methods.

use alloy_sol_macro_expander::{
    ReturnInfo, SolCallData, SolInterfaceKind, expand_from_into_tuples_simple,
};
use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};

use crate::utils::SolType;

use super::common;
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
            let params: Vec<TokenStream> =
                m.params.iter().map(|(n, ty)| quote! { #n: #ty }).collect();

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

    let param_names = method.param_names();
    let param_types = method.param_types();
    let param_tys = method.raw_param_types();

    let common::EncodedParams {
        param_tuple,
        tokenize_impl,
    } = common::encode_params(&param_names, &param_tys)?;

    let signature = registry.compute_signature(&method.sol_name, &param_tys)?;

    let doc = common::signature_doc("Function", &signature);

    let call_fields: Vec<_> = method.params.iter().map(|(n, ty)| (n, ty)).collect();
    let call_struct = common::generate_simple_struct(&call_name, &call_fields, &doc);

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

    let from_tuple = expand_from_into_tuples_simple(&call_name, &param_names, &param_types);

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
fn generate_calls_enum(methods: &[MethodDef], registry: &TypeRegistry) -> syn::Result<TokenStream> {
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
        .map(|m| registry.compute_signature(&m.sol_name, &m.raw_param_types()))
        .collect();
    let field_counts: Vec<usize> = methods.iter().map(|m| m.params.len()).collect();

    Ok(common::generate_sol_interface_container(
        "Calls",
        &variants,
        &types,
        &signatures?,
        &field_counts,
        SolInterfaceKind::Call,
    ))
}
