//! Interface trait code generation for the `#[solidity]` module macro.
//!
//! Generates `SolCall` structs for each method and a container `Calls`
//! enum with `SolInterface` implementation.
//!
//! Also transforms the trait to inject `msg_sender: Address` for mutable methods.

use alloy_sol_macro_expander::{
    CallCodegen, ReturnInfo, SolInterfaceKind, StructLayout, gen_from_into_tuple,
};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::{
    common::{self, SynSolType},
    parser::{FieldAccessors, InterfaceDef, MethodDef},
    registry::TypeRegistry,
};

/// Generate code for the Interface trait.
pub(super) fn generate_interface(
    def: &InterfaceDef,
    registry: &TypeRegistry,
) -> syn::Result<TokenStream> {
    let method_impls = def
        .methods
        .iter()
        .map(|m| generate_method_code(m, registry))
        .collect::<syn::Result<Vec<_>>>()?;

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
    let trait_name = format_ident!("Interface");
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

    let param_names = method.field_names();
    let param_rust_types = method.field_types();
    let param_raw_types = method.field_raw_types();
    let param_sol_types = common::types_to_sol_types(&param_raw_types)?;

    let common::EncodedParams {
        param_tuple: call_tuple,
        tokenize_impl,
    } = common::encode_params(&param_names, &param_raw_types)?;

    let signature = registry.compute_signature(&method.sol_name, &param_raw_types)?;

    let doc = common::signature_doc(
        "Function",
        &signature,
        false,
        method.solidity_decl("function"),
    );

    let call_fields: Vec<_> = method.fields().collect();
    let call_struct = common::generate_simple_struct(&call_name, &call_fields, &doc);

    let (return_struct, return_from_tuple, return_sol_tuple, return_info) =
        if let Some(ref ret_ty) = method.return_type {
            let ret_sol = SynSolType::parse(ret_ty)?.to_sol_data();
            let field_name = format_ident!("_0");
            let return_field_names = vec![field_name.clone()];
            let return_sol_types = vec![ret_sol.clone()];
            let return_rust_types = vec![quote! { #ret_ty }];
            (
                quote! {
                    #[derive(Clone, Debug, PartialEq, Eq)]
                    pub struct #return_name {
                        pub _0: #ret_ty,
                    }
                },
                gen_from_into_tuple(
                    &return_name,
                    &return_field_names,
                    &return_sol_types,
                    &return_rust_types,
                    StructLayout::Named,
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
            // For empty returns, generate _tokenize method required by CallCodegen
            (
                quote! {
                    #[derive(Clone, Debug, PartialEq, Eq)]
                    pub struct #return_name;

                    impl #return_name {
                        #[doc(hidden)]
                        pub fn _tokenize(_: &Self) -> () {
                            ()
                        }
                    }
                },
                gen_from_into_tuple(&return_name, &[], &[], &[], StructLayout::Unit),
                quote! { () },
                ReturnInfo::Empty {
                    return_name: return_name.clone(),
                },
            )
        };

    let call_layout = if param_names.is_empty() {
        StructLayout::Unit
    } else {
        StructLayout::Named
    };
    let call_from_tuple = gen_from_into_tuple(
        &call_name,
        &param_names,
        &param_sol_types,
        &param_rust_types,
        call_layout,
    );

    let sol_call_impl = CallCodegen::new(call_tuple, return_sol_tuple, tokenize_impl, return_info)
        .expand(&call_name, &signature);

    // Wrap trait impls in const blocks to avoid type alias conflicts between calls
    Ok(quote! {
        #call_struct
        #return_struct

        #[allow(non_camel_case_types, non_snake_case, clippy::pub_underscore_fields, clippy::style)]
        const _: () = {
            use alloy_sol_types as alloy_sol_types;
            #call_from_tuple
            #sol_call_impl
        };

        #[allow(non_camel_case_types, non_snake_case, clippy::pub_underscore_fields, clippy::style)]
        const _: () = {
            use alloy_sol_types as alloy_sol_types;
            #return_from_tuple
        };
    })
}

/// Generate the container enum for all calls.
fn generate_calls_enum(methods: &[MethodDef], registry: &TypeRegistry) -> syn::Result<TokenStream> {
    fn vec<T>(capacity: usize) -> Vec<T> {
        Vec::with_capacity(capacity)
    }

    let cap = methods.len();
    let (mut variants, mut types, mut signatures, mut field_counts) =
        (vec(cap), vec(cap), vec(cap), vec(cap));

    for m in methods {
        variants.push(format_ident!("{}", m.sol_name));
        types.push(format_ident!("{}Call", m.sol_name));
        signatures.push(registry.compute_signature(&m.sol_name, &m.field_raw_types())?);
        field_counts.push(m.params.len());
    }

    Ok(common::generate_sol_interface_container(
        "Calls",
        &variants,
        &types,
        &signatures,
        &field_counts,
        SolInterfaceKind::Call,
    ))
}
