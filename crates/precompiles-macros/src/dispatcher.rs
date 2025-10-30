//! Dispatcher generation for contract macro.
//!
//! This module generates the `trait Precompile` implementation that routes
//! EVM calldata to trait methods based on function selectors.

use crate::{interface::FunctionKind, traits::GetterFn};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Ident, Type};

/// Generates the `Precompile` implementation for the contract.
pub(crate) fn gen_dispatcher(
    strukt: &Ident,
    _interface_types: &[Type],
    match_results: &[GetterFn<'_>],
) -> TokenStream {
    let trait_name = format_ident!("{}Call", strukt);

    // Generate match arms for each interface function
    let match_arms: Vec<TokenStream> = match_results
        .iter()
        .map(|result| gen_match_arm(&trait_name, result))
        .collect();

    quote! {
        impl<'a, S: crate::storage::PrecompileStorageProvider> crate::Precompile for #strukt<'a, S> {
            fn call(&mut self, calldata: &[u8], msg_sender: ::alloy::primitives::Address) -> ::revm::precompile::PrecompileResult {
                let selector: [u8; 4] = calldata
                    .get(..4)
                    .ok_or_else(|| {
                        ::revm::precompile::PrecompileError::Other(
                            "Invalid input: missing function selector".to_string()
                        )
                    })?
                    .try_into()
                    .map_err(|_| {
                        ::revm::precompile::PrecompileError::Other(
                            "Invalid selector format".to_string()
                        )
                    })?;

                match selector {
                    #(#match_arms)*
                    _ => Err(::revm::precompile::PrecompileError::Other(
                        "Unknown function selector".to_string()
                    )),
                }
            }
        }
    }
}

/// Generates an individual match arm for a function.
fn gen_match_arm(trait_name: &Ident, result: &GetterFn<'_>) -> TokenStream {
    let func = &result.function;
    let call_type = &func.call_type_path;
    let method_name = format_ident!("{}", func.name);

    // Extract parameter field accessors from the call struct
    let param_fields = func.params.iter().map(|(name, _)| {
        let field_name = format_ident!("{}", name);
        quote! { call.#field_name }
    });

    match func.kind() {
        FunctionKind::Metadata => {
            quote! {
                #call_type::SELECTOR => {
                    crate::metadata::<#call_type>(|| #trait_name::#method_name(self))
                }
            }
        }
        FunctionKind::View => {
            let call_expr = if func.params.is_empty() {
                quote! { #trait_name::#method_name(self) }
            } else {
                quote! { #trait_name::#method_name(self, #(#param_fields),*) }
            };
            quote! {
                #call_type::SELECTOR => {
                    crate::view::<#call_type>(calldata, |call| {
                        #call_expr
                    })
                }
            }
        }
        FunctionKind::Mutate => {
            let call_expr = if func.params.is_empty() {
                quote! { #trait_name::#method_name(self, s) }
            } else {
                quote! { #trait_name::#method_name(self, s, #(#param_fields),*) }
            };
            quote! {
                #call_type::SELECTOR => {
                    crate::mutate::<#call_type>(
                        calldata,
                        msg_sender,
                        |s, call| #call_expr
                    )
                }
            }
        }
        FunctionKind::MutateVoid => {
            let call_expr = if func.params.is_empty() {
                quote! { #trait_name::#method_name(self, s) }
            } else {
                quote! { #trait_name::#method_name(self, s, #(#param_fields),*) }
            };
            quote! {
                #call_type::SELECTOR => {
                    crate::mutate_void::<#call_type>(
                        calldata,
                        msg_sender,
                        |s, call| #call_expr
                    )
                }
            }
        }
    }
}
