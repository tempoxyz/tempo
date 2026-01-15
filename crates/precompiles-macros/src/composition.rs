//! ABI type aliasing and Precompile implementation for `#[contract(abi)]`.
//!
//! When a contract specifies `#[contract(abi)]`, this generates:
//! - Type aliases from the `abi` module's types to contract-prefixed names
//! - Implementation of `IConstants` trait
//!
//! When `#[contract(abi, dispatch)]` is specified, additionally generates:
//! - Implementation of `Dispatch` trait
//! - Implementation of `Precompile` trait (with initialization check for dynamic precompiles)

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::Ident;

/// Generate type aliases and trait implementations for the `abi` module.
///
/// For `#[contract(abi)]` on `struct MyContract`, generates:
/// - `pub type MyContractCalls = abi::Calls;`
/// - `pub type MyContractError = abi::Error;`
/// - `pub type MyContractEvent = abi::Event;`
/// - `impl abi::IConstants for MyContract {}`
///
/// For `#[contract(abi, dispatch)]`, additionally generates:
/// - `impl abi::Dispatch for MyContract {}`
/// - `impl crate::Precompile for MyContract { ... }`
///
/// # Arguments
/// * `struct_name` - The name of the contract struct
/// * `dispatch` - If true, generate `Dispatch` and `Precompile` impls
/// * `is_dynamic` - If true (no fixed address), add initialization check before dispatch
pub(crate) fn generate_abi_aliases(
    struct_name: &Ident,
    dispatch: bool,
    is_dynamic: bool,
) -> syn::Result<TokenStream> {
    let calls_alias = format_ident!("{}Calls", struct_name);
    let error_alias = format_ident!("{}Error", struct_name);
    let event_alias = format_ident!("{}Event", struct_name);

    let dispatch_impls = if dispatch {
        // For dynamic precompiles (no fixed address), add initialization check.
        // The abi module must define an `Error::Uninitialized` variant for this to work.
        let init_check = if is_dynamic {
            quote! {
                if !self.is_initialized().unwrap_or(false) {
                    return Ok(::revm::precompile::PrecompileOutput::new_reverted(
                        self.storage.gas_used(),
                        ::alloy::sol_types::SolError::abi_encode(&abi::Uninitialized {}).into(),
                    ));
                }
            }
        } else {
            quote! {}
        };

        quote! {
            impl abi::Dispatch for #struct_name {}

            impl crate::Precompile for #struct_name {
                fn call(
                    &mut self,
                    calldata: &[u8],
                    msg_sender: ::alloy::primitives::Address,
                ) -> ::revm::precompile::PrecompileResult {
                    self.storage
                        .deduct_gas(crate::input_cost(calldata.len()))
                        .map_err(|_| ::revm::precompile::PrecompileError::OutOfGas)?;

                    #init_check

                    abi::precompile_call(self, calldata, msg_sender)
                }
            }
        }
    } else {
        quote! {}
    };

    Ok(quote! {
        /// Unified calls enum for this contract.
        pub type #calls_alias = abi::Calls;

        /// Unified error enum for this contract.
        pub type #error_alias = abi::Error;

        /// Unified event enum for this contract.
        pub type #event_alias = abi::Event;

        impl abi::IConstants for #struct_name {}

        #dispatch_impls
    })
}
