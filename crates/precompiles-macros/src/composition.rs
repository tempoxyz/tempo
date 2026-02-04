//! ABI type aliasing and Precompile implementation for `#[contract(abi)]`.
//!
//! When a contract specifies `#[contract(abi)]` or `#[contract(abi = ModName)]`, this generates:
//! - Type aliases from the ABI module's types to contract-prefixed names
//! - Re-exports of `{abi_mod}::prelude` and `{abi_mod}::traits` submodules
//! - Implementation of `IConstants` trait
//!
//! When `#[contract(abi, dispatch)]` is specified, additionally generates:
//! - Implementation of `Dispatch` trait
//! - Implementation of `Precompile` trait (with initialization check for dynamic precompiles)

use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;
use syn::Ident;

/// Generate type aliases, re-exports, and trait implementations for the ABI module.
///
/// For `#[contract(abi)]` on `struct MyContract`, generates:
/// - `pub type MyContractCalls = abi::Calls;`
/// - `pub type MyContractError = abi::Error;`
/// - `pub type MyContractEvent = abi::Event;`
/// - `pub use abi::prelude;` - Re-export prelude submodule
/// - `pub use abi::traits;` - Re-export traits submodule
/// - `impl abi::IConstants for MyContract {}`
///
/// For `#[contract(abi = IFeeManager)]`, uses `IFeeManager` instead of `abi`.
///
/// For `#[contract(abi, dispatch)]`, additionally generates:
/// - `impl abi::Dispatch for MyContract {}`
/// - `impl crate::Precompile for MyContract { ... }`
///
/// # Arguments
/// * `struct_name` - The name of the contract struct
/// * `abi_mod` - The ABI module name (e.g., `abi` or `IFeeManager`)
/// * `dispatch` - If true, generate `Dispatch` and `Precompile` impls
/// * `is_dynamic` - If true (no fixed address), add initialization check before dispatch
pub(crate) fn generate_abi_aliases(
    struct_name: &Ident,
    abi_mod: &Ident,
    dispatch: bool,
    is_dynamic: bool,
) -> syn::Result<TokenStream> {
    let calls_alias = format_ident!("{}Calls", struct_name);
    let error_alias = format_ident!("{}Error", struct_name);
    let event_alias = format_ident!("{}Event", struct_name);
    let iconstants_name = format_ident!(
        "{}Constants",
        crate::utils::to_pascal_case(&abi_mod.to_string())
    );

    let dispatch_impls = if dispatch {
        // For dynamic precompiles (no fixed address), add initialization check.
        // The abi module must define an `Error::Uninitialized` variant for this to work.
        let init_check = if is_dynamic {
            quote! {
                if !self.is_initialized().unwrap_or(false) {
                    return Ok(::revm::precompile::PrecompileOutput::new_reverted(
                        self.storage.gas_used(),
                        ::alloy::sol_types::SolError::abi_encode(&#abi_mod::Uninitialized {}).into(),
                    ));
                }
            }
        } else {
            quote! {}
        };

        quote! {
            impl #abi_mod::Dispatch for #struct_name {}

            impl crate::dispatch::Precompile for #struct_name {
                fn call(
                    &mut self,
                    calldata: &[u8],
                    msg_sender: ::alloy::primitives::Address,
                ) -> ::revm::precompile::PrecompileResult {
                    use crate::storage::ContractStorage;

                    self.storage
                        .deduct_gas(crate::dispatch::input_cost(calldata.len()))
                        .map_err(|_| ::revm::precompile::PrecompileError::OutOfGas)?;

                    #init_check

                    #abi_mod::precompile_call(self, calldata, msg_sender)
                }
            }
        }
    } else {
        quote! {}
    };

    Ok(quote! {
        /// Unified calls enum for this contract.
        pub type #calls_alias = #abi_mod::Calls;

        /// Unified error enum for this contract.
        pub type #error_alias = #abi_mod::Error;

        /// Unified event enum for this contract.
        pub type #event_alias = #abi_mod::Event;

        /// Re-export prelude for convenient glob imports.
        ///
        /// Usage: `use crate::module::prelude::*;`
        pub use #abi_mod::prelude;

        /// Re-export traits for selective trait imports.
        ///
        /// Usage: `use crate::module::traits::*;`
        pub use #abi_mod::traits;

        #[cfg(feature = "rpc")]
        pub use #abi_mod::new;

        impl #abi_mod::#iconstants_name for #struct_name {}

        #dispatch_impls
    })
}
