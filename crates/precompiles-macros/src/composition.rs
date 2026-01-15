//! ABI type aliasing for `#[contract(abi)]`.
//!
//! When a contract specifies `#[contract(abi)]`, this generates type aliases
//! from the `abi` module's types to contract-prefixed names.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::Ident;

/// Generate type aliases for the `abi` module.
///
/// For `#[contract(abi)]` on `struct MyContract`, generates:
/// - `pub type MyContractCalls = abi::Calls;`
/// - `pub type MyContractError = abi::Error;`
/// - `pub type MyContractEvent = abi::Event;`
pub(crate) fn generate_abi_aliases(struct_name: &Ident) -> syn::Result<TokenStream> {
    let calls_alias = format_ident!("{}Calls", struct_name);
    let error_alias = format_ident!("{}Error", struct_name);
    let event_alias = format_ident!("{}Event", struct_name);

    Ok(quote! {
        /// Unified calls enum for this contract.
        pub type #calls_alias = abi::Calls;

        /// Unified error enum for this contract.
        pub type #error_alias = abi::Error;

        /// Unified event enum for this contract.
        pub type #event_alias = abi::Event;

        impl abi::IConstants for #struct_name {}
    })
}
