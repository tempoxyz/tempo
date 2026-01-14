//! ABI type aliasing for `#[contract(abi(module))]`.
//!
//! When a contract specifies an ABI module via `#[contract(abi(module))]`,
//! this generates type aliases from the module's types to contract-prefixed names.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Ident, Path};

/// Generate type aliases for a single ABI module.
///
/// For `#[contract(abi(my_abi))]` on `struct MyContract`, generates:
/// - `pub type MyContractCalls = my_abi::Calls;`
/// - `pub type MyContractError = my_abi::Error;`
/// - `pub type MyContractEvent = my_abi::Event;`
pub(crate) fn generate_abi_aliases(
    struct_name: &Ident,
    module: &Path,
) -> syn::Result<TokenStream> {
    let calls_alias = format_ident!("{}Calls", struct_name);
    let error_alias = format_ident!("{}Error", struct_name);
    let event_alias = format_ident!("{}Event", struct_name);

    Ok(quote! {
        /// Unified calls enum for this contract.
        pub type #calls_alias = #module::Calls;

        /// Unified error enum for this contract.
        pub type #error_alias = #module::Error;

        /// Unified event enum for this contract.
        pub type #event_alias = #module::Event;
    })
}
