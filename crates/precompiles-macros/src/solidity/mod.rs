//! `#[solidity]` module attribute macro.
//!
//! This module provides a unified macro for defining Solidity-compatible types
//! in a single Rust module, eliminating the need for separate `#[interface]`,
//! `#[error]`, `#[event]`, and `#[derive(SolStruct)]` macros.
//!
//! # Advantages
//!
//! - **Correct selectors**: Struct types are fully resolved before selector computation
//! - **EIP-712 components**: Nested struct dependencies are properly tracked
//! - **Convention over configuration**: Names determine type semantics
//! - **Co-location**: All related types live in one module
//!
//! # Example
//!
//! ```ignore
//! #[solidity]
//! pub mod roles_auth {
//!     use super::*;
//!
//!     #[derive(Clone, Debug)]
//!     pub struct Transfer {
//!         pub from: Address,
//!         pub to: Address,
//!         pub amount: U256,
//!     }
//!
//!     pub enum PolicyType {
//!         Whitelist,
//!         Blacklist,
//!     }
//!
//!     pub enum Error {
//!         Unauthorized,
//!         InsufficientBalance { available: U256, required: U256 },
//!     }
//!
//!     pub enum Event {
//!         RoleMembershipUpdated {
//!             #[indexed] role: B256,
//!             #[indexed] account: Address,
//!             sender: Address,
//!             has_role: bool,
//!         },
//!     }
//!
//!     pub trait Interface {
//!         fn has_role(&self, account: Address, role: B256) -> Result<bool>;
//!         fn grant_role(&mut self, role: B256, account: Address) -> Result<()>;
//!     }
//! }
//! ```

mod common;
mod enums;
mod interface;
mod parser;
mod registry;
mod structs;



#[cfg(test)]
mod test_utils;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::ItemMod;

use crate::{SolidityConfig, utils::to_pascal_case};
use parser::SolidityModule;
use registry::TypeRegistry;

/// Main expansion entry point for `#[solidity]` attribute macro.
pub(crate) fn expand(item: ItemMod, config: SolidityConfig) -> syn::Result<TokenStream> {
    let module = SolidityModule::parse(item)?;
    let registry = TypeRegistry::from_module(&module)?;

    // Check for selector collisions before generating code
    registry.check_selector_collisions(&module)?;

    let mod_name = &module.name;
    let vis = &module.vis;

    let imports: Vec<TokenStream> = module.imports.iter().map(|i| quote! { #i }).collect();

    let struct_impls = module
        .structs
        .iter()
        .map(|def| structs::generate_struct(def, &registry))
        .collect::<syn::Result<Vec<_>>>()?;

    let unit_enum_impls: Vec<TokenStream> = module
        .unit_enums
        .iter()
        .map(enums::generate_unit_enum)
        .collect();

    use common::AbiType;

    // Generate Error enum (user-defined or dummy)
    let error_impl = if let Some(ref def) = module.error {
        enums::generate_variant_enum(def, &registry, AbiType::Error)?
    } else {
        common::generate_dummy_container(AbiType::Error)
    };

    // Generate Event enum (user-defined or dummy)
    let event_impl = if let Some(ref def) = module.event {
        enums::generate_variant_enum(def, &registry, AbiType::Event)?
    } else {
        common::generate_dummy_container(AbiType::Event)
    };

    // Generate Interface traits and their Calls enums
    let interface_impls = module
        .interfaces
        .iter()
        .map(|def| interface::generate_interface(def, &registry))
        .collect::<syn::Result<Vec<_>>>()?;

    // Generate unified Calls enum that composes all interface Calls
    let unified_calls = interface::generate_unified_calls(&module.interfaces);

    // Generate instance impl for first interface (for backward compatibility)
    // TODO: Consider generating instances for all interfaces
    let instance_impl = module
        .interfaces
        .first()
        .map(|def| interface::generate_instance(&module.name, def))
        .transpose()?;

    let other_items: Vec<TokenStream> = module.other_items.iter().map(|i| quote! { #i }).collect();

    let reexports = if config.no_reexport {
        quote! {}
    } else {
        let alias_name = config
            .interface_alias
            .unwrap_or_else(|| format!("I{}", to_pascal_case(&mod_name.to_string())));
        let alias_ident = format_ident!("{}", alias_name);

        quote! {
            #[doc(hidden)]
            #vis use self::#mod_name::*;

            #[allow(non_snake_case)]
            #[doc = concat!("Interface alias for [`", stringify!(#mod_name), "`].")]
            #vis mod #alias_ident {
                #![allow(ambiguous_glob_reexports)]
                pub use super::#mod_name::*;
            }
        }
    };

    Ok(quote! {
        #[allow(non_camel_case_types, non_snake_case, clippy::pub_underscore_fields, clippy::style, clippy::empty_structs_with_brackets)]
        #vis mod #mod_name {
            #(#imports)*

            #(#struct_impls)*

            #(#unit_enum_impls)*

            #error_impl

            #event_impl

            #(#interface_impls)*

            #unified_calls

            #instance_impl

            #(#other_items)*
        }

        #reexports
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_integration() -> syn::Result<()> {
        let item: ItemMod = syn::parse2(quote! {
            pub mod test {
                use super::*;
                pub struct Transfer { pub from: Address, pub to: Address, pub amount: U256 }
                pub enum OrderStatus { Pending, Filled }
                pub enum Error { Unauthorized }
                pub enum Event { Transfer { #[indexed] from: Address, to: Address, amount: U256 } }
                pub trait Interface {
                    fn balance_of(&self, account: Address) -> Result<U256>;
                    fn transfer(&mut self, data: Transfer) -> Result<()>;
                }
            }
        })?;

        let module = SolidityModule::parse(item)?;
        let registry = TypeRegistry::from_module(&module)?;

        assert_eq!(
            registry.resolve_abi(&syn::parse_quote!(Transfer))?,
            "(address,address,uint256)"
        );
        assert!(registry.is_unit_enum(&syn::parse_quote!(OrderStatus)));
        let sig = registry.compute_signature("transfer", &[syn::parse_quote!(Transfer)])?;
        assert_eq!(sig, "transfer((address,address,uint256))");

        Ok(())
    }
}
