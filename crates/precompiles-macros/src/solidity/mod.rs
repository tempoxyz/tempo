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
use quote::quote;
use syn::ItemMod;

use parser::SolidityModule;
use registry::TypeRegistry;

/// Main expansion entry point for `#[solidity]` attribute macro.
///
/// This function:
/// 1. Parses the module into IR
/// 2. Builds a type registry for ABI resolution
/// 3. Generates code for all types with full type knowledge
pub(crate) fn expand(item: ItemMod) -> syn::Result<TokenStream> {
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

    let error_impl = if let Some(ref def) = module.error {
        Some(enums::generate_variant_enum(
            def,
            &registry,
            enums::VariantEnumKind::Error,
        )?)
    } else {
        None
    };

    let event_impl = if let Some(ref def) = module.event {
        Some(enums::generate_variant_enum(
            def,
            &registry,
            enums::VariantEnumKind::Event,
        )?)
    } else {
        None
    };

    let interface_impl = if let Some(ref def) = module.interface {
        Some(interface::generate_interface(def, &registry)?)
    } else {
        None
    };

    let other_items: Vec<TokenStream> = module.other_items.iter().map(|i| quote! { #i }).collect();

    Ok(quote! {
        #[allow(non_camel_case_types, non_snake_case, clippy::pub_underscore_fields, clippy::style, clippy::empty_structs_with_brackets)]
        #vis mod #mod_name {
            #(#imports)*

            #(#struct_impls)*

            #(#unit_enum_impls)*

            #error_impl

            #event_impl

            #interface_impl

            #(#other_items)*
        }
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
