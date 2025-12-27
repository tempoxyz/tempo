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

mod error_gen;
mod event_gen;
mod interface_gen;
mod parser;
mod registry;
mod selector;
mod struct_gen;
mod unit_enum_gen;

use proc_macro2::TokenStream;
use quote::quote;
use syn::ItemMod;

use parser::parse_solidity_module;
use registry::TypeRegistry;

/// Main expansion entry point for `#[solidity]` attribute macro.
///
/// This function:
/// 1. Parses the module into IR
/// 2. Builds a type registry for ABI resolution
/// 3. Generates code for all types with full type knowledge
pub(crate) fn expand(item: ItemMod) -> syn::Result<TokenStream> {
    let module = parse_solidity_module(item)?;
    let registry = TypeRegistry::from_module(&module)?;

    let mod_name = &module.name;
    let vis = &module.vis;

    let imports: Vec<TokenStream> = module.imports.iter().map(|i| quote! { #i }).collect();

    let struct_impls: syn::Result<Vec<TokenStream>> = module
        .structs
        .iter()
        .map(|def| struct_gen::generate_struct(def, &registry))
        .collect();
    let struct_impls = struct_impls?;

    let unit_enum_impls: Vec<TokenStream> = module
        .unit_enums
        .iter()
        .map(unit_enum_gen::generate_unit_enum)
        .collect();

    let error_impl = if let Some(ref def) = module.error {
        Some(error_gen::generate_error_enum(def, &registry)?)
    } else {
        None
    };

    let event_impl = if let Some(ref def) = module.event {
        Some(event_gen::generate_event_enum(def, &registry)?)
    } else {
        None
    };

    let interface_impl = if let Some(ref def) = module.interface {
        Some(interface_gen::generate_interface(def, &registry)?)
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
    fn test_parse_and_build_registry() {
        let item: ItemMod = syn::parse2(quote! {
            pub mod test {
                use super::*;

                #[derive(Clone, Debug)]
                pub struct Transfer {
                    pub from: Address,
                    pub to: Address,
                    pub amount: U256,
                }

                pub enum OrderStatus {
                    Pending,
                    Filled,
                }

                pub enum Error {
                    Unauthorized,
                }

                pub enum Event {
                    Transfer {
                        #[indexed]
                        from: Address,
                        to: Address,
                        amount: U256,
                    },
                }

                pub trait Interface {
                    fn balance_of(&self, account: Address) -> Result<U256>;
                    fn transfer(&mut self, data: Transfer) -> Result<()>;
                }
            }
        })
        .unwrap();

        let module = parse_solidity_module(item).unwrap();
        let registry = TypeRegistry::from_module(&module).unwrap();

        assert_eq!(
            registry.get_struct_abi("Transfer"),
            Some("(address,address,uint256)")
        );

        assert!(registry.is_unit_enum(&syn::parse_quote!(OrderStatus)));

        let sig = registry
            .compute_signature("transfer", &[syn::parse_quote!(Transfer)])
            .unwrap();
        assert_eq!(sig, "transfer((address,address,uint256))");
    }

    #[test]
    fn test_interface_with_struct_param() {
        let item: ItemMod = syn::parse2(quote! {
            pub mod test {
                pub struct Data {
                    pub value: U256,
                }

                pub trait Interface {
                    fn process(&mut self, data: Data) -> Result<()>;
                }
            }
        })
        .unwrap();

        let module = parse_solidity_module(item).unwrap();
        let registry = TypeRegistry::from_module(&module).unwrap();

        let interface = module.interface.as_ref().unwrap();
        let method = &interface.methods[0];

        let param_types: Vec<_> = method.params.iter().map(|(_, ty)| ty.clone()).collect();
        assert!(registry.has_struct_params(&param_types));

        let sig = registry
            .compute_signature(&method.sol_name, &param_types)
            .unwrap();
        assert_eq!(sig, "process((uint256))");
    }

    #[test]
    fn test_expand_full_module() {
        let item: ItemMod = syn::parse2(quote! {
            pub mod example {
                use super::*;

                pub struct Transfer {
                    pub from: Address,
                    pub to: Address,
                    pub amount: U256,
                }

                pub enum OrderStatus {
                    Pending,
                    Filled,
                }

                pub enum Error {
                    Unauthorized,
                    InsufficientBalance { available: U256, required: U256 },
                }

                pub enum Event {
                    Transfer {
                        #[indexed]
                        from: Address,
                        #[indexed]
                        to: Address,
                        amount: U256,
                    },
                }

                pub trait Interface {
                    fn balance_of(&self, account: Address) -> Result<U256>;
                    fn transfer(&mut self, to: Address, amount: U256) -> Result<()>;
                }
            }
        })
        .unwrap();

        let result = expand(item);
        assert!(result.is_ok(), "expand failed: {:?}", result.err());

        let tokens = result.unwrap();
        let code = tokens.to_string();

        assert!(code.contains("mod example"));
        assert!(code.contains("struct Transfer"));
        assert!(code.contains("enum OrderStatus"));
        assert!(code.contains("enum Error"));
        assert!(code.contains("enum Event"));
        assert!(code.contains("trait Interface"));
        assert!(code.contains("balanceOfCall"));
        assert!(code.contains("transferCall"));
    }

    #[test]
    fn test_expand_empty_module() {
        let item: ItemMod = syn::parse2(quote! {
            pub mod empty {
                use super::*;
            }
        })
        .unwrap();

        let result = expand(item);
        assert!(result.is_ok());
    }

    #[test]
    fn test_expand_structs_only() {
        let item: ItemMod = syn::parse2(quote! {
            pub mod structs_only {
                pub struct Inner {
                    pub value: U256,
                }

                pub struct Outer {
                    pub inner: Inner,
                    pub extra: Address,
                }
            }
        })
        .unwrap();

        let result = expand(item);
        assert!(result.is_ok());

        let code = result.unwrap().to_string();
        assert!(code.contains("struct Inner"));
        assert!(code.contains("struct Outer"));
        assert!(code.contains("SolTupleSignature"));
    }
}
