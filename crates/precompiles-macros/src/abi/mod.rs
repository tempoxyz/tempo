//! `#[abi]` module attribute macro.
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
//! # Generated Submodules
//!
//! Two submodules are always generated for convenient imports:
//!
//! ## `prelude` - All public types
//!
//! ```ignore
//! use crate::tip20::contracts::prelude::*;
//! ```
//!
//! Includes: all traits, `{Trait}Calls` enums, `Calls`, `Error`, `Event`,
//! structs, unit enums, and constants.
//!
//! ## `traits` - Interface traits and constants (for cross-calling)
//!
//! ```ignore
//! use crate::tip20::contracts::traits::*;
//! ```
//!
//! Includes: `{ModName}Constants`, interface traits (`IToken`, `IRolesAuth`, etc.),
//! and constants. Use this for cross-calling other precompiles.
//!
//! # Example
//!
//! ```ignore
//! #[abi]
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
mod constants;
mod dispatch;
mod enums;
mod interface;
mod parser;
mod registry;
mod structs;

#[cfg(test)]
mod test_utils;

use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};
use syn::ItemMod;

use parser::{ConstantDef, InterfaceDef, SolStructDef, SolidityModule, UnitEnumDef};
use registry::TypeRegistry;

/// Generate the prelude and traits submodules containing re-exports.
///
/// - `prelude` - all public types for glob imports
/// - `traits` - only interface traits for selective imports
fn generate_submodules(
    mod_name: &Ident,
    structs: &[SolStructDef],
    unit_enums: &[UnitEnumDef],
    interfaces: &[InterfaceDef],
    constants: &[ConstantDef],
    has_error: bool,
    has_event: bool,
) -> TokenStream {
    let iconstants_name = format_ident!(
        "{}Constants",
        crate::utils::to_pascal_case(&mod_name.to_string())
    );
    // Collect trait names
    let trait_names: Vec<&Ident> = interfaces.iter().map(|i| &i.name).collect();
    // Collect {TraitName}Calls enum names
    let trait_calls_names: Vec<Ident> = interfaces
        .iter()
        .map(|i| format_ident!("{}Calls", i.name))
        .collect();

    // Collect struct names
    let struct_names: Vec<&Ident> = structs.iter().map(|s| &s.name).collect();

    // Collect unit enum names
    let unit_enum_names: Vec<&Ident> = unit_enums.iter().map(|e| &e.name).collect();

    // Collect constant names
    let constant_names: Vec<&Ident> = constants.iter().map(|c| &c.name).collect();

    // Build re-export statements
    // Trait re-exports are gated by cfg since traits are only generated with precompile feature
    let trait_reexports = if trait_names.is_empty() {
        quote! {}
    } else {
        quote! {
            #[cfg(feature = "precompiles")]
            pub use super::{#(#trait_names),*};
        }
    };

    // Build trait re-exports for the `traits` module with renamed `Interface` -> `{ModName}Interface`
    let traits_mod_reexports: Vec<TokenStream> = interfaces
        .iter()
        .map(|i| {
            let name = &i.name;
            if name == "Interface" {
                let renamed = format_ident!("{}Interface", mod_name);
                quote! { pub use super::#name as #renamed; }
            } else {
                quote! { pub use super::#name; }
            }
        })
        .collect();
    let traits_mod_trait_reexports = if traits_mod_reexports.is_empty() {
        quote! {}
    } else {
        quote! {
            #[cfg(feature = "precompiles")]
            #(#traits_mod_reexports)*
        }
    };
    let trait_calls_reexports = if trait_calls_names.is_empty() {
        quote! {}
    } else {
        quote! { pub use super::{#(#trait_calls_names),*}; }
    };

    let struct_reexports = if struct_names.is_empty() {
        quote! {}
    } else {
        quote! { pub use super::{#(#struct_names),*}; }
    };

    let unit_enum_reexports = if unit_enum_names.is_empty() {
        quote! {}
    } else {
        quote! { pub use super::{#(#unit_enum_names),*}; }
    };

    let constant_reexports = if constant_names.is_empty() {
        quote! {}
    } else {
        quote! { pub use super::{#(#constant_names),*}; }
    };

    let error_reexport = if has_error {
        quote! { pub use super::Error; }
    } else {
        quote! {}
    };

    let event_reexport = if has_event {
        quote! { pub use super::Event; }
    } else {
        quote! {}
    };

    // {ModName}Constants re-export is gated by cfg
    let iconstants_reexport = quote! {
        #[cfg(feature = "precompiles")]
        pub use super::#iconstants_name;
    };

    // Traits module is gated by cfg
    let traits_mod = quote! {
        #[cfg(feature = "precompiles")]
        /// Traits module for cross-calling other precompiles.
        ///
        /// Import interface traits and constants:
        /// ```ignore
        /// use crate::module::contracts::traits::*;
        /// ```
        ///
        /// For implementing a contract (when you need Error, Event, structs),
        /// use `prelude::*` instead.
        pub mod traits {
            // {ModName}Constants trait (always present)
            pub use super::#iconstants_name;

            // Interface traits (renamed: Interface -> {ModName}Interface)
            #traits_mod_trait_reexports

            // Constants
            #constant_reexports
        }
    };

    quote! {
        #traits_mod

        /// Prelude module for convenient glob imports.
        ///
        /// Import all public types with:
        /// ```ignore
        /// use crate::module::contracts::prelude::*;
        /// ```
        pub mod prelude {
            // Unified Calls enum (always present)
            pub use super::Calls;

            // {ModName}Constants trait (when traits are enabled)
            #iconstants_reexport

            // Interface traits
            #trait_reexports

            // {TraitName}Calls enums
            #trait_calls_reexports

            // Structs
            #struct_reexports

            // Unit enums
            #unit_enum_reexports

            // Constants
            #constant_reexports

            // Error type (if defined)
            #error_reexport

            // Event type (if defined)
            #event_reexport
        }
    }
}

/// Generate getter metadata macro that passes getter field names to `#[contract]` for impl
/// generation. Always emitted (even with an empty list) so `#[contract]` can unconditionally
/// reference `abi_mod::__abi_getter_fields!`. Uses module-scoped `macro_rules!` with
/// `pub(crate) use` re-export instead of `#[macro_export]` to avoid Rust issue #52234.
fn generate_getter_metadata(_mod_name: &Ident, interfaces: &[InterfaceDef]) -> TokenStream {
    let mut seen = std::collections::HashSet::new();
    let getter_fields: Vec<Ident> = interfaces
        .iter()
        .flat_map(|def| def.methods.iter().filter_map(|m| m.resolved_getter_field()))
        .filter(|f| seen.insert(f.to_string()))
        .cloned()
        .collect();

    quote! {
        #[cfg(feature = "precompiles")]
        #[doc(hidden)]
        #[allow(unused_macros)]
        macro_rules! __abi_getter_fields {
            ($mac:ident) => {
                $mac!([#(#getter_fields),*]);
            };
        }

        #[cfg(feature = "precompiles")]
        #[doc(hidden)]
        pub(crate) use __abi_getter_fields;
    }
}

/// Main expansion entry point for `#[abi]` attribute macro.
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

    // Generate __Getters trait (collects all getter methods across interfaces)
    let getters_trait = interface::generate_getters_trait(&module.interfaces);

    // Generate Interface traits and their Calls enums
    // Traits are wrapped in #[cfg(feature = "precompiles")] by generate_interface
    let interface_impls = module
        .interfaces
        .iter()
        .map(|def| interface::generate_interface(def, &registry))
        .collect::<syn::Result<Vec<_>>>()?;

    // Generate {ModName}Constants trait
    let constants_trait = constants::generate_trait(mod_name, &module.constants);

    // Generate constants definitions, call structs, and calls enum (only if constants exist)
    let constants_impl = constants::generate_constants(&module.constants, &registry)?;
    let has_constants = !module.constants.is_empty();

    // Generate unified Calls enum that composes all interface Calls and constants
    let unified_calls = interface::generate_unified_calls(&module.interfaces, has_constants);

    // Generate getter metadata macro for #[contract] to consume
    let getter_metadata = generate_getter_metadata(mod_name, &module.interfaces);

    // Generate the Dispatch trait for routing calls to methods
    // This requires revm types and dispatch helpers from tempo_precompiles
    // Gated by #[cfg(all(feature = "precompiles", feature = "dispatch"))] in the generated code
    let dispatch_trait =
        dispatch::generate_dispatch_trait(mod_name, &module.interfaces, &module.constants);

    // Generate instance impl aggregating ALL interface traits
    // Wrapped in cfg(feature = "rpc") as it depends on alloy_contract
    // We use a private cfg-gated module to wrap all items generated by ContractCodegen
    let instance_impl = if module.interfaces.is_empty() && module.constants.is_empty() {
        None
    } else {
        // Extract event names for filter generation
        let events: Vec<alloy_sol_macro_expander::ContractEventInfo> = module
            .event
            .as_ref()
            .map(|e| {
                e.variants
                    .iter()
                    .map(|v| alloy_sol_macro_expander::ContractEventInfo {
                        event_name: v.name.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let pascal_name = crate::utils::to_pascal_case(&module.name.to_string());
        let pascal_ident = format_ident!("{}", pascal_name);
        let instance_name = format_ident!("{}Instance", pascal_name);
        let inner = interface::generate_instance(
            &pascal_ident,
            &module.interfaces,
            &module.constants,
            events,
        )?;
        Some(quote! {
            #[cfg(feature = "rpc")]
            mod __instance_impl {
                use super::*;
                #inner
            }
            #[cfg(feature = "rpc")]
            pub use __instance_impl::{#instance_name, new};
        })
    };

    let other_items: Vec<TokenStream> = module.other_items.iter().map(|i| quote! { #i }).collect();

    // Generate prelude and traits submodules
    let submodules = generate_submodules(
        mod_name,
        &module.structs,
        &module.unit_enums,
        &module.interfaces,
        &module.constants,
        module.error.is_some(),
        module.event.is_some(),
    );

    Ok(quote! {
        #[allow(non_camel_case_types, non_snake_case, clippy::pub_underscore_fields, clippy::style, clippy::empty_structs_with_brackets, clippy::too_many_arguments)]
        #vis mod #mod_name {
            #(#imports)*

            #(#struct_impls)*

            #(#unit_enum_impls)*

            #error_impl

            #event_impl

            #getters_trait

            #getter_metadata

            #(#interface_impls)*

            #constants_trait

            #constants_impl

            #unified_calls

            #dispatch_trait

            #instance_impl

            #(#other_items)*

            #submodules
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
