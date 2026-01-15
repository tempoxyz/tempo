//! Dispatcher code generation for the `#[abi]` module macro.
//!
//! Generates:
//! - A `Dispatch` trait with a `dispatch` method that routes decoded `Calls` enum
//!   variants to the appropriate trait method implementations.
//! - A `precompile_call` helper function that wraps `dispatch_call` for easy `Precompile` impl.
//!
//! The generated code requires the `tempo_precompiles` crate to be in scope
//! with the dispatch helper functions (`view`, `mutate`, `mutate_void`, `metadata`, `dispatch_call`).

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::parser::{ConstantDef, InterfaceDef, MethodDef};

/// Generate the `Dispatch` trait with routing logic for all interface methods and constants.
///
/// The generated trait:
/// - Requires all interface traits as supertraits
/// - Also requires `IConstants` as a supertrait (for constants access)
/// - Provides a `dispatch` method that matches on `Calls` variants
/// - Uses appropriate helpers based on method type (provided by the implementor's crate)
pub(super) fn generate_dispatch_trait(
    interfaces: &[InterfaceDef],
    constants: &[ConstantDef],
) -> TokenStream {
    if interfaces.is_empty() {
        return quote! {};
    }

    // Build the supertrait bounds (require all interface traits + IConstants)
    let mut trait_bounds: Vec<TokenStream> = interfaces
        .iter()
        .map(|iface| {
            let name = &iface.name;
            quote! { #name }
        })
        .collect();

    // Always add IConstants as a bound (it's always generated, even if empty)
    trait_bounds.push(quote! { IConstants });
    let bounds = quote! { : #(#trait_bounds)+* };
    let match_body = generate_match_body(interfaces, constants);

    quote! {
        /// Dispatcher trait for routing decoded calls to trait method implementations.
        ///
        /// This trait is auto-generated and provides a unified `dispatch` method
        /// that handles all interface methods and constants.
        ///
        /// # Requirements
        ///
        /// This trait requires the `tempo_precompiles` crate to be available, as it depends on:
        /// - `view` - For non-mutable methods with parameters
        /// - `mutate` - For mutable methods returning a value
        /// - `mutate_void` - For mutable methods returning `()`
        /// - `metadata` - For non-mutable methods without parameters
        /// - `revm::precompile::PrecompileResult` - The return type
        pub trait Dispatch #bounds {
            /// Dispatch a decoded call to the appropriate trait method.
            ///
            /// # Arguments
            /// * `call` - The decoded `Calls` enum variant
            /// * `msg_sender` - The caller's address (injected for mutable methods)
            ///
            /// # Returns
            /// A `PrecompileResult` with the ABI-encoded return value.
            fn dispatch(
                &mut self,
                call: Calls,
                msg_sender: ::alloy::primitives::Address,
            ) -> ::revm::precompile::PrecompileResult
            where
                Self: Sized,
            {
                use crate::{metadata, mutate, mutate_void, view};
                #match_body
            }
        }

        /// Helper function to decode calldata and dispatch to the appropriate method.
        ///
        /// This function wraps `dispatch_call` with the `Calls::abi_decode` decoder
        /// and routes to the `Dispatch::dispatch` method.
        pub fn precompile_call<T: Dispatch>(
            this: &mut T,
            calldata: &[u8],
            msg_sender: ::alloy::primitives::Address,
        ) -> ::revm::precompile::PrecompileResult {
            use ::alloy::sol_types::SolInterface as _;
            crate::dispatch_call(calldata, Calls::abi_decode, |call| {
                this.dispatch(call, msg_sender)
            })
        }
    }
}

/// Generate the match body based on the structure of the `Calls` enum.
fn generate_match_body(interfaces: &[InterfaceDef], constants: &[ConstantDef]) -> TokenStream {
    let has_constants = !constants.is_empty();
    let total_sources = interfaces.len() + if has_constants { 1 } else { 0 };

    if total_sources == 0 {
        return quote! {
            match call {}
        };
    }

    // Single source: Calls is a type alias to that source's Calls enum
    if total_sources == 1 {
        if has_constants {
            let arms = generate_constant_arms(constants);
            return quote! {
                match call {
                    #(#arms)*
                }
            };
        } else {
            let iface = &interfaces[0];
            let arms = generate_method_arms_flat(iface);
            return quote! {
                match call {
                    #(#arms)*
                }
            };
        }
    }

    // Multiple sources: Calls is an enum with variants for each source
    let interface_branches: Vec<TokenStream> = interfaces
        .iter()
        .map(|iface| {
            let variant_name = &iface.name;
            let calls_name = format_ident!("{}Calls", iface.name);
            let inner_arms = generate_method_arms_nested(iface, &calls_name);

            quote! {
                Calls::#variant_name(inner) => match inner {
                    #(#inner_arms)*
                }
            }
        })
        .collect();

    let constants_branch = if has_constants {
        let arms = generate_constant_arms_nested(constants);
        quote! {
            Calls::Constants(inner) => match inner {
                #(#arms)*
            }
        }
    } else {
        quote! {}
    };

    quote! {
        match call {
            #(#interface_branches,)*
            #constants_branch
        }
    }
}

/// Generate match arms for methods when Calls is directly aliased to {Interface}Calls.
fn generate_method_arms_flat(iface: &InterfaceDef) -> Vec<TokenStream> {
    let calls_name = format_ident!("{}Calls", iface.name);

    iface
        .methods
        .iter()
        .map(|method| {
            let variant = format_ident!("{}", method.sol_name);
            let dispatch_call = generate_dispatch_call(method);

            quote! {
                #calls_name::#variant(call) => { #dispatch_call }
            }
        })
        .collect()
}

/// Generate match arms for methods when nested inside Calls::{Interface}(inner).
fn generate_method_arms_nested(
    iface: &InterfaceDef,
    calls_name: &proc_macro2::Ident,
) -> Vec<TokenStream> {
    iface
        .methods
        .iter()
        .map(|method| {
            let variant = format_ident!("{}", method.sol_name);
            let dispatch_call = generate_dispatch_call(method);

            quote! {
                #calls_name::#variant(call) => { #dispatch_call }
            }
        })
        .collect()
}

/// Generate the dispatch call for a single method.
fn generate_dispatch_call(method: &MethodDef) -> TokenStream {
    let rust_name = &method.name;
    let param_names: Vec<_> = method.params.iter().map(|(name, _)| name).collect();
    let call_name = format_ident!("{}Call", method.sol_name);

    let is_void = method.return_type.is_none();

    if method.is_mutable {
        // Mutable method: use mutate or mutate_void
        let method_call = if param_names.is_empty() {
            quote! { self.#rust_name(s) }
        } else {
            quote! { self.#rust_name(s, #(c.#param_names),*) }
        };

        if is_void {
            quote! {
                mutate_void(call, msg_sender, |s, c| #method_call)
            }
        } else {
            quote! {
                mutate(call, msg_sender, |s, c| #method_call)
            }
        }
    } else {
        // View method: use view or metadata
        // Methods with no parameters use metadata, others use view
        if param_names.is_empty() {
            // No parameters - use metadata helper
            quote! {
                metadata::<#call_name>(|| self.#rust_name())
            }
        } else {
            // Has parameters - use view helper
            let method_call = quote! { self.#rust_name(#(c.#param_names),*) };
            quote! {
                view(call, |c| #method_call)
            }
        }
    }
}

/// Generate match arms for constants when Calls is directly aliased to ConstantsCalls.
fn generate_constant_arms(constants: &[ConstantDef]) -> Vec<TokenStream> {
    constants
        .iter()
        .map(|c| {
            let sol_name = c.sol_name();
            let variant = format_ident!("{}", sol_name);
            let call_name = format_ident!("{}Call", sol_name);
            let rust_name = &c.name;

            // IConstants methods are infallible, so wrap in Ok()
            quote! {
                ConstantsCalls::#variant(_) => {
                    metadata::<#call_name>(|| Ok(self.#rust_name()))
                }
            }
        })
        .collect()
}

/// Generate match arms for constants when nested inside Calls::Constants(inner).
fn generate_constant_arms_nested(constants: &[ConstantDef]) -> Vec<TokenStream> {
    constants
        .iter()
        .map(|c| {
            let sol_name = c.sol_name();
            let variant = format_ident!("{}", sol_name);
            let call_name = format_ident!("{}Call", sol_name);
            let rust_name = &c.name;

            // IConstants methods are infallible, so wrap in Ok()
            quote! {
                ConstantsCalls::#variant(_) => {
                    metadata::<#call_name>(|| Ok(self.#rust_name()))
                }
            }
        })
        .collect()
}
