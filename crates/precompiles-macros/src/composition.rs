//! ABI type aliasing and Precompile implementation for `#[contract(abi)]`.
//!
//! This module provides:
//! - **Shared composition helpers** for generating unified `Calls` enums with `SolInterface` impls
//! - **Contract-specific code** for type aliases, re-exports, and dispatch impls
//!
//! ## Shared Helpers
//!
//! The [`CallSource`] struct and [`expand_composed_calls`] function are reused by both:
//! - `#[contract(abi = [Mod1, Mod2])]` - composes multiple ABI modules
//! - `#[abi]` macro - composes multiple interface traits within a module
//!
//! ## Contract-Specific Code
//!
//! When a contract specifies `#[contract(abi)]` or `#[contract(abi = ModName)]`, this generates:
//! - Type aliases from the ABI module's types to contract-prefixed names
//! - Re-exports of `{abi_mod}::prelude` and `{abi_mod}::traits` submodules
//! - Implementation of `IConstants` trait
//!
//! When `dispatch` is specified, additionally generates:
//! - Implementation of `Dispatch` trait
//! - Implementation of `Precompile` trait (with initialization check for dynamic precompiles)

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Ident, Path};

/// A source for composing `SolInterface` enums.
///
/// Each source represents one inner Calls enum that will become a variant
/// in the composed unified Calls enum.
pub(crate) struct CallSource {
    /// The variant name in the unified enum (e.g., `FeeManager`, `Interface`)
    pub variant: Ident,
    /// The inner Calls type (e.g., `IFeeManager::Calls` or `InterfaceCalls`)
    pub calls_ty: TokenStream,
}

impl CallSource {
    /// Create a new CallSource.
    pub(crate) fn new(variant: Ident, calls_ty: TokenStream) -> Self {
        Self { variant, calls_ty }
    }
}

/// Configuration for which `sol_types` crate path to use.
pub(crate) enum SolTypesPath {
    /// Use `::alloy_sol_types` (for `#[abi]` macro)
    AlloySolTypes,
    /// Use `::alloy::sol_types` (for `#[contract]` macro)
    Alloy,
}

impl SolTypesPath {
    fn quote_path(&self) -> TokenStream {
        match self {
            Self::AlloySolTypes => quote! { ::alloy_sol_types },
            Self::Alloy => quote! { ::alloy::sol_types },
        }
    }
}

/// Generate a composed `Calls` enum from multiple sources with full `SolInterface` impl.
///
/// This is the core shared logic used by both `#[contract(abi=[...])]` and `#[abi]` macros.
///
/// # Generated Code
///
/// - Enum definition with variants for each source
/// - `SELECTORS` const with compile-time concatenated selectors
/// - `valid_selector()` and `abi_decode()` methods
/// - Full `SolInterface` trait implementation
/// - `From<InnerCalls>` impls for each source
///
/// # Arguments
///
/// * `enum_name` - The name of the unified enum (e.g., `Calls` or `MyContractCalls`)
/// * `sources` - The sources to compose (callers must ensure `len() >= 2`)
/// * `sol_path` - Which sol_types crate path to use
pub(crate) fn expand_composed_calls(
    enum_name: &Ident,
    sources: &[CallSource],
    sol_path: SolTypesPath,
) -> TokenStream {
    debug_assert!(
        sources.len() >= 2,
        "expand_composed_calls requires at least 2 sources"
    );

    let sol = sol_path.quote_path();
    let n = sources.len();

    let decls: Vec<_> = sources
        .iter()
        .map(|s| {
            let v = &s.variant;
            let c = &s.calls_ty;
            quote! { #v(#c) }
        })
        .collect();

    let selectors: Vec<_> = sources
        .iter()
        .map(|s| {
            let c = &s.calls_ty;
            quote! { #c::SELECTORS }
        })
        .collect();

    let counts: Vec<_> = sources
        .iter()
        .map(|s| {
            let c = &s.calls_ty;
            quote! { <#c as #sol::SolInterface>::COUNT }
        })
        .collect();

    let decode: Vec<_> = sources
        .iter()
        .map(|s| {
            let v = &s.variant;
            let c = &s.calls_ty;
            quote! {
                if <#c as #sol::SolInterface>::valid_selector(sel) {
                    return <#c as #sol::SolInterface>::abi_decode(data).map(Self::#v);
                }
            }
        })
        .collect();

    let sel_match: Vec<_> = sources
        .iter()
        .map(|s| {
            let v = &s.variant;
            let c = &s.calls_ty;
            quote! { Self::#v(inner) => <#c as #sol::SolInterface>::selector(inner) }
        })
        .collect();

    let size_match: Vec<_> = sources
        .iter()
        .map(|s| {
            let v = &s.variant;
            let c = &s.calls_ty;
            quote! { Self::#v(inner) => <#c as #sol::SolInterface>::abi_encoded_size(inner) }
        })
        .collect();

    let enc_match: Vec<_> = sources
        .iter()
        .map(|s| {
            let v = &s.variant;
            let c = &s.calls_ty;
            quote! { Self::#v(inner) => <#c as #sol::SolInterface>::abi_encode_raw(inner, out) }
        })
        .collect();

    let from_impls: Vec<_> = sources
        .iter()
        .map(|s| {
            let v = &s.variant;
            let c = &s.calls_ty;
            quote! {
                impl From<#c> for #enum_name {
                    #[inline]
                    fn from(c: #c) -> Self { Self::#v(c) }
                }
            }
        })
        .collect();

    quote! {
        #[derive(Clone, Debug, PartialEq, Eq)]
        #[allow(non_camel_case_types, clippy::large_enum_variant)]
        pub enum #enum_name { #(#decls),* }

        impl #enum_name {
            const fn concat_selectors<const N: usize, const M: usize>(
                a: [&'static [[u8; 4]]; N]
            ) -> [[u8; 4]; M] {
                let mut r = [[0u8; 4]; M];
                let (mut i, mut n_idx) = (0, 0);
                while n_idx < N {
                    let s = a[n_idx];
                    let mut j = 0;
                    while j < s.len() { r[i] = s[j]; i += 1; j += 1; }
                    n_idx += 1;
                }
                r
            }

            /// All function selectors from all composed sources.
            pub const SELECTORS: &'static [[u8; 4]] = &{
                const TOTAL: usize = #(#selectors.len())+*;
                Self::concat_selectors::<#n, TOTAL>([#(#selectors),*])
            };

            /// Check if a selector is valid for any composed source.
            #[inline]
            pub fn valid_selector(s: [u8; 4]) -> bool { Self::SELECTORS.contains(&s) }

            /// Decode calldata, routing to the appropriate source.
            pub fn abi_decode(data: &[u8]) -> #sol::Result<Self> {
                let sel: [u8; 4] = data.get(..4).and_then(|s| s.try_into().ok())
                    .ok_or_else(|| #sol::Error::Other("calldata too short".into()))?;
                #(#decode)*
                Err(#sol::Error::unknown_selector(<Self as #sol::SolInterface>::NAME, sel))
            }
        }

        impl #sol::SolInterface for #enum_name {
            const NAME: &'static str = stringify!(#enum_name);
            const MIN_DATA_LENGTH: usize = 0;
            const COUNT: usize = #(#counts)+*;
            #[inline] fn selector(&self) -> [u8; 4] { match self { #(#sel_match),* } }
            #[inline] fn selector_at(i: usize) -> Option<[u8; 4]> { Self::SELECTORS.get(i).copied() }
            #[inline] fn valid_selector(s: [u8; 4]) -> bool { Self::valid_selector(s) }
            #[inline] fn abi_decode_raw(sel: [u8; 4], data: &[u8]) -> #sol::Result<Self> {
                let mut buf = Vec::with_capacity(4 + data.len()); buf.extend_from_slice(&sel); buf.extend_from_slice(data);
                Self::abi_decode(&buf)
            }
            #[inline] fn abi_decode_raw_validate(sel: [u8; 4], data: &[u8]) -> #sol::Result<Self> { Self::abi_decode_raw(sel, data) }
            #[inline] fn abi_encoded_size(&self) -> usize { match self { #(#size_match),* } }
            #[inline] fn abi_encode_raw(&self, out: &mut Vec<u8>) { match self { #(#enc_match),* } }
        }

        #(#from_impls)*
    }
}

/// Generate the initialization check for dynamic precompiles (those without a fixed address).
///
/// When `is_dynamic` is true, emits a guard that reverts with the given `Uninitialized`
/// SolError type before dispatch if the contract is not yet initialized.
fn init_check_block(is_dynamic: bool, uninit_error_path: TokenStream) -> TokenStream {
    if is_dynamic {
        quote! {
            if !self.is_initialized().unwrap_or(false) {
                return Ok(::revm::precompile::PrecompileOutput::new_reverted(
                    self.storage.gas_used(),
                    ::alloy::sol_types::SolError::abi_encode(&#uninit_error_path {}).into(),
                ));
            }
        }
    } else {
        quote! {}
    }
}

/// Generate type aliases, re-exports, and trait implementations for the ABI module(s).
///
/// Delegates to single-module or multi-module code generation based on the number
/// of ABI modules provided. When `dispatch` is true, additionally generates
/// `Dispatch` and `Precompile` impls (with init check for dynamic precompiles).
pub(crate) fn generate_abi_aliases(
    struct_name: &Ident,
    abi_mods: &[Path],
    dispatch: bool,
    is_dynamic: bool,
) -> syn::Result<TokenStream> {
    if abi_mods.len() == 1 {
        generate_single_module_aliases(struct_name, &abi_mods[0], dispatch, is_dynamic)
    } else {
        generate_multi_module_aliases(struct_name, abi_mods, dispatch, is_dynamic)
    }
}

/// Extract the last segment name from a path for naming purposes.
fn path_last_segment_name(path: &Path) -> String {
    path.segments
        .last()
        .map(|s| s.ident.to_string())
        .unwrap_or_default()
}

/// Generate aliases and impls for a single ABI module.
fn generate_single_module_aliases(
    struct_name: &Ident,
    abi_mod: &Path,
    dispatch: bool,
    is_dynamic: bool,
) -> syn::Result<TokenStream> {
    let calls_alias = format_ident!("{}Calls", struct_name);
    let error_alias = format_ident!("{}Error", struct_name);
    let event_alias = format_ident!("{}Event", struct_name);
    let mod_name = path_last_segment_name(abi_mod);
    let iconstants_name = format_ident!("{}Constants", crate::utils::to_pascal_case(&mod_name));

    let dispatch_impls = if dispatch {
        let init_check = init_check_block(is_dynamic, quote! { #abi_mod::Uninitialized });

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

/// Generate composed Calls enum and dispatch for multiple ABI modules.
fn generate_multi_module_aliases(
    struct_name: &Ident,
    abi_mods: &[Path],
    dispatch: bool,
    is_dynamic: bool,
) -> syn::Result<TokenStream> {
    let calls_alias = format_ident!("{}Calls", struct_name);

    // Generate variant names from module names (e.g., IFeeManager -> FeeManager)
    let variant_names: Vec<Ident> = abi_mods
        .iter()
        .map(|m| {
            let name = path_last_segment_name(m);
            // Strip leading 'I' if present (convention for interface modules)
            let stripped = name.strip_prefix('I').unwrap_or(&name);
            format_ident!("{}", stripped)
        })
        .collect();

    // Build CallSource list for the shared helper
    let sources: Vec<CallSource> = variant_names
        .iter()
        .zip(abi_mods.iter())
        .map(|(v, m)| CallSource::new(v.clone(), quote! { #m::Calls }))
        .collect();

    let composed_calls = expand_composed_calls(&calls_alias, &sources, SolTypesPath::Alloy);

    // IConstants trait names and impls
    let iconstants_impls: Vec<TokenStream> = abi_mods
        .iter()
        .map(|m| {
            let mod_name = path_last_segment_name(m);
            let iconstants_name =
                format_ident!("{}Constants", crate::utils::to_pascal_case(&mod_name));
            quote! { impl #m::#iconstants_name for #struct_name {} }
        })
        .collect();

    // Generate dispatch if requested
    let dispatch_impls = if dispatch {
        generate_multi_module_dispatch(
            struct_name,
            abi_mods,
            &variant_names,
            &calls_alias,
            is_dynamic,
        )
    } else {
        quote! {}
    };

    Ok(quote! {
        #composed_calls

        #(#iconstants_impls)*

        #dispatch_impls
    })
}

/// Generate Dispatch trait and Precompile impl for multiple modules.
fn generate_multi_module_dispatch(
    struct_name: &Ident,
    abi_mods: &[Path],
    variant_names: &[Ident],
    calls_alias: &Ident,
    is_dynamic: bool,
) -> TokenStream {
    let dispatch_arms: Vec<TokenStream> = variant_names
        .iter()
        .zip(abi_mods.iter())
        .map(|(v, m)| {
            quote! {
                #calls_alias::#v(inner) => #m::Dispatch::dispatch(self, inner, msg_sender)
            }
        })
        .collect();

    let first_mod = &abi_mods[0];
    let init_check = init_check_block(is_dynamic, quote! { #first_mod::Uninitialized });

    quote! {
        // Implement each module's Dispatch for the struct
        #(
            #[cfg(feature = "precompiles")]
            impl #abi_mods::Dispatch for #struct_name {}
        )*

        #[cfg(feature = "precompiles")]
        impl crate::dispatch::Precompile for #struct_name {
            fn call(
                &mut self,
                calldata: &[u8],
                msg_sender: ::alloy::primitives::Address,
            ) -> ::revm::precompile::PrecompileResult {
                use ::alloy::sol_types::SolInterface as _;
                use crate::storage::ContractStorage;

                self.storage
                    .deduct_gas(crate::dispatch::input_cost(calldata.len()))
                    .map_err(|_| ::revm::precompile::PrecompileError::OutOfGas)?;

                #init_check

                crate::dispatch::dispatch_call(calldata, #calls_alias::abi_decode, |call| {
                    match call {
                        #(#dispatch_arms,)*
                    }
                })
            }
        }
    }
}
