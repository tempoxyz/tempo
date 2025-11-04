//! Procedural macros for generating type-safe EVM storage accessors.
//!
//! This crate provides:
//! - `#[contract]` macro that transforms a storage schema into a fully-functional contract
//! - `#[derive(Storable)]` macro for multi-slot storage structs
//! - `storable_alloy_ints!` macro for generating alloy integer storage implementations
//! - `storable_alloy_bytes!` macro for generating alloy FixedBytes storage implementations
//! - `storable_rust_ints!` macro for generating standard Rust integer storage implementations

mod dispatcher;
mod errors;
mod events;
mod interface;
mod layout;
mod storable;
mod storable_primitives;
mod storable_tests;
mod traits;
mod utils;

use alloy::primitives::U256;
use proc_macro::TokenStream;
use quote::quote;
use std::cell::OnceCell;
use syn::{Data, DeriveInput, Fields, Ident, Type, Visibility, parse_macro_input};

use crate::utils::extract_attributes;

const RESERVED: &[&str] = &["address", "storage", "msg_sender"];

/// Parsed macro attributes for the contract macro.
struct ContractAttrs {
    interface_idents: Vec<Ident>,
}

impl syn::parse::Parse for ContractAttrs {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        if input.is_empty() {
            return Ok(Self {
                interface_idents: Vec::new(),
            });
        }

        let mut interface_idents = Vec::new();
        interface_idents.push(input.parse::<Ident>()?);

        // Parse comma-separated interface identifiers
        while input.peek(syn::Token![,]) {
            input.parse::<syn::Token![,]>()?;
            if !input.is_empty() {
                interface_idents.push(input.parse::<Ident>()?);
            }
        }

        Ok(Self { interface_idents })
    }
}

/// Transforms a storage schema struct into a contract with accessible storage.
///
/// # Input: Storage Layout
///
/// ```ignore
/// #[contract(ITIP20)]
/// pub struct TIP20Token {
///     pub name: String,
///     pub symbol: String,
///     #[slot(3)]
///     total_supply: U256,
///     #[slot(10)]
///     #[map = "balanceOf"]
///     pub balances: Mapping<Address, U256>,
///     #[slot(11)]
///     pub allowances: Mapping<Address, Mapping<Address, U256>>,
/// }
/// ```
///
/// # Output: Contract with accessible storage via getter and setter methods.
///
/// The macro generates:
/// 1. Transformed struct with generic parameters and runtime fields
/// 2. Constructor: `_new(address, storage)`
/// 3. Type-safe (private) getter and setter methods
/// 4. (If interface specified) Trait with default getter impls, to easily interact with the contract.
///
/// # Requirements
///
/// - No duplicate slot assignments
/// - Unique field names, excluding the reserved ones: `address`, `storage`, `msg_sender`.
/// - All field types must implement `Storable`, and mapping keys must implement `StorageKey`.
#[proc_macro_attribute]
pub fn contract(attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let attrs = parse_macro_input!(attr as ContractAttrs);

    match gen_contract_output(input, attrs) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// Main code generation function with optional call trait generation
fn gen_contract_output(
    input: DeriveInput,
    attrs: ContractAttrs,
) -> syn::Result<proc_macro2::TokenStream> {
    let (ident, vis) = (input.ident.clone(), input.vis.clone());
    let fields = parse_fields(input)?;

    let storage_output = gen_contract_storage(&ident, &vis, &fields)?;
    let impl_output = if !attrs.interface_idents.is_empty() {
        gen_contract_impl(&ident, &attrs.interface_idents, &fields)?
    } else {
        quote! {}
    };

    // Combine outputs
    Ok(quote! {
        #storage_output
        #impl_output
    })
}

/// Generates the contract call trait and its dispatcher based on the contract struct and interfaces.
fn gen_contract_impl(
    ident: &Ident,
    interfaces: &[Ident],
    fields: &[FieldInfo],
) -> syn::Result<proc_macro2::TokenStream> {
    // Parse each interface and collect per-interface data
    let interface_data: Vec<_> = interfaces
        .iter()
        .map(|interface_ident| {
            let parsed = interface::parse_interface(interface_ident)?;
            Ok::<_, syn::Error>((interface_ident.clone(), parsed))
        })
        .collect::<syn::Result<_>>()?;

    // Aggregate functions, errors, and events for dispatcher and error generation
    let (all_funcs, all_errors, events) = interface_data.iter().fold(
        (Vec::new(), Vec::new(), Vec::new()),
        |(mut funcs, mut errs, mut events), (interface_ident, parsed)| {
            funcs.extend(parsed.functions.clone());

            if !parsed.errors.is_empty() {
                errs.push((interface_ident.clone(), parsed.errors.clone()));
            }

            events.push(events::gen_event_helpers(
                ident,
                interface_ident,
                &parsed.events,
            ));
            (funcs, errs, events)
        },
    );

    // TODO(rusowsky): Check for selector collisions across all interfaces

    let trait_output = traits::gen_traits_and_impls(ident, &interface_data, fields);
    let dispatcher_output = dispatcher::gen_dispatcher(ident, interfaces, &all_funcs, fields);
    // NOTE: Error helpers are commented out to avoid orphan rule violations when using
    // external interfaces. Error constructors should be defined where the interfaces are defined.
    // let errors = errors::gen_error_helpers(&all_errors);

    Ok(quote! {
        #trait_output
        #dispatcher_output
        #(#events)*
        // #errors
    })
}

/// Information extracted from a field in the storage schema
#[derive(Debug)]
struct FieldInfo {
    name: Ident,
    ty: Type,
    slot: Option<U256>,
    base_slot: Option<U256>,
    slot_count: Option<usize>,
    map: Option<String>,
    /// Lazily computed from `map` and `name`
    effective_name: OnceCell<String>,
}

impl FieldInfo {
    /// Computed lazily on first access from either the `map` attribute or field name.
    pub(crate) fn name(&self) -> &str {
        self.effective_name.get_or_init(|| match self.map.as_ref() {
            Some(name) => name.to_owned(),
            None => self.name.to_string(),
        })
    }
}

/// Classification of a field based on its type
#[derive(Debug)]
enum FieldKind<'a> {
    /// Direct value field (single-slot type).
    Direct,
    /// Single-level mapping (Mapping<K, V>)
    Mapping { key: &'a Type, value: &'a Type },
    /// Nested mapping (Mapping<K1, Mapping<K2, V>>)
    NestedMapping {
        key1: &'a Type,
        key2: &'a Type,
        value: &'a Type,
    },
    /// Multi-slot storage block (custom struct implementing `trait Storable`)
    StorageBlock(&'a Type),
}

fn parse_fields(input: DeriveInput) -> syn::Result<Vec<FieldInfo>> {
    // Ensure no generic parameters on input
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.generics,
            "Contract structs cannot have generic parameters",
        ));
    }

    // Ensure struct with named fields
    let named_fields = if let Data::Struct(data) = input.data
        && let Fields::Named(fields) = data.fields
    {
        fields.named
    } else {
        return Err(syn::Error::new_spanned(
            input.ident,
            "Only structs with named fields are supported",
        ));
    };

    // Parse extract attributes
    named_fields
        .into_iter()
        .map(|field| {
            let name = field
                .ident
                .as_ref()
                .ok_or_else(|| syn::Error::new_spanned(&field, "Fields must have names"))?;

            if RESERVED.contains(&name.to_string().as_str()) {
                return Err(syn::Error::new_spanned(
                    name,
                    format!("Field name '{name}' is reserved"),
                ));
            }

            let (slot, base_slot, slot_count, map) = extract_attributes(&field.attrs)?;
            Ok(FieldInfo {
                name: name.to_owned(),
                ty: field.ty,
                slot,
                base_slot,
                slot_count,
                map,
                effective_name: OnceCell::new(),
            })
        })
        .collect()
}

/// Main code generation function for storage accessors
fn gen_contract_storage(
    ident: &Ident,
    vis: &Visibility,
    fields: &[FieldInfo],
) -> syn::Result<proc_macro2::TokenStream> {
    // Generate the complete output
    let allocated_fields = layout::allocate_slots(fields)?;
    let slot_id_types = layout::gen_slot_id_types(&allocated_fields);
    let slots_module = layout::gen_slots_module(&allocated_fields);
    let transformed_struct = layout::gen_struct(ident, vis);
    let storage_trait = layout::gen_contract_storage_impl(ident);
    let constructor = layout::gen_constructor(ident);
    let methods: Vec<_> = allocated_fields
        .iter()
        .map(|allocated| layout::gen_getters_and_setters(ident, allocated))
        .collect();

    let output = quote! {
        #slot_id_types
        #transformed_struct
        #constructor
        #storage_trait
        #(#methods)*
        #slots_module
    };

    Ok(output)
}

/// Derives the `Storable` trait for structs with named fields.
///
/// This macro generates implementations for loading and storing multi-slot
/// storage structures in EVM storage.
///
/// # Requirements
///
/// - The struct must have named fields (not tuple structs or unit structs)
/// - All fields must implement the `Storable` trait
///
/// # Generated Code
///
/// For each struct field, the macro generates sequential slot offsets.
/// It implements the `Storable` trait methods:
/// - `load` - Loads the struct from storage
/// - `store` - Stores the struct to storage
/// - `delete` - Uses default implementation (sets all slots to zero)
///
/// # Example
///
/// ```ignore
/// use precompiles::storage::Storable;
/// use alloy_primitives::{Address, U256};
///
/// #[derive(Storable)]
/// pub struct RewardStream {
///     pub funder: Address,              // offset 0
///     pub start_time: u64,              // offset 1
///     pub end_time: u64,                // offset 2
///     pub rate_per_second_scaled: U256, // offset 3
///     pub amount_total: U256,           // offset 4
/// }
/// ```
#[proc_macro_derive(Storable)]
pub fn derive_storage_block(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match storable::derive_impl(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

// -- STORAGE IMPLEMENTATIONS --------------------------------------------------------------

/// Generate `StorableType` and `Storable<1>` implementations for all standard integer types.
///
/// Generates implementations for all standard Rust integer types:
/// u8/i8, u16/i16, u32/i32, u64/i64, u128/i128.
///
/// Each type gets:
/// - `StorableType` impl with `BYTE_COUNT` constant
/// - `Storable<1>` impl with `load()`, `store()`, `to_evm_words()`, `from_evm_words()` methods
/// - `StorageKey` impl for use as mapping keys
/// - Auto-generated tests that verify round-trip conversions with random values
///
/// # Usage
/// ```ignore
/// storable_rust_ints!();
/// ```
#[proc_macro]
pub fn storable_rust_ints(_input: TokenStream) -> TokenStream {
    storable_primitives::gen_storable_rust_ints().into()
}

/// Generate `StorableType` and `Storable<1>` implementations for alloy integer types.
///
/// Generates implementations for all alloy integer types (both signed and unsigned):
/// U8/I8, U16/I16, U32/I32, U64/I64, U128/I128, U256/I256.
///
/// Each type gets:
/// - `StorableType` impl with `BYTE_COUNT` constant
/// - `Storable<1>` impl with `load()`, `store()`, `to_evm_words()`, `from_evm_words()` methods
/// - `StorageKey` impl for use as mapping keys
/// - Auto-generated tests that verify round-trip conversions using alloy's `.random()` method
///
/// # Usage
/// ```ignore
/// storable_alloy_ints!();
/// ```
#[proc_macro]
pub fn storable_alloy_ints(_input: TokenStream) -> TokenStream {
    storable_primitives::gen_storable_alloy_ints().into()
}

/// Generate `StorableType` and `Storable<1>` implementations for alloy FixedBytes types.
///
/// Generates implementations for all fixed-size byte arrays from FixedBytes<1> to FixedBytes<32>.
/// All sizes fit within a single storage slot.
///
/// Each type gets:
/// - `StorableType` impl with `BYTE_COUNT` constant
/// - `Storable<1>` impl with `load()`, `store()`, `to_evm_words()`, `from_evm_words()` methods
/// - `StorageKey` impl for use as mapping keys
/// - Auto-generated tests that verify round-trip conversions using alloy's `.random()` method
///
/// # Usage
/// ```ignore
/// storable_alloy_bytes!();
/// ```
#[proc_macro]
pub fn storable_alloy_bytes(_input: TokenStream) -> TokenStream {
    storable_primitives::gen_storable_alloy_bytes().into()
}

/// Generate comprehensive property tests for all storage types.
///
/// This macro generates:
/// - Arbitrary function generators for all Rust and Alloy integer types
/// - Arbitrary function generators for all FixedBytes<N> sizes (1..=32)
/// - Property test invocations using the existing test body macros
#[proc_macro]
pub fn gen_storable_tests(_input: TokenStream) -> TokenStream {
    storable_tests::gen_storable_tests().into()
}
