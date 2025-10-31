//! Procedural macro for generating type-safe EVM storage accessors.
//!
//! This crate provides the `#[contract]` macro that transforms a storage schema
//! into a fully-functional contract with type-safe getter/setter methods.

mod dispatcher;
mod errors;
mod events;
mod interface;
mod storage;
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
    interface_types: Vec<Type>,
}

impl syn::parse::Parse for ContractAttrs {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        if input.is_empty() {
            return Ok(Self {
                interface_types: Vec::new(),
            });
        }

        let mut interface_types = Vec::new();
        interface_types.push(input.parse::<Type>()?);

        // Parse comma-separated interface types
        while input.peek(syn::Token![,]) {
            input.parse::<syn::Token![,]>()?;
            if !input.is_empty() {
                interface_types.push(input.parse::<Type>()?);
            }
        }

        Ok(Self { interface_types })
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
/// - All field types must implement `StorageType`, and mapping keys must implement `StorageKey`.
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
    let impl_output = if !attrs.interface_types.is_empty() {
        gen_contract_impl(&ident, &attrs.interface_types, &fields)?
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
    interfaces: &[Type],
    fields: &[FieldInfo],
) -> syn::Result<proc_macro2::TokenStream> {
    // Parse each interface and collect per-interface data
    let interface_data: Vec<_> = interfaces
        .iter()
        .map(|interface| {
            let parsed = interface::parse_interface(interface)?;
            Ok::<_, syn::Error>((interface.clone(), parsed))
        })
        .collect::<syn::Result<_>>()?;

    // Aggregate functions, errors, and events for dispatcher and error generation
    let (all_funcs, all_errors, events) = interface_data.iter().fold(
        (Vec::new(), Vec::new(), Vec::new()),
        |(mut funcs, mut errs, mut events), (interface, parsed)| {
            funcs.extend(parsed.functions.clone());

            if !parsed.errors.is_empty() {
                errs.push((interface.clone(), parsed.errors.clone()));
            }

            events.push(events::gen_event_helpers(ident, interface, &parsed.events));
            (funcs, errs, events)
        },
    );

    // TODO(rusowsky): Check for selector collisions across all interfaces

    let trait_output = traits::gen_traits_and_impls(ident, &interface_data, fields);
    let dispatcher_output = dispatcher::gen_dispatcher(ident, interfaces, &all_funcs, fields);
    let errors = errors::gen_error_helpers(&all_errors);

    Ok(quote! {
        #trait_output
        #dispatcher_output
        #(#events)*
        #errors
    })
}

/// Information extracted from a field in the storage schema
#[derive(Debug)]
struct FieldInfo {
    name: Ident,
    ty: Type,
    slot: Option<U256>,
    base_slot: Option<U256>,
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
    /// Direct value field.
    Direct,
    /// Single-level mapping (Mapping<K, V>)
    Mapping { key: &'a Type, value: &'a Type },
    /// Nested mapping (Mapping<K1, Mapping<K2, V>>)
    NestedMapping {
        key1: &'a Type,
        key2: &'a Type,
        value: &'a Type,
    },
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

            let (slot, base_slot, map) = extract_attributes(&field.attrs)?;
            Ok(FieldInfo {
                name: name.to_owned(),
                ty: field.ty,
                slot,
                base_slot,
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
    let allocated_fields = storage::allocate_slots(fields)?;
    let slots_module = storage::gen_slots_module(&allocated_fields);
    let transformed_struct = storage::gen_struct(ident, vis);
    let storage_trait = storage::gen_contract_storage_impl(ident);
    let constructor = storage::gen_constructor(ident);
    let methods: Vec<_> = allocated_fields
        .iter()
        .map(|allocated| storage::gen_getters_and_setters(ident, allocated))
        .collect();

    let output = quote! {
        #transformed_struct
        #constructor
        #storage_trait
        #(#methods)*
        #slots_module
    };

    Ok(output)
}
