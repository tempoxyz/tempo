//! Procedural macros for generating type-safe EVM storage accessors.
//!
//! This crate provides:
//! - `#[contract]` macro that transforms a storage schema into a fully-functional contract
//! - `#[derive(Storable)]` macro for multi-slot storage structs
//! - `storable_alloy_ints!` macro for generating alloy integer storage implementations
//! - `storable_alloy_bytes!` macro for generating alloy FixedBytes storage implementations
//! - `storable_rust_ints!` macro for generating standard Rust integer storage implementations

mod layout;
mod packing;
mod storable;
mod storable_primitives;
mod storable_tests;
mod utils;

use alloy::primitives::U256;
use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Data, DeriveInput, Expr, Fields, Ident, Token, Type, Visibility,
    parse::{ParseStream, Parser},
    parse_macro_input,
    punctuated::Punctuated,
};

use crate::utils::extract_attributes;

const RESERVED: &[&str] = &["address", "storage", "msg_sender"];

/// Transforms a struct that represents a storage layout into a contract with helper methods to
/// easily interact with the EVM storage.
/// Its packing and encoding schemes aim to be an exact representation of the storage model used by Solidity.
///
/// # Input: Storage Layout
///
/// ```ignore
/// #[contract]
/// pub struct TIP20Token {
///     pub name: String,
///     pub symbol: String,
///     total_supply: U256,
///     #[slot(10)]
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
///
/// # Requirements
///
/// - No duplicate slot assignments
/// - Unique field names, excluding the reserved ones: `address`, `storage`, `msg_sender`.
/// - All field types must implement `Storable`, and mapping keys must implement `StorageKey`.
#[proc_macro_attribute]
pub fn contract(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);

    match gen_contract_output(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// Main code generation function with optional call trait generation
fn gen_contract_output(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let (ident, vis) = (input.ident.clone(), input.vis.clone());
    let fields = parse_fields(input)?;

    let storage_output = gen_contract_storage(&ident, &vis, &fields)?;
    Ok(quote! { #storage_output })
}

/// Information extracted from a field in the storage schema
#[derive(Debug)]
struct FieldInfo {
    name: Ident,
    ty: Type,
    slot: Option<U256>,
    base_slot: Option<U256>,
}

/// Classification of a field based on its type
#[derive(Debug, Clone, Copy)]
enum FieldKind<'a> {
    /// Fields with a direct slot allocation, either single or multi (`Slot<V>`).
    Direct(&'a Type),
    /// Mapping fields. Handles all nesting levels via recursive types.
    Mapping { key: &'a Type, value: &'a Type },
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

            let (slot, base_slot) = extract_attributes(&field.attrs)?;
            Ok(FieldInfo {
                name: name.to_owned(),
                ty: field.ty,
                slot,
                base_slot,
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
    let allocated_fields = packing::allocate_slots(fields)?;
    let transformed_struct = layout::gen_struct(ident, vis, &allocated_fields);
    let storage_trait = layout::gen_contract_storage_impl(ident);
    let constructor = layout::gen_constructor(ident, &allocated_fields);
    let slots_module = layout::gen_slots_module(&allocated_fields);

    let output = quote! {
        #slots_module
        #transformed_struct
        #constructor
        #storage_trait
    };

    Ok(output)
}

/// Derives the `Storable` trait for structs with named fields.
///
/// This macro generates implementations for loading and storing multi-slot
/// struct layout in EVM storage.
/// Its packing and encoding schemes aim to be an exact representation of
/// the storage model used by Solidity.
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
///     pub funder: Address,              // rel slot: 0 (20 bytes)
///     pub start_time: u64,              // rel slot: 0 (8 bytes)
///     pub end_time: u64,                // rel slot: 1 (8 bytes)
///     pub rate_per_second_scaled: U256, // rel slot: 2 (32 bytes)
///     pub amount_total: U256,           // rel slot: 3 (32 bytes)
/// }
/// ```
#[proc_macro_derive(Storable, attributes(storable_arrays))]
pub fn derive_storage_block(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match storable::derive_impl(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

// -- STORAGE PRIMITIVES TRAIT IMPLEMENTATIONS -------------------------------------------

/// Generate `StorableType` and `Storable` implementations for all standard integer types.
///
/// Generates implementations for all standard Rust integer types:
/// u8/i8, u16/i16, u32/i32, u64/i64, u128/i128.
///
/// Each type gets:
/// - `StorableType` impl with `BYTE_COUNT` constant
/// - `Storable` impl with `load()`, `store()` methods
/// - `StorageKey` impl for use as mapping keys
/// - Auto-generated tests that verify round-trip conversions with random values
#[proc_macro]
pub fn storable_rust_ints(_input: TokenStream) -> TokenStream {
    storable_primitives::gen_storable_rust_ints().into()
}

/// Generate `StorableType` and `Storable` implementations for alloy integer types.
///
/// Generates implementations for all alloy integer types (both signed and unsigned):
/// U8/I8, U16/I16, U32/I32, U64/I64, U128/I128, U256/I256.
///
/// Each type gets:
/// - `StorableType` impl with `BYTE_COUNT` constant
/// - `Storable` impl with `load()`, `store()` methods
/// - `StorageKey` impl for use as mapping keys
/// - Auto-generated tests that verify round-trip conversions using alloy's `.random()` method
#[proc_macro]
pub fn storable_alloy_ints(_input: TokenStream) -> TokenStream {
    storable_primitives::gen_storable_alloy_ints().into()
}

/// Generate `StorableType` and `Storable` implementations for alloy `FixedBytes<N>` types.
///
/// Generates implementations for all fixed-size byte arrays from `N = 1..32`
/// All sizes fit within a single storage slot.
///
/// Each type gets:
/// - `StorableType` impl with `BYTE_COUNT` constant
/// - `Storable` impl with `load()`, `store()` methods
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
/// - Arbitrary function generators for all `FixedBytes<N>` sizes `N = 1..32`
/// - Property test invocations using the existing test body macros
#[proc_macro]
pub fn gen_storable_tests(_input: TokenStream) -> TokenStream {
    storable_tests::gen_storable_tests().into()
}

/// Generate `Storable` implementations for fixed-size arrays of primitive types.
///
/// Generates implementations for arrays of sizes 1-32 for the following element types:
/// - Rust integers: u8-u128, i8-i128
/// - Alloy integers: U8-U256, I8-I256
/// - Address
/// - FixedBytes<20>, FixedBytes<32>
///
/// Each array gets:
/// - `StorableType` impl with `LAYOUT = Layout::Slot`
/// - `Storable`
#[proc_macro]
pub fn storable_arrays(_input: TokenStream) -> TokenStream {
    storable_primitives::gen_storable_arrays().into()
}

/// Generate `Storable` implementations for nested arrays of small primitive types.
///
/// Generates implementations for nested arrays like `[[u8; 4]; 8]` where:
/// - Inner arrays are small (2, 4, 8, 16 for u8; 2, 4, 8 for u16)
/// - Total slot count ≤ 32
#[proc_macro]
pub fn storable_nested_arrays(_input: TokenStream) -> TokenStream {
    storable_primitives::gen_nested_arrays().into()
}

// -- TEST HELPERS -------------------------------------------------------------

/// Test helper macro for validating slots
#[proc_macro]
pub fn gen_test_fields_layout(input: TokenStream) -> TokenStream {
    let input = proc_macro2::TokenStream::from(input);

    // Parse comma-separated identifiers
    let parser = syn::punctuated::Punctuated::<Ident, syn::Token![,]>::parse_terminated;
    let idents = match parser.parse2(input) {
        Ok(idents) => idents,
        Err(err) => return err.to_compile_error().into(),
    };

    // Generate storage fields
    let field_calls: Vec<_> = idents
        .into_iter()
        .map(|ident| {
            let field_name = ident.to_string();
            let const_name = field_name.to_uppercase();
            let field_name = utils::to_camel_case(&field_name);
            let slot_ident = Ident::new(&const_name, ident.span());
            let offset_ident = Ident::new(&format!("{const_name}_OFFSET"), ident.span());
            let bytes_ident = Ident::new(&format!("{const_name}_BYTES"), ident.span());

            quote! {
                RustStorageField::new(#field_name, slots::#slot_ident, slots::#offset_ident, slots::#bytes_ident)
            }
        })
        .collect();

    // Generate the final vec!
    let output = quote! {
        vec![#(#field_calls),*]
    };

    output.into()
}

/// Test helper macro for validating slots
#[proc_macro]
pub fn gen_test_fields_struct(input: TokenStream) -> TokenStream {
    let input = proc_macro2::TokenStream::from(input);

    // Parse comma-separated identifiers
    let parser = |input: ParseStream<'_>| {
        let base_slot: Expr = input.parse()?;
        input.parse::<Token![,]>()?;
        let fields = Punctuated::<Ident, Token![,]>::parse_terminated(input)?;
        Ok((base_slot, fields))
    };

    let (base_slot, idents) = match Parser::parse2(parser, input) {
        Ok(result) => result,
        Err(err) => return err.to_compile_error().into(),
    };

    // Generate storage fields
    let field_calls: Vec<_> = idents
        .into_iter()
        .map(|ident| {
            let field_name = ident.to_string();
            let const_name = field_name.to_uppercase();
            let field_name = utils::to_camel_case(&field_name);
            let slot_ident = Ident::new(&const_name, ident.span());
            let offset_ident = Ident::new(&format!("{const_name}_OFFSET"), ident.span());
            let loc_ident = Ident::new(&format!("{const_name}_LOC"), ident.span());
            let bytes_ident = quote! {#loc_ident.size};

            quote! {
                RustStorageField::new(#field_name, #base_slot + #slot_ident, #offset_ident, #bytes_ident)
            }
        })
        .collect();

    // Generate the final vec!
    let output = quote! {
        vec![#(#field_calls),*]
    };

    output.into()
}
