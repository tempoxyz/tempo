//! Procedural macros for generating type-safe EVM storage accessors.
//!
//! This crate provides:
//! - `#[contract]` macro that transforms a storage schema into a fully-functional contract
//! - `#[derive(Storable)]` macro for multi-slot storage structs
//! - `#[abi]` macro for unified module-level Solidity ABI type generation
//! - `storable_alloy_ints!` macro for generating alloy integer storage implementations
//! - `storable_alloy_bytes!` macro for generating alloy FixedBytes storage implementations
//! - `storable_rust_ints!` macro for generating standard Rust integer storage implementations

mod composition;
mod layout;
mod packing;
mod solidity;
mod storable;
mod storable_primitives;
mod storable_tests;
mod utils;

use alloy::primitives::U256;
use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Data, DeriveInput, Expr, Fields, Ident, Token, Type, Visibility,
    parse::{Parse, ParseStream, Parser},
    parse_macro_input,
    punctuated::Punctuated,
};

use crate::utils::extract_attributes;

/// Configuration parsed from `#[contract(...)]` attribute arguments.
#[derive(Default)]
struct ContractConfig {
    /// Optional address expression for generating `Self::new()` and `Default`.
    address: Option<Expr>,
    /// Whether to link to an `abi` module for ABI types.
    use_abi: bool,
    /// Whether to generate `Dispatch` and `Precompile` impls (requires `abi`).
    dispatch: bool,
}

impl Parse for ContractConfig {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut config = Self::default();

        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            match ident.to_string().as_str() {
                "addr" | "address" => {
                    input.parse::<Token![=]>()?;
                    config.address = Some(input.parse()?);
                }
                "abi" => {
                    if input.peek(syn::token::Paren) {
                        return Err(syn::Error::new(
                            ident.span(),
                            "`abi` attribute does not accept arguments; \
                             define a sibling `#[abi] pub mod abi { ... }` module instead",
                        ));
                    }
                    config.use_abi = true;
                }
                "dispatch" => {
                    config.dispatch = true;
                }
                other => {
                    return Err(syn::Error::new(
                        ident.span(),
                        format!("unknown attribute `{other}`, expected `addr`, `abi`, or `dispatch`"),
                    ));
                }
            }

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(config)
    }
}

const RESERVED: &[&str] = &["address", "storage", "msg_sender"];

/// Transforms a struct that represents a storage layout into a contract with helper methods to
/// easily interact with the EVM storage.
/// Its packing and encoding schemes aim to be an exact representation of the storage model used by Solidity.
///
/// # Attributes
///
/// - `#[contract]` - Basic contract with storage accessors
/// - `#[contract(addr = EXPR)]` - Contract with fixed address (generates `new()` and `Default`)
/// - `#[contract(abi)]` - Link to a sibling `#[abi] pub mod abi { ... }` module (generates type aliases and `IConstants` impl)
/// - `#[contract(abi, dispatch)]` - Same as above plus `Dispatch` and `Precompile` impls (adds initialization check for dynamic precompiles)
///
/// # Storage Layout Example
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
/// # Generated Types
///
/// The macro generates:
/// 1. Transformed struct with generic parameters and runtime fields
/// 2. Constructor: `__new(address, storage)`
/// 3. Type-safe (private) getter and setter methods
///
/// # ABI Composition
///
/// When using `#[contract(abi(mod1, mod2, ...))]`, the macro generates unified types from
/// multiple `#[abi]` modules:
///
/// ```ignore
/// #[contract(abi(types::tip20, types::roles_auth, types::rewards))]
/// pub struct TIP20Token { ... }
///
/// // Generates:
/// // - `TIP20TokenCalls` - Unified calls enum with variants for each module
/// // - `TIP20TokenError` - Unified error enum with `From` impls
/// // - `TIP20TokenEvent` - Unified event enum with `IntoLogData` impl
/// ```
///
/// **Generated `{Name}Calls`:**
/// - `SELECTORS: &[[u8; 4]]` - Flattened selectors from all modules
/// - `valid_selector(sel) -> bool` - Check if selector matches any module
/// - `abi_decode(data) -> Result<Self>` - Decode by selector routing
/// - `SolInterface` trait impl
///
/// **Generated `{Name}Error`:**
/// - `SELECTORS: &[[u8; 4]]` - All error selectors
/// - `selector(&self) -> [u8; 4]` - Get selector for this error
/// - `From<module::Error>` impls for ergonomic error conversion
/// - `SolInterface` trait impl
///
/// **Generated `{Name}Event`:**
/// - `SELECTORS: &[B256]` - All event topic0 hashes
/// - `From<module::Event>` impls
/// - `IntoLogData` trait impl
///
/// # Requirements
///
/// - No duplicate slot assignments
/// - Unique field names, excluding the reserved ones: `address`, `storage`, `msg_sender`.
/// - All field types must implement `Storable`, and mapping keys must implement `StorageKey`.
/// - For `abi(...)`: All referenced modules must be `#[abi]` modules with `Calls`, `Error`, and `Event` types.
#[proc_macro_attribute]
pub fn contract(attr: TokenStream, item: TokenStream) -> TokenStream {
    let config = parse_macro_input!(attr as ContractConfig);
    let input = parse_macro_input!(item as DeriveInput);

    match gen_contract_output(input, &config) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// Configuration parsed from `#[abi(...)]` attribute arguments.
#[derive(Default)]
pub(crate) struct SolidityConfig {
    /// Custom name for the interface alias module (defaults to `I{PascalCaseName}`).
    pub interface_alias: Option<String>,
    /// Disable auto re-export of module contents.
    pub no_reexport: bool,
    /// Generate Dispatch trait and precompile_call helper (requires revm).
    pub dispatch: bool,
}

impl Parse for SolidityConfig {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut config = Self::default();

        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            match ident.to_string().as_str() {
                "interface_alias" => {
                    input.parse::<Token![=]>()?;
                    let lit: syn::LitStr = input.parse()?;
                    config.interface_alias = Some(lit.value());
                }
                "no_reexport" => {
                    config.no_reexport = true;
                }
                "dispatch" => {
                    config.dispatch = true;
                }
                other => {
                    return Err(syn::Error::new(
                        ident.span(),
                        format!(
                            "unknown attribute `{other}`, expected `interface_alias`, `no_reexport`, or `dispatch`"
                        ),
                    ));
                }
            }

            // Consume optional trailing comma
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(config)
    }
}

/// Unified module macro for generating Solidity-compatible types.
///
/// This macro processes an entire module containing Solidity ABI type definitions,
/// enabling correct selector computation for functions with struct parameters
/// and proper EIP-712 component tracking for nested structs.
///
/// # Attributes
///
/// - `#[abi]` - Default behavior with auto re-exports
/// - `#[abi(dispatch)]` - Generate `Dispatch` trait and `precompile_call` helper (requires `revm`)
/// - `#[abi(interface_alias = "CustomName")]` - Custom interface alias module name
/// - `#[abi(no_reexport)]` - Disable auto re-export behavior
///
/// # Auto Re-exports
///
/// By default, the macro generates sibling re-export items after the module:
///
/// ```ignore
/// #[abi]
/// pub mod tip20 { ... }
///
/// // Auto-generated:
/// pub use self::tip20::*;
/// #[allow(non_snake_case)]
/// pub mod ITip20 { pub use super::tip20::*; }
/// ```
///
/// The interface alias uses PascalCase naming: `tip20` → `ITip20`, `roles_auth` → `IRolesAuth`.
///
/// Use `#[abi(no_reexport)]` to disable this behavior, or
/// `#[abi(interface_alias = "CustomName")]` to customize the alias name.
///
/// # Naming Conventions
///
/// | Item Type | Required Name | Cardinality |
/// |-----------|---------------|-------------|
/// | Interface trait | `Interface` | 0 or 1 |
/// | Error enum | `Error` | 0 or 1 |
/// | Event enum | `Event` | 0 or 1 |
/// | Structs | Any valid identifier | 0 or more |
/// | Other enums | Any valid identifier | 0 or more (unit variants only) |
/// | Constants | Any (const/static) | 0 or more |
///
/// # Generated Types
///
/// **Always generated** (for `#[contract(abi)]` composition):
/// - `Error` enum with `SELECTORS`, `valid_selector()`, `selector()` (dummy if not defined)
/// - `Event` enum with `SELECTORS`, `IntoLogData` impl (dummy if not defined)
/// - `Calls` enum with `SELECTORS`, `valid_selector()`, `abi_decode()` (dummy if not defined)
///
/// For each struct:
/// - `SolStruct`, `SolType`, `SolValue`, `EventTopic` implementations
///
/// For unit enums (non-Error/Event):
/// - `#[repr(u8)]` with explicit discriminants
/// - `From<Enum> for u8` and `TryFrom<u8> for Enum`
/// - `SolType` implementation (encodes as uint8)
///
/// For Error enum:
/// - Individual error structs with `SolError` implementations
/// - Container `Error` enum with `SolInterface` implementation
/// - Snake_case constructor methods
///
/// For Event enum:
/// - Individual event structs with `SolEvent` implementations
/// - Container `Event` enum with `IntoLogData` implementation
/// - Use `#[indexed]` on fields to mark them as indexed topics
///
/// For Interface trait:
/// - `{camelCaseName}Call` structs with `SolCall` implementations
/// - `Calls` enum with `SolInterface` implementation
/// - Trait with `msg_sender: Address` auto-injected for `&mut self` methods
///
/// For constants (const/static items):
/// - `{CONSTANT_NAME}Call` structs for each constant
/// - `IConstants` trait with getter methods
/// - `ConstantsCalls` enum merged into unified `Calls`
///
/// # Dummy Types
///
/// When a module doesn't define `Error`, `Event`, or `Interface`, the macro generates
/// empty "dummy" types to ensure compatibility with `#[contract(abi)]` composition:
///
/// ```ignore
/// #[abi]
/// pub mod rewards {
///     pub trait Interface {
///         fn claim_rewards(&mut self) -> Result<U256>;
///     }
/// }
/// // Generates real Calls enum + dummy Error and Event enums
/// ```
///
/// Dummy types implement the required API with empty selectors:
/// - `Error::SELECTORS` = `&[]`, `valid_selector()` returns `false`
/// - `Event::SELECTORS` = `&[]`
/// - `Calls` (if no Interface) = empty enum with `abi_decode()` returning error
///
/// # Example
///
/// ```ignore
/// #[abi]
/// pub mod abi {
///     use super::*;
///
///     pub static PAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"PAUSE_ROLE"));
///
///     #[derive(Clone, Debug)]
///     pub struct Transfer {
///         pub from: Address,
///         pub to: Address,
///         pub amount: U256,
///     }
///
///     pub enum PolicyType {
///         Whitelist,  // = 0
///         Blacklist,  // = 1
///     }
///
///     pub enum Error {
///         Unauthorized,
///         InsufficientBalance { available: U256, required: U256 },
///     }
///
///     pub enum Event {
///         RoleMembershipUpdated {
///             #[indexed] role: B256,
///             #[indexed] account: Address,
///             sender: Address,
///             has_role: bool,
///         },
///     }
///
///     pub trait Interface {
///         fn has_role(&self, account: Address, role: B256) -> Result<bool>;
///         fn grant_role(&mut self, role: B256, account: Address) -> Result<()>;
///     }
/// }
/// ```
#[proc_macro_attribute]
pub fn abi(attr: TokenStream, item: TokenStream) -> TokenStream {
    let config = parse_macro_input!(attr as SolidityConfig);
    let input = parse_macro_input!(item as syn::ItemMod);

    match solidity::expand(input, config) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}



fn gen_contract_output(
    input: DeriveInput,
    config: &ContractConfig,
) -> syn::Result<proc_macro2::TokenStream> {
    let (ident, vis) = (input.ident.clone(), input.vis.clone());
    let fields = parse_fields(input)?;

    let storage_output = gen_contract_storage(&ident, &vis, &fields, config.address.as_ref())?;

    let abi_aliases = if config.use_abi {
        let is_dynamic = config.address.is_none();
        composition::generate_abi_aliases(&ident, config.dispatch, is_dynamic)?
    } else {
        proc_macro2::TokenStream::new()
    };

    Ok(quote! {
        #storage_output
        #abi_aliases
    })
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
    address: Option<&Expr>,
) -> syn::Result<proc_macro2::TokenStream> {
    // Generate the complete output
    let allocated_fields = packing::allocate_slots(fields)?;
    let transformed_struct = layout::gen_struct(ident, vis, &allocated_fields);
    let storage_trait = layout::gen_contract_storage_impl(ident);
    let constructor = layout::gen_constructor(ident, &allocated_fields, address);
    let slots_module = layout::gen_slots_module(&allocated_fields);
    let default_impl = if address.is_some() {
        layout::gen_default_impl(ident)
    } else {
        proc_macro2::TokenStream::new()
    };

    let output = quote! {
        #slots_module
        #transformed_struct
        #constructor
        #storage_trait
        #default_impl
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
