//! Code generation for primitive type storage implementations.

use proc_macro2::TokenStream;
use quote::quote;

pub(crate) const RUST_INT_SIZES: &[usize] = &[8, 16, 32, 64, 128];
pub(crate) const ALLOY_INT_SIZES: &[usize] = &[8, 16, 32, 64, 128, 256];

// -- CONFIGURATION TYPES ------------------------------------------------------

/// Strategy for converting to U256
#[derive(Debug, Clone)]
enum StorableConversionStrategy {
    U256, // no conversion needed (identity)
    UnsignedRust,
    UnsignedAlloy(proc_macro2::Ident),
    SignedRust(proc_macro2::Ident),
    SignedAlloy(proc_macro2::Ident),
    FixedBytes(usize),
}

/// Strategy for converting to storage key bytes
#[derive(Debug, Clone)]
enum StorageKeyStrategy {
    Simple,           // `self.to_be_bytes()`
    WithSize(usize),  // `self.to_be_bytes::<N>()`
    SignedRaw(usize), // `self.into_raw().to_be_bytes::<N>()`
    AsSlice,          // `self.as_slice()`
}

/// Complete configuration for generating implementations for a type
#[derive(Debug, Clone)]
struct TypeConfig {
    type_path: TokenStream,
    byte_count: usize,
    storable_strategy: StorableConversionStrategy,
    storage_key_strategy: StorageKeyStrategy,
}

// -- IMPLEMENTATION GENERATORS ------------------------------------------------

/// Generate a `StorableType` implementation
fn gen_storable_layout_impl(type_path: &TokenStream, byte_count: usize) -> TokenStream {
    quote! {
        impl StorableType for #type_path {
            const LAYOUT: Layout = Layout::Bytes(#byte_count);
            type Handler = crate::storage::Slot<Self>;

            fn handle(slot: U256, ctx: LayoutCtx, address: ::alloy::primitives::Address) -> Self::Handler {
                crate::storage::Slot::new_with_ctx(slot, ctx, address)
            }
        }
    }
}

/// Generate a `StorageKey` implementation based on the conversion strategy
fn gen_storage_key_impl(type_path: &TokenStream, strategy: &StorageKeyStrategy) -> TokenStream {
    let conversion = match strategy {
        StorageKeyStrategy::Simple => quote! { self.to_be_bytes() },
        StorageKeyStrategy::WithSize(size) => quote! { self.to_be_bytes::<#size>() },
        StorageKeyStrategy::SignedRaw(size) => quote! { self.into_raw().to_be_bytes::<#size>() },
        StorageKeyStrategy::AsSlice => quote! { self.as_slice() },
    };

    quote! {
        impl StorageKey for #type_path {
            #[inline]
            fn as_storage_bytes(&self) -> impl AsRef<[u8]> {
                #conversion
            }
        }
    }
}

/// Generate `OnlyPrimitives` and `Packable` implementations based on the conversion strategy.
/// This generates `to_word` and `from_word` - storage I/O is in `Storable` (blanket impl).
fn gen_packable_impl(
    type_path: &TokenStream,
    strategy: &StorableConversionStrategy,
) -> TokenStream {
    match strategy {
        StorableConversionStrategy::U256 => {
            quote! {
                impl crate::storage::types::sealed::OnlyPrimitives for #type_path {}
                impl Packable for #type_path {
                    #[inline]
                    fn to_word(&self) -> U256 {
                        *self
                    }

                    #[inline]
                    fn from_word(word: U256) -> crate::error::Result<Self> {
                        Ok(word)
                    }
                }
            }
        }
        StorableConversionStrategy::UnsignedRust => {
            quote! {
                impl crate::storage::types::sealed::OnlyPrimitives for #type_path {}
                impl Packable for #type_path {
                    #[inline]
                    fn to_word(&self) -> U256 {
                        ::alloy::primitives::U256::from(*self)
                    }

                    #[inline]
                    fn from_word(word: U256) -> crate::error::Result<Self> {
                        word.try_into().map_err(|_| crate::error::TempoPrecompileError::under_overflow())
                    }
                }
            }
        }
        StorableConversionStrategy::UnsignedAlloy(ty) => {
            quote! {
                impl crate::storage::types::sealed::OnlyPrimitives for #type_path {}
                impl Packable for #type_path {
                    #[inline]
                    fn to_word(&self) -> ::alloy::primitives::U256 {
                        ::alloy::primitives::U256::from(*self)
                    }

                    #[inline]
                    fn from_word(word: ::alloy::primitives::U256) -> crate::error::Result<Self> {
                        // Check if value fits in target type
                        if word > ::alloy::primitives::U256::from(::alloy::primitives::#ty::MAX) {
                            return Err(crate::error::TempoPrecompileError::under_overflow());
                        }
                        Ok(word.to::<Self>())
                    }
                }
            }
        }
        StorableConversionStrategy::SignedRust(unsigned_type) => {
            quote! {
                impl crate::storage::types::sealed::OnlyPrimitives for #type_path {}
                impl Packable for #type_path {
                    #[inline]
                    fn to_word(&self) -> U256 {
                        // Store as right-aligned unsigned representation
                        ::alloy::primitives::U256::from(*self as #unsigned_type)
                    }

                    #[inline]
                    fn from_word(word: U256) -> crate::error::Result<Self> {
                        // Extract low bytes as unsigned, then interpret as signed
                        let unsigned: #unsigned_type = word.try_into()
                            .map_err(|_| crate::error::TempoPrecompileError::under_overflow())?;
                        Ok(unsigned as Self)
                    }
                }
            }
        }
        StorableConversionStrategy::SignedAlloy(unsigned_type) => {
            quote! {
                impl crate::storage::types::sealed::OnlyPrimitives for #type_path {}
                impl Packable for #type_path {
                    #[inline]
                    fn to_word(&self) -> ::alloy::primitives::U256 {
                        // Store as right-aligned unsigned representation
                        ::alloy::primitives::U256::from(self.into_raw())
                    }

                    #[inline]
                    fn from_word(word: ::alloy::primitives::U256) -> crate::error::Result<Self> {
                        // Check if value fits in the unsigned backing type
                        if word > ::alloy::primitives::U256::from(::alloy::primitives::#unsigned_type::MAX) {
                            return Err(crate::error::TempoPrecompileError::under_overflow());
                        }
                        // Extract low bytes as unsigned, then interpret as signed
                        let unsigned_val = word.to::<::alloy::primitives::#unsigned_type>();
                        Ok(Self::from_raw(unsigned_val))
                    }
                }
            }
        }
        StorableConversionStrategy::FixedBytes(size) => {
            quote! {
                impl crate::storage::types::sealed::OnlyPrimitives for #type_path {}
                impl Packable for #type_path {
                    #[inline]
                    fn to_word(&self) -> ::alloy::primitives::U256 {
                        let mut bytes = [0u8; 32];
                        bytes[..#size].copy_from_slice(&self[..]);
                        ::alloy::primitives::U256::from_be_bytes(bytes)
                    }

                    #[inline]
                    fn from_word(word: ::alloy::primitives::U256) -> crate::error::Result<Self> {
                        let bytes = word.to_be_bytes::<32>();
                        let mut fixed_bytes = [0u8; #size];
                        fixed_bytes.copy_from_slice(&bytes[..#size]);
                        Ok(Self::from(fixed_bytes))
                    }
                }
            }
        }
    }
}

/// Generate all storage-related impls for a type.
///
/// Note: `Storable` is provided by a blanket impl for all `Packable` types.
fn gen_complete_impl_set(config: &TypeConfig) -> TokenStream {
    let storable_type_impl = gen_storable_layout_impl(&config.type_path, config.byte_count);
    let packable_impl = gen_packable_impl(&config.type_path, &config.storable_strategy);
    let storage_key_impl = gen_storage_key_impl(&config.type_path, &config.storage_key_strategy);

    quote! {
        #storable_type_impl
        #packable_impl
        #storage_key_impl
    }
}

/// Generate `StorableType`, `Packable`, and `StorageKey` for all standard Rust integer types.
pub(crate) fn gen_storable_rust_ints() -> TokenStream {
    let mut impls = Vec::with_capacity(RUST_INT_SIZES.len() * 2);

    for size in RUST_INT_SIZES {
        let unsigned_type = quote::format_ident!("u{}", size);
        let signed_type = quote::format_ident!("i{}", size);
        let byte_count = size / 8;

        // Generate unsigned integer configuration and implementation
        let unsigned_config = TypeConfig {
            type_path: quote! { #unsigned_type },
            byte_count,
            storable_strategy: StorableConversionStrategy::UnsignedRust,
            storage_key_strategy: StorageKeyStrategy::Simple,
        };
        impls.push(gen_complete_impl_set(&unsigned_config));

        // Generate signed integer configuration and implementation
        let signed_config = TypeConfig {
            type_path: quote! { #signed_type },
            byte_count,
            storable_strategy: StorableConversionStrategy::SignedRust(unsigned_type.clone()),
            storage_key_strategy: StorageKeyStrategy::Simple,
        };
        impls.push(gen_complete_impl_set(&signed_config));
    }

    quote! {
        #(#impls)*
    }
}

/// Generate `StorableType`, `Packable`, and `StorageKey` for alloy integer types.
fn gen_alloy_integers() -> Vec<TokenStream> {
    let mut impls = Vec::with_capacity(ALLOY_INT_SIZES.len() * 2);

    for &size in ALLOY_INT_SIZES {
        let unsigned_type = quote::format_ident!("U{}", size);
        let signed_type = quote::format_ident!("I{}", size);
        let byte_count = size / 8;

        // Generate unsigned integer configuration and implementation
        let unsigned_config = TypeConfig {
            type_path: quote! { ::alloy::primitives::#unsigned_type },
            byte_count,
            storable_strategy: if size == 256 {
                StorableConversionStrategy::U256
            } else {
                StorableConversionStrategy::UnsignedAlloy(unsigned_type.clone())
            },
            storage_key_strategy: StorageKeyStrategy::WithSize(byte_count),
        };
        impls.push(gen_complete_impl_set(&unsigned_config));

        // Generate signed integer configuration and implementation
        let signed_config = TypeConfig {
            type_path: quote! { ::alloy::primitives::#signed_type },
            byte_count,
            storable_strategy: StorableConversionStrategy::SignedAlloy(unsigned_type.clone()),
            storage_key_strategy: StorageKeyStrategy::SignedRaw(byte_count),
        };
        impls.push(gen_complete_impl_set(&signed_config));
    }

    impls
}

/// Generate `StorableType`, `Packable`, and `StorageKey` for `FixedBytes<N>` types.
fn gen_fixed_bytes(sizes: &[usize]) -> Vec<TokenStream> {
    let mut impls = Vec::with_capacity(sizes.len());

    for &size in sizes {
        // Generate FixedBytes configuration and implementation
        let config = TypeConfig {
            type_path: quote! { ::alloy::primitives::FixedBytes<#size> },
            byte_count: size,
            storable_strategy: StorableConversionStrategy::FixedBytes(size),
            storage_key_strategy: StorageKeyStrategy::AsSlice,
        };
        impls.push(gen_complete_impl_set(&config));
    }

    impls
}

/// Generate `StorableType`, `Packable`, and `StorageKey` for `FixedBytes<N>` types.
pub(crate) fn gen_storable_alloy_bytes() -> TokenStream {
    let sizes: Vec<usize> = (1..=32).collect();
    let impls = gen_fixed_bytes(&sizes);

    quote! {
        #(#impls)*
    }
}

/// Generate `StorableType`, `Packable`, and `StorageKey` for all alloy integer types.
pub(crate) fn gen_storable_alloy_ints() -> TokenStream {
    let impls = gen_alloy_integers();

    quote! {
        #(#impls)*
    }
}

// -- ARRAY IMPLEMENTATIONS ----------------------------------------------------

/// Configuration for generating array implementations
#[derive(Debug, Clone)]
struct ArrayConfig {
    elem_type: TokenStream,
    array_size: usize,
    elem_byte_count: usize,
    elem_is_packable: bool,
}

/// Whether a given amount of bytes (primitives only) should be packed, or not.
fn is_packable(byte_count: usize) -> bool {
    byte_count < 32 && 32 % byte_count == 0
}

/// Generate `StorableType`, `Storable`, and `StorageKey` for a fixed-size array.
fn gen_array_impl(config: &ArrayConfig) -> TokenStream {
    let ArrayConfig {
        elem_type,
        array_size,
        elem_byte_count,
        elem_is_packable,
    } = config;

    // Calculate slot count at compile time
    let slot_count = if *elem_is_packable {
        // Packed: multiple elements per slot
        (*array_size * elem_byte_count).div_ceil(32)
    } else {
        // Unpacked: each element uses full slots (assume 1 slot per element for primitives)
        *array_size
    };

    let load_impl = if *elem_is_packable {
        gen_packed_array_load(array_size, elem_byte_count)
    } else {
        gen_unpacked_array_load(array_size)
    };

    let store_impl = if *elem_is_packable {
        gen_packed_array_store(array_size, elem_byte_count)
    } else {
        gen_unpacked_array_store()
    };

    quote! {
        // Implement StorableType
        impl crate::storage::StorableType for [#elem_type; #array_size] {
            // Arrays cannot be packed, so they must take full slots
            const LAYOUT: crate::storage::Layout = crate::storage::Layout::Slots(#slot_count);

            type Handler = crate::storage::types::array::ArrayHandler<#elem_type, #array_size>;

            fn handle(slot: ::alloy::primitives::U256, ctx: crate::storage::LayoutCtx, address: ::alloy::primitives::Address) -> Self::Handler {
                debug_assert_eq!(ctx, crate::storage::LayoutCtx::FULL, "Arrays cannot be packed");
                Self::Handler::new(slot, address)
            }
        }

        // Implement Storable with full I/O logic
        impl crate::storage::Storable for [#elem_type; #array_size] {
            #[inline]
            fn load<S: crate::storage::StorageOps>(storage: &S, slot: ::alloy::primitives::U256, ctx: crate::storage::LayoutCtx) -> crate::error::Result<Self> {
                debug_assert_eq!(
                    ctx, crate::storage::LayoutCtx::FULL,
                    "Arrays can only be loaded with LayoutCtx::FULL"
                );

                use crate::storage::packing::{calc_element_slot, calc_element_offset, extract_packed_value, calc_element_offset_and_slot};
                let base_slot = slot;
                #load_impl
            }

            #[inline]
            fn store<S: crate::storage::StorageOps>(&self, storage: &mut S, slot: ::alloy::primitives::U256, ctx: crate::storage::LayoutCtx) -> crate::error::Result<()> {
                debug_assert_eq!(
                    ctx, crate::storage::LayoutCtx::FULL,
                    "Arrays can only be stored with LayoutCtx::FULL"
                );

                use crate::storage::packing::{calc_element_slot, calc_element_offset, insert_packed_value,  calc_element_offset_and_slot};
                let base_slot = slot;
                #store_impl
            }

            // delete uses the default implementation from the trait
        }

        // Implement StorageKey for use as mapping keys
        impl crate::storage::StorageKey for [#elem_type; #array_size] {
            #[inline]
            fn as_storage_bytes(&self) -> impl AsRef<[u8]> {
                use crate::storage::StorageKey;
                let mut bytes = Vec::with_capacity(#array_size * <#elem_type as crate::storage::StorableType>::BYTES);
                for elem in self.iter() {
                    bytes.extend_from_slice(elem.as_storage_bytes().as_ref());
                }
                bytes
            }
        }
    }
}

/// Generate load implementation for packed arrays
fn gen_packed_array_load(array_size: &usize, elem_byte_count: &usize) -> TokenStream {
    quote! {
        let mut result = [Default::default(); #array_size];
        for i in 0..#array_size {
            let (slot_idx, offset) = calc_element_offset_and_slot(i, #elem_byte_count);
            let slot_addr = base_slot + U256::from(slot_idx);
            let slot_value = storage.load(slot_addr)?;
            result[i] = extract_packed_value(slot_value, offset, #elem_byte_count)?;
        }
        Ok(result)
    }
}

/// Generate store implementation for packed arrays
fn gen_packed_array_store(array_size: &usize, elem_byte_count: &usize) -> TokenStream {
    quote! {
        // Determine how many slots we need
        let slot_count = (#array_size * #elem_byte_count).div_ceil(32);

        // Build slots by packing elements
        for slot_idx in 0..slot_count {
            let slot_addr = base_slot + U256::from(slot_idx);
            let mut slot_value = U256::ZERO;

            // Pack all elements that belong to this slot
            for i in 0..#array_size {
                let elem_slot = calc_element_slot(i, #elem_byte_count);
                if elem_slot == slot_idx {
                    let offset = calc_element_offset(i, #elem_byte_count);
                    slot_value = insert_packed_value(slot_value, &self[i], offset, #elem_byte_count)?;
                }
            }

            storage.store(slot_addr, slot_value)?;
        }
        Ok(())
    }
}

/// Generate load implementation for unpacked arrays
fn gen_unpacked_array_load(array_size: &usize) -> TokenStream {
    quote! {
        let mut result = [Default::default(); #array_size];
        for i in 0..#array_size {
            let elem_slot = base_slot + ::alloy::primitives::U256::from(i);
            result[i] = crate::storage::Storable::load(storage, elem_slot, crate::storage::LayoutCtx::FULL)?;
        }
        Ok(result)
    }
}

/// Generate store implementation for unpacked arrays
fn gen_unpacked_array_store() -> TokenStream {
    quote! {
        for (i, elem) in self.iter().enumerate() {
            let elem_slot = base_slot + ::alloy::primitives::U256::from(i);
            crate::storage::Storable::store(elem, storage, elem_slot, crate::storage::LayoutCtx::FULL)?;
        }
        Ok(())
    }
}

/// Generate array implementations for a specific element type
fn gen_arrays_for_type(
    elem_type: TokenStream,
    elem_byte_count: usize,
    sizes: &[usize],
) -> Vec<TokenStream> {
    let elem_is_packable = is_packable(elem_byte_count);

    sizes
        .iter()
        .map(|&size| {
            let config = ArrayConfig {
                elem_type: elem_type.clone(),
                array_size: size,
                elem_byte_count,
                elem_is_packable,
            };
            gen_array_impl(&config)
        })
        .collect()
}

/// Generate `StorableType`, `Storable`, and `StorageKey` for fixed-size arrays of primitive types.
pub(crate) fn gen_storable_arrays() -> TokenStream {
    let mut all_impls = Vec::new();
    let sizes: Vec<usize> = (1..=32).collect();

    // Rust unsigned integers
    for &bit_size in RUST_INT_SIZES {
        let type_ident = quote::format_ident!("u{}", bit_size);
        let byte_count = bit_size / 8;
        all_impls.extend(gen_arrays_for_type(
            quote! { #type_ident },
            byte_count,
            &sizes,
        ));
    }

    // Rust signed integers
    for &bit_size in RUST_INT_SIZES {
        let type_ident = quote::format_ident!("i{}", bit_size);
        let byte_count = bit_size / 8;
        all_impls.extend(gen_arrays_for_type(
            quote! { #type_ident },
            byte_count,
            &sizes,
        ));
    }

    // Alloy unsigned integers
    for &bit_size in ALLOY_INT_SIZES {
        let type_ident = quote::format_ident!("U{}", bit_size);
        let byte_count = bit_size / 8;
        all_impls.extend(gen_arrays_for_type(
            quote! { ::alloy::primitives::#type_ident },
            byte_count,
            &sizes,
        ));
    }

    // Alloy signed integers
    for &bit_size in ALLOY_INT_SIZES {
        let type_ident = quote::format_ident!("I{}", bit_size);
        let byte_count = bit_size / 8;
        all_impls.extend(gen_arrays_for_type(
            quote! { ::alloy::primitives::#type_ident },
            byte_count,
            &sizes,
        ));
    }

    // Address (20 bytes, not packable since 32 % 20 != 0)
    all_impls.extend(gen_arrays_for_type(
        quote! { ::alloy::primitives::Address },
        20,
        &sizes,
    ));

    // Common FixedBytes types
    for &byte_size in &[20, 32] {
        all_impls.extend(gen_arrays_for_type(
            quote! { ::alloy::primitives::FixedBytes<#byte_size> },
            byte_size,
            &sizes,
        ));
    }

    quote! {
        #(#all_impls)*
    }
}

/// Generate nested array implementations for common small cases
pub(crate) fn gen_nested_arrays() -> TokenStream {
    let mut all_impls = Vec::new();

    // Nested u8 arrays: [[u8; INNER]; OUTER]
    // Only generate where total slots <= 32
    for inner in &[2usize, 4, 8, 16] {
        let inner_slots = inner.div_ceil(32); // u8 packs, so this is ceil(inner/32)
        let max_outer = 32 / inner_slots.max(1);

        for outer in 1..=max_outer.min(32) {
            all_impls.extend(gen_arrays_for_type(
                quote! { [u8; #inner] },
                inner_slots * 32, // BYTE_COUNT for [u8; inner]
                &[outer],
            ));
        }
    }

    // Nested u16 arrays
    for inner in &[2usize, 4, 8] {
        let inner_slots = (inner * 2).div_ceil(32);
        let max_outer = 32 / inner_slots.max(1);

        for outer in 1..=max_outer.min(16) {
            all_impls.extend(gen_arrays_for_type(
                quote! { [u16; #inner] },
                inner_slots * 32,
                &[outer],
            ));
        }
    }

    quote! {
        #(#all_impls)*
    }
}

// -- STRUCT ARRAY IMPLEMENTATIONS ---------------------------------------------

/// Generate array implementations for user-defined structs (multi-slot types).
///
/// Unlike primitive arrays, struct arrays:
/// - Always use unpacked layout (structs span multiple slots)
/// - Each element occupies `<T>::SLOTS` consecutive slots
/// - Slot addressing uses multiplication: `base_slot + (i * <T>::SLOTS)`
///
/// # Parameters
///
/// - `struct_type`: The type path of the struct (e.g., `quote! { MyStruct }`)
/// - `array_sizes`: Vector of array sizes to generate (e.g., `[1, 2, 4, 8]`)
///
/// # Returns
///
/// A `TokenStream` containing all the generated array implementations.
pub(crate) fn gen_struct_arrays(struct_type: TokenStream, array_sizes: &[usize]) -> TokenStream {
    let impls: Vec<_> = array_sizes
        .iter()
        .map(|&size| gen_struct_array_impl(&struct_type, size))
        .collect();

    quote! {
        #(#impls)*
    }
}

/// Generate a single array implementation for a user-defined struct.
fn gen_struct_array_impl(struct_type: &TokenStream, array_size: usize) -> TokenStream {
    // Generate unique module name for this array type
    let struct_type_str = struct_type
        .to_string()
        .replace("::", "_")
        .replace(['<', '>', ' ', '[', ']', ';'], "_");
    let mod_ident = quote::format_ident!("__array_{}_{}", struct_type_str, array_size);

    // Generate implementation methods
    let load_impl = gen_struct_array_load(struct_type, array_size);
    let store_impl = gen_struct_array_store(struct_type);

    quote! {
        // Helper module with compile-time constants
        mod #mod_ident {
            use super::*;
            pub const ELEM_SLOTS: usize = <#struct_type as crate::storage::StorableType>::SLOTS;
            pub const ARRAY_LEN: usize = #array_size;
            pub const SLOT_COUNT: usize = ARRAY_LEN * ELEM_SLOTS;
        }

        // Implement StorableType
        impl crate::storage::StorableType for [#struct_type; #array_size] {
            const LAYOUT: crate::storage::Layout = crate::storage::Layout::Slots(#mod_ident::SLOT_COUNT);

            type Handler = crate::storage::Slot<Self>;

            fn handle(slot: ::alloy::primitives::U256, ctx: crate::storage::LayoutCtx, address: ::alloy::primitives::Address) -> Self::Handler {
                crate::storage::Slot::new_with_ctx(slot, ctx, address)
            }
        }

        // Implement Storable with full I/O logic
        impl crate::storage::Storable for [#struct_type; #array_size] {
            #[inline]
            fn load<S: crate::storage::StorageOps>(storage: &S, slot: ::alloy::primitives::U256, ctx: crate::storage::LayoutCtx) -> crate::error::Result<Self> {
                debug_assert_eq!(
                    ctx, crate::storage::LayoutCtx::FULL,
                    "Struct arrays can only be loaded with LayoutCtx::FULL"
                );
                let base_slot = slot;
                #load_impl
            }

            #[inline]
            fn store<S: crate::storage::StorageOps>(&self, storage: &mut S, slot: ::alloy::primitives::U256, ctx: crate::storage::LayoutCtx) -> crate::error::Result<()> {
                debug_assert_eq!(
                    ctx, crate::storage::LayoutCtx::FULL,
                    "Struct arrays can only be stored with LayoutCtx::FULL"
                );
                let base_slot = slot;
                #store_impl
            }

            // delete uses the default implementation from the trait
        }

        // Implement StorageKey for use as mapping keys
        impl crate::storage::StorageKey for [#struct_type; #array_size] {
            #[inline]
            fn as_storage_bytes(&self) -> impl AsRef<[u8]> {
                use crate::storage::StorageKey;
                // Iterate elements and concatenate their bytes
                let mut bytes = Vec::with_capacity(#array_size * <#struct_type as crate::storage::StorableType>::SLOTS * 32);
                for elem in self.iter() {
                    bytes.extend_from_slice(elem.as_storage_bytes().as_ref());
                }
                bytes
            }
        }
    }
}

/// Generate load implementation for struct arrays.
///
/// Each element occupies `<T>::SLOTS` consecutive slots.
fn gen_struct_array_load(struct_type: &TokenStream, array_size: usize) -> TokenStream {
    quote! {
        let mut result = [Default::default(); #array_size];
        for i in 0..#array_size {
            // Calculate slot for this element: base_slot + (i * element_slot_count)
            let elem_slot = base_slot.checked_add(
                ::alloy::primitives::U256::from(i).checked_mul(
                    ::alloy::primitives::U256::from(<#struct_type as crate::storage::StorableType>::SLOTS)
                ).ok_or(crate::error::TempoError::SlotOverflow)?
            ).ok_or(crate::error::TempoError::SlotOverflow)?;

            result[i] = <#struct_type as crate::storage::Storable>::load(storage, elem_slot, crate::storage::LayoutCtx::FULL)?;
        }
        Ok(result)
    }
}

/// Generate store implementation for struct arrays.
fn gen_struct_array_store(struct_type: &TokenStream) -> TokenStream {
    quote! {
        for (i, elem) in self.iter().enumerate() {
            // Calculate slot for this element: base_slot + (i * element_slot_count)
            let elem_slot = base_slot.checked_add(
                ::alloy::primitives::U256::from(i).checked_mul(
                    ::alloy::primitives::U256::from(<#struct_type as crate::storage::StorableType>::SLOTS)
                ).ok_or(crate::error::TempoError::SlotOverflow)?
            ).ok_or(crate::error::TempoError::SlotOverflow)?;

            <#struct_type as crate::storage::Storable>::store(elem, storage, elem_slot, crate::storage::LayoutCtx::FULL)?;
        }
        Ok(())
    }
}
