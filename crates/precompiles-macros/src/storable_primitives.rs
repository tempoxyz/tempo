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
    Unsigned,
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
fn gen_storable_type_impl(type_path: &TokenStream, byte_count: usize) -> TokenStream {
    quote! {
        impl StorableType for #type_path {
            const BYTE_COUNT: usize = #byte_count;
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

/// Generate a `Storable<1>` implementation based on the conversion strategy
fn gen_storable_impl(
    type_path: &TokenStream,
    strategy: &StorableConversionStrategy,
) -> TokenStream {
    match strategy {
        StorableConversionStrategy::Unsigned => {
            quote! {
                impl Storable<1> for #type_path {
                    const SLOT_COUNT: usize = 1;

                    #[inline]
                    fn load<S: StorageOps>(storage: &mut S, base_slot: U256) -> Result<Self> {
                        let value = storage.sload(base_slot)?;
                        Ok(value.to::<Self>())
                    }

                    #[inline]
                    fn store<S: StorageOps>(&self, storage: &mut S, base_slot: U256) -> Result<()> {
                        storage.sstore(base_slot, U256::from(*self))
                    }

                    #[inline]
                    fn to_evm_words(&self) -> Result<[U256; 1]> {
                        Ok([U256::from(*self)])
                    }

                    #[inline]
                    fn from_evm_words(words: [U256; 1]) -> Result<Self> {
                        Ok(words[0].to::<Self>())
                    }
                }
            }
        }
        StorableConversionStrategy::U256 => {
            quote! {
                impl Storable<1> for #type_path {
                    const SLOT_COUNT: usize = 1;

                    #[inline]
                    fn load<S: StorageOps>(storage: &mut S, base_slot: #type_path) -> Result<Self> {
                        storage.sload(base_slot)
                    }

                    #[inline]
                    fn store<S: StorageOps>(&self, storage: &mut S, base_slot: #type_path) -> Result<()> {
                        storage.sstore(base_slot, *self)
                    }

                    #[inline]
                    fn to_evm_words(&self) -> Result<[#type_path; 1]> {
                        Ok([*self])
                    }

                    #[inline]
                    fn from_evm_words(words: [#type_path; 1]) -> Result<Self> {
                        Ok(words[0])
                    }
                }
            }
        }
        StorableConversionStrategy::SignedRust(unsigned_type) => {
            quote! {
                impl Storable<1> for #type_path {
                    const SLOT_COUNT: usize = 1;

                    #[inline]
                    fn load<S: StorageOps>(storage: &mut S, base_slot: U256) -> Result<Self> {
                        let value = storage.sload(base_slot)?;
                        // Read as unsigned then cast to signed (preserves bit pattern)
                        Ok(value.to::<#unsigned_type>() as Self)
                    }

                    #[inline]
                    fn store<S: StorageOps>(&self, storage: &mut S, base_slot: U256) -> Result<()> {
                        // Cast to unsigned to preserve bit pattern, then extend to U256
                        storage.sstore(base_slot, U256::from(*self as #unsigned_type))
                    }

                    #[inline]
                    fn to_evm_words(&self) -> Result<[U256; 1]> {
                        Ok([U256::from(*self as #unsigned_type)])
                    }

                    #[inline]
                    fn from_evm_words(words: [U256; 1]) -> Result<Self> {
                        Ok(words[0].to::<#unsigned_type>() as Self)
                    }
                }
            }
        }
        StorableConversionStrategy::SignedAlloy(unsigned_type) => {
            quote! {
                impl Storable<1> for #type_path {
                    const SLOT_COUNT: usize = 1;

                    #[inline]
                    fn load<S: StorageOps>(storage: &mut S, base_slot: ::alloy::primitives::U256) -> Result<Self> {
                        let value = storage.sload(base_slot)?;
                        // Convert U256 to unsigned type, then reinterpret as signed
                        let unsigned_val = value.to::<::alloy::primitives::#unsigned_type>();
                        Ok(Self::from_raw(unsigned_val))
                    }

                    #[inline]
                    fn store<S: StorageOps>(&self, storage: &mut S, base_slot: ::alloy::primitives::U256) -> Result<()> {
                        // Get unsigned bit pattern and store it
                        let unsigned_val = self.into_raw();
                        storage.sstore(base_slot, ::alloy::primitives::U256::from(unsigned_val))
                    }

                    #[inline]
                    fn to_evm_words(&self) -> Result<[::alloy::primitives::U256; 1]> {
                        let unsigned_val = self.into_raw();
                        Ok([::alloy::primitives::U256::from(unsigned_val)])
                    }

                    #[inline]
                    fn from_evm_words(words: [::alloy::primitives::U256; 1]) -> Result<Self> {
                        let unsigned_val = words[0].to::<::alloy::primitives::#unsigned_type>();
                        Ok(Self::from_raw(unsigned_val))
                    }
                }
            }
        }
        StorableConversionStrategy::FixedBytes(size) => {
            quote! {
                impl Storable<1> for #type_path {
                    const SLOT_COUNT: usize = 1;

                    #[inline]
                    fn load<S: StorageOps>(storage: &mut S, base_slot: ::alloy::primitives::U256) -> Result<Self> {
                        let value = storage.sload(base_slot)?;
                        // `FixedBytes` are stored left-aligned in the slot. Extract the first N bytes from the U256
                        let bytes = value.to_be_bytes::<32>();
                        let mut fixed_bytes = [0u8; #size];
                        fixed_bytes.copy_from_slice(&bytes[..#size]);
                        Ok(Self::from(fixed_bytes))
                    }

                    #[inline]
                    fn store<S: StorageOps>(&self, storage: &mut S, base_slot: ::alloy::primitives::U256) -> Result<()> {
                        // Pad `FixedBytes` to 32 bytes (left-aligned).
                        let mut bytes = [0u8; 32];
                        bytes[..#size].copy_from_slice(&self[..]);
                        let value = ::alloy::primitives::U256::from_be_bytes(bytes);
                        storage.sstore(base_slot, value)
                    }

                    #[inline]
                    fn to_evm_words(&self) -> Result<[::alloy::primitives::U256; 1]> {
                        let mut bytes = [0u8; 32];
                        bytes[..#size].copy_from_slice(&self[..]);
                        Ok([::alloy::primitives::U256::from_be_bytes(bytes)])
                    }

                    #[inline]
                    fn from_evm_words(words: [::alloy::primitives::U256; 1]) -> Result<Self> {
                        let bytes = words[0].to_be_bytes::<32>();
                        let mut fixed_bytes = [0u8; #size];
                        fixed_bytes.copy_from_slice(&bytes[..#size]);
                        Ok(Self::from(fixed_bytes))
                    }
                }
            }
        }
    }
}

/// Generate all storage-related impls for a type
fn gen_complete_impl_set(config: &TypeConfig) -> TokenStream {
    let storable_type_impl = gen_storable_type_impl(&config.type_path, config.byte_count);
    let storable_impl = gen_storable_impl(&config.type_path, &config.storable_strategy);
    let storage_key_impl = gen_storage_key_impl(&config.type_path, &config.storage_key_strategy);

    quote! {
        #storable_type_impl
        #storable_impl
        #storage_key_impl
    }
}

/// Generate `StorableType` and `Storable<1>` implementations for all standard Rust integer types.
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
            storable_strategy: StorableConversionStrategy::Unsigned,
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

/// Generate `StorableType` and `Storable<1>` implementations for alloy integer types.
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
                StorableConversionStrategy::Unsigned
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

/// Generate `StorableType` and `Storable<1>` implementations for FixedBytes<N> types.
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

/// Generate `StorableType` and `Storable<1>` implementations for FixedBytes<N> types.
pub(crate) fn gen_storable_alloy_bytes() -> TokenStream {
    let sizes: Vec<usize> = (1..=32).collect();
    let impls = gen_fixed_bytes(&sizes);

    quote! {
        #(#impls)*
    }
}

/// Generate `StorableType` and `Storable<1>` implementations for all alloy integer types.
pub(crate) fn gen_storable_alloy_ints() -> TokenStream {
    let impls = gen_alloy_integers();

    quote! {
        #(#impls)*
    }
}
