//! Code generation for primitive type storage implementations.

use proc_macro2::TokenStream;
use quote::quote;

const RUST_INT_SIZES: &[usize] = &[8, 16, 32, 64, 128];
const ALLOY_INT_SIZES: &[usize] = &[8, 16, 32, 64, 128, 256];

// -- RUST INTEGERS ------------------------------------------------------------

/// Generate `StorableType` and `Storable<1>` implementations for all standard Rust integer types.
///
/// Generates implementations for all standard integer sizes: u8/i8, u16/i16, u32/i32, u64/i64, u128/i128.
///
/// Each type gets:
/// - `StorableType` impl with `BYTE_COUNT` constant
/// - `Storable<1>` impl with `load()`, `store()`, `to_evm_words()`, `from_evm_words()` methods
/// - `StorageKey` impl for use as mapping keys
/// - Auto-generated tests that verify round-trip conversions with random values
pub(crate) fn gen_storable_rust_ints() -> TokenStream {
    let mut impls = Vec::with_capacity(RUST_INT_SIZES.len());
    let mut tests = Vec::with_capacity(RUST_INT_SIZES.len());

    for size in RUST_INT_SIZES {
        let unsigned_type = quote::format_ident!("u{}", size);
        let signed_type = quote::format_ident!("i{}", size);
        let byte_count = size / 8;

        // Generate unsigned integer implementation
        impls.push(quote! {
            impl StorableType for #unsigned_type {
                const BYTE_COUNT: usize = #byte_count;
            }

            impl Storable<1> for #unsigned_type {
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

            impl StorageKey for #unsigned_type {
                #[inline]
                fn as_storage_bytes(&self) -> impl AsRef<[u8]> {
                    self.to_be_bytes()
                }
            }
        });

        // Generate signed integer implementation
        impls.push(quote! {
            impl StorableType for #signed_type {
                const BYTE_COUNT: usize = #byte_count;
            }

            impl Storable<1> for #signed_type {
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

            impl StorageKey for #signed_type {
                #[inline]
                fn as_storage_bytes(&self) -> impl AsRef<[u8]> {
                    self.to_be_bytes()
                }
            }
        });

        tests.push(gen_rust_int_test(&unsigned_type, byte_count, "evm"));
        tests.push(gen_rust_int_test(&signed_type, byte_count, "evm"));
        tests.push(gen_rust_int_test(&unsigned_type, byte_count, "storage_key"));
        tests.push(gen_rust_int_test(&signed_type, byte_count, "storage_key"));
    }

    quote! {
        #(#impls)*

        #[cfg(test)]
        mod generated_storable_integer_tests {
            use super::*;

            #(#tests)*
        }
    }
}

// -- ALLOY TYPES (INTEGERS + FIXED BYTES) ---------------------------------------------------------

/// Generate `StorableType` and `Storable<1>` implementations for alloy integer types.
///
/// This function generates implementations for both signed and unsigned alloy integer
/// types of the specified sizes.
///
/// Each type gets:
/// - `StorableType` impl with `BYTE_COUNT` constant
/// - `Storable<1>` impl with `load()`, `store()`, `to_evm_words()`, `from_evm_words()` methods
/// - Auto-generated tests that verify round-trip conversions
fn gen_alloy_integers() -> (Vec<TokenStream>, Vec<TokenStream>) {
    let mut impls = Vec::with_capacity(ALLOY_INT_SIZES.len());
    let mut tests = Vec::with_capacity(ALLOY_INT_SIZES.len());

    for &size in ALLOY_INT_SIZES {
        let unsigned_type = quote::format_ident!("U{}", size);
        let signed_type = quote::format_ident!("I{}", size);
        let byte_count = size / 8;

        // Generate unsigned integer implementation
        if size == 256 {
            impls.push(quote! {
                impl StorableType for ::alloy::primitives::#unsigned_type {
                    const BYTE_COUNT: usize = #byte_count;
                }

                impl Storable<1> for ::alloy::primitives::#unsigned_type {
                    #[inline]
                    fn load<S: StorageOps>(storage: &mut S, base_slot: ::alloy::primitives::U256) -> Result<Self> {
                        storage.sload(base_slot)
                    }

                    #[inline]
                    fn store<S: StorageOps>(&self, storage: &mut S, base_slot: ::alloy::primitives::U256) -> Result<()> {
                        storage.sstore(base_slot, *self)
                    }

                    #[inline]
                    fn to_evm_words(&self) -> Result<[::alloy::primitives::U256; 1]> {
                        Ok([*self])
                    }

                    #[inline]
                    fn from_evm_words(words: [::alloy::primitives::U256; 1]) -> Result<Self> {
                        Ok(words[0])
                    }
                }

                impl StorageKey for ::alloy::primitives::#unsigned_type {
                    #[inline]
                    fn as_storage_bytes(&self) -> impl AsRef<[u8]> {
                        self.to_be_bytes::<#byte_count>()
                    }
                }
            });
        } else {
            // Smaller unsigned types need conversion to/from U256
            impls.push(quote! {
                impl StorableType for ::alloy::primitives::#unsigned_type {
                    const BYTE_COUNT: usize = #byte_count;
                }

                impl Storable<1> for ::alloy::primitives::#unsigned_type {
                    #[inline]
                    fn load<S: StorageOps>(storage: &mut S, base_slot: ::alloy::primitives::U256) -> Result<Self> {
                        let value = storage.sload(base_slot)?;
                        Ok(value.to::<Self>())
                    }

                    #[inline]
                    fn store<S: StorageOps>(&self, storage: &mut S, base_slot: ::alloy::primitives::U256) -> Result<()> {
                        storage.sstore(base_slot, ::alloy::primitives::U256::from(*self))
                    }

                    #[inline]
                    fn to_evm_words(&self) -> Result<[::alloy::primitives::U256; 1]> {
                        Ok([::alloy::primitives::U256::from(*self)])
                    }

                    #[inline]
                    fn from_evm_words(words: [::alloy::primitives::U256; 1]) -> Result<Self> {
                        Ok(words[0].to::<Self>())
                    }
                }

                impl StorageKey for ::alloy::primitives::#unsigned_type {
                    #[inline]
                    fn as_storage_bytes(&self) -> impl AsRef<[u8]> {
                        self.to_be_bytes::<#byte_count>()
                    }
                }
            });
        }

        // Generate signed integer implementation
        // Signed integers are stored as their unsigned bit pattern (two's complement)
        impls.push(quote! {
            impl StorableType for ::alloy::primitives::#signed_type {
                const BYTE_COUNT: usize = #byte_count;
            }

            impl Storable<1> for ::alloy::primitives::#signed_type {
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

            impl StorageKey for ::alloy::primitives::#signed_type {
                #[inline]
                fn as_storage_bytes(&self) -> impl AsRef<[u8]> {
                    self.into_raw().to_be_bytes::<#byte_count>()
                }
            }
        });

        tests.push(gen_alloy_int_test(&unsigned_type, byte_count, None, "evm"));
        tests.push(gen_alloy_int_test(
            &signed_type,
            byte_count,
            Some(&unsigned_type),
            "evm",
        ));
        tests.push(gen_alloy_int_test(
            &unsigned_type,
            byte_count,
            None,
            "storage_key",
        ));
        tests.push(gen_alloy_int_test(
            &signed_type,
            byte_count,
            Some(&unsigned_type),
            "storage_key",
        ));
    }

    (impls, tests)
}

/// Generate `StorableType` and `Storable<1>` implementations for FixedBytes<N> types.
///
/// This function generates implementations for fixed-size byte arrays.
///
/// Each type gets:
/// - `StorableType` impl with `BYTE_COUNT` constant
/// - `Storable<1>` impl with `load()`, `store()`, `to_evm_words()`, `from_evm_words()` methods
/// - Auto-generated tests that verify round-trip conversions
fn gen_fixed_bytes(sizes: &[usize]) -> (Vec<TokenStream>, Vec<TokenStream>) {
    let (mut impls, mut tests) = (Vec::new(), Vec::new());

    for &size in sizes {
        // Generate FixedBytes implementation
        impls.push(quote! {
            impl StorableType for ::alloy::primitives::FixedBytes<#size> {
                const BYTE_COUNT: usize = #size;
            }

            impl Storable<1> for ::alloy::primitives::FixedBytes<#size> {
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

            impl StorageKey for ::alloy::primitives::FixedBytes<#size> {
                #[inline]
                fn as_storage_bytes(&self) -> impl AsRef<[u8]> {
                    self.as_slice()
                }
            }
        });

        tests.push(gen_fixed_bytes_test(size, "evm_words_roundtrip"));
        tests.push(gen_fixed_bytes_test(size, "storage_key"));
    }

    (impls, tests)
}

/// Generate `StorableType` and `Storable<1>` implementations for all alloy `FixedBytes` types that fit within a single slot.
///
/// Each type gets:
/// - `StorableType` impl with `BYTE_COUNT` constant
/// - `Storable<1>` impl with `load()`, `store()`, `to_evm_words()`, `from_evm_words()` methods
/// - `StorageKey` impl for use as mapping keys
/// - Auto-generated tests that verify round-trip conversions using alloy's `.random()` method
pub(crate) fn gen_storable_alloy_bytes() -> TokenStream {
    let sizes: Vec<usize> = (1..=32).collect();
    let (impls, tests) = gen_fixed_bytes(&sizes);

    quote! {
        #(#impls)*

        #[cfg(test)]
        mod generated_storable_fixedbytes_tests {
            use super::*;

            #(#tests)*
        }
    }
}

/// Generate `StorableType` and `Storable<1>` implementations for all alloy integer types.
///
/// Generates implementations for all alloy integer types, both signed and unsigned.
///
/// Each type gets:
/// - `StorableType` impl with `BYTE_COUNT` constant
/// - `Storable<1>` impl with `load()`, `store()`, `to_evm_words()`, `from_evm_words()` methods
/// - `StorageKey` impl for use as mapping keys
/// - Auto-generated tests that verify round-trip conversions using alloy's `.random()` method
pub(crate) fn gen_storable_alloy_ints() -> TokenStream {
    let (impls, tests) = gen_alloy_integers();

    quote! {
        #(#impls)*

        #[cfg(test)]
        mod generated_storable_alloy_integer_tests {
            use super::*;

            #(#tests)*
        }
    }
}

// -- TEST HELPERS -------------------------------------------------------------

/// Generate test for rust integer types.
fn gen_rust_int_test(
    type_name: &proc_macro2::Ident,
    byte_count: usize,
    test_type: &str,
) -> TokenStream {
    let test_suffix = if test_type == "evm" {
        "evm_words_roundtrip"
    } else {
        "storage_key"
    };
    let test_name = quote::format_ident!("test_{}_{}", type_name, test_suffix);

    if test_type == "evm" {
        quote! {
            #[test]
            fn #test_name() {
                use rand::distributions::{Distribution, Standard};

                // Test edge cases
                let edge_cases = [#type_name::MIN, #type_name::MAX, 0];
                for &value in &edge_cases {
                    let words = value.to_evm_words().expect("to_evm_words failed");
                    let recovered = #type_name::from_evm_words(words).expect("from_evm_words failed");
                    assert_eq!(value, recovered, "EVM words round-trip failed for edge case {}", value);
                }

                // Test random values
                let mut rng = rand::thread_rng();
                for _ in 0..100 {
                    let value: #type_name = Standard.sample(&mut rng);
                    let words = value.to_evm_words().expect("to_evm_words failed");
                    let recovered = #type_name::from_evm_words(words).expect("from_evm_words failed");
                    assert_eq!(value, recovered, "EVM words round-trip failed for random value {}", value);
                }
            }
        }
    } else {
        quote! {
            #[test]
            fn #test_name() {
                use rand::distributions::{Distribution, Standard};

                // Test byte length
                let value = #type_name::MAX;
                let bytes = value.as_storage_bytes();
                assert_eq!(bytes.as_ref().len(), #byte_count, "StorageKey byte length mismatch");

                // Test edge cases
                let edge_cases = [#type_name::MIN, #type_name::MAX, 0];
                for &value in &edge_cases {
                    let bytes = value.as_storage_bytes();
                    assert_eq!(bytes.as_ref().len(), #byte_count);
                    assert_eq!(bytes.as_ref(), &value.to_be_bytes(), "StorageKey bytes mismatch for edge case {}", value);
                }

                // Test random values
                let mut rng = rand::thread_rng();
                for _ in 0..100 {
                    let value: #type_name = Standard.sample(&mut rng);
                    let bytes = value.as_storage_bytes();
                    assert_eq!(bytes.as_ref().len(), #byte_count);
                    assert_eq!(bytes.as_ref(), &value.to_be_bytes(), "StorageKey bytes mismatch for random value");
                }
            }
        }
    }
}

/// Generate test for alloy integer types.
fn gen_alloy_int_test(
    type_name: &proc_macro2::Ident,
    byte_count: usize,
    unsigned_type: Option<&proc_macro2::Ident>,
    test_type: &str,
) -> TokenStream {
    let test_suffix = if test_type == "evm" {
        "evm_words_roundtrip"
    } else {
        "storage_key"
    };
    let test_name = quote::format_ident!(
        "test_{}_{}",
        type_name.to_string().to_lowercase(),
        test_suffix
    );

    if test_type == "evm" {
        let (edge_cases, random_value) = if let Some(unsigned_type) = unsigned_type {
            (
                quote! { [::alloy::primitives::#type_name::ZERO, ::alloy::primitives::#type_name::MINUS_ONE, ::alloy::primitives::#type_name::MAX, ::alloy::primitives::#type_name::MIN] },
                quote! {
                    let unsigned_value = ::alloy::primitives::#unsigned_type::random();
                    let value = ::alloy::primitives::#type_name::from_raw(unsigned_value);
                },
            )
        } else {
            (
                quote! { [::alloy::primitives::#type_name::ZERO, ::alloy::primitives::#type_name::MAX] },
                quote! { let value = ::alloy::primitives::#type_name::random(); },
            )
        };

        quote! {
            #[test]
            fn #test_name() {
                // Test edge cases
                let edge_cases = #edge_cases;
                for value in edge_cases {
                    let words = value.to_evm_words().expect("to_evm_words failed");
                    let recovered = ::alloy::primitives::#type_name::from_evm_words(words).expect("from_evm_words failed");
                    assert_eq!(value, recovered, "EVM words round-trip failed for edge case");
                }

                // Test random values
                for _ in 0..100 {
                    #random_value
                    let words = value.to_evm_words().expect("to_evm_words failed");
                    let recovered = ::alloy::primitives::#type_name::from_evm_words(words).expect("from_evm_words failed");
                    assert_eq!(value, recovered, "EVM words round-trip failed for random value");
                }
            }
        }
    } else if let Some(unsigned_type) = unsigned_type {
        // Signed `StorageKey` test
        quote! {
            #[test]
            fn #test_name() {
                // Test byte length
                let value = ::alloy::primitives::#type_name::MAX;
                let bytes = value.as_storage_bytes();
                assert_eq!(bytes.as_ref().len(), #byte_count, "StorageKey byte length mismatch");

                // Test edge cases
                let edge_cases = [::alloy::primitives::#type_name::ZERO, ::alloy::primitives::#type_name::MINUS_ONE, ::alloy::primitives::#type_name::MAX, ::alloy::primitives::#type_name::MIN];
                for value in edge_cases {
                    let bytes = value.as_storage_bytes();
                    assert_eq!(bytes.as_ref().len(), #byte_count);
                    let expected_bytes = value.into_raw().to_be_bytes::<#byte_count>();
                    assert_eq!(bytes.as_ref(), &expected_bytes, "StorageKey bytes mismatch for edge case");
                }

                // Test random values
                for _ in 0..100 {
                    let unsigned_value = ::alloy::primitives::#unsigned_type::random();
                    let value = ::alloy::primitives::#type_name::from_raw(unsigned_value);
                    let bytes = value.as_storage_bytes();
                    assert_eq!(bytes.as_ref().len(), #byte_count);
                    let expected_bytes = value.into_raw().to_be_bytes::<#byte_count>();
                    assert_eq!(bytes.as_ref(), &expected_bytes, "StorageKey bytes mismatch for random value");
                }
            }
        }
    } else {
        // Unsigned `StorageKey` test
        quote! {
            #[test]
            fn #test_name() {
                // Test byte length
                let value = ::alloy::primitives::#type_name::MAX;
                let bytes = value.as_storage_bytes();
                assert_eq!(bytes.as_ref().len(), #byte_count, "StorageKey byte length mismatch");

                // Test edge cases
                let edge_cases = [::alloy::primitives::#type_name::ZERO, ::alloy::primitives::#type_name::MAX];
                for value in edge_cases {
                    let bytes = value.as_storage_bytes();
                    assert_eq!(bytes.as_ref().len(), #byte_count);
                    assert_eq!(bytes.as_ref(), &value.to_be_bytes::<#byte_count>(), "StorageKey bytes mismatch for edge case");
                }

                // Test random values
                for _ in 0..100 {
                    let value = ::alloy::primitives::#type_name::random();
                    let bytes = value.as_storage_bytes();
                    assert_eq!(bytes.as_ref().len(), #byte_count);
                    assert_eq!(bytes.as_ref(), &value.to_be_bytes::<#byte_count>(), "StorageKey bytes mismatch for random value");
                }
            }
        }
    }
}

/// Generate tests for `FixedBytes` types.
fn gen_fixed_bytes_test(size: usize, test_type: &str) -> TokenStream {
    let test_name = quote::format_ident!("test_fixedbytes_{}_{}", size, test_type);

    if test_type == "evm_words_roundtrip" {
        quote! {
            #[test]
            fn #test_name() {
                // Test edge cases
                let zero = ::alloy::primitives::FixedBytes::<#size>::ZERO;
                let words = zero.to_evm_words().expect("to_evm_words failed");
                let recovered = ::alloy::primitives::FixedBytes::<#size>::from_evm_words(words).expect("from_evm_words failed");
                assert_eq!(zero, recovered, "EVM words round-trip failed for zero");

                let max = ::alloy::primitives::FixedBytes::<#size>::from([0xFFu8; #size]);
                let words = max.to_evm_words().expect("to_evm_words failed");
                let recovered = ::alloy::primitives::FixedBytes::<#size>::from_evm_words(words).expect("from_evm_words failed");
                assert_eq!(max, recovered, "EVM words round-trip failed for max");

                // Test random values
                for _ in 0..100 {
                    let value = ::alloy::primitives::FixedBytes::<#size>::random();
                    let words = value.to_evm_words().expect("to_evm_words failed");
                    let recovered = ::alloy::primitives::FixedBytes::<#size>::from_evm_words(words).expect("from_evm_words failed");
                    assert_eq!(value, recovered, "EVM words round-trip failed for random value");
                }
            }
        }
    } else {
        // storage_key variant
        quote! {
            #[test]
            fn #test_name() {
                // Test byte length
                let value = ::alloy::primitives::FixedBytes::<#size>::ZERO;
                let bytes = value.as_storage_bytes();
                assert_eq!(bytes.as_ref().len(), #size, "StorageKey byte length mismatch");

                // Test edge cases
                let zero = ::alloy::primitives::FixedBytes::<#size>::ZERO;
                let bytes = zero.as_storage_bytes();
                assert_eq!(bytes.as_ref().len(), #size);
                assert_eq!(bytes.as_ref(), zero.as_slice(), "StorageKey bytes mismatch for zero");

                let max = ::alloy::primitives::FixedBytes::<#size>::from([0xFFu8; #size]);
                let bytes = max.as_storage_bytes();
                assert_eq!(bytes.as_ref().len(), #size);
                assert_eq!(bytes.as_ref(), max.as_slice(), "StorageKey bytes mismatch for max");

                // Test random values
                for _ in 0..100 {
                    let value = ::alloy::primitives::FixedBytes::<#size>::random();
                    let bytes = value.as_storage_bytes();
                    assert_eq!(bytes.as_ref().len(), #size);
                    assert_eq!(bytes.as_ref(), value.as_slice(), "StorageKey bytes mismatch for random value");
                }
            }
        }
    }
}
