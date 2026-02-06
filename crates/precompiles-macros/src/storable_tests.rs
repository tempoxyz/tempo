//! Code generation for storage trait property tests.
//!
//! This module generates comprehensive property tests for all supported storage types,
//! including complete test function implementations.

use proc_macro2::{Ident, TokenStream};
use quote::quote;

use crate::storable_primitives::{ALLOY_INT_SIZES, RUST_INT_SIZES};
const FIXED_BYTES_SIZES: &[usize] = &[
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32,
];

fn proptest_block(cases: u32, tests: Vec<TokenStream>) -> TokenStream {
    quote! {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(#cases))]
            #(#tests)*
        }
    }
}

fn storage_key_abi_test(
    fn_name: Ident,
    strategy: TokenStream,
    extra: Option<TokenStream>,
) -> TokenStream {
    let extra = extra.unwrap_or_else(TokenStream::new);

    quote! {
        #[test]
        fn #fn_name(value in #strategy) {
            let encoded = crate::storage::StorageKey::abi_encoded(&value);
            let abi = ::alloy::sol_types::SolValue::abi_encode(&value);
            prop_assert_eq!(encoded.as_ref(), abi.as_slice());
            #extra
        }
    }
}

/// Generate all storage type tests.
///
/// This function generates:
/// 1. Arbitrary function generators for all types
/// 2. Complete proptest! blocks with test function implementations
pub(crate) fn gen_storable_tests() -> TokenStream {
    let rust_unsigned_arb = gen_rust_unsigned_arbitrary();
    let rust_signed_arb = gen_rust_signed_arbitrary();
    let alloy_unsigned_arb = gen_alloy_unsigned_arbitrary();
    let alloy_signed_arb = gen_alloy_signed_arbitrary();
    let fixed_bytes_arb = gen_fixed_bytes_arbitrary();

    let rust_unsigned_tests = gen_rust_unsigned_tests();
    let rust_signed_tests = gen_rust_signed_tests();
    let alloy_unsigned_tests = gen_alloy_unsigned_tests();
    let alloy_signed_tests = gen_alloy_signed_tests();
    let fixed_bytes_tests = gen_fixed_bytes_tests();

    quote! {
        // -- ARBITRARY FUNCTION GENERATORS ----------------------------------------

        #rust_unsigned_arb
        #rust_signed_arb
        #alloy_unsigned_arb
        #alloy_signed_arb
        #fixed_bytes_arb

        // -- GENERATED TESTS ------------------------------------------------------

        #rust_unsigned_tests
        #rust_signed_tests
        #alloy_unsigned_tests
        #alloy_signed_tests
        #fixed_bytes_tests
    }
}

/// Generate property tests for StorageKey ABI encoding.
pub(crate) fn gen_storage_key_tests() -> TokenStream {
    let rust_unsigned_tests = gen_rust_unsigned_storage_key_tests();
    let rust_signed_tests = gen_rust_signed_storage_key_tests();
    let bool_tests = gen_bool_storage_key_tests();
    let address_tests = gen_address_storage_key_tests();
    let u256_tests = gen_u256_storage_key_tests();
    let i256_tests = gen_i256_storage_key_tests();
    let fixed_bytes_tests = gen_fixed_bytes_storage_key_tests();
    let fixed_array_tests = gen_fixed_array_storage_key_tests();

    quote! {
        #rust_unsigned_tests
        #rust_signed_tests
        #bool_tests
        #address_tests
        #u256_tests
        #i256_tests
        #fixed_bytes_tests
        #fixed_array_tests
    }
}

fn gen_rust_unsigned_storage_key_tests() -> TokenStream {
    let sizes = [16usize, 32, 64, 128];
    let tests: Vec<_> = sizes
        .iter()
        .map(|&size| {
            let type_name = quote::format_ident!("u{size}");
            let alloy_type = quote::format_ident!("U{size}");
            let fn_name = quote::format_ident!("test_storage_key_u{size}_abi_encoding");
            let extra = quote! {
                let alloy_value = ::alloy::primitives::#alloy_type::from(value);
                let alloy_encoded = crate::storage::StorageKey::abi_encoded(&alloy_value);
                prop_assert_eq!(encoded.as_ref(), alloy_encoded.as_ref());
            };

            storage_key_abi_test(fn_name, quote! { any::<#type_name>() }, Some(extra))
        })
        .collect();

    proptest_block(500, tests)
}

fn gen_rust_signed_storage_key_tests() -> TokenStream {
    let tests: Vec<_> = RUST_INT_SIZES
        .iter()
        .map(|&size| {
            let type_name = quote::format_ident!("i{size}");
            let alloy_type = quote::format_ident!("I{size}");
            let unsigned_type = quote::format_ident!("U{size}");
            let fn_name = quote::format_ident!("test_storage_key_i{size}_abi_encoding");
            let extra = quote! {
                let alloy_unsigned = ::alloy::primitives::#unsigned_type::from_be_bytes(value.to_be_bytes());
                let alloy_value = ::alloy::primitives::#alloy_type::from_raw(alloy_unsigned);
                let alloy_encoded = crate::storage::StorageKey::abi_encoded(&alloy_value);
                prop_assert_eq!(encoded.as_ref(), alloy_encoded.as_ref());
            };

            storage_key_abi_test(fn_name, quote! { any::<#type_name>() }, Some(extra))
        })
        .collect();

    proptest_block(500, tests)
}

fn gen_bool_storage_key_tests() -> TokenStream {
    let test = storage_key_abi_test(
        quote::format_ident!("test_storage_key_bool_abi_encoding"),
        quote! { any::<bool>() },
        None,
    );

    proptest_block(500, vec![test])
}

fn gen_address_storage_key_tests() -> TokenStream {
    let test = storage_key_abi_test(
        quote::format_ident!("test_storage_key_address_abi_encoding"),
        quote! { arb_address() },
        None,
    );

    proptest_block(500, vec![test])
}

fn gen_u256_storage_key_tests() -> TokenStream {
    let test = storage_key_abi_test(
        quote::format_ident!("test_storage_key_u256_abi_encoding"),
        quote! { any::<[u64; 4]>().prop_map(::alloy::primitives::U256::from_limbs) },
        None,
    );

    proptest_block(500, vec![test])
}

fn gen_i256_storage_key_tests() -> TokenStream {
    let test = storage_key_abi_test(
        quote::format_ident!("test_storage_key_i256_abi_encoding"),
        quote! {
            any::<[u64; 4]>().prop_map(|limbs| {
                ::alloy::primitives::I256::from_raw(::alloy::primitives::U256::from_limbs(limbs))
            })
        },
        None,
    );

    proptest_block(500, vec![test])
}

fn gen_fixed_bytes_storage_key_tests() -> TokenStream {
    let tests: Vec<_> = FIXED_BYTES_SIZES
        .iter()
        .map(|&size| {
            let fn_name = quote::format_ident!("test_storage_key_fixed_bytes_{size}_abi_encoding");
            let arb_fn = quote::format_ident!("arb_fixed_bytes_{size}");

            storage_key_abi_test(fn_name, quote! { #arb_fn() }, None)
        })
        .collect();

    proptest_block(500, tests)
}

fn gen_fixed_array_storage_key_tests() -> TokenStream {
    let mut tests = Vec::new();
    tests.push(storage_key_abi_test(
        quote::format_ident!("test_storage_key_array_address_len_4_abi_encoding"),
        quote! { prop::array::uniform4(arb_address()) },
        None,
    ));

    for size in [16usize, 32, 64, 128] {
        let type_name = quote::format_ident!("u{size}");
        let alloy_type = quote::format_ident!("U{size}");
        let fn_name = quote::format_ident!("test_storage_key_array_u{size}_len_4_abi_encoding");
        let extra = quote! {
            let alloy_value = value.map(|v| ::alloy::primitives::#alloy_type::from(v));
            let alloy_encoded = crate::storage::StorageKey::abi_encoded(&alloy_value);
            prop_assert_eq!(encoded.as_ref(), alloy_encoded.as_ref());
        };

        tests.push(storage_key_abi_test(
            fn_name,
            quote! { prop::array::uniform4(any::<#type_name>()) },
            Some(extra),
        ));
    }

    for size in [16usize, 32, 64, 128] {
        let type_name = quote::format_ident!("i{size}");
        let alloy_type = quote::format_ident!("I{size}");
        let fn_name = quote::format_ident!("test_storage_key_array_i{size}_len_4_abi_encoding");
        let extra = quote! {
            let alloy_value =
                value.map(|v| ::alloy::primitives::#alloy_type::from_be_bytes(v.to_be_bytes()));
            let alloy_encoded = crate::storage::StorageKey::abi_encoded(&alloy_value);
            prop_assert_eq!(encoded.as_ref(), alloy_encoded.as_ref());
        };

        tests.push(storage_key_abi_test(
            fn_name,
            quote! { prop::array::uniform4(any::<#type_name>()) },
            Some(extra),
        ));
    }

    proptest_block(200, tests)
}

/// Generate arbitrary functions for Rust unsigned integers
fn gen_rust_unsigned_arbitrary() -> TokenStream {
    quote! {}
}

/// Generate arbitrary functions for Rust signed integers
fn gen_rust_signed_arbitrary() -> TokenStream {
    quote! {}
}

/// Generate arbitrary functions for Alloy unsigned integers
fn gen_alloy_unsigned_arbitrary() -> TokenStream {
    let funcs: Vec<_> = ALLOY_INT_SIZES
        .iter()
        .map(|&size| {
            let type_name = quote::format_ident!("U{size}");
            let fn_name = quote::format_ident!("arb_u{size}_alloy");

            quote! {
                fn #fn_name() -> impl Strategy<Value = ::alloy::primitives::#type_name> {
                    Just(()).prop_perturb(|_, _| ::alloy::primitives::#type_name::random())
                }
            }
        })
        .collect();

    quote! { #(#funcs)* }
}

/// Generate arbitrary functions for Alloy signed integers
fn gen_alloy_signed_arbitrary() -> TokenStream {
    let funcs: Vec<_> = ALLOY_INT_SIZES
        .iter()
        .flat_map(|&size| {
            let signed_type = quote::format_ident!("I{size}");
            let unsigned_type = quote::format_ident!("U{size}");
            let arb_any_fn = quote::format_ident!("arb_i{size}_alloy");
            let arb_pos_fn = quote::format_ident!("arb_positive_i{size}_alloy");
            let arb_neg_fn = quote::format_ident!("arb_negative_i{size}_alloy");
            let arb_unsigned_fn = quote::format_ident!("arb_u{size}_alloy");

            vec![
                // Any signed value
                quote! {
                    fn #arb_any_fn() -> impl Strategy<Value = ::alloy::primitives::#signed_type> {
                        #arb_unsigned_fn().prop_map(|u| ::alloy::primitives::#signed_type::from_raw(u))
                    }
                },
                // Positive values only
                quote! {
                    fn #arb_pos_fn() -> impl Strategy<Value = ::alloy::primitives::#signed_type> {
                        #arb_unsigned_fn().prop_map(|u| {
                            ::alloy::primitives::#signed_type::from_raw(
                                u & (::alloy::primitives::#unsigned_type::MAX >> 1)
                            )
                        })
                    }
                },
                // Negative values only
                quote! {
                    fn #arb_neg_fn() -> impl Strategy<Value = ::alloy::primitives::#signed_type> {
                        #arb_pos_fn().prop_map(|i| -i)
                    }
                },
            ]
        })
        .collect();

    quote! { #(#funcs)* }
}

/// Generate arbitrary functions for FixedBytes
fn gen_fixed_bytes_arbitrary() -> TokenStream {
    let funcs: Vec<_> = FIXED_BYTES_SIZES
        .iter()
        .map(|&size| {
            let fn_name = quote::format_ident!("arb_fixed_bytes_{size}");

            quote! {
                fn #fn_name() -> impl Strategy<Value = ::alloy::primitives::FixedBytes<#size>> {
                    Just(()).prop_perturb(|_, _| ::alloy::primitives::FixedBytes::<#size>::random())
                }
            }
        })
        .collect();

    quote! { #(#funcs)* }
}

/// Generate complete proptest! block for Rust unsigned integers
fn gen_rust_unsigned_tests() -> TokenStream {
    let tests: Vec<_> = RUST_INT_SIZES
        .iter()
        .map(|&size| {
            let type_name = quote::format_ident!("u{size}");
            let test_name = quote::format_ident!("test_u{size}_storage_roundtrip");
            let label = format!("u{size}");

            quote! {
                #[test]
                fn #test_name(value in any::<#type_name>(), base_slot in arb_safe_slot()) {
                    let (mut storage, address) = setup_storage();
                    StorageCtx::enter(&mut storage, || {
                        let mut slot = Slot::<#type_name>::new(base_slot, address);

                        // Verify store → load roundtrip
                        slot.write(value).unwrap();
                        let loaded = slot.read().unwrap();
                        assert_eq!(value, loaded, concat!(#label, " roundtrip failed"));

                        // Verify delete works
                        slot.delete().unwrap();
                        let after_delete = slot.read().unwrap();
                        assert_eq!(after_delete, 0, concat!(#label, " not zero after delete"));

                        // EVM word roundtrip
                        let word = value.to_word();
                        let recovered = #type_name::from_word(word).unwrap();
                        assert_eq!(value, recovered, concat!(#label, " EVM word roundtrip failed"));

                    });
                }
            }
        })
        .collect();

    quote! {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(500))]

            #(#tests)*
        }
    }
}

/// Generate complete proptest! block for Rust signed integers
fn gen_rust_signed_tests() -> TokenStream {
    let tests: Vec<_> = RUST_INT_SIZES
        .iter()
        .flat_map(|&size| {
            let type_name = quote::format_ident!("i{size}");
            let pos_test_name = quote::format_ident!("test_i{size}_positive_storage_roundtrip");
            let neg_test_name = quote::format_ident!("test_i{size}_negative_storage_roundtrip");
            let label = format!("i{size}");

            vec![
                // Positive test
                quote! {
                    #[test]
                    fn #pos_test_name(value in 0 as #type_name..=#type_name::MAX, base_slot in arb_safe_slot()) {
                        let (mut storage, address) = setup_storage();
                        StorageCtx::enter(&mut storage, || {
                            let mut slot = Slot::<#type_name>::new(base_slot, address);

                            // Verify store → load roundtrip
                            slot.write(value).unwrap();
                            let loaded = slot.read().unwrap();
                            assert_eq!(value, loaded, concat!(#label, " positive roundtrip failed"));

                            // Verify delete works
                            slot.delete().unwrap();
                            let after_delete = slot.read().unwrap();
                            assert_eq!(after_delete, 0, concat!(#label, " not zero after delete"));

                            // EVM word roundtrip
                            let word = value.to_word();
                            let recovered = #type_name::from_word(word).unwrap();
                            assert_eq!(value, recovered, concat!(#label, " positive EVM word roundtrip failed"));
                        });
                    }
                },
                // Negative test
                quote! {
                    #[test]
                    fn #neg_test_name(value in #type_name::MIN..0 as #type_name, base_slot in arb_safe_slot()) {
                        let (mut storage, address) = setup_storage();
                        StorageCtx::enter(&mut storage, || {
                            let mut slot = Slot::<#type_name>::new(base_slot, address);

                            // Verify store → load roundtrip
                            slot.write(value).unwrap();
                            let loaded = slot.read().unwrap();
                            assert_eq!(value, loaded, concat!(#label, " negative roundtrip failed"));

                            // Verify delete works
                            slot.delete().unwrap();
                            let after_delete = slot.read().unwrap();
                            assert_eq!(after_delete, 0, concat!(#label, " not zero after delete"));

                            // EVM word roundtrip
                            let word = value.to_word();
                            let recovered = #type_name::from_word(word).unwrap();
                            assert_eq!(value, recovered, concat!(#label, " negative EVM word roundtrip failed"));
                        });
                    }
                },
            ]
        })
        .collect();

    quote! {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(500))]

            #(#tests)*
        }
    }
}

/// Generate complete proptest! block for Alloy unsigned integers
fn gen_alloy_unsigned_tests() -> TokenStream {
    let tests: Vec<_> = ALLOY_INT_SIZES
        .iter()
        .map(|&size| {
            let type_name = quote::format_ident!("U{size}");
            let test_name = quote::format_ident!("test_u{size}_alloy_storage_roundtrip");
            let arb_fn = quote::format_ident!("arb_u{size}_alloy");
            let label = format!("U{size}");

            quote! {
                #[test]
                fn #test_name(value in #arb_fn(), base_slot in arb_safe_slot()) {
                    let (mut storage, address) = setup_storage();
                    StorageCtx::enter(&mut storage, || {
                        let mut slot = Slot::<::alloy::primitives::#type_name>::new(base_slot, address);

                        // Verify store → load roundtrip
                        slot.write(value).unwrap();
                        let loaded = slot.read().unwrap();
                        assert_eq!(value, loaded, concat!(#label, " roundtrip failed"));

                        // Verify delete works
                        slot.delete().unwrap();
                        let after_delete = slot.read().unwrap();
                        assert_eq!(
                            after_delete,
                            ::alloy::primitives::#type_name::ZERO,
                            concat!(#label, " not zero after delete")
                        );

                        // EVM word roundtrip
                        let word = value.to_word();
                        let recovered = ::alloy::primitives::#type_name::from_word(word).unwrap();
                        assert_eq!(value, recovered, concat!(#label, " EVM word roundtrip failed"));

                    });
                }
            }
        })
        .collect();

    quote! {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(500))]

            #(#tests)*
        }
    }
}

/// Generate complete proptest! block for Alloy signed integers
fn gen_alloy_signed_tests() -> TokenStream {
    let tests: Vec<_> = ALLOY_INT_SIZES
        .iter()
        .flat_map(|&size| {
            let type_name = quote::format_ident!("I{size}");
            let pos_test_name = quote::format_ident!("test_i{size}_alloy_positive_storage_roundtrip");
            let neg_test_name = quote::format_ident!("test_i{size}_alloy_negative_storage_roundtrip");
            let arb_pos_fn = quote::format_ident!("arb_positive_i{size}_alloy");
            let arb_neg_fn = quote::format_ident!("arb_negative_i{size}_alloy");
            let label = format!("I{size}");

            vec![
                // Positive test
                quote! {
                    #[test]
                    fn #pos_test_name(value in #arb_pos_fn(), base_slot in arb_safe_slot()) {
                        let (mut storage, address) = setup_storage();
                        StorageCtx::enter(&mut storage, || {
                            let mut slot = Slot::<::alloy::primitives::#type_name>::new(base_slot, address);

                            // Verify store → load roundtrip
                            slot.write(value).unwrap();
                            let loaded = slot.read().unwrap();
                            assert_eq!(value, loaded, concat!(#label, " positive roundtrip failed"));

                            // Verify delete works
                            slot.delete().unwrap();
                            let after_delete = slot.read().unwrap();
                            assert_eq!(
                                after_delete,
                                ::alloy::primitives::#type_name::ZERO,
                                concat!(#label, " not zero after delete")
                            );

                            // EVM word roundtrip
                            let word = value.to_word();
                            let recovered = ::alloy::primitives::#type_name::from_word(word).unwrap();
                            assert_eq!(value, recovered, concat!(#label, " positive EVM word roundtrip failed"));
                        });
                    }
                },
                // Negative test
                quote! {
                    #[test]
                    fn #neg_test_name(value in #arb_neg_fn(), base_slot in arb_safe_slot()) {
                        let (mut storage, address) = setup_storage();
                        StorageCtx::enter(&mut storage, || {
                            let mut slot = Slot::<::alloy::primitives::#type_name>::new(base_slot, address);

                            // Verify store → load roundtrip
                            slot.write(value).unwrap();
                            let loaded = slot.read().unwrap();
                            assert_eq!(value, loaded, concat!(#label, " negative roundtrip failed"));

                            // Verify delete works
                            slot.delete().unwrap();
                            let after_delete = slot.read().unwrap();
                            assert_eq!(
                                after_delete,
                                ::alloy::primitives::#type_name::ZERO,
                                concat!(#label, " not zero after delete")
                            );

                            // EVM word roundtrip
                            let word = value.to_word();
                            let recovered = ::alloy::primitives::#type_name::from_word(word).unwrap();
                            assert_eq!(value, recovered, concat!(#label, " negative EVM word roundtrip failed"));
                        });
                    }
                },
            ]
        })
        .collect();

    quote! {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(500))]

            #(#tests)*
        }
    }
}

/// Generate complete proptest! block for FixedBytes
fn gen_fixed_bytes_tests() -> TokenStream {
    let tests: Vec<_> = FIXED_BYTES_SIZES
        .iter()
        .map(|&size| {
            let test_name = quote::format_ident!("test_fixed_bytes_{size}_storage_roundtrip");
            let arb_fn = quote::format_ident!("arb_fixed_bytes_{size}");

            quote! {
                #[test]
                fn #test_name(value in #arb_fn(), base_slot in arb_safe_slot()) {
                    let (mut storage, address) = setup_storage();
                    StorageCtx::enter(&mut storage, || {
                        let mut slot = Slot::<::alloy::primitives::FixedBytes<#size>>::new(base_slot, address);

                        // Verify store → load roundtrip
                        slot.write(value).unwrap();
                        let loaded = slot.read().unwrap();
                        assert_eq!(
                            value, loaded,
                            concat!("FixedBytes<", stringify!(#size), "> roundtrip failed")
                        );

                        // Verify delete works
                        slot.delete().unwrap();
                        let after_delete = slot.read().unwrap();
                        assert_eq!(
                            after_delete,
                            ::alloy::primitives::FixedBytes::<#size>::ZERO,
                            concat!("FixedBytes<", stringify!(#size), "> not zero after delete")
                        );

                        // EVM word roundtrip
                        let word = value.to_word();
                        let recovered = ::alloy::primitives::FixedBytes::<#size>::from_word(word).unwrap();
                        assert_eq!(
                            value, recovered,
                            concat!("FixedBytes<", stringify!(#size), "> EVM word roundtrip failed")
                        );

                    });
                }
            }
        })
        .collect();

    quote! {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(500))]

            #(#tests)*
        }
    }
}
