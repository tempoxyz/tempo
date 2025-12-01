//! Code generation for storage trait property tests.
//!
//! This module generates comprehensive property tests for all supported storage types,
//! including complete test function implementations.

use proc_macro2::TokenStream;
use quote::quote;

use crate::storable_primitives::{ALLOY_INT_SIZES, RUST_INT_SIZES};
const FIXED_BYTES_SIZES: &[usize] = &[
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32,
];

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
                fn #test_name(value in any::<#type_name>(), slot in arb_safe_slot()) {
                    let mut contract = setup_test_contract();

                    // Storage roundtrip
                    value.store(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                    let loaded = #type_name::load(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                    assert_eq!(value, loaded, concat!(#label, " storage roundtrip failed"));

                    // Delete
                    #type_name::delete(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                    let after_delete = #type_name::load(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                    assert_eq!(after_delete, 0, concat!(#label, " not zero after delete"));

                    // EVM words roundtrip
                    let words = value.to_evm_words()?;
                    let recovered = #type_name::from_evm_words(words)?;
                    assert_eq!(value, recovered, concat!(#label, " EVM words roundtrip failed"));
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
                    fn #pos_test_name(value in 0 as #type_name..=#type_name::MAX, slot in arb_safe_slot()) {
                        let mut contract = setup_test_contract();

                        // Storage roundtrip
                        value.store(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                        let loaded = #type_name::load(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                        assert_eq!(value, loaded, concat!(#label, " positive storage roundtrip failed"));

                        // Delete
                        #type_name::delete(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                        let after_delete = #type_name::load(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                        assert_eq!(after_delete, 0, concat!(#label, " not zero after delete"));

                        // EVM words roundtrip
                        let words = value.to_evm_words()?;
                        let recovered = #type_name::from_evm_words(words)?;
                        assert_eq!(value, recovered, concat!(#label, " positive EVM words roundtrip failed"));
                    }
                },
                // Negative test
                quote! {
                    #[test]
                    fn #neg_test_name(value in #type_name::MIN..0 as #type_name, slot in arb_safe_slot()) {
                        let mut contract = setup_test_contract();

                        // Storage roundtrip
                        value.store(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                        let loaded = #type_name::load(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                        assert_eq!(value, loaded, concat!(#label, " negative storage roundtrip failed"));

                        // Delete
                        #type_name::delete(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                        let after_delete = #type_name::load(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                        assert_eq!(after_delete, 0, concat!(#label, " not zero after delete"));

                        // EVM words roundtrip
                        let words = value.to_evm_words()?;
                        let recovered = #type_name::from_evm_words(words)?;
                        assert_eq!(value, recovered, concat!(#label, " negative EVM words roundtrip failed"));
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
                fn #test_name(value in #arb_fn(), slot in arb_safe_slot()) {
                    let mut contract = setup_test_contract();

                    // Storage roundtrip
                    value.store(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                    let loaded = ::alloy::primitives::#type_name::load(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                    assert_eq!(value, loaded, concat!(#label, " storage roundtrip failed"));

                    // Delete
                    ::alloy::primitives::#type_name::delete(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                    let after_delete = ::alloy::primitives::#type_name::load(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                    assert_eq!(
                        after_delete,
                        ::alloy::primitives::#type_name::ZERO,
                        concat!(#label, " not zero after delete")
                    );

                    // EVM words roundtrip
                    let words = value.to_evm_words()?;
                    let recovered = ::alloy::primitives::#type_name::from_evm_words(words)?;
                    assert_eq!(value, recovered, concat!(#label, " EVM words roundtrip failed"));
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
                    fn #pos_test_name(value in #arb_pos_fn(), slot in arb_safe_slot()) {
                        let mut contract = setup_test_contract();

                        // Storage roundtrip
                        value.store(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                        let loaded = ::alloy::primitives::#type_name::load(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                        assert_eq!(value, loaded, concat!(#label, " positive storage roundtrip failed"));

                        // Delete
                        ::alloy::primitives::#type_name::delete(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                        let after_delete = ::alloy::primitives::#type_name::load(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                        assert_eq!(
                            after_delete,
                            ::alloy::primitives::#type_name::ZERO,
                            concat!(#label, " not zero after delete")
                        );

                        // EVM words roundtrip
                        let words = value.to_evm_words()?;
                        let recovered = ::alloy::primitives::#type_name::from_evm_words(words)?;
                        assert_eq!(value, recovered, concat!(#label, " positive EVM words roundtrip failed"));
                    }
                },
                // Negative test
                quote! {
                    #[test]
                    fn #neg_test_name(value in #arb_neg_fn(), slot in arb_safe_slot()) {
                        let mut contract = setup_test_contract();

                        // Storage roundtrip
                        value.store(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                        let loaded = ::alloy::primitives::#type_name::load(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                        assert_eq!(value, loaded, concat!(#label, " negative storage roundtrip failed"));

                        // Delete
                        ::alloy::primitives::#type_name::delete(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                        let after_delete = ::alloy::primitives::#type_name::load(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                        assert_eq!(
                            after_delete,
                            ::alloy::primitives::#type_name::ZERO,
                            concat!(#label, " not zero after delete")
                        );

                        // EVM words roundtrip
                        let words = value.to_evm_words()?;
                        let recovered = ::alloy::primitives::#type_name::from_evm_words(words)?;
                        assert_eq!(value, recovered, concat!(#label, " negative EVM words roundtrip failed"));
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
                fn #test_name(value in #arb_fn(), slot in arb_safe_slot()) {
                    let mut contract = setup_test_contract();

                    // Storage roundtrip
                    value.store(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                    let loaded = ::alloy::primitives::FixedBytes::<#size>::load(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                    assert_eq!(
                        value, loaded,
                        concat!("FixedBytes<", stringify!(#size), "> storage roundtrip failed")
                    );

                    // Delete
                    ::alloy::primitives::FixedBytes::<#size>::delete(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                    let after_delete = ::alloy::primitives::FixedBytes::<#size>::load(&mut contract, slot, crate::storage::LayoutCtx::FULL)?;
                    assert_eq!(
                        after_delete,
                        ::alloy::primitives::FixedBytes::<#size>::ZERO,
                        concat!("FixedBytes<", stringify!(#size), "> not zero after delete")
                    );

                    // EVM words roundtrip
                    let words = value.to_evm_words()?;
                    let recovered = ::alloy::primitives::FixedBytes::<#size>::from_evm_words(words)?;
                    assert_eq!(
                        value, recovered,
                        concat!("FixedBytes<", stringify!(#size), "> EVM words roundtrip failed")
                    );
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
