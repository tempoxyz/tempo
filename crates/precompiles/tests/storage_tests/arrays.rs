//! Fixed-size array storage tests.

use super::*;

#[test]
fn test_array_storage() {
    use alloy::primitives::address;

    #[contract]
    pub struct Layout {
        pub field_a: U256, // Auto: slot 0
        #[slot(10)]
        pub small_array: [u8; 32], // Explicit: slot 10 (single-slot, packed)
        pub field_b: U256, // Auto: slot 1
        #[slot(20)]
        pub large_array: [U256; 5], // Explicit: slots 20-24 (multi-slot)
        pub field_c: U256, // Auto: slot 2
        pub auto_array: [Address; 3], // Auto: slots 3-5 (multi-slot)
        pub field_d: U256, // Auto: slot 6 (after multi-slot array)
    }

    let mut s = setup_storage();

    let small_array = [42u8; 32];
    let large_array = [
        U256::from(100),
        U256::from(200),
        U256::from(300),
        U256::from(400),
        U256::from(500),
    ];
    let auto_array = [
        address!("0x0000000000000000000000000000000000000011"),
        address!("0x0000000000000000000000000000000000000022"),
        address!("0x0000000000000000000000000000000000000033"),
    ];

    // Store data
    {
        let mut layout = Layout::_new(s.address, s.storage());
        layout.sstore_field_a(U256::ONE).unwrap();
        layout.sstore_small_array(small_array).unwrap();
        layout.sstore_field_b(U256::from(2)).unwrap();
        layout.sstore_large_array(large_array).unwrap();
        layout.sstore_field_c(U256::from(3)).unwrap();
        layout.sstore_auto_array(auto_array).unwrap();
        layout.sstore_field_d(U256::from(4)).unwrap();

        // Verify getters
        assert_eq!(layout.sload_field_a().unwrap(), U256::ONE);
        assert_eq!(layout.sload_small_array().unwrap(), small_array);
        assert_eq!(layout.sload_field_b().unwrap(), U256::from(2));
        assert_eq!(layout.sload_large_array().unwrap(), large_array);
        assert_eq!(layout.sload_field_c().unwrap(), U256::from(3));
        assert_eq!(layout.sload_auto_array().unwrap(), auto_array);
        assert_eq!(layout.sload_field_d().unwrap(), U256::from(4));
    }

    // Verify actual slot assignments
    assert_eq!(s.storage.sload(s.address, U256::from(0)), Ok(U256::ONE)); // field_a

    // small_array is packed into slot 10
    let expected_small = U256::from_be_bytes(small_array);
    assert_eq!(
        s.storage.sload(s.address, U256::from(10)),
        Ok(expected_small)
    );

    assert_eq!(s.storage.sload(s.address, U256::ONE), Ok(U256::from(2))); // field_b

    // large_array occupies slots 20-24
    assert_eq!(
        s.storage.sload(s.address, U256::from(20)),
        Ok(U256::from(100))
    );
    assert_eq!(
        s.storage.sload(s.address, U256::from(21)),
        Ok(U256::from(200))
    );
    assert_eq!(
        s.storage.sload(s.address, U256::from(22)),
        Ok(U256::from(300))
    );
    assert_eq!(
        s.storage.sload(s.address, U256::from(23)),
        Ok(U256::from(400))
    );
    assert_eq!(
        s.storage.sload(s.address, U256::from(24)),
        Ok(U256::from(500))
    );

    assert_eq!(s.storage.sload(s.address, U256::from(2)), Ok(U256::from(3))); // field_c

    // auto_array occupies slots 3-5
    assert_eq!(
        s.storage.sload(s.address, U256::from(3)),
        Ok(U256::from(0x11))
    );
    assert_eq!(
        s.storage.sload(s.address, U256::from(4)),
        Ok(U256::from(0x22))
    );
    assert_eq!(
        s.storage.sload(s.address, U256::from(5)),
        Ok(U256::from(0x33))
    );

    assert_eq!(s.storage.sload(s.address, U256::from(6)), Ok(U256::from(4))); // field_d

    // Verify slots module
    assert_eq!(slots::FIELD_A, U256::from(0));
    assert_eq!(slots::SMALL_ARRAY, U256::from(10));
    assert_eq!(slots::FIELD_B, U256::ONE);
    assert_eq!(slots::LARGE_ARRAY, U256::from(20));
    assert_eq!(slots::FIELD_C, U256::from(2));
    assert_eq!(slots::AUTO_ARRAY, U256::from(3));
    assert_eq!(slots::FIELD_D, U256::from(6));

    // Test delete
    {
        let mut layout = Layout::_new(s.address, s.storage());
        layout.clear_large_array().unwrap();
        layout.clear_auto_array().unwrap();
    }

    // Verify array slots are zeroed
    for slot in 20..=24 {
        assert_eq!(s.storage.sload(s.address, U256::from(slot)), Ok(U256::ZERO));
    }
    for slot in 3..=5 {
        assert_eq!(s.storage.sload(s.address, U256::from(slot)), Ok(U256::ZERO));
    }

    // Verify other fields unchanged
    assert_eq!(s.storage.sload(s.address, U256::from(0)), Ok(U256::ONE)); // field_a
    assert_eq!(
        s.storage.sload(s.address, U256::from(10)),
        Ok(expected_small)
    ); // small_array
    assert_eq!(s.storage.sload(s.address, U256::ONE), Ok(U256::from(2))); // field_b
    assert_eq!(s.storage.sload(s.address, U256::from(2)), Ok(U256::from(3))); // field_c
    assert_eq!(s.storage.sload(s.address, U256::from(6)), Ok(U256::from(4))); // field_d
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Property test for array storage
    #[test]
    fn proptest_array_storage(
        field_a_val in arb_u256(),
        small_array in arb_small_array(),
        field_b_val in arb_u256(),
        large_array in arb_large_u256_array(),
        field_c_val in arb_u256(),
    ) {
        #[contract]
        pub struct Layout {
            pub field_a: U256, // Auto: slot 0
            #[slot(10)]
            pub small_array: [u8; 32], // Explicit: slot 10 (single-slot, packed)
            pub field_b: U256, // Auto: slot 1
            #[slot(20)]
            pub large_array: [U256; 5], // Explicit: slots 20-24 (multi-slot)
            pub field_c: U256, // Auto: slot 2
        }

        let mut s = setup_storage();

        {
            let mut layout = Layout::_new(s.address, s.storage());

            // Store random values
            layout.sstore_field_a(field_a_val)?;
            layout.sstore_small_array(small_array)?;
            layout.sstore_field_b(field_b_val)?;
            layout.sstore_large_array(large_array)?;
            layout.sstore_field_c(field_c_val)?;

            // Roundtrip property
            prop_assert_eq!(layout.sload_field_a()?, field_a_val);
            prop_assert_eq!(layout.sload_small_array()?, small_array);
            prop_assert_eq!(layout.sload_field_b()?, field_b_val);
            prop_assert_eq!(layout.sload_large_array()?, large_array);
            prop_assert_eq!(layout.sload_field_c()?, field_c_val);

            // Delete property for large_array
            layout.clear_large_array()?;
            let default_array = [U256::ZERO; 5];
            prop_assert_eq!(layout.sload_large_array()?, default_array);

            // Isolation: other fields unchanged
            prop_assert_eq!(layout.sload_field_a()?, field_a_val);
            prop_assert_eq!(layout.sload_small_array()?, small_array);
            prop_assert_eq!(layout.sload_field_b()?, field_b_val);
            prop_assert_eq!(layout.sload_field_c()?, field_c_val);
        }

        // Verify large_array slots are zeroed (slots 20-24)
        for slot in 20..=24 {
            prop_assert_eq!(s.storage.sload(s.address, U256::from(slot))?, U256::ZERO);
        }
    }
}
