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

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);

    StorageCtx::enter(&mut storage, || {
        // Verify actual slot assignments
        assert_eq!(layout.field_a.slot(), U256::ZERO);
        assert_eq!(layout.small_array.base_slot(), U256::from(10));
        assert_eq!(layout.field_b.slot(), U256::ONE);
        assert_eq!(layout.large_array.base_slot(), U256::from(20));
        assert_eq!(layout.field_b.slot(), U256::ONE);
        assert_eq!(layout.field_c.slot(), U256::from(2));
        assert_eq!(layout.auto_array.base_slot(), U256::from(3));
        assert_eq!(layout.field_d.slot(), U256::from(6));

        // Verify slots module
        assert_eq!(slots::FIELD_A, U256::from(0));
        assert_eq!(slots::SMALL_ARRAY, U256::from(10));
        assert_eq!(slots::FIELD_B, U256::ONE);
        assert_eq!(slots::LARGE_ARRAY, U256::from(20));
        assert_eq!(slots::FIELD_C, U256::from(2));
        assert_eq!(slots::AUTO_ARRAY, U256::from(3));
        assert_eq!(slots::FIELD_D, U256::from(6));

        // Store data
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

        layout.field_a.write(U256::ONE).unwrap();
        layout.small_array.write(small_array).unwrap();
        layout.field_b.write(U256::from(2)).unwrap();
        layout.large_array.write(large_array).unwrap();
        layout.field_c.write(U256::from(3)).unwrap();
        layout.auto_array.write(auto_array).unwrap();
        layout.field_d.write(U256::from(4)).unwrap();

        // Verify data is properly stored
        assert_eq!(layout.field_a.read().unwrap(), U256::ONE);
        assert_eq!(layout.small_array.read().unwrap(), small_array);
        assert_eq!(layout.field_b.read().unwrap(), U256::from(2));
        assert_eq!(layout.large_array.read().unwrap(), large_array);
        assert_eq!(layout.field_c.read().unwrap(), U256::from(3));
        assert_eq!(layout.auto_array.read().unwrap(), auto_array);
        assert_eq!(layout.field_d.read().unwrap(), U256::from(4));

        // Test individual element access
        layout.large_array[1].delete().unwrap();
        layout.large_array[2].write(U256::from(222)).unwrap();
        assert_eq!(layout.large_array[0].read().unwrap(), U256::from(100));
        assert_eq!(layout.large_array[1].read().unwrap(), U256::ZERO);
        assert_eq!(layout.large_array[2].read().unwrap(), U256::from(222));

        // Test delete
        layout.large_array.delete().unwrap();
        layout.auto_array.delete().unwrap();

        // Verify array slots are zeroed
        assert_eq!(layout.large_array.read().unwrap(), <[U256; 5]>::default());
        assert_eq!(layout.auto_array.read().unwrap(), <[Address; 3]>::default());

        // Verify other fields unchanged
        assert_eq!(layout.field_a.read().unwrap(), U256::ONE);
        assert_eq!(layout.small_array.read().unwrap(), small_array);
        assert_eq!(layout.field_b.read().unwrap(), U256::from(2));
        assert_eq!(layout.field_c.read().unwrap(), U256::from(3));
        assert_eq!(layout.field_d.read().unwrap(), U256::from(4));

        Ok::<(), tempo_precompiles::error::TempoPrecompileError>(())
    })
    .unwrap()
}

#[test]
fn test_array_element_access() {
    #[contract]
    pub struct Layout {
        pub small_array: [u8; 32],  // Packed storage
        pub large_array: [U256; 5], // Unpacked storage
    }

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);

    StorageCtx::enter(&mut storage, || {
        // Test packed array element access (u8 elements, T::BYTES = 1 <= 16)
        let small_data = [42u8; 32];
        layout.small_array.write(small_data).unwrap();

        // Read individual elements from packed array
        assert_eq!(layout.small_array[0].read().unwrap(), 42_u8);
        assert_eq!(layout.small_array[15].read().unwrap(), 42_u8);
        assert_eq!(layout.small_array[31].read().unwrap(), 42_u8);

        // Write individual element in packed array
        layout.small_array[10].write(99u8).unwrap();
        layout.small_array[11].delete().unwrap();
        assert_eq!(layout.small_array[9].read().unwrap(), 42_u8);
        assert_eq!(layout.small_array[10].read().unwrap(), 99_u8);
        assert_eq!(layout.small_array[11].read().unwrap(), 0_u8);

        // Test unpacked array element access (U256 elements, T::BYTES = 32 > 16)
        let large_data = [
            U256::from(100),
            U256::from(200),
            U256::from(300),
            U256::from(400),
            U256::from(500),
        ];
        layout.large_array.write(large_data).unwrap();

        // Read individual elements from unpacked array
        assert_eq!(layout.large_array[0].read().unwrap(), U256::from(100));
        assert_eq!(layout.large_array[2].read().unwrap(), U256::from(300));
        assert_eq!(layout.large_array[4].read().unwrap(), U256::from(500));

        // Write individual element in unpacked array
        layout.large_array[2].write(U256::from(999)).unwrap();
        assert_eq!(layout.large_array[2].read().unwrap(), U256::from(999));
        // Verify other elements unchanged
        assert_eq!(layout.large_array[1].read().unwrap(), U256::from(200));
        assert_eq!(
            layout.large_array[3].unwrap().read().unwrap(),
            U256::from(400)
        );

        // Delete individual element in unpacked array
        layout.large_array[2].delete().unwrap();
        assert_eq!(layout.large_array[2].read().unwrap(), U256::ZERO);
        assert_eq!(layout.large_array[1].read().unwrap(), U256::from(200));

        Ok::<(), tempo_precompiles::error::TempoPrecompileError>(())
    })
    .unwrap()
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

        let (mut storage, address) = setup_storage();
        let mut layout = Layout::__new(address);

        StorageCtx::enter(&mut storage, || {
            // Store random values
            layout.field_a.write(field_a_val)?;
        layout.small_array.write(small_array)?;
        layout.field_b.write(field_b_val)?;
        layout.large_array.write(large_array)?;
        layout.field_c.write(field_c_val)?;

        // Roundtrip property
        prop_assert_eq!(layout.field_a.read()?, field_a_val);
        prop_assert_eq!(layout.small_array.read()?, small_array);
        prop_assert_eq!(layout.field_b.read()?, field_b_val);
        prop_assert_eq!(layout.large_array.read()?, large_array);
        prop_assert_eq!(layout.field_c.read()?, field_c_val);

        // Test individual element access
        prop_assert_eq!(layout.large_array[2].read()?, large_array[2]);
        layout.small_array[5].write(small_array[5])?;
        prop_assert_eq!(layout.small_array[5].read()?, small_array[5]);

        // Delete property for large_array
        layout.large_array.delete()?;
        let default_array = [U256::ZERO; 5];
        prop_assert_eq!(layout.large_array.read()?, default_array);

            // Isolation: other fields unchanged
            prop_assert_eq!(layout.field_a.read()?, field_a_val);
            prop_assert_eq!(layout.small_array.read()?, small_array);
            prop_assert_eq!(layout.field_b.read()?, field_b_val);
            prop_assert_eq!(layout.field_c.read()?, field_c_val);

            Ok(())
        })?;
    }
}
