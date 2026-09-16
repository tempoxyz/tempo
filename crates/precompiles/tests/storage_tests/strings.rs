//! String storage tests.

use super::*;
use tempo_chainspec::hardfork::TempoHardfork;

#[test]
fn test_string() {
    #[contract]
    pub struct Layout {
        pub one_string: String,
        pub another_string: String,
    }

    let (mut storage, address) = setup_storage();
    StorageCtx::enter(&mut storage, || {
        let mut layout = Layout::__new(address);

        // Test empty string
        layout
            .another_string
            .write(
                &mut tempo_precompiles::storage::StorageCtx::test_writable(),
                String::new(),
            )
            .unwrap();
        assert_eq!(layout.another_string.read().unwrap(), "");

        // Test short string
        let short = "Hello Tempo!".to_string();
        layout
            .one_string
            .write(
                &mut tempo_precompiles::storage::StorageCtx::test_writable(),
                short.clone(),
            )
            .unwrap();
        assert_eq!(layout.one_string.read().unwrap(), short);

        // Test max length (31 bytes)
        let short_max = "a".repeat(31);
        layout
            .one_string
            .write(
                &mut tempo_precompiles::storage::StorageCtx::test_writable(),
                short_max.clone(),
            )
            .unwrap();
        assert_eq!(layout.one_string.read().unwrap(), short_max);

        // Test long string (32 bytes)
        let long_min = "b".repeat(32);
        layout
            .one_string
            .write(
                &mut tempo_precompiles::storage::StorageCtx::test_writable(),
                long_min.clone(),
            )
            .unwrap();
        assert_eq!(layout.one_string.read().unwrap(), long_min);

        // Test long string (100 bytes)
        let long = "c".repeat(100);
        layout
            .one_string
            .write(
                &mut tempo_precompiles::storage::StorageCtx::test_writable(),
                long.clone(),
            )
            .unwrap();
        assert_eq!(layout.one_string.read().unwrap(), long);

        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    #[allow(clippy::redundant_clone)]
    fn proptest_one_string(
        str1 in arb_string(),
        str2 in arb_string()
    ) {
        #[contract]
        pub struct Layout {
            pub one_string: String,
            pub another_string: String,
        }

        let (mut storage, address) = setup_storage();
        StorageCtx::enter(&mut storage, || {
            let mut layout = Layout::__new(address);

            // Store arbitrary strings
            layout.one_string.write(&mut tempo_precompiles::storage::StorageCtx::test_writable(), str1.clone())?;
            layout.another_string.write(&mut tempo_precompiles::storage::StorageCtx::test_writable(), str2.clone())?;

            // Roundtrip property
            prop_assert_eq!(layout.one_string.read()?, str1);
            prop_assert_eq!(layout.another_string.read()?, str2.clone());

            // Delete property
            layout.one_string.delete(&mut tempo_precompiles::storage::StorageCtx::test_writable())?;
            prop_assert_eq!(layout.one_string.read()?, String::new());

            // Other field should be unaffected (isolation)
            prop_assert_eq!(layout.another_string.read()?, str2.clone());

            Ok(())
        })?;
    }
}

// -- OVERWRITE-CLEANUP TESTS --------------------------------------------------------------

#[test]
fn test_string_overwrite_long_to_short_cleans_tail() -> error::Result<()> {
    let address = Address::random();
    let base_slot = U256::ONE;
    for &hardfork in &[TempoHardfork::T4, TempoHardfork::T5] {
        let mut storage = HashMapStorageProvider::new_with_spec(1, hardfork);
        StorageCtx::enter(&mut storage, || {
            let mut handler = Slot::<String>::new(base_slot, address);

            // 100 bytes -> ceil(100/32) = 4 tail chunks.
            handler.write(
                &mut tempo_precompiles::storage::StorageCtx::test_writable(),
                "x".repeat(100),
            )?;
            handler.write(
                &mut tempo_precompiles::storage::StorageCtx::test_writable(),
                "hi".to_string(),
            )?;
            assert_eq!(handler.read()?, "hi");

            for i in 0..4 {
                let chunk = Slot::<U256>::new(dyn_tail_slot(base_slot, i), address).read()?;
                if hardfork.is_t5() {
                    assert_eq!(chunk, U256::ZERO, "T5: tail chunk {i} must clear");
                } else {
                    assert_ne!(chunk, U256::ZERO, "pre-T5: stale chunk {i} must persist");
                }
            }
            error::Result::Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn test_string_overwrite_long_to_shorter_long_cleans_only_excess() -> error::Result<()> {
    let address = Address::random();
    let base_slot = U256::ONE;
    for &hardfork in &[TempoHardfork::T4, TempoHardfork::T5] {
        let mut storage = HashMapStorageProvider::new_with_spec(1, hardfork);
        StorageCtx::enter(&mut storage, || {
            let mut handler = Slot::<String>::new(base_slot, address);

            // 200 bytes -> 7 chunks; shrink to 64 bytes -> 2 chunks.
            handler.write(
                &mut tempo_precompiles::storage::StorageCtx::test_writable(),
                "a".repeat(200),
            )?;
            let new_value = "b".repeat(64);
            handler.write(
                &mut tempo_precompiles::storage::StorageCtx::test_writable(),
                new_value.clone(),
            )?;
            assert_eq!(handler.read()?, new_value);

            // Chunks 0..2 are overwritten with new data (non-zero) on both forks.
            for i in 0..2 {
                let chunk = Slot::<U256>::new(dyn_tail_slot(base_slot, i), address).read()?;
                assert_ne!(chunk, U256::ZERO, "surviving chunk {i} must hold new data");
            }
            // Chunks 2..7 fell off the tail.
            for i in 2..7 {
                let chunk = Slot::<U256>::new(dyn_tail_slot(base_slot, i), address).read()?;
                if hardfork.is_t5() {
                    assert_eq!(chunk, U256::ZERO, "T5: stale chunk {i} must clear");
                } else {
                    assert_ne!(chunk, U256::ZERO, "pre-T5: stale chunk {i} must persist");
                }
            }
            error::Result::Ok(())
        })?;
    }
    Ok(())
}
