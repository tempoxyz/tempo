//! Vec overwrite-cleanup tests.

use super::*;
use crate::storage::vec::VecHandler;
use tempo_chainspec::hardfork::TempoHardfork;

#[test]
fn test_vec_overwrite_unpacked_cleans_tail() -> error::Result<()> {
    let address = Address::random();
    let len_slot = U256::ONE;
    for &hardfork in &[TempoHardfork::T4, TempoHardfork::T5] {
        let mut storage = HashMapStorageProvider::new_with_spec(1, hardfork);
        StorageCtx::enter(&mut storage, || {
            let mut handler = VecHandler::<U256>::new(len_slot, address);

            // Seed 5 unpacked elements (U256, T::SLOTS = 1), then shrink to 2.
            handler.write(vec![
                U256::from(11),
                U256::from(22),
                U256::from(33),
                U256::from(44),
                U256::from(55),
            ])?;
            handler.write(vec![U256::from(11), U256::from(22)])?;
            assert_eq!(handler.read()?, vec![U256::from(11), U256::from(22)]);

            for (i, old) in [33u64, 44, 55].iter().enumerate() {
                let idx = (i + 2) as u64;
                let raw = Slot::<U256>::new(dyn_tail_slot(len_slot, idx), address).read()?;
                if hardfork.is_t5() {
                    assert_eq!(raw, U256::ZERO, "T5: stale element {idx} must clear");
                } else {
                    assert_eq!(raw, U256::from(*old), "T4: stale elem {idx} must persist",);
                }
            }
            error::Result::Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn test_vec_overwrite_packed_cleans_tail() -> error::Result<()> {
    let address = Address::random();
    let len_slot = U256::ONE;
    for &hardfork in &[TempoHardfork::T4, TempoHardfork::T5] {
        let mut storage = HashMapStorageProvider::new_with_spec(1, hardfork);
        StorageCtx::enter(&mut storage, || {
            let mut handler = VecHandler::<u64>::new(len_slot, address);

            // 9 u64 values -> ceil(9 * 8 / 32) = 3 slots; shrink to 3 -> 1 slot.
            let initial: Vec<u64> = (1..=9).collect();
            handler.write(initial.clone())?;
            assert_eq!(handler.read()?, initial);

            handler.write(vec![1u64, 2, 3])?;
            assert_eq!(handler.read()?, vec![1u64, 2, 3]);

            // Slots 1 and 2 (which previously held elements [4..9]) fell off the tail.
            for slot_idx in 1..3 {
                let raw = Slot::<U256>::new(dyn_tail_slot(len_slot, slot_idx), address).read()?;
                if hardfork.is_t5() {
                    assert_eq!(raw, U256::ZERO, "T5: stale slot {slot_idx} must clear");
                } else {
                    assert_ne!(raw, U256::ZERO, "T4: stale slot {slot_idx} must persist",);
                }
            }
            error::Result::Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn test_t5_vec_push_skips_cleanup() -> error::Result<()> {
    let address = Address::random();
    let len_slot = U256::ONE;
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
    StorageCtx::enter(&mut storage, || {
        let mut handler = VecHandler::<String>::new(len_slot, address);
        handler.write(vec!["1".to_string(), "2".to_string(), "3".to_string()])?;

        StorageCtx.reset_counters();
        handler.push("4".to_string())?;
        assert_eq!(StorageCtx.counter_sload(), 1, "push must only SLOAD length");
        assert_eq!(StorageCtx.counter_sstore(), 2, "push: element + length");
        Ok(())
    })
}
