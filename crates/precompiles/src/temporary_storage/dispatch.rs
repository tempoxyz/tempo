//! ABI dispatch for the [`TemporaryStorage`] precompile.

use crate::{
    Precompile, charge_input_cost, dispatch, mutate_void, temporary_storage::TemporaryStorage, view,
};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::ITemporaryStorage;

impl Precompile for TemporaryStorage {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(calldata, |call| match call {
            ITemporaryStorage::ITemporaryStorageCalls {
                temporaryStore(call) =>
                    mutate_void(call, msg_sender, |sender, c| self.temporary_store(sender, c)),
                temporaryLoad(call) => view(call, |c| self.temporary_load(msg_sender, c)),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dispatch::StaticCallNotAllowed,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use alloy::{
        primitives::B256,
        sol_types::{SolCall, SolError},
    };
    use tempo_contracts::precompiles::ITemporaryStorage::ITemporaryStorageCalls;

    #[test]
    fn test_dispatch_store_load_roundtrip() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut temporary_storage = TemporaryStorage::new();
            let sender = Address::repeat_byte(0x11);
            let key = B256::repeat_byte(0x01);
            let value = B256::repeat_byte(0x02);

            let store = ITemporaryStorage::temporaryStoreCall { key, value }.abi_encode();
            let output = temporary_storage.call(&store, sender)?;
            assert!(!output.is_revert());
            assert!(output.bytes.is_empty());

            let load = ITemporaryStorage::temporaryLoadCall { key }.abi_encode();
            let output = temporary_storage.call(&load, sender)?;
            assert!(!output.is_revert());
            assert_eq!(output.bytes.as_ref(), value.as_slice());

            // Another sender's read of the same key returns zero.
            let output = temporary_storage.call(&load, Address::repeat_byte(0x22))?;
            assert!(!output.is_revert());
            assert_eq!(output.bytes.as_ref(), B256::ZERO.as_slice());
            Ok(())
        })
    }

    #[test]
    fn test_dispatch_static_call_rejects_store() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        storage.set_is_static(true);
        StorageCtx::enter(&mut storage, || {
            let mut temporary_storage = TemporaryStorage::new();
            let sender = Address::repeat_byte(0x11);
            let key = B256::repeat_byte(0x01);

            let store = ITemporaryStorage::temporaryStoreCall {
                key,
                value: B256::repeat_byte(0x02),
            }
            .abi_encode();
            let output = temporary_storage.call(&store, sender)?;
            assert!(output.is_revert());
            assert!(StaticCallNotAllowed::abi_decode(&output.bytes).is_ok());

            let load = ITemporaryStorage::temporaryLoadCall { key }.abi_encode();
            let output = temporary_storage.call(&load, sender)?;
            assert!(!output.is_revert());
            Ok(())
        })
    }

    #[test]
    fn test_temporary_storage_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut temporary_storage = TemporaryStorage::new();

            let unsupported = check_selector_coverage(
                &mut temporary_storage,
                ITemporaryStorageCalls::SELECTORS,
                "ITemporaryStorage",
                ITemporaryStorageCalls::name_by_selector,
            );

            assert_full_coverage([unsupported]);
            Ok(())
        })
    }
}
