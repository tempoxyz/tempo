//! Epoch-scoped temporary key-value storage precompile as per [TIP-1040].
//!
//! Values are keyed by `keccak256(sender || key)` and stored in a separate account per
//! epoch (`TEMPORARY_STORAGE_ADDRESS + epoch + 1`), so data written in epoch `E` is
//! readable in epochs `E` and `E+1` and nodes can prune older epoch accounts wholesale.
//!
//! [TIP-1040]: <https://docs.tempo.xyz/protocol/tip1040>

pub mod dispatch;

pub use tempo_contracts::precompiles::ITemporaryStorage;
use tempo_precompiles_macros::contract;
use tempo_primitives::TemporaryStorageAccount;

use crate::{TEMPORARY_STORAGE_ADDRESS, error::Result};
use alloy::primitives::{Address, B256, U256, keccak256};

/// Number of blocks per TIP-1040 epoch, approximately 24 hours at 500ms slot times.
pub const EPOCH_LENGTH: u64 = 172_800;

/// Gas cost for `temporaryStore` when the slot is zero in the current epoch.
const TEMPORARY_STORE_GAS_NEW: u64 = 40_000;

/// Gas cost for `temporaryStore` when the slot is nonzero in the current epoch and cold
/// (`COLD_SLOAD_COST` + `SSTORE_RESET_GAS`).
const TEMPORARY_STORE_GAS_EXISTING_COLD: u64 = 2_100 + 5_000;

/// Gas cost for `temporaryStore` when the slot is nonzero in the current epoch and warm
/// (`WARM_STORAGE_READ_COST` + `SSTORE_WRITE_GAS_DELTA`).
const TEMPORARY_STORE_GAS_EXISTING_WARM: u64 = 200;

/// TIP-1040 temporary storage precompile.
///
/// The precompile address itself only hosts the dispatch logic; all values live in the
/// per-epoch [`TemporaryStorageAccount`]s. `temporaryLoad` gas follows the standard
/// EIP-2929 SLOAD pricing; `temporaryStore` uses the TIP-1040 pricing above, metered by
/// this precompile on top of the unmetered [`temporary_sstore`](crate::storage::StorageCtx::temporary_sstore).
#[contract(addr = TEMPORARY_STORAGE_ADDRESS)]
pub struct TemporaryStorage {}

impl TemporaryStorage {
    /// Initializes the temporary storage precompile.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Returns the TIP-1040 epoch containing the current block.
    pub fn current_epoch(&self) -> u64 {
        self.storage.block_number() / EPOCH_LENGTH
    }

    /// Derives the storage slot for a `(sender, key)` pair: `keccak256(sender || key)`.
    ///
    /// Unmetered, like [`Mapping`](crate::storage::Mapping) slot derivation; TIP-1040 prices
    /// the hash into the flat operation costs.
    fn slot(sender: Address, key: B256) -> U256 {
        let mut buf = [0u8; 52];
        buf[..20].copy_from_slice(sender.as_slice());
        buf[20..].copy_from_slice(key.as_slice());
        keccak256(buf).into()
    }

    /// Stores `value` at the derived slot in the current epoch's account.
    pub fn temporary_store(
        &mut self,
        sender: Address,
        call: ITemporaryStorage::temporaryStoreCall,
    ) -> Result<()> {
        let slot = Self::slot(sender, call.key);
        let account = TemporaryStorageAccount::for_epoch(self.current_epoch());

        // Pre-charge the minimum store cost before touching storage to avoid cheap useless
        // work, mirroring the metered SSTORE path.
        self.storage.deduct_gas(TEMPORARY_STORE_GAS_EXISTING_WARM)?;
        let result = self
            .storage
            .temporary_sstore(account, slot, call.value.into())?;
        let gas = if result.data.present_value.is_zero() {
            TEMPORARY_STORE_GAS_NEW
        } else if result.is_cold {
            TEMPORARY_STORE_GAS_EXISTING_COLD
        } else {
            TEMPORARY_STORE_GAS_EXISTING_WARM
        };
        self.storage
            .deduct_gas(gas - TEMPORARY_STORE_GAS_EXISTING_WARM)
    }

    /// Loads the value for the derived slot, checking the current epoch first and falling
    /// back to the previous epoch. Returns zero if the key is unset in both.
    pub fn temporary_load(
        &self,
        sender: Address,
        call: ITemporaryStorage::temporaryLoadCall,
    ) -> Result<B256> {
        let slot = Self::slot(sender, call.key);
        let epoch = self.current_epoch();

        let value = self
            .storage
            .sload(TemporaryStorageAccount::for_epoch(epoch).address(), slot)?;
        if !value.is_zero() || epoch == 0 {
            return Ok(value.into());
        }
        Ok(self
            .storage
            .sload(
                TemporaryStorageAccount::for_epoch(epoch - 1).address(),
                slot,
            )?
            .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use alloy::primitives::{address, keccak256};

    const SENDER: Address = address!("0x1111111111111111111111111111111111111111");

    fn store(sender: Address, key: B256, value: B256) -> Result<()> {
        TemporaryStorage::new()
            .temporary_store(sender, ITemporaryStorage::temporaryStoreCall { key, value })
    }

    fn load(sender: Address, key: B256) -> Result<B256> {
        TemporaryStorage::new().temporary_load(sender, ITemporaryStorage::temporaryLoadCall { key })
    }

    #[test]
    fn test_store_load_roundtrip() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let key = B256::repeat_byte(0x01);
            let value = B256::repeat_byte(0x02);

            assert_eq!(load(SENDER, key)?, B256::ZERO);

            store(SENDER, key, value)?;
            assert_eq!(load(SENDER, key)?, value);

            // Overwrites replace the previous value.
            let value2 = B256::repeat_byte(0x03);
            store(SENDER, key, value2)?;
            assert_eq!(load(SENDER, key)?, value2);
            Ok(())
        })
    }

    #[test]
    fn test_sender_isolation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let other = address!("0x2222222222222222222222222222222222222222");
            let key = B256::repeat_byte(0x01);

            store(SENDER, key, B256::repeat_byte(0xAA))?;

            assert_eq!(load(other, key)?, B256::ZERO);
            store(other, key, B256::repeat_byte(0xBB))?;
            assert_eq!(load(SENDER, key)?, B256::repeat_byte(0xAA));
            Ok(())
        })
    }

    #[test]
    fn test_value_stored_in_epoch_account() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        storage.set_block_number(5 * EPOCH_LENGTH);
        StorageCtx::enter(&mut storage, || {
            let key = B256::repeat_byte(0x01);
            store(SENDER, key, B256::repeat_byte(0x02))
        })?;

        let mut buf = [0u8; 52];
        buf[..20].copy_from_slice(SENDER.as_slice());
        buf[20..].copy_from_slice(&[0x01; 32]);
        let slot: U256 = keccak256(buf).into();

        // Epoch 5's data lives at `TEMPORARY_STORAGE_ADDRESS + 6`.
        let expected_account = address!("0x1040000000000000000000000000000000000006");
        assert_eq!(
            storage.into_storage().collect::<Vec<_>>(),
            vec![(expected_account, slot, U256::from_be_bytes([0x02; 32]))]
        );
        Ok(())
    }

    #[test]
    fn test_epoch_expiry() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let key = B256::repeat_byte(0x01);
        let value = B256::repeat_byte(0x02);

        // Write in the last block of epoch 0.
        storage.set_block_number(EPOCH_LENGTH - 1);
        StorageCtx::enter(&mut storage, || store(SENDER, key, value))?;

        // Readable throughout epoch 1 via the previous-epoch fallback; the first block
        // of epoch 1 is where the "no previous epoch" guard flips off.
        for block in [EPOCH_LENGTH, 2 * EPOCH_LENGTH - 1] {
            storage.set_block_number(block);
            StorageCtx::enter(&mut storage, || {
                assert_eq!(load(SENDER, key).unwrap(), value)
            });
        }

        // Unreachable from epoch 2 onward.
        storage.set_block_number(2 * EPOCH_LENGTH);
        StorageCtx::enter(&mut storage, || {
            assert_eq!(load(SENDER, key).unwrap(), B256::ZERO)
        });
        Ok(())
    }

    #[test]
    fn test_current_epoch_shadows_previous() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let key = B256::repeat_byte(0x01);
        let old = B256::repeat_byte(0x02);
        let new = B256::repeat_byte(0x03);

        storage.set_block_number(3 * EPOCH_LENGTH);
        StorageCtx::enter(&mut storage, || store(SENDER, key, old))?;

        storage.set_block_number(4 * EPOCH_LENGTH);
        StorageCtx::enter(&mut storage, || {
            // Fallback still returns the epoch-3 value until overwritten.
            assert_eq!(load(SENDER, key)?, old);
            store(SENDER, key, new)?;
            assert_eq!(load(SENDER, key)?, new);
            Ok(())
        })
    }

    /// Storing zero does not shadow the previous epoch's value: the fallback triggers on
    /// a zero current-epoch slot, so temporary storage has no tombstones.
    #[test]
    fn test_storing_zero_does_not_tombstone_previous_epoch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let key = B256::repeat_byte(0x01);
        let value = B256::repeat_byte(0x02);

        storage.set_block_number(3 * EPOCH_LENGTH);
        StorageCtx::enter(&mut storage, || store(SENDER, key, value))?;

        storage.set_block_number(4 * EPOCH_LENGTH);
        StorageCtx::enter(&mut storage, || {
            store(SENDER, key, B256::ZERO)?;
            assert_eq!(load(SENDER, key)?, value);
            Ok(())
        })
    }

    /// Exercises the TIP-1040 gas schedule against the journal-backed provider, which
    /// tracks warm/cold state per `(account, slot)` like production.
    #[test]
    fn test_gas_costs() -> eyre::Result<()> {
        use crate::storage::{PrecompileStorageProvider, evm::EvmPrecompileStorageProvider};
        use alloy_evm::{EthEvmFactory, EvmEnv, EvmFactory, EvmInternals};
        use revm::{
            context::{CfgEnv, ContextTr, JournalTr, TxEnv},
            database::{CacheDB, EmptyDB},
        };
        use tempo_chainspec::hardfork::TempoHardfork;
        use tempo_primitives::TempoBlockEnv;

        let mut cfg = CfgEnv::<TempoHardfork>::default();
        cfg.set_spec_and_mainnet_gas_params(TempoHardfork::T9);
        let tx = TxEnv::default();
        let block = TempoBlockEnv::default(); // block 0, epoch 0

        let db = CacheDB::new(EmptyDB::new());
        let mut evm = EthEvmFactory::default().create_evm(db, EvmEnv::default());

        let key = B256::repeat_byte(0x01);
        let run = |journal: &mut _, block: &TempoBlockEnv, f: &dyn Fn() -> Result<()>| {
            let internals = EvmInternals::new(journal, block, &cfg, &tx);
            let mut provider =
                EvmPrecompileStorageProvider::new_with_gas_limit(internals, &cfg, 1_000_000, 0);
            StorageCtx::enter(&mut provider, f)?;
            Ok::<_, eyre::Report>(provider.gas_used())
        };

        // New slot (zero in current epoch): flat 40,000, no cold surcharge.
        let gas = run(evm.journal_mut(), &block, &|| {
            store(SENDER, key, B256::repeat_byte(0x02))
        })?;
        assert_eq!(gas, 40_000);

        // Existing warm slot: 200.
        let gas = run(evm.journal_mut(), &block, &|| {
            store(SENDER, key, B256::repeat_byte(0x03))
        })?;
        assert_eq!(gas, 200);

        // Warm load: 100.
        let gas = run(evm.journal_mut(), &block, &|| load(SENDER, key).map(|_| ()))?;
        assert_eq!(gas, 100);

        // Cold load of an unset key at epoch 0: 2,100 and no previous-epoch fallback.
        let gas = run(evm.journal_mut(), &block, &|| {
            load(SENDER, B256::repeat_byte(0xFF)).map(|_| ())
        })?;
        assert_eq!(gas, 2_100);

        // New transaction: all slots are cold again.
        evm.journal_mut().commit_tx();

        // Existing cold slot: 2,100 + 5,000.
        let gas = run(evm.journal_mut(), &block, &|| {
            store(SENDER, key, B256::repeat_byte(0x04))
        })?;
        assert_eq!(gas, 7_100);

        // Storing zero into an empty slot is still a "new slot" store, and leaves the slot
        // new: a subsequent store to it is priced as new again.
        let zero_key = B256::repeat_byte(0xAB);
        let gas = run(evm.journal_mut(), &block, &|| {
            store(SENDER, zero_key, B256::ZERO)
        })?;
        assert_eq!(gas, 40_000);
        let gas = run(evm.journal_mut(), &block, &|| {
            store(SENDER, zero_key, B256::repeat_byte(0x05))
        })?;
        assert_eq!(gas, 40_000);

        // Cold load of an unset key past epoch 0 falls back to the previous epoch's
        // account, charging both slots independently: 2 * 2,100.
        let block_epoch_1 = TempoBlockEnv {
            inner: revm::context::BlockEnv {
                number: U256::from(EPOCH_LENGTH),
                ..Default::default()
            },
            ..Default::default()
        };
        let gas = run(evm.journal_mut(), &block_epoch_1, &|| {
            load(SENDER, B256::repeat_byte(0xFF)).map(|_| ())
        })?;
        assert_eq!(gas, 2 * 2_100);

        Ok(())
    }

    /// TIP-1040 data must survive block commit. The epoch account carries storage but no
    /// balance/nonce, so it needs the `0xEF` marker (deployed by the block executor at the
    /// start of each block) — without it the account is touched-but-empty and EIP-161
    /// state clear drops it, storage included.
    #[test]
    fn test_epoch_account_survives_state_clear_only_with_marker() -> eyre::Result<()> {
        use crate::storage::evm::EvmPrecompileStorageProvider;
        use alloy_evm::{EthEvmFactory, EvmEnv, EvmFactory, EvmInternals};
        use revm::{
            Database as _, DatabaseCommit as _,
            context::{CfgEnv, ContextTr, JournalTr, TxEnv},
            database::State,
            state::Bytecode,
        };
        use tempo_chainspec::hardfork::TempoHardfork;
        use tempo_primitives::TempoBlockEnv;

        let key = B256::repeat_byte(0x01);
        let value = B256::repeat_byte(0x02);
        let epoch_account = TemporaryStorageAccount::for_epoch(0).address();

        let run_block = |with_marker: bool| -> eyre::Result<U256> {
            let mut cfg = CfgEnv::<TempoHardfork>::default();
            cfg.set_spec_and_mainnet_gas_params(TempoHardfork::T9);
            let tx = TxEnv::default();
            let block = TempoBlockEnv::default(); // block 0, epoch 0

            let db = State::builder().with_bundle_update().build();
            let mut evm = EthEvmFactory::default().create_evm(db, EvmEnv::default());

            {
                let internals = EvmInternals::new(evm.journal_mut(), &block, &cfg, &tx);
                let mut provider =
                    EvmPrecompileStorageProvider::new_with_gas_limit(internals, &cfg, 1_000_000, 0);
                StorageCtx::enter(&mut provider, || {
                    if with_marker {
                        StorageCtx.set_code(
                            epoch_account,
                            Bytecode::new_legacy(TemporaryStorageAccount::MARKER_CODE.into()),
                        )?;
                    }
                    store(SENDER, key, value)
                })?;
            }

            // Commit the block: journal -> State applies EIP-161 state clear.
            let state = evm.journal_mut().finalize();
            evm.db_mut().commit(state);

            // Read back through the database, as the next block would.
            Ok(evm
                .db_mut()
                .storage(epoch_account, TemporaryStorage::slot(SENDER, key))?)
        };

        assert_eq!(
            run_block(true)?,
            U256::from_be_bytes([0x02; 32]),
            "storage must survive commit when the epoch account has the marker"
        );
        assert_eq!(
            run_block(false)?,
            U256::ZERO,
            "without the marker, EIP-161 state clear drops the epoch account"
        );
        Ok(())
    }
}
