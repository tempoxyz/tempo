//! Unmetered, read-only storage for native validator getters at a block boundary.

use std::collections::HashMap;

use alloy_primitives::{Address, B256, LogData, U256};
use reth_ethereum::evm::{
    primitives::EvmEnvFor,
    revm::{
        Database,
        context::journaled_state::JournalCheckpoint,
        state::{AccountInfo, Bytecode},
    },
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_node::evm::TempoEvmConfig;
use tempo_precompiles::{
    error::{Result, TempoPrecompileError},
    storage::PrecompileStorageProvider,
};
use tempo_primitives::TempoBlockEnv;

/// Reuses the precompile's typed storage accessors without constructing an EVM or journal.
/// The database must represent the state at the same block as `env`.
pub(super) struct ReadOnlyStorage<DB> {
    db: DB,
    env: EvmEnvFor<TempoEvmConfig>,
    // Typed accessors can read the same packed slot several times. Keep the journal's caching
    // benefit, but scope the cache to this one block read.
    slots: HashMap<(Address, U256), U256>,
}

impl<DB> ReadOnlyStorage<DB> {
    pub(super) fn new(db: DB, env: EvmEnvFor<TempoEvmConfig>) -> Self {
        Self {
            db,
            env,
            slots: HashMap::new(),
        }
    }
}

fn read_only_error() -> TempoPrecompileError {
    TempoPrecompileError::Fatal("validator storage is read-only".into())
}

fn database_error(error: impl std::fmt::Display) -> TempoPrecompileError {
    TempoPrecompileError::Fatal(error.to_string())
}

impl<DB: Database> PrecompileStorageProvider for ReadOnlyStorage<DB> {
    fn chain_id(&self) -> u64 {
        self.env.cfg_env.chain_id
    }

    fn block_env(&self) -> &TempoBlockEnv {
        &self.env.block_env
    }

    fn spec(&self) -> TempoHardfork {
        self.env.cfg_env.spec
    }

    fn amsterdam_eip8037_enabled(&self) -> bool {
        self.env.cfg_env.enable_amsterdam_eip8037
    }

    fn is_static(&self) -> bool {
        true
    }

    fn sload(&mut self, address: Address, key: U256) -> Result<U256> {
        if let Some(value) = self.slots.get(&(address, key)) {
            return Ok(*value);
        }
        let value = self.db.storage(address, key).map_err(database_error)?;
        self.slots.insert((address, key), value);
        Ok(value)
    }

    fn with_account_info(
        &mut self,
        address: Address,
        f: &mut dyn FnMut(&AccountInfo),
    ) -> Result<()> {
        let info = self
            .db
            .basic(address)
            .map_err(database_error)?
            .unwrap_or_default();
        f(&info);
        Ok(())
    }

    fn account_code(&mut self, address: Address) -> Result<(B256, Bytecode)> {
        let Some(info) = self.db.basic(address).map_err(database_error)? else {
            return Ok((B256::ZERO, Bytecode::default()));
        };
        let code = match info.code {
            Some(code) => code,
            None => self
                .db
                .code_by_hash(info.code_hash)
                .map_err(database_error)?,
        };
        Ok((info.code_hash, code))
    }

    fn tload(&mut self, _address: Address, _key: U256) -> Result<U256> {
        // Transient storage is empty at a block boundary.
        Ok(U256::ZERO)
    }

    fn sstore(&mut self, _address: Address, _key: U256, _value: U256) -> Result<()> {
        Err(read_only_error())
    }

    fn tstore(&mut self, _address: Address, _key: U256, _value: U256) -> Result<()> {
        Err(read_only_error())
    }

    fn set_code(&mut self, _address: Address, _code: Bytecode) -> Result<()> {
        Err(read_only_error())
    }

    fn emit_event(&mut self, _address: Address, _event: LogData) -> Result<()> {
        Err(read_only_error())
    }

    // These are off-chain reads, so hashing and slot access do not consume transaction gas.
    fn deduct_gas(&mut self, _gas: u64) -> Result<()> {
        Ok(())
    }

    fn refund_gas(&mut self, _gas: i64) {}

    fn gas_limit(&self) -> u64 {
        u64::MAX
    }

    fn gas_used(&self) -> u64 {
        0
    }

    fn state_gas_used(&self) -> u64 {
        0
    }

    fn state_gas_spilled(&self) -> u64 {
        0
    }

    fn gas_refunded(&self) -> i64 {
        0
    }

    fn reservoir(&self) -> u64 {
        0
    }

    fn checkpoint(&mut self) -> JournalCheckpoint {
        panic!("validator storage does not support write checkpoints")
    }

    fn checkpoint_commit(&mut self, _checkpoint: JournalCheckpoint) {
        panic!("validator storage does not support write checkpoints")
    }

    fn checkpoint_revert(&mut self, _checkpoint: JournalCheckpoint) {
        panic!("validator storage does not support write checkpoints")
    }

    fn set_tip1060_storage_credits(&mut self, _enabled: bool) {}
}

#[cfg(test)]
mod tests {
    use reth_ethereum::evm::revm::database_interface::DBErrorMarker;
    use reth_node_builder::ConfigureEvm as _;
    use tempo_primitives::TempoHeader;

    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("historical storage unavailable")]
    struct TestError;
    impl DBErrorMarker for TestError {}

    #[derive(Default)]
    struct TestDatabase {
        slots: HashMap<(Address, U256), U256>,
        reads: usize,
        fail: bool,
    }

    impl Database for TestDatabase {
        type Error = TestError;

        fn basic(
            &mut self,
            _address: Address,
        ) -> std::result::Result<Option<AccountInfo>, TestError> {
            Ok(None)
        }

        fn code_by_hash(&mut self, _hash: B256) -> std::result::Result<Bytecode, TestError> {
            Ok(Bytecode::default())
        }

        fn block_hash(&mut self, _number: u64) -> std::result::Result<B256, TestError> {
            Ok(B256::ZERO)
        }

        fn storage(&mut self, address: Address, key: U256) -> std::result::Result<U256, TestError> {
            self.reads += 1;
            if self.fail {
                return Err(TestError);
            }
            Ok(self.slots.get(&(address, key)).copied().unwrap_or_default())
        }
    }

    fn storage(db: TestDatabase) -> ReadOnlyStorage<TestDatabase> {
        ReadOnlyStorage::new(
            db,
            TempoEvmConfig::moderato()
                .evm_env(&TempoHeader::default())
                .unwrap(),
        )
    }

    #[test]
    fn caches_slots_by_account_and_preserves_missing_slot_semantics() {
        let a = Address::from([1; 20]);
        let b = Address::from([2; 20]);
        let mut storage = storage(TestDatabase {
            slots: HashMap::from([
                ((a, U256::ZERO), U256::from(11)),
                ((b, U256::ZERO), U256::from(22)),
            ]),
            ..Default::default()
        });
        for _ in 0..2 {
            assert_eq!(storage.sload(a, U256::ZERO).unwrap(), U256::from(11));
            assert_eq!(storage.sload(b, U256::ZERO).unwrap(), U256::from(22));
            assert_eq!(storage.sload(a, U256::ONE).unwrap(), U256::ZERO);
        }
        assert_eq!(storage.db.reads, 3);
    }

    #[test]
    fn propagates_storage_errors_without_caching_zero() {
        let mut storage = storage(TestDatabase {
            fail: true,
            ..Default::default()
        });
        assert_eq!(
            storage.sload(Address::ZERO, U256::ZERO),
            Err(TempoPrecompileError::Fatal(
                "historical storage unavailable".into()
            ))
        );
        storage.db.fail = false;
        storage
            .db
            .slots
            .insert((Address::ZERO, U256::ZERO), U256::from(42));
        assert_eq!(
            storage.sload(Address::ZERO, U256::ZERO).unwrap(),
            U256::from(42)
        );
        assert_eq!(storage.db.reads, 2);
    }

    #[test]
    fn rejects_writes_and_events() {
        let mut storage = storage(TestDatabase::default());
        assert!(storage.is_static());
        assert_eq!(
            storage.sstore(Address::ZERO, U256::ZERO, U256::ONE),
            Err(read_only_error())
        );
        assert_eq!(
            storage.tstore(Address::ZERO, U256::ZERO, U256::ONE),
            Err(read_only_error())
        );
        assert_eq!(
            storage.set_code(Address::ZERO, Bytecode::default()),
            Err(read_only_error())
        );
        assert_eq!(
            storage.emit_event(Address::ZERO, LogData::empty()),
            Err(read_only_error())
        );
        assert_eq!(
            storage.sload(Address::ZERO, U256::ZERO).unwrap(),
            U256::ZERO
        );
        assert_eq!(
            storage.tload(Address::ZERO, U256::ZERO).unwrap(),
            U256::ZERO
        );
    }
}
