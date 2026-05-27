//! Attempt-local state view.

use crate::blockstm::{
    overlay::BlockStmOverlay,
    rw_set::{BlockStmAccessKey, BlockStmReadSet, BlockStmValue, BlockStmWriteSet},
};
use alloy_primitives::{Address, B256, U256, keccak256};
use reth_revm::{
    Database, DatabaseCommit,
    bytecode::Bytecode,
    state::{AccountInfo, EvmState},
};

/// State view used by a speculative attempt.
#[derive(Debug)]
pub struct BlockStmStateView<'a> {
    tx_index: usize,
    overlay: &'a BlockStmOverlay,
    reads: BlockStmReadSet,
    writes: BlockStmWriteSet,
}

impl<'a> BlockStmStateView<'a> {
    /// Creates an attempt-local state view.
    pub fn new(tx_index: usize, overlay: &'a BlockStmOverlay) -> Self {
        Self {
            tx_index,
            overlay,
            reads: BlockStmReadSet::default(),
            writes: BlockStmWriteSet::default(),
        }
    }

    /// Reads a key, preferring this attempt's own writes and then the committed prefix/base state.
    pub fn read(&mut self, key: BlockStmAccessKey) -> BlockStmValue {
        let value = self
            .writes
            .get(&key)
            .unwrap_or_else(|| self.overlay.read(key, self.tx_index));
        self.reads.record(key, value);
        value
    }

    /// Records an attempt-local write.
    pub fn write(&mut self, key: BlockStmAccessKey, value: impl Into<BlockStmValue>) {
        self.writes.record(key, value);
    }

    /// Consumes the view and returns captured read and write sets.
    pub fn finish(self) -> (BlockStmReadSet, BlockStmWriteSet) {
        (self.reads, self.writes)
    }
}

/// Database adapter that records real reads performed by the EVM.
#[derive(Debug)]
pub struct BlockStmTrackingDb<DB> {
    inner: DB,
    reads: BlockStmReadSet,
}

impl<DB> BlockStmTrackingDb<DB> {
    /// Creates a tracking database around `inner`.
    pub fn new(inner: DB) -> Self {
        Self {
            inner,
            reads: BlockStmReadSet::default(),
        }
    }

    /// Returns a clone of the captured read set.
    pub fn read_set(&self) -> BlockStmReadSet {
        self.reads.clone()
    }

    /// Consumes the wrapper and returns the inner database.
    pub fn into_inner(self) -> DB {
        self.inner
    }

    fn record_read(&mut self, key: BlockStmAccessKey, value: impl Into<BlockStmValue>) {
        self.reads.record(key, value);
    }
}

impl<DB: Database> Database for BlockStmTrackingDb<DB> {
    type Error = DB::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let info = self.inner.basic(address)?;
        self.record_read(
            BlockStmAccessKey::Account(address),
            account_fingerprint(info.as_ref()),
        );
        if let Some(info) = &info {
            self.record_read(BlockStmAccessKey::Code { address }, info.code_hash);
            self.record_read(BlockStmAccessKey::CodeHash(info.code_hash), info.code_hash);
        }
        Ok(info)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        let code = self.inner.code_by_hash(code_hash)?;
        self.record_read(BlockStmAccessKey::CodeHash(code_hash), code_hash);
        Ok(code)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let value = self.inner.storage(address, index)?;
        self.record_read(
            BlockStmAccessKey::Storage {
                address,
                slot: index,
            },
            value,
        );
        Ok(value)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.inner.block_hash(number)
    }
}

impl<DB: DatabaseCommit> DatabaseCommit for BlockStmTrackingDb<DB> {
    fn commit(&mut self, changes: reth_revm::primitives::AddressMap<reth_revm::state::Account>) {
        self.inner.commit(changes);
    }

    fn commit_iter(
        &mut self,
        changes: &mut dyn Iterator<Item = (alloy_primitives::Address, reth_revm::state::Account)>,
    ) {
        self.inner.commit_iter(changes);
    }
}

/// Converts the state returned by a real EVM execution into a Block-STM write set.
pub fn write_set_from_evm_state(state: &EvmState) -> BlockStmWriteSet {
    let mut writes = BlockStmWriteSet::default();
    for (address, account) in state {
        if account.is_touched() {
            writes.record(
                BlockStmAccessKey::Account(*address),
                account_fingerprint(Some(&account.info)),
            );
            writes.record(
                BlockStmAccessKey::Code { address: *address },
                account.info.code_hash,
            );
        }

        for (slot, value) in account.changed_storage_slots() {
            writes.record(
                BlockStmAccessKey::Storage {
                    address: *address,
                    slot: *slot,
                },
                value.present_value(),
            );
        }
    }
    writes
}

fn account_fingerprint(info: Option<&AccountInfo>) -> BlockStmValue {
    let Some(info) = info else {
        return BlockStmValue::default();
    };

    let mut bytes = Vec::with_capacity(72);
    bytes.extend_from_slice(&info.balance.to_be_bytes::<32>());
    bytes.extend_from_slice(&info.nonce.to_be_bytes());
    bytes.extend_from_slice(info.code_hash.as_slice());
    BlockStmValue(keccak256(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Bytes, TxKind};
    use reth_evm::{Evm, EvmEnv};
    use reth_revm::{
        context::{BlockEnv, TxEnv},
        db::{CacheDB, EmptyDB},
    };
    use tempo_evm::{TempoBlockEnv, evm::TempoEvm};
    use tempo_revm::TempoTxEnv;

    fn evm_with_tracking_db(
        db: BlockStmTrackingDb<CacheDB<EmptyDB>>,
    ) -> TempoEvm<BlockStmTrackingDb<CacheDB<EmptyDB>>> {
        TempoEvm::new(
            db,
            EvmEnv {
                block_env: TempoBlockEnv {
                    inner: BlockEnv {
                        basefee: 0,
                        gas_limit: 30_000_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        )
    }

    fn read_then_write_fixture() -> (BlockStmTrackingDb<CacheDB<EmptyDB>>, Address, Address, B256) {
        let caller = Address::repeat_byte(0x01);
        let contract = Address::repeat_byte(0xaa);
        let runtime = Bytes::from_static(&[
            0x60, 0x00, 0x54, 0x80, 0x60, 0x00, 0x52, 0x80, 0x60, 0x01, 0x01, 0x60, 0x01, 0x55,
            0x50, 0x60, 0x20, 0x60, 0x00, 0xa0, 0x00,
        ]);
        let bytecode = Bytecode::new_raw(runtime);
        let code_hash = bytecode.hash_slow();

        let mut db = CacheDB::new(EmptyDB::default());
        db.insert_account_info(
            caller,
            AccountInfo {
                balance: U256::from(1_000_000_000u64),
                ..Default::default()
            },
        );
        db.insert_account_info(
            contract,
            AccountInfo {
                code_hash,
                code: Some(bytecode),
                ..Default::default()
            },
        );
        db.insert_account_storage(contract, U256::ZERO, U256::from(41u64))
            .expect("storage insert should succeed");

        (BlockStmTrackingDb::new(db), caller, contract, code_hash)
    }

    fn execute_fixture() -> (BlockStmReadSet, BlockStmWriteSet, Address, Address, B256) {
        let (tracking_db, caller, contract, code_hash) = read_then_write_fixture();
        let mut evm = evm_with_tracking_db(tracking_db);
        let result = evm
            .transact_raw(TempoTxEnv {
                inner: TxEnv {
                    caller,
                    gas_price: 0,
                    gas_limit: 1_000_000,
                    kind: TxKind::Call(contract),
                    ..Default::default()
                },
                ..Default::default()
            })
            .expect("fixture transaction should execute");
        assert!(result.result.is_success());

        let writes = write_set_from_evm_state(&result.state);
        let (tracking_db, _) = evm.finish();
        (tracking_db.read_set(), writes, caller, contract, code_hash)
    }

    #[test]
    fn blockstm_rw_records_real_evm_storage_reads() {
        let (reads, _, _, contract, _) = execute_fixture();

        assert!(reads.contains_key(&BlockStmAccessKey::Storage {
            address: contract,
            slot: U256::ZERO,
        }));
        assert_eq!(
            reads.get(&BlockStmAccessKey::Storage {
                address: contract,
                slot: U256::ZERO,
            }),
            Some(BlockStmValue::from(U256::from(41u64)))
        );
    }

    #[test]
    fn blockstm_rw_records_account_and_code_reads() {
        let (reads, _, caller, contract, code_hash) = execute_fixture();

        assert!(reads.contains_key(&BlockStmAccessKey::Account(caller)));
        assert!(reads.contains_key(&BlockStmAccessKey::Account(contract)));
        assert!(reads.contains_key(&BlockStmAccessKey::Code { address: contract }));
        assert!(reads.contains_key(&BlockStmAccessKey::CodeHash(code_hash)));
    }

    #[test]
    fn blockstm_rw_readset_is_not_access_list_only() {
        let (reads, _, _, contract, _) = execute_fixture();

        assert!(reads.contains_key(&BlockStmAccessKey::Storage {
            address: contract,
            slot: U256::ZERO,
        }));
    }

    #[test]
    fn blockstm_rw_write_capture_matches_serial_state_changes() {
        let (_, writes, caller, contract, _) = execute_fixture();

        assert!(writes.contains_key(&BlockStmAccessKey::Account(caller)));
        assert!(writes.contains_key(&BlockStmAccessKey::Account(contract)));
        assert_eq!(
            writes.get(&BlockStmAccessKey::Storage {
                address: contract,
                slot: U256::from(1u64),
            }),
            Some(BlockStmValue::from(U256::from(42u64)))
        );
    }
}
