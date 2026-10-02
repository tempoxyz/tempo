//! Recorded execution on a worker-owned provider, reusable by the ordered executor.

use super::*;

/// A successful speculative execution, including every database read. Fields are
/// private so callers cannot construct an unchecked result.
#[derive(Debug)]
pub struct PreexecutedTransaction {
    tx: TempoTxEnv,
    env: Env,
    result: ResultAndState<TempoHaltReason>,
    validator_fee: U256,
    reads: Vec<(ReadKey, ReadValue)>,
    fee_updates: Vec<FeeUpdate>,
}

impl PreexecutedTransaction {
    pub(crate) fn into_candidate<E>(self, tx: &TempoTxEnv) -> Option<SpeculativeResult<E>> {
        transactions_match(&self.tx, tx).then(|| SpeculativeResult {
            env: self.env,
            result: Ok(self.result),
            validator_fee: self.validator_fee,
            reads: self.reads,
            fee_updates: self.fee_updates,
            fees_rebased: false,
            body: None,
        })
    }
}

/// Reuses an EVM on one prewarming worker. The provider stays on its owning
/// thread; no writes are committed and no validation checks are disabled.
#[expect(missing_debug_implementations)]
pub struct PrewarmingExecutor<DB: Database> {
    evm: TempoEvm<ReadRecorder<DB>>,
    env: Env,
}

impl<DB: Database> PrewarmingExecutor<DB> {
    /// Creates a recorder using the same environment as the ordered executor.
    pub fn new(db: DB, env: Env) -> Self {
        Self {
            evm: TempoEvm::new(
                ReadRecorder {
                    db,
                    reads: Vec::new(),
                    predicted_nonce_ptr: None,
                },
                env.clone(),
            ),
            env,
        }
    }

    /// Executes without committing. The optional expiring-nonce offset is only
    /// a prediction: its observed pointer is validated like every other read.
    /// Errors return no reusable result and are executed normally by the owner.
    pub fn execute(
        &mut self,
        tx: TempoTxEnv,
        expiring_nonce_offset: Option<usize>,
    ) -> Result<PreexecutedTransaction, EVMError<DB::Error, TempoInvalidTransaction>> {
        let db = &mut self.evm.ctx_mut().journaled_state.database;
        db.reads.clear();
        db.predicted_nonce_ptr = None;
        if self.env.cfg_env.spec.is_t1()
            && tx
                .tempo_tx_env
                .as_ref()
                .is_some_and(|aa| aa.nonce_key == U256::MAX)
            && let Some(offset) = expiring_nonce_offset
            && let ReadValue::Storage(ptr) =
                read(&mut db.db, nonce_ptr_key()).map_err(EVMError::Database)?
            && let Ok(ptr) = u32::try_from(ptr)
        {
            let capacity = self.env.cfg_env.spec.expiring_nonce_set_capacity();
            if ptr < capacity {
                db.predicted_nonce_ptr = Some(U256::from(
                    (u64::from(ptr) + (offset % capacity as usize) as u64) % u64::from(capacity),
                ));
            }
        }
        let record_fees = !self.env.cfg_env.enable_amsterdam_eip8037
            && self.env.cfg_env.gas_params
                == tempo_revm::gas_params::tempo_gas_params(self.env.cfg_env.spec)
            && tx.calls().all(|(kind, _)| kind.is_call());
        let (result, fee_updates) = if record_fees {
            fee_updates::record(|| self.evm.transact_raw(tx.clone()))
        } else {
            (self.evm.transact_raw(tx.clone()), Vec::new())
        };
        let reads = std::mem::take(&mut self.evm.ctx_mut().journaled_state.database.reads);
        Ok(PreexecutedTransaction {
            tx,
            env: self.env.clone(),
            result: result?,
            validator_fee: self.evm.validator_fee(),
            reads,
            fee_updates,
        })
    }
}

#[derive(Debug)]
struct ReadRecorder<DB> {
    db: DB,
    reads: Vec<(ReadKey, ReadValue)>,
    predicted_nonce_ptr: Option<U256>,
}

impl<DB: Database> ReadRecorder<DB> {
    fn read(&mut self, key: ReadKey) -> Result<ReadValue, DB::Error> {
        let value = if key == nonce_ptr_key()
            && let Some(ptr) = self.predicted_nonce_ptr
        {
            ReadValue::Storage(ptr)
        } else {
            read(&mut self.db, key)?
        };
        self.reads.push((key, value.clone()));
        Ok(value)
    }
}

impl<DB: Database> reth_revm::Database for ReadRecorder<DB> {
    type Error = DB::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let ReadValue::Account(value) = self.read(ReadKey::Account(address))? else {
            unreachable!()
        };
        Ok(value)
    }

    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        tempo_precompiles::storage::access::storage(address, slot);
        let ReadValue::Storage(value) = self.read(ReadKey::Storage(address, slot))? else {
            unreachable!()
        };
        Ok(value)
    }

    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        let ReadValue::Code(value) = self.read(ReadKey::Code(hash))? else {
            unreachable!()
        };
        Ok(value)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        let ReadValue::BlockHash(value) = self.read(ReadKey::BlockHash(number))? else {
            unreachable!()
        };
        Ok(value)
    }
}
