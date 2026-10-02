//! Recorded execution on a worker-owned provider, reusable by the ordered executor.

use super::*;

/// Advisory values from the builder's accepted prefix. Workers may read across
/// updates; exact ordered validation still checks every value before reuse.
/// Dropping the block's prewarming context releases this cache.
#[derive(Clone, Debug, Default)]
pub struct PrewarmingState(Arc<RwLock<PrefixState>>);

#[derive(Debug, Default)]
struct PrefixState {
    accounts: HashMap<Address, PrefixAccount>,
    code: HashMap<B256, Bytecode>,
    /// Actual ring position and next source-preview offset after the last
    /// accepted expiring transaction. Skipped candidates don't advance the ring.
    nonce_cursor: Option<(U256, usize)>,
}

#[derive(Debug, Default)]
struct PrefixAccount {
    info: Option<AccountInfo>,
    storage: HashMap<U256, U256>,
    cleared: bool,
}

impl PrewarmingState {
    /// Publishes a transaction's accepted state for subsequent speculation.
    /// `expiring_offset` is its position among expiring source candidates, before
    /// pool filtering. The state is only a hint and never committed by workers.
    pub fn record(&self, state: &reth_revm::state::EvmState, expiring_offset: Option<usize>) {
        let mut prefix = self.0.write().expect("prewarming prefix poisoned");
        for (&address, account) in state {
            if !account.is_touched() {
                continue;
            }
            if let Some(code) = &account.info.code {
                prefix.code.insert(account.info.code_hash, code.clone());
            }
            let cached = prefix.accounts.entry(address).or_default();
            if account.is_created() || account.is_selfdestructed() {
                cached.storage.clear();
                cached.cleared = true;
            }
            if account.is_selfdestructed() {
                cached.info = None;
                continue;
            }
            cached.info = Some(account.info.clone());
            for (&slot, value) in &account.storage {
                // Include unchanged observations too: a newly-created account
                // can expose zero-valued storage without a changed slot.
                cached.storage.insert(slot, value.present_value);
            }
        }
        if let Some(slot) = state
            .get(&NONCE_PRECOMPILE_ADDRESS)
            .and_then(|account| account.storage.get(&nonce_slots::EXPIRING_NONCE_RING_PTR))
        {
            if let Some(next_offset) = expiring_offset.and_then(|offset| offset.checked_add(1)) {
                prefix.nonce_cursor = Some((slot.present_value, next_offset));
            } else if slot.is_changed() {
                prefix.nonce_cursor = None;
            }
        }
    }

    fn read(&self, key: ReadKey) -> Option<ReadValue> {
        let prefix = self.0.read().expect("prewarming prefix poisoned");
        match key {
            ReadKey::Account(address) => prefix
                .accounts
                .get(&address)
                .map(|account| ReadValue::Account(account.info.clone())),
            ReadKey::Storage(address, slot) => {
                let account = prefix.accounts.get(&address)?;
                account
                    .storage
                    .get(&slot)
                    .copied()
                    .or_else(|| account.cleared.then_some(U256::ZERO))
                    .map(ReadValue::Storage)
            }
            ReadKey::Code(hash) => prefix.code.get(&hash).cloned().map(ReadValue::Code),
            ReadKey::BlockHash(_) => None,
        }
    }

    fn nonce_cursor(&self, offset: usize) -> Option<(U256, usize)> {
        let (ptr, next_offset) = self
            .0
            .read()
            .expect("prewarming prefix poisoned")
            .nonce_cursor?;
        Some((ptr, offset.checked_sub(next_offset)?))
    }
}

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
            conflict: None,
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
        let mut evm = TempoEvm::new(
            ReadRecorder {
                db,
                reads: Vec::new(),
                predicted_nonce_ptr: None,
                prefix: None,
            },
            env.clone(),
        );
        evm.inner_mut().enable_storage_access_recording();
        Self { evm, env }
    }

    /// Reads accepted prefix hints before consulting the parent-state provider.
    pub fn with_state(mut self, state: PrewarmingState) -> Self {
        self.evm.ctx_mut().journaled_state.database.prefix = Some(state);
        self
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
        {
            let (ptr, offset) = if let Some(cursor) = db
                .prefix
                .as_ref()
                .and_then(|prefix| prefix.nonce_cursor(offset))
            {
                cursor
            } else {
                let ReadValue::Storage(ptr) =
                    read(&mut db.db, nonce_ptr_key()).map_err(EVMError::Database)?
                else {
                    unreachable!()
                };
                (ptr, offset)
            };
            let capacity = self.env.cfg_env.spec.expiring_nonce_set_capacity();
            if let Ok(ptr) = u32::try_from(ptr)
                && ptr < capacity
            {
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
    prefix: Option<PrewarmingState>,
}

impl<DB: Database> ReadRecorder<DB> {
    fn read(&mut self, key: ReadKey) -> Result<ReadValue, DB::Error> {
        let value = if key == nonce_ptr_key()
            && let Some(ptr) = self.predicted_nonce_ptr
        {
            ReadValue::Storage(ptr)
        } else if let Some(value) = self.prefix.as_ref().and_then(|prefix| prefix.read(key)) {
            value
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
