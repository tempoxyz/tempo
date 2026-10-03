//! Bounded, advisory handoff from Engine prewarming to ordered execution.
//!
//! A hash locates a candidate; it never validates one. The recipient must still
//! check the complete transaction, environment, configuration and recorded reads.

use super::{Env, PreexecutedTransaction, PrewarmingState, ReadValue};
use alloy_primitives::{B256, map::HashMap};
use std::{
    collections::BTreeMap,
    mem::size_of,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tempo_revm::{ExecutionContext, TempoTxEnv};

const MAX_TRANSACTIONS: usize = 65_536;
const LOOKAHEAD: usize = 128;
const MAX_ESTIMATED_BYTES: usize = 32 * 1024 * 1024;

/// Holds only the latest Engine session. Outstanding workers may finish an old
/// session, but cannot publish into its replacement.
#[derive(Clone, Debug, Default)]
pub(crate) struct EnginePrewarmingCache {
    current: Arc<Mutex<Option<Arc<EnginePrewarmingSession>>>>,
}

impl EnginePrewarmingCache {
    /// Removes the lookup session for a payload that will not capture results.
    /// Existing worker handles remain isolated from future sessions.
    pub(crate) fn clear(&self) {
        if let Ok(mut current) = self.current.lock() {
            *current = None;
        }
    }

    /// Starts a new session. Invalid input clears the current session so that
    /// an earlier block with the same environment cannot supply its index map.
    pub(crate) fn begin(
        &self,
        env: Env,
        hashes: impl IntoIterator<Item = B256>,
    ) -> Option<Arc<EnginePrewarmingSession>> {
        let mut indices = HashMap::default();
        let mut valid = true;
        for hash in hashes {
            let index = indices.len();
            if index == MAX_TRANSACTIONS || indices.insert(hash, index).is_some() {
                valid = false;
                break;
            }
        }
        let session = valid.then(|| {
            Arc::new(EnginePrewarmingSession {
                env,
                indices,
                next: AtomicUsize::new(0),
                retained: Mutex::default(),
                prefix: PrewarmingState::default(),
            })
        });
        *self.current.lock().ok()? = session.clone();
        session
    }

    /// Finds only an exact canonical environment. The factory must normalize
    /// its explicitly authorized prewarming flags before this lookup.
    pub(crate) fn session(&self, env: &Env) -> Option<Arc<EnginePrewarmingSession>> {
        let current = self.current.lock().ok()?;
        current
            .as_ref()
            .filter(|session| session.env == *env)
            .cloned()
    }
}

/// A block's hash index, bounded completed results and accepted-prefix hints.
/// The prefix retains the block's published state footprint separately from the
/// completed-result byte estimate. Contains no provider or database reference.
#[derive(Debug)]
pub(crate) struct EnginePrewarmingSession {
    env: Env,
    indices: HashMap<B256, usize>,
    next: AtomicUsize,
    retained: Mutex<Retained>,
    prefix: PrewarmingState,
}

#[derive(Debug, Default)]
struct Retained {
    results: BTreeMap<usize, (PreexecutedTransaction, usize)>,
    estimated_bytes: usize,
}

impl Retained {
    fn take_through(
        &mut self,
        index: usize,
        previous: usize,
        is_system_tx: bool,
    ) -> Option<PreexecutedTransaction> {
        let mut result = None;
        while self
            .results
            .first_key_value()
            .is_some_and(|(&key, _)| key <= index)
        {
            let (key, (candidate, bytes)) = self.results.pop_first()?;
            self.estimated_bytes -= bytes;
            if key == index && index >= previous && !is_system_tx {
                result = Some(candidate);
            }
        }
        result
    }
}

impl EnginePrewarmingSession {
    pub(crate) const fn env(&self) -> &Env {
        &self.env
    }

    pub(crate) fn prefix(&self) -> PrewarmingState {
        self.prefix.clone()
    }

    /// Called only for accepted state in the block executor's commit path.
    /// Never seed this prefix from a cache: Engine offsets remain relative to
    /// the worker's parent state. With no source offset, the nonce cursor stays
    /// absent and the recorder applies that original parent offset exactly once.
    pub(crate) fn record_commit(&self, state: &reth_revm::state::EvmState) -> (Duration, Duration) {
        self.prefix.record_timed(state, None)
    }

    fn index(&self, tx: &TempoTxEnv) -> Option<usize> {
        let ExecutionContext::Transaction { tx_hash } = tx.execution_context else {
            return None;
        };
        self.indices.get(&tx_hash).copied()
    }

    fn in_window(&self, index: usize) -> bool {
        let next = self.next.load(Ordering::Acquire);
        index >= next && index < next.saturating_add(LOOKAHEAD)
    }

    /// Cheap admission only: publication checks the cursor again after work.
    pub(crate) fn can_capture(&self, tx: &TempoTxEnv) -> bool {
        !tx.is_system_tx && self.index(tx).is_some_and(|index| self.in_window(index))
    }

    /// Keeps a completed strict result without waiting on the ordered executor.
    /// Contention, stale work, duplicate work and budget misses simply fall back.
    pub(crate) fn publish(&self, mut candidate: PreexecutedTransaction) -> bool {
        if candidate.env != self.env || candidate.tx.is_system_tx {
            return false;
        }
        let Some(index) = self.index(&candidate.tx) else {
            return false;
        };
        if !self.in_window(index) {
            return false;
        }
        // Traverse owned data before taking the publication lock.
        let Some(bytes) = estimated_bytes(&mut candidate) else {
            return false;
        };
        let Ok(mut retained) = self.retained.try_lock() else {
            return false;
        };
        if !self.in_window(index)
            || retained.results.contains_key(&index)
            || retained.results.len() >= LOOKAHEAD
        {
            return false;
        }
        let Some(total) = retained.estimated_bytes.checked_add(bytes) else {
            return false;
        };
        if total > MAX_ESTIMATED_BYTES {
            return false;
        }
        retained.results.insert(index, (candidate, bytes));
        retained.estimated_bytes = total;
        true
    }

    /// Advances even on a miss. Call for every canonical transaction, including
    /// transactions for which the ordinary scheduler already prepared a result.
    #[cfg(test)]
    pub(crate) fn take(&self, tx: &TempoTxEnv) -> Option<PreexecutedTransaction> {
        self.take_timed(tx).0
    }

    /// The same ordered take, with serial-consumer lock acquisition/hold wall time.
    /// Unindexed transactions acquire no lock and return no timing sample.
    pub(crate) fn take_timed(
        &self,
        tx: &TempoTxEnv,
    ) -> (Option<PreexecutedTransaction>, Option<(Duration, Duration)>) {
        let Some(index) = self.index(tx) else {
            return (None, None);
        };
        let previous = self
            .next
            .fetch_max(index.saturating_add(1), Ordering::AcqRel);
        let waiting = Instant::now();
        // Poisoning still declines reuse. Drop the poisoned guard before returning
        // timings, preserving the original lock().ok()? behavior.
        let retained = self.retained.lock();
        let acquired = Instant::now();
        let result = match retained {
            Ok(mut retained) => retained.take_through(index, previous, tx.is_system_tx),
            Err(poisoned) => {
                drop(poisoned);
                None
            }
        };
        let held = acquired.elapsed();
        (result, Some((acquired.duration_since(waiting), held)))
    }
}

/// Checked estimate of retained payload, not an allocator/RSS bound: Bytes and
/// bytecode jump tables can retain backing capacity their APIs do not expose.
/// Charge every occurrence of shared code, all exposed container capacities,
/// original account metadata and generous map/allocation overhead. Entries and
/// hash counts are hard bounded independently of this estimate.
fn estimated_bytes(candidate: &mut PreexecutedTransaction) -> Option<usize> {
    use reth_revm::context::result::ExecutionResult;
    let mut budget = ByteBudget(0);
    // Includes the BTreeMap node allowance and the environment's shared 256-word
    // gas table, counted afresh for each candidate rather than amortized.
    budget.add(size_of::<PreexecutedTransaction>().checked_add(4096)?)?;
    budget.transaction(&candidate.tx)?;
    budget.vector(&candidate.reads)?;
    for (_, value) in &candidate.reads {
        match value {
            ReadValue::Account(Some(info)) => budget.account_info(info)?,
            ReadValue::Code(code) => budget.code(code)?,
            ReadValue::Account(None) | ReadValue::Storage(_) | ReadValue::BlockHash(_) => {}
        }
    }
    budget.map::<alloy_primitives::Address, reth_revm::state::Account>(
        candidate.result.state.capacity(),
    )?;
    for account in candidate.result.state.values() {
        budget.account_info(&account.info)?;
        // This API clones only inline metadata and shared code. Charge the box
        // even when no original account info was allocated (a deliberate overcount).
        budget.add(size_of::<reth_revm::state::AccountInfo>() + 64)?;
        budget.account_info(&account.original_info())?;
        budget.map::<alloy_primitives::U256, reth_revm::state::EvmStorageSlot>(
            account.storage.capacity(),
        )?;
    }
    let (logs, output) = match &mut candidate.result.result {
        ExecutionResult::Success { logs, output, .. } => (logs, Some(output.data())),
        ExecutionResult::Revert { logs, output, .. } => (logs, Some(&*output)),
        ExecutionResult::Halt { logs, reason, .. } => {
            budget.halt_reason(reason)?;
            (logs, None)
        }
    };
    budget.vector(logs)?;
    for log in logs {
        // This accessor exposes the allocation capacity; no topics are changed.
        budget.vector(log.data.topics_mut_unchecked())?;
        budget.bytes(log.data.data.len())?;
    }
    if let Some(output) = output {
        budget.bytes(output.len())?;
    }
    budget.vector(&candidate.fee_updates)?;
    for update in &candidate.fee_updates {
        budget.add(update.estimated_heap_size().checked_add(64)?)?;
    }
    Some(budget.0)
}

struct ByteBudget(usize);

impl ByteBudget {
    fn add(&mut self, bytes: usize) -> Option<()> {
        self.0 = self.0.checked_add(bytes)?;
        (self.0 <= MAX_ESTIMATED_BYTES).then_some(())
    }

    fn bytes(&mut self, len: usize) -> Option<()> {
        self.add(len.checked_add(64)?)
    }

    fn vector<T>(&mut self, values: &Vec<T>) -> Option<()> {
        self.add(
            values
                .capacity()
                .checked_mul(size_of::<T>())?
                .checked_add(64)?,
        )
    }

    fn map<K, V>(&mut self, capacity: usize) -> Option<()> {
        // Covers the table's load factor, control bytes and allocation headers.
        self.add(
            capacity
                .checked_mul(size_of::<(K, V)>().checked_add(1)?)?
                .checked_mul(2)?
                .checked_add(128)?,
        )
    }

    fn code(&mut self, code: &reth_revm::state::Bytecode) -> Option<()> {
        self.add(256)?;
        self.bytes(code.bytes_slice().len())?;
        if let Some(table) = code.legacy_jump_table() {
            self.bytes(table.as_slice().len())?;
        }
        Some(())
    }

    fn account_info(&mut self, info: &reth_revm::state::AccountInfo) -> Option<()> {
        // Exhaustive destructuring forces review if this dependency gains an
        // account extension or another owned field.
        let reth_revm::state::AccountInfo {
            balance: _,
            nonce: _,
            code_hash: _,
            account_id: _,
            code,
        } = info;
        if let Some(code) = code {
            self.code(code)?;
        }
        Some(())
    }

    fn signature(&mut self, signature: &tempo_primitives::TempoSignature) -> Option<()> {
        use tempo_primitives::TempoSignature;
        match signature {
            TempoSignature::Primitive(signature) => self.primitive_signature(signature),
            TempoSignature::Keychain(signature) => self.primitive_signature(&signature.signature),
        }
    }

    fn primitive_signature(
        &mut self,
        signature: &tempo_primitives::transaction::PrimitiveSignature,
    ) -> Option<()> {
        use tempo_primitives::transaction::PrimitiveSignature;
        match signature {
            PrimitiveSignature::Secp256k1(_) | PrimitiveSignature::P256(_) => Some(()),
            PrimitiveSignature::WebAuthn(signature) => self.bytes(signature.webauthn_data.len()),
        }
    }

    fn halt_reason(&mut self, reason: &reth_revm::context::result::HaltReason) -> Option<()> {
        use reth_revm::context::result::HaltReason;
        match reason {
            HaltReason::PrecompileErrorWithContext(message) => self.bytes(message.capacity()),
            HaltReason::OutOfGas(_)
            | HaltReason::OpcodeNotFound
            | HaltReason::InvalidFEOpcode
            | HaltReason::InvalidJump
            | HaltReason::NotActivated
            | HaltReason::StackUnderflow
            | HaltReason::StackOverflow
            | HaltReason::OutOfOffset
            | HaltReason::CreateCollision
            | HaltReason::PrecompileError
            | HaltReason::NonceOverflow
            | HaltReason::CreateContractSizeLimit
            | HaltReason::CreateContractStartingWithEF
            | HaltReason::CreateInitCodeSizeLimit
            | HaltReason::OverflowPayment
            | HaltReason::StateChangeDuringStaticCall
            | HaltReason::CallNotAllowedInsideStatic
            | HaltReason::OutOfFunds
            | HaltReason::CallTooDeep => Some(()),
        }
    }

    fn transaction(&mut self, tx: &TempoTxEnv) -> Option<()> {
        self.bytes(tx.inner.data.len())?;
        self.vector(&tx.inner.access_list.0)?;
        for item in &tx.inner.access_list.0 {
            self.vector(&item.storage_keys)?;
        }
        self.vector(&tx.inner.blob_hashes)?;
        // Ethereum authorizations contain only inline values.
        self.vector(&tx.inner.authorization_list)?;
        if let Some(aa) = &tx.tempo_tx_env {
            self.add(size_of::<tempo_revm::TempoBatchCallEnv>() + 64)?;
            self.signature(&aa.signature)?;
            self.vector(&aa.aa_calls)?;
            for call in &aa.aa_calls {
                self.bytes(call.input.len())?;
            }
            self.vector(&aa.tempo_authorization_list)?;
            for authorization in &aa.tempo_authorization_list {
                self.signature(authorization.signature())?;
            }
            if let Some(key) = &aa.key_authorization {
                self.primitive_signature(&key.signature)?;
                if let Some(limits) = &key.authorization.limits {
                    self.vector(limits)?;
                }
                if let Some(scopes) = &key.authorization.allowed_calls {
                    self.vector(scopes)?;
                    for scope in scopes {
                        self.vector(&scope.selector_rules)?;
                        for selector in &scope.selector_rules {
                            self.vector(&selector.recipients)?;
                        }
                    }
                }
            }
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parallel::PrewarmingExecutor;
    use alloy_evm::Evm;
    use alloy_primitives::{Address, Bytes, TxKind};
    use revm::{context::TxEnv, database::EmptyDB};

    fn hash(index: usize) -> B256 {
        B256::from(alloy_primitives::U256::from(index).to_be_bytes::<32>())
    }

    fn tx(index: usize) -> TempoTxEnv {
        TempoTxEnv {
            inner: TxEnv {
                caller: Address::with_last_byte(201),
                kind: TxKind::Call(Address::with_last_byte(202)),
                gas_limit: 1_000_000,
                ..Default::default()
            },
            execution_context: ExecutionContext::Transaction {
                tx_hash: hash(index),
            },
            ..Default::default()
        }
    }

    fn env() -> Env {
        crate::test_utils::test_evm_with_basefee(EmptyDB::default(), 0)
            .finish()
            .1
    }

    fn candidate(index: usize) -> PreexecutedTransaction {
        PrewarmingExecutor::new(EmptyDB::default(), env())
            .execute(tx(index), None)
            .unwrap()
    }

    #[test]
    fn duplicate_and_oversized_blocks_clear_the_current_session() {
        let cache = EnginePrewarmingCache::default();
        let original = cache.begin(env(), [hash(0)]).unwrap();
        assert!(Arc::ptr_eq(&cache.session(&env()).unwrap(), &original));
        assert!(cache.begin(env(), [hash(0), hash(0)]).is_none());
        assert!(cache.session(&env()).is_none());
        assert!(
            cache
                .begin(env(), (0..MAX_TRANSACTIONS).map(hash))
                .is_some()
        );
        assert!(
            cache
                .begin(env(), (0..=MAX_TRANSACTIONS).map(hash))
                .is_none()
        );
        assert!(cache.session(&env()).is_none());
        cache.begin(env(), [hash(0)]).unwrap();
        #[expect(
            clippy::redundant_clone,
            reason = "verify clones share the current session"
        )]
        cache.clone().clear();
        assert!(cache.session(&env()).is_none());
    }

    #[test]
    fn environment_and_transaction_context_must_match() {
        let cache = EnginePrewarmingCache::default();
        let session = cache.begin(env(), [hash(0)]).unwrap();
        let mut changed = env();
        changed.block_env.inner.basefee += 1;
        assert!(cache.session(&changed).is_none());
        let mut simulation = tx(0);
        simulation.execution_context = ExecutionContext::Simulation;
        assert!(!session.can_capture(&simulation));
        assert!(session.take(&simulation).is_none());
        let mut system = tx(0);
        system.is_system_tx = true;
        assert!(!session.can_capture(&system));
        assert!(!session.can_capture(&tx(1)));
        let mut wrong_env = candidate(0);
        wrong_env.env = changed;
        assert!(!session.publish(wrong_env));
        assert!(session.publish(candidate(0)));
        assert!(session.take(&tx(0)).is_some());
        assert!(session.take(&tx(0)).is_none());
    }

    #[test]
    fn ordered_misses_discard_late_work_and_open_the_next_window() {
        let session = EnginePrewarmingCache::default()
            .begin(env(), (0..=LOOKAHEAD).map(hash))
            .unwrap();
        assert!(session.can_capture(&tx(LOOKAHEAD - 1)));
        assert!(!session.can_capture(&tx(LOOKAHEAD)));
        assert!(!session.publish(candidate(LOOKAHEAD)));
        assert!(session.take(&tx(0)).is_none());
        assert!(!session.publish(candidate(0)));
        assert!(session.can_capture(&tx(LOOKAHEAD)));
        assert!(session.publish(candidate(LOOKAHEAD)));
        assert!(session.take(&tx(LOOKAHEAD)).is_some());
        assert!(!session.can_capture(&tx(LOOKAHEAD - 1)));
        assert_eq!(session.retained.lock().unwrap().estimated_bytes, 0);
    }

    #[test]
    fn publication_never_waits_and_retains_only_one_full_window() {
        let session = EnginePrewarmingCache::default()
            .begin(env(), (0..=LOOKAHEAD).map(hash))
            .unwrap();
        let guard = session.retained.lock().unwrap();
        assert!(!session.publish(candidate(0)));
        drop(guard);
        for index in 0..LOOKAHEAD {
            assert!(session.publish(candidate(index)));
        }
        assert!(!session.publish(candidate(0)));
        assert!(!session.publish(candidate(LOOKAHEAD)));
        assert_eq!(session.retained.lock().unwrap().results.len(), LOOKAHEAD);
        assert!(session.take(&tx(LOOKAHEAD - 1)).is_some());
        let retained = session.retained.lock().unwrap();
        assert!(retained.results.is_empty());
        assert_eq!(retained.estimated_bytes, 0);
    }

    #[test]
    fn replacement_sessions_do_not_receive_old_workers_results() {
        let cache = EnginePrewarmingCache::default();
        let old = cache.begin(env(), [hash(0)]).unwrap();
        let new = cache.begin(env(), [hash(0)]).unwrap();
        assert!(old.publish(candidate(0)));
        assert!(new.take(&tx(0)).is_none());
        assert!(Arc::ptr_eq(&cache.session(&env()).unwrap(), &new));
    }

    #[test]
    fn oversized_payloads_and_aggregate_budget_fail_closed() {
        let session = EnginePrewarmingCache::default()
            .begin(env(), [hash(0), hash(1)])
            .unwrap();
        let mut oversized = candidate(0);
        oversized.tx.inner.data = Bytes::from(vec![0; MAX_ESTIMATED_BYTES]);
        assert!(!session.publish(oversized));
        for index in 0..2 {
            let mut large = candidate(index);
            large.tx.inner.data = Bytes::from(vec![0; MAX_ESTIMATED_BYTES / 2]);
            assert_eq!(session.publish(large), index == 0);
        }
        assert!(session.take(&tx(0)).is_some());
        assert_eq!(session.retained.lock().unwrap().estimated_bytes, 0);
        assert!(session.publish(candidate(1)));
        assert!(ByteBudget(0).add(usize::MAX).is_none());
        assert!(ByteBudget(1).add(usize::MAX).is_none());
    }

    #[test]
    fn nested_payloads_and_retained_capacity_are_charged() {
        use alloy_primitives::Log;
        use reth_revm::context::result::{ExecutionResult, HaltReason, ResultGas};
        use tempo_primitives::transaction::Call;

        let mut nested = candidate(0);
        let baseline = estimated_bytes(&mut nested).unwrap();
        nested.tx.tempo_tx_env = Some(Box::new(tempo_revm::TempoBatchCallEnv {
            aa_calls: vec![Call {
                to: TxKind::Call(Address::with_last_byte(202)),
                value: Default::default(),
                input: Bytes::from(vec![0; 8192]),
            }],
            ..Default::default()
        }));
        assert!(estimated_bytes(&mut nested).unwrap() >= baseline + 8192);

        let mut message = String::with_capacity(8192);
        message.push('x');
        let mut log: Log = Log::default();
        log.data.topics_mut_unchecked().reserve(256);
        let topic_bytes = log.data.topics_mut_unchecked().capacity() * size_of::<B256>();
        nested.result.result = ExecutionResult::Halt {
            reason: HaltReason::PrecompileErrorWithContext(message),
            gas: ResultGas::default(),
            logs: vec![log],
        };
        assert!(estimated_bytes(&mut nested).unwrap() >= baseline + 16_384 + topic_bytes);
    }

    #[test]
    fn hash_lookup_does_not_replace_complete_transaction_validation() {
        let session = EnginePrewarmingCache::default()
            .begin(env(), [hash(0)])
            .unwrap();
        assert!(session.publish(candidate(0)));
        let mut changed = tx(0);
        changed.inner.caller = Address::with_last_byte(203);
        let result = session.take(&changed).unwrap();
        assert!(
            result
                .into_candidate::<std::convert::Infallible>(&changed)
                .is_none()
        );
    }
}

#[cfg(test)]
#[path = "engine_prewarming_tests.rs"]
mod capture_tests;
