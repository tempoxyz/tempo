//! Experimental STM replay for engine block validation.

use std::sync::{Arc, Condvar, Mutex};

use alloy_evm::{Evm, block::ExecutableTxParts};
use reth_engine_tree::tree::{PayloadExecutionStrategy, PrewarmDatabase};
use reth_evm::{
    BlockExecutorForEvm, Database, EvmEnvFor, EvmErrorFor, EvmFor, RecoveredTx,
    block::{BlockExecutionError, BlockExecutor, BlockValidationError},
    execute::ExecutableTxFor,
};
use reth_revm::context::result::{HaltReason, ResultAndState};

use tempo_primitives::TempoTxEnvelope;
use tempo_revm::TempoTxEnv;

use crate::{ExpiringNonceReplay, StorageActionReplay, StorageActionReplayError, TempoEvmConfig};

/// Records independent payment transactions during prewarming and replays them in block order.
///
/// Unsupported transactions and unsuccessful speculation execute normally. A replay conflict
/// rejects the entire block, without sequential retry. This experimental mode can therefore reject
/// blocks accepted by ordinary execution and must only be enabled on coordinated test networks.
#[derive(Clone, Debug, Default)]
pub struct TempoValidationStrategy {
    enabled: bool,
    replay: Arc<ReplayTransactions>,
}

impl TempoValidationStrategy {
    /// Creates a strategy, with STM validation disabled unless explicitly enabled.
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            replay: Arc::default(),
        }
    }
}

impl PayloadExecutionStrategy<TempoEvmConfig> for TempoValidationStrategy {
    fn for_block(&self, transaction_count: usize) -> Self {
        if !self.enabled {
            return self.clone();
        }
        Self {
            enabled: self.enabled,
            replay: Arc::new(ReplayTransactions {
                slots: Mutex::new(
                    (0..transaction_count)
                        .map(|_| ReplaySlot::Pending)
                        .collect(),
                ),
                ready: Condvar::new(),
            }),
        }
    }

    fn requires_prewarming(&self) -> bool {
        self.enabled
    }

    fn allow_parallel_bal_execution(&self) -> bool {
        !self.enabled
    }

    fn configure_prewarm_env(&self, env: &mut EvmEnvFor<TempoEvmConfig>) {
        if !self.enabled {
            env.cfg_env.disable_nonce_check = true;
            env.cfg_env.disable_balance_check = true;
        }
    }

    fn configure_prewarm_evm(
        &self,
        evm: EvmFor<TempoEvmConfig, PrewarmDatabase>,
    ) -> EvmFor<TempoEvmConfig, PrewarmDatabase> {
        if self.enabled {
            evm.with_actions()
        } else {
            evm
        }
    }

    fn prewarm_transaction<Tx: ExecutableTxParts<TempoTxEnv, TempoTxEnvelope>>(
        &self,
        index: usize,
        evm: &mut EvmFor<TempoEvmConfig, PrewarmDatabase>,
        tx: Tx,
    ) -> Result<
        ResultAndState<HaltReason>,
        EvmErrorFor<TempoEvmConfig, <PrewarmDatabase as reth_revm::Database>::Error>,
    > {
        let (env, recovered) = tx.into_parts();
        if !self.enabled {
            return evm.transact(env);
        }
        let tx = recovered.tx();
        // Match the builder's strict payment classifier, including before its T5 activation.
        let candidate = tx.is_payment_v2() && tx.nonce_key_ref().is_some_and(|key| !key.is_zero());
        let expiring_nonce = tx
            .is_expiring_nonce()
            .then(|| {
                Some(ExpiringNonceReplay {
                    hash: tx.as_aa()?.expiring_nonce_hash(*recovered.signer()),
                    valid_before: tx.valid_before()?,
                })
            })
            .flatten();

        evm.clear_actions();
        let output = evm.transact(env)?;
        if candidate
            && output.result.is_success()
            && let Some(actions) = evm.take_actions()
        {
            self.replay.publish(
                index,
                Some(StorageActionReplay {
                    result: output.result.clone(),
                    actions,
                    expiring_nonce,
                    validator_fee: evm.validator_fee(),
                }),
            );
        }
        Ok(output)
    }

    fn on_prewarm_finished(&self, index: usize) {
        if self.enabled {
            self.replay.publish(index, None);
        }
    }

    fn execute_transaction<'a, DB: Database + 'a, Tx: ExecutableTxFor<TempoEvmConfig>>(
        &self,
        index: usize,
        executor: &mut BlockExecutorForEvm<'a, TempoEvmConfig, DB>,
        tx: Tx,
    ) -> Result<(), BlockExecutionError> {
        if self.enabled
            && let Some(replay) = self.replay.take(index)
        {
            let (env, recovered) = tx.into_parts();
            executor.validate_tx_pre_execution(recovered.tx())?;
            return executor
                .execute_transaction_with_actions((env, recovered), replay, |_| {})
                .map_err(|error| {
                    // Provider/internal errors remain processing failures. A replay conflict
                    // must be a validation error so the Engine API returns INVALID.
                    if let Some(reason) =
                        StorageActionReplayError::from_block_execution_error(&error)
                    {
                        BlockValidationError::other(reason).into()
                    } else {
                        error
                    }
                });
        }
        if self.enabled {
            executor.invalidate_expiring_nonce_cache();
        }
        executor.execute_transaction(tx)?;
        Ok(())
    }
}

/// Block-local speculative results. Only the execution thread waits; workers publish by index.
#[derive(Debug, Default)]
struct ReplayTransactions {
    slots: Mutex<Vec<ReplaySlot>>,
    ready: Condvar,
}

impl ReplayTransactions {
    fn publish(&self, index: usize, replay: Option<StorageActionReplay>) {
        let mut slots = self.slots.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(slot @ ReplaySlot::Pending) = slots.get_mut(index) {
            *slot = ReplaySlot::Ready(replay.map(Box::new));
            self.ready.notify_one();
        }
    }

    fn take(&self, index: usize) -> Option<StorageActionReplay> {
        let mut slots = self.slots.lock().unwrap_or_else(|error| error.into_inner());
        while matches!(slots[index], ReplaySlot::Pending) {
            slots = self
                .ready
                .wait(slots)
                .unwrap_or_else(|error| error.into_inner());
        }
        match std::mem::replace(&mut slots[index], ReplaySlot::Consumed) {
            ReplaySlot::Ready(replay) => replay.map(|replay| *replay),
            ReplaySlot::Pending | ReplaySlot::Consumed => None,
        }
    }
}

/// Completion is separate from replay availability: failed speculation must release execution.
#[derive(Debug)]
enum ReplaySlot {
    Pending,
    Ready(Option<Box<StorageActionReplay>>),
    Consumed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        TempoEvmFactory,
        test_utils::{TestExecutorBuilder, test_chainspec},
    };
    use alloy_consensus::transaction::Recovered;
    use alloy_evm::{EvmEnv, EvmFactory, FromRecoveredTx};
    use alloy_primitives::{Address, B256, TxKind, U256};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use alloy_sol_types::SolCall;
    use reth_primitives_traits::{Account, Bytecode};
    use reth_revm::{DatabaseCommit, State, db::InMemoryDB, state::EvmState};
    use reth_storage_api::{EvmStateProvider, EvmStateProviderBox, errors::ProviderResult};
    use std::{sync::mpsc, thread, time::Duration};
    use tempo_chainspec::TempoHardfork;
    use tempo_contracts::precompiles::ITIP20;
    use tempo_precompiles::{
        NONCE_PRECOMPILE_ADDRESS, PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
        storage::{StorageActions, StorageCtx},
        test_util::TIP20Setup,
    };
    use tempo_primitives::{TempoTransaction, TempoTxEnvelope, transaction::Call};

    struct TestProvider(InMemoryDB);

    impl EvmStateProvider for TestProvider {
        fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
            Ok(self
                .0
                .cache
                .accounts
                .get(address)
                .and_then(|account| account.info())
                .map(|info| Account {
                    nonce: info.nonce,
                    balance: info.balance,
                    bytecode_hash: Some(info.code_hash),
                }))
        }

        fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
            Ok(self.0.cache.block_hashes.get(&U256::from(number)).copied())
        }

        fn bytecode_by_hash(&self, hash: &B256) -> ProviderResult<Option<Bytecode>> {
            Ok(self.0.cache.contracts.get(hash).cloned().map(Bytecode))
        }

        fn storage(&self, address: Address, key: B256) -> ProviderResult<Option<U256>> {
            Ok(self
                .0
                .cache
                .accounts
                .get(&address)
                .and_then(|account| account.storage.get(&U256::from_be_bytes(key.0)))
                .copied())
        }
    }

    fn transfer(
        signer: &PrivateKeySigner,
        nonce_key: u64,
        nonce: u64,
    ) -> Recovered<TempoTxEnvelope> {
        transfer_to(signer, nonce_key, nonce, Address::repeat_byte(2))
    }

    fn transfer_to(
        signer: &PrivateKeySigner,
        nonce_key: u64,
        nonce: u64,
        recipient: Address,
    ) -> Recovered<TempoTxEnvelope> {
        signed_transfer(signer, U256::from(nonce_key), nonce, recipient, None)
    }

    fn signed_transfer(
        signer: &PrivateKeySigner,
        nonce_key: U256,
        nonce: u64,
        recipient: Address,
        valid_before: Option<std::num::NonZeroU64>,
    ) -> Recovered<TempoTxEnvelope> {
        let tx = TempoTransaction {
            chain_id: 1,
            max_fee_per_gas: 1,
            gas_limit: 1_000_000,
            fee_token: Some(PATH_USD_ADDRESS),
            nonce_key,
            nonce,
            valid_before,
            calls: vec![Call {
                to: TxKind::Call(PATH_USD_ADDRESS),
                value: U256::ZERO,
                input: ITIP20::transferCall {
                    to: recipient,
                    amount: U256::from(100),
                }
                .abi_encode()
                .into(),
            }],
            ..Default::default()
        };
        let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
        Recovered::new_unchecked(tx.into_signed(signature.into()).into(), signer.address())
    }

    fn fixture(
        signer: &PrivateKeySigner,
    ) -> (InMemoryDB, EvmEnvFor<TempoEvmConfig>, PrivateKeySigner) {
        fixture_with_recipient_balance(signer, 1000)
    }

    fn fixture_with_recipient_balance(
        signer: &PrivateKeySigner,
        recipient_balance: u64,
    ) -> (InMemoryDB, EvmEnvFor<TempoEvmConfig>, PrivateKeySigner) {
        let second_sender = PrivateKeySigner::random();
        let chainspec = test_chainspec();
        let mut db = State::builder()
            .with_database(InMemoryDB::default())
            .build();
        let executor = TestExecutorBuilder::default()
            .with_spec(TempoHardfork::T5)
            .build(&mut db, &chainspec);
        let env = EvmEnv {
            cfg_env: executor.evm().cfg_env().clone(),
            block_env: executor.evm().block().clone(),
        };
        let mut evm = TempoEvmFactory::default().create_evm(InMemoryDB::default(), env.clone());
        StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
            TIP20Setup::path_usd(signer.address())
                .with_issuer(signer.address())
                .with_mint(signer.address(), U256::from(10_000_000))
                .with_mint(second_sender.address(), U256::from(10_000_000))
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(1000))
                .with_mint(Address::repeat_byte(2), U256::from(recipient_balance))
                .apply()
        })
        .unwrap();
        let setup = evm.ctx_mut().journaled_state.finalize();
        evm.db_mut().commit(setup);
        // Keep precompile and funded sender accounts nonempty, as in initialized chain state.
        for address in [
            NONCE_PRECOMPILE_ADDRESS,
            TIP_FEE_MANAGER_ADDRESS,
            signer.address(),
            second_sender.address(),
        ] {
            evm.db_mut().insert_account_info(
                address,
                reth_revm::state::AccountInfo {
                    nonce: 1,
                    ..Default::default()
                },
            );
        }
        // Initialize shared fee slots with a prior payment, leaving the tested recipient alone.
        let warmup = transfer_to(signer, 99, 0, Address::repeat_byte(3));
        let output = evm
            .transact(TempoTxEnv::from_recovered_tx(
                warmup.inner(),
                signer.address(),
            ))
            .unwrap();
        assert!(output.result.is_success());
        evm.db_mut().commit(output.state);
        (evm.finish().0, env, second_sender)
    }

    fn speculate(
        strategy: &TempoValidationStrategy,
        db: &InMemoryDB,
        env: &EvmEnvFor<TempoEvmConfig>,
        index: usize,
        tx: &Recovered<TempoTxEnvelope>,
    ) {
        let provider = Box::new(TestProvider(db.clone())) as EvmStateProviderBox;
        let mut env = env.clone();
        strategy.configure_prewarm_env(&mut env);
        let mut evm = strategy.configure_prewarm_evm(
            TempoEvmFactory::default().create_evm(PrewarmDatabase::new(provider), env),
        );
        let output = strategy.prewarm_transaction(index, &mut evm, tx).unwrap();
        assert!(output.result.is_success(), "{:?}", output.result);
        strategy.on_prewarm_finished(index);
    }

    #[test]
    fn independent_transfers_match_execution_and_state_hooks() {
        transfers_match_execution_and_state_hooks(false);
    }

    #[test]
    fn expiring_nonce_transfers_match_execution_and_state_hooks() {
        transfers_match_execution_and_state_hooks(true);
    }

    fn transfers_match_execution_and_state_hooks(expiring: bool) {
        let signer = PrivateKeySigner::random();
        let (db, env, second_sender) = fixture(&signer);
        let txs = if expiring {
            let valid_before = std::num::NonZeroU64::new(env.block_env.timestamp.to::<u64>() + 10);
            [
                signed_transfer(&signer, U256::MAX, 0, Address::repeat_byte(2), valid_before),
                signed_transfer(
                    &second_sender,
                    U256::MAX,
                    0,
                    Address::repeat_byte(2),
                    valid_before,
                ),
            ]
        } else {
            [transfer(&signer, 42, 0), transfer(&second_sender, 43, 0)]
        };
        let strategy = TempoValidationStrategy::new(true).for_block(txs.len());
        // Finish workers in reverse order; authoritative execution remains in block order.
        for index in (0..txs.len()).rev() {
            speculate(&strategy, &db, &env, index, &txs[index]);
        }
        let chainspec = test_chainspec();
        let mut serial = State::builder()
            .with_database(db.clone())
            .with_bundle_update()
            .build();
        let mut replay = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();
        let (state_tx, state_rx) = mpsc::channel();
        replay.set_state_hook(Some(Box::new(move |state: EvmState| {
            state_tx.send(state).unwrap();
        })));
        let mut expected = TestExecutorBuilder::default()
            .with_spec(TempoHardfork::T5)
            .build(&mut serial, &chainspec);
        let mut actual = TestExecutorBuilder::default()
            .with_spec(TempoHardfork::T5)
            .build(&mut replay, &chainspec);
        for (index, tx) in txs.iter().enumerate() {
            expected.execute_transaction(tx).unwrap();
            strategy
                .execute_transaction(index, &mut actual, tx)
                .unwrap();
            assert_eq!(actual.receipts(), expected.receipts());
        }
        assert_eq!(state_rx.try_iter().count(), txs.len());
        drop(expected);
        drop(actual);
        serial.merge_transitions(reth_revm::db::states::bundle_state::BundleRetention::PlainState);
        replay.merge_transitions(reth_revm::db::states::bundle_state::BundleRetention::PlainState);
        assert_eq!(replay.take_bundle(), serial.take_bundle());
    }

    #[test]
    fn stale_storage_conflict_rejects_a_sequentially_valid_block() {
        let signer = PrivateKeySigner::random();
        let (db, env, _) = fixture_with_recipient_balance(&signer, 0);
        let txs = [transfer(&signer, 42, 0), transfer(&signer, 43, 0)];
        let strategy = TempoValidationStrategy::new(true).for_block(2);
        for (index, tx) in txs.iter().enumerate() {
            speculate(&strategy, &db, &env, index, tx);
        }
        let chainspec = test_chainspec();
        let mut serial = State::builder().with_database(db.clone()).build();
        let mut expected = TestExecutorBuilder::default()
            .with_spec(TempoHardfork::T5)
            .build(&mut serial, &chainspec);
        for tx in &txs {
            expected.execute_transaction(tx).unwrap();
        }
        assert_eq!(expected.receipts().len(), 2);
        let mut replay = State::builder().with_database(db).build();
        let mut executor = TestExecutorBuilder::default()
            .with_spec(TempoHardfork::T5)
            .build(&mut replay, &chainspec);
        strategy
            .execute_transaction(0, &mut executor, &txs[0])
            .unwrap();
        let error = strategy
            .execute_transaction(1, &mut executor, &txs[1])
            .unwrap_err();
        assert_eq!(error.to_string(), "storage action conflict");
        let error = reth_engine_tree::tree::error::InsertBlockErrorKind::from(error);
        assert!(error.ensure_validation_error().is_ok());
        assert_eq!(executor.receipts().len(), 1);
    }

    #[test]
    fn nonce_conflict_rejects_without_sequential_retry() {
        let signer = PrivateKeySigner::random();
        let (db, env, _) = fixture(&signer);
        let txs = [transfer(&signer, 42, 0), transfer(&signer, 42, 0)];
        let strategy = TempoValidationStrategy::new(true).for_block(2);
        for (index, tx) in txs.iter().enumerate() {
            speculate(&strategy, &db, &env, index, tx);
        }
        let chainspec = test_chainspec();
        let mut db = State::builder().with_database(db).build();
        let mut executor = TestExecutorBuilder::default()
            .with_spec(TempoHardfork::T5)
            .build(&mut db, &chainspec);
        strategy
            .execute_transaction(0, &mut executor, &txs[0])
            .unwrap();
        let error = strategy
            .execute_transaction(1, &mut executor, &txs[1])
            .unwrap_err();
        assert_eq!(error.to_string(), "storage action conflict");
        let error = reth_engine_tree::tree::error::InsertBlockErrorKind::from(error);
        assert!(error.ensure_validation_error().is_ok());
        assert_eq!(executor.receipts().len(), 1);
    }

    #[test]
    fn unavailable_speculation_falls_back_and_blocks_are_isolated() {
        let signer = PrivateKeySigner::random();
        let (db, env, _) = fixture(&signer);
        let tx = transfer(&signer, 42, 0);
        let strategy = TempoValidationStrategy::new(true);
        let first = strategy.for_block(1);
        let second = strategy.for_block(1);
        speculate(&first, &db, &env, 0, &tx);
        assert!(matches!(
            second.replay.slots.lock().unwrap()[0],
            ReplaySlot::Pending
        ));
        second.on_prewarm_finished(0);
        let chainspec = test_chainspec();
        let mut db = State::builder().with_database(db).build();
        let mut executor = TestExecutorBuilder::default()
            .with_spec(TempoHardfork::T5)
            .build(&mut db, &chainspec);
        second.execute_transaction(0, &mut executor, &tx).unwrap();
        assert_eq!(executor.receipts().len(), 1);
        assert!(first.replay.take(0).is_some());
    }

    #[test]
    fn failed_speculation_executes_against_prior_transaction_state() {
        let signer = PrivateKeySigner::random();
        let (db, env, _) = fixture(&signer);
        let txs = [transfer(&signer, 42, 0), transfer(&signer, 42, 1)];
        let strategy = TempoValidationStrategy::new(true).for_block(2);
        speculate(&strategy, &db, &env, 0, &txs[0]);
        let provider = Box::new(TestProvider(db.clone())) as EvmStateProviderBox;
        let mut worker = TempoEvmFactory::default()
            .create_evm(PrewarmDatabase::new(provider), env)
            .with_actions();
        assert!(
            strategy
                .prewarm_transaction(1, &mut worker, &txs[1])
                .is_err()
        );
        strategy.on_prewarm_finished(1);
        let chainspec = test_chainspec();
        let mut db = State::builder().with_database(db).build();
        let mut executor = TestExecutorBuilder::default()
            .with_spec(TempoHardfork::T5)
            .build(&mut db, &chainspec);
        for (index, tx) in txs.iter().enumerate() {
            strategy
                .execute_transaction(index, &mut executor, tx)
                .unwrap();
        }
        assert_eq!(executor.receipts().len(), 2);
    }

    #[derive(Debug)]
    struct FailingDatabase;

    impl reth_revm::Database for FailingDatabase {
        type Error = reth_storage_api::errors::ProviderError;

        fn basic(
            &mut self,
            _address: Address,
        ) -> Result<Option<reth_revm::state::AccountInfo>, Self::Error> {
            Err(Self::Error::UnsupportedProvider)
        }

        fn code_by_hash(
            &mut self,
            _hash: B256,
        ) -> Result<reth_revm::bytecode::Bytecode, Self::Error> {
            Err(Self::Error::UnsupportedProvider)
        }

        fn storage(&mut self, _address: Address, _slot: U256) -> Result<U256, Self::Error> {
            Err(Self::Error::UnsupportedProvider)
        }

        fn block_hash(&mut self, _number: u64) -> Result<B256, Self::Error> {
            Err(Self::Error::UnsupportedProvider)
        }
    }

    #[test]
    fn replay_provider_errors_remain_engine_failures() {
        let signer = PrivateKeySigner::random();
        let (db, env, _) = fixture(&signer);
        let tx = transfer(&signer, 42, 0);
        let strategy = TempoValidationStrategy::new(true).for_block(1);
        speculate(&strategy, &db, &env, 0, &tx);
        let chainspec = test_chainspec();
        let mut state = State::builder().with_database(FailingDatabase).build();
        let mut executor = TestExecutorBuilder::default()
            .with_spec(TempoHardfork::T5)
            .build(&mut state, &chainspec);
        let error = strategy
            .execute_transaction(0, &mut executor, &tx)
            .unwrap_err();
        assert!(matches!(error, BlockExecutionError::Internal(_)));
        let error = reth_engine_tree::tree::error::InsertBlockErrorKind::from(error);
        assert!(error.ensure_validation_error().is_err());
        assert!(executor.receipts().is_empty());
    }

    #[test]
    fn failed_worker_releases_waiting_execution() {
        let strategy = TempoValidationStrategy::new(true).for_block(1);
        let worker = strategy.clone();
        let (result_tx, result_rx) = mpsc::channel();
        let consumer = thread::spawn(move || {
            result_tx.send(strategy.replay.take(0).is_none()).unwrap();
        });
        worker.on_prewarm_finished(0);
        assert!(result_rx.recv_timeout(Duration::from_secs(5)).unwrap());
        consumer.join().unwrap();
    }
}
