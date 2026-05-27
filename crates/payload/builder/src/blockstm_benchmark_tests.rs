use crate::blockstm::{
    BlockStmAccessKey,
    action::{
        production::{BlockStmSemanticPlan, capture_tip20_semantic_plan},
        slots::{
            expiring_nonce_ring_key, expiring_nonce_ring_ptr_key, expiring_nonce_seen_key,
            fee_manager_collected_fees_key, tip20_balance_key,
        },
    },
    executor::BlockStmAttempt,
    state_view::{BlockStmTrackingDb, write_set_from_evm_state},
};
use alloy_consensus::Transaction;
use alloy_consensus::transaction::{Recovered, SignerRecoverable};
use alloy_evm::{Evm, EvmEnv, eth::EthBlockExecutionCtx};
use alloy_primitives::{
    Address, B256, Bytes, TxKind, U256,
    map::{AddressMap, B256Map, HashMap, HashSet},
};
use alloy_signer::SignerSync;
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner};
use alloy_sol_types::SolCall;
use reth_evm::{
    ConfigureEvm, Database,
    block::{BlockExecutor, BlockExecutorFactory, TxResult},
};
use reth_primitives_traits::{Account as RethAccount, Bytecode as RethBytecode};
use reth_revm::{
    DatabaseCommit, State,
    database::StateProviderDatabase,
    db::{CacheDB, DbAccount, EmptyDB},
    revm::context_interface::JournalTr,
    state::{Account as EvmAccount, AccountInfo, EvmStorageSlot, TransactionId},
};
use reth_storage_api::{
    AccountReader, BlockHashReader, BytecodeReader, HashedPostStateProvider, StateProofProvider,
    StateProvider, StateRootProvider, StorageRootProvider,
    errors::{ProviderError, ProviderResult},
};
use reth_transaction_pool::PoolTransaction;
use reth_trie::{
    AccountProof, ExecutionWitnessMode, HashedPostState, HashedStorage, MultiProof,
    MultiProofTargets, StorageMultiProof, StorageProof, TrieInput, updates::TrieUpdates,
};
use std::{
    hint::black_box,
    num::NonZeroU64,
    sync::Arc,
    time::{Duration, Instant},
};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardfork, spec::TEMPO_T1_BASE_FEE};
use tempo_evm::{TempoBlockEnv, TempoBlockExecutionCtx, TempoEvmConfig, evm::TempoEvm};
use tempo_precompiles::{
    ADDRESS_REGISTRY_ADDRESS, NONCE_PRECOMPILE_ADDRESS, PATH_USD_ADDRESS,
    SIGNATURE_VERIFIER_ADDRESS, TIP20_CHANNEL_RESERVE_ADDRESS, VALIDATOR_CONFIG_V2_ADDRESS,
    error::TempoPrecompileError,
    nonce::{EXPIRING_NONCE_MAX_EXPIRY_SECS, EXPIRING_NONCE_SET_CAPACITY, NonceManager},
    storage::StorageCtx,
    tip_fee_manager::TipFeeManager,
    tip20::{ISSUER_ROLE, ITIP20, TIP20Token},
    tip20_factory::TIP20Factory,
    tip403_registry::TIP403Registry,
};
use tempo_primitives::{
    AASigned, TempoSignature, TempoTransaction, TempoTxEnvelope,
    transaction::{Call, PrimitiveSignature, TEMPO_EXPIRING_NONCE_KEY, calc_gas_balance_spending},
};
use tempo_revm::gas_params::tempo_gas_params_with_amsterdam;
use tempo_transaction_pool::transaction::TempoPooledTransaction;

const CHAIN_ID: u64 = 1337;
const TXGEN_MNEMONIC: &str = "test test test test test test test test test test test junk";
const ACCOUNT_COUNT: usize = 1_000;
const BENCH_TX_COUNT: usize = 25_000;
const BENCH_SAMPLES: usize = 3;
const BLOCK_TIMESTAMP: u64 = 1_700_000_000;
const TXGEN_GAS_LIMIT: u64 = 300_000;
const TXGEN_FEE_PER_GAS: u128 = 100_000_000_000;
const PARTICIPANT_MINT_AMOUNT: u128 = 1_000_000_000_000_000_000;

#[derive(Clone, Debug)]
struct InMemoryStateProvider {
    accounts: Arc<AddressMap<RethAccount>>,
    storage: Arc<HashMap<(Address, B256), U256>>,
    contracts: Arc<B256Map<RethBytecode>>,
    block_hashes: Arc<HashMap<u64, B256>>,
}

#[derive(Clone)]
struct BenchFixture {
    provider: InMemoryStateProvider,
}

#[derive(Debug, PartialEq, Eq)]
struct ExecutionDigest {
    txs: u64,
    gas_used: u64,
    validator_fees: U256,
    receipts: usize,
    participant_balances: Vec<U256>,
    fee_manager_balance: U256,
    collected_fees: U256,
    nonce_ring_ptr: U256,
    nonce_ring: Vec<U256>,
    nonce_seen: Vec<U256>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct BenchmarkActionCounts {
    expiring_nonce_uses: usize,
    tip20_fee_escrows: usize,
    tip20_transfers: usize,
    collected_fees: usize,
    semantic_prefix_reads: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct BenchmarkPhaseTimes {
    setup: Duration,
    batch_setup: Duration,
    worker_merge: Duration,
    semantic_reduce: Duration,
    strip_state: Duration,
    hydrate_cache: Duration,
    commit_tx: Duration,
    bump_bal_index: Duration,
    final_semantic_commit: Duration,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct BenchmarkStats {
    accepted: u64,
    rejected: u64,
    speculative_executions: u64,
    committed: u64,
    conflicts: u64,
    reused_worker_results: u64,
    reexecutions: u64,
    serial_commit_reexecutions: u64,
    fallback: u64,
    built_blocks: u64,
    max_in_flight_real_evm_executions: u64,
    worker_lanes_with_attempts: u64,
    semantic_actions: u64,
    action_counts: BenchmarkActionCounts,
}

#[derive(Debug, PartialEq, Eq)]
struct ParallelBenchmarkRun {
    digest: Option<ExecutionDigest>,
    stats: BenchmarkStats,
    gas_used: u64,
    speculative_wall: Duration,
    commit_wall: Duration,
    phase_times: BenchmarkPhaseTimes,
}

#[allow(dead_code)]
struct BenchSemanticWorkerOutput {
    semantic_effects: BenchSemanticChunkEffects,
    stats: BenchmarkStats,
    gas_used: u64,
    validator_fees: U256,
}

struct BenchFullWorkerOutput {
    commits: Vec<BenchCommitOutput>,
    semantic_effects: BenchSemanticChunkEffects,
    stats: BenchmarkStats,
}

struct BenchCommitOutput {
    commit: tempo_evm::TempoStrippedTxCommit,
    validator_fee: U256,
    semantic_actions: usize,
}

#[allow(dead_code)]
struct SerialBenchmarkRun {
    digest: Option<ExecutionDigest>,
    gas_used: u64,
}

impl BenchmarkStats {
    fn add_pure_tip20_actions(&mut self) {
        self.action_counts.expiring_nonce_uses += 1;
        self.action_counts.tip20_fee_escrows += 1;
        self.action_counts.tip20_transfers += 1;
        self.action_counts.collected_fees += 1;
        self.action_counts.semantic_prefix_reads += 1;
    }
}

fn timed<T>(enabled: bool, total: &mut Duration, f: impl FnOnce() -> T) -> T {
    if enabled {
        let started = Instant::now();
        let output = f();
        *total += started.elapsed();
        output
    } else {
        f()
    }
}

fn blockstm_bench_workers() -> usize {
    std::env::var("TEMPO_BLOCKSTM_BENCH_WORKERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|workers| *workers > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map_or(4, usize::from)
                .clamp(4, 32)
        })
}

#[derive(Debug, Clone, Copy)]
struct BenchFastSemanticPlan {
    nonce_hash: B256,
    valid_before: u64,
    fee_payer: Address,
    sender: Address,
    recipient: Address,
    transfer_amount: U256,
    max_fee_precharge: U256,
    actual_spending: U256,
    refund_amount: U256,
}

#[derive(Clone)]
struct BenchSemanticChunkEffects {
    balance_debits: Vec<U256>,
    balance_credits: Vec<U256>,
    fee_manager_delta: U256,
    collected_fees_delta: U256,
    nonce_writes: Vec<(BlockStmAccessKey, U256)>,
    nonce_count: usize,
}

impl BenchSemanticChunkEffects {
    fn new(participant_count: usize) -> Self {
        Self {
            balance_debits: vec![U256::ZERO; participant_count],
            balance_credits: vec![U256::ZERO; participant_count],
            fee_manager_delta: U256::ZERO,
            collected_fees_delta: U256::ZERO,
            nonce_writes: Vec::new(),
            nonce_count: 0,
        }
    }
}

fn materialize_bench_semantic_changes(
    provider: &InMemoryStateProvider,
    participants: &[Address],
    beneficiary: Address,
    effects: BenchSemanticChunkEffects,
) -> AddressMap<EvmAccount> {
    let mut changes = AddressMap::<EvmAccount>::default();
    semantic_change_account(provider, &mut changes, PATH_USD_ADDRESS)
        .storage
        .reserve(participants.len() + 1);
    if let BlockStmAccessKey::Storage { address, .. } =
        fee_manager_collected_fees_key(beneficiary, PATH_USD_ADDRESS)
    {
        semantic_change_account(provider, &mut changes, address)
            .storage
            .reserve(1);
    }
    if let BlockStmAccessKey::Storage { address, .. } = expiring_nonce_ring_ptr_key() {
        semantic_change_account(provider, &mut changes, address)
            .storage
            .reserve(effects.nonce_writes.len() + 1);
    }

    for (idx, participant) in participants.iter().copied().enumerate() {
        let initial = provider_storage(provider, tip20_balance_key(PATH_USD_ADDRESS, participant));
        assert!(
            initial >= effects.balance_debits[idx],
            "benchmark participant {participant} cannot cover semantic debit without prefix credits"
        );
        let after_debits = initial
            .checked_sub(effects.balance_debits[idx])
            .expect("benchmark balance underflow");
        let balance = after_debits
            .checked_add(effects.balance_credits[idx])
            .expect("benchmark balance overflow");
        materialize_storage_value(
            provider,
            &mut changes,
            tip20_balance_key(PATH_USD_ADDRESS, participant),
            balance,
        );
    }

    let fee_manager_balance = provider_storage(
        provider,
        tip20_balance_key(PATH_USD_ADDRESS, tempo_precompiles::TIP_FEE_MANAGER_ADDRESS),
    )
    .checked_add(effects.fee_manager_delta)
    .expect("benchmark fee manager overflow");
    materialize_storage_value(
        provider,
        &mut changes,
        tip20_balance_key(PATH_USD_ADDRESS, tempo_precompiles::TIP_FEE_MANAGER_ADDRESS),
        fee_manager_balance,
    );

    let collected_fees = provider_storage(
        provider,
        fee_manager_collected_fees_key(beneficiary, PATH_USD_ADDRESS),
    )
    .checked_add(effects.collected_fees_delta)
    .expect("benchmark collected fees overflow");
    materialize_storage_value(
        provider,
        &mut changes,
        fee_manager_collected_fees_key(beneficiary, PATH_USD_ADDRESS),
        collected_fees,
    );

    let initial_ring_ptr = provider_storage(provider, expiring_nonce_ring_ptr_key()).to::<u32>();
    assert!(
        effects.nonce_count <= (EXPIRING_NONCE_SET_CAPACITY - initial_ring_ptr) as usize,
        "benchmark nonce ring should not wrap"
    );
    for (key, value) in effects.nonce_writes {
        materialize_storage_value_with_original(provider, &mut changes, key, U256::ZERO, value);
    }
    materialize_storage_value(
        provider,
        &mut changes,
        expiring_nonce_ring_ptr_key(),
        U256::from(initial_ring_ptr + effects.nonce_count as u32),
    );

    changes
}

fn materialize_storage_value(
    provider: &InMemoryStateProvider,
    changes: &mut AddressMap<EvmAccount>,
    key: BlockStmAccessKey,
    value: U256,
) {
    let original = provider_storage(provider, key);
    materialize_storage_value_with_original(provider, changes, key, original, value);
}

fn materialize_storage_value_with_original(
    provider: &InMemoryStateProvider,
    changes: &mut AddressMap<EvmAccount>,
    key: BlockStmAccessKey,
    original: U256,
    value: U256,
) {
    let BlockStmAccessKey::Storage { address, slot } = key else {
        return;
    };
    if original == value {
        return;
    }
    let account = semantic_change_account(provider, changes, address);
    account.storage.insert(
        slot,
        EvmStorageSlot::new_changed(original, value, TransactionId::ZERO),
    );
}

fn semantic_change_account<'a>(
    provider: &InMemoryStateProvider,
    changes: &'a mut AddressMap<EvmAccount>,
    address: Address,
) -> &'a mut EvmAccount {
    changes.entry(address).or_insert_with(|| {
        let info: AccountInfo = provider
            .accounts
            .get(&address)
            .copied()
            .unwrap_or_default()
            .into();
        let mut account = EvmAccount::default();
        account.info = info.clone();
        *account.original_info_mut() = info;
        account.mark_touch();
        account
    })
}

fn nonce_ring_slot(initial_ring_ptr: u32, sequence: usize) -> u32 {
    let sequence =
        u32::try_from(sequence).expect("benchmark expiring nonce sequence should fit in u32");
    let slot = initial_ring_ptr
        .checked_add(sequence)
        .expect("benchmark expiring nonce ring sequence overflow");
    assert!(
        slot < EXPIRING_NONCE_SET_CAPACITY,
        "benchmark nonce ring should not wrap"
    );
    slot
}

fn commit_semantic_changes<DB>(
    db: &mut DB,
    changes: AddressMap<EvmAccount>,
) -> Result<(), DB::Error>
where
    DB: Database + DatabaseCommit,
{
    for address in changes.keys() {
        let _ = db.basic(*address)?;
    }
    db.commit(changes);
    Ok(())
}

fn merge_bench_semantic_effects(
    target: &mut BenchSemanticChunkEffects,
    source: BenchSemanticChunkEffects,
) {
    for idx in 0..target.balance_debits.len() {
        checked_add_assign(
            &mut target.balance_debits[idx],
            source.balance_debits[idx],
            "benchmark balance debit overflow",
        );
        checked_add_assign(
            &mut target.balance_credits[idx],
            source.balance_credits[idx],
            "benchmark balance credit overflow",
        );
    }
    checked_add_assign(
        &mut target.fee_manager_delta,
        source.fee_manager_delta,
        "benchmark fee manager overflow",
    );
    checked_add_assign(
        &mut target.collected_fees_delta,
        source.collected_fees_delta,
        "benchmark collected fees overflow",
    );
    target.nonce_writes.extend(source.nonce_writes);
    target.nonce_count += source.nonce_count;
}

fn record_bench_semantic_plan(
    initial_ring_ptr: u32,
    nonce_sequence: usize,
    participant_index: &AddressMap<usize>,
    effects: &mut BenchSemanticChunkEffects,
    plan: BenchFastSemanticPlan,
) {
    assert!(plan.valid_before > BLOCK_TIMESTAMP);
    assert!(plan.valid_before <= BLOCK_TIMESTAMP + EXPIRING_NONCE_MAX_EXPIRY_SECS);
    assert_eq!(
        plan.actual_spending
            .checked_add(plan.refund_amount)
            .expect("benchmark fee arithmetic overflow"),
        plan.max_fee_precharge
    );
    effects.nonce_writes.push((
        expiring_nonce_ring_key(nonce_ring_slot(initial_ring_ptr, nonce_sequence)),
        U256::from_be_bytes(plan.nonce_hash.0),
    ));
    effects.nonce_writes.push((
        expiring_nonce_seen_key(plan.nonce_hash),
        U256::from(plan.valid_before),
    ));
    effects.nonce_count += 1;

    add_participant_delta(
        participant_index,
        &mut effects.balance_debits,
        plan.fee_payer,
        plan.max_fee_precharge,
        "benchmark fee payer must be a participant",
    );
    add_participant_delta(
        participant_index,
        &mut effects.balance_credits,
        plan.fee_payer,
        plan.refund_amount,
        "benchmark fee payer must be a participant",
    );
    add_participant_delta(
        participant_index,
        &mut effects.balance_debits,
        plan.sender,
        plan.transfer_amount,
        "benchmark sender must be a participant",
    );
    add_participant_delta(
        participant_index,
        &mut effects.balance_credits,
        plan.recipient,
        plan.transfer_amount,
        "benchmark recipient must be a participant",
    );
    checked_add_assign(
        &mut effects.fee_manager_delta,
        plan.actual_spending,
        "benchmark fee manager overflow",
    );
    checked_add_assign(
        &mut effects.collected_fees_delta,
        plan.actual_spending,
        "benchmark collected fees overflow",
    );
}

fn add_participant_delta(
    participant_index: &AddressMap<usize>,
    values: &mut [U256],
    account: Address,
    amount: U256,
    missing_message: &str,
) {
    let idx = *participant_index.get(&account).expect(missing_message);
    checked_add_assign(&mut values[idx], amount, "benchmark balance delta overflow");
}

fn checked_add_assign(value: &mut U256, amount: U256, message: &str) {
    *value = value.checked_add(amount).expect(message);
}

#[allow(dead_code)]
fn merge_benchmark_stats(target: &mut BenchmarkStats, source: BenchmarkStats) {
    target.accepted += source.accepted;
    target.rejected += source.rejected;
    target.speculative_executions += source.speculative_executions;
    target.committed += source.committed;
    target.conflicts += source.conflicts;
    target.reused_worker_results += source.reused_worker_results;
    target.reexecutions += source.reexecutions;
    target.serial_commit_reexecutions += source.serial_commit_reexecutions;
    target.fallback += source.fallback;
    target.built_blocks = target.built_blocks.max(source.built_blocks);
    target.max_in_flight_real_evm_executions = target
        .max_in_flight_real_evm_executions
        .max(source.max_in_flight_real_evm_executions);
    target.worker_lanes_with_attempts += source.worker_lanes_with_attempts;
    target.semantic_actions += source.semantic_actions;
    target.action_counts.expiring_nonce_uses += source.action_counts.expiring_nonce_uses;
    target.action_counts.tip20_fee_escrows += source.action_counts.tip20_fee_escrows;
    target.action_counts.tip20_transfers += source.action_counts.tip20_transfers;
    target.action_counts.collected_fees += source.action_counts.collected_fees;
    target.action_counts.semantic_prefix_reads += source.action_counts.semantic_prefix_reads;
}

fn provider_storage(provider: &InMemoryStateProvider, key: BlockStmAccessKey) -> U256 {
    let BlockStmAccessKey::Storage { address, slot } = key else {
        return U256::ZERO;
    };
    provider
        .storage(address, B256::new(slot.to_be_bytes()))
        .expect("benchmark provider read")
        .unwrap_or_default()
}

impl BenchFixture {
    fn state_db(&self) -> State<StateProviderDatabase<InMemoryStateProvider>> {
        State::builder()
            .with_database(StateProviderDatabase::new(self.provider.clone()))
            .with_bundle_update()
            .build()
    }
}

impl AccountReader for InMemoryStateProvider {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<RethAccount>> {
        Ok(self.accounts.get(address).copied())
    }
}

impl StateProvider for InMemoryStateProvider {
    fn storage(&self, account: Address, storage_key: B256) -> ProviderResult<Option<U256>> {
        Ok(self.storage.get(&(account, storage_key)).copied())
    }
}

impl BytecodeReader for InMemoryStateProvider {
    fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<RethBytecode>> {
        Ok(self.contracts.get(code_hash).cloned())
    }
}

impl BlockHashReader for InMemoryStateProvider {
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        Ok(self.block_hashes.get(&number).copied())
    }

    fn canonical_hashes_range(&self, _start: u64, _end: u64) -> ProviderResult<Vec<B256>> {
        Err(ProviderError::UnsupportedProvider)
    }
}

impl StateRootProvider for InMemoryStateProvider {
    fn state_root(&self, _hashed_state: HashedPostState) -> ProviderResult<B256> {
        Err(ProviderError::UnsupportedProvider)
    }

    fn state_root_from_nodes(&self, _input: TrieInput) -> ProviderResult<B256> {
        Err(ProviderError::UnsupportedProvider)
    }

    fn state_root_with_updates(
        &self,
        _hashed_state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        Err(ProviderError::UnsupportedProvider)
    }

    fn state_root_from_nodes_with_updates(
        &self,
        _input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        Err(ProviderError::UnsupportedProvider)
    }
}

impl StorageRootProvider for InMemoryStateProvider {
    fn storage_root(
        &self,
        _address: Address,
        _hashed_storage: HashedStorage,
    ) -> ProviderResult<B256> {
        Err(ProviderError::UnsupportedProvider)
    }

    fn storage_proof(
        &self,
        _address: Address,
        _slot: B256,
        _hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageProof> {
        Err(ProviderError::UnsupportedProvider)
    }

    fn storage_multiproof(
        &self,
        _address: Address,
        _slots: &[B256],
        _hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageMultiProof> {
        Err(ProviderError::UnsupportedProvider)
    }
}

impl StateProofProvider for InMemoryStateProvider {
    fn proof(
        &self,
        _input: TrieInput,
        _address: Address,
        _slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        Err(ProviderError::UnsupportedProvider)
    }

    fn multiproof(
        &self,
        _input: TrieInput,
        _targets: MultiProofTargets,
    ) -> ProviderResult<MultiProof> {
        Err(ProviderError::UnsupportedProvider)
    }

    fn witness(
        &self,
        _input: TrieInput,
        _target: HashedPostState,
        _mode: ExecutionWitnessMode,
    ) -> ProviderResult<Vec<Bytes>> {
        Err(ProviderError::UnsupportedProvider)
    }
}

impl HashedPostStateProvider for InMemoryStateProvider {
    fn hashed_post_state(&self, _bundle_state: &reth_revm::db::BundleState) -> HashedPostState {
        unreachable!("Block-STM builder benchmark does not compute hashed post-state")
    }
}

fn bench_env(block_timestamp: u64) -> EvmEnv<TempoHardfork, TempoBlockEnv> {
    let spec = TempoHardfork::T5;
    let mut cfg_env = reth_revm::context::CfgEnv::default();
    cfg_env.chain_id = CHAIN_ID;
    cfg_env.spec = spec;
    cfg_env.gas_params = tempo_gas_params_with_amsterdam(spec, false);
    cfg_env.tx_gas_limit_cap = spec.tx_gas_limit_cap();

    EvmEnv {
        cfg_env,
        block_env: TempoBlockEnv {
            inner: reth_revm::context::BlockEnv {
                number: U256::from(1),
                beneficiary: Address::repeat_byte(0x42),
                timestamp: U256::from(block_timestamp),
                basefee: TEMPO_T1_BASE_FEE,
                gas_limit: 10_000_000_000,
                ..Default::default()
            },
            timestamp_millis_part: 0,
        },
    }
}

fn bench_ctx(tx_count: usize) -> TempoBlockExecutionCtx<'static> {
    TempoBlockExecutionCtx {
        inner: EthBlockExecutionCtx {
            parent_hash: B256::ZERO,
            parent_beacon_block_root: Some(B256::ZERO),
            ommers: &[],
            withdrawals: None,
            extra_data: Bytes::new(),
            tx_count_hint: Some(tx_count),
            slot_number: None,
        },
        general_gas_limit: 10_000_000_000,
        shared_gas_limit: 0,
        validator_set: None,
        consensus_context: None,
        subblock_fee_recipients: Default::default(),
    }
}

fn seed_fixture(participants: &[Address]) -> BenchFixture {
    let mut evm = TempoEvm::new(CacheDB::new(EmptyDB::default()), bench_env(BLOCK_TIMESTAMP));
    let admin = participants[0];

    let ctx = evm.ctx_mut();
    StorageCtx::enter_evm(
        &mut ctx.journaled_state,
        &ctx.block,
        &ctx.cfg,
        &ctx.tx,
        || {
            TIP403Registry::new().initialize()?;
            TIP20Factory::new().initialize()?;
            TIP20Factory::new().create_token_reserved_address(
                PATH_USD_ADDRESS,
                "pathUSD",
                "pathUSD",
                "USD",
                Address::ZERO,
                admin,
            )?;

            let mut token = TIP20Token::from_address(PATH_USD_ADDRESS)?;
            token.grant_role_internal(admin, *ISSUER_ROLE)?;
            for participant in participants {
                token.mint(
                    admin,
                    ITIP20::mintCall {
                        to: *participant,
                        amount: U256::from(PARTICIPANT_MINT_AMOUNT),
                    },
                )?;
            }

            TipFeeManager::new().initialize()?;
            NonceManager::new().initialize()?;
            Ok::<(), TempoPrecompileError>(())
        },
    )
    .expect("failed to seed Block-STM TIP20 benchmark fixture");

    let evm_state = evm.ctx_mut().journaled_state.evm_state().clone();
    evm.db_mut().commit(evm_state);
    let state_cache = evm.finish().0.cache;

    let mut accounts = AddressMap::default();
    let mut storage = HashMap::default();
    let mut contracts = B256Map::default();
    let mut block_hashes = HashMap::default();

    for (hash, bytecode) in state_cache.contracts {
        contracts.insert(hash, RethBytecode(bytecode));
    }
    for (address, account) in state_cache.accounts {
        insert_account(&mut accounts, address, &account);
        for (slot, value) in account.storage {
            storage.insert((address, B256::new(slot.to_be_bytes())), value);
        }
    }
    for (number, hash) in state_cache.block_hashes {
        block_hashes.insert(number.to::<u64>(), hash);
    }
    for address in [
        ADDRESS_REGISTRY_ADDRESS,
        NONCE_PRECOMPILE_ADDRESS,
        SIGNATURE_VERIFIER_ADDRESS,
        TIP20_CHANNEL_RESERVE_ADDRESS,
        VALIDATOR_CONFIG_V2_ADDRESS,
    ] {
        accounts.entry(address).or_insert_with(RethAccount::default);
    }
    for participant in participants {
        accounts
            .entry(*participant)
            .or_insert_with(RethAccount::default);
    }

    BenchFixture {
        provider: InMemoryStateProvider {
            accounts: Arc::new(accounts),
            storage: Arc::new(storage),
            contracts: Arc::new(contracts),
            block_hashes: Arc::new(block_hashes),
        },
    }
}

fn insert_account(accounts: &mut AddressMap<RethAccount>, address: Address, account: &DbAccount) {
    if let Some(info) = account.info() {
        accounts.insert(address, RethAccount::from(&info));
    }
}

fn txgen_signers() -> Vec<PrivateKeySigner> {
    (0..ACCOUNT_COUNT)
        .map(|idx| {
            MnemonicBuilder::from_phrase(TXGEN_MNEMONIC)
                .index(idx as u32)
                .expect("valid txgen account index")
                .build()
                .expect("valid txgen mnemonic")
        })
        .collect()
}

fn sign_tip20_transfer(
    signer: &PrivateKeySigner,
    recipient: Address,
    unique_id: u64,
) -> Recovered<TempoTxEnvelope> {
    let tx = TempoTransaction {
        chain_id: CHAIN_ID,
        fee_token: Some(PATH_USD_ADDRESS),
        max_priority_fee_per_gas: TXGEN_FEE_PER_GAS,
        max_fee_per_gas: TXGEN_FEE_PER_GAS,
        gas_limit: TXGEN_GAS_LIMIT,
        calls: vec![Call {
            to: TxKind::Call(PATH_USD_ADDRESS),
            value: U256::ZERO,
            input: Bytes::from(
                ITIP20::transferCall {
                    to: recipient,
                    amount: U256::ONE,
                }
                .abi_encode(),
            ),
        }],
        access_list: Default::default(),
        nonce_key: TEMPO_EXPIRING_NONCE_KEY,
        nonce: 0,
        fee_payer_signature: None,
        valid_before: Some(NonZeroU64::new(BLOCK_TIMESTAMP + 10).unwrap()),
        valid_after: Some(
            NonZeroU64::new(BLOCK_TIMESTAMP - BENCH_TX_COUNT as u64 + unique_id)
                .expect("benchmark valid_after must be non-zero"),
        ),
        key_authorization: None,
        tempo_authorization_list: Vec::new(),
    };
    let signature = signer
        .sign_hash_sync(&tx.signature_hash())
        .expect("failed to sign generated TIP20 transaction");
    let signed = AASigned::new_unhashed(
        tx,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
    );

    TempoTxEnvelope::from(signed)
        .try_into_recovered()
        .expect("generated TIP20 benchmark transaction should recover")
}

fn workload() -> (
    Vec<Recovered<TempoTxEnvelope>>,
    Vec<TempoPooledTransaction>,
    Vec<Address>,
) {
    let signers = txgen_signers();
    let participants = signers
        .iter()
        .map(PrivateKeySigner::address)
        .collect::<Vec<_>>();
    let transactions: Vec<Recovered<TempoTxEnvelope>> = (0..BENCH_TX_COUNT)
        .map(|idx| {
            let signer = &signers[idx % signers.len()];
            let recipient = participants[(idx.wrapping_mul(17) + 1) % participants.len()];
            sign_tip20_transfer(signer, recipient, idx as u64)
        })
        .collect();
    let pooled = transactions
        .iter()
        .cloned()
        .map(TempoPooledTransaction::new)
        .collect::<Vec<_>>();
    for tx in &pooled {
        let _ = tx.tx_env();
    }
    (transactions, pooled, participants)
}

fn execute_serial(
    config: &TempoEvmConfig,
    fixture: &BenchFixture,
    txs: &[Recovered<TempoTxEnvelope>],
    pooled: &[TempoPooledTransaction],
    participants: &[Address],
) -> ExecutionDigest {
    execute_serial_run(config, fixture, txs, pooled, participants, true)
        .digest
        .expect("serial digest requested")
}

#[allow(dead_code)]
fn execute_serial_no_digest(
    config: &TempoEvmConfig,
    fixture: &BenchFixture,
    pooled: &[TempoPooledTransaction],
) -> u64 {
    execute_serial_run(config, fixture, &[], pooled, &[], false).gas_used
}

fn execute_serial_run(
    config: &TempoEvmConfig,
    fixture: &BenchFixture,
    txs: &[Recovered<TempoTxEnvelope>],
    pooled: &[TempoPooledTransaction],
    participants: &[Address],
    include_digest: bool,
) -> SerialBenchmarkRun {
    let evm = TempoEvm::new(fixture.state_db(), bench_env(BLOCK_TIMESTAMP));
    let mut executor = BlockExecutorFactory::create_executor(config, evm, bench_ctx(pooled.len()));
    executor
        .apply_pre_execution_changes()
        .expect("failed to apply serial pre-execution changes");

    let mut tx_count = 0u64;
    let mut gas_used = 0u64;
    let mut validator_fees = U256::ZERO;
    for pool_tx in pooled {
        black_box(pool_tx.fee_balance_slot());
        let output = executor
            .execute_transaction_without_commit(pool_tx.clone_into_with_tx_env())
            .expect("serial TIP20 transaction execution failed");
        assert!(
            output.result().result.is_success(),
            "serial TIP20 transaction reverted: {:?}",
            output.result().result
        );
        validator_fees += output.validator_fee();
        gas_used = gas_used.saturating_add(executor.commit_transaction(output).tx_gas_used());
        executor.evm_mut().db_mut().bump_bal_index();
        tx_count += 1;
    }

    let digest = include_digest.then(|| {
        digest(
            &mut executor,
            txs,
            participants,
            tx_count,
            gas_used,
            validator_fees,
        )
    });
    SerialBenchmarkRun { digest, gas_used }
}

fn execute_parallel_blockstm(
    config: &TempoEvmConfig,
    fixture: &BenchFixture,
    txs: &[Recovered<TempoTxEnvelope>],
    pooled: &[TempoPooledTransaction],
    participants: &[Address],
    workers: usize,
    include_digest: bool,
) -> ParallelBenchmarkRun {
    let profile_phases = std::env::var_os("TEMPO_BLOCKSTM_BENCH_PROFILE").is_some();
    let mut phase_times = BenchmarkPhaseTimes::default();
    let mut executor = timed(profile_phases, &mut phase_times.setup, || {
        let evm = TempoEvm::new(fixture.state_db(), bench_env(BLOCK_TIMESTAMP));
        let mut executor =
            BlockExecutorFactory::create_executor(config, evm, bench_ctx(pooled.len()));
        executor
            .apply_pre_execution_changes()
            .expect("failed to apply Block-STM pre-execution changes");
        executor
    });

    let batch_len = pooled.len().max(1);
    let beneficiary = executor.evm().block().beneficiary;
    let mut participant_index = AddressMap::default();
    for (idx, participant) in participants.iter().copied().enumerate() {
        participant_index.insert(participant, idx);
    }
    let mut semantic_effects = BenchSemanticChunkEffects::new(participants.len());
    let initial_ring_ptr =
        provider_storage(&fixture.provider, expiring_nonce_ring_ptr_key()).to::<u32>();
    let mut tx_count = 0u64;
    let mut gas_used = 0u64;
    let mut validator_fees = U256::ZERO;
    let mut stats = BenchmarkStats {
        built_blocks: 1,
        ..Default::default()
    };
    let mut speculative_wall = Duration::ZERO;
    let mut commit_wall = Duration::ZERO;
    let mut final_semantic_changes = None;
    for (batch_base, batch) in pooled.chunks(batch_len).enumerate() {
        let first_index = batch_base * batch_len;
        let (prefix_cache, evm_env, ctx, worker_count) =
            timed(profile_phases, &mut phase_times.batch_setup, || {
                (
                    executor.evm_mut().db_mut().cache.clone(),
                    executor.evm().evm_env(),
                    bench_ctx(pooled.len()),
                    workers.max(1).min(batch.len()),
                )
            });
        let speculative_started = Instant::now();
        let worker_outputs = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(worker_count);
            for worker in 0..worker_count {
                let batch = batch;
                let provider = fixture.provider.clone();
                let evm_env = evm_env.clone();
                let ctx = ctx.clone();
                let prefix_cache = prefix_cache.clone();
                let participant_index = &participant_index;
                handles.push(
                    std::thread::Builder::new()
                        .name(format!("blockstm-{}", worker + 1))
                        .spawn_scoped(scope, move || {
                            let mut output = BenchFullWorkerOutput {
                                commits: Vec::with_capacity(batch.len().div_ceil(worker_count)),
                                semantic_effects: BenchSemanticChunkEffects::new(
                                    participant_index.len(),
                                ),
                                stats: BenchmarkStats::default(),
                            };
                            for offset in (worker..batch.len()).step_by(worker_count) {
                                let attempt = execute_bench_attempt(
                                    provider.clone(),
                                    config,
                                    evm_env.clone(),
                                    ctx.clone(),
                                    prefix_cache.clone(),
                                    first_index + offset,
                                    &batch[offset],
                                    beneficiary,
                                );

                                let result_ref = attempt
                                    .output
                                    .execution_result
                                    .as_ref()
                                    .expect("Block-STM attempt must execute successfully");
                                if attempt.output.semantic_plan.is_none() {
                                    let hot_writes = attempt
                                        .write_set
                                        .iter()
                                        .filter_map(|(key, value)| match key {
                                            crate::blockstm::BlockStmAccessKey::Storage {
                                                address,
                                                slot,
                                            } if *address == PATH_USD_ADDRESS
                                                || *address
                                                    == tempo_precompiles::TIP_FEE_MANAGER_ADDRESS
                                                || *address == NONCE_PRECOMPILE_ADDRESS =>
                                            {
                                                Some((*address, *slot, *value))
                                            }
                                            _ => None,
                                        })
                                        .collect::<Vec<_>>();
                                    panic!(
                                        "pure TIP20 transaction must capture semantic actions; success={:?} fee={} hot_writes={hot_writes:?}",
                                        result_ref.result().result,
                                        result_ref.validator_fee()
                                    )
                                }

                                let BenchAttemptOutput {
                                    execution_result,
                                    semantic_plan,
                                    fast_plan,
                                } = attempt.output;
                                let semantic_plan = semantic_plan
                                    .expect("Block-STM pure TIP20 semantic plan missing");
                                let fast_plan =
                                    fast_plan.expect("Block-STM pure TIP20 fast semantic plan missing");
                                record_bench_semantic_plan(
                                    initial_ring_ptr,
                                    first_index + offset,
                                    participant_index,
                                    &mut output.semantic_effects,
                                    fast_plan,
                                );
                                let result =
                                    execution_result.expect("Block-STM pure TIP20 execution failed");
                                let validator_fee = result.validator_fee();
                                output.commits.push(BenchCommitOutput {
                                    commit: result
                                        .into_stripped_commit()
                                        .expect("Block-STM pure TIP20 result must be stripped"),
                                    validator_fee,
                                    semantic_actions: semantic_plan.action_count(),
                                });
                                output.stats.speculative_executions += 1;
                            }
                            if output.stats.speculative_executions > 0 {
                                output.stats.worker_lanes_with_attempts = 1;
                            }
                            output
                        })
                        .expect("spawn Block-STM benchmark worker"),
                );
            }

            handles
                .into_iter()
                .map(|handle| handle.join().expect("worker panicked"))
                .collect::<Vec<_>>()
        });
        speculative_wall += speculative_started.elapsed();
        stats.max_in_flight_real_evm_executions = stats
            .max_in_flight_real_evm_executions
            .max(worker_count as u64);
        let mut worker_commit_iters = timed(profile_phases, &mut phase_times.worker_merge, || {
            let mut worker_commit_iters = Vec::with_capacity(worker_count);
            for output in worker_outputs {
                merge_benchmark_stats(&mut stats, output.stats);
                merge_bench_semantic_effects(&mut semantic_effects, output.semantic_effects);
                worker_commit_iters.push(output.commits.into_iter());
            }
            worker_commit_iters
        });

        let semantic_effects_for_materialization = std::mem::replace(
            &mut semantic_effects,
            BenchSemanticChunkEffects::new(participants.len()),
        );
        let (semantic_changes, semantic_reduce_elapsed) = std::thread::scope(|scope| {
            let provider = &fixture.provider;
            let semantic_handle = std::thread::Builder::new()
                .name("blockstm-mat-1".to_string())
                .spawn_scoped(scope, move || {
                    let started = profile_phases.then(Instant::now);
                    let changes = materialize_bench_semantic_changes(
                        provider,
                        participants,
                        beneficiary,
                        semantic_effects_for_materialization,
                    );
                    let elapsed = started.map_or(Duration::ZERO, |started| started.elapsed());
                    (changes, elapsed)
                })
                .expect("spawn Block-STM semantic materialization worker");

            executor.reserve_receipts(batch.len());
            let commit_started = Instant::now();
            for offset in 0..batch.len() {
                let commit = worker_commit_iters[offset % worker_count]
                    .next()
                    .expect("Block-STM commit output missing");
                let BenchCommitOutput {
                    commit,
                    validator_fee,
                    semantic_actions,
                } = commit;
                stats.semantic_actions += semantic_actions as u64;
                stats.add_pure_tip20_actions();

                validator_fees += validator_fee;
                let tx_gas_used = executor
                    .commit_prepared_stripped_transaction(commit)
                    .tx_gas_used();
                gas_used = gas_used.saturating_add(tx_gas_used);
                executor.evm_mut().db_mut().bump_bal_index();
                tx_count += 1;
                stats.accepted += 1;
                stats.committed += 1;
                stats.reused_worker_results += 1;
            }
            let commit_elapsed = commit_started.elapsed();
            commit_wall += commit_elapsed;
            if profile_phases {
                phase_times.commit_tx += commit_elapsed;
            }

            semantic_handle
                .join()
                .expect("semantic materialization worker panicked")
        });
        phase_times.semantic_reduce += semantic_reduce_elapsed;
        final_semantic_changes = Some(semantic_changes);
    }

    let semantic_changes =
        final_semantic_changes.expect("Block-STM benchmark semantic changes missing");

    timed(
        profile_phases,
        &mut phase_times.final_semantic_commit,
        || {
            commit_semantic_changes(executor.evm_mut().db_mut(), semantic_changes)
                .expect("Block-STM benchmark final semantic commit failed");
        },
    );

    ParallelBenchmarkRun {
        digest: include_digest.then(|| {
            digest(
                &mut executor,
                txs,
                participants,
                tx_count,
                gas_used,
                validator_fees,
            )
        }),
        stats,
        gas_used,
        speculative_wall,
        commit_wall,
        phase_times,
    }
}

#[allow(dead_code)]
fn execute_parallel_blockstm_semantic_only(
    config: &TempoEvmConfig,
    fixture: &BenchFixture,
    txs: &[Recovered<TempoTxEnvelope>],
    pooled: &[TempoPooledTransaction],
    participants: &[Address],
    workers: usize,
    include_digest: bool,
) -> ParallelBenchmarkRun {
    let evm = TempoEvm::new(fixture.state_db(), bench_env(BLOCK_TIMESTAMP));
    let mut executor = BlockExecutorFactory::create_executor(config, evm, bench_ctx(pooled.len()));
    executor
        .apply_pre_execution_changes()
        .expect("failed to apply Block-STM pre-execution changes");

    let beneficiary = executor.evm().block().beneficiary;
    let mut participant_index = AddressMap::default();
    for (idx, participant) in participants.iter().copied().enumerate() {
        participant_index.insert(participant, idx);
    }

    let prefix_cache = executor.evm_mut().db_mut().cache.clone();
    let evm_env = executor.evm().evm_env();
    let ctx = bench_ctx(pooled.len());
    let worker_count = workers.max(1).min(pooled.len().max(1));
    let initial_ring_ptr =
        provider_storage(&fixture.provider, expiring_nonce_ring_ptr_key()).to::<u32>();
    let profile_phases = std::env::var_os("TEMPO_BLOCKSTM_BENCH_PROFILE").is_some();
    let mut phase_times = BenchmarkPhaseTimes::default();

    let speculative_started = Instant::now();
    let worker_outputs = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);
        for worker in 0..worker_count {
            let pooled = &pooled;
            let provider = fixture.provider.clone();
            let evm_env = evm_env.clone();
            let ctx = ctx.clone();
            let prefix_cache = prefix_cache.clone();
            let participant_index = &participant_index;
            handles.push(
                std::thread::Builder::new()
                    .name(format!("blockstm-{}", worker + 1))
                    .spawn_scoped(scope, move || {
                        let mut output = BenchSemanticWorkerOutput {
                            semantic_effects: BenchSemanticChunkEffects::new(
                                participant_index.len(),
                            ),
                            stats: BenchmarkStats::default(),
                            gas_used: 0,
                            validator_fees: U256::ZERO,
                        };
                        for tx_index in (worker..pooled.len()).step_by(worker_count) {
                            let attempt = execute_bench_attempt(
                                provider.clone(),
                                config,
                                evm_env.clone(),
                                ctx.clone(),
                                prefix_cache.clone(),
                                tx_index,
                                &pooled[tx_index],
                                beneficiary,
                            );

                            let BenchAttemptOutput {
                                execution_result,
                                semantic_plan,
                                fast_plan,
                            } = attempt.output;
                            let result = execution_result
                                .expect("Block-STM semantic benchmark execution failed");
                            assert!(
                                result.result().result.is_success(),
                                "Block-STM semantic benchmark transaction reverted: {:?}",
                                result.result().result
                            );
                            let semantic_plan =
                                semantic_plan.expect("Block-STM semantic benchmark plan missing");
                            let fast_plan =
                                fast_plan.expect("Block-STM semantic benchmark fast plan missing");
                            record_bench_semantic_plan(
                                initial_ring_ptr,
                                tx_index,
                                participant_index,
                                &mut output.semantic_effects,
                                fast_plan,
                            );
                            output.gas_used = output
                                .gas_used
                                .saturating_add(result.result().result.tx_gas_used());
                            output.validator_fees += result.validator_fee();
                            output.stats.speculative_executions += 1;
                            output.stats.accepted += 1;
                            output.stats.committed += 1;
                            output.stats.reused_worker_results += 1;
                            output.stats.semantic_actions += semantic_plan.action_count() as u64;
                            output.stats.add_pure_tip20_actions();
                        }
                        if output.stats.speculative_executions > 0 {
                            output.stats.worker_lanes_with_attempts = 1;
                        }
                        output
                    })
                    .expect("spawn Block-STM semantic benchmark worker"),
            );
        }

        handles
            .into_iter()
            .map(|handle| handle.join().expect("semantic worker panicked"))
            .collect::<Vec<_>>()
    });
    let speculative_wall = speculative_started.elapsed();

    let mut stats = BenchmarkStats {
        built_blocks: 1,
        max_in_flight_real_evm_executions: worker_count as u64,
        ..Default::default()
    };
    let mut semantic_effects = BenchSemanticChunkEffects::new(participants.len());
    let mut gas_used = 0u64;
    let mut validator_fees = U256::ZERO;
    for output in worker_outputs {
        merge_benchmark_stats(&mut stats, output.stats);
        merge_bench_semantic_effects(&mut semantic_effects, output.semantic_effects);
        gas_used = gas_used.saturating_add(output.gas_used);
        validator_fees += output.validator_fees;
    }

    let semantic_changes = timed(profile_phases, &mut phase_times.semantic_reduce, || {
        materialize_bench_semantic_changes(
            &fixture.provider,
            participants,
            beneficiary,
            semantic_effects,
        )
    });

    timed(
        profile_phases,
        &mut phase_times.final_semantic_commit,
        || {
            commit_semantic_changes(executor.evm_mut().db_mut(), semantic_changes)
                .expect("Block-STM semantic benchmark final commit failed");
        },
    );

    ParallelBenchmarkRun {
        digest: include_digest.then(|| {
            digest_with_receipts(
                &mut executor,
                txs,
                participants,
                txs.len() as u64,
                gas_used,
                validator_fees,
                txs.len(),
            )
        }),
        stats,
        gas_used,
        speculative_wall,
        commit_wall: Duration::ZERO,
        phase_times,
    }
}

struct BenchAttemptOutput {
    execution_result: Result<tempo_evm::TempoTxResult, reth_evm::block::BlockExecutionError>,
    semantic_plan: Option<BlockStmSemanticPlan>,
    fast_plan: Option<BenchFastSemanticPlan>,
}

fn execute_bench_attempt(
    provider: InMemoryStateProvider,
    config: &TempoEvmConfig,
    evm_env: EvmEnv<TempoHardfork, TempoBlockEnv>,
    ctx: TempoBlockExecutionCtx<'_>,
    prefix_cache: reth_revm::db::CacheState,
    tx_index: usize,
    tx: &TempoPooledTransaction,
    beneficiary: Address,
) -> BlockStmAttempt<BenchAttemptOutput> {
    let db = State::builder()
        .with_database(StateProviderDatabase::new(provider))
        .with_cached_prestate(prefix_cache)
        .with_bundle_update()
        .build();
    let tracking_db = BlockStmTrackingDb::new(db);
    let evm = config.evm_with_env(tracking_db, evm_env);
    let mut executor = BlockExecutorFactory::create_executor(config, evm, ctx);
    let mut execution_result =
        executor.execute_transaction_without_commit(tx.clone_into_with_tx_env());
    let read_set = executor.evm().db().read_set();
    let write_set = execution_result
        .as_ref()
        .map(|result| write_set_from_evm_state(&result.result().state))
        .unwrap_or_default();
    let semantic_plan = execution_result.as_ref().ok().and_then(|result| {
        capture_tip20_semantic_plan(tx_index, &tx, result, &write_set, beneficiary)
    });
    let fast_plan = execution_result.as_ref().ok().and_then(|result| {
        semantic_plan
            .as_ref()
            .and_then(|_| capture_fast_semantic_plan(&tx, result))
    });
    if let (Ok(result), Some(semantic_plan), Some(_)) =
        (&mut execution_result, semantic_plan.as_ref(), fast_plan)
    {
        strip_covered_storage(result, semantic_plan.covered_keys(), true);
    }

    BlockStmAttempt {
        tx_index,
        attempt: 0,
        read_set,
        write_set,
        output: BenchAttemptOutput {
            execution_result,
            semantic_plan,
            fast_plan,
        },
    }
}

fn capture_fast_semantic_plan(
    tx: &TempoPooledTransaction,
    result: &tempo_evm::TempoTxResult,
) -> Option<BenchFastSemanticPlan> {
    let sender = tx.sender();
    let fee_payer = tx.inner().fee_payer(sender).ok()?;
    let mut calls = tx.inner().calls();
    let (kind, input) = calls.next()?;
    if calls.next().is_some() || kind.to().copied() != Some(PATH_USD_ADDRESS) {
        return None;
    }
    let transfer = ITIP20::transferCall::abi_decode(input).ok()?;
    let max_fee_precharge = calc_gas_balance_spending(tx.gas_limit(), tx.max_fee_per_gas());
    let actual_spending = result.validator_fee();
    let refund_amount = max_fee_precharge.checked_sub(actual_spending)?;

    Some(BenchFastSemanticPlan {
        nonce_hash: tx.expiring_nonce_hash()?,
        valid_before: tx.inner().as_aa()?.tx().valid_before?.get(),
        fee_payer,
        sender,
        recipient: transfer.to,
        transfer_amount: transfer.amount,
        max_fee_precharge,
        actual_spending,
        refund_amount,
    })
}

fn strip_covered_storage(
    result: &mut tempo_evm::TempoTxResult,
    covered_keys: &HashSet<BlockStmAccessKey>,
    verify_no_uncovered_writes: bool,
) {
    let state = &mut result.result_mut().state;
    if verify_no_uncovered_writes {
        for key in covered_keys {
            let BlockStmAccessKey::Storage { address, slot } = *key else {
                continue;
            };
            if let Some(account) = state.get_mut(&address) {
                account.storage.remove(&slot);
            }
        }

        for (address, account) in state.iter() {
            assert!(
                !account.storage.values().any(|slot| slot.is_changed()),
                "pure TIP20 benchmark left uncovered storage writes for {address}"
            );
            assert_eq!(
                account.info,
                account.original_info(),
                "pure TIP20 benchmark left uncovered account info change for {address}"
            );
        }
    }

    state.clear();
}

fn digest<DB, I>(
    executor: &mut tempo_evm::TempoBlockExecutor<'_, DB, I>,
    txs: &[Recovered<TempoTxEnvelope>],
    participants: &[Address],
    tx_count: u64,
    gas_used: u64,
    validator_fees: U256,
) -> ExecutionDigest
where
    DB: reth_evm::block::StateDB,
    I: reth_revm::Inspector<tempo_revm::evm::TempoContext<DB>>,
{
    digest_with_receipts(
        executor,
        txs,
        participants,
        tx_count,
        gas_used,
        validator_fees,
        executor.receipts().len(),
    )
}

fn digest_with_receipts<DB, I>(
    executor: &mut tempo_evm::TempoBlockExecutor<'_, DB, I>,
    txs: &[Recovered<TempoTxEnvelope>],
    participants: &[Address],
    tx_count: u64,
    gas_used: u64,
    validator_fees: U256,
    receipts: usize,
) -> ExecutionDigest
where
    DB: reth_evm::block::StateDB,
    I: reth_revm::Inspector<tempo_revm::evm::TempoContext<DB>>,
{
    let beneficiary = executor.evm().block().beneficiary;
    let db = executor.evm_mut().db_mut();

    let participant_balances = participants
        .iter()
        .map(|account| read_storage(db, tip20_balance_key(PATH_USD_ADDRESS, *account)))
        .collect::<Vec<_>>();
    let fee_manager_balance = read_storage(
        db,
        tip20_balance_key(PATH_USD_ADDRESS, tempo_precompiles::TIP_FEE_MANAGER_ADDRESS),
    );
    let collected_fees = read_storage(
        db,
        fee_manager_collected_fees_key(beneficiary, PATH_USD_ADDRESS),
    );
    let nonce_ring_ptr = read_storage(
        db,
        crate::blockstm::action::slots::expiring_nonce_ring_ptr_key(),
    );
    let nonce_ring = (0..txs.len())
        .map(|idx| read_storage(db, expiring_nonce_ring_key(idx as u32)))
        .collect::<Vec<_>>();
    let nonce_seen = txs
        .iter()
        .map(|tx| {
            let hash = tx
                .inner()
                .as_aa()
                .expect("benchmark uses AA txs")
                .expiring_nonce_hash(tx.signer());
            read_storage(
                db,
                crate::blockstm::action::slots::expiring_nonce_seen_key(hash),
            )
        })
        .collect();

    ExecutionDigest {
        txs: tx_count,
        gas_used,
        validator_fees,
        receipts,
        participant_balances,
        fee_manager_balance,
        collected_fees,
        nonce_ring_ptr,
        nonce_ring,
        nonce_seen,
    }
}

fn read_storage<DB: Database>(db: &mut DB, key: crate::blockstm::BlockStmAccessKey) -> U256 {
    let crate::blockstm::BlockStmAccessKey::Storage { address, slot } = key else {
        return U256::ZERO;
    };
    db.storage(address, slot)
        .expect("benchmark state read should succeed")
}

fn median(mut values: Vec<Duration>) -> Duration {
    values.sort_unstable();
    values[values.len() / 2]
}

#[ignore = "25k pure TIP20 serial-vs-Block-STM benchmark; run from scripts/check-blockstm-builder.sh"]
#[test]
fn blockstm_pure_tip20_parallel_builder_benchmark() {
    let (txs, pooled, participants) = workload();
    assert_eq!(txs.len(), BENCH_TX_COUNT);
    assert_eq!(pooled.len(), BENCH_TX_COUNT);
    assert_eq!(participants.len(), ACCOUNT_COUNT);

    let fixture = seed_fixture(&participants);
    let config = TempoEvmConfig::new(Arc::new(TempoChainSpec::moderato()));
    let workers = blockstm_bench_workers();

    let expected = execute_serial(&config, &fixture, &txs, &pooled, &participants);
    let parallel = execute_parallel_blockstm(
        &config,
        &fixture,
        &txs,
        &pooled,
        &participants,
        workers,
        true,
    );
    assert_eq!(
        parallel.digest.as_ref(),
        Some(&expected),
        "Block-STM output must match serial"
    );
    assert_parallel_benchmark_stats(&parallel.stats);

    let mut serial_times = Vec::with_capacity(BENCH_SAMPLES);
    let mut parallel_times = Vec::with_capacity(BENCH_SAMPLES);
    let mut last_parallel_stats = parallel.stats.clone();
    for _ in 0..BENCH_SAMPLES {
        let started = Instant::now();
        let digest = execute_serial(&config, &fixture, &txs, &pooled, &participants);
        assert_eq!(digest, expected);
        serial_times.push(started.elapsed());

        let started = Instant::now();
        let run = execute_parallel_blockstm(
            &config,
            &fixture,
            &txs,
            &pooled,
            &participants,
            workers,
            true,
        );
        assert_eq!(run.digest.as_ref(), Some(&expected));
        assert_parallel_benchmark_stats(&run.stats);
        parallel_times.push(started.elapsed());
        last_parallel_stats = run.stats;
    }

    let serial_median = median(serial_times);
    let parallel_median = median(parallel_times);
    let serial_tps = BENCH_TX_COUNT as f64 / serial_median.as_secs_f64();
    let parallel_tps = BENCH_TX_COUNT as f64 / parallel_median.as_secs_f64();
    let speedup = serial_median.as_secs_f64() / parallel_median.as_secs_f64();
    let phase_times = parallel.phase_times;

    println!(
        "blockstm_pure_tip20_parallel_builder_benchmark txs={} accounts={} workers={} serial_median={:?} parallel_median={:?} serial_tps={:.2} parallel_tps={:.2} speedup={:.2}x accepted={} rejected={} speculative={} committed={} reused_worker_results={} conflicts={} reexecutions={} serial_commit_reexecutions={} fallback={} built_blocks={} max_in_flight={} worker_lanes={} semantic_actions={} speculative_wall={:?} commit_wall={:?} phases={{setup:{:?}, batch_setup:{:?}, worker_merge:{:?}, semantic_reduce:{:?}, strip_state:{:?}, hydrate_cache:{:?}, commit_tx:{:?}, bump_bal_index:{:?}, final_semantic_commit:{:?}}} actions={{ExpiringNonceUse:{}, Tip20FeeEscrowDelta:{}, Tip20TransferDelta:{}, CollectedFeesDelta:{}, SemanticPrefixRead:{}}}",
        BENCH_TX_COUNT,
        ACCOUNT_COUNT,
        workers,
        serial_median,
        parallel_median,
        serial_tps,
        parallel_tps,
        speedup,
        last_parallel_stats.accepted,
        last_parallel_stats.rejected,
        last_parallel_stats.speculative_executions,
        last_parallel_stats.committed,
        last_parallel_stats.reused_worker_results,
        last_parallel_stats.conflicts,
        last_parallel_stats.reexecutions,
        last_parallel_stats.serial_commit_reexecutions,
        last_parallel_stats.fallback,
        last_parallel_stats.built_blocks,
        last_parallel_stats.max_in_flight_real_evm_executions,
        last_parallel_stats.worker_lanes_with_attempts,
        last_parallel_stats.semantic_actions,
        parallel.speculative_wall,
        parallel.commit_wall,
        phase_times.setup,
        phase_times.batch_setup,
        phase_times.worker_merge,
        phase_times.semantic_reduce,
        phase_times.strip_state,
        phase_times.hydrate_cache,
        phase_times.commit_tx,
        phase_times.bump_bal_index,
        phase_times.final_semantic_commit,
        last_parallel_stats.action_counts.expiring_nonce_uses,
        last_parallel_stats.action_counts.tip20_fee_escrows,
        last_parallel_stats.action_counts.tip20_transfers,
        last_parallel_stats.action_counts.collected_fees,
        last_parallel_stats.action_counts.semantic_prefix_reads,
    );
    black_box((serial_tps, parallel_tps));

    assert!(
        speedup >= 1.5,
        "Block-STM median throughput speedup {speedup:.2}x is below required 1.5x"
    );
}

fn assert_parallel_benchmark_stats(stats: &BenchmarkStats) {
    assert_eq!(stats.accepted, BENCH_TX_COUNT as u64);
    assert_eq!(stats.rejected, 0);
    assert!(
        stats.speculative_executions >= stats.accepted,
        "speculative executions must cover all accepted txs"
    );
    assert_eq!(stats.committed, stats.accepted);
    assert_eq!(
        stats.reused_worker_results, stats.accepted,
        "benchmark must commit the worker-produced results without serial re-execution"
    );
    assert_eq!(
        stats.serial_commit_reexecutions, 0,
        "benchmark commit loop must not re-execute transactions serially"
    );
    assert_eq!(stats.built_blocks, 1);
    assert_eq!(stats.fallback, 0);
    assert!(
        stats.max_in_flight_real_evm_executions >= 2,
        "benchmark did not observe concurrent real EVM attempts"
    );
    assert!(
        stats.worker_lanes_with_attempts >= 2,
        "benchmark did not spread attempts across multiple worker lanes"
    );
    assert_eq!(
        stats.semantic_actions,
        stats.accepted * 5,
        "pure TIP20 benchmark should replay five semantic actions per tx"
    );
    assert!(
        stats.reexecutions <= stats.accepted / 20,
        "pure TIP20 re-executions {} exceeded threshold for {} accepted txs",
        stats.reexecutions,
        stats.accepted
    );
    assert!(stats.action_counts.expiring_nonce_uses > 0);
    assert!(stats.action_counts.tip20_fee_escrows > 0);
    assert!(stats.action_counts.tip20_transfers > 0);
    assert!(stats.action_counts.collected_fees > 0);
    assert!(stats.action_counts.semantic_prefix_reads > 0);
}
