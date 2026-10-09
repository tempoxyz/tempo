//! Shared microbenchmark helpers for EVM execution benches.

use alloy_consensus::transaction::{Recovered, SignerRecoverable};
use alloy_primitives::{
    Address, B256, Bytes, TxKind, U256,
    map::{AddressMap, B256Map, HashMap},
};
use alloy_signer::SignerSync;
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner};
use evm2::evm::{AccountInfo, InMemoryDB};
use reth_evm::{BlockExecutor, BlockExecutorFactory, database::StateProviderDatabase};
use reth_evm_ethereum::EthBlockExecutionCtx;
use reth_execution_cache::{
    CachedStateMetrics, CachedStateMetricsSource, CachedStateProvider, ExecutionCache,
};
use reth_primitives_traits::{Account as RethAccount, Bytecode as RethBytecode};
use reth_storage_api::{
    AccountReader, BlockHashReader, BytecodeReader, EvmStateProviderAdapter,
    HashedPostStateProvider, StateProofProvider, StateProvider, StateRootProvider,
    StorageRootProvider,
    errors::{ProviderError, ProviderResult},
};
use reth_trie::{
    AccountProof, DecodedMultiProofV2, HashedPostState, HashedStorage, MultiProof,
    MultiProofTargets, MultiProofTargetsV2, StorageMultiProof, StorageProof, TrieInput,
    updates::TrieUpdates,
};
use std::{
    num::NonZeroU64,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tempo_chainspec::{
    TempoChainSpec,
    hardfork::{TempoHardfork, TempoHardforks},
    spec::TEMPO_T1_BASE_FEE,
};
use tempo_evm::{
    TempoBlockEnv, TempoBlockExecutionCtx, TempoEvm, TempoEvmConfig, TempoEvmEnv, TempoTxEnv,
    tempo_execution_config,
};
use tempo_precompiles::{
    ADDRESS_REGISTRY_ADDRESS, NONCE_PRECOMPILE_ADDRESS, PATH_USD_ADDRESS,
    SIGNATURE_VERIFIER_ADDRESS, STABLECOIN_DEX_ADDRESS, TIP20_CHANNEL_RESERVE_ADDRESS,
    VALIDATOR_CONFIG_V2_ADDRESS,
};
use tempo_primitives::{
    TempoBlockExt, TempoTransaction, TempoTxEnvelope,
    transaction::{Call, TEMPO_EXPIRING_NONCE_KEY},
};

pub(crate) const CHAIN_ID: u64 = 1337;
pub(crate) const TXGEN_MNEMONIC: &str =
    "test test test test test test test test test test test junk";
pub(crate) const DEFAULT_ACCOUNT_COUNT: usize = 1_024;
pub(crate) const DEFAULT_BLOCK_TIMESTAMP: u64 = 1_700_000_000;
pub(crate) const TXGEN_GAS_LIMIT: u64 = 2_000_000;
pub(crate) const TXGEN_FEE_PER_GAS: u128 = 100_000_000_000;
pub(crate) const EXECUTION_CACHE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Default)]
pub(crate) struct ExecutionStats {
    pub(crate) txs: u64,
    pub(crate) gas_used: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct InMemoryStateProvider {
    accounts: Arc<AddressMap<RethAccount>>,
    storage: Arc<HashMap<(Address, B256), U256>>,
    contracts: Arc<B256Map<RethBytecode>>,
    block_hashes: Arc<HashMap<u64, B256>>,
}

#[derive(Clone)]
pub(crate) struct ExecutionFixture {
    provider: InMemoryStateProvider,
    cache: ExecutionCache,
    metrics: CachedStateMetrics,
    tx_envs: Vec<Recovered<TempoTxEnv>>,
}

/// Fresh execution state and prepared transactions, constructed outside benchmark timing.
pub(crate) struct FixedCacheDb {
    db: StateProviderDatabase<CachedStateProvider<EvmStateProviderAdapter<InMemoryStateProvider>>>,
    tx_envs: Vec<Recovered<TempoTxEnv>>,
}

impl ExecutionFixture {
    pub(crate) fn with_transactions(mut self, txs: &[Recovered<TempoTxEnvelope>]) -> Self {
        self.tx_envs = txs
            .iter()
            .map(|tx| Recovered::new_unchecked(TempoTxEnv::from(tx.clone()), tx.signer()))
            .collect();
        self
    }

    pub(crate) fn state_db(&self) -> FixedCacheDb {
        let provider = CachedStateProvider::new(
            self.provider.clone().into_evm_state_provider(),
            self.cache.clone(),
            Some(self.metrics.clone()),
        );
        FixedCacheDb {
            db: StateProviderDatabase::new(provider),
            tx_envs: self.tx_envs.clone(),
        }
    }

    pub(crate) fn prewarm_state_db(&self) -> FixedCacheDb {
        let provider = CachedStateProvider::new_prewarm(
            self.provider.clone().into_evm_state_provider(),
            self.cache.clone(),
        );
        FixedCacheDb {
            db: StateProviderDatabase::new(provider),
            tx_envs: self.tx_envs.clone(),
        }
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
    fn multiproof_v2(
        &self,
        _input: TrieInput,
        _targets: MultiProofTargetsV2,
    ) -> ProviderResult<DecodedMultiProofV2> {
        Err(ProviderError::UnsupportedProvider)
    }
    fn witness(
        &self,
        _input: TrieInput,
        _target: HashedPostState,
        _mode: reth_trie::ExecutionWitnessMode,
    ) -> ProviderResult<Vec<Bytes>> {
        Err(ProviderError::UnsupportedProvider)
    }
}
impl HashedPostStateProvider for InMemoryStateProvider {
    fn hashed_post_state(
        &self,
        _bundle_state: &reth_evm::BundleState,
    ) -> ProviderResult<HashedPostState> {
        Ok(HashedPostState::default())
    }
}

pub(crate) fn current_active_hardfork() -> TempoHardfork {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs();
    TempoChainSpec::mainnet().tempo_hardfork_at(now)
}
pub(crate) fn latest_known_hardfork() -> TempoHardfork {
    *TempoHardfork::VARIANTS
        .last()
        .expect("TempoHardfork has at least one variant")
}
pub(crate) fn hardfork_bench_cases() -> Vec<(&'static str, TempoHardfork)> {
    let current = current_active_hardfork();
    let latest = latest_known_hardfork();
    let mut cases = vec![("current", current)];
    if latest != current {
        cases.push(("latest", latest));
    }
    cases
}

pub(crate) fn bench_env(hardfork: TempoHardfork, block_timestamp: u64) -> TempoEvmEnv {
    let mut version = *tempo_execution_config(hardfork, CHAIN_ID).version();
    version.tx_gas_limit_cap = hardfork.tx_gas_limit_cap().unwrap_or(u64::MAX);
    TempoEvmEnv {
        spec: hardfork,
        version,
        block: TempoBlockEnv {
            number: U256::ONE,
            beneficiary: Address::repeat_byte(0x42),
            timestamp: U256::from(block_timestamp),
            basefee: U256::from(TEMPO_T1_BASE_FEE),
            gas_limit: U256::from(10_000_000_000u64),
            ext: TempoBlockExt::default(),
            ..Default::default()
        },
    }
}

pub(crate) fn bench_evm(
    db: InMemoryDB,
    hardfork: TempoHardfork,
    timestamp: u64,
) -> TempoEvm<'static> {
    BlockExecutorFactory::evm_with_env(
        &TempoEvmConfig::moderato(),
        db,
        bench_env(hardfork, timestamp),
    )
}

pub(crate) fn seeded_db(evm: &TempoEvm<'_>) -> InMemoryDB {
    InMemoryDB {
        cache: evm.overlay_db().cache.clone(),
        ..Default::default()
    }
}

pub(crate) fn txgen_signers(account_count: usize) -> Vec<PrivateKeySigner> {
    (0..account_count)
        .map(|idx| {
            MnemonicBuilder::from_phrase(TXGEN_MNEMONIC)
                .index(idx as u32)
                .expect("valid txgen account index")
                .build()
                .expect("valid txgen mnemonic")
        })
        .collect()
}

pub(crate) fn sign_precompile_call(
    signer: &PrivateKeySigner,
    to: Address,
    input: Bytes,
) -> Recovered<TempoTxEnvelope> {
    let tx = TempoTransaction {
        chain_id: CHAIN_ID,
        fee_token: Some(PATH_USD_ADDRESS),
        max_priority_fee_per_gas: TXGEN_FEE_PER_GAS,
        max_fee_per_gas: TXGEN_FEE_PER_GAS,
        gas_limit: TXGEN_GAS_LIMIT,
        calls: vec![Call {
            to: TxKind::Call(to),
            value: U256::ZERO,
            input,
        }],
        access_list: Default::default(),
        nonce_key: TEMPO_EXPIRING_NONCE_KEY,
        nonce: 0,
        fee_payer_signature: None,
        valid_before: Some(NonZeroU64::new(DEFAULT_BLOCK_TIMESTAMP + 10).unwrap()),
        valid_after: None,
        key_authorization: None,
        tempo_authorization_list: Vec::new(),
    };
    let signature = signer
        .sign_hash_sync(&tx.signature_hash())
        .expect("failed to sign generated benchmark transaction");
    let signed = tx.into_signed(signature.into());
    TempoTxEnvelope::from(signed)
        .try_into_recovered()
        .expect("generated benchmark transaction should recover")
}

pub(crate) fn fixture_from_seeded_db(seeded: InMemoryDB) -> ExecutionFixture {
    let state_cache = seeded.cache;
    let execution_cache = ExecutionCache::new(EXECUTION_CACHE_BYTES);
    let mut accounts = AddressMap::default();
    let mut storage = HashMap::default();
    let mut contracts = B256Map::default();
    let mut block_hashes = HashMap::default();
    for (hash, bytecode) in state_cache.contracts {
        let bytecode = RethBytecode(reth_execution_types::revm_bytecode(&bytecode));
        execution_cache.insert_code(hash, Some(bytecode.clone()));
        contracts.insert(hash, bytecode);
    }
    for (address, account) in state_cache.accounts {
        if let Some(account) = account {
            insert_account(&execution_cache, &mut accounts, address, &account);
        } else {
            execution_cache.insert_account(address, None);
        }
    }
    for (address, account_storage) in state_cache.storage {
        for (slot, value) in account_storage.slots {
            let storage_key = B256::from(slot);
            execution_cache.insert_storage(address, storage_key, Some(value));
            storage.insert((address, storage_key), value);
        }
    }
    for (number, hash) in state_cache.block_hashes {
        block_hashes.insert(number.to::<u64>(), hash);
    }
    for address in [
        ADDRESS_REGISTRY_ADDRESS,
        NONCE_PRECOMPILE_ADDRESS,
        SIGNATURE_VERIFIER_ADDRESS,
        STABLECOIN_DEX_ADDRESS,
        TIP20_CHANNEL_RESERVE_ADDRESS,
        VALIDATOR_CONFIG_V2_ADDRESS,
    ] {
        if !accounts.contains_key(&address) {
            execution_cache.insert_account(address, None);
        }
    }
    ExecutionFixture {
        provider: InMemoryStateProvider {
            accounts: Arc::new(accounts),
            storage: Arc::new(storage),
            contracts: Arc::new(contracts),
            block_hashes: Arc::new(block_hashes),
        },
        cache: execution_cache,
        metrics: CachedStateMetrics::zeroed(CachedStateMetricsSource::Builder),
        tx_envs: Vec::new(),
    }
}

fn insert_account(
    cache: &ExecutionCache,
    accounts: &mut AddressMap<RethAccount>,
    address: Address,
    account: &AccountInfo,
) {
    let info = account;
    let bytecode_hash = info.code_hash;
    let account = RethAccount {
        nonce: info.nonce,
        balance: info.balance,
        bytecode_hash: Some(bytecode_hash),
    };
    cache.insert_account(address, Some(account));
    accounts.insert(address, account);
}

pub(crate) fn execute_txs(
    config: &TempoEvmConfig,
    db: FixedCacheDb,
    txs: &[Recovered<TempoTxEnvelope>],
    block_timestamp: u64,
    hardfork: TempoHardfork,
) -> ExecutionStats {
    let FixedCacheDb { db, tx_envs } = db;
    let evm = config.evm_with_database(db, bench_env(hardfork, block_timestamp));
    let ctx = TempoBlockExecutionCtx {
        inner: EthBlockExecutionCtx {
            parent_hash: B256::ZERO,
            parent_beacon_block_root: Some(B256::ZERO),
            ommers: &[],
            withdrawals: None,
            extra_data: Bytes::new(),
            tx_count_hint: Some(txs.len()),
            slot_number: None,
        },
        general_gas_limit: 10_000_000_000,
        shared_gas_limit: 0,
        consensus_context: None,
    };
    let mut executor = config.create_executor(evm, ctx);
    executor
        .apply_pre_execution_changes()
        .expect("failed to apply pre-execution changes");
    let mut stats = ExecutionStats::default();
    assert_eq!(txs.len(), tx_envs.len());
    for (tx, tx_env) in txs.iter().zip(tx_envs) {
        assert!(
            tx.inner().is_aa(),
            "execution bench expects Tempo AA transactions"
        );
        let output = executor
            .execute_transaction_without_commit((tx_env, tx))
            .expect("transaction execution failed");
        assert!(
            output.result().status,
            "transaction reverted: {:?}",
            output.result()
        );
        stats.gas_used = stats.gas_used.saturating_add(
            executor
                .commit_transaction(output)
                .expect("commit failed")
                .tx_gas_used(),
        );
        stats.txs += 1;
    }
    stats
}
