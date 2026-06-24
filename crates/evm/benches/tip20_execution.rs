//! Pure TIP20 execution benchmark.
//!
//! By default this generates txgen-style AA TIP20 transfers from the benchmark mnemonic. Set
//! `TEMPO_TIP20_EXEC_TXS` to a newline-delimited raw 2718 txgen output file to replay exact
//! txgen transactions against the in-memory fixed-cache execution path.

use alloy_consensus::transaction::{Recovered, SignerRecoverable};
use alloy_eips::Decodable2718;
use alloy_evm::{
    Evm, EvmEnv, EvmFactory,
    block::{BlockExecutor, BlockExecutorFactory, StateDB, TxResult},
    eth::EthBlockExecutionCtx,
};
use alloy_primitives::{
    Address, B256, Bytes, TxKind, U256,
    map::{AddressMap, B256Map, HashMap},
};
use alloy_signer::SignerSync;
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner};
use alloy_sol_types::SolCall;
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use reth_execution_cache::{
    CachedStateMetrics, CachedStateMetricsSource, CachedStateProvider, ExecutionCache,
};
use reth_primitives_traits::{Account as RethAccount, Bytecode as RethBytecode};
use reth_revm::{State, database::StateProviderDatabase};
use reth_storage_api::{
    AccountReader, BlockHashReader, BytecodeReader, HashedPostStateProvider, StateProofProvider,
    StateProvider, StateRootProvider, StorageRootProvider,
    errors::{ProviderError, ProviderResult},
};
use reth_trie::{
    AccountProof, HashedPostState, HashedStorage, MultiProof, MultiProofTargets, StorageMultiProof,
    StorageProof, TrieInput, updates::TrieUpdates,
};
use revm::{
    DatabaseCommit,
    context::{BlockEnv, CfgEnv, JournalTr},
    database::{CacheDB, DbAccount, EmptyDB},
};
use std::{
    collections::BTreeSet,
    fs,
    hint::black_box,
    num::NonZeroU64,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tempo_chainspec::{
    TempoChainSpec,
    hardfork::{TempoHardfork, TempoHardforks},
    spec::TEMPO_T1_BASE_FEE,
};
use tempo_contracts::precompiles::ITIP20;
use tempo_evm::{
    TempoBlockEnv, TempoBlockExecutionCtx, TempoEvmConfig, TempoEvmFactory, evm::TempoEvm,
};
use tempo_precompiles::{
    ADDRESS_REGISTRY_ADDRESS, NONCE_PRECOMPILE_ADDRESS, PATH_USD_ADDRESS,
    SIGNATURE_VERIFIER_ADDRESS, TIP20_CHANNEL_RESERVE_ADDRESS, VALIDATOR_CONFIG_V2_ADDRESS,
    error::TempoPrecompileError,
    nonce::NonceManager,
    storage::{StorageActions, StorageCtx},
    tip_fee_manager::TipFeeManager,
    tip20::{ISSUER_ROLE, TIP20Token},
    tip20_factory::TIP20Factory,
    tip403_registry::TIP403Registry,
};
use tempo_primitives::{
    AASigned, TempoSignature, TempoTransaction, TempoTxEnvelope,
    transaction::{Call, PrimitiveSignature, TEMPO_EXPIRING_NONCE_KEY},
};
use tempo_revm::gas_params::tempo_gas_params_with_amsterdam;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const CHAIN_ID: u64 = 1337;
const TXGEN_MNEMONIC: &str = "test test test test test test test test test test test junk";
const DEFAULT_ACCOUNT_COUNT: usize = 1_024;
const DEFAULT_TX_COUNT: usize = 4_096;
const DEFAULT_BLOCK_TIMESTAMP: u64 = 1_700_000_000;
const TXGEN_GAS_LIMIT: u64 = 2_000_000;
const TXGEN_FEE_PER_GAS: u128 = 100_000_000_000;
const PARTICIPANT_MINT_AMOUNT: u128 = 1_000_000_000_000_000_000;
const REWARD_BENCH_TX_COUNT: usize = 1_024;
const REWARD_DISTRIBUTION_AMOUNT: u128 = 1_000_000_000_000;
const REWARD_TRANSFER_AMOUNT: u128 = 1_000_000;
const EXECUTION_CACHE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone)]
struct Workload {
    transactions: Vec<Recovered<TempoTxEnvelope>>,
    participants: Vec<Address>,
    block_timestamp: u64,
}

#[derive(Clone, Copy)]
enum RewardSeedMode {
    None,
    SelfRecipient,
    SharedDelegate,
    DistinctDelegate,
}

#[derive(Clone, Copy)]
enum RewardBenchKind {
    Transfer {
        sender: RewardSeedMode,
        recipient: RewardSeedMode,
        reward_delta: bool,
    },
    ClaimRewards,
    DistributeReward {
        opted_in_accounts: usize,
    },
}

struct RewardBenchWorkload {
    name: &'static str,
    transactions: Vec<Recovered<TempoTxEnvelope>>,
    participants: Vec<Address>,
    delegates: Vec<Address>,
    kind: RewardBenchKind,
}

#[derive(Default)]
struct ExecutionStats {
    txs: u64,
    gas_used: u64,
}

#[derive(Clone, Debug)]
struct InMemoryStateProvider {
    accounts: Arc<AddressMap<RethAccount>>,
    storage: Arc<HashMap<(Address, B256), U256>>,
    contracts: Arc<B256Map<RethBytecode>>,
    block_hashes: Arc<HashMap<u64, B256>>,
}

#[derive(Clone)]
struct ExecutionFixture {
    provider: InMemoryStateProvider,
    cache: ExecutionCache,
    metrics: CachedStateMetrics,
}

type FixedCacheDb = State<StateProviderDatabase<CachedStateProvider<InMemoryStateProvider>>>;

impl ExecutionFixture {
    fn state_db(&self) -> FixedCacheDb {
        let provider = CachedStateProvider::new(
            self.provider.clone(),
            self.cache.clone(),
            Some(self.metrics.clone()),
        );
        State::builder()
            .with_database(StateProviderDatabase::new(provider))
            .with_bundle_update()
            .build()
    }

    fn prewarm_state_db(&self) -> FixedCacheDb {
        let provider = CachedStateProvider::new_prewarm(self.provider.clone(), self.cache.clone());
        State::builder()
            .with_database(StateProviderDatabase::new(provider))
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
        _mode: reth_trie::ExecutionWitnessMode,
    ) -> ProviderResult<Vec<Bytes>> {
        Err(ProviderError::UnsupportedProvider)
    }
}

impl HashedPostStateProvider for InMemoryStateProvider {
    fn hashed_post_state(&self, _bundle_state: &reth_revm::db::BundleState) -> HashedPostState {
        unreachable!("TIP20 execution benchmark does not compute hashed post-state")
    }
}

fn current_active_hardfork() -> TempoHardfork {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before UNIX_EPOCH")
        .as_secs();
    TempoChainSpec::mainnet().tempo_hardfork_at(now)
}

fn latest_known_hardfork() -> TempoHardfork {
    *TempoHardfork::VARIANTS
        .last()
        .expect("TempoHardfork must define at least one variant")
}

fn hardfork_bench_cases() -> Vec<(&'static str, TempoHardfork)> {
    let current = current_active_hardfork();
    let latest = latest_known_hardfork();
    let mut cases = vec![("current", current)];

    if latest != current {
        cases.push(("latest", latest));
    }

    cases
}

fn bench_env(
    hardfork: TempoHardfork,
    block_timestamp: u64,
) -> EvmEnv<TempoHardfork, TempoBlockEnv> {
    let spec = hardfork;
    let amsterdam_eip8037_enabled = false;
    let mut cfg_env = CfgEnv::default();
    cfg_env.chain_id = CHAIN_ID;
    cfg_env.spec = spec;
    cfg_env.gas_params = tempo_gas_params_with_amsterdam(spec, amsterdam_eip8037_enabled);
    cfg_env.tx_gas_limit_cap = spec.tx_gas_limit_cap();

    EvmEnv {
        cfg_env,
        block_env: TempoBlockEnv {
            inner: BlockEnv {
                number: U256::from(1),
                beneficiary: Address::repeat_byte(0x42),
                timestamp: U256::from(block_timestamp),
                basefee: TEMPO_T1_BASE_FEE,
                gas_limit: 10_000_000_000,
                ..Default::default()
            },
            timestamp_millis_part: 0,
            ..Default::default()
        },
    }
}

fn seed_in_memory_cache_db(
    participants: &[Address],
    block_timestamp: u64,
    reward_seed: Option<(&[Address], RewardBenchKind)>,
    hardfork: TempoHardfork,
) -> CacheDB<EmptyDB> {
    // This setup database only materializes the benchmark fixture in memory. The measured
    // execution path below uses Reth's fixed-cache execution provider, not CacheDB.
    let mut evm = TempoEvmFactory::default().create_evm(
        CacheDB::new(EmptyDB::default()),
        bench_env(hardfork, block_timestamp),
    );
    let admin = participants
        .first()
        .copied()
        .unwrap_or_else(|| Address::repeat_byte(0x01));

    let ctx = evm.ctx_mut();
    StorageCtx::enter_evm(
        &mut ctx.journaled_state,
        &ctx.block,
        &ctx.cfg,
        &ctx.tx,
        StorageActions::disabled(),
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

            if let Some((delegates, kind)) = reward_seed {
                seed_reward_bench_state(&mut token, admin, participants, delegates, kind)?;
            }

            TipFeeManager::new().initialize()?;
            NonceManager::new().initialize()?;
            Ok::<(), TempoPrecompileError>(())
        },
    )
    .expect("failed to seed TIP20 benchmark state");

    let evm_state = evm.ctx_mut().journaled_state.evm_state().clone();
    evm.db_mut().commit(evm_state);
    evm.finish().0
}

fn setup_fixed_cache_state(
    participants: &[Address],
    block_timestamp: u64,
    reward_seed: Option<(&[Address], RewardBenchKind)>,
    hardfork: TempoHardfork,
) -> ExecutionFixture {
    let seeded = seed_in_memory_cache_db(participants, block_timestamp, reward_seed, hardfork);
    let state_cache = seeded.cache;
    let execution_cache = ExecutionCache::new(EXECUTION_CACHE_BYTES);

    let mut accounts = AddressMap::default();
    let mut storage = HashMap::default();
    let mut contracts = B256Map::default();
    let mut block_hashes = HashMap::default();

    for (hash, bytecode) in state_cache.contracts {
        let bytecode = RethBytecode(bytecode);
        execution_cache.insert_code(hash, Some(bytecode.clone()));
        contracts.insert(hash, bytecode);
    }

    for (address, account) in state_cache.accounts {
        insert_account(&execution_cache, &mut accounts, address, &account);
        for (slot, value) in account.storage {
            let storage_key = B256::new(slot.to_be_bytes());
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
    }
}

fn insert_account(
    cache: &ExecutionCache,
    accounts: &mut AddressMap<RethAccount>,
    address: Address,
    account: &DbAccount,
) {
    let Some(info) = account.info() else {
        cache.insert_account(address, None);
        return;
    };

    let account = RethAccount::from(&info);
    cache.insert_account(address, Some(account));
    accounts.insert(address, account);
}

fn seed_reward_bench_state(
    token: &mut TIP20Token,
    admin: Address,
    participants: &[Address],
    delegates: &[Address],
    kind: RewardBenchKind,
) -> Result<(), TempoPrecompileError> {
    match kind {
        RewardBenchKind::Transfer {
            sender,
            recipient,
            reward_delta,
        } => {
            for chunk in participants.chunks(2) {
                if let Some(sender_addr) = chunk.first().copied() {
                    apply_seed_reward_mode(token, sender_addr, sender, delegates)?;
                }
                if let Some(recipient_addr) = chunk.get(1).copied() {
                    apply_seed_reward_mode(token, recipient_addr, recipient, delegates)?;
                }
            }
            if reward_delta {
                token.distribute_reward(
                    admin,
                    ITIP20::distributeRewardCall {
                        amount: U256::from(REWARD_DISTRIBUTION_AMOUNT),
                    },
                )?;
            }
        }
        RewardBenchKind::ClaimRewards => {
            for participant in participants {
                token.set_reward_recipient(
                    *participant,
                    ITIP20::setRewardRecipientCall {
                        recipient: *participant,
                    },
                )?;
            }
            token.distribute_reward(
                admin,
                ITIP20::distributeRewardCall {
                    amount: U256::from(REWARD_DISTRIBUTION_AMOUNT),
                },
            )?;
            for participant in participants {
                token.update_rewards(*participant)?;
            }
        }
        RewardBenchKind::DistributeReward { opted_in_accounts } => {
            for participant in participants.iter().take(opted_in_accounts) {
                token.set_reward_recipient(
                    *participant,
                    ITIP20::setRewardRecipientCall {
                        recipient: *participant,
                    },
                )?;
            }
        }
    }
    Ok(())
}

fn apply_seed_reward_mode(
    token: &mut TIP20Token,
    account: Address,
    mode: RewardSeedMode,
    delegates: &[Address],
) -> Result<(), TempoPrecompileError> {
    let recipient = match mode {
        RewardSeedMode::None => return Ok(()),
        RewardSeedMode::SelfRecipient => account,
        RewardSeedMode::SharedDelegate => delegates[0],
        RewardSeedMode::DistinctDelegate => {
            delegates[account.as_slice()[19] as usize % delegates.len()]
        }
    };
    token.set_reward_recipient(account, ITIP20::setRewardRecipientCall { recipient })?;
    Ok(())
}

fn txgen_signers(account_count: usize) -> Vec<PrivateKeySigner> {
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

fn sign_tip20_transfer(
    signer: &PrivateKeySigner,
    recipient: Address,
    amount: U256,
) -> Recovered<TempoTxEnvelope> {
    sign_tip20_call(
        signer,
        Bytes::from(
            ITIP20::transferCall {
                to: recipient,
                amount,
            }
            .abi_encode(),
        ),
    )
}

fn sign_tip20_call(signer: &PrivateKeySigner, input: Bytes) -> Recovered<TempoTxEnvelope> {
    let tx = TempoTransaction {
        chain_id: CHAIN_ID,
        fee_token: Some(PATH_USD_ADDRESS),
        max_priority_fee_per_gas: TXGEN_FEE_PER_GAS,
        max_fee_per_gas: TXGEN_FEE_PER_GAS,
        gas_limit: TXGEN_GAS_LIMIT,
        calls: vec![Call {
            to: TxKind::Call(PATH_USD_ADDRESS),
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
        .expect("failed to sign generated TIP20 transaction");
    let signed = AASigned::new_unhashed(
        tx,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
    );

    TempoTxEnvelope::from(signed)
        .try_into_recovered()
        .expect("generated TIP20 benchmark transaction should recover")
}

fn generated_workload() -> Workload {
    let signers = txgen_signers(DEFAULT_ACCOUNT_COUNT);
    let mut participants = Vec::with_capacity(signers.len());
    participants.extend(signers.iter().map(|signer| signer.address()));

    let transactions = (0..DEFAULT_TX_COUNT)
        .map(|idx| {
            let signer = &signers[idx % signers.len()];
            let recipient = participants[(idx.wrapping_mul(17) + 1) % participants.len()];
            sign_tip20_transfer(signer, recipient, U256::from(idx as u64 + 1))
        })
        .collect();

    Workload {
        transactions,
        participants,
        block_timestamp: DEFAULT_BLOCK_TIMESTAMP,
    }
}

fn reward_bench_workloads() -> Vec<RewardBenchWorkload> {
    let signers = txgen_signers(DEFAULT_ACCOUNT_COUNT);
    let participants: Vec<_> = signers.iter().map(|signer| signer.address()).collect();
    let delegates = vec![Address::repeat_byte(0xa1), Address::repeat_byte(0xa2)];

    vec![
        transfer_reward_workload(
            "tip20_transfer_rewards_opted_out",
            &signers,
            RewardSeedMode::None,
            RewardSeedMode::None,
            false,
            &delegates,
        ),
        transfer_reward_workload(
            "tip20_transfer_rewards_self_no_delta",
            &signers,
            RewardSeedMode::SelfRecipient,
            RewardSeedMode::SelfRecipient,
            false,
            &delegates,
        ),
        transfer_reward_workload(
            "tip20_transfer_rewards_self_with_delta",
            &signers,
            RewardSeedMode::SelfRecipient,
            RewardSeedMode::SelfRecipient,
            true,
            &delegates,
        ),
        transfer_reward_workload(
            "tip20_transfer_rewards_delegate_no_delta",
            &signers,
            RewardSeedMode::SharedDelegate,
            RewardSeedMode::SharedDelegate,
            false,
            &delegates,
        ),
        transfer_reward_workload(
            "tip20_transfer_rewards_delegate_with_delta",
            &signers,
            RewardSeedMode::SharedDelegate,
            RewardSeedMode::SharedDelegate,
            true,
            &delegates,
        ),
        transfer_reward_workload(
            "tip20_transfer_mixed_sender_recipient",
            &signers,
            RewardSeedMode::DistinctDelegate,
            RewardSeedMode::SelfRecipient,
            true,
            &delegates,
        ),
        RewardBenchWorkload {
            name: "tip20_claim_rewards",
            transactions: signers
                .iter()
                .take(REWARD_BENCH_TX_COUNT)
                .map(|signer| {
                    sign_tip20_call(
                        signer,
                        Bytes::from(ITIP20::claimRewardsCall {}.abi_encode()),
                    )
                })
                .collect(),
            participants: participants.clone(),
            delegates: delegates.clone(),
            kind: RewardBenchKind::ClaimRewards,
        },
        RewardBenchWorkload {
            name: "tip20_distribute_reward",
            transactions: signers
                .iter()
                .take(REWARD_BENCH_TX_COUNT)
                .map(|signer| {
                    sign_tip20_call(
                        signer,
                        Bytes::from(
                            ITIP20::distributeRewardCall {
                                amount: U256::from(REWARD_DISTRIBUTION_AMOUNT / 1_000),
                            }
                            .abi_encode(),
                        ),
                    )
                })
                .collect(),
            participants,
            delegates,
            kind: RewardBenchKind::DistributeReward {
                opted_in_accounts: DEFAULT_ACCOUNT_COUNT,
            },
        },
    ]
}

fn transfer_reward_workload(
    name: &'static str,
    signers: &[PrivateKeySigner],
    sender: RewardSeedMode,
    recipient: RewardSeedMode,
    reward_delta: bool,
    delegates: &[Address],
) -> RewardBenchWorkload {
    let participants: Vec<_> = signers.iter().map(|signer| signer.address()).collect();
    let transactions = (0..REWARD_BENCH_TX_COUNT)
        .map(|idx| {
            let signer = &signers[idx % signers.len()];
            let recipient = participants[(idx.wrapping_mul(17) + 1) % participants.len()];
            sign_tip20_transfer(signer, recipient, U256::from(REWARD_TRANSFER_AMOUNT))
        })
        .collect();

    RewardBenchWorkload {
        name,
        transactions,
        participants,
        delegates: delegates.to_vec(),
        kind: RewardBenchKind::Transfer {
            sender,
            recipient,
            reward_delta,
        },
    }
}

fn decode_raw_tx_line(line: &str) -> Recovered<TempoTxEnvelope> {
    let raw = line
        .trim()
        .trim_matches('"')
        .strip_prefix("0x")
        .unwrap_or(line.trim());
    let bytes = alloy_primitives::hex::decode(raw).expect("invalid raw transaction hex");
    TempoTxEnvelope::decode_2718_exact(bytes.as_slice())
        .expect("invalid 2718 transaction")
        .try_into_recovered()
        .expect("raw transaction should recover signer")
}

fn load_txgen_workload(path: &Path) -> Workload {
    let raw = fs::read_to_string(path).expect("failed to read txgen transaction stream");
    let transactions: Vec<_> = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(decode_raw_tx_line)
        .collect();
    assert!(
        !transactions.is_empty(),
        "txgen transaction stream was empty"
    );

    let mut participants = BTreeSet::new();
    let mut min_valid_before = None;
    let mut max_valid_after = None;
    for tx in &transactions {
        participants.insert(tx.signer());
        if let Some(aa) = tx.inner().as_aa() {
            let aa_tx = aa.tx();
            min_valid_before = aa_tx
                .valid_before
                .map(NonZeroU64::get)
                .into_iter()
                .chain(min_valid_before)
                .min();
            max_valid_after = aa_tx
                .valid_after
                .map(NonZeroU64::get)
                .into_iter()
                .chain(max_valid_after)
                .max();

            for call in &aa_tx.calls {
                if call.to.to() == Some(&PATH_USD_ADDRESS)
                    && let Ok(transfer) = ITIP20::transferCall::abi_decode(&call.input)
                {
                    participants.insert(transfer.to);
                }
            }
        }
    }

    let block_timestamp = min_valid_before
        .map(|ts| ts.saturating_sub(1))
        .unwrap_or(DEFAULT_BLOCK_TIMESTAMP)
        .max(max_valid_after.unwrap_or(0));

    Workload {
        transactions,
        participants: participants.into_iter().collect(),
        block_timestamp,
    }
}

fn workload() -> Workload {
    if let Ok(path) = std::env::var("TEMPO_TIP20_EXEC_TXS") {
        load_txgen_workload(Path::new(&path))
    } else {
        generated_workload()
    }
}

fn execute_txs<DB>(
    config: &TempoEvmConfig,
    db: DB,
    txs: &[Recovered<TempoTxEnvelope>],
    block_timestamp: u64,
    hardfork: TempoHardfork,
) -> ExecutionStats
where
    DB: StateDB,
{
    let evm: TempoEvm<_, _> =
        TempoEvmFactory::default().create_evm(db, bench_env(hardfork, block_timestamp));
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
        validator_set: None,
        consensus_context: None,
        subblock_fee_recipients: Default::default(),
    };

    let mut executor = config.create_executor(evm, ctx);
    executor
        .apply_pre_execution_changes()
        .expect("failed to apply pre-execution changes");

    let mut stats = ExecutionStats::default();
    for tx in txs {
        assert!(
            tx.inner().is_aa(),
            "tip20 execution bench expects Tempo AA transactions"
        );
        let output = executor
            .execute_transaction_without_commit(tx)
            .expect("TIP20 transaction execution failed");
        assert!(
            output.result().result.is_success(),
            "TIP20 transaction reverted: {:?}",
            output.result().result
        );
        stats.gas_used = stats
            .gas_used
            .saturating_add(executor.commit_transaction(output).tx_gas_used());
        stats.txs += 1;
    }
    stats
}

fn tip20_execution(c: &mut Criterion) {
    let workload = workload();
    let hardfork_cases = hardfork_bench_cases();
    let config = TempoEvmConfig::new(Arc::new(TempoChainSpec::moderato()));

    for &(label, hardfork) in &hardfork_cases {
        let fixture = setup_fixed_cache_state(
            &workload.participants,
            workload.block_timestamp,
            None,
            hardfork,
        );
        execute_txs(
            &config,
            fixture.prewarm_state_db(),
            &workload.transactions,
            workload.block_timestamp,
            hardfork,
        );

        let mut group = c.benchmark_group(format!("{label}/tip20_execution"));
        group.throughput(Throughput::Elements(workload.transactions.len() as u64));
        group.bench_function("txgen_tip20_pure_execution", |b| {
            b.iter_batched(
                || fixture.state_db(),
                |db| {
                    let stats = execute_txs(
                        &config,
                        db,
                        &workload.transactions,
                        workload.block_timestamp,
                        hardfork,
                    );
                    black_box(stats.gas_used);
                },
                BatchSize::SmallInput,
            )
        });
        group.finish();
    }

    let reward_workloads = reward_bench_workloads();
    for &(label, hardfork) in &hardfork_cases {
        for reward_workload in &reward_workloads {
            let fixture = setup_fixed_cache_state(
                &reward_workload.participants,
                DEFAULT_BLOCK_TIMESTAMP,
                Some((&reward_workload.delegates, reward_workload.kind)),
                hardfork,
            );
            execute_txs(
                &config,
                fixture.prewarm_state_db(),
                &reward_workload.transactions,
                DEFAULT_BLOCK_TIMESTAMP,
                hardfork,
            );

            let mut group = c.benchmark_group(format!("{label}/tip20_rewards"));
            group.throughput(Throughput::Elements(
                reward_workload.transactions.len() as u64
            ));
            group.bench_function(reward_workload.name, |b| {
                b.iter_batched(
                    || fixture.state_db(),
                    |db| {
                        let stats = execute_txs(
                            &config,
                            db,
                            &reward_workload.transactions,
                            DEFAULT_BLOCK_TIMESTAMP,
                            hardfork,
                        );
                        black_box(stats.gas_used);
                    },
                    BatchSize::SmallInput,
                )
            });
            group.finish();
        }
    }
}

criterion_group!(benches, tip20_execution);
criterion_main!(benches);
