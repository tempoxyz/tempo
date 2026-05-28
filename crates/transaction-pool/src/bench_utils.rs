//! Test-feature utilities for Criterion transaction-pool benchmarks.

use crate::{
    AA2dPool, AA2dPoolConfig, TempoTransactionPool,
    amm::AmmLiquidityCache,
    maintain::{EVICTION_BUFFER_SECS, TempoPoolState},
    transaction::TempoPooledTransaction,
    validator::{
        DEFAULT_AA_VALID_AFTER_MAX_SECS, DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
        TempoTransactionValidator,
    },
};
use alloy_consensus::{Header, Transaction};
use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256};
use alloy_sol_types::SolCall;
use core::num::NonZeroU64;
use reth_primitives_traits::Recovered;
use reth_provider::test_utils::MockEthProvider;
use reth_transaction_pool::{
    AddedTransactionOutcome, CoinbaseTipOrdering, Pool, PoolConfig, PoolResult, PoolTransaction,
    SubPoolLimit, TransactionOrigin, TransactionPool, TransactionValidationOutcome,
    TransactionValidationTaskExecutor,
    blobstore::InMemoryBlobStore,
    validate::{EthTransactionValidatorBuilder, ValidTransaction},
};
use std::sync::Arc;
use tempo_chainspec::{
    TempoChainSpec,
    spec::{DEV, TEMPO_T1_TX_GAS_LIMIT_CAP},
};
use tempo_contracts::precompiles::{DEFAULT_FEE_TOKEN, ITIP20};
use tempo_evm::TempoEvmConfig;
use tempo_primitives::{
    AASigned, Block, TempoHeader, TempoPrimitives, TempoSignature, TempoTransaction,
    TempoTxEnvelope,
    transaction::{Call, PrimitiveSignature, TEMPO_EXPIRING_NONCE_KEY},
};

/// Default account count used by the txgen-style TIP20 workload.
pub const DEFAULT_TXGEN_ACCOUNT_COUNT: usize = 1_024;
/// Default transaction count used by the txgen-style TIP20 workload.
pub const DEFAULT_TXGEN_TX_COUNT: usize = 4_096;
/// Timestamp used for the synthetic pool tip and transaction validity window.
pub const DEFAULT_BLOCK_TIMESTAMP: u64 = 1_700_000_000;
/// `valid_for_secs` from `contrib/bench/txgen/presets/tip20.yml`.
pub const TXGEN_TIP20_VALID_FOR_SECS: u64 = 10;
/// Gas limit from `contrib/bench/txgen/presets/tip20.yml`.
pub const TXGEN_TIP20_GAS_LIMIT: u64 = 300_000;
/// Fee settings from the txgen TIP20 preset.
pub const TXGEN_FEE_PER_GAS: u128 = 100_000_000_000;
/// Chain id from the txgen TIP20 preset.
pub const TXGEN_CHAIN_ID: u64 = 1337;

/// Mock provider type used by the transaction-pool benches.
pub type BenchProvider = MockEthProvider<TempoPrimitives, TempoChainSpec>;
/// Tempo transaction pool type used by the transaction-pool benches.
pub type BenchPool = TempoTransactionPool<BenchProvider>;

/// Configuration for the txgen-style TIP20 expiring nonce pool benchmarks.
#[derive(Debug, Clone)]
pub struct TxpoolBenchConfig {
    pub account_count: usize,
    pub tx_count: usize,
    pub block_timestamp: u64,
    pub valid_for_secs: u64,
    pub chain_id: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

impl Default for TxpoolBenchConfig {
    fn default() -> Self {
        Self {
            account_count: DEFAULT_TXGEN_ACCOUNT_COUNT,
            tx_count: DEFAULT_TXGEN_TX_COUNT,
            block_timestamp: DEFAULT_BLOCK_TIMESTAMP,
            valid_for_secs: TXGEN_TIP20_VALID_FOR_SECS,
            chain_id: TXGEN_CHAIN_ID,
            gas_limit: TXGEN_TIP20_GAS_LIMIT,
            max_fee_per_gas: TXGEN_FEE_PER_GAS,
            max_priority_fee_per_gas: TXGEN_FEE_PER_GAS,
        }
    }
}

/// Pre-generated txgen-style workload used as input to timed pool operations.
#[derive(Debug, Clone)]
pub struct TxpoolWorkload {
    pub transactions: Vec<TempoPooledTransaction>,
    pub participants: Vec<Address>,
}

/// Maintenance state wrapper that exposes the expiry path used by
/// `maintain_tempo_pool` without running the infinite async event loop.
#[derive(Default)]
pub struct ExpiryMaintenanceState {
    inner: TempoPoolState,
}

impl ExpiryMaintenanceState {
    /// Seed expiry tracking from the current pool contents, matching
    /// `maintain_tempo_pool` startup behavior.
    pub fn from_pool(pool: &BenchPool) -> Self {
        let mut inner = TempoPoolState::default();
        let all_txs = pool.all_transactions();
        for tx in all_txs.pending.iter().chain(all_txs.queued.iter()) {
            inner.track(&tx.transaction);
        }
        Self { inner }
    }

    /// Run the expiring-transaction eviction portion of one maintenance tick.
    pub fn evict_expired(&mut self, pool: &BenchPool, tip_timestamp: u64) -> usize {
        let max_expiry = tip_timestamp.saturating_add(EVICTION_BUFFER_SECS);
        let expired: Vec<_> = self
            .inner
            .drain_expired(max_expiry)
            .into_iter()
            .filter(|hash| pool.contains(hash))
            .collect();
        if expired.is_empty() {
            return 0;
        }
        pool.remove_transactions(expired).len()
    }
}

/// Build deterministic TIP20 expiring nonce transactions with the same pool-relevant shape as
/// the txgen TIP20 preset: AA transaction, TIP20 transfer call, explicit fee token, expiring
/// nonce key, nonce 0, and a 10s validity window. Like txgen, the fee fields are bumped by a
/// per-transaction counter so deterministic expiring-nonce hashes stay unique.
pub fn txgen_tip20_expiring_nonce_workload(config: &TxpoolBenchConfig) -> TxpoolWorkload {
    assert!(config.account_count > 0, "account_count must be non-zero");

    let participants = (0..config.account_count)
        .map(indexed_user_address)
        .collect::<Vec<_>>();
    let transactions = (0..config.tx_count)
        .map(|idx| {
            let sender = participants[idx % participants.len()];
            let recipient = participants
                [(idx.wrapping_mul(17) + 1 + idx / participants.len()) % participants.len()];
            tip20_expiring_nonce_tx(config, sender, recipient, idx as u128 + 1)
        })
        .collect();

    TxpoolWorkload {
        transactions,
        participants,
    }
}

/// Create a fresh mock-backed Tempo transaction pool sized for the benchmark workload.
pub fn fresh_pool(config: &TxpoolBenchConfig) -> BenchPool {
    let provider = provider_with_tip(config.block_timestamp);
    let inner = EthTransactionValidatorBuilder::new(provider.clone(), TempoEvmConfig::mainnet())
        .disable_balance_check()
        .build(InMemoryBlobStore::default());
    let amm_cache = AmmLiquidityCache::new(provider).expect("failed to setup AmmLiquidityCache");
    let validator = TempoTransactionValidator::new(
        inner,
        DEFAULT_AA_VALID_AFTER_MAX_SECS,
        DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
        amm_cache,
    );

    let (executor, _task) = TransactionValidationTaskExecutor::new(validator);
    let protocol_pool = Pool::new(
        executor,
        CoinbaseTipOrdering::default(),
        InMemoryBlobStore::default(),
        PoolConfig::default(),
    );
    let aa_config = AA2dPoolConfig {
        pending_limit: SubPoolLimit::max(),
        queued_limit: SubPoolLimit::max(),
        max_txs_per_sender: config.tx_count.max(1),
        ..Default::default()
    };
    TempoTransactionPool::new(protocol_pool, AA2dPool::new(aa_config))
}

/// Insert a transaction through the validated transaction path, bypassing expensive EVM
/// validation so the benchmark isolates pool admission and indexing.
pub fn add_validated_transaction_for_bench(
    pool: &BenchPool,
    pooled: TempoPooledTransaction,
) -> PoolResult<AddedTransactionOutcome> {
    let state_nonce = pooled.nonce();
    let validated = TransactionValidationOutcome::Valid {
        balance: *pooled.cost(),
        state_nonce,
        bytecode_hash: None,
        transaction: ValidTransaction::new(pooled, None),
        propagate: true,
        authorities: None,
    };
    pool.add_validated_transaction(TransactionOrigin::External, validated)
}

/// Create a fully populated pool and matching expiry-maintenance state.
pub fn populated_pool_with_expiry_state(
    workload: &TxpoolWorkload,
    config: &TxpoolBenchConfig,
) -> (BenchPool, ExpiryMaintenanceState) {
    let pool = fresh_pool(config);
    for tx in workload.transactions.iter().cloned() {
        add_validated_transaction_for_bench(&pool, tx)
            .expect("benchmark transaction should be admitted");
    }
    let state = ExpiryMaintenanceState::from_pool(&pool);
    (pool, state)
}

fn tip20_expiring_nonce_tx(
    config: &TxpoolBenchConfig,
    sender: Address,
    recipient: Address,
    uniqueness_bump: u128,
) -> TempoPooledTransaction {
    let input = Bytes::from(
        ITIP20::transferCall {
            to: recipient,
            amount: U256::from(1),
        }
        .abi_encode(),
    );
    let max_priority_fee_per_gas = config
        .max_priority_fee_per_gas
        .checked_add(uniqueness_bump)
        .expect("benchmark priority fee overflow");
    let max_fee_per_gas = config
        .max_fee_per_gas
        .checked_add(uniqueness_bump)
        .expect("benchmark max fee overflow");
    let tx = TempoTransaction {
        chain_id: config.chain_id,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit: config.gas_limit,
        calls: vec![Call {
            to: TxKind::Call(DEFAULT_FEE_TOKEN),
            value: U256::ZERO,
            input,
        }],
        nonce_key: TEMPO_EXPIRING_NONCE_KEY,
        nonce: 0,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        fee_payer_signature: None,
        valid_after: None,
        valid_before: NonZeroU64::new(config.block_timestamp + config.valid_for_secs),
        access_list: Default::default(),
        tempo_authorization_list: Vec::new(),
        key_authorization: None,
    };
    let signature =
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));
    let envelope: TempoTxEnvelope = AASigned::new_unhashed(tx, signature).into();
    TempoPooledTransaction::new(Recovered::new_unchecked(envelope, sender))
}

fn provider_with_tip(block_timestamp: u64) -> BenchProvider {
    let provider = MockEthProvider::<TempoPrimitives>::new()
        .with_chain_spec(Arc::unwrap_or_clone(DEV.clone()));
    provider.add_block(
        B256::with_last_byte(1),
        Block {
            header: TempoHeader {
                inner: Header {
                    gas_limit: TEMPO_T1_TX_GAS_LIMIT_CAP,
                    timestamp: block_timestamp,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        },
    );
    provider
}

fn indexed_user_address(index: usize) -> Address {
    let mut bytes = [0u8; 20];
    bytes[0] = 0x10;
    bytes[12..].copy_from_slice(&(index as u64).to_be_bytes());
    Address::from(bytes)
}
