//! Benchmark helpers for transaction-pool internals.

use crate::{
    AA2dPoolConfig, TempoTransactionPool,
    amm::AmmLiquidityCache,
    best::MergeBestTransactions,
    maintain::{TempoPoolState, process_tempo_pool_block_update},
    metrics::TempoPoolMaintenanceMetrics,
    transaction::TempoPooledTransaction,
    tt_2d_pool::AA2dPool,
    validator::{
        DEFAULT_AA_VALID_AFTER_MAX_SECS, DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
        TempoTransactionValidator,
    },
};
use alloy_consensus::{Header, Transaction};
use alloy_primitives::{Address, Signature, TxKind, U256};
use reth_primitives_traits::Recovered;
use reth_provider::{
    Chain, ExecutionOutcome,
    test_utils::{ExtendedAccount, MockEthProvider},
};
use reth_transaction_pool::{
    CoinbaseTipOrdering, Pool, PoolConfig, SubPoolLimit, TransactionOrigin,
    TransactionValidationTaskExecutor, ValidPoolTransaction, blobstore::InMemoryBlobStore,
    identifier::TransactionId, test_utils::OkValidator, validate::EthTransactionValidatorBuilder,
};
use std::{num::NonZeroU64, sync::Arc, time::Instant};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardfork, spec::MODERATO};
use tempo_evm::TempoEvmConfig;
use tempo_primitives::{
    Block, BlockBody, TempoHeader, TempoPrimitives, TempoTxEnvelope,
    transaction::{
        TEMPO_EXPIRING_NONCE_KEY, TempoTransaction,
        tempo_transaction::Call,
        tt_signature::{PrimitiveSignature, TempoSignature},
        tt_signed::AASigned,
    },
};

const BENCH_CHAIN_ID: u64 = 42431;
const BENCH_NONCE_KEY: u64 = 1;
const BENCH_GAS_LIMIT: u64 = 1_000_000;
const BENCH_MAX_PRIORITY_FEE_PER_GAS: u128 = 1_000_000_000;
const BENCH_MAX_FEE_PER_GAS: u128 = 20_000_000_000;
const BENCH_VALID_BEFORE: u64 = 1_700_000_010;
const BENCH_MAINTENANCE_TIP_TIMESTAMP: u64 = BENCH_VALID_BEFORE + 1;

type BenchProvider = MockEthProvider<TempoPrimitives, TempoChainSpec>;

/// Builds an AA 2D pool with `sequences` independent nonce chains of `chain_len` txs each.
pub fn aa2d_pool_fixture(sequences: usize, chain_len: usize) -> AA2dPool {
    assert!(
        sequences > 0,
        "benchmark fixture must have at least one sequence"
    );
    assert!(
        chain_len > 0,
        "benchmark fixture must have at least one tx per sequence"
    );

    let mut pool = AA2dPool::new(AA2dPoolConfig {
        pending_limit: SubPoolLimit::max(),
        queued_limit: SubPoolLimit::max(),
        max_txs_per_sender: chain_len,
        ..Default::default()
    });

    for sequence in 0..sequences {
        let sender = bench_address(0x10, sequence);
        let target = bench_address(0x20, sequence);

        for nonce in 0..chain_len {
            let tx = bench_aa_tx(
                sender,
                target,
                U256::from(BENCH_NONCE_KEY),
                nonce as u64,
                None,
            );
            pool.add_transaction(Arc::new(wrap_valid_tx(tx)), 0, TempoHardfork::T1)
                .expect("benchmark AA 2D transaction must be accepted");
        }
    }

    pool
}

/// Fixture for one expired-transaction txpool maintenance block update.
pub struct ExpiredTxpoolMaintenanceFixture {
    pool: TempoTransactionPool<BenchProvider>,
    state: TempoPoolState,
    metrics: TempoPoolMaintenanceMetrics,
    amm_cache: AmmLiquidityCache,
    chain: Arc<Chain<TempoPrimitives>>,
}

impl ExpiredTxpoolMaintenanceFixture {
    /// Runs one maintenance block update and returns the number of expired transactions evicted.
    pub fn run_one(&mut self) -> usize {
        process_tempo_pool_block_update(
            &self.pool,
            &mut self.state,
            &self.metrics,
            &self.amm_cache,
            &self.chain,
        )
        .expired_evicted
    }
}

/// Builds a txpool maintenance fixture where all AA2D transactions are expired.
pub fn expired_txpool_maintenance_fixture(
    sequences: usize,
    txs_per_sender: usize,
) -> ExpiredTxpoolMaintenanceFixture {
    assert!(
        sequences > 0,
        "benchmark fixture must have at least one sequence"
    );
    assert!(
        txs_per_sender > 0,
        "benchmark fixture must have at least one tx per sender"
    );

    let mut state = TempoPoolState::default();
    let mut aa_pool = AA2dPool::new(AA2dPoolConfig {
        pending_limit: SubPoolLimit::max(),
        queued_limit: SubPoolLimit::max(),
        max_txs_per_sender: txs_per_sender,
        ..Default::default()
    });

    for sequence in 0..sequences {
        let sender = bench_address(0x50, sequence);
        let target = bench_address(0x60, sequence);

        for nonce in 0..txs_per_sender {
            let tx = bench_aa_tx(
                sender,
                target,
                U256::from(BENCH_NONCE_KEY),
                nonce as u64,
                NonZeroU64::new(BENCH_VALID_BEFORE),
            );
            state.track(&tx);
            aa_pool
                .add_transaction(Arc::new(wrap_valid_tx(tx)), 0, TempoHardfork::T1)
                .expect("benchmark expired AA 2D transaction must be accepted");
        }
    }

    let provider = bench_provider();
    let protocol_pool = bench_protocol_pool(provider);
    let pool = TempoTransactionPool::new(protocol_pool, aa_pool);
    let amm_cache = pool.amm_liquidity_cache();
    let chain = maintenance_chain(BENCH_MAINTENANCE_TIP_TIMESTAMP);

    ExpiredTxpoolMaintenanceFixture {
        pool,
        state,
        metrics: TempoPoolMaintenanceMetrics::default(),
        amm_cache,
        chain,
    }
}

/// Builds an AA pool with independent expiring-nonce transactions.
pub fn expiring_nonce_pool_fixture(sequences: usize, txs_per_sender: usize) -> AA2dPool {
    assert!(
        sequences > 0,
        "benchmark fixture must have at least one sequence"
    );
    assert!(
        txs_per_sender > 0,
        "benchmark fixture must have at least one tx per sender"
    );

    let mut pool = AA2dPool::new(AA2dPoolConfig {
        pending_limit: SubPoolLimit::max(),
        queued_limit: SubPoolLimit::max(),
        max_txs_per_sender: txs_per_sender,
        ..Default::default()
    });

    for sequence in 0..sequences {
        let sender = bench_address(0x30, sequence);

        for tx_idx in 0..txs_per_sender {
            let target = bench_address(0x40, sequence * txs_per_sender + tx_idx);
            let tx = bench_aa_tx(
                sender,
                target,
                TEMPO_EXPIRING_NONCE_KEY,
                expiring_nonce_value(),
                NonZeroU64::new(BENCH_VALID_BEFORE + tx_idx as u64),
            );
            pool.add_transaction(Arc::new(wrap_valid_tx(tx)), 0, TempoHardfork::T1)
                .expect("benchmark expiring nonce transaction must be accepted");
        }
    }

    pool
}

/// Creates a merged best-transaction snapshot.
pub fn best_transactions_snapshot(pool: &AA2dPool) -> MergeBestTransactions {
    MergeBestTransactions::new(empty_protocol_best_transactions(), pool.best_transactions())
}

fn empty_protocol_best_transactions()
-> reth_transaction_pool::pool::BestTransactions<CoinbaseTipOrdering<TempoPooledTransaction>> {
    let pool = Pool::new(
        OkValidator::<TempoPooledTransaction>::default(),
        CoinbaseTipOrdering::default(),
        InMemoryBlobStore::default(),
        PoolConfig::default(),
    );

    pool.inner().best_transactions()
}

fn bench_provider() -> BenchProvider {
    let provider = MockEthProvider::<TempoPrimitives>::new()
        .with_chain_spec(Arc::unwrap_or_clone(MODERATO.clone()))
        .with_genesis_block();
    provider.add_account(Address::ZERO, ExtendedAccount::new(0, U256::MAX));
    provider
}

fn bench_protocol_pool(
    provider: BenchProvider,
) -> Pool<
    TransactionValidationTaskExecutor<TempoTransactionValidator<BenchProvider>>,
    CoinbaseTipOrdering<TempoPooledTransaction>,
    InMemoryBlobStore,
> {
    let inner = EthTransactionValidatorBuilder::new(provider, TempoEvmConfig::mainnet())
        .disable_balance_check()
        .build(InMemoryBlobStore::default());
    let validator = TempoTransactionValidator::new(
        inner,
        DEFAULT_AA_VALID_AFTER_MAX_SECS,
        DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
        AmmLiquidityCache::with_unique_validators(Vec::new()),
    );
    let (executor, _task) = TransactionValidationTaskExecutor::new(validator);

    Pool::new(
        executor,
        CoinbaseTipOrdering::default(),
        InMemoryBlobStore::default(),
        PoolConfig::default(),
    )
}

fn maintenance_chain(tip_timestamp: u64) -> Arc<Chain<TempoPrimitives>> {
    let block = Block::new(
        TempoHeader {
            inner: Header {
                number: 1,
                timestamp: tip_timestamp,
                ..Default::default()
            },
            ..Default::default()
        },
        BlockBody::default(),
    );
    let recovered = reth_primitives_traits::RecoveredBlock::new_unhashed(block, Vec::new());

    Arc::new(Chain::new(
        vec![recovered],
        ExecutionOutcome::default(),
        Default::default(),
    ))
}

fn bench_aa_tx(
    sender: Address,
    target: Address,
    nonce_key: U256,
    nonce: u64,
    valid_before: Option<NonZeroU64>,
) -> TempoPooledTransaction {
    let tx = TempoTransaction {
        chain_id: BENCH_CHAIN_ID,
        max_priority_fee_per_gas: BENCH_MAX_PRIORITY_FEE_PER_GAS,
        max_fee_per_gas: BENCH_MAX_FEE_PER_GAS,
        gas_limit: BENCH_GAS_LIMIT,
        calls: vec![Call {
            to: TxKind::Call(target),
            value: U256::ZERO,
            input: Default::default(),
        }],
        nonce_key,
        nonce,
        fee_token: None,
        fee_payer_signature: None,
        valid_after: None,
        valid_before,
        access_list: Default::default(),
        tempo_authorization_list: Default::default(),
        key_authorization: None,
    };

    let signature =
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));
    let aa_signed = AASigned::new_unhashed(tx, signature);
    let envelope: TempoTxEnvelope = aa_signed.into();
    let recovered = Recovered::new_unchecked(envelope, sender);

    TempoPooledTransaction::new(recovered)
}

fn wrap_valid_tx(tx: TempoPooledTransaction) -> ValidPoolTransaction<TempoPooledTransaction> {
    let tx_id = TransactionId::new(0u64.into(), tx.nonce());
    ValidPoolTransaction {
        transaction: tx,
        transaction_id: tx_id,
        propagate: true,
        timestamp: Instant::now(),
        origin: TransactionOrigin::Local,
        authority_ids: None,
    }
}

fn expiring_nonce_value() -> u64 {
    u64::default()
}

fn bench_address(prefix: u8, index: usize) -> Address {
    let mut bytes = [0u8; 20];
    bytes[0] = prefix;
    bytes[12..].copy_from_slice(&(index as u64).to_be_bytes());
    Address::from(bytes)
}
