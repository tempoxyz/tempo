use alloy_consensus::{Header, Transaction};
use alloy_primitives::{Address, B256, Signature, TxKind, U256, uint};
use core::num::NonZeroU64;
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
use reth_transaction_pool::{
    BestTransactionsAttributes, BlockInfo, Pool, PoolConfig, PoolTransaction, SubPoolLimit,
    TransactionOrigin, TransactionPool, TransactionPoolExt, TransactionValidationTaskExecutor,
    blobstore::InMemoryBlobStore, validate::EthTransactionValidatorBuilder,
};
use std::{hint::black_box, sync::Arc};
use tempo_chainspec::{
    TempoChainSpec,
    hardfork::TempoHardfork,
    spec::{MODERATO, TEMPO_T1_TX_GAS_LIMIT_CAP},
};
use tempo_evm::TempoEvmConfig;
use tempo_precompiles::{
    PATH_USD_ADDRESS,
    tip20::{TIP20Token, slots as tip20_slots},
};
use tempo_primitives::{
    AASigned, Block, TempoHeader, TempoPrimitives, TempoSignature, TempoTransaction,
    TempoTxEnvelope, TempoTxType,
    transaction::{Call, PrimitiveSignature, TEMPO_EXPIRING_NONCE_KEY},
};
use tempo_transaction_pool::{
    AA2dPool, AA2dPoolConfig, DEFAULT_MAX_TXS_PER_SENDER, TempoTransactionPool,
    amm::AmmLiquidityCache,
    ordering::TempoTipOrdering,
    transaction::TempoPooledTransaction,
    validator::{
        DEFAULT_AA_VALID_AFTER_MAX_SECS, DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
        TempoTransactionValidator,
    },
};
use tokio::{runtime::Runtime, task::JoinHandle};

const TX_COUNT: usize = 50_000;
const CHAIN_ID: u64 = 42431;
const GAS_LIMIT: u64 = 1_000_000;
const PRIORITY_FEE_BASE: u128 = 1_000_000_000;
const VALID_BEFORE: u64 = 1_771_000_600;
const BLOCK_TIMESTAMP: u64 = VALID_BEFORE - 15;
const FEE_TOKEN_BALANCE: u128 = 1_000_000_000_000_000_000;

type BenchProvider = MockEthProvider<TempoPrimitives, TempoChainSpec>;
type BenchPool = TempoTransactionPool<BenchProvider>;

fn aa2d_expiring_nonce_50k(c: &mut Criterion) {
    let runtime = Runtime::new().expect("failed to create tokio runtime");
    let base_fee = TempoHardfork::T1.base_fee();
    let txs = build_transactions(base_fee);
    let provider = build_provider(&txs);

    let mut group = c.benchmark_group("aa2d_expiring_nonce_50k");
    group.sample_size(10);
    group.throughput(Throughput::Elements(TX_COUNT as u64));

    group.bench_function("add_transactions", |b| {
        b.iter_batched(
            || {
                let pool = build_pool(provider.clone(), &runtime);
                set_pool_block_info(&pool, base_fee);
                (pool, txs.clone())
            },
            |(pool, txs)| {
                let results =
                    runtime.block_on(pool.add_transactions(TransactionOrigin::Local, txs));
                assert_all_admitted(&results);
                black_box(pool);
            },
            BatchSize::LargeInput,
        );
    });

    let pool = build_pool(provider, &runtime);
    set_pool_block_info(&pool, base_fee);
    let results = runtime.block_on(pool.add_transactions(TransactionOrigin::Local, txs));
    assert_all_admitted(&results);

    let attributes = BestTransactionsAttributes::base_fee(base_fee);
    let lower_base_fee = base_fee - 1;
    let lower_attributes = BestTransactionsAttributes::base_fee(lower_base_fee);

    group.bench_function("best_transactions_with_attributes", |b| {
        b.iter(|| {
            drop(black_box(
                pool.best_transactions_with_attributes(attributes),
            ));
        });
    });

    group.bench_function("best_transactions_with_lower_base_fee", |b| {
        b.iter(|| {
            drop(black_box(
                pool.best_transactions_with_attributes(lower_attributes),
            ));
        });
    });

    group.bench_function("advance_best_transactions_with_attributes", |b| {
        b.iter_batched(
            || pool.best_transactions_with_attributes(attributes),
            |best| {
                let mut count = 0usize;
                for tx in best {
                    black_box(tx);
                    count += 1;
                }
                black_box(count);
            },
            BatchSize::LargeInput,
        );
    });

    group.bench_function("advance_best_transactions_with_lower_base_fee", |b| {
        b.iter_batched(
            || pool.best_transactions_with_attributes(lower_attributes),
            |best| {
                let mut count = 0usize;
                for tx in best {
                    black_box(tx);
                    count += 1;
                }
                black_box(count);
            },
            BatchSize::LargeInput,
        );
    });

    let base_info = bench_block_info(base_fee);
    let lower_info = bench_block_info(lower_base_fee);
    group.bench_function("set_block_info_round_trip", |b| {
        b.iter(|| {
            pool.set_block_info(black_box(lower_info));
            pool.set_block_info(black_box(base_info));
        });
    });

    group.finish();
}

fn assert_all_admitted<T, E: std::fmt::Debug>(results: &[Result<T, E>]) {
    assert_eq!(results.len(), TX_COUNT);
    if let Some((index, err)) = results
        .iter()
        .enumerate()
        .find_map(|(index, result)| result.as_ref().err().map(|err| (index, err)))
    {
        panic!("benchmark transaction {index} was rejected: {err:?}");
    }
}

fn build_pool(provider: BenchProvider, runtime: &Runtime) -> BenchPool {
    let inner = EthTransactionValidatorBuilder::new(provider.clone(), TempoEvmConfig::moderato())
        .with_custom_tx_type(TempoTxType::AA as u8)
        .disable_balance_check()
        .build(InMemoryBlobStore::default());
    let amm_cache = AmmLiquidityCache::new(provider).expect("failed to setup AMM cache");
    let validator = TempoTransactionValidator::new(
        inner,
        DEFAULT_AA_VALID_AFTER_MAX_SECS,
        DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
        amm_cache,
    );

    let (executor, task) = TransactionValidationTaskExecutor::new(validator);
    drop(spawn_validation_task(runtime, task.run()));

    let protocol_pool = Pool::new(
        executor,
        TempoTipOrdering::default(),
        InMemoryBlobStore::default(),
        PoolConfig::default(),
    );
    TempoTransactionPool::new(protocol_pool, AA2dPool::new(bench_aa_config()))
}

fn set_pool_block_info(pool: &BenchPool, base_fee: u64) {
    pool.set_block_info(bench_block_info(base_fee));
}

fn bench_block_info(base_fee: u64) -> BlockInfo {
    BlockInfo {
        last_seen_block_hash: B256::ZERO,
        last_seen_block_number: 0,
        block_gas_limit: TEMPO_T1_TX_GAS_LIMIT_CAP,
        pending_basefee: base_fee,
        pending_blob_fee: None,
    }
}

fn spawn_validation_task(
    runtime: &Runtime,
    task: impl std::future::Future<Output = ()> + Send + 'static,
) -> JoinHandle<()> {
    runtime.spawn(task)
}

fn bench_aa_config() -> AA2dPoolConfig {
    AA2dPoolConfig {
        price_bump_config: Default::default(),
        pending_limit: SubPoolLimit {
            max_txs: TX_COUNT + 1,
            max_size: usize::MAX,
        },
        queued_limit: SubPoolLimit {
            max_txs: TX_COUNT + 1,
            max_size: usize::MAX,
        },
        max_txs_per_sender: DEFAULT_MAX_TXS_PER_SENDER.max(TX_COUNT + 1),
    }
}

fn build_provider(txs: &[TempoPooledTransaction]) -> BenchProvider {
    let provider = MockEthProvider::<TempoPrimitives>::new()
        .with_chain_spec(Arc::unwrap_or_clone(MODERATO.clone()));
    provider.add_block(
        B256::random(),
        Block {
            header: TempoHeader {
                inner: Header {
                    gas_limit: TEMPO_T1_TX_GAS_LIMIT_CAP,
                    timestamp: BLOCK_TIMESTAMP,
                    base_fee_per_gas: Some(TempoHardfork::T1.base_fee()),
                    blob_gas_used: Some(0),
                    excess_blob_gas: Some(0),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        },
    );

    let usd_currency_value =
        uint!(0x5553440000000000000000000000000000000000000000000000000000000006_U256);
    let transfer_policy_id_packed =
        uint!(0x0000000000000000000000010000000000000000000000000000000000000000_U256);
    let mut token_storage = Vec::with_capacity(txs.len() + 2);
    token_storage.push((tip20_slots::CURRENCY.into(), usd_currency_value));
    token_storage.push((
        tip20_slots::TRANSFER_POLICY_ID.into(),
        transfer_policy_id_packed,
    ));

    let path_usd = TIP20Token::from_address(PATH_USD_ADDRESS)
        .expect("PATH_USD_ADDRESS must be a valid TIP20 token");
    for tx in txs {
        provider.add_account(tx.sender(), ExtendedAccount::new(tx.nonce(), U256::ZERO));
        token_storage.push((
            path_usd.balances[tx.sender()].base_slot().into(),
            U256::from(FEE_TOKEN_BALANCE),
        ));
    }

    provider.add_account(
        PATH_USD_ADDRESS,
        ExtendedAccount::new(0, U256::ZERO).extend_storage(token_storage),
    );
    provider
}

fn build_transactions(base_fee: u64) -> Vec<TempoPooledTransaction> {
    (0..TX_COUNT)
        .map(|index| expiring_nonce_tx(index, base_fee))
        .collect()
}

fn expiring_nonce_tx(index: usize, base_fee: u64) -> TempoPooledTransaction {
    let sender = indexed_address(index as u64 + 1);
    let recipient = indexed_address(index as u64 + 1_000_000);
    let priority_fee = PRIORITY_FEE_BASE + index as u128;

    let tx = TempoTransaction {
        chain_id: CHAIN_ID,
        max_priority_fee_per_gas: priority_fee,
        max_fee_per_gas: u128::from(base_fee) + priority_fee + 1,
        gas_limit: GAS_LIMIT,
        calls: vec![Call {
            to: TxKind::Call(recipient),
            value: U256::ZERO,
            input: Default::default(),
        }],
        nonce_key: TEMPO_EXPIRING_NONCE_KEY,
        nonce: 0,
        fee_token: Some(PATH_USD_ADDRESS),
        fee_payer_signature: None,
        valid_after: None,
        valid_before: Some(NonZeroU64::new(VALID_BEFORE).unwrap()),
        access_list: Default::default(),
        tempo_authorization_list: Vec::new(),
        key_authorization: None,
    };
    let signed = AASigned::new_unhashed(
        tx,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature())),
    );
    let envelope: TempoTxEnvelope = signed.into();
    TempoPooledTransaction::new(alloy_consensus::transaction::Recovered::new_unchecked(
        envelope, sender,
    ))
}

fn indexed_address(index: u64) -> Address {
    let mut bytes = [0u8; 20];
    bytes[12..].copy_from_slice(&index.to_be_bytes());
    Address::from(bytes)
}

criterion_group!(benches, aa2d_expiring_nonce_50k);
criterion_main!(benches);
