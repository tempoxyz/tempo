//! Pool admission microbenchmark: single-transaction validation versus coalesced batches.
//!
//! The validator runs against an in-memory mock provider, so the numbers cover the validator's
//! own per-transaction work (pool EVM setup, state cache, nonce/fee/balance checks) and exclude
//! the cost of building a state provider over a real database.

use alloy_consensus::{Header, Signed, TxEip1559};
use alloy_primitives::{Address, B256, Signature, TxKind, U256, uint};
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use reth_primitives_traits::{Recovered, SealedBlock};
use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
use reth_transaction_pool::{
    TransactionOrigin, TransactionValidationOutcome, TransactionValidator,
    blobstore::InMemoryBlobStore, validate::EthTransactionValidatorBuilder,
};
use std::{cell::Cell, hint::black_box, sync::Arc};
use tempo_chainspec::{
    TempoChainSpec,
    spec::{MODERATO, TEMPO_T0_BASE_FEE, TEMPO_T1_TX_GAS_LIMIT_CAP},
};
use tempo_evm::TempoEvmConfig;
use tempo_precompiles::{
    PATH_USD_ADDRESS,
    tip20::{TIP20Token, slots as tip20_slots},
};
use tempo_primitives::{Block, TempoHeader, TempoPrimitives, TempoTxEnvelope, TempoTxType};
use tempo_transaction_pool::{
    amm::AmmLiquidityCache,
    transaction::TempoPooledTransaction,
    validator::{
        DEFAULT_AA_VALID_AFTER_MAX_SECS, DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
        TempoTransactionValidator,
    },
};

/// Number of distinct funded senders the workload cycles through.
const SENDER_COUNT: usize = 1024;
/// Chain id of the MODERATO chain spec used by the validator.
const CHAIN_ID: u64 = 42431;

type BenchValidator = TempoTransactionValidator<MockEthProvider<TempoPrimitives, TempoChainSpec>>;

/// Funded senders and a validator whose tip state is anchored to a mock block.
struct Fixture {
    validator: BenchValidator,
    senders: Vec<Address>,
    /// Round-robin cursor into `senders`; interior mutability lets the benchmark closures share
    /// the fixture.
    next_sender: Cell<usize>,
}

impl Fixture {
    fn new() -> Self {
        let provider = MockEthProvider::<TempoPrimitives>::new()
            .with_chain_spec(Arc::unwrap_or_clone(MODERATO.clone()));
        let senders = (0..SENDER_COUNT)
            .map(|_| Address::random())
            .collect::<Vec<_>>();
        for sender in &senders {
            provider.add_account(*sender, ExtendedAccount::new(0, U256::ZERO));
        }
        // The tip block is both the provider's best block and the block the validator anchors
        // its tip state to, as in production where `on_new_head_block` follows the canonical tip.
        let tip = SealedBlock::seal_slow(Block {
            header: TempoHeader {
                inner: Header {
                    timestamp: 1,
                    gas_limit: TEMPO_T1_TX_GAS_LIMIT_CAP,
                    excess_blob_gas: Some(0),
                    base_fee_per_gas: Some(TEMPO_T0_BASE_FEE),
                    ..Default::default()
                },
                ..Default::default()
            },
            body: Default::default(),
        });
        provider.add_block(tip.hash(), tip.clone_block());

        // PATH_USD as the default fee token: USD currency, always-allow transfer policy, and a
        // fee balance for every sender.
        let usd_currency_value =
            uint!(0x5553440000000000000000000000000000000000000000000000000000000006_U256);
        let transfer_policy_id_packed =
            uint!(0x0000000000000000000000010000000000000000000000000000000000000000_U256);
        let path_usd = TIP20Token::from_address(PATH_USD_ADDRESS).expect("PATH_USD is a TIP20");
        let mut path_usd_storage = vec![
            (B256::from(tip20_slots::CURRENCY), usd_currency_value),
            (
                B256::from(tip20_slots::TRANSFER_POLICY_ID),
                transfer_policy_id_packed,
            ),
        ];
        for sender in &senders {
            path_usd_storage.push((
                B256::from(path_usd.balances[*sender].slot()),
                U256::from(1_000_000_000_000u64),
            ));
        }
        provider.add_account(
            PATH_USD_ADDRESS,
            ExtendedAccount::new(0, U256::ZERO).extend_storage(path_usd_storage),
        );

        let inner =
            EthTransactionValidatorBuilder::new(provider.clone(), TempoEvmConfig::moderato())
                .with_custom_tx_type(TempoTxType::AA as u8)
                .disable_balance_check()
                .build(InMemoryBlobStore::default());
        let amm_cache = AmmLiquidityCache::new(provider).expect("AMM liquidity cache");
        let validator = TempoTransactionValidator::new(
            inner,
            DEFAULT_AA_VALID_AFTER_MAX_SECS,
            DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
            amm_cache,
        );
        validator.on_new_head_block(&tip);

        Self {
            validator,
            senders,
            next_sender: Cell::new(0),
        }
    }

    /// Builds a fresh EIP-1559 transfer from the next sender in round-robin order.
    ///
    /// Each call returns a new pooled transaction so per-transaction caches (e.g. the cached
    /// `TxEnv`) start cold, as they do for a freshly decoded RPC submission.
    fn next_transaction(&self) -> TempoPooledTransaction {
        let sender = self.senders[self.next_sender.get()];
        self.next_sender
            .set((self.next_sender.get() + 1) % self.senders.len());
        let tx = TxEip1559 {
            chain_id: CHAIN_ID,
            nonce: 0,
            to: TxKind::Call(Address::with_last_byte(0x42)),
            gas_limit: 1_000_000,
            max_fee_per_gas: 20_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            ..Default::default()
        };
        let envelope = TempoTxEnvelope::Eip1559(Signed::new_unchecked(
            tx,
            Signature::test_signature(),
            B256::random(),
        ));
        TempoPooledTransaction::new(Recovered::new_unchecked(envelope, sender))
    }

    fn next_batch(&self, size: usize) -> Vec<(TransactionOrigin, TempoPooledTransaction)> {
        (0..size)
            .map(|_| (TransactionOrigin::Local, self.next_transaction()))
            .collect()
    }
}

fn assert_valid(outcome: &TransactionValidationOutcome<TempoPooledTransaction>) {
    assert!(
        matches!(outcome, TransactionValidationOutcome::Valid { .. }),
        "benchmark transactions must be admitted, got {outcome:?}"
    );
}

fn bench_validate(c: &mut Criterion) {
    let fixture = Fixture::new();

    // Sanity check the fixture once so the benchmark does not silently time rejections.
    let tx = fixture.next_transaction();
    assert_valid(&futures::executor::block_on(
        fixture
            .validator
            .validate_transaction(TransactionOrigin::Local, tx),
    ));

    let mut group = c.benchmark_group("pool_admission");
    group.throughput(Throughput::Elements(1));
    group.bench_function("validate_transaction", |b| {
        b.iter_batched(
            || fixture.next_transaction(),
            |tx| {
                black_box(futures::executor::block_on(
                    fixture
                        .validator
                        .validate_transaction(TransactionOrigin::Local, tx),
                ))
            },
            BatchSize::SmallInput,
        )
    });

    for batch_size in [8usize, 64] {
        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_function(format!("validate_transactions/{batch_size}"), |b| {
            b.iter_batched(
                || fixture.next_batch(batch_size),
                |batch| {
                    black_box(futures::executor::block_on(
                        fixture.validator.validate_transactions(batch),
                    ))
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

criterion_group!(benches, bench_validate);
criterion_main!(benches);
