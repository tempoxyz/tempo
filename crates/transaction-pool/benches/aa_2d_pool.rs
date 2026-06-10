//! Benchmarks for the AA 2D nonce pool under saturation.
//!
//! Covers the hot paths observed in high-TPS runs:
//! * `add_transaction` while the pool is at capacity (every insert triggers eviction)
//! * `on_state_updates` when a block mines many 2D nonce and expiring nonce transactions

use alloy_primitives::{Address, Signature, TxKind, U256, map::AddressMap};
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use reth_primitives_traits::Recovered;
use reth_transaction_pool::{SubPoolLimit, TransactionOrigin, ValidPoolTransaction};
use revm::database::{AccountStatus, BundleAccount, states::StorageSlot};
use std::{hint::black_box, sync::Arc, time::Instant};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::NONCE_PRECOMPILE_ADDRESS;
use tempo_primitives::{
    TempoTxEnvelope,
    transaction::{
        TEMPO_EXPIRING_NONCE_KEY, TempoTransaction,
        tempo_transaction::Call,
        tt_signature::{PrimitiveSignature, TempoSignature},
        tt_signed::AASigned,
    },
};
use tempo_transaction_pool::{AA2dPool, AA2dPoolConfig, transaction::TempoPooledTransaction};

const HARDFORK: TempoHardfork = TempoHardfork::T8;

/// Builds a valid pool transaction for the given sender/nonce key/nonce.
///
/// `tip` controls `max_priority_fee_per_gas`, which determines eviction priority.
fn build_tx(
    sender: Address,
    nonce_key: U256,
    nonce: u64,
    tip: u128,
) -> Arc<ValidPoolTransaction<TempoPooledTransaction>> {
    let tx = TempoTransaction {
        chain_id: 42431,
        max_priority_fee_per_gas: tip,
        max_fee_per_gas: 20_000_000_000 + tip,
        gas_limit: 100_000,
        calls: vec![Call {
            to: TxKind::Call(Address::with_last_byte(1)),
            value: U256::ZERO,
            input: Default::default(),
        }],
        nonce_key,
        nonce,
        fee_token: None,
        fee_payer_signature: None,
        valid_after: None,
        valid_before: None,
        access_list: Default::default(),
        tempo_authorization_list: Vec::new(),
        key_authorization: None,
    };
    let signature =
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));
    let envelope: TempoTxEnvelope = AASigned::new_unhashed(tx, signature).into();
    let recovered = Recovered::new_unchecked(envelope, sender);
    let transaction = TempoPooledTransaction::new(recovered);
    let transaction_id = reth_transaction_pool::identifier::TransactionId::new(0u64.into(), nonce);
    Arc::new(ValidPoolTransaction {
        transaction,
        transaction_id,
        propagate: true,
        timestamp: Instant::now(),
        origin: TransactionOrigin::External,
        authority_ids: None,
    })
}

/// Deterministic sender address derived from an index.
fn sender(i: u64) -> Address {
    Address::from_slice(&{
        let mut b = [0u8; 20];
        b[..8].copy_from_slice(&i.to_be_bytes());
        b[19] = 0x42;
        b
    })
}

/// Builds `n` expiring nonce transactions from unique senders with increasing tips.
fn build_expiring_txs(
    n: u64,
    tip_offset: u128,
) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
    (0..n)
        .map(|i| {
            build_tx(
                sender(i),
                TEMPO_EXPIRING_NONCE_KEY,
                i,
                1_000_000 + tip_offset + u128::from(i),
            )
        })
        .collect()
}

/// Builds 2D nonce transactions: `keys` nonce keys starting at `key_offset`, with
/// `per_key` sequential nonces each.
fn build_2d_txs(
    keys: u64,
    per_key: u64,
    key_offset: u64,
    tip_offset: u128,
) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
    (key_offset..key_offset + keys)
        .flat_map(|k| {
            (0..per_key).map(move |n| {
                build_tx(
                    sender(k),
                    U256::from(k + 1),
                    n,
                    1_000_000 + tip_offset + u128::from(k),
                )
            })
        })
        .collect()
}

fn pool_config(max_txs: usize) -> AA2dPoolConfig {
    AA2dPoolConfig {
        pending_limit: SubPoolLimit {
            max_txs,
            max_size: usize::MAX,
        },
        queued_limit: SubPoolLimit {
            max_txs,
            max_size: usize::MAX,
        },
        max_txs_per_sender: usize::MAX,
        ..Default::default()
    }
}

/// Builds a pool pre-filled with the given transactions.
fn fill_pool(
    config: AA2dPoolConfig,
    txs: &[Arc<ValidPoolTransaction<TempoPooledTransaction>>],
) -> AA2dPool {
    let mut pool = AA2dPool::new(config);
    pool.set_base_fee(1_000_000_000);
    for tx in txs {
        pool.add_transaction(Arc::clone(tx), 0, HARDFORK).unwrap();
    }
    pool
}

/// Inserting expiring nonce transactions into a pool that is at capacity, so every
/// insert evicts the current lowest-priority transaction.
fn bench_add_at_capacity(c: &mut Criterion) {
    const CAPACITY: usize = 10_000;
    const ADDS: u64 = 2_000;

    let mut group = c.benchmark_group("aa_2d_pool/add_at_capacity");
    group.throughput(Throughput::Elements(ADDS));
    group.sample_size(10);

    let base = build_expiring_txs(CAPACITY as u64, 0);
    // higher tips so each insert evicts an old transaction instead of itself
    let incoming = build_expiring_txs(ADDS, 1_000_000_000);

    group.bench_function("expiring", |b| {
        b.iter_batched_ref(
            || fill_pool(pool_config(CAPACITY), &base),
            |pool| {
                for tx in &incoming {
                    let _ = black_box(pool.add_transaction(Arc::clone(tx), 0, HARDFORK));
                }
            },
            BatchSize::PerIteration,
        )
    });

    let base_2d = build_2d_txs(CAPACITY as u64 / 4, 4, 0, 0);
    // disjoint nonce keys so inserts evict instead of replacing
    let incoming_2d = build_2d_txs(ADDS / 4, 4, CAPACITY as u64, 1_000_000_000);

    group.bench_function("2d", |b| {
        b.iter_batched_ref(
            || fill_pool(pool_config(CAPACITY), &base_2d),
            |pool| {
                for tx in &incoming_2d {
                    let _ = black_box(pool.add_transaction(Arc::clone(tx), 0, HARDFORK));
                }
            },
            BatchSize::PerIteration,
        )
    });

    group.finish();
}

/// Filling an empty pool below capacity (no eviction pressure).
fn bench_add_fill(c: &mut Criterion) {
    const N: u64 = 10_000;

    let mut group = c.benchmark_group("aa_2d_pool/add_fill");
    group.throughput(Throughput::Elements(N));
    group.sample_size(10);

    let expiring = build_expiring_txs(N, 0);
    group.bench_function("expiring", |b| {
        b.iter_batched_ref(
            || {
                let mut pool = AA2dPool::new(pool_config(N as usize * 2));
                pool.set_base_fee(1_000_000_000);
                pool
            },
            |pool| {
                for tx in &expiring {
                    let _ = black_box(pool.add_transaction(Arc::clone(tx), 0, HARDFORK));
                }
            },
            BatchSize::PerIteration,
        )
    });

    let txs_2d = build_2d_txs(N / 4, 4, 0, 0);
    group.bench_function("2d", |b| {
        b.iter_batched_ref(
            || {
                let mut pool = AA2dPool::new(pool_config(N as usize * 2));
                pool.set_base_fee(1_000_000_000);
                pool
            },
            |pool| {
                for tx in &txs_2d {
                    let _ = black_box(pool.add_transaction(Arc::clone(tx), 0, HARDFORK));
                }
            },
            BatchSize::PerIteration,
        )
    });

    group.finish();
}

/// State updates that mine a large number of transactions at once out of a saturated pool.
fn bench_on_state_updates(c: &mut Criterion) {
    const CAPACITY: usize = 10_000;
    const MINED: u64 = 5_000;

    let mut group = c.benchmark_group("aa_2d_pool/on_state_updates");
    group.throughput(Throughput::Elements(MINED));
    group.sample_size(10);

    // Expiring nonce transactions: mark MINED of them as seen on chain.
    let expiring = build_expiring_txs(CAPACITY as u64, 0);
    let mut storage = revm::primitives::HashMap::default();
    for tx in expiring.iter().take(MINED as usize) {
        let slot = tx
            .transaction
            .expiring_nonce_slot()
            .expect("expiring nonce tx has slot");
        storage.insert(slot, StorageSlot::new_changed(U256::ZERO, U256::from(1u64)));
    }
    let mut expiring_state = AddressMap::default();
    expiring_state.insert(
        NONCE_PRECOMPILE_ADDRESS,
        BundleAccount::new(None, None, storage, AccountStatus::Changed),
    );

    group.bench_function("expiring_mined", |b| {
        b.iter_batched_ref(
            || fill_pool(pool_config(CAPACITY * 2), &expiring),
            |pool| black_box(pool.on_state_updates(&expiring_state)),
            BatchSize::PerIteration,
        )
    });

    // 2D nonce transactions: advance the on-chain nonce of each key so that
    // MINED transactions across all keys are pruned at once.
    const PER_KEY: u64 = 4;
    let keys = CAPACITY as u64 / PER_KEY;
    let txs_2d = build_2d_txs(keys, PER_KEY, 0, 0);
    let mined_per_key = 2u64;
    let mut storage = revm::primitives::HashMap::default();
    for k in 0..(MINED / mined_per_key) {
        let slot = txs_2d[(k * PER_KEY) as usize]
            .transaction
            .nonce_key_slot()
            .expect("2d tx has nonce key slot");
        storage.insert(
            slot,
            StorageSlot::new_changed(U256::ZERO, U256::from(mined_per_key)),
        );
    }
    let mut state_2d = AddressMap::default();
    state_2d.insert(
        NONCE_PRECOMPILE_ADDRESS,
        BundleAccount::new(None, None, storage, AccountStatus::Changed),
    );

    group.bench_function("2d_mined", |b| {
        b.iter_batched_ref(
            || fill_pool(pool_config(CAPACITY * 2), &txs_2d),
            |pool| black_box(pool.on_state_updates(&state_2d)),
            BatchSize::PerIteration,
        )
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_add_at_capacity,
    bench_add_fill,
    bench_on_state_updates
);
criterion_main!(benches);
