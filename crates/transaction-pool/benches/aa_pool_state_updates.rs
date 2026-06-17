use alloy_consensus::Transaction;
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{
    Address, Bytes, Signature, TxKind, U256,
    map::{AddressMap, HashMap},
};
use core::num::NonZeroU64;
use criterion::{
    BatchSize, BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main,
};
use reth_primitives_traits::Recovered;
use reth_transaction_pool::{
    PriceBumpConfig, SubPoolLimit, TransactionOrigin, ValidPoolTransaction,
    identifier::TransactionId,
};
use revm::database::{AccountStatus, BundleAccount, states::StorageSlot};
use std::{sync::Arc, time::Duration};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::NONCE_PRECOMPILE_ADDRESS;
use tempo_primitives::{
    TempoTxEnvelope,
    transaction::{
        TempoTransaction,
        tempo_transaction::Call,
        tt_signature::{PrimitiveSignature, TempoSignature},
        tt_signed::AASigned,
    },
};
use tempo_transaction_pool::{AA2dPool, AA2dPoolConfig, transaction::TempoPooledTransaction};

#[derive(Clone)]
struct ExpiringNonceFixture {
    transactions: Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    state: AddressMap<BundleAccount>,
}

impl ExpiringNonceFixture {
    fn new(pool_size: usize, update_count: usize) -> Self {
        assert!(update_count <= pool_size);

        let transactions = (0..pool_size)
            .map(|idx| {
                let tx = expiring_nonce_transaction(idx);
                Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local))
            })
            .collect::<Vec<_>>();

        let mut storage = HashMap::default();
        for tx in transactions.iter().take(update_count) {
            let slot = tx
                .transaction
                .expiring_nonce_slot()
                .expect("expiring nonce tx has a storage slot");
            storage.insert(
                slot,
                StorageSlot::new_changed(U256::ZERO, U256::from(123u64)),
            );
        }

        let mut state = AddressMap::default();
        state.insert(
            NONCE_PRECOMPILE_ADDRESS,
            BundleAccount::new(None, None, storage, AccountStatus::Changed),
        );

        Self {
            transactions,
            state,
        }
    }

    fn pool(&self) -> AA2dPool {
        let mut pool = AA2dPool::new(AA2dPoolConfig {
            price_bump_config: PriceBumpConfig::default(),
            pending_limit: SubPoolLimit {
                max_txs: self.transactions.len(),
                max_size: usize::MAX,
            },
            queued_limit: SubPoolLimit {
                max_txs: self.transactions.len(),
                max_size: usize::MAX,
            },
            max_txs_per_sender: self.transactions.len(),
        });

        for tx in &self.transactions {
            pool.add_transaction_for_test(Arc::clone(tx), 0, TempoHardfork::T1)
                .expect("benchmark tx inserts into pool");
        }

        pool
    }

    fn pool_after_state_updates(&self) -> AA2dPool {
        let mut pool = self.pool();
        let (promoted, mined) = pool.on_state_updates_for_test(&self.state);
        assert!(promoted.is_empty());
        assert!(!mined.is_empty());
        pool
    }
}

fn expiring_nonce_transaction(idx: usize) -> TempoPooledTransaction {
    let sender = address(idx + 1);
    let call_to = address(idx + 1_000_001);
    let fee_token = address(idx + 2_000_001);
    let valid_before = NonZeroU64::new(120 + (idx % 30) as u64).unwrap();

    let tx = TempoTransaction {
        chain_id: 42431,
        max_priority_fee_per_gas: 1_000_000_000 + idx as u128,
        max_fee_per_gas: 20_000_000_000 + idx as u128,
        gas_limit: 1_000_000,
        calls: vec![Call {
            to: TxKind::Call(call_to),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: U256::MAX,
        nonce: 0,
        fee_token: Some(fee_token),
        fee_payer_signature: None,
        valid_after: None,
        valid_before: Some(valid_before),
        access_list: AccessList::default(),
        tempo_authorization_list: Vec::new(),
        key_authorization: None,
    };

    let signature =
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));
    let aa_signed = AASigned::new_unhashed(tx, signature);
    let envelope: TempoTxEnvelope = aa_signed.into();
    TempoPooledTransaction::new(Recovered::new_unchecked(envelope, sender))
}

fn address(idx: usize) -> Address {
    let mut bytes = [0u8; 20];
    bytes[12..].copy_from_slice(&(idx as u64).to_be_bytes());
    Address::from(bytes)
}

fn wrap_valid_tx(
    tx: TempoPooledTransaction,
    origin: TransactionOrigin,
) -> ValidPoolTransaction<TempoPooledTransaction> {
    let tx_id = TransactionId::new(0u64.into(), tx.nonce());
    ValidPoolTransaction {
        transaction: tx,
        transaction_id: tx_id,
        propagate: true,
        timestamp: std::time::Instant::now(),
        origin,
        authority_ids: None,
    }
}

fn notify_aa_pool_on_expiring_nonce_updates(c: &mut Criterion) {
    let mut group = c.benchmark_group("aa_pool_state_updates/expiring_nonce_inclusions");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    for (pool_size, update_count) in [
        (10_000, 10_000),
        (15_000, 15_000),
        (50_000, 10_000),
        (50_000, 15_000),
    ] {
        let fixture = ExpiringNonceFixture::new(pool_size, update_count);
        let id = BenchmarkId::from_parameter(format!("pool_{pool_size}_updates_{update_count}"));
        group.throughput(Throughput::Elements(update_count as u64));
        group.bench_with_input(id, &fixture, |b, fixture| {
            b.iter_batched(
                || fixture.pool(),
                |mut pool| {
                    let (promoted, mined) =
                        pool.on_state_updates_for_test(black_box(&fixture.state));
                    black_box((promoted.len(), mined.len()));
                    (pool, promoted, mined)
                },
                BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

fn best_transactions_after_expiring_nonce_updates(c: &mut Criterion) {
    let mut group = c.benchmark_group("aa_pool_best_transactions/after_expiring_nonce_inclusions");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    for (pool_size, update_count) in [
        (10_000, 10_000),
        (15_000, 15_000),
        (50_000, 10_000),
        (50_000, 15_000),
    ] {
        let fixture = ExpiringNonceFixture::new(pool_size, update_count);
        let id = BenchmarkId::from_parameter(format!("pool_{pool_size}_updates_{update_count}"));
        let remaining = pool_size - update_count;
        group.throughput(Throughput::Elements(remaining.max(1) as u64));
        group.bench_with_input(id, &fixture, |b, fixture| {
            b.iter_batched_ref(
                || fixture.pool_after_state_updates(),
                |pool| black_box(pool.best_transactions_snapshot_len_for_test()),
                BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    notify_aa_pool_on_expiring_nonce_updates,
    best_transactions_after_expiring_nonce_updates
);
criterion_main!(benches);
