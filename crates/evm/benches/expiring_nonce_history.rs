use alloy_primitives::{B256, map::B256HashSet};
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use tempo_evm::{
    ExpiringNonceBlock, ExpiringNonceBlockOverlay, ExpiringNonceEntry, ExpiringNonceHistory,
};

fn hash(value: u64) -> B256 {
    B256::left_padding_from(&value.to_be_bytes())
}

fn entries(start: u64, count: usize, valid_before: u64) -> Vec<ExpiringNonceEntry> {
    (0..count)
        .map(|offset| ExpiringNonceEntry {
            replay_id: hash(start + offset as u64),
            valid_before,
        })
        .collect()
}

fn block(
    hash: B256,
    parent_hash: B256,
    timestamp: u64,
    entries: Vec<ExpiringNonceEntry>,
) -> ExpiringNonceBlock {
    ExpiringNonceBlock {
        hash,
        parent_hash,
        timestamp,
        entries,
    }
}

fn bench_record_block(c: &mut Criterion) {
    let mut group = c.benchmark_group("expiring_nonce_history/record_block");
    for count in [1_000, 10_000] {
        group.throughput(Throughput::Elements(count));
        group.bench_function(count.to_string(), |b| {
            b.iter_batched(
                || {
                    (
                        ExpiringNonceHistory::new(300),
                        entries(1, count as usize, 301),
                    )
                },
                |(history, entries)| {
                    history.record_block(block(hash(1), B256::ZERO, 1, entries));
                    black_box(history);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_contains(c: &mut Criterion) {
    let history = ExpiringNonceHistory::new(300);
    let replay_id = hash(1);
    let mut parent = B256::ZERO;
    for number in 1..=300 {
        let block_hash = hash(number);
        let entries = if number == 1 {
            vec![ExpiringNonceEntry {
                replay_id,
                valid_before: 600,
            }]
        } else {
            Vec::new()
        };
        history.record_block(block(block_hash, parent, number, entries));
        parent = block_hash;
    }

    let mut group = c.benchmark_group("expiring_nonce_history/contains");
    group.bench_function("miss", |b| {
        b.iter(|| black_box(history.contains(parent, hash(10_000), 300).unwrap()))
    });
    group.bench_function("oldest_live_hit", |b| {
        b.iter(|| black_box(history.contains(parent, replay_id, 300).unwrap()))
    });
    group.finish();
}

fn bench_intra_block_dedup(c: &mut Criterion) {
    const ENTRY_COUNT: usize = 10_000;
    let replay_ids = (0..ENTRY_COUNT)
        .map(|index| hash(index as u64))
        .collect::<Vec<_>>();
    let mut group = c.benchmark_group("expiring_nonce_history/intra_block_dedup");
    group.throughput(Throughput::Elements(ENTRY_COUNT as u64));
    group.bench_function("10k", |b| {
        b.iter_batched(
            B256HashSet::default,
            |mut seen| {
                for replay_id in &replay_ids {
                    black_box(seen.insert(*replay_id));
                }
                black_box(seen);
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_block_overlay_handoff(c: &mut Criterion) {
    const ENTRY_COUNT: usize = 10_000;
    let entries = entries(1, ENTRY_COUNT, 300);

    let mut group = c.benchmark_group("expiring_nonce_history/block_overlay_handoff");
    group.throughput(Throughput::Elements(ENTRY_COUNT as u64));
    group.bench_function("10k", |b| {
        b.iter_batched(
            || (ExpiringNonceBlockOverlay::default(), entries.clone()),
            |(overlay, entries)| {
                overlay.bench_publish(entries);
                black_box(overlay.bench_take());
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_prune(c: &mut Criterion) {
    const ENTRY_COUNT: usize = 10_000;
    let mut group = c.benchmark_group("expiring_nonce_history/prune");
    group.throughput(Throughput::Elements(ENTRY_COUNT as u64));
    group.bench_function("10k", |b| {
        b.iter_batched(
            || {
                let history = ExpiringNonceHistory::new(10);
                history.record_block(block(hash(1), B256::ZERO, 1, entries(1, ENTRY_COUNT, 11)));
                let mut parent = hash(1);
                for timestamp in 2..=21 {
                    let block_hash = hash(timestamp);
                    history.record_block(block(block_hash, parent, timestamp, Vec::new()));
                    parent = block_hash;
                }
                (history, parent)
            },
            |(history, parent)| {
                history.record_block(block(hash(22), parent, 22, Vec::new()));
                black_box(history);
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_record_block,
    bench_contains,
    bench_intra_block_dedup,
    bench_block_overlay_handoff,
    bench_prune
);
criterion_main!(benches);
