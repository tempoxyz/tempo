use alloy_primitives::{B256, U256, keccak256};
use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use rand::{SeedableRng, rngs::StdRng};
use rand_distr::{Distribution, Zipf};
use reth_primitives_traits::Account;
use reth_qmdb::{QmdbBlock, QmdbConfig, QmdbHead, QmdbState};
use reth_trie_common::{HashedPostState, HashedStorage};
use std::{
    env,
    time::{Duration, Instant},
};
use tempfile::TempDir;
use tempo_node::qmdb::QmdbOverlayArena;

const ACCOUNT_COUNT: usize = 1_024;
const TRANSFERS_PER_BLOCK: usize = 200;
const BLOCK_COUNT: usize = 16;
const ZIPF_EXPONENT: f64 = 1.4;
const GENESIS_HASH: B256 = B256::ZERO;
const ROOT_WAIT_GATE_ENV: &str = "TEMPO_QMDB_ROOT_WAIT_P95_MAX_MS";
const ROOT_WAIT_GATE_SAMPLES: usize = 64;

#[derive(Clone)]
struct SyntheticBlock {
    block: QmdbBlock,
    hashed_state: HashedPostState,
}

fn hash_index(domain: u8, value: u64) -> B256 {
    let mut input = [0u8; 9];
    input[0] = domain;
    input[1..].copy_from_slice(&value.to_be_bytes());
    keccak256(input)
}

fn zipf_index(zipf: Zipf<f64>, rng: &mut StdRng) -> usize {
    zipf.sample(rng) as usize - 1
}

fn tip20_shape_workload() -> Vec<SyntheticBlock> {
    let token = hash_index(0, 0);
    let token_code_hash = hash_index(0, 1);
    let slots: Vec<_> = (0..ACCOUNT_COUNT)
        .map(|index| hash_index(1, index as u64))
        .collect();
    let mut balances = vec![1_000_000u64; ACCOUNT_COUNT];
    let zipf = Zipf::new(ACCOUNT_COUNT as f64, ZIPF_EXPONENT).expect("valid Zipf distribution");
    let mut rng = StdRng::seed_from_u64(0x5449503230);
    let mut parent_hash = GENESIS_HASH;

    (1..=BLOCK_COUNT)
        .map(|number| {
            let number = number as u64;
            let mut storage_updates = Vec::with_capacity(TRANSFERS_PER_BLOCK * 2);
            for _ in 0..TRANSFERS_PER_BLOCK {
                let sender = zipf_index(zipf, &mut rng);
                let mut recipient = zipf_index(zipf, &mut rng);
                if sender == recipient {
                    recipient = (recipient + 1) % ACCOUNT_COUNT;
                }

                balances[sender] = balances[sender].saturating_sub(1);
                balances[recipient] = balances[recipient].saturating_add(1);
                storage_updates.push((slots[sender], U256::from(balances[sender])));
                storage_updates.push((slots[recipient], U256::from(balances[recipient])));
            }

            let mut hashed_state = HashedPostState::default();
            hashed_state.accounts.insert(
                token,
                Some(Account {
                    nonce: 0,
                    balance: U256::ZERO,
                    bytecode_hash: Some(token_code_hash),
                }),
            );
            hashed_state
                .storages
                .insert(token, HashedStorage::from_iter(false, storage_updates));

            let hash = hash_index(9, number);
            let block = QmdbBlock {
                number,
                hash,
                parent_hash,
            };
            parent_hash = hash;

            SyntheticBlock {
                block,
                hashed_state,
            }
        })
        .collect()
}

fn open_qmdb(prefix: &str) -> (TempDir, QmdbState, QmdbHead) {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let qmdb = QmdbState::open(
        QmdbConfig::new(tempdir.path())
            .with_partition_prefix(prefix)
            .with_worker_threads(2),
    )
    .expect("QMDB should open");
    let head = qmdb
        .commit_block(
            QmdbBlock {
                number: 0,
                hash: GENESIS_HASH,
                parent_hash: B256::ZERO,
            },
            HashedPostState::default(),
        )
        .expect("genesis should commit");
    (tempdir, qmdb, head)
}

fn percentile_duration(samples: &mut [Duration], percentile: usize) -> Duration {
    samples.sort_unstable();
    let index = (samples.len() * percentile).div_ceil(100).saturating_sub(1);
    samples[index]
}

fn validate_optional_root_wait_gate(
    qmdb: &QmdbState,
    head: QmdbHead,
    hashed_state: &HashedPostState,
) {
    let Ok(limit_ms) = env::var(ROOT_WAIT_GATE_ENV) else {
        return;
    };
    let limit_ms = limit_ms
        .parse::<f64>()
        .expect("TEMPO_QMDB_ROOT_WAIT_P95_MAX_MS must be a floating-point millisecond value");
    let limit = Duration::from_secs_f64(limit_ms / 1000.0);
    let mut samples = Vec::with_capacity(ROOT_WAIT_GATE_SAMPLES);

    for _ in 0..ROOT_WAIT_GATE_SAMPLES {
        let mut arena = QmdbOverlayArena::new(head);
        arena.extend_hashed_state(hashed_state);
        arena
            .prefetch_base_values(qmdb)
            .expect("base values should prefetch for root wait gate");
        let started = Instant::now();
        let commit = arena
            .compute_root_fast_commit(qmdb)
            .expect("fast root should compute for root wait gate")
            .expect("TIP20-shaped root wait gate should use flat mutations");
        black_box(commit);
        samples.push(started.elapsed());
    }

    let p95 = percentile_duration(&mut samples, 95);
    assert!(
        p95 <= limit,
        "QMDB final root wait p95 exceeded gate: p95={:.3}ms limit={:.3}ms samples={}",
        p95.as_secs_f64() * 1000.0,
        limit_ms,
        ROOT_WAIT_GATE_SAMPLES
    );
}

fn validate_qmdb_root_workload(workload: &[SyntheticBlock]) {
    let (_tempdir, qmdb, mut head) = open_qmdb("qmdb-root-validation");
    let mut committed_heads = vec![head];

    validate_optional_root_wait_gate(&qmdb, head, &workload[0].hashed_state);

    for synthetic in workload {
        assert_eq!(synthetic.block.number, head.number + 1);
        assert_eq!(synthetic.block.parent_hash, head.hash);

        let expected_header_root = qmdb
            .overlay_root(synthetic.hashed_state.clone())
            .expect("current QMDB overlay root should compute");

        let mut arena = QmdbOverlayArena::new(head);
        arena.extend_hashed_state(&synthetic.hashed_state);
        let arena_commit = arena
            .compute_root(&qmdb)
            .expect("arena root should compute");
        assert_eq!(
            arena_commit.root, expected_header_root.root,
            "arena root diverged from QMDB overlay root at block {}",
            synthetic.block.number
        );

        let mut fast_arena = QmdbOverlayArena::new(head);
        fast_arena.extend_hashed_state(&synthetic.hashed_state);
        let (fast_commit, fast_mutations) = fast_arena
            .compute_root_fast_commit(&qmdb)
            .expect("fast arena root should compute")
            .expect("TIP20-shaped workload should stay on flat-mutation path");
        assert_eq!(
            fast_commit.root, expected_header_root.root,
            "fast arena root diverged from QMDB overlay root at block {}",
            synthetic.block.number
        );
        assert_eq!(
            fast_mutations.len(),
            expected_header_root.entries,
            "fast arena mutation count diverged from QMDB overlay entries at block {}",
            synthetic.block.number
        );

        let committed = qmdb
            .commit_block(synthetic.block, synthetic.hashed_state.clone())
            .expect("block should commit to QMDB");
        assert_eq!(
            committed.root, expected_header_root.root,
            "committed QMDB head root must match the block header state root at block {}",
            synthetic.block.number
        );
        assert_eq!(
            qmdb.root().expect("QMDB root should be readable"),
            committed.root
        );
        assert_eq!(
            qmdb.head().expect("QMDB head should be readable"),
            Some(committed)
        );

        head = committed;
        committed_heads.push(head);
    }

    let final_head = head;
    let rewind_index = workload.len() / 2;
    let rewind_head = committed_heads[rewind_index];
    let rewound = qmdb
        .rewind_to_block(rewind_head.number)
        .expect("QMDB rewind should succeed")
        .expect("rewound head should exist");
    assert_eq!(rewound, rewind_head);
    assert_eq!(
        qmdb.root().expect("QMDB root should be readable"),
        rewind_head.root
    );
    assert_eq!(
        qmdb.head().expect("QMDB head should be readable"),
        Some(rewind_head)
    );

    let replay_blocks = workload[rewind_index..]
        .iter()
        .map(|synthetic| (synthetic.block, synthetic.hashed_state.clone()))
        .collect();
    let replayed = qmdb
        .commit_blocks(replay_blocks)
        .expect("QMDB replay commit should succeed")
        .expect("replayed head should exist");
    assert_eq!(
        replayed, final_head,
        "reorg/rewind replay must return the original final root"
    );
    assert_eq!(
        qmdb.root().expect("QMDB root should be readable"),
        final_head.root
    );
}

fn bench_qmdb_root(c: &mut Criterion) {
    let workload = tip20_shape_workload();
    validate_qmdb_root_workload(&workload);

    let first_block = workload[0].hashed_state.clone();
    let (_tempdir, qmdb, head) = open_qmdb("qmdb-root-bench");

    let mut group = c.benchmark_group("qmdb_root_tip20_shape");
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("current_overlay_root", |b| {
        b.iter_batched(
            || first_block.clone(),
            |hashed_state| black_box(qmdb.overlay_root(black_box(hashed_state)).unwrap()),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("arena_total_work", |b| {
        b.iter_batched(
            || first_block.clone(),
            |hashed_state| {
                let mut arena = QmdbOverlayArena::new(head);
                arena.extend_hashed_state(&hashed_state);
                black_box(arena.compute_root(&qmdb).unwrap())
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("arena_fast_total_work", |b| {
        b.iter_batched(
            || first_block.clone(),
            |hashed_state| {
                let mut arena = QmdbOverlayArena::new(head);
                arena.extend_hashed_state(&hashed_state);
                black_box(arena.compute_root_fast(&qmdb).unwrap().unwrap())
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("arena_final_wait_after_streaming", |b| {
        b.iter_batched(
            || {
                let mut arena = QmdbOverlayArena::new(head);
                arena.extend_hashed_state(&first_block);
                arena
            },
            |arena| black_box(arena.compute_root(&qmdb).unwrap()),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("arena_fast_final_wait_after_streaming", |b| {
        b.iter_batched(
            || {
                let mut arena = QmdbOverlayArena::new(head);
                arena.extend_hashed_state(&first_block);
                arena
            },
            |mut arena| black_box(arena.compute_root_fast(&qmdb).unwrap().unwrap()),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("commit_blocks", |b| {
        b.iter_batched(
            || {
                let (tempdir, qmdb, _) = open_qmdb("qmdb-root-commit-bench");
                let blocks = workload
                    .iter()
                    .map(|block| (block.block, block.hashed_state.clone()))
                    .collect::<Vec<_>>();
                (tempdir, qmdb, blocks)
            },
            |(_tempdir, qmdb, blocks)| black_box(qmdb.commit_blocks(blocks).unwrap()),
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_qmdb_root);
criterion_main!(benches);
