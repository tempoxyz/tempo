//! Benchmark-only parallel recovery and calldata-driven snapshot prefetch.
//! Run with TEMPO_PAYMENT_PIPELINE_BENCH=1. Synthetic latency is per backend read;
//! it is not a measurement of RocksDB, trie traversal, or production disk latency.
use super::{common, *};
use alloy_primitives::{
    B256,
    map::{HashMap, HashSet},
};
use evm2::{
    bytecode::Bytecode,
    evm::{AccountInfo, Cache, DbResult, DynDatabase},
};
use rayon::prelude::*;
use std::{
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tempo_precompiles::{
    NONCE_PRECOMPILE_ADDRESS, STORAGE_CREDITS_ADDRESS, TIP403_REGISTRY_ADDRESS,
    storage::StorageKey,
    storage_credits::StorageCredits,
    tip_fee_manager::{TIP_FEE_MANAGER_ADDRESS, slots as fee_slots},
    tip20::{rewards::__packing_user_reward_info as reward_slots, slots as token_slots},
    tip403_registry::slots as policy_slots,
};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum Key {
    Account(Address),
    Code(B256),
    Storage(Address, U256),
    BlockHash(U256),
}
#[derive(Clone)]
enum Value {
    Account(Option<AccountInfo>),
    Code(Bytecode),
    Word(U256),
    Hash(B256),
}

fn read_snapshot(parent: &Cache, key: Key, delay: Duration) -> Value {
    if !delay.is_zero() {
        std::thread::sleep(delay);
    }
    match key {
        Key::Account(a) => Value::Account(parent.accounts.get(&a).cloned().flatten()),
        Key::Code(h) => Value::Code(parent.contracts.get(&h).cloned().unwrap_or_default()),
        Key::Storage(a, k) => Value::Word(
            parent
                .storage
                .get(&a)
                .and_then(|s| s.slots.get(&k))
                .copied()
                .unwrap_or_default(),
        ),
        Key::BlockHash(n) => Value::Hash(parent.block_hashes.get(&n).copied().unwrap_or_default()),
    }
}

struct Snapshot {
    cache: Cache,
    spec: TempoHardfork,
}

#[derive(Default)]
struct Counts {
    hits: AtomicUsize,
    misses: AtomicUsize,
}
struct SnapshotDB {
    parent: Arc<Snapshot>,
    prefetched: HashMap<Key, Value>,
    delay: Duration,
    counts: Arc<Counts>,
    trace: Option<Arc<Mutex<HashSet<Key>>>>,
}
impl SnapshotDB {
    fn read(&self, key: Key) -> Value {
        if let Some(trace) = &self.trace {
            trace.lock().unwrap().insert(key);
        }
        if let Some(value) = self.prefetched.get(&key) {
            self.counts.hits.fetch_add(1, Ordering::Relaxed);
            value.clone()
        } else {
            self.counts.misses.fetch_add(1, Ordering::Relaxed);
            read_snapshot(&self.parent.cache, key, self.delay)
        }
    }
}
impl DynDatabase for SnapshotDB {
    fn get_account(&mut self, a: &Address) -> DbResult<Option<AccountInfo>> {
        let Value::Account(v) = self.read(Key::Account(*a)) else {
            unreachable!()
        };
        Ok(v)
    }
    fn get_code_by_hash(&mut self, h: &B256) -> DbResult<Bytecode> {
        let Value::Code(v) = self.read(Key::Code(*h)) else {
            unreachable!()
        };
        Ok(v)
    }
    fn get_storage(&mut self, a: &Address, k: &U256) -> DbResult<U256> {
        let Value::Word(v) = self.read(Key::Storage(*a, *k)) else {
            unreachable!()
        };
        Ok(v)
    }
    fn get_block_hash(&mut self, n: &U256) -> DbResult<B256> {
        let Value::Hash(v) = self.read(Key::BlockHash(*n)) else {
            unreachable!()
        };
        Ok(v)
    }
}

struct Prepared {
    tx: Recovered<TempoTxEnvelope>,
    keys: Vec<Key>,
    holders: Vec<Address>,
    expiring: bool,
}
fn reward_keys(keys: &mut Vec<Key>, holder: Address) {
    let base = holder.mapping_slot(token_slots::USER_REWARD_INFO);
    for offset in [
        reward_slots::REWARD_RECIPIENT,
        reward_slots::REWARD_PER_TOKEN,
        reward_slots::REWARD_BALANCE,
    ] {
        keys.push(Key::Storage(PATH_USD_ADDRESS, base + offset));
    }
}
fn prepare(
    tx: &TempoTxEnvelope,
    signer: Option<Address>,
    predict: bool,
    spec: TempoHardfork,
) -> Prepared {
    // These inputs are signed envelopes, not recovered transactions. This performs
    // real ECDSA recovery in both the serial and parallel verification variants.
    let signer = signer.unwrap_or_else(|| tx.recover_signer().expect("valid signature"));
    let aa = tx.as_aa().expect("AA workload");
    let inner = aa.tx();
    assert!(inner.key_authorization.is_none());
    assert_eq!(inner.fee_token, Some(PATH_USD_ADDRESS));
    assert!(inner.fee_payer_signature.is_none());
    let mut keys = vec![];
    let mut holders = vec![];
    for call in &inner.calls {
        let decoded = ITIP20::transferCall::abi_decode(&call.input).expect("transfer workload");
        assert_eq!(call.to.to(), Some(&PATH_USD_ADDRESS));
        if predict {
            if !spec.is_t8() {
                holders.extend([signer, decoded.to]);
            }
            for holder in [signer, decoded.to, TIP_FEE_MANAGER_ADDRESS] {
                keys.push(Key::Storage(
                    PATH_USD_ADDRESS,
                    holder.mapping_slot(token_slots::BALANCES),
                ));
                if !spec.is_t8() {
                    reward_keys(&mut keys, holder);
                }
            }
            let policy = decoded.to.mapping_slot(policy_slots::RECEIVE_POLICIES);
            keys.push(Key::Storage(TIP403_REGISTRY_ADDRESS, policy));
            // Optional recovery-policy fields remain on-demand misses.
        }
    }
    let expiring = inner.nonce_key == tempo_primitives::transaction::TEMPO_EXPIRING_NONCE_KEY;
    if predict {
        for address in [
            signer,
            PATH_USD_ADDRESS,
            TIP_FEE_MANAGER_ADDRESS,
            NONCE_PRECOMPILE_ADDRESS,
            TIP403_REGISTRY_ADDRESS,
            STORAGE_CREDITS_ADDRESS,
            Address::repeat_byte(0x42),
        ] {
            keys.push(Key::Account(address));
        }
        for slot in [
            token_slots::CURRENCY,
            token_slots::PAUSED,
            token_slots::TRANSFER_POLICY_ID,
        ] {
            keys.push(Key::Storage(PATH_USD_ADDRESS, slot));
        }
        if !spec.is_t8() {
            for slot in [
                token_slots::GLOBAL_REWARD_PER_TOKEN,
                token_slots::OPTED_IN_SUPPLY,
            ] {
                keys.push(Key::Storage(PATH_USD_ADDRESS, slot));
            }
        }
        if spec.is_t14() {
            keys.push(Key::Storage(
                TIP403_REGISTRY_ADDRESS,
                PATH_USD_ADDRESS.mapping_slot(policy_slots::TOKEN_TRANSFER_POLICIES),
            ));
        }
        keys.push(Key::Storage(
            STORAGE_CREDITS_ADDRESS,
            StorageCredits::slot(PATH_USD_ADDRESS),
        ));
        let beneficiary = Address::repeat_byte(0x42);
        keys.push(Key::Storage(
            TIP_FEE_MANAGER_ADDRESS,
            beneficiary.mapping_slot(fee_slots::VALIDATOR_TOKENS),
        ));
        keys.push(Key::Storage(
            TIP_FEE_MANAGER_ADDRESS,
            PATH_USD_ADDRESS.mapping_slot(beneficiary.mapping_slot(fee_slots::COLLECTED_FEES)),
        ));
        if expiring {
            keys.push(Key::Storage(
                NONCE_PRECOMPILE_ADDRESS,
                aa.expiring_nonce_hash(signer)
                    .mapping_slot(tempo_precompiles::nonce::slots::EXPIRING_NONCE_SEEN),
            ));
            keys.push(Key::Storage(
                NONCE_PRECOMPILE_ADDRESS,
                tempo_precompiles::nonce::slots::EXPIRING_NONCE_RING_PTR,
            ));
        } else if !inner.nonce_key.is_zero() {
            keys.push(Key::Storage(
                NONCE_PRECOMPILE_ADDRESS,
                inner
                    .nonce_key
                    .mapping_slot(signer.mapping_slot(tempo_precompiles::nonce::slots::NONCES)),
            ));
        }
    }
    Prepared {
        tx: Recovered::new_unchecked(tx.clone(), signer),
        keys,
        holders,
        expiring,
    }
}

fn prefetch(
    pool: &rayon::ThreadPool,
    parent: &Snapshot,
    prepared: &[Prepared],
    delay: Duration,
) -> HashMap<Key, Value> {
    let keys: HashSet<_> = prepared
        .iter()
        .flat_map(|p| p.keys.iter().copied())
        .collect();
    let mut loaded: HashMap<_, _> = pool.install(|| {
        keys.into_par_iter()
            .map(|k| (k, read_snapshot(&parent.cache, k, delay)))
            .collect()
    });
    let mut more: HashSet<Key> = HashSet::default();
    for value in loaded.values() {
        if let Value::Account(Some(info)) = value {
            more.insert(Key::Code(info.code_hash));
        }
    }
    // Expand reward delegates from the first batch of parent-state reads.
    for holder in prepared.iter().flat_map(|p| p.holders.iter().copied()) {
        let key = Key::Storage(
            PATH_USD_ADDRESS,
            holder.mapping_slot(token_slots::USER_REWARD_INFO) + reward_slots::REWARD_RECIPIENT,
        );
        if let Some(Value::Word(word)) = loaded.get(&key) {
            let delegate = Address::from_word(B256::from(word.to_be_bytes::<32>()));
            if !delegate.is_zero() {
                let mut delegate_keys = vec![];
                reward_keys(&mut delegate_keys, delegate);
                more.extend(delegate_keys);
            }
        }
    }
    // Provisional coordinator offsets are hints: invalid preceding transactions
    // can change the actual ring index, in which case execution loads on demand.
    let ptr_key = Key::Storage(
        NONCE_PRECOMPILE_ADDRESS,
        tempo_precompiles::nonce::slots::EXPIRING_NONCE_RING_PTR,
    );
    if let Some(Value::Word(ptr)) = loaded.get(&ptr_key) {
        let nonce = NonceManager::new();
        let capacity = parent.spec.expiring_nonce_set_capacity();
        let start = ptr.to::<u32>();
        for offset in 0..prepared.iter().filter(|p| p.expiring).count() as u32 {
            more.insert(Key::Storage(
                NONCE_PRECOMPILE_ADDRESS,
                nonce.expiring_nonce_ring[(start + offset) % capacity].slot(),
            ));
        }
    }
    more.retain(|k| !loaded.contains_key(k));
    let expanded: Vec<_> = pool.install(|| {
        more.into_par_iter()
            .map(|k| (k, read_snapshot(&parent.cache, k, delay)))
            .collect()
    });
    loaded.extend(expanded);
    loaded
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Recovered,
    SerialVerify,
    ParallelVerify,
    PrefetchRecovered,
    ParallelPrefetch,
}
struct Timing {
    prep: f64,
    fetch: f64,
    execute: f64,
    total: f64,
    fetched: usize,
    hits: usize,
    misses: usize,
}
fn execute(
    config: &TempoEvmConfig,
    parent: Arc<Snapshot>,
    loaded: HashMap<Key, Value>,
    txs: &[Recovered<TempoTxEnvelope>],
    timestamp: u64,
    delay: Duration,
    trace: Option<Arc<Mutex<HashSet<Key>>>>,
) -> (common::ExecutionStats, Cache, Arc<Counts>) {
    let counts = Arc::new(Counts::default());
    let db = SnapshotDB {
        parent: parent.clone(),
        prefetched: loaded,
        delay,
        counts: counts.clone(),
        trace,
    };
    let (stats, cache) = common::execute_txs_inspecting_cache(
        config,
        db,
        txs,
        timestamp,
        parent.spec,
        true,
        Clone::clone,
    );
    (stats, cache, counts)
}
fn measure(
    pool: &rayon::ThreadPool,
    config: &TempoEvmConfig,
    parent: Arc<Snapshot>,
    workload: &Workload,
    mode: Mode,
    delay: Duration,
    capture: bool,
) -> (Timing, common::ExecutionStats, Option<Cache>) {
    let counts = Arc::new(Counts::default());
    let started = Instant::now();
    let predict = matches!(mode, Mode::ParallelPrefetch | Mode::PrefetchRecovered);
    let prepared = match mode {
        Mode::Recovered => Vec::new(),
        Mode::SerialVerify => workload
            .transactions
            .iter()
            .map(|tx| prepare(tx.inner(), None, false, parent.spec))
            .collect(),
        _ => pool.install(|| {
            workload
                .transactions
                .par_iter()
                .map(|tx| {
                    prepare(
                        tx.inner(),
                        matches!(mode, Mode::PrefetchRecovered).then_some(tx.signer()),
                        predict,
                        parent.spec,
                    )
                })
                .collect()
        }),
    };
    let txs = if prepared.is_empty() {
        workload.transactions.clone()
    } else {
        prepared.iter().map(|p| p.tx.clone()).collect()
    };
    let prep = started.elapsed().as_secs_f64() * 1000.;
    let fetch_started = Instant::now();
    let loaded = if predict {
        prefetch(pool, &parent, &prepared, delay)
    } else {
        HashMap::default()
    };
    let fetched = loaded.len();
    let fetch = fetch_started.elapsed().as_secs_f64() * 1000.;
    let db = SnapshotDB {
        parent: parent.clone(),
        prefetched: loaded,
        delay,
        counts: counts.clone(),
        trace: None,
    };
    let exec_started = Instant::now();
    let (stats, cache) = common::execute_txs_inspecting_cache(
        config,
        db,
        &txs,
        workload.block_timestamp,
        parent.spec,
        true,
        |cache| capture.then(|| cache.clone()),
    );
    let execute = exec_started.elapsed().as_secs_f64() * 1000.;
    drop(prepared);
    drop(txs);
    (
        Timing {
            prep,
            fetch,
            execute,
            total: started.elapsed().as_secs_f64() * 1000.,
            fetched,
            hits: counts.hits.load(Ordering::Relaxed),
            misses: counts.misses.load(Ordering::Relaxed),
        },
        stats,
        cache,
    )
}

pub(super) fn run() {
    let workers = std::env::var("TEMPO_PREFETCH_WORKERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    let repeats = std::env::var("TEMPO_PREFETCH_REPEATS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5usize);
    assert!(repeats > 0);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()
        .unwrap();
    let workload = super::generated_workload();
    let config = TempoEvmConfig::new(Arc::new(TempoChainSpec::moderato()));
    println!(
        "PIPELINE_BENCH workers={workers} transactions={} repeats={repeats} hardforks=T14,T6",
        workload.transactions.len()
    );
    let calibration = Instant::now();
    for _ in 0..100 {
        std::thread::sleep(Duration::from_micros(50));
    }
    println!(
        "LATENCY_MODEL requested_sleep_us=50 measured_sleep_us={:.2}",
        calibration.elapsed().as_secs_f64() * 1_000_000. / 100.
    );
    println!(
        "workload,fork,latency_us,mode,prep_ms,prefetch_ms,execute_ms,total_ms,min_ms,max_ms,prefetched_keys,cache_hits,backend_reads"
    );
    for delegated in [false, true] {
        let name = if delegated {
            "delegated_rewards"
        } else {
            "plain"
        };
        if std::env::var("TEMPO_PREFETCH_WORKLOAD").is_ok_and(|selected| selected != name) {
            continue;
        }
        let delegates = [Address::repeat_byte(0x99)];
        let reward = delegated.then_some((
            &delegates[..],
            RewardBenchKind::Transfer {
                sender: RewardSeedMode::SharedDelegate,
                recipient: RewardSeedMode::SharedDelegate,
                reward_delta: true,
            },
        ));
        let spec = if delegated {
            // New reward registration/distribution is disabled at T7; update
            // accounting is disabled at T8. Use the fully active T6 fixture.
            TempoHardfork::T6
        } else {
            TempoHardfork::T14
        };
        let parent = Arc::new(Snapshot {
            spec,
            cache: seed_in_memory_cache_db(
                &workload.participants,
                workload.block_timestamp,
                reward,
                spec,
            )
            .cache,
        });
        let name = if delegated {
            "delegated_rewards"
        } else {
            "plain"
        };
        // Capture the actual read set only for reporting prediction coverage; it
        // never becomes the prefetch plan or supplies prefetched values.
        let trace = Arc::new(Mutex::new(HashSet::default()));
        let (baseline_stats, baseline_cache, _) = execute(
            &config,
            parent.clone(),
            HashMap::default(),
            &workload.transactions,
            workload.block_timestamp,
            Duration::ZERO,
            Some(trace.clone()),
        );
        let (trial, stats, cache) = measure(
            &pool,
            &config,
            parent.clone(),
            &workload,
            Mode::ParallelPrefetch,
            Duration::ZERO,
            true,
        );
        assert_eq!(stats.gas_used, baseline_stats.gas_used);
        assert_eq!(stats.txs, baseline_stats.txs);
        assert_eq!(
            cache.as_ref(),
            Some(&baseline_cache),
            "prefetch must preserve all final state, including sequential writes"
        );
        if delegated {
            let delegate_balance = delegates[0].mapping_slot(token_slots::USER_REWARD_INFO)
                + reward_slots::REWARD_BALANCE;
            assert!(
                baseline_cache.storage[&PATH_USD_ADDRESS].slots[&delegate_balance] > U256::ZERO,
                "the historical reward workload must actually accrue delegated rewards"
            );
        }
        let (_, recovered_stats, recovered_cache) = measure(
            &pool,
            &config,
            parent.clone(),
            &workload,
            Mode::PrefetchRecovered,
            Duration::ZERO,
            true,
        );
        assert_eq!(recovered_stats.gas_used, baseline_stats.gas_used);
        assert_eq!(recovered_cache.as_ref(), Some(&baseline_cache));
        let actual = trace.lock().unwrap();
        println!(
            "PARITY {name}: state/gas/count match; actual_unique_reads={} predicted={} hits={} misses={}",
            actual.len(),
            trial.fetched,
            trial.hits,
            trial.misses
        );
        drop(actual);
        for latency_us in [0, 50] {
            for mode in [
                Mode::Recovered,
                Mode::SerialVerify,
                Mode::ParallelVerify,
                Mode::PrefetchRecovered,
                Mode::ParallelPrefetch,
            ] {
                // One untimed warmup for every variant.
                measure(
                    &pool,
                    &config,
                    parent.clone(),
                    &workload,
                    mode,
                    Duration::from_micros(latency_us),
                    false,
                );
                let mut timings = Vec::new();
                for _ in 0..repeats {
                    let (timing, stats, _) = measure(
                        &pool,
                        &config,
                        parent.clone(),
                        &workload,
                        mode,
                        Duration::from_micros(latency_us),
                        false,
                    );
                    assert_eq!(stats.gas_used, baseline_stats.gas_used);
                    assert_eq!(stats.txs, baseline_stats.txs);
                    timings.push(timing);
                }
                timings.sort_by(|a, b| a.total.total_cmp(&b.total));
                let t = &timings[timings.len() / 2];
                println!(
                    "{name},{spec:?},{latency_us},{mode:?},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{},{},{}",
                    t.prep,
                    t.fetch,
                    t.execute,
                    t.total,
                    timings.first().unwrap().total,
                    timings.last().unwrap().total,
                    t.fetched,
                    t.hits,
                    t.misses
                );
            }
        }
    }
}
