//! Concurrent pool validation state reads; compare one L3 with spread CPUs (e.g. EPYC 9254): `LLC_BENCH_CPUS=0,1,2,3,4,5 cargo bench -p tempo-transaction-pool --features bench --bench validation_reads`, then the same with `LLC_BENCH_CPUS=0,6,12,18,1,7`.
//!
//! Each of N threads, thread `i` pinned to the `i`-th CPU of `LLC_BENCH_CPUS` (Linux only;
//! default 4 unpinned threads), does the state reads of one transaction validation through a real
//! [`TempoTransactionValidator`]'s tip snapshot, thread-local front cache and shared state cache,
//! plus the AMM validator token check. `txpool_validation_reads_head_updates` also has thread 0
//! publish a new tip every [`HEAD_EVERY`] validations.

use alloy_consensus::Header;
use alloy_primitives::{Address, B256, U256};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use reth_primitives_traits::SealedBlock;
use reth_provider::test_utils::MockEthProvider;
use reth_transaction_pool::{
    TransactionValidator, blobstore::InMemoryBlobStore, validate::EthTransactionValidatorBuilder,
};
use revm::{
    DatabaseRef, bytecode::Bytecode, database_interface::WrapDatabaseRef, state::AccountInfo,
};
use std::{
    convert::Infallible,
    hint::black_box,
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tempo_chainspec::{TempoChainSpec, spec::MODERATO};
use tempo_evm::TempoEvmConfig;
use tempo_primitives::{Block, TempoHeader, TempoPrimitives};
use tempo_transaction_pool::{
    amm::AmmLiquidityCache,
    validator::{
        DEFAULT_AA_VALID_AFTER_MAX_SECS, DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
        TempoTransactionValidator,
    },
};

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// System storage slots every validation reads.
const HOT_SLOTS: u64 = 24;
/// Distinct senders validations draw from.
const SENDERS: u64 = 200_000;
/// Validations on thread 0 between head updates in `txpool_validation_reads_head_updates`.
const HEAD_EVERY: u64 = 20_000;
/// Untimed validations per thread before each measurement.
const WARMUP: u64 = 64;
/// Fee manager, fee token, TIP-403 registry, account keychain.
const SYSTEM: [u8; 4] = [0xfe, 0x20, 0x40, 0xaa];

/// A validator and the chain state the benchmark threads share.
struct Fixture {
    validator: TempoTransactionValidator<MockEthProvider<TempoPrimitives, TempoChainSpec>>,
    /// The validator's AMM cache, which tracks `fee_token` as a validator token.
    amm: AmmLiquidityCache,
    fee_token: Address,
    /// Chain tip number, as `chain_info().best_hash` reports it.
    best: AtomicU64,
    /// Validations thread 0 has done, counted across runs.
    head_ops: AtomicU64,
}

impl Fixture {
    /// A validator on a mock provider whose published tip is `tip_hash(1)`.
    fn new() -> Self {
        let fee_token = addr(SYSTEM[1], 0);
        let provider = MockEthProvider::<TempoPrimitives>::new()
            .with_chain_spec(Arc::unwrap_or_clone(MODERATO.clone()));
        let block = tip_block(1);
        provider.add_block(block.hash(), block.into_block());
        let inner =
            EthTransactionValidatorBuilder::new(provider.clone(), TempoEvmConfig::moderato())
                .build(InMemoryBlobStore::default());
        let amm = AmmLiquidityCache::new(provider).expect("failed to set up AmmLiquidityCache");
        amm.track_tokens(&[fee_token, addr(SYSTEM[1], 2)]);
        let validator = TempoTransactionValidator::new(
            inner,
            DEFAULT_AA_VALID_AFTER_MAX_SECS,
            DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
            amm.clone(),
        );
        Self {
            validator,
            amm,
            fee_token,
            best: AtomicU64::new(1),
            head_ops: AtomicU64::new(0),
        }
    }
}

/// Stand-in for the state provider behind the validator's state cache.
#[derive(Debug)]
struct MockDb;

impl DatabaseRef for MockDb {
    type Error = Infallible;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(Some(AccountInfo {
            balance: U256::from(address.0[19]),
            nonce: 1,
            ..Default::default()
        }))
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(Bytecode::default())
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        Ok(index + U256::from(address.0[0]))
    }

    fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
        Ok(B256::ZERO)
    }
}

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// The benchmark's CPUs from `LLC_BENCH_CPUS`, `None` for each of 4 unpinned threads by default.
fn bench_cpus() -> Vec<Option<usize>> {
    std::env::var("LLC_BENCH_CPUS").map_or_else(
        |_| vec![None; 4],
        |cpus| {
            cpus.split(',')
                .map(|cpu| Some(cpu.trim().parse().expect("LLC_BENCH_CPUS: invalid CPU")))
                .collect()
        },
    )
}

/// Pins the calling thread to `cpu`.
#[cfg(target_os = "linux")]
fn pin_to(cpu: usize) {
    // SAFETY: `set` is a plain bitmask that outlives the call, and pid 0 is the calling thread.
    unsafe {
        let mut set = std::mem::zeroed::<libc::cpu_set_t>();
        libc::CPU_SET(cpu, &mut set);
        let rc = libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &set);
        assert_eq!(
            rc,
            0,
            "sched_setaffinity({cpu}): {}",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn pin_to(_cpu: usize) {}

fn addr(tag: u8, n: u64) -> Address {
    let mut a = [0u8; 20];
    a[0] = tag;
    a[12..20].copy_from_slice(&n.to_be_bytes());
    Address::from(a)
}

fn tip_hash(n: u64) -> B256 {
    B256::left_padding_from(&n.to_be_bytes())
}

fn tip_block(n: u64) -> SealedBlock<Block> {
    let block = Block {
        header: TempoHeader {
            inner: Header {
                number: n,
                gas_limit: 500_000_000,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };
    SealedBlock::new_unchecked(block, tip_hash(n))
}

/// The state reads one transaction validation does: system configuration and fee token slots
/// read by every transaction, plus the sender's account, fee token balance and keychain slot.
fn validation_reads(db: &impl DatabaseRef<Error = Infallible>, sender: Address) -> U256 {
    let mut acc = U256::ZERO;
    for s in 0..HOT_SLOTS {
        acc += db
            .storage_ref(addr(SYSTEM[(s % 4) as usize], 0), U256::from(s))
            .unwrap();
    }
    for account in [addr(SYSTEM[0], 0), addr(SYSTEM[1], 0), sender] {
        acc += db
            .basic_ref(account)
            .unwrap()
            .map(|a| a.balance)
            .unwrap_or_default();
    }
    let word = U256::from_be_bytes(sender.into_word().0);
    acc += db.storage_ref(addr(SYSTEM[1], 0), word).unwrap();
    acc += db
        .storage_ref(addr(SYSTEM[3], 0), word + U256::ONE)
        .unwrap();
    acc
}

/// Runs `iters` validations on each thread after [`WARMUP`] untimed ones and returns the wall
/// time of the timed part. With `head_every`, thread 0 publishes a new tip every `head_every`
/// of its validations.
fn run(cpus: &[Option<usize>], fixture: &Fixture, head_every: Option<u64>, iters: u64) -> Duration {
    let barrier = Barrier::new(cpus.len() + 1);
    std::thread::scope(|s| {
        for (idx, &cpu) in cpus.iter().enumerate() {
            let barrier = &barrier;
            let Fixture {
                validator,
                amm,
                fee_token,
                best,
                head_ops,
            } = fixture;
            s.spawn(move || {
                if let Some(cpu) = cpu {
                    pin_to(cpu);
                }
                let mut rng =
                    XorShift(0x2545_F491_4F6C_DD1D ^ ((idx as u64 + 1) * 0x9E37_79B9_7F4A_7C15));
                let mut ops = head_ops.load(Ordering::Relaxed);
                let mut validate = || {
                    ops += 1;
                    if idx == 0
                        && let Some(every) = head_every
                        && ops % every == 0
                    {
                        // Canonical state advances first, then the pool's head update.
                        let next = best.fetch_add(1, Ordering::Relaxed) + 1;
                        validator.on_new_head_block(&tip_block(next));
                    }
                    let state_tip = tip_hash(best.load(Ordering::Relaxed));
                    let sender = addr(0x01, rng.next() % SENDERS);
                    let acc = validator.with_tip_state_db(Some(state_tip), &MockDb, |db| {
                        validation_reads(db, sender)
                    });
                    let has_liquidity = amm
                        .has_enough_liquidity(*fee_token, U256::ONE, WrapDatabaseRef(&MockDb))
                        .unwrap();
                    black_box((acc, has_liquidity));
                };
                (0..WARMUP).for_each(|_| validate());
                barrier.wait();
                (0..iters).for_each(|_| validate());
                barrier.wait();
                if idx == 0 {
                    head_ops.store(ops, Ordering::Relaxed);
                }
            });
        }
        barrier.wait();
        let start = Instant::now();
        barrier.wait();
        start.elapsed()
    })
}

fn bench_validation_reads(c: &mut Criterion) {
    let cpus = bench_cpus();
    let label = cpus
        .iter()
        .map(|cpu| cpu.map_or_else(|| "-".to_string(), |cpu| cpu.to_string()))
        .collect::<Vec<_>>()
        .join(",");
    let mut group = c.benchmark_group("txpool");
    // Elements are validations across all threads.
    group.throughput(Throughput::Elements(cpus.len() as u64));
    for (name, head_every) in [
        ("txpool_validation_reads", None),
        ("txpool_validation_reads_head_updates", Some(HEAD_EVERY)),
    ] {
        let fixture = Fixture::new();
        group.bench_function(format!("{name}/cpus={label}"), |b| {
            b.iter_custom(|iters| run(&cpus, &fixture, head_every, iters))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_validation_reads);
criterion_main!(benches);
