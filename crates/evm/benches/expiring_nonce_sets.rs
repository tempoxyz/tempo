//! Expiring nonce set strategies under real block streams.
//!
//! Replays a stream of blocks (Tempo mainnet blocks from a JSONL dump, or a txgen-shaped synthetic
//! load) and measures, per block, the work and memory of keeping a set for every unfinalized block:
//!
//! - \`store\`: the production [\`ExpiringNonceSets\`] (derive, pin, prune on finality). Its buckets
//!   are persistent tries by default and deep copies with the \`expiring-nonce-deep-clone\`
//!   feature, so running this bench with and without the feature compares the two.
//! - \`base-diff\`: one set at the finalized block, mutated in place when finality advances, plus
//!   each unfinalized block's entries. A block's root re-applies every entry since finality to
//!   copies of the buckets they touch.
//! - \`rebuild\`: the cost of regenerating a set from the last \`max_expiry\` seconds of entries, as
//!   after a reorg without snapshots.
//!
//! Every strategy's root is checked against the store's root at every block.
//!
//! Run:
//!   BLOCKS=path.jsonl|synthetic DEPTH=2 FORK_EVERY=10 \
//!   cargo bench -p tempo-evm --bench expiring_nonce_sets [--features expiring-nonce-deep-clone]
//! Synthetic load: TPS (default 50000), VALID_FOR (default 10), SECONDS (default 120).
//! JSONL rows: [number, timestamp, tx_count, [[hash, valid_before], ...]].

use alloy_primitives::{B256, keccak256, map::B256Map};
use reth_trie_common::{HashBuilder, Nibbles};
use reth_trie_sparse::{ArenaParallelSparseTrie, LeafUpdate, SparseTrie, TrieNodeEpoch};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    collections::{BTreeMap, HashMap, HashSet},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};
use tempo_evm::expiring_nonces::{ExpiringNonce, ExpiringNonceSet, ExpiringNonceSets, bucket_key};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
        PEAK.fetch_max(live, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size > layout.size() {
            let live = LIVE.fetch_add(new_size - layout.size(), Ordering::Relaxed) + new_size
                - layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        } else {
            LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

const PRESENT: [u8; 1] = [0x01];

struct Block {
    number: u64,
    timestamp: u64,
    entries: Vec<ExpiringNonce>,
}

fn env<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn load_blocks() -> (String, Vec<Block>) {
    let source = std::env::var("BLOCKS").unwrap_or_else(|_| "synthetic".into());
    if source != "synthetic" {
        let mut blocks: Vec<Block> = std::fs::read_to_string(&source)
            .expect("read BLOCKS")
            .lines()
            .map(|line| {
                let row: serde_json::Value = serde_json::from_str(line).expect("jsonl row");
                Block {
                    number: row[0].as_u64().unwrap(),
                    timestamp: row[1].as_u64().unwrap(),
                    entries: row[3]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|e| ExpiringNonce {
                            hash: e[0].as_str().unwrap().parse().unwrap(),
                            valid_before: e[1].as_u64().unwrap(),
                        })
                        .collect(),
                }
            })
            .collect();
        blocks.sort_by_key(|b| b.number);
        return (source, blocks);
    }
    // txgen tip20 preset: every transaction is an expiring nonce transaction with
    // valid_before = send time + valid_for_secs; two blocks per second.
    let tps: u64 = env("TPS", 50_000);
    let valid_for: u64 = env("VALID_FOR", 10);
    let seconds: u64 = env("SECONDS", 120);
    let per_block = tps / 2;
    let mut seed = 0u64;
    let blocks = (0..seconds * 2)
        .map(|i| {
            let timestamp = 1_000_000 + i / 2;
            let entries = (0..per_block)
                .map(|j| {
                    seed += 1;
                    // Sent up to a second before inclusion.
                    let sent = timestamp - (j % 2);
                    ExpiringNonce { hash: keccak256(seed.to_be_bytes()), valid_before: sent + valid_for }
                })
                .collect();
            Block { number: i + 1, timestamp, entries }
        })
        .collect();
    (format!("synthetic tps={tps} valid_for={valid_for}s seconds={seconds}"), blocks)
}

fn block_hash(number: u64, branch: u64) -> B256 {
    keccak256([number.to_be_bytes(), branch.to_be_bytes()].concat())
}

/// Finalized set plus unfinalized blocks' entries.
#[derive(Default)]
struct BaseDiff {
    base: BTreeMap<u64, (ArenaParallelSparseTrie, B256)>,
    /// Unfinalized blocks by hash: parent hash, timestamp, entries.
    diffs: HashMap<B256, (B256, u64, Vec<ExpiringNonce>)>,
    finalized: B256,
}

impl BaseDiff {
    /// Entries of the unfinalized ancestors of \`parent\` (inclusive), oldest first.
    fn chain(&self, mut parent: B256) -> Vec<&Vec<ExpiringNonce>> {
        let mut out = Vec::new();
        while parent != self.finalized {
            let (grand, _, entries) = &self.diffs[&parent];
            out.push(entries);
            parent = *grand;
        }
        out.reverse();
        out
    }

    fn contains(&self, chain: &[&Vec<ExpiringNonce>], seen: &HashSet<B256>, entry: &ExpiringNonce) -> bool {
        seen.contains(&entry.hash)
            || self.base.get(&entry.valid_before).is_some_and(|(trie, _)| {
                trie.get_leaf_value(&Nibbles::unpack(entry.hash)).is_some()
            })
            || chain.iter().any(|d| d.iter().any(|e| e.hash == entry.hash))
    }

    /// Checks \`entries\` for replays and returns the root of the set after a block at
    /// \`timestamp\` on top of \`parent\`. Does not change the base.
    fn derive(&self, parent: B256, timestamp: u64, entries: &[ExpiringNonce]) -> B256 {
        let chain = self.chain(parent);
        // Replay check against the chain, with an index so this is not quadratic.
        let chain_hashes: HashSet<B256> = chain.iter().flat_map(|d| d.iter().map(|e| e.hash)).collect();
        let mut seen = HashSet::new();
        for entry in entries {
            let replay = seen.contains(&entry.hash)
                || chain_hashes.contains(&entry.hash)
                || self.contains(&[], &HashSet::new(), entry);
            assert!(!replay, "replay in bench stream");
            seen.insert(entry.hash);
        }
        let mut touched: BTreeMap<u64, B256Map<LeafUpdate>> = BTreeMap::new();
        for entry in chain.iter().flat_map(|d| d.iter()).chain(entries) {
            if entry.valid_before > timestamp {
                touched
                    .entry(entry.valid_before)
                    .or_default()
                    .insert(entry.hash, LeafUpdate::Changed(PRESENT.to_vec()));
            }
        }
        let mut roots: BTreeMap<u64, B256> = self
            .base
            .range(timestamp + 1..)
            .map(|(vb, (_, root))| (*vb, *root))
            .collect();
        for (vb, mut leaves) in touched {
            let mut trie = self.base.get(&vb).map(|(t, _)| t.clone()).unwrap_or_default();
            trie.update_leaves(&mut leaves, |_, _| panic!("bucket blinded")).unwrap();
            roots.insert(vb, trie.root(TrieNodeEpoch::UNMODIFIED));
        }
        top_root(roots)
    }

    fn insert(&mut self, hash: B256, parent: B256, timestamp: u64, entries: Vec<ExpiringNonce>) {
        self.diffs.insert(hash, (parent, timestamp, entries));
    }

    /// Applies the newly finalized block \`hash\` (a child of the current finalized block) to the
    /// base in place and drops diffs that can no longer be built on.
    fn finalize(&mut self, hash: B256) {
        let (_, timestamp, entries) = self.diffs.remove(&hash).expect("finalized diff");
        self.base = self.base.split_off(&(timestamp + 1));
        let mut updates: BTreeMap<u64, B256Map<LeafUpdate>> = BTreeMap::new();
        for e in entries {
            updates.entry(e.valid_before).or_default().insert(e.hash, LeafUpdate::Changed(PRESENT.to_vec()));
        }
        for (vb, mut leaves) in updates {
            let (trie, root) = self.base.entry(vb).or_default();
            trie.update_leaves(&mut leaves, |_, _| panic!("bucket blinded")).unwrap();
            *root = trie.root(TrieNodeEpoch::UNMODIFIED);
        }
        let old = std::mem::replace(&mut self.finalized, hash);
        // Siblings of the finalized block, and anything built on them, are unreachable.
        let mut keep: HashSet<B256> = HashSet::new();
        let mut changed = true;
        while changed {
            changed = false;
            for (h, (p, _, _)) in &self.diffs {
                if !keep.contains(h) && (*p == hash || keep.contains(p)) {
                    keep.insert(*h);
                    changed = true;
                }
            }
        }
        self.diffs.retain(|h, _| keep.contains(h));
        let _ = old;
    }
}

fn top_root(buckets: BTreeMap<u64, B256>) -> B256 {
    let mut builder = HashBuilder::default();
    for (vb, root) in buckets {
        builder.add_leaf(Nibbles::unpack(bucket_key(vb)), &alloy_rlp::encode(root));
    }
    builder.root()
}

#[derive(Default)]
struct Stats {
    times: Vec<Duration>,
    live_bytes: Vec<usize>,
}

impl Stats {
    fn report(&mut self, name: &str, peak: usize) {
        self.times.sort();
        let q = |p: f64| self.times[((self.times.len() - 1) as f64 * p) as usize];
        let total: Duration = self.times.iter().sum();
        self.live_bytes.sort();
        let mib = |b: usize| b as f64 / (1024.0 * 1024.0);
        println!(
            "{name:<10} per block: p50 {:>9.3?} p99 {:>9.3?} max {:>9.3?} total {:>9.3?} | live MiB p50 {:>8.1} max {:>8.1} | peak MiB {:>8.1}",
            q(0.5),
            q(0.99),
            q(1.0),
            total,
            mib(self.live_bytes[self.live_bytes.len() / 2]),
            mib(*self.live_bytes.last().unwrap()),
            mib(peak),
        );
    }
}

fn main() {
    // \`cargo bench\` passes --bench; nothing else is accepted.
    let depth: u64 = env("DEPTH", 2);
    let fork_every: u64 = env("FORK_EVERY", 0);
    let max_expiry: u64 = env("MAX_EXPIRY", 300);
    let only: String = env("ONLY", "all".to_string());
    let (source, blocks) = load_blocks();
    let entries: usize = blocks.iter().map(|b| b.entries.len()).sum();
    println!(
        "== {source}: {} blocks, {entries} entries, finality depth {depth}, sibling every {} blocks, bucket trie {}",
        blocks.len(),
        if fork_every == 0 { "never".to_string() } else { fork_every.to_string() },
        if cfg!(feature = "expiring-nonce-deep-clone") { "deep-clone" } else { "persistent" },
    );

    // Reference roots from the production store, which every strategy must match.
    let mut roots: HashMap<B256, B256> = HashMap::new();
    let genesis = block_hash(0, 0);

    if only == "all" || only == "store" {
        let base = LIVE.load(Ordering::Relaxed);
        PEAK.store(base, Ordering::Relaxed);
        let sets = ExpiringNonceSets::default();
        sets.insert(genesis, blocks[0].number - 1, ExpiringNonceSet::default().for_block(true));
        let mut stats = Stats::default();
        let mut parent = genesis;
        let mut hashes = vec![genesis];
        for block in &blocks {
            let hash = block_hash(block.number, 0);
            let start = Instant::now();
            let set = sets.derive(parent, block.timestamp, &block.entries, true).expect("derive");
            let root = set.root();
            sets.insert(hash, block.number, set);
            if fork_every > 0 && block.number % fork_every == 0 {
                // A competing proposal at the same height with half the transactions.
                let half = &block.entries[..block.entries.len() / 2];
                let sibling = sets.derive(parent, block.timestamp, half, true).expect("derive");
                sets.insert(block_hash(block.number, 1), block.number, sibling);
            }
            hashes.push(hash);
            if hashes.len() as u64 > depth {
                let fin = hashes.len() - 1 - depth as usize;
                sets.prune_finalized(block.number - depth, hashes[fin]);
            }
            stats.times.push(start.elapsed());
            stats.live_bytes.push(LIVE.load(Ordering::Relaxed) - base);
            roots.insert(hash, root);
            parent = hash;
        }
        stats.report("store", PEAK.load(Ordering::Relaxed) - base);
    }

    if only == "all" || only == "base-diff" {
        let base = LIVE.load(Ordering::Relaxed);
        PEAK.store(base, Ordering::Relaxed);
        let mut bd = BaseDiff { finalized: genesis, ..Default::default() };
        let mut stats = Stats::default();
        let mut parent = genesis;
        let mut chain = vec![genesis];
        for block in &blocks {
            let hash = block_hash(block.number, 0);
            let start = Instant::now();
            let root = bd.derive(parent, block.timestamp, &block.entries);
            bd.insert(hash, parent, block.timestamp, block.entries.clone());
            if fork_every > 0 && block.number % fork_every == 0 {
                let half = block.entries[..block.entries.len() / 2].to_vec();
                let _ = bd.derive(parent, block.timestamp, &half);
                bd.insert(block_hash(block.number, 1), parent, block.timestamp, half);
            }
            chain.push(hash);
            if chain.len() as u64 > depth + 1 {
                let next = chain[chain.len() - 1 - depth as usize];
                bd.finalize(next);
            }
            stats.times.push(start.elapsed());
            stats.live_bytes.push(LIVE.load(Ordering::Relaxed) - base);
            if let Some(expected) = roots.get(&hash) {
                assert_eq!(root, *expected, "base-diff root differs at block {}", block.number);
            }
            parent = hash;
        }
        drop(bd);
        stats.report("base-diff", PEAK.load(Ordering::Relaxed) - base);
    }

    if only == "all" || only == "rebuild" {
        // Regenerating a set after a reorg: replay every block of the last max_expiry seconds.
        let mut times = Vec::new();
        for at in [blocks.len() / 2, blocks.len() * 3 / 4, blocks.len() - 1] {
            let tip = &blocks[at];
            let window: Vec<&Block> = blocks[..=at]
                .iter()
                .filter(|b| b.timestamp + max_expiry >= tip.timestamp)
                .collect();
            let start = Instant::now();
            let mut set = ExpiringNonceSet::default().for_block(true);
            for b in &window {
                set.apply(b.timestamp, &b.entries).unwrap();
            }
            times.push(start.elapsed());
            if let Some(expected) = roots.get(&block_hash(tip.number, 0)) {
                assert_eq!(set.root(), *expected, "rebuild root differs");
            }
            if at == blocks.len() - 1 {
                println!(
                    "rebuild    from {} blocks ({} entries, {} live): {:?} (runs: {:?})",
                    window.len(),
                    window.iter().map(|b| b.entries.len()).sum::<usize>(),
                    set.len(),
                    times.iter().max().unwrap(),
                    times
                );
            }
        }
    }
}
