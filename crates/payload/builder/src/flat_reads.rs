//! Serve EVM account/storage point reads from the flat MPT.
//!
//! Wraps the builder's state provider (below the execution cache): basic
//! account fields and storage slots come from the [`tempo_flatmpt::FlatShadow`]
//! instead of MDBX plain state; bytecode, block hashes, and all trie/proof
//! machinery fall through to the wrapped provider.
//!
//! Safety with streamed application: the execution `State` caches every key it
//! has touched this block, so the provider only ever sees *first-touch* reads.
//! A key that reaches us has not been written by any earlier transaction in
//! this block, hence no streamed chunk contains it, hence the flat state holds
//! exactly the parent value for it — even while chunks for *other* keys land
//! concurrently. Reads take the `RwLock` shared, so they run concurrently with
//! each other and only serialize against chunk applies.

use alloy_primitives::{Address, B256, Bytes, keccak256};
use reth_errors::ProviderResult;
use reth_primitives_traits::{Account, Bytecode};
use reth_storage_api::{
    AccountReader, BlockHashReader, BytecodeReader, HashedPostStateProvider, StateProofProvider,
    StateProvider, StateRootProvider, StorageRootProvider,
};
use reth_trie_common::{
    AccountProof, HashedPostState, HashedStorage, MultiProof, MultiProofTargets, StorageMultiProof,
    StorageProof, TrieInput, updates::TrieUpdates,
};

/// `TEMPO_FLATMPT_READS=1` (in root mode) routes builder state reads through
/// the flat MPT.
/// `TEMPO_NO_STATE_KV` (set on the node): the duplicate state KV is not
/// persisted, so reading MDBX/rocksdb state would return empty values — every
/// fallback that would do so must wait for the flat store instead.
pub(crate) fn no_state_kv_active() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| std::env::var("TEMPO_NO_STATE_KV").is_ok_and(|v| v == "1" || v == "all"))
}

pub(crate) fn flat_reads_enabled() -> bool {
    tempo_flatmpt::mode() == tempo_flatmpt::FlatMode::Root
        && (no_state_kv_active() || std::env::var("TEMPO_FLATMPT_READS").as_deref() == Ok("1"))
}

/// Per-block flat-read context shared by the builder's provider and every
/// prewarm executor's provider: one snapshot, one hashed-key memo, one reveal
/// feed — so any thread's first touch of a key feeds the commitment worker,
/// and nobody hashes or fetches the same thing twice.
pub(crate) struct FlatReadShared {
    /// Lock-free snapshot of the flat store, pinned for the whole build —
    /// reads never wait on the writer and never observe mid-block advances.
    /// Either exactly at the parent state (`overlay` empty) or at an ancestor
    /// the `overlay` chain extends to the parent.
    pub snap: tempo_flatmpt::FlatSnapshot,
    /// Pending (queued, unapplied) blocks between the snapshot state and the
    /// parent state, newest first. First-touch reads consult these before the
    /// snapshot, so the builder never waits for the follower's applies.
    pub overlay: Vec<std::sync::Arc<tempo_flatmpt::PendingBlock>>,
    /// Per-block keccak(address) memo shared by all reading threads.
    pub hashed: HashedKeyMemo,
    /// When a sparse commitment worker is active, first-touch reads walk the
    /// same records its reveals need — capture the path nodes during the read
    /// and hand them over, so the worker never re-fetches them (lossy; a
    /// dropped batch only means the worker fetches that path itself).
    /// Must be `None` when `overlay` is non-empty: reveal nodes from the
    /// ancestor trie carry sibling hashes stale relative to the parent trie.
    pub reveal: Option<RevealFeed>,
}

pub(crate) struct FlatReadProvider {
    pub inner: reth_storage_api::StateProviderBox,
    pub shared: std::sync::Arc<FlatReadShared>,
}

/// Per-block memo of `keccak(address)` — the provider is hit by ~30 prewarm
/// threads plus the exec thread, mostly for the same few thousand senders and
/// recycled contracts; hashing per read costs the hot path for nothing.
#[derive(Default)]
pub(crate) struct HashedKeyMemo {
    accounts: parking_lot::RwLock<alloy_primitives::map::AddressMap<B256>>,
}

impl HashedKeyMemo {
    fn account(&self, address: &Address) -> B256 {
        if let Some(k) = self.accounts.read().get(address) {
            return *k;
        }
        let k = keccak256(address.0.0);
        self.accounts.write().insert(*address, k);
        k
    }
}

pub(crate) struct RevealFeed {
    pub sink: tempo_flatmpt::RevealSink,
    /// Lock-free probabilistic dedup of keys already handed over this block.
    /// The previous `Mutex<HashSet>` stalled all ~30 prewarm workers together
    /// whenever the 265k-entry set rehashed under the lock (5-10ms correlated
    /// stalls — the dispatch-latch trigger). A false positive only means the
    /// commitment worker fetches that one path itself.
    sent_accounts: SentFilter,
    sent_slots: SentFilter,
}

/// Fixed-size atomic bitmap: test-and-set on a hash of the key. 2^23 bits
/// (1 MiB) per filter — at ~300k inserts/block the false-positive rate stays
/// under ~2%. Never resizes, never locks.
pub(crate) struct SentFilter {
    bits: Box<[std::sync::atomic::AtomicU64]>,
}

impl Default for SentFilter {
    fn default() -> Self {
        Self {
            bits: (0..(1usize << 23) / 64)
                .map(|_| std::sync::atomic::AtomicU64::new(0))
                .collect(),
        }
    }
}

impl SentFilter {
    /// True iff this key was NOT seen before (and marks it seen).
    fn first(&self, key: &[u8]) -> bool {
        // keys are keccak outputs — any 8 bytes are uniformly random
        let h = u64::from_le_bytes(key[..8].try_into().unwrap());
        let bit = (h as usize) & ((1 << 23) - 1);
        let (word, mask) = (bit / 64, 1u64 << (bit % 64));
        let prev = self.bits[word].fetch_or(mask, std::sync::atomic::Ordering::Relaxed);
        prev & mask == 0
    }
}

impl RevealFeed {
    pub(crate) fn new(sink: tempo_flatmpt::RevealSink) -> Self {
        Self {
            sink,
            sent_accounts: Default::default(),
            sent_slots: Default::default(),
        }
    }
}

fn other(e: anyhow::Error) -> reth_errors::ProviderError {
    reth_errors::ProviderError::other(std::io::Error::other(format!("{e:#}")))
}

/// Latency of a single state-element fetch on the prewarm workers' cache-miss
/// path (whatever sits below the execution cache: the flat snapshot in flat
/// mode, MDBX/rocksdb otherwise). Log2-bucket ns histograms, process-wide;
/// a summary line is logged every 2^17 samples per kind.
pub(crate) mod fetch_stats {
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

    const BUCKETS: usize = 40; // bucket i covers [2^(i-1), 2^i) ns
    static HIST: [[AtomicU64; BUCKETS]; 2] = [const { [const { AtomicU64::new(0) }; BUCKETS] }; 2];
    static COUNT: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
    static SUM_NS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
    static MAX_NS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

    pub(crate) fn record(kind: usize, ns: u64) {
        let b = (64 - ns.leading_zeros() as usize).min(BUCKETS - 1);
        HIST[kind][b].fetch_add(1, Relaxed);
        SUM_NS[kind].fetch_add(ns, Relaxed);
        MAX_NS[kind].fetch_max(ns, Relaxed);
        let n = COUNT[kind].fetch_add(1, Relaxed) + 1;
        if n & ((1 << 17) - 1) == 0 {
            log_summary(kind, n);
        }
    }

    fn percentile(kind: usize, total: u64, p: f64) -> u64 {
        let target = (total as f64 * p) as u64;
        let mut cum = 0u64;
        for (i, b) in HIST[kind].iter().enumerate() {
            cum += b.load(Relaxed);
            if cum >= target {
                return 1u64 << i; // upper edge of the bucket
            }
        }
        1u64 << (BUCKETS - 1)
    }

    fn log_summary(kind: usize, n: u64) {
        let name = ["account", "storage"][kind];
        tracing::info!(
            target: "flatmpt",
            kind = name,
            n,
            avg_us = SUM_NS[kind].load(Relaxed) / n / 1000,
            p50_us = percentile(kind, n, 0.50) / 1000,
            p90_us = percentile(kind, n, 0.90) / 1000,
            p99_us = percentile(kind, n, 0.99) / 1000,
            p999_us = percentile(kind, n, 0.999) / 1000,
            max_us = MAX_NS[kind].load(Relaxed) / 1000,
            "worker fetch stats"
        );
    }
}

/// Wraps the provider below the prewarm execution cache and times every
/// account/storage fetch (i.e. only real fetches — cache hits never get here).
pub(crate) struct FetchTimedProvider {
    pub inner: reth_storage_api::StateProviderBox,
}

impl AccountReader for FetchTimedProvider {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        let t = std::time::Instant::now();
        let r = self.inner.basic_account(address);
        fetch_stats::record(0, t.elapsed().as_nanos() as u64);
        r
    }
}

impl StateProvider for FetchTimedProvider {
    fn storage(
        &self,
        account: Address,
        storage_key: alloy_primitives::StorageKey,
    ) -> ProviderResult<Option<alloy_primitives::StorageValue>> {
        let t = std::time::Instant::now();
        let r = self.inner.storage(account, storage_key);
        fetch_stats::record(1, t.elapsed().as_nanos() as u64);
        r
    }
}

impl BlockHashReader for FetchTimedProvider {
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        self.inner.block_hash(number)
    }
    fn convert_block_hash(
        &self,
        hash_or_number: alloy_eips::BlockHashOrNumber,
    ) -> ProviderResult<Option<B256>> {
        self.inner.convert_block_hash(hash_or_number)
    }
    fn canonical_hashes_range(&self, start: u64, end: u64) -> ProviderResult<Vec<B256>> {
        self.inner.canonical_hashes_range(start, end)
    }
}

impl BytecodeReader for FetchTimedProvider {
    fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        self.inner.bytecode_by_hash(code_hash)
    }
}

impl StateRootProvider for FetchTimedProvider {
    fn state_root(&self, hashed_state: HashedPostState) -> ProviderResult<B256> {
        self.inner.state_root(hashed_state)
    }
    fn state_root_from_nodes(&self, input: TrieInput) -> ProviderResult<B256> {
        self.inner.state_root_from_nodes(input)
    }
    fn state_root_with_updates(
        &self,
        hashed_state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        self.inner.state_root_with_updates(hashed_state)
    }
    fn state_root_from_nodes_with_updates(
        &self,
        input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        self.inner.state_root_from_nodes_with_updates(input)
    }
}

impl StorageRootProvider for FetchTimedProvider {
    fn storage_root(
        &self,
        address: Address,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<B256> {
        self.inner.storage_root(address, hashed_storage)
    }
    fn storage_proof(
        &self,
        address: Address,
        slot: B256,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageProof> {
        self.inner.storage_proof(address, slot, hashed_storage)
    }
    fn storage_multiproof(
        &self,
        address: Address,
        slots: &[B256],
        hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageMultiProof> {
        self.inner
            .storage_multiproof(address, slots, hashed_storage)
    }
}

impl StateProofProvider for FetchTimedProvider {
    fn proof(
        &self,
        input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        self.inner.proof(input, address, slots)
    }
    fn multiproof(
        &self,
        input: TrieInput,
        targets: MultiProofTargets,
    ) -> ProviderResult<MultiProof> {
        self.inner.multiproof(input, targets)
    }
    fn witness(
        &self,
        input: TrieInput,
        target: HashedPostState,
        mode: reth_trie_common::ExecutionWitnessMode,
    ) -> ProviderResult<Vec<Bytes>> {
        self.inner.witness(input, target, mode)
    }
}

impl HashedPostStateProvider for FetchTimedProvider {
    fn hashed_post_state(
        &self,
        bundle_state: &reth_revm::db::BundleState,
    ) -> ProviderResult<HashedPostState> {
        self.inner.hashed_post_state(bundle_state)
    }
}

impl FlatReadProvider {
    /// Account point-read; when a reveal feed is attached and this is the
    /// first touch of `key`, the read's walk doubles as the reveal.
    fn read_account_rlp(&self, key: &B256) -> ProviderResult<Option<Vec<u8>>> {
        if let Some(feed) = &self.shared.reveal
            && feed.sent_accounts.first(&key.0)
        {
            let (value, nodes) = self
                .shared
                .snap
                .get_value_reveal(&key.0)
                .map_err(|e| other(anyhow::anyhow!("{e:#}")))?;
            feed.sink.account(*key, nodes);
            return Ok(value);
        }
        self.shared
            .snap
            .get_value(&key.0)
            .map_err(|e| other(anyhow::anyhow!("{e:#}")))
    }

    fn read_storage_rlp(&self, acct: &B256, slot: &B256) -> ProviderResult<Option<Vec<u8>>> {
        if let Some(feed) = &self.shared.reveal
            && feed.sent_slots.first(&{
                let mut k = [0u8; 16];
                k[..8].copy_from_slice(&acct.0[..8]);
                k[8..].copy_from_slice(&slot.0[..8]);
                k
            })
        {
            let (value, nodes) = self
                .shared
                .snap
                .get_storage_reveal(&acct.0, &slot.0)
                .map_err(|e| other(anyhow::anyhow!("{e:#}")))?;
            if let Some(nodes) = nodes {
                feed.sink.storage(*acct, *slot, nodes);
            }
            return Ok(value);
        }
        self.shared
            .snap
            .get_storage(&acct.0, &slot.0)
            .map_err(|e| other(anyhow::anyhow!("{e:#}")))
    }
}

impl AccountReader for FlatReadProvider {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        let key = self.shared.hashed.account(address);
        for pending in &self.shared.overlay {
            if let Some(hit) = pending.account(&key.0) {
                return Ok(hit.map(|(nonce, balance, code_hash)| Account {
                    nonce,
                    balance,
                    bytecode_hash: (code_hash != keccak256([]).0).then(|| B256::from(code_hash)),
                }));
            }
        }
        let read = self
            .read_account_rlp(&key)?
            .map(|rlp| tempo_flatmpt::FlatShadow::decode_account_rlp(rlp.as_slice()))
            .transpose()
            .map_err(other)?;
        Ok(read.map(|(nonce, balance, code_hash)| Account {
            nonce,
            balance,
            // MDBX convention: EOAs carry no bytecode hash.
            bytecode_hash: (code_hash != keccak256([]).0).then(|| B256::from(code_hash)),
        }))
    }
}

impl StateProvider for FlatReadProvider {
    fn storage(
        &self,
        account: Address,
        storage_key: alloy_primitives::StorageKey,
    ) -> ProviderResult<Option<alloy_primitives::StorageValue>> {
        let acct_key = self.shared.hashed.account(&account);
        let slot_key = alloy_primitives::keccak256(storage_key.0);
        for pending in &self.shared.overlay {
            if let Some(hit) = pending.storage(&acct_key.0, &slot_key.0) {
                return hit
                    .map(|mut rlp| {
                        <alloy_primitives::U256 as alloy_rlp::Decodable>::decode(&mut rlp)
                            .map_err(|e| other(anyhow::anyhow!("{e}")))
                    })
                    .transpose();
            }
        }
        let read = self
            .read_storage_rlp(&acct_key, &slot_key)?
            .map(|rlp| {
                <alloy_primitives::U256 as alloy_rlp::Decodable>::decode(&mut rlp.as_slice())
                    .map_err(|e| anyhow::anyhow!("{e}"))
            })
            .transpose()
            .map_err(other)?;
        Ok(read)
    }
}

impl BlockHashReader for FlatReadProvider {
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        self.inner.block_hash(number)
    }
    fn convert_block_hash(
        &self,
        hash_or_number: alloy_eips::BlockHashOrNumber,
    ) -> ProviderResult<Option<B256>> {
        self.inner.convert_block_hash(hash_or_number)
    }
    fn canonical_hashes_range(&self, start: u64, end: u64) -> ProviderResult<Vec<B256>> {
        self.inner.canonical_hashes_range(start, end)
    }
}

impl BytecodeReader for FlatReadProvider {
    fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        self.inner.bytecode_by_hash(code_hash)
    }
}

impl StateRootProvider for FlatReadProvider {
    fn state_root(&self, hashed_state: HashedPostState) -> ProviderResult<B256> {
        self.inner.state_root(hashed_state)
    }
    fn state_root_from_nodes(&self, input: TrieInput) -> ProviderResult<B256> {
        self.inner.state_root_from_nodes(input)
    }
    fn state_root_with_updates(
        &self,
        hashed_state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        self.inner.state_root_with_updates(hashed_state)
    }
    fn state_root_from_nodes_with_updates(
        &self,
        input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        self.inner.state_root_from_nodes_with_updates(input)
    }
}

impl StorageRootProvider for FlatReadProvider {
    fn storage_root(
        &self,
        address: Address,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<B256> {
        self.inner.storage_root(address, hashed_storage)
    }
    fn storage_proof(
        &self,
        address: Address,
        slot: B256,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageProof> {
        self.inner.storage_proof(address, slot, hashed_storage)
    }
    fn storage_multiproof(
        &self,
        address: Address,
        slots: &[B256],
        hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageMultiProof> {
        self.inner
            .storage_multiproof(address, slots, hashed_storage)
    }
}

impl StateProofProvider for FlatReadProvider {
    fn proof(
        &self,
        input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        self.inner.proof(input, address, slots)
    }
    fn multiproof(
        &self,
        input: TrieInput,
        targets: MultiProofTargets,
    ) -> ProviderResult<MultiProof> {
        self.inner.multiproof(input, targets)
    }
    fn witness(
        &self,
        input: TrieInput,
        target: HashedPostState,
        mode: reth_trie_common::ExecutionWitnessMode,
    ) -> ProviderResult<Vec<Bytes>> {
        self.inner.witness(input, target, mode)
    }
}

impl HashedPostStateProvider for FlatReadProvider {
    fn hashed_post_state(
        &self,
        bundle_state: &reth_revm::db::BundleState,
    ) -> ProviderResult<HashedPostState> {
        self.inner.hashed_post_state(bundle_state)
    }
}
