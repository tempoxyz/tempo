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

use alloy_primitives::{keccak256, Address, B256, Bytes};
use parking_lot::RwLock;
use reth_errors::ProviderResult;
use reth_primitives_traits::{Account, Bytecode};
use reth_storage_api::{
    AccountReader, BlockHashReader, BytecodeReader, HashedPostStateProvider, StateProofProvider,
    StateProvider, StateRootProvider, StorageRootProvider,
};
use reth_trie_common::{
    updates::TrieUpdates, AccountProof, HashedPostState, HashedStorage, MultiProof,
    MultiProofTargets, StorageMultiProof, StorageProof, TrieInput,
};
use tempo_flatmpt::FlatShadow;

/// `TEMPO_FLATMPT_READS=1` (in root mode) routes builder state reads through
/// the flat MPT.
pub(crate) fn flat_reads_enabled() -> bool {
    tempo_flatmpt::mode() == tempo_flatmpt::FlatMode::Root
        && std::env::var("TEMPO_FLATMPT_READS").as_deref() == Ok("1")
}

pub(crate) struct FlatReadProvider {
    pub inner: reth_storage_api::StateProviderBox,
    /// Lock-free snapshot of the flat store, pinned at the block's parent
    /// state for the whole build — reads never wait on the writer and never
    /// observe mid-block flat advances.
    pub snap: tempo_flatmpt::FlatSnapshot,
    /// When a sparse commitment worker is active, first-touch reads walk the
    /// same records its reveals need — capture the path nodes during the read
    /// and hand them over, so the worker never re-fetches them (lossy; a
    /// dropped batch only means the worker fetches that path itself).
    pub reveal: Option<RevealFeed>,
}

pub(crate) struct RevealFeed {
    pub sink: tempo_flatmpt::RevealSink,
    /// Keys already handed over this block (reads are first-touch per key via
    /// the execution cache, but prewarm threads race the main pass).
    sent_accounts: parking_lot::Mutex<std::collections::HashSet<B256>>,
    sent_slots: parking_lot::Mutex<std::collections::HashSet<(B256, B256)>>,
}

impl RevealFeed {
    pub fn new(sink: tempo_flatmpt::RevealSink) -> Self {
        Self {
            sink,
            sent_accounts: parking_lot::Mutex::new(Default::default()),
            sent_slots: parking_lot::Mutex::new(Default::default()),
        }
    }
}

fn other(e: anyhow::Error) -> reth_errors::ProviderError {
    reth_errors::ProviderError::other(std::io::Error::other(format!("{e:#}")))
}

impl FlatReadProvider {
    /// Account point-read; when a reveal feed is attached and this is the
    /// first touch of `key`, the read's walk doubles as the reveal.
    fn read_account_rlp(&self, key: &B256) -> ProviderResult<Option<Vec<u8>>> {
        if let Some(feed) = &self.reveal {
            if feed.sent_accounts.lock().insert(*key) {
                let (value, nodes) = self
                    .snap
                    .get_value_reveal(&key.0)
                    .map_err(|e| other(anyhow::anyhow!("{e:#}")))?;
                feed.sink.account(*key, nodes);
                return Ok(value);
            }
        }
        self.snap.get_value(&key.0).map_err(|e| other(anyhow::anyhow!("{e:#}")))
    }

    fn read_storage_rlp(&self, acct: &B256, slot: &B256) -> ProviderResult<Option<Vec<u8>>> {
        if let Some(feed) = &self.reveal {
            if feed.sent_slots.lock().insert((*acct, *slot)) {
                let (value, nodes) = self
                    .snap
                    .get_storage_reveal(&acct.0, &slot.0)
                    .map_err(|e| other(anyhow::anyhow!("{e:#}")))?;
                if let Some(nodes) = nodes {
                    feed.sink.storage(*acct, *slot, nodes);
                }
                return Ok(value);
            }
        }
        self.snap.get_storage(&acct.0, &slot.0).map_err(|e| other(anyhow::anyhow!("{e:#}")))
    }
}

impl AccountReader for FlatReadProvider {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        let key = alloy_primitives::keccak256(address.0 .0);
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
        let acct_key = alloy_primitives::keccak256(account.0 .0);
        let slot_key = alloy_primitives::keccak256(storage_key.0);
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
        self.inner.storage_multiproof(address, slots, hashed_storage)
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
    ) -> HashedPostState {
        self.inner.hashed_post_state(bundle_state)
    }
}
