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
}

fn other(e: anyhow::Error) -> reth_errors::ProviderError {
    reth_errors::ProviderError::other(std::io::Error::other(format!("{e:#}")))
}

impl AccountReader for FlatReadProvider {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        let key = alloy_primitives::keccak256(address.0 .0);
        let read = self
            .snap
            .get_value(&key.0)
            .map_err(|e| other(anyhow::anyhow!("{e:#}")))?
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
            .snap
            .get_storage(&acct_key.0, &slot_key.0)
            .map_err(|e| other(anyhow::anyhow!("{e:#}")))?
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
