use crate::node::{QmdbArgs, StateRootBackend};
use alloy_eips::BlockNumHash;
use alloy_evm::block::{OnStateHook, StateChangeSource};
use alloy_primitives::{
    Address, B256, BlockNumber, Bytes, FixedBytes, StorageKey, StorageValue, U256, keccak256,
};
use reth_chain_state::ExecutedBlock;
use reth_chainspec::{ChainInfo, ChainSpecProvider, EthChainSpec};
use reth_engine_primitives::NoopInvalidBlockHook;
use reth_engine_tree::{
    persistence::{RemoveBlocksHook, SaveBlocksHook},
    tree::{
        BasicEngineValidator, CacheWaitDurations, EngineApiTreeState, EngineValidator, SavedCache,
        TreeConfig, ValidationOutcome, WaitForCaches,
        payload_processor::multiproof::{
            QmdbRawStateUpdate, SharedStateRootComputeOutcome, SharedStateRootHandle,
            SharedStateRootMessage,
        },
        payload_validator::{CustomStateRootInput, TreeCtx},
    },
};
use reth_evm::ConfigureEvm;
use reth_node_api::{
    BlockTy, ConfigureEngineEvm, FullNodeComponents, NodeTypes, PayloadTypes, PayloadValidator,
};
use reth_node_builder::{
    AddOnsContext, NodeConfig,
    invalid_block_hook::InvalidBlockHookExt,
    rpc::{EngineValidatorBuilder, PayloadValidatorBuilder},
};
use reth_node_core::args::EngineArgs;
use reth_payload_primitives::{
    BuiltPayloadExecutedBlock, InvalidPayloadAttributesError, NewPayloadError,
};
use reth_primitives_traits::{Account, AlloyBlockHeader, Bytecode};
use reth_provider::{ProviderError, ProviderResult};
use reth_qmdb::{
    QmdbBlock, QmdbBlockMutations, QmdbCommit, QmdbConfig, QmdbError, QmdbHead,
    QmdbKey as RethQmdbKey, QmdbStage, QmdbState, QmdbStateRootProvider,
    QmdbValue as RethQmdbValue, genesis_hashed_state,
};
use reth_stages::{StageId, StageSetBuilder};
use reth_storage_api::{
    AccountReader, BlockHashReader, BlockIdReader, BlockNumReader, BytecodeReader, ChangeSetReader,
    HashedPostStateProvider, HeaderProvider, StateProofProvider, StateProvider, StateProviderBox,
    StateProviderFactory, StateReader, StateRootProvider, StorageChangeSetReader, StorageReader,
    StorageRootProvider,
};
use reth_tracing::tracing::{debug, info};
use reth_trie_common::{
    AccountProof, ExecutionWitnessMode, HashedPostState, HashedStorage, KeccakKeyHasher,
    MultiProof, MultiProofTargets, StorageMultiProof, StorageProof, TrieInput,
    updates::TrieUpdates,
};
use reth_trie_db::ChangesetCache;
use reth_trie_parallel::root::ParallelStateRootError;
use revm_state::EvmState;
use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex, OnceLock, mpsc},
    thread,
    time::{Duration, Instant},
};
use tempo_chainspec::spec::TempoChainSpec;
use tempo_primitives::TempoPrimitives;

/// Engine tree persistence threshold required by QMDB state roots.
pub const QMDB_ENGINE_PERSISTENCE_THRESHOLD: u64 = 0;

/// Engine tree memory block buffer target required by QMDB state roots.
pub const QMDB_ENGINE_MEMORY_BLOCK_BUFFER_TARGET: u64 = 0;
const QMDB_PARENT_OVERLAY_WAIT_TIMEOUT: Duration = Duration::from_secs(2);

/// Returns a tree config that keeps QMDB state roots in the QMDB backend.
pub fn qmdb_engine_tree_config(tree_config: TreeConfig) -> TreeConfig {
    tree_config
        .with_persistence_threshold(QMDB_ENGINE_PERSISTENCE_THRESHOLD)
        .with_memory_block_buffer_target(QMDB_ENGINE_MEMORY_BLOCK_BUFFER_TARGET)
        .with_share_sparse_trie_with_payload_builder(true)
        .with_suppress_persistence_during_build(false)
}

/// Applies QMDB engine tree requirements to CLI engine arguments before launch.
pub fn configure_qmdb_engine_args(engine: &mut EngineArgs) {
    engine.persistence_threshold = QMDB_ENGINE_PERSISTENCE_THRESHOLD;
    engine.memory_block_buffer_target = QMDB_ENGINE_MEMORY_BLOCK_BUFFER_TARGET;
    engine.share_sparse_trie_with_payload_builder = true;
    engine.suppress_persistence_during_build = false;
}

const QMDB_KEY_BYTES: usize = 65;
const QMDB_VALUE_BYTES: usize = 74;
const QMDB_ACCOUNT_TAG: u8 = 0;
const QMDB_STORAGE_TAG: u8 = 1;

pub type QmdbKey = FixedBytes<QMDB_KEY_BYTES>;
pub type QmdbValue = FixedBytes<QMDB_VALUE_BYTES>;
pub type EntryId = usize;
type QmdbRawMutation = (RethQmdbKey, Option<RethQmdbValue>);
type QmdbRawMutations = Vec<QmdbRawMutation>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmdbOverlayEntry {
    pub key: QmdbKey,
    pub before: Option<QmdbValue>,
    pub after: Option<QmdbValue>,
    pub generation: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QmdbRootStats {
    pub state_updates: usize,
    pub parent_overlays: usize,
    pub arena_entries: usize,
    pub dirty_keys: usize,
    pub hashed_accounts: usize,
    pub hashed_storage_sets: usize,
    pub overlay_entries: usize,
    pub base_reads: usize,
    pub base_read_duration: Duration,
    pub stream_duration: Duration,
    pub final_wait_duration: Duration,
    pub total_duration: Duration,
}

#[derive(Clone, Debug)]
pub struct QmdbOverlayCommit {
    pub anchor: QmdbHead,
    pub root: B256,
    pub entries: usize,
    pub hashed_state: Arc<HashedPostState>,
    pub(crate) mutations: Option<Arc<QmdbRawMutations>>,
    pub stats: QmdbRootStats,
}

#[derive(Clone, Debug)]
pub struct QmdbRootOutcome {
    pub root: B256,
    pub entries: usize,
    pub commit: Arc<QmdbOverlayCommit>,
    pub stats: QmdbRootStats,
}

#[derive(Debug)]
pub enum QmdbRootMessage {
    StateUpdate(StateChangeSource, EvmState),
    ParentOverlay(Arc<HashedPostState>),
    FinishedStateUpdates,
}

#[derive(Debug)]
pub struct QmdbRootHandle {
    pub anchor: QmdbHead,
    updates_tx: crossbeam_channel::Sender<QmdbRootMessage>,
    root_rx: Option<mpsc::Receiver<Result<QmdbRootOutcome, QmdbError>>>,
}

impl QmdbRootHandle {
    pub const fn new(
        anchor: QmdbHead,
        updates_tx: crossbeam_channel::Sender<QmdbRootMessage>,
        root_rx: mpsc::Receiver<Result<QmdbRootOutcome, QmdbError>>,
    ) -> Self {
        Self {
            anchor,
            updates_tx,
            root_rx: Some(root_rx),
        }
    }

    pub const fn updates_tx(&self) -> &crossbeam_channel::Sender<QmdbRootMessage> {
        &self.updates_tx
    }

    pub fn state_hook(&self) -> impl OnStateHook {
        let sender = QmdbStateHookSender(self.updates_tx.clone());
        move |source: StateChangeSource, state: &EvmState| {
            let _ = sender
                .0
                .send(QmdbRootMessage::StateUpdate(source, state.clone()));
        }
    }

    pub fn state_root(&mut self) -> Result<QmdbRootOutcome, QmdbError> {
        self.root_rx
            .take()
            .expect("QMDB state root already taken")
            .recv()
            .map_err(|_| QmdbError::ActorClosed)?
    }
}

#[allow(dead_code)]
#[derive(Debug)]
struct QmdbStateHookSender(crossbeam_channel::Sender<QmdbRootMessage>);

impl Drop for QmdbStateHookSender {
    fn drop(&mut self) {
        let _ = self.0.send(QmdbRootMessage::FinishedStateUpdates);
    }
}

#[derive(Clone, Debug)]
pub struct QmdbOverlayArena {
    pub anchor: QmdbHead,
    pub base_values: HashMap<QmdbKey, Option<QmdbValue>>,
    pub entries: Vec<QmdbOverlayEntry>,
    pub latest_by_key: HashMap<QmdbKey, EntryId>,
    pub dirty_order: Vec<EntryId>,
    pub pending_parent_overlays: Vec<Arc<QmdbOverlayCommit>>,
    known_base_values: HashSet<QmdbKey>,
    hashed_addresses: HashMap<Address, B256>,
    hashed_slots: HashMap<U256, B256>,
    generation: u64,
}

impl QmdbOverlayArena {
    pub fn new(anchor: QmdbHead) -> Self {
        Self {
            anchor,
            base_values: HashMap::new(),
            entries: Vec::new(),
            latest_by_key: HashMap::new(),
            dirty_order: Vec::new(),
            pending_parent_overlays: Vec::new(),
            known_base_values: HashSet::new(),
            hashed_addresses: HashMap::new(),
            hashed_slots: HashMap::new(),
            generation: 0,
        }
    }

    pub fn push_parent_overlay(&mut self, overlay: Arc<QmdbOverlayCommit>) {
        self.pending_parent_overlays.push(overlay);
    }

    pub fn insert_raw(
        &mut self,
        key: QmdbKey,
        before: Option<QmdbValue>,
        after: Option<QmdbValue>,
    ) -> EntryId {
        self.insert_with_base(key, before, after, true)
    }

    fn insert_unknown_base(&mut self, key: QmdbKey, after: Option<QmdbValue>) -> EntryId {
        self.insert_with_base(key, None, after, false)
    }

    fn hashed_address(&mut self, address: Address) -> B256 {
        *self
            .hashed_addresses
            .entry(address)
            .or_insert_with(|| keccak256(address))
    }

    fn hashed_slot(&mut self, slot: U256) -> B256 {
        *self
            .hashed_slots
            .entry(slot)
            .or_insert_with(|| keccak256(B256::from(slot)))
    }

    fn insert_with_base(
        &mut self,
        key: QmdbKey,
        before: Option<QmdbValue>,
        after: Option<QmdbValue>,
        base_known: bool,
    ) -> EntryId {
        self.generation += 1;
        let was_known = self.known_base_values.contains(&key);
        let base = if let Some(base) = self.base_values.get_mut(&key) {
            if base_known && !was_known {
                *base = before;
            }
            *base
        } else {
            self.base_values.insert(key, before);
            before
        };
        if base_known {
            self.known_base_values.insert(key);
        }

        if let Some(entry_id) = self.latest_by_key.get(&key).copied() {
            let entry = &mut self.entries[entry_id];
            if base_known && !was_known {
                entry.before = before;
            }
            entry.after = after;
            entry.generation = self.generation;
            return entry_id;
        }

        let entry_id = self.entries.len();
        self.entries.push(QmdbOverlayEntry {
            key,
            before: base,
            after,
            generation: self.generation,
        });
        self.latest_by_key.insert(key, entry_id);
        self.dirty_order.push(entry_id);
        entry_id
    }

    pub fn extend_hashed_state(&mut self, hashed_state: &HashedPostState) {
        for (hashed_address, account) in &hashed_state.accounts {
            let after = account.as_ref().copied().and_then(encode_present_account);
            self.insert_unknown_base(account_key(hashed_address), after);
        }

        for (hashed_address, storage) in &hashed_state.storages {
            for (hashed_slot, value) in &storage.storage {
                let after = encode_present_storage(*value);
                self.insert_unknown_base(storage_key(hashed_address, hashed_slot), after);
            }
        }
    }

    pub fn extend_evm_state(&mut self, state: EvmState) {
        for (address, account) in state {
            if !account.is_touched() {
                continue;
            }

            let hashed_address = self.hashed_address(address);
            if account.info != account.original_info() {
                let before = encode_present_account(account.original_info().into());
                let after = if account.is_selfdestructed() {
                    None
                } else {
                    encode_present_account(account.info.into())
                };
                self.insert_raw(account_key(&hashed_address), before, after);
            }

            for (slot, value) in account.storage {
                if !value.is_changed() {
                    continue;
                }

                let hashed_slot = self.hashed_slot(slot);
                let before = encode_present_storage(value.original_value);
                let after = encode_present_storage(value.present_value);
                self.insert_raw(storage_key(&hashed_address, &hashed_slot), before, after);
            }
        }
    }

    pub fn extend_raw_updates(&mut self, updates: Vec<QmdbRawStateUpdate>) {
        self.base_values.reserve(updates.len());
        self.entries.reserve(updates.len());
        self.latest_by_key.reserve(updates.len());
        self.dirty_order.reserve(updates.len());
        self.known_base_values.reserve(updates.len());

        for update in updates {
            self.insert_raw(
                qmdb_key_from_raw(update.key),
                update.before.map(qmdb_value_from_raw),
                update.after.map(qmdb_value_from_raw),
            );
        }
    }

    fn can_use_flat_mutations(&self) -> bool {
        self.pending_parent_overlays.is_empty()
    }

    fn resolve_base_values(&mut self, qmdb: &QmdbState) -> Result<usize, QmdbError> {
        let mut keys = Vec::new();
        for entry_id in &self.dirty_order {
            let key = self.entries[*entry_id].key;
            if !self.known_base_values.contains(&key) {
                keys.push(key);
            }
        }

        if keys.is_empty() {
            return Ok(0);
        }

        let raw_keys = keys.iter().copied().map(reth_qmdb_key).collect();
        let values = qmdb.get_many(raw_keys)?;
        let read_count = keys.len();
        for (key, value) in keys.into_iter().zip(values) {
            let value = value.map(local_qmdb_value);
            self.known_base_values.insert(key);
            self.base_values.insert(key, value);
            if let Some(entry_id) = self.latest_by_key.get(&key).copied() {
                self.entries[entry_id].before = value;
            }
        }

        Ok(read_count)
    }

    pub fn prefetch_base_values(&mut self, qmdb: &QmdbState) -> Result<usize, QmdbError> {
        if !self.can_use_flat_mutations() {
            return Ok(0);
        }

        self.resolve_base_values(qmdb)
    }

    fn flat_mutations(&self) -> Vec<(QmdbKey, Option<QmdbValue>)> {
        self.dirty_order
            .iter()
            .filter_map(|entry_id| {
                let entry = &self.entries[*entry_id];
                let before = self.base_values.get(&entry.key).copied().unwrap_or(None);
                (entry.after != before).then_some((entry.key, entry.after))
            })
            .collect()
    }

    pub fn compute_root_fast(
        &mut self,
        qmdb: &QmdbState,
    ) -> Result<Option<(Arc<HashedPostState>, QmdbCommit, QmdbRawMutations)>, QmdbError> {
        let Some((commit, mutations)) = self.compute_root_fast_commit(qmdb)? else {
            return Ok(None);
        };
        let hashed_state = Arc::new(self.to_hashed_state()?);
        Ok(Some((hashed_state, commit, mutations)))
    }

    pub fn compute_root_fast_commit(
        &mut self,
        qmdb: &QmdbState,
    ) -> Result<Option<(QmdbCommit, QmdbRawMutations)>, QmdbError> {
        if !self.can_use_flat_mutations() {
            return Ok(None);
        }

        self.resolve_base_values(qmdb)?;
        let mutations: QmdbRawMutations = self
            .flat_mutations()
            .into_iter()
            .map(|(key, value)| (reth_qmdb_key(key), value.map(reth_qmdb_value)))
            .collect();
        let commit = qmdb.overlay_mutations(mutations.clone())?;
        Ok(Some((commit, mutations)))
    }

    pub fn to_hashed_state(&self) -> Result<HashedPostState, QmdbError> {
        self.to_hashed_state_inner(true)
    }

    fn to_current_hashed_state(&self) -> Result<HashedPostState, QmdbError> {
        self.to_hashed_state_inner(false)
    }

    fn to_hashed_state_inner(
        &self,
        include_parent_overlays: bool,
    ) -> Result<HashedPostState, QmdbError> {
        let mut hashed_state = HashedPostState::default();

        if include_parent_overlays {
            for parent in &self.pending_parent_overlays {
                hashed_state.extend_ref(parent.hashed_state.as_ref());
            }
        }

        for entry_id in &self.dirty_order {
            let entry = &self.entries[*entry_id];
            match decode_key(&entry.key)? {
                DecodedQmdbKey::Account(hashed_address) => {
                    let account = entry.after.map(decode_account).transpose()?;
                    hashed_state.accounts.insert(hashed_address, account);
                }
                DecodedQmdbKey::Storage {
                    hashed_address,
                    hashed_slot,
                } => {
                    let storage = hashed_state
                        .storages
                        .entry(hashed_address)
                        .or_insert_with(|| HashedStorage::new(false));
                    let value = entry.after.map(decode_storage).transpose()?;
                    storage
                        .storage
                        .insert(hashed_slot, value.unwrap_or(U256::ZERO));
                }
            }
        }

        Ok(hashed_state)
    }

    pub fn compute_root(&self, qmdb: &QmdbState) -> Result<QmdbOverlayCommit, QmdbError> {
        let hashed_state = Arc::new(self.to_hashed_state()?);
        let QmdbCommit { root, entries } = qmdb.overlay_root(hashed_state.as_ref().clone())?;
        Ok(QmdbOverlayCommit {
            anchor: self.anchor,
            root,
            entries,
            hashed_state,
            mutations: None,
            stats: QmdbRootStats {
                parent_overlays: self.pending_parent_overlays.len(),
                arena_entries: self.entries.len(),
                dirty_keys: self.latest_by_key.len(),
                hashed_accounts: 0,
                hashed_storage_sets: 0,
                overlay_entries: entries,
                ..Default::default()
            },
        })
    }
}

enum DecodedQmdbKey {
    Account(B256),
    Storage {
        hashed_address: B256,
        hashed_slot: B256,
    },
}

fn account_key(hashed_address: &B256) -> QmdbKey {
    let mut key = [0; QMDB_KEY_BYTES];
    key[0] = QMDB_ACCOUNT_TAG;
    key[1..33].copy_from_slice(hashed_address.as_slice());
    QmdbKey::new(key)
}

fn storage_key(hashed_address: &B256, hashed_slot: &B256) -> QmdbKey {
    let mut key = [0; QMDB_KEY_BYTES];
    key[0] = QMDB_STORAGE_TAG;
    key[1..33].copy_from_slice(hashed_address.as_slice());
    key[33..65].copy_from_slice(hashed_slot.as_slice());
    QmdbKey::new(key)
}

fn reth_qmdb_key(key: QmdbKey) -> RethQmdbKey {
    let mut bytes = [0; QMDB_KEY_BYTES];
    bytes.copy_from_slice(key.as_slice());
    RethQmdbKey::new(bytes)
}

fn raw_qmdb_key(key: QmdbKey) -> [u8; QMDB_KEY_BYTES] {
    let mut bytes = [0; QMDB_KEY_BYTES];
    bytes.copy_from_slice(key.as_slice());
    bytes
}

fn qmdb_key_from_raw(bytes: [u8; QMDB_KEY_BYTES]) -> QmdbKey {
    QmdbKey::new(bytes)
}

fn reth_qmdb_value(value: QmdbValue) -> RethQmdbValue {
    let mut bytes = [0; QMDB_VALUE_BYTES];
    bytes.copy_from_slice(value.as_slice());
    RethQmdbValue::new(bytes)
}

fn raw_qmdb_value(value: QmdbValue) -> [u8; QMDB_VALUE_BYTES] {
    let mut bytes = [0; QMDB_VALUE_BYTES];
    bytes.copy_from_slice(value.as_slice());
    bytes
}

fn qmdb_value_from_raw(bytes: [u8; QMDB_VALUE_BYTES]) -> QmdbValue {
    QmdbValue::new(bytes)
}

fn local_qmdb_value(value: RethQmdbValue) -> QmdbValue {
    QmdbValue::from_slice(value.as_ref())
}

fn decode_key(key: &QmdbKey) -> Result<DecodedQmdbKey, QmdbError> {
    let bytes: &[u8] = key.as_ref();
    match bytes[0] {
        QMDB_ACCOUNT_TAG => Ok(DecodedQmdbKey::Account(B256::from_slice(&bytes[1..33]))),
        QMDB_STORAGE_TAG => Ok(DecodedQmdbKey::Storage {
            hashed_address: B256::from_slice(&bytes[1..33]),
            hashed_slot: B256::from_slice(&bytes[33..65]),
        }),
        _ => Err(QmdbError::InvalidStorageKey),
    }
}

fn encode_present_account(account: Account) -> Option<QmdbValue> {
    (!account.is_empty()).then(|| encode_account(account))
}

fn encode_account(account: Account) -> QmdbValue {
    let mut value = [0; QMDB_VALUE_BYTES];
    value[0] = QMDB_ACCOUNT_TAG;
    value[1..9].copy_from_slice(&account.nonce.to_be_bytes());
    value[9..41].copy_from_slice(&account.balance.to_be_bytes::<32>());
    if let Some(bytecode_hash) = account.bytecode_hash {
        value[41] = 1;
        value[42..74].copy_from_slice(bytecode_hash.as_slice());
    }
    QmdbValue::new(value)
}

fn decode_account(value: QmdbValue) -> Result<Account, QmdbError> {
    let bytes: &[u8] = value.as_ref();
    if bytes[0] != QMDB_ACCOUNT_TAG || bytes[41] > 1 {
        return Err(QmdbError::InvalidAccountValue);
    }

    let nonce = u64::from_be_bytes(bytes[1..9].try_into().expect("nonce has fixed size"));
    let balance_bytes: [u8; 32] = bytes[9..41].try_into().expect("balance has fixed size");
    let balance = U256::from_be_bytes(balance_bytes);
    let bytecode_hash = (bytes[41] == 1).then(|| B256::from_slice(&bytes[42..74]));
    Ok(Account {
        nonce,
        balance,
        bytecode_hash,
    })
}

fn encode_present_storage(storage: U256) -> Option<QmdbValue> {
    (!storage.is_zero()).then(|| encode_storage(storage))
}

fn encode_storage(storage: U256) -> QmdbValue {
    let mut value = [0; QMDB_VALUE_BYTES];
    value[0] = QMDB_STORAGE_TAG;
    value[1..33].copy_from_slice(&storage.to_be_bytes::<32>());
    QmdbValue::new(value)
}

fn decode_storage(value: QmdbValue) -> Result<U256, QmdbError> {
    let bytes: &[u8] = value.as_ref();
    if bytes[0] != QMDB_STORAGE_TAG {
        return Err(QmdbError::InvalidStorageValue);
    }
    let storage_bytes: [u8; 32] = bytes[1..33]
        .try_into()
        .expect("storage value has fixed size");
    Ok(U256::from_be_bytes(storage_bytes))
}

fn parent_overlay_commit(
    anchor: QmdbHead,
    hashed_state: Arc<HashedPostState>,
) -> QmdbOverlayCommit {
    QmdbOverlayCommit {
        anchor,
        root: B256::ZERO,
        entries: 0,
        hashed_state: normalize_qmdb_hashed_state_arc(hashed_state),
        mutations: None,
        stats: QmdbRootStats::default(),
    }
}

fn normalize_qmdb_hashed_state(mut hashed_state: HashedPostState) -> HashedPostState {
    for storage in hashed_state.storages.values_mut() {
        storage.wiped = false;
    }
    hashed_state
}

fn normalize_qmdb_hashed_state_arc(hashed_state: Arc<HashedPostState>) -> Arc<HashedPostState> {
    if hashed_state.storages.values().any(|storage| storage.wiped) {
        Arc::new(normalize_qmdb_hashed_state(hashed_state.as_ref().clone()))
    } else {
        hashed_state
    }
}

#[allow(dead_code)]
fn spawn_qmdb_root_handle(
    qmdb: QmdbState,
    anchor: QmdbHead,
    parent_overlays: Vec<Arc<HashedPostState>>,
) -> QmdbRootHandle {
    let (updates_tx, updates_rx) = crossbeam_channel::unbounded();
    let (root_tx, root_rx) = mpsc::channel();
    thread::Builder::new()
        .name("tempo-qmdb-root".to_string())
        .spawn(move || {
            let result = run_qmdb_root_task(qmdb, anchor, parent_overlays, updates_rx);
            let _ = root_tx.send(result);
        })
        .expect("failed to spawn QMDB root task");

    QmdbRootHandle::new(anchor, updates_tx, root_rx)
}

fn spawn_qmdb_state_root_handle(
    qmdb: QmdbState,
    anchor: QmdbHead,
    parent_overlays: Vec<QmdbParentOverlay>,
    pending_blocks: PendingQmdbBlocks,
) -> SharedStateRootHandle {
    let (updates_tx, updates_rx) = crossbeam_channel::unbounded();
    let (root_tx, root_rx) = mpsc::channel();
    let (hashed_state_tx, hashed_state_rx) = mpsc::channel();
    thread::Builder::new()
        .name("tempo-qmdb-shared-root".to_string())
        .spawn(move || {
            let result = run_qmdb_state_root_task(qmdb, anchor, parent_overlays, updates_rx)
                .map(|outcome| {
                    let _ = hashed_state_tx.send(outcome.commit.hashed_state.as_ref().clone());
                    pending_blocks.insert_root_commit(Arc::clone(&outcome.commit));
                    SharedStateRootComputeOutcome {
                        state_root: outcome.root,
                        trie_updates: Arc::new(TrieUpdates::default()),
                        #[cfg(feature = "trie-debug")]
                        debug_recorders: Vec::new(),
                    }
                })
                .map_err(|err| ParallelStateRootError::Other(err.to_string()));
            let _ = root_tx.send(result);
        })
        .expect("failed to spawn QMDB shared root task");

    SharedStateRootHandle::new_with_state_update_encoder(
        anchor.root,
        updates_tx,
        root_rx,
        hashed_state_rx,
        Arc::new(qmdb_raw_state_update_message),
    )
}

fn qmdb_raw_state_update_message(
    _source: StateChangeSource,
    state: &EvmState,
) -> SharedStateRootMessage {
    let mut updates = Vec::with_capacity(state.len().saturating_mul(3));

    for (address, account) in state {
        if !account.is_touched() {
            continue;
        }

        let hashed_address = keccak256(*address);
        if account.info != account.original_info() {
            let before = encode_present_account(account.original_info().into()).map(raw_qmdb_value);
            let after = if account.is_selfdestructed() {
                None
            } else {
                encode_present_account(account.info.clone().into()).map(raw_qmdb_value)
            };
            updates.push(QmdbRawStateUpdate {
                key: raw_qmdb_key(account_key(&hashed_address)),
                before,
                after,
            });
        }

        for (slot, value) in &account.storage {
            if !value.is_changed() {
                continue;
            }

            let hashed_slot = keccak256(B256::from(*slot));
            updates.push(QmdbRawStateUpdate {
                key: raw_qmdb_key(storage_key(&hashed_address, &hashed_slot)),
                before: encode_present_storage(value.original_value).map(raw_qmdb_value),
                after: encode_present_storage(value.present_value).map(raw_qmdb_value),
            });
        }
    }

    SharedStateRootMessage::QmdbRawUpdate(updates)
}

#[allow(dead_code)]
fn run_qmdb_root_task(
    qmdb: QmdbState,
    anchor: QmdbHead,
    parent_overlays: Vec<Arc<HashedPostState>>,
    updates_rx: crossbeam_channel::Receiver<QmdbRootMessage>,
) -> Result<QmdbRootOutcome, QmdbError> {
    let mut arena = QmdbOverlayArena::new(anchor);
    for parent in parent_overlays {
        arena.push_parent_overlay(Arc::new(parent_overlay_commit(anchor, parent)));
    }

    let task_start = Instant::now();
    let mut stats = QmdbRootStats::default();
    while let Ok(message) = updates_rx.recv() {
        match message {
            QmdbRootMessage::StateUpdate(_, state) => {
                stats.state_updates += 1;
                arena.extend_evm_state(state);
            }
            QmdbRootMessage::ParentOverlay(hashed_state) => {
                arena.push_parent_overlay(Arc::new(parent_overlay_commit(anchor, hashed_state)));
            }
            QmdbRootMessage::FinishedStateUpdates => break,
        }
    }
    stats.stream_duration = task_start.elapsed();

    finish_qmdb_root_task(qmdb, arena, Vec::new(), stats, task_start, true)
}

fn run_qmdb_state_root_task(
    qmdb: QmdbState,
    anchor: QmdbHead,
    mut parent_overlays: Vec<QmdbParentOverlay>,
    updates_rx: crossbeam_channel::Receiver<SharedStateRootMessage>,
) -> Result<QmdbRootOutcome, QmdbError> {
    let mut arena = QmdbOverlayArena::new(anchor);

    let task_start = Instant::now();
    let mut stats = QmdbRootStats::default();
    stats.parent_overlays = parent_overlays.len();
    if !parent_overlays.is_empty() {
        arena = effective_qmdb_root_arena(&qmdb, arena, std::mem::take(&mut parent_overlays))?;
    }
    while let Ok(message) = updates_rx.recv() {
        match message {
            SharedStateRootMessage::StateUpdate(_, state) => {
                stats.state_updates += 1;
                arena.extend_evm_state(state);
            }
            SharedStateRootMessage::HashedStateUpdate(hashed_state) => {
                stats.state_updates += 1;
                arena.extend_hashed_state(&hashed_state);
            }
            SharedStateRootMessage::QmdbRawUpdate(updates) => {
                stats.state_updates += 1;
                arena.extend_raw_updates(updates);
            }
            SharedStateRootMessage::PrefetchProofs(_) => {}
            SharedStateRootMessage::BlockAccessList(_) => {
                return Err(QmdbError::Commonware(
                    "QMDB shared root does not support block access list updates yet".to_string(),
                ));
            }
            SharedStateRootMessage::FinishedStateUpdates => break,
        }
    }
    stats.stream_duration = task_start.elapsed();

    finish_qmdb_root_task(qmdb, arena, parent_overlays, stats, task_start, false)
}

fn wait_for_qmdb_head_hash(
    qmdb: &QmdbState,
    fallback_head: QmdbHead,
    target_hash: B256,
) -> Result<QmdbHead, QmdbError> {
    let started = Instant::now();
    loop {
        let durable_head = qmdb.head()?.unwrap_or(fallback_head);
        if durable_head.hash == target_hash {
            return Ok(durable_head);
        }
        if started.elapsed() >= QMDB_PARENT_OVERLAY_WAIT_TIMEOUT {
            return Err(QmdbError::Commonware(format!(
                "QMDB durable head {} did not reach pending parent {} within {:?}",
                durable_head.hash, target_hash, QMDB_PARENT_OVERLAY_WAIT_TIMEOUT
            )));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn effective_qmdb_root_arena(
    qmdb: &QmdbState,
    arena: QmdbOverlayArena,
    parent_overlays: Vec<QmdbParentOverlay>,
) -> Result<QmdbOverlayArena, QmdbError> {
    if parent_overlays.is_empty() {
        return Ok(arena);
    }

    let target_parent_hash = parent_overlays
        .last()
        .expect("parent overlays are not empty")
        .block
        .hash;
    let durable_head = wait_for_qmdb_head_hash(qmdb, arena.anchor, target_parent_hash)?;
    let committed_parent_count = if durable_head.hash == arena.anchor.hash {
        0
    } else {
        let Some(index) = parent_overlays
            .iter()
            .position(|overlay| overlay.block.hash == durable_head.hash)
        else {
            return Err(QmdbError::Commonware(format!(
                "QMDB durable head {} is not the root anchor {} or a pending parent overlay",
                durable_head.hash, arena.anchor.hash
            )));
        };
        index + 1
    };

    let current_state = arena.to_current_hashed_state()?;
    let mut effective = QmdbOverlayArena::new(durable_head);
    for overlay in parent_overlays.into_iter().skip(committed_parent_count) {
        effective.push_parent_overlay(Arc::new(parent_overlay_commit(
            durable_head,
            overlay.hashed_state,
        )));
    }
    effective.extend_hashed_state(&current_state);
    Ok(effective)
}

fn finish_qmdb_root_task(
    qmdb: QmdbState,
    arena: QmdbOverlayArena,
    parent_overlays: Vec<QmdbParentOverlay>,
    mut stats: QmdbRootStats,
    task_start: Instant,
    include_hashed_state: bool,
) -> Result<QmdbRootOutcome, QmdbError> {
    let mut arena = effective_qmdb_root_arena(&qmdb, arena, parent_overlays)?;
    let final_wait_start = Instant::now();
    let (hashed_state, root, entries, mutations) =
        if let Some((QmdbCommit { root, entries }, mutations)) =
            arena.compute_root_fast_commit(&qmdb)?
        {
            let hashed_state = if include_hashed_state {
                Arc::new(arena.to_hashed_state()?)
            } else {
                Arc::new(HashedPostState::default())
            };
            (hashed_state, root, entries, Some(Arc::new(mutations)))
        } else {
            let hashed_state = Arc::new(arena.to_hashed_state()?);
            let QmdbCommit { root, entries } = qmdb.overlay_root(hashed_state.as_ref().clone())?;
            (hashed_state, root, entries, None)
        };
    let flat_mutations = mutations.is_some();
    stats.final_wait_duration = final_wait_start.elapsed();
    stats.total_duration = task_start.elapsed();
    stats.parent_overlays = arena.pending_parent_overlays.len();
    stats.arena_entries = arena.entries.len();
    stats.dirty_keys = arena.latest_by_key.len();
    stats.hashed_accounts = hashed_state.accounts.len();
    stats.hashed_storage_sets = hashed_state.storages.len();
    stats.overlay_entries = entries;

    metrics::histogram!("tempo_qmdb_shared_root_wait_duration_seconds")
        .record(stats.final_wait_duration);
    metrics::histogram!("tempo_qmdb_root_task_total_duration_seconds").record(stats.total_duration);

    debug!(
        target: "tempo::qmdb",
        root = ?root,
        overlay_entries = entries,
        arena_entries = stats.arena_entries,
        dirty_keys = stats.dirty_keys,
        state_updates = stats.state_updates,
        parent_overlays = stats.parent_overlays,
        base_reads = stats.base_reads,
        base_read_ms = stats.base_read_duration.as_secs_f64() * 1000.0,
        flat_mutations,
        final_wait_ms = stats.final_wait_duration.as_secs_f64() * 1000.0,
        total_ms = stats.total_duration.as_secs_f64() * 1000.0,
        "computed QMDB shared state root"
    );

    let commit = Arc::new(QmdbOverlayCommit {
        anchor: arena.anchor,
        root,
        entries,
        hashed_state,
        mutations,
        stats: stats.clone(),
    });

    Ok(QmdbRootOutcome {
        root,
        entries,
        commit,
        stats,
    })
}

/// Lazy QMDB state opener shared across node services.
#[derive(Clone)]
pub struct QmdbStateLoader {
    args: QmdbArgs,
    state: Arc<OnceLock<QmdbState>>,
    pending_blocks: PendingQmdbBlocks,
}

impl Default for QmdbStateLoader {
    fn default() -> Self {
        Self::new(QmdbArgs::default())
    }
}

impl fmt::Debug for QmdbStateLoader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QmdbStateLoader")
            .field("args", &self.args)
            .finish_non_exhaustive()
    }
}

impl QmdbStateLoader {
    /// Creates a QMDB state loader.
    pub fn new(args: QmdbArgs) -> Self {
        Self {
            args,
            state: Arc::new(OnceLock::new()),
            pending_blocks: PendingQmdbBlocks::default(),
        }
    }

    /// Returns the QMDB config for a node config.
    pub fn config_for_node<ChainSpec>(&self, config: &NodeConfig<ChainSpec>) -> QmdbConfig
    where
        ChainSpec: EthChainSpec,
    {
        QmdbConfig::new(config.datadir().data_dir().join("qmdb"))
            .with_partition_prefix(self.args.partition_prefix.clone())
            .with_worker_threads(self.args.qmdb_worker_threads)
    }

    /// Opens the QMDB state store.
    pub fn open<ChainSpec>(&self, config: &NodeConfig<ChainSpec>) -> eyre::Result<QmdbState>
    where
        ChainSpec: EthChainSpec,
    {
        if let Some(state) = self.state.get() {
            debug!(target: "tempo::qmdb", "reusing open QMDB state store");
            return Ok(state.clone());
        }

        let path = config.datadir().data_dir().join("qmdb");
        info!(
            target: "tempo::qmdb",
            path = %path.display(),
            partition_prefix = %self.args.partition_prefix,
            worker_threads = self.args.qmdb_worker_threads,
            "opening QMDB state store"
        );
        let state = QmdbState::open(self.config_for_node(config))?;
        let _ = self.state.set(state);
        Ok(self
            .state
            .get()
            .expect("QMDB state was just initialized")
            .clone())
    }

    /// Opens QMDB and commits genesis if needed.
    pub fn open_initialized<ChainSpec>(
        &self,
        config: &NodeConfig<ChainSpec>,
    ) -> eyre::Result<QmdbState>
    where
        ChainSpec: EthChainSpec,
    {
        let state = self.open(config)?;
        if state.head()?.is_none() {
            let genesis = config.chain.genesis_header();
            info!(
                target: "tempo::qmdb",
                block_number = genesis.number(),
                block_hash = %config.chain.genesis_hash(),
                "initializing QMDB genesis state"
            );
            state.commit_block(
                QmdbBlock {
                    number: genesis.number(),
                    hash: config.chain.genesis_hash(),
                    parent_hash: genesis.parent_hash(),
                },
                genesis_hashed_state(config.chain.genesis()),
            )?;
        } else {
            debug!(target: "tempo::qmdb", "QMDB state store already initialized");
        }
        Ok(state)
    }

    /// Opens initialized QMDB and reconciles it against the canonical DB.
    pub fn open_for_provider<ChainSpec, Provider>(
        &self,
        config: &NodeConfig<ChainSpec>,
        provider: &Provider,
    ) -> eyre::Result<QmdbState>
    where
        ChainSpec: EthChainSpec,
        Provider: BlockNumReader + HeaderProvider,
    {
        let state = self.open_initialized(config)?;
        info!(target: "tempo::qmdb", "reconciling QMDB state store with canonical DB");
        state.reconcile_canonical(provider)?;
        info!(target: "tempo::qmdb", "QMDB state store reconciled");
        Ok(state)
    }

    pub(crate) fn batch_blocks(&self) -> u64 {
        self.args.batch_blocks
    }

    pub(crate) fn pending_blocks(&self) -> PendingQmdbBlocks {
        self.pending_blocks.clone()
    }
}

#[derive(Clone, Debug)]
struct TempoQmdbStateRootProvider<S> {
    inner: QmdbStateRootProvider<S>,
    pending_blocks: PendingQmdbBlocks,
    parent_hash: Option<B256>,
}

impl<S> TempoQmdbStateRootProvider<S> {
    fn new(
        inner: S,
        qmdb: QmdbState,
        pending_blocks: PendingQmdbBlocks,
        parent_hash: Option<B256>,
    ) -> Self {
        Self {
            inner: QmdbStateRootProvider::new(inner, qmdb),
            pending_blocks,
            parent_hash,
        }
    }
}

impl<S> BlockHashReader for TempoQmdbStateRootProvider<S>
where
    QmdbStateRootProvider<S>: BlockHashReader,
{
    fn block_hash(&self, number: BlockNumber) -> ProviderResult<Option<B256>> {
        self.inner.block_hash(number)
    }

    fn canonical_hashes_range(
        &self,
        start: BlockNumber,
        end: BlockNumber,
    ) -> ProviderResult<Vec<B256>> {
        self.inner.canonical_hashes_range(start, end)
    }
}

impl<S> AccountReader for TempoQmdbStateRootProvider<S>
where
    QmdbStateRootProvider<S>: AccountReader,
{
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        self.inner.basic_account(address)
    }
}

impl<S> BytecodeReader for TempoQmdbStateRootProvider<S>
where
    QmdbStateRootProvider<S>: BytecodeReader,
{
    fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        self.inner.bytecode_by_hash(code_hash)
    }
}

impl<S> HashedPostStateProvider for TempoQmdbStateRootProvider<S>
where
    QmdbStateRootProvider<S>: HashedPostStateProvider,
{
    fn hashed_post_state(&self, bundle_state: &reth_revm::db::BundleState) -> HashedPostState {
        self.inner.hashed_post_state(bundle_state)
    }
}

impl<S> StateRootProvider for TempoQmdbStateRootProvider<S> {
    fn state_root(&self, hashed_state: HashedPostState) -> ProviderResult<B256> {
        let hashed_state = if let Some(parent_hash) = self.parent_hash {
            self.pending_blocks.state_for_parent(
                self.inner.qmdb(),
                None,
                parent_hash,
                &hashed_state,
            )?
        } else {
            normalize_qmdb_hashed_state(hashed_state)
        };

        self.inner
            .qmdb()
            .overlay_root(hashed_state)
            .map(|commit| commit.root)
            .map_err(ProviderError::other)
    }

    fn state_root_from_nodes(&self, input: TrieInput) -> ProviderResult<B256> {
        self.state_root(input.state)
    }

    fn state_root_with_updates(
        &self,
        hashed_state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        self.state_root(hashed_state)
            .map(|root| (root, TrieUpdates::default()))
    }

    fn state_root_from_nodes_with_updates(
        &self,
        input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        self.state_root_from_nodes(input)
            .map(|root| (root, TrieUpdates::default()))
    }
}

impl<S> StorageRootProvider for TempoQmdbStateRootProvider<S>
where
    QmdbStateRootProvider<S>: StorageRootProvider,
{
    fn storage_root(&self, address: Address, storage: HashedStorage) -> ProviderResult<B256> {
        self.inner.storage_root(address, storage)
    }

    fn storage_proof(
        &self,
        address: Address,
        slot: B256,
        storage: HashedStorage,
    ) -> ProviderResult<StorageProof> {
        self.inner.storage_proof(address, slot, storage)
    }

    fn storage_multiproof(
        &self,
        address: Address,
        slots: &[B256],
        storage: HashedStorage,
    ) -> ProviderResult<StorageMultiProof> {
        self.inner.storage_multiproof(address, slots, storage)
    }
}

impl<S> StateProofProvider for TempoQmdbStateRootProvider<S>
where
    QmdbStateRootProvider<S>: StateProofProvider,
{
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
        mode: ExecutionWitnessMode,
    ) -> ProviderResult<Vec<Bytes>> {
        self.inner.witness(input, target, mode)
    }
}

impl<S> StateProvider for TempoQmdbStateRootProvider<S>
where
    QmdbStateRootProvider<S>: StateProvider,
{
    fn storage(
        &self,
        account: Address,
        storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        self.inner.storage(account, storage_key)
    }
}

#[derive(Clone, Debug)]
pub struct TempoQmdbStateProviderFactory<P> {
    inner: P,
    qmdb: QmdbState,
    pending_blocks: PendingQmdbBlocks,
}

impl<P> TempoQmdbStateProviderFactory<P> {
    fn new(inner: P, qmdb: QmdbState, pending_blocks: PendingQmdbBlocks) -> Self {
        Self {
            inner,
            qmdb,
            pending_blocks,
        }
    }

    fn wrap(&self, provider: StateProviderBox, parent_hash: Option<B256>) -> StateProviderBox {
        Box::new(TempoQmdbStateRootProvider::new(
            provider,
            self.qmdb.clone(),
            self.pending_blocks.clone(),
            parent_hash,
        ))
    }
}

impl<P: BlockHashReader> BlockHashReader for TempoQmdbStateProviderFactory<P> {
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        self.inner.block_hash(number)
    }

    fn canonical_hashes_range(&self, start: u64, end: u64) -> ProviderResult<Vec<B256>> {
        self.inner.canonical_hashes_range(start, end)
    }
}

impl<P: BlockNumReader> BlockNumReader for TempoQmdbStateProviderFactory<P> {
    fn chain_info(&self) -> ProviderResult<ChainInfo> {
        self.inner.chain_info()
    }

    fn best_block_number(&self) -> ProviderResult<u64> {
        self.inner.best_block_number()
    }

    fn last_block_number(&self) -> ProviderResult<u64> {
        self.inner.last_block_number()
    }

    fn earliest_block_number(&self) -> ProviderResult<u64> {
        self.inner.earliest_block_number()
    }

    fn block_number(&self, hash: B256) -> ProviderResult<Option<u64>> {
        self.inner.block_number(hash)
    }
}

impl<P: BlockIdReader> BlockIdReader for TempoQmdbStateProviderFactory<P> {
    fn pending_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        self.inner.pending_block_num_hash()
    }

    fn safe_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        self.inner.safe_block_num_hash()
    }

    fn finalized_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        self.inner.finalized_block_num_hash()
    }
}

impl<P: ChainSpecProvider> ChainSpecProvider for TempoQmdbStateProviderFactory<P> {
    type ChainSpec = P::ChainSpec;

    fn chain_spec(&self) -> Arc<Self::ChainSpec> {
        self.inner.chain_spec()
    }
}

impl<P: StateProviderFactory> StateProviderFactory for TempoQmdbStateProviderFactory<P> {
    fn latest(&self) -> ProviderResult<StateProviderBox> {
        self.inner
            .latest()
            .map(|provider| self.wrap(provider, None))
    }

    fn state_by_block_number_or_tag(
        &self,
        number_or_tag: alloy_eips::BlockNumberOrTag,
    ) -> ProviderResult<StateProviderBox> {
        self.inner
            .state_by_block_number_or_tag(number_or_tag)
            .map(|provider| self.wrap(provider, None))
    }

    fn history_by_block_number(&self, block: u64) -> ProviderResult<StateProviderBox> {
        self.inner
            .history_by_block_number(block)
            .map(|provider| self.wrap(provider, None))
    }

    fn history_by_block_hash(&self, block: B256) -> ProviderResult<StateProviderBox> {
        self.inner
            .history_by_block_hash(block)
            .map(|provider| self.wrap(provider, Some(block)))
    }

    fn state_by_block_hash(&self, block: B256) -> ProviderResult<StateProviderBox> {
        self.inner
            .state_by_block_hash(block)
            .map(|provider| self.wrap(provider, Some(block)))
    }

    fn pending(&self) -> ProviderResult<StateProviderBox> {
        self.inner
            .pending()
            .map(|provider| self.wrap(provider, None))
    }

    fn pending_state_by_hash(&self, block_hash: B256) -> ProviderResult<Option<StateProviderBox>> {
        self.inner
            .pending_state_by_hash(block_hash)
            .map(|provider| provider.map(|provider| self.wrap(provider, Some(block_hash))))
    }

    fn maybe_pending(&self) -> ProviderResult<Option<StateProviderBox>> {
        self.inner
            .maybe_pending()
            .map(|provider| provider.map(|provider| self.wrap(provider, None)))
    }
}

/// State provider factory used by Tempo payload building.
#[derive(Clone, Debug)]
pub enum TempoStateRootProviderFactory<P> {
    Mpt(P),
    Qmdb(TempoQmdbStateProviderFactory<P>),
}

impl<P> TempoStateRootProviderFactory<P> {
    /// Creates an MPT-backed provider factory.
    pub const fn mpt(provider: P) -> Self {
        Self::Mpt(provider)
    }

    /// Creates a QMDB-backed provider factory.
    pub(crate) fn qmdb(provider: P, qmdb: QmdbState, pending_blocks: PendingQmdbBlocks) -> Self {
        Self::Qmdb(TempoQmdbStateProviderFactory::new(
            provider,
            qmdb,
            pending_blocks,
        ))
    }
}

impl<P: BlockHashReader> BlockHashReader for TempoStateRootProviderFactory<P> {
    fn block_hash(&self, number: u64) -> ProviderResult<Option<alloy_primitives::B256>> {
        match self {
            Self::Mpt(provider) => provider.block_hash(number),
            Self::Qmdb(provider) => provider.block_hash(number),
        }
    }

    fn canonical_hashes_range(
        &self,
        start: u64,
        end: u64,
    ) -> ProviderResult<Vec<alloy_primitives::B256>> {
        match self {
            Self::Mpt(provider) => provider.canonical_hashes_range(start, end),
            Self::Qmdb(provider) => provider.canonical_hashes_range(start, end),
        }
    }
}

impl<P: BlockNumReader> BlockNumReader for TempoStateRootProviderFactory<P> {
    fn chain_info(&self) -> ProviderResult<ChainInfo> {
        match self {
            Self::Mpt(provider) => provider.chain_info(),
            Self::Qmdb(provider) => provider.chain_info(),
        }
    }

    fn best_block_number(&self) -> ProviderResult<u64> {
        match self {
            Self::Mpt(provider) => provider.best_block_number(),
            Self::Qmdb(provider) => provider.best_block_number(),
        }
    }

    fn last_block_number(&self) -> ProviderResult<u64> {
        match self {
            Self::Mpt(provider) => provider.last_block_number(),
            Self::Qmdb(provider) => provider.last_block_number(),
        }
    }

    fn earliest_block_number(&self) -> ProviderResult<u64> {
        match self {
            Self::Mpt(provider) => provider.earliest_block_number(),
            Self::Qmdb(provider) => provider.earliest_block_number(),
        }
    }

    fn block_number(&self, hash: alloy_primitives::B256) -> ProviderResult<Option<u64>> {
        match self {
            Self::Mpt(provider) => provider.block_number(hash),
            Self::Qmdb(provider) => provider.block_number(hash),
        }
    }
}

impl<P: BlockIdReader> BlockIdReader for TempoStateRootProviderFactory<P> {
    fn pending_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        match self {
            Self::Mpt(provider) => provider.pending_block_num_hash(),
            Self::Qmdb(provider) => provider.pending_block_num_hash(),
        }
    }

    fn safe_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        match self {
            Self::Mpt(provider) => provider.safe_block_num_hash(),
            Self::Qmdb(provider) => provider.safe_block_num_hash(),
        }
    }

    fn finalized_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        match self {
            Self::Mpt(provider) => provider.finalized_block_num_hash(),
            Self::Qmdb(provider) => provider.finalized_block_num_hash(),
        }
    }
}

impl<P: ChainSpecProvider> ChainSpecProvider for TempoStateRootProviderFactory<P> {
    type ChainSpec = P::ChainSpec;

    fn chain_spec(&self) -> Arc<Self::ChainSpec> {
        match self {
            Self::Mpt(provider) => provider.chain_spec(),
            Self::Qmdb(provider) => provider.chain_spec(),
        }
    }
}

impl<P: StateProviderFactory> StateProviderFactory for TempoStateRootProviderFactory<P> {
    fn latest(&self) -> ProviderResult<StateProviderBox> {
        match self {
            Self::Mpt(provider) => provider.latest(),
            Self::Qmdb(provider) => provider.latest(),
        }
    }

    fn state_by_block_number_or_tag(
        &self,
        number_or_tag: alloy_eips::BlockNumberOrTag,
    ) -> ProviderResult<StateProviderBox> {
        match self {
            Self::Mpt(provider) => provider.state_by_block_number_or_tag(number_or_tag),
            Self::Qmdb(provider) => provider.state_by_block_number_or_tag(number_or_tag),
        }
    }

    fn history_by_block_number(&self, block: u64) -> ProviderResult<StateProviderBox> {
        match self {
            Self::Mpt(provider) => provider.history_by_block_number(block),
            Self::Qmdb(provider) => provider.history_by_block_number(block),
        }
    }

    fn history_by_block_hash(
        &self,
        block: alloy_primitives::B256,
    ) -> ProviderResult<StateProviderBox> {
        match self {
            Self::Mpt(provider) => provider.history_by_block_hash(block),
            Self::Qmdb(provider) => provider.history_by_block_hash(block),
        }
    }

    fn state_by_block_hash(
        &self,
        block: alloy_primitives::B256,
    ) -> ProviderResult<StateProviderBox> {
        match self {
            Self::Mpt(provider) => provider.state_by_block_hash(block),
            Self::Qmdb(provider) => provider.state_by_block_hash(block),
        }
    }

    fn pending(&self) -> ProviderResult<StateProviderBox> {
        match self {
            Self::Mpt(provider) => provider.pending(),
            Self::Qmdb(provider) => provider.pending(),
        }
    }

    fn pending_state_by_hash(
        &self,
        block_hash: alloy_primitives::B256,
    ) -> ProviderResult<Option<StateProviderBox>> {
        match self {
            Self::Mpt(provider) => provider.pending_state_by_hash(block_hash),
            Self::Qmdb(provider) => provider.pending_state_by_hash(block_hash),
        }
    }

    fn maybe_pending(&self) -> ProviderResult<Option<StateProviderBox>> {
        match self {
            Self::Mpt(provider) => provider.maybe_pending(),
            Self::Qmdb(provider) => provider.maybe_pending(),
        }
    }
}

#[derive(Clone, Debug)]
struct PendingQmdbBlock {
    block: QmdbBlock,
    hashed_state: Arc<HashedPostState>,
    qmdb_commit: Option<Arc<QmdbOverlayCommit>>,
}

#[derive(Clone, Debug)]
struct QmdbParentOverlay {
    block: QmdbBlock,
    hashed_state: Arc<HashedPostState>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct PendingQmdbBlocks {
    inner: Arc<Mutex<PendingQmdbBlocksInner>>,
}

#[derive(Clone, Debug, Default)]
struct PendingQmdbBlocksInner {
    by_hash: HashMap<B256, PendingQmdbBlock>,
    by_root: HashMap<B256, Arc<QmdbOverlayCommit>>,
}

impl PendingQmdbBlocks {
    fn insert_block(
        &self,
        block: QmdbBlock,
        hashed_state: Arc<HashedPostState>,
        qmdb_commit: Option<Arc<QmdbOverlayCommit>>,
    ) {
        let hashed_state = normalize_qmdb_hashed_state_arc(hashed_state);
        let mut inner = self
            .inner
            .lock()
            .expect("pending QMDB blocks mutex poisoned");
        let qmdb_commit = qmdb_commit.or_else(|| {
            inner
                .by_hash
                .get(&block.hash)
                .and_then(|pending| pending.qmdb_commit.clone())
        });
        inner.by_hash.insert(
            block.hash,
            PendingQmdbBlock {
                block,
                hashed_state,
                qmdb_commit,
            },
        );
    }

    fn insert_root_commit(&self, commit: Arc<QmdbOverlayCommit>) {
        if commit.mutations.is_none() {
            return;
        }

        let mut inner = self
            .inner
            .lock()
            .expect("pending QMDB blocks mutex poisoned");
        if inner.by_root.len() >= 4_096
            && let Some(evict) = inner.by_root.keys().next().copied()
        {
            inner.by_root.remove(&evict);
        }
        inner.by_root.insert(commit.root, commit);
    }

    fn take_root_commit(&self, root: B256) -> Option<Arc<QmdbOverlayCommit>> {
        self.inner
            .lock()
            .expect("pending QMDB blocks mutex poisoned")
            .by_root
            .remove(&root)
    }

    fn insert_built_payload(&self, block: &BuiltPayloadExecutedBlock<TempoPrimitives>) {
        let recovered = block.recovered_block.as_ref();
        let header = recovered.header();
        let qmdb_block = QmdbBlock {
            number: header.number(),
            hash: recovered.hash(),
            parent_hash: header.parent_hash(),
        };
        let qmdb_commit = self.take_root_commit(header.state_root());

        self.insert_block(qmdb_block, Arc::clone(&block.hashed_state), qmdb_commit);
    }

    fn insert_executed(&self, block: &ExecutedBlock<TempoPrimitives>) {
        let recovered = block.recovered_block.as_ref();
        let header = recovered.header();
        let qmdb_block = QmdbBlock {
            number: header.number(),
            hash: recovered.hash(),
            parent_hash: header.parent_hash(),
        };
        let qmdb_commit = self.take_root_commit(header.state_root());
        let hashed_state = HashedPostState::from_bundle_state::<KeccakKeyHasher>(
            block.execution_output.state.state.iter(),
        );

        self.insert_block(qmdb_block, Arc::new(hashed_state), qmdb_commit);
    }

    fn cached_commit_for(&self, block_hash: B256) -> Option<Arc<QmdbOverlayCommit>> {
        self.inner
            .lock()
            .expect("pending QMDB blocks mutex poisoned")
            .by_hash
            .get(&block_hash)
            .and_then(|block| block.qmdb_commit.clone())
    }

    fn remove_hash(&self, block_hash: B256) {
        self.inner
            .lock()
            .expect("pending QMDB blocks mutex poisoned")
            .by_hash
            .remove(&block_hash);
    }

    fn remove_committed_through(&self, number: u64) {
        self.inner
            .lock()
            .expect("pending QMDB blocks mutex poisoned")
            .by_hash
            .retain(|_, block| block.block.number > number);
    }

    fn state_for_parent(
        &self,
        qmdb: &QmdbState,
        parent_number: Option<u64>,
        parent_hash: B256,
        current_hashed_state: &HashedPostState,
    ) -> ProviderResult<HashedPostState> {
        if let (Some(parent_number), Some(head)) =
            (parent_number, qmdb.head().map_err(ProviderError::other)?)
            && head.number > parent_number
        {
            info!(
                target: "tempo::qmdb",
                from_block = head.number,
                to_block = parent_number,
                parent_hash = %parent_hash,
                "rewinding QMDB before sidechain state-root validation"
            );
            qmdb.rewind_to_block(parent_number)
                .map_err(ProviderError::other)?;
        }

        let mut ancestors = self.parent_overlays(qmdb, parent_hash)?;
        if !ancestors.is_empty() {
            wait_for_qmdb_head_hash(
                qmdb,
                qmdb.head().map_err(ProviderError::other)?.ok_or_else(|| {
                    ProviderError::other(std::io::Error::other("QMDB head is not initialized"))
                })?,
                parent_hash,
            )
            .map_err(ProviderError::other)?;
            ancestors = self.parent_overlays(qmdb, parent_hash)?;
            if !ancestors.is_empty() {
                return Err(ProviderError::other(std::io::Error::other(format!(
                    "QMDB durable head did not reach parent {parent_hash}"
                ))));
            }
        }
        let ancestor_count = ancestors.len();
        let mut hashed_state = HashedPostState::default();
        for ancestor in ancestors {
            hashed_state.extend_ref(ancestor.hashed_state.as_ref());
        }
        if current_hashed_state
            .storages
            .values()
            .any(|storage| storage.wiped)
        {
            let current_hashed_state = normalize_qmdb_hashed_state(current_hashed_state.clone());
            hashed_state.extend_ref(&current_hashed_state);
        } else {
            hashed_state.extend_ref(current_hashed_state);
        }
        debug!(
            target: "tempo::qmdb",
            parent_hash = %parent_hash,
            pending_ancestors = ancestor_count,
            "computing QMDB overlay root with pending engine state"
        );
        Ok(hashed_state)
    }

    fn parent_overlays(
        &self,
        qmdb: &QmdbState,
        parent_hash: B256,
    ) -> ProviderResult<Vec<QmdbParentOverlay>> {
        let durable_head = qmdb.head().map_err(ProviderError::other)?;
        let durable_hash = durable_head.as_ref().map(|head| head.hash);
        let mut next_parent_hash = parent_hash;
        let mut ancestors = Vec::new();

        {
            let pending = self
                .inner
                .lock()
                .expect("pending QMDB blocks mutex poisoned");
            while Some(next_parent_hash) != durable_hash {
                let Some(block) = pending.by_hash.get(&next_parent_hash) else {
                    let durable = durable_head
                        .as_ref()
                        .map(|head| format!("{} {}", head.number, head.hash))
                        .unwrap_or_else(|| "none".to_string());
                    return Err(ProviderError::other(std::io::Error::other(format!(
                        "missing pending QMDB parent overlay for parent {}; durable head {durable}",
                        next_parent_hash
                    ))));
                };

                ancestors.push(block.clone());
                next_parent_hash = block.block.parent_hash;

                if ancestors.len() > 1_024 {
                    return Err(ProviderError::other(std::io::Error::other(
                        "pending QMDB parent overlay chain exceeded 1024 blocks",
                    )));
                }
            }
        }

        Ok(ancestors
            .into_iter()
            .rev()
            .map(|ancestor| QmdbParentOverlay {
                block: ancestor.block,
                hashed_state: ancestor.hashed_state,
            })
            .collect())
    }

    fn state_for(
        &self,
        qmdb: &QmdbState,
        input: CustomStateRootInput<'_, TempoPrimitives>,
    ) -> ProviderResult<HashedPostState> {
        let block_number = input.block.number();
        let parent_hash = input.block.parent_hash();
        let hashed_state = self.state_for_parent(
            qmdb,
            Some(block_number.saturating_sub(1)),
            parent_hash,
            input.hashed_state.get().as_ref(),
        )?;
        debug!(
            target: "tempo::qmdb",
            block_number,
            parent_hash = %parent_hash,
            "computed QMDB validation state"
        );
        Ok(hashed_state)
    }
}

/// Engine validator wrapper that tracks executed in-memory blocks for QMDB roots.
pub struct TempoQmdbEngineValidator<P, Evm: ConfigureEvm, V> {
    inner: BasicEngineValidator<P, Evm, V>,
    pending_qmdb: Option<PendingQmdbBlocks>,
    qmdb: Option<QmdbState>,
}

impl<P, Evm: ConfigureEvm, V> fmt::Debug for TempoQmdbEngineValidator<P, Evm, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TempoQmdbEngineValidator")
            .field("tracks_pending_qmdb", &self.pending_qmdb.is_some())
            .field("has_qmdb_shared_root", &self.qmdb.is_some())
            .finish_non_exhaustive()
    }
}

impl<P, Evm: ConfigureEvm, V> TempoQmdbEngineValidator<P, Evm, V> {
    fn mpt(inner: BasicEngineValidator<P, Evm, V>) -> Self {
        Self {
            inner,
            pending_qmdb: None,
            qmdb: None,
        }
    }

    fn qmdb(
        inner: BasicEngineValidator<P, Evm, V>,
        qmdb: QmdbState,
        pending_qmdb: PendingQmdbBlocks,
    ) -> Self {
        Self {
            inner,
            pending_qmdb: Some(pending_qmdb),
            qmdb: Some(qmdb),
        }
    }
}

impl<Types, P, Evm, V> EngineValidator<Types, TempoPrimitives>
    for TempoQmdbEngineValidator<P, Evm, V>
where
    Types: PayloadTypes,
    Evm: ConfigureEvm,
    BasicEngineValidator<P, Evm, V>: EngineValidator<Types, TempoPrimitives>,
{
    fn validate_payload_attributes_against_header(
        &self,
        attr: &Types::PayloadAttributes,
        header: &<TempoPrimitives as reth_primitives_traits::NodePrimitives>::BlockHeader,
    ) -> Result<(), InvalidPayloadAttributesError> {
        self.inner
            .validate_payload_attributes_against_header(attr, header)
    }

    fn convert_payload_to_block(
        &self,
        payload: Types::ExecutionData,
    ) -> Result<
        reth_primitives_traits::SealedBlock<
            <TempoPrimitives as reth_primitives_traits::NodePrimitives>::Block,
        >,
        NewPayloadError,
    > {
        self.inner.convert_payload_to_block(payload)
    }

    fn validate_payload(
        &mut self,
        payload: Types::ExecutionData,
        ctx: TreeCtx<'_, TempoPrimitives>,
    ) -> ValidationOutcome<TempoPrimitives> {
        let outcome = self.inner.validate_payload(payload, ctx);
        if let (Some(pending), Ok(output)) = (&self.pending_qmdb, &outcome) {
            pending.insert_executed(&output.executed_block);
        }
        outcome
    }

    fn validate_block(
        &mut self,
        block: reth_primitives_traits::SealedBlock<
            <TempoPrimitives as reth_primitives_traits::NodePrimitives>::Block,
        >,
        ctx: TreeCtx<'_, TempoPrimitives>,
    ) -> ValidationOutcome<TempoPrimitives> {
        let outcome = self.inner.validate_block(block, ctx);
        if let (Some(pending), Ok(output)) = (&self.pending_qmdb, &outcome) {
            pending.insert_executed(&output.executed_block);
        }
        outcome
    }

    fn on_inserted_executed_block(
        &self,
        block: BuiltPayloadExecutedBlock<TempoPrimitives>,
        state: &EngineApiTreeState<TempoPrimitives>,
    ) -> ProviderResult<ExecutedBlock<TempoPrimitives>> {
        if let Some(pending) = &self.pending_qmdb {
            let block_hash = block.recovered_block.as_ref().hash();
            pending.insert_built_payload(&block);
            match self.inner.on_inserted_executed_block(block, state) {
                Ok(executed) => return Ok(executed),
                Err(err) => {
                    pending.remove_hash(block_hash);
                    return Err(err);
                }
            }
        }
        self.inner.on_inserted_executed_block(block, state)
    }

    fn cache_for(&self, block_hash: B256) -> Option<SavedCache> {
        self.inner.cache_for(block_hash)
    }

    fn shared_state_root_handle_for(
        &self,
        parent_hash: B256,
        parent_state_root: B256,
        state: &EngineApiTreeState<TempoPrimitives>,
    ) -> Option<SharedStateRootHandle> {
        if let (Some(qmdb), Some(pending_qmdb)) = (&self.qmdb, &self.pending_qmdb) {
            let anchor = match qmdb.head() {
                Ok(Some(head)) => head,
                Ok(None) => QmdbHead {
                    number: 0,
                    hash: parent_hash,
                    root: parent_state_root,
                },
                Err(err) => {
                    debug!(
                        target: "tempo::qmdb",
                        %err,
                        "unable to create QMDB shared root handle"
                    );
                    return None;
                }
            };

            let parent_overlays = match pending_qmdb.parent_overlays(qmdb, parent_hash) {
                Ok(parent_overlays) => parent_overlays,
                Err(err) => {
                    debug!(
                        target: "tempo::qmdb",
                        %err,
                        parent_hash = %parent_hash,
                        "unable to collect QMDB parent overlays for shared root"
                    );
                    return None;
                }
            };

            debug!(
                target: "tempo::qmdb",
                parent_hash = %parent_hash,
                parent_state_root = ?parent_state_root,
                qmdb_anchor_number = anchor.number,
                qmdb_anchor_hash = %anchor.hash,
                qmdb_anchor_root = ?anchor.root,
                parent_overlays = parent_overlays.len(),
                "spawning QMDB shared root handle"
            );
            return Some(spawn_qmdb_state_root_handle(
                qmdb.clone(),
                anchor,
                parent_overlays,
                pending_qmdb.clone(),
            ));
        }

        self.inner
            .shared_state_root_handle_for(parent_hash, parent_state_root, state)
    }

    fn persistence_save_blocks_hook(&self) -> Option<SaveBlocksHook<TempoPrimitives>> {
        self.inner.persistence_save_blocks_hook()
    }

    fn persistence_remove_blocks_hook(&self) -> Option<RemoveBlocksHook> {
        self.inner.persistence_remove_blocks_hook()
    }
}

impl<P, Evm, V> WaitForCaches for TempoQmdbEngineValidator<P, Evm, V>
where
    Evm: ConfigureEvm,
{
    fn wait_for_caches(&self) -> CacheWaitDurations {
        self.inner.wait_for_caches()
    }
}

/// Engine validator builder that switches to QMDB roots for QMDB chain specs.
#[derive(Debug, Clone)]
pub struct QmdbEngineValidatorBuilder<EV> {
    payload_validator_builder: EV,
    qmdb: QmdbStateLoader,
    state_root_backend: Option<StateRootBackend>,
}

impl<EV> QmdbEngineValidatorBuilder<EV> {
    /// Creates a QMDB-aware engine validator builder.
    pub const fn new(
        payload_validator_builder: EV,
        qmdb: QmdbStateLoader,
        state_root_backend: Option<StateRootBackend>,
    ) -> Self {
        Self {
            payload_validator_builder,
            qmdb,
            state_root_backend,
        }
    }

    fn backend(&self, chain_spec: &TempoChainSpec) -> StateRootBackend {
        StateRootBackend::resolve(self.state_root_backend, chain_spec)
    }
}

impl<Node, EV> EngineValidatorBuilder<Node> for QmdbEngineValidatorBuilder<EV>
where
    Node: FullNodeComponents<
            Evm: ConfigureEngineEvm<
                <<Node::Types as NodeTypes>::Payload as PayloadTypes>::ExecutionData,
            >,
            Types: NodeTypes<ChainSpec = TempoChainSpec, Primitives = TempoPrimitives>,
        >,
    EV: PayloadValidatorBuilder<Node>,
    EV::Validator:
        PayloadValidator<<Node::Types as NodeTypes>::Payload, Block = BlockTy<Node::Types>> + Clone,
{
    type EngineValidator = TempoQmdbEngineValidator<Node::Provider, Node::Evm, EV::Validator>;

    async fn build_tree_validator(
        self,
        ctx: &AddOnsContext<'_, Node>,
        tree_config: TreeConfig,
        changeset_cache: ChangesetCache,
    ) -> eyre::Result<Self::EngineValidator> {
        let backend = self.backend(ctx.config.chain.as_ref());
        let validator = self.payload_validator_builder.build(ctx).await?;

        if !matches!(backend, StateRootBackend::Qmdb) {
            let data_dir = ctx
                .config
                .datadir
                .clone()
                .resolve_datadir(ctx.config.chain.chain());
            let invalid_block_hook = ctx.create_invalid_block_hook(&data_dir).await?;

            return Ok(TempoQmdbEngineValidator::mpt(BasicEngineValidator::new(
                ctx.node.provider().clone(),
                Arc::new(ctx.node.consensus().clone()),
                ctx.node.evm_config().clone(),
                validator,
                tree_config,
                invalid_block_hook,
                changeset_cache,
                ctx.node.task_executor().clone(),
            )));
        }

        let qmdb = self
            .qmdb
            .open_for_provider(ctx.config, ctx.node.provider())?;
        let tree_config = qmdb_engine_tree_config(tree_config);
        info!(
            target: "tempo::qmdb",
            "QMDB engine validator hooks active with immediate tree persistence"
        );
        let pending_qmdb = self.qmdb.pending_blocks();
        let save_pending_qmdb = pending_qmdb.clone();
        let save_qmdb = qmdb.clone();
        let save_blocks_hook: SaveBlocksHook<TempoPrimitives> = Arc::new(move |blocks| {
            let mut qmdb_blocks = Vec::with_capacity(blocks.len());
            let mut mutation_blocks = Vec::with_capacity(blocks.len());
            let mut use_cached_mutations = true;
            let mut last_expected_root = None;
            for block in blocks {
                let recovered = block.recovered_block();
                let header = recovered.header();
                let block_hash = recovered.hash();
                let state_root = header.state_root();
                let qmdb_block = QmdbBlock {
                    number: header.number(),
                    hash: block_hash,
                    parent_hash: header.parent_hash(),
                };

                if use_cached_mutations {
                    let cached = save_pending_qmdb.cached_commit_for(block_hash);
                    match cached.and_then(|commit| {
                        let mutations = commit.mutations.as_ref()?.clone();
                        (commit.root == state_root
                            && commit.anchor.hash == header.parent_hash()
                            && commit.anchor.number.saturating_add(1) == header.number())
                        .then_some(mutations)
                    }) {
                        Some(mutations) => {
                            mutation_blocks.push(QmdbBlockMutations {
                                block: qmdb_block,
                                expected_root: state_root,
                                mutations: mutations.as_ref().clone(),
                            });
                        }
                        None => {
                            use_cached_mutations = false;
                            mutation_blocks.clear();
                        }
                    }
                }

                qmdb_blocks.push((
                    qmdb_block,
                    normalize_qmdb_hashed_state(HashedPostState::from(
                        (*block.hashed_state()).clone(),
                    )),
                ));
                last_expected_root = Some(state_root);
            }
            let first_number = qmdb_blocks.first().map(|(block, _)| block.number);
            let last_number = qmdb_blocks.last().map(|(block, _)| block.number);
            if let Some((first, _)) = qmdb_blocks.first()
                && let Some(head) = save_qmdb.head().map_err(ProviderError::other)?
                && (head.number >= first.number || head.hash != first.parent_hash)
            {
                info!(
                    target: "tempo::qmdb",
                    from_block = first.number.saturating_sub(1),
                    "rewinding QMDB before canonical commit"
                );
                save_qmdb
                    .rewind_to_block(first.number.saturating_sub(1))
                    .map_err(ProviderError::other)?;
            }
            let committed_with_mutations =
                use_cached_mutations && mutation_blocks.len() == qmdb_blocks.len();
            let head = if committed_with_mutations {
                save_qmdb.commit_blocks_mutations(mutation_blocks)
            } else {
                save_qmdb.commit_blocks(qmdb_blocks)
            }
            .map_err(ProviderError::other)?;

            if let (Some(head), Some(last), Some(expected)) =
                (head, last_number, last_expected_root)
                && head.number == last
                && head.root != expected
            {
                return Err(ProviderError::other(QmdbError::CanonicalRootMismatch {
                    number: head.number,
                    expected,
                    actual: head.root,
                }));
            }

            if let (Some(first), Some(last)) = (first_number, last_number) {
                info!(
                    target: "tempo::qmdb",
                    first_block = first,
                    last_block = last,
                    cached_mutations = committed_with_mutations,
                    "committed canonical blocks to QMDB"
                );
            }
            if let Some(last) = last_number {
                save_pending_qmdb.remove_committed_through(last);
            }
            Ok(())
        });

        let remove_qmdb = qmdb.clone();
        let remove_blocks_hook: RemoveBlocksHook = Arc::new(move |new_tip| {
            info!(target: "tempo::qmdb", new_tip, "rewinding QMDB after canonical block removal");
            remove_qmdb
                .rewind_to_block(new_tip)
                .map(|_| ())
                .map_err(ProviderError::other)
        });

        let root_qmdb = qmdb.clone();
        let root_pending_qmdb = pending_qmdb.clone();
        let custom_state_root =
            Arc::new(move |input: CustomStateRootInput<'_, TempoPrimitives>| {
                let hashed_state = root_pending_qmdb.state_for(&root_qmdb, input)?;
                root_qmdb
                    .overlay_root(hashed_state)
                    .map(|commit| (commit.root, TrieUpdates::default()))
                    .map_err(ProviderError::other)
            });

        Ok(TempoQmdbEngineValidator::qmdb(
            BasicEngineValidator::new(
                ctx.node.provider().clone(),
                Arc::new(ctx.node.consensus().clone()),
                ctx.node.evm_config().clone(),
                validator,
                tree_config,
                Box::new(NoopInvalidBlockHook::default()),
                changeset_cache,
                ctx.node.task_executor().clone(),
            )
            .with_custom_state_root(custom_state_root)
            .with_persistence_hooks(Some(save_blocks_hook), Some(remove_blocks_hook)),
            qmdb,
            pending_qmdb,
        ))
    }

    fn customize_pipeline_stages<Provider>(
        &self,
        config: &NodeConfig<<Node::Types as NodeTypes>::ChainSpec>,
        stages: StageSetBuilder<Provider>,
    ) -> eyre::Result<StageSetBuilder<Provider>>
    where
        Provider: HeaderProvider<
                Header = <<Node::Types as NodeTypes>::Primitives as reth_primitives_traits::NodePrimitives>::BlockHeader,
            > + AccountReader
            + ChangeSetReader
            + StorageChangeSetReader
            + StorageReader
            + StateReader
            + BlockNumReader
            + Send
            + 'static,
    {
        if !matches!(self.backend(config.chain.as_ref()), StateRootBackend::Qmdb) {
            return Ok(stages);
        }

        let qmdb = self.qmdb.open_initialized(config)?;
        info!(target: "tempo::qmdb", "installing QMDB stage and disabling MPT state root stages");
        Ok(stages
            .disable_all(&[
                StageId::MerkleUnwind,
                StageId::AccountHashing,
                StageId::StorageHashing,
                StageId::MerkleExecute,
            ])
            .add_after(
                QmdbStage::new(qmdb).with_batch_blocks(self.qmdb.batch_blocks()),
                StageId::Execution,
            ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_head() -> QmdbHead {
        QmdbHead {
            number: 0,
            hash: B256::with_last_byte(1),
            root: B256::with_last_byte(2),
        }
    }

    fn test_account(balance: u64) -> Account {
        Account {
            nonce: balance,
            balance: U256::from(balance),
            bytecode_hash: Some(B256::with_last_byte(balance as u8)),
        }
    }

    fn open_test_qmdb(prefix: &str) -> (tempfile::TempDir, QmdbState, QmdbHead) {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let qmdb = QmdbState::open(
            QmdbConfig::new(tempdir.path())
                .with_partition_prefix(prefix)
                .with_worker_threads(1),
        )
        .expect("QMDB should open");
        let head = qmdb
            .commit_block(
                QmdbBlock {
                    number: 0,
                    hash: B256::with_last_byte(1),
                    parent_hash: B256::ZERO,
                },
                HashedPostState::default(),
            )
            .expect("genesis should commit");

        (tempdir, qmdb, head)
    }

    #[test]
    fn qmdb_overlay_arena_matches_repeated_hot_slot_blocks() {
        let (_tempdir, qmdb, mut head) = open_test_qmdb("arena-hot-slots");
        let token = B256::repeat_byte(0xf0);
        let token_code_hash = B256::repeat_byte(0xf1);
        let slots: Vec<_> = (0..16)
            .map(|index| B256::with_last_byte(index as u8))
            .collect();
        let mut balances = vec![1_000_000u64; slots.len()];
        let mut committed_heads = vec![head];
        let mut committed_blocks = Vec::new();

        for number in 1..=8u64 {
            let mut storage_updates = Vec::with_capacity(400);
            for transfer in 0..200usize {
                let sender = (transfer + number as usize) % 4;
                let recipient = 4 + ((transfer * 7 + number as usize) % (slots.len() - 4));

                balances[sender] = balances[sender].saturating_sub(1);
                balances[recipient] = balances[recipient].saturating_add(1);
                storage_updates.push((slots[sender], U256::from(balances[sender])));
                storage_updates.push((slots[recipient], U256::from(balances[recipient])));
            }

            let mut hashed_state = HashedPostState::default();
            hashed_state.accounts.insert(
                token,
                Some(Account {
                    nonce: number,
                    balance: U256::ZERO,
                    bytecode_hash: Some(token_code_hash),
                }),
            );
            hashed_state
                .storages
                .insert(token, HashedStorage::from_iter(false, storage_updates));

            let expected = qmdb
                .overlay_root(hashed_state.clone())
                .expect("current QMDB overlay root should compute");

            let mut arena = QmdbOverlayArena::new(head);
            arena.extend_hashed_state(&hashed_state);
            let arena_commit = arena
                .compute_root(&qmdb)
                .expect("arena root should compute");
            assert_eq!(
                arena_commit.root, expected.root,
                "arena root diverged at block {number}"
            );

            let mut fast_arena = QmdbOverlayArena::new(head);
            fast_arena.extend_hashed_state(&hashed_state);
            let (fast_commit, fast_mutations) = fast_arena
                .compute_root_fast_commit(&qmdb)
                .expect("fast arena root should compute")
                .expect("flat mutations should be usable without parent overlays");
            assert_eq!(
                fast_commit.root, expected.root,
                "fast arena root diverged at block {number}"
            );
            assert_eq!(fast_mutations.len(), expected.entries);
            assert!(fast_mutations.len() <= slots.len() + 1);

            let block = QmdbBlock {
                number,
                hash: B256::with_last_byte(0xa0 + number as u8),
                parent_hash: head.hash,
            };
            let committed = qmdb
                .commit_block_mutations(block, expected.root, fast_mutations)
                .expect("flat mutations should commit with the expected root");
            assert_eq!(committed.root, expected.root);
            assert_eq!(
                qmdb.head().expect("QMDB head should be readable"),
                Some(committed)
            );

            head = committed;
            committed_heads.push(head);
            committed_blocks.push((block, hashed_state));
        }

        let final_head = head;
        let rewind_head = committed_heads[4];
        let rewound = qmdb
            .rewind_to_block(rewind_head.number)
            .expect("QMDB rewind should succeed")
            .expect("rewound head should exist");
        assert_eq!(rewound, rewind_head);
        assert_eq!(
            qmdb.root().expect("QMDB root should be readable"),
            rewind_head.root
        );

        let replayed = qmdb
            .commit_blocks(committed_blocks[4..].to_vec())
            .expect("replayed QMDB blocks should commit")
            .expect("replayed head should exist");
        assert_eq!(replayed, final_head);
        assert_eq!(
            qmdb.root().expect("QMDB root should be readable"),
            final_head.root
        );
    }

    #[test]
    fn qmdb_overlay_arena_uses_qmdb_key_encoding() {
        let hashed_address = B256::repeat_byte(0x11);
        let hashed_slot = B256::repeat_byte(0x22);

        let account = account_key(&hashed_address);
        let account_bytes: &[u8] = account.as_ref();
        assert_eq!(account_bytes[0], QMDB_ACCOUNT_TAG);
        assert_eq!(&account_bytes[1..33], hashed_address.as_slice());
        assert!(account_bytes[33..].iter().all(|byte| *byte == 0));

        let storage = storage_key(&hashed_address, &hashed_slot);
        let storage_bytes: &[u8] = storage.as_ref();
        assert_eq!(storage_bytes[0], QMDB_STORAGE_TAG);
        assert_eq!(&storage_bytes[1..33], hashed_address.as_slice());
        assert_eq!(&storage_bytes[33..65], hashed_slot.as_slice());
    }

    #[test]
    fn qmdb_overlay_arena_dedupes_mutations_last_write_wins() {
        let mut arena = QmdbOverlayArena::new(test_head());
        let key = storage_key(&B256::repeat_byte(0x33), &B256::repeat_byte(0x44));
        let before = Some(encode_storage(U256::from(1)));

        let first = arena.insert_raw(key, before, Some(encode_storage(U256::from(2))));
        let second = arena.insert_raw(key, Some(encode_storage(U256::from(99))), None);

        assert_eq!(first, second);
        assert_eq!(arena.entries.len(), 1);
        assert_eq!(arena.dirty_order, vec![first]);
        assert_eq!(arena.entries[first].before, before);
        assert_eq!(arena.entries[first].after, None);
    }

    #[test]
    fn qmdb_overlay_arena_preserves_storage_zero_delete() {
        let hashed_address = B256::repeat_byte(0x55);
        let hashed_slot = B256::repeat_byte(0x66);
        let mut hashed_state = HashedPostState::default();
        hashed_state.storages.insert(
            hashed_address,
            HashedStorage::from_iter(false, [(hashed_slot, U256::ZERO)]),
        );

        let mut arena = QmdbOverlayArena::new(test_head());
        arena.extend_hashed_state(&hashed_state);
        let rebuilt = arena.to_hashed_state().expect("arena should rebuild state");
        let storage = rebuilt
            .storages
            .get(&hashed_address)
            .expect("storage update should be present");

        assert!(!storage.wiped);
        assert_eq!(storage.storage.get(&hashed_slot), Some(&U256::ZERO));
    }

    #[test]
    fn qmdb_overlay_arena_treats_empty_accounts_as_deletes() {
        let hashed_address = B256::repeat_byte(0x65);
        let mut hashed_state = HashedPostState::default();
        hashed_state.accounts.insert(
            hashed_address,
            Some(Account {
                nonce: 0,
                balance: U256::ZERO,
                bytecode_hash: None,
            }),
        );

        let mut arena = QmdbOverlayArena::new(test_head());
        arena.extend_hashed_state(&hashed_state);
        let rebuilt = arena.to_hashed_state().expect("arena should rebuild state");

        assert_eq!(rebuilt.accounts.get(&hashed_address), Some(&None));
    }

    #[test]
    fn qmdb_overlay_arena_dedupes_account_delete_then_recreate() {
        let hashed_address = B256::repeat_byte(0x66);
        let key = account_key(&hashed_address);
        let original = Some(encode_account(test_account(1)));
        let recreated = Some(encode_account(test_account(2)));
        let mut arena = QmdbOverlayArena::new(test_head());

        let deleted = arena.insert_raw(key, original, None);
        let recreated_entry = arena.insert_raw(key, None, recreated);

        assert_eq!(deleted, recreated_entry);
        assert_eq!(arena.entries.len(), 1);
        assert_eq!(arena.entries[deleted].before, original);
        assert_eq!(arena.entries[deleted].after, recreated);
    }

    #[test]
    fn qmdb_overlay_arena_root_matches_account_recreation() {
        let (_tempdir, qmdb, head) = open_test_qmdb("arena-account-recreate");
        let hashed_address = B256::repeat_byte(0x67);
        let mut hashed_state = HashedPostState::default();
        hashed_state
            .accounts
            .insert(hashed_address, Some(test_account(1)));
        hashed_state.accounts.insert(hashed_address, None);
        hashed_state
            .accounts
            .insert(hashed_address, Some(test_account(2)));

        let mut arena = QmdbOverlayArena::new(head);
        arena.extend_hashed_state(&hashed_state);
        let arena_commit = arena
            .compute_root(&qmdb)
            .expect("arena account recreation root should compute");
        let direct_commit = qmdb
            .overlay_root(hashed_state)
            .expect("direct QMDB root should compute");

        assert_eq!(arena_commit.root, direct_commit.root);
    }

    #[test]
    fn qmdb_overlay_arena_treats_storage_wipe_as_sparse_update() {
        let hashed_address = B256::repeat_byte(0x77);
        let keep_slot = B256::repeat_byte(0x88);
        let delete_slot = B256::repeat_byte(0x99);
        let mut hashed_state = HashedPostState::default();
        hashed_state.storages.insert(
            hashed_address,
            HashedStorage::from_iter(
                true,
                [(keep_slot, U256::from(7)), (delete_slot, U256::ZERO)],
            ),
        );

        let mut arena = QmdbOverlayArena::new(test_head());
        arena.extend_hashed_state(&hashed_state);
        let rebuilt = arena.to_hashed_state().expect("arena should rebuild state");
        let storage = rebuilt
            .storages
            .get(&hashed_address)
            .expect("storage update should be present");

        assert!(!storage.wiped);
        assert_eq!(storage.storage.get(&keep_slot), Some(&U256::from(7)));
        assert_eq!(storage.storage.get(&delete_slot), Some(&U256::ZERO));
    }

    #[test]
    fn qmdb_overlay_arena_merges_parent_overlays_before_child_updates() {
        let inherited = B256::repeat_byte(0xaa);
        let overwritten = B256::repeat_byte(0xbb);
        let mut parent_state = HashedPostState::default();
        parent_state
            .accounts
            .insert(inherited, Some(test_account(1)));
        parent_state
            .accounts
            .insert(overwritten, Some(test_account(2)));

        let parent = Arc::new(QmdbOverlayCommit {
            anchor: test_head(),
            root: B256::with_last_byte(3),
            entries: 2,
            hashed_state: Arc::new(parent_state),
            mutations: None,
            stats: QmdbRootStats::default(),
        });

        let mut child_state = HashedPostState::default();
        child_state
            .accounts
            .insert(overwritten, Some(test_account(9)));

        let mut arena = QmdbOverlayArena::new(test_head());
        arena.push_parent_overlay(parent);
        arena.extend_hashed_state(&child_state);

        let rebuilt = arena.to_hashed_state().expect("arena should rebuild state");
        assert_eq!(
            rebuilt.accounts.get(&inherited),
            Some(&Some(test_account(1)))
        );
        assert_eq!(
            rebuilt.accounts.get(&overwritten),
            Some(&Some(test_account(9)))
        );
    }

    #[test]
    fn qmdb_overlay_arena_root_matches_qmdb_overlay_root() {
        let (_tempdir, qmdb, head) = open_test_qmdb("arena-root");

        let hashed_address = B256::repeat_byte(0xcc);
        let hashed_slot = B256::repeat_byte(0xdd);
        let mut hashed_state = HashedPostState::default();
        hashed_state
            .accounts
            .insert(hashed_address, Some(test_account(42)));
        hashed_state.storages.insert(
            hashed_address,
            HashedStorage::from_iter(false, [(hashed_slot, U256::from(100))]),
        );

        let mut arena = QmdbOverlayArena::new(head);
        arena.extend_hashed_state(&hashed_state);

        let arena_commit = arena
            .compute_root(&qmdb)
            .expect("arena root should compute successfully");
        let direct_commit = qmdb
            .overlay_root(hashed_state)
            .expect("direct QMDB root should compute successfully");

        assert_eq!(arena_commit.root, direct_commit.root);
        assert_eq!(arena_commit.entries, direct_commit.entries);
    }

    #[test]
    fn qmdb_overlay_arena_fast_root_matches_qmdb_overlay_root() {
        let (_tempdir, qmdb, genesis_head) = open_test_qmdb("arena-fast-root");

        let hashed_address = B256::repeat_byte(0xc1);
        let hashed_slot = B256::repeat_byte(0xd1);
        let mut base_state = HashedPostState::default();
        base_state
            .accounts
            .insert(hashed_address, Some(test_account(40)));
        base_state.storages.insert(
            hashed_address,
            HashedStorage::from_iter(false, [(hashed_slot, U256::from(90))]),
        );
        let head = qmdb
            .commit_block(
                QmdbBlock {
                    number: 1,
                    hash: B256::with_last_byte(11),
                    parent_hash: genesis_head.hash,
                },
                base_state,
            )
            .expect("base block should commit");

        let mut hashed_state = HashedPostState::default();
        hashed_state
            .accounts
            .insert(hashed_address, Some(test_account(42)));
        hashed_state.storages.insert(
            hashed_address,
            HashedStorage::from_iter(false, [(hashed_slot, U256::from(100))]),
        );

        let mut arena = QmdbOverlayArena::new(head);
        arena.extend_hashed_state(&hashed_state);
        let (rebuilt_state, arena_commit, mutations) = arena
            .compute_root_fast(&qmdb)
            .expect("fast arena root should compute")
            .expect("flat mutations should be usable");
        let direct_commit = qmdb
            .overlay_root(hashed_state.clone())
            .expect("direct QMDB root should compute successfully");

        assert_eq!(rebuilt_state.as_ref(), &hashed_state);
        assert_eq!(arena_commit.root, direct_commit.root);
        assert_eq!(arena_commit.entries, direct_commit.entries);
        assert_eq!(mutations.len(), direct_commit.entries);
    }

    #[test]
    fn qmdb_overlay_arena_evm_state_uses_original_values_as_base() {
        let (_tempdir, qmdb, genesis_head) = open_test_qmdb("arena-evm-base");

        let address = Address::repeat_byte(0x42);
        let slot = U256::from(3);
        let hashed_address = keccak256(address);
        let hashed_slot = keccak256(B256::from(slot));
        let code_hash = B256::repeat_byte(0x43);

        let mut base_state = HashedPostState::default();
        base_state.accounts.insert(
            hashed_address,
            Some(Account {
                nonce: 1,
                balance: U256::from(10),
                bytecode_hash: Some(code_hash),
            }),
        );
        base_state.storages.insert(
            hashed_address,
            HashedStorage::from_iter(false, [(hashed_slot, U256::from(20))]),
        );
        let head = qmdb
            .commit_block(
                QmdbBlock {
                    number: 1,
                    hash: B256::with_last_byte(41),
                    parent_hash: genesis_head.hash,
                },
                base_state,
            )
            .expect("base block should commit");

        let mut evm_account = revm_state::Account::default();
        *evm_account.original_info_mut() = revm_state::AccountInfo {
            nonce: 1,
            balance: U256::from(10),
            code_hash,
            ..Default::default()
        };
        evm_account.info = revm_state::AccountInfo {
            nonce: 2,
            balance: U256::from(11),
            code_hash,
            ..Default::default()
        };
        evm_account.storage.insert(
            slot,
            revm_state::EvmStorageSlot::new_changed(
                U256::from(20),
                U256::from(21),
                revm_state::TransactionId::ZERO,
            ),
        );
        evm_account.mark_touch();

        let mut evm_state = EvmState::default();
        evm_state.insert(address, evm_account);

        let mut expected_state = HashedPostState::default();
        expected_state.accounts.insert(
            hashed_address,
            Some(Account {
                nonce: 2,
                balance: U256::from(11),
                bytecode_hash: Some(code_hash),
            }),
        );
        expected_state.storages.insert(
            hashed_address,
            HashedStorage::from_iter(false, [(hashed_slot, U256::from(21))]),
        );

        let mut arena = QmdbOverlayArena::new(head);
        arena.extend_evm_state(evm_state);
        assert_eq!(
            arena
                .prefetch_base_values(&qmdb)
                .expect("prefetch should run"),
            0,
            "EVM state updates should carry known base values"
        );
        let (arena_commit, mutations) = arena
            .compute_root_fast_commit(&qmdb)
            .expect("fast arena root should compute")
            .expect("flat mutations should be usable");
        let direct_commit = qmdb
            .overlay_root(expected_state)
            .expect("direct QMDB root should compute");

        assert_eq!(arena_commit.root, direct_commit.root);
        assert_eq!(mutations.len(), direct_commit.entries);
    }

    #[test]
    fn qmdb_overlay_arena_fast_root_falls_back_for_parent_overlay() {
        let (_tempdir, qmdb, head) = open_test_qmdb("arena-fast-parent");
        let inherited = B256::repeat_byte(0xc4);
        let overwritten = B256::repeat_byte(0xc5);
        let mut parent_state = HashedPostState::default();
        parent_state
            .accounts
            .insert(inherited, Some(test_account(10)));
        parent_state
            .accounts
            .insert(overwritten, Some(test_account(11)));

        let parent = Arc::new(QmdbOverlayCommit {
            anchor: head,
            root: B256::with_last_byte(4),
            entries: 2,
            hashed_state: Arc::new(parent_state.clone()),
            mutations: None,
            stats: QmdbRootStats::default(),
        });

        let mut child_state = HashedPostState::default();
        child_state
            .accounts
            .insert(overwritten, Some(test_account(12)));

        let mut arena = QmdbOverlayArena::new(head);
        arena.push_parent_overlay(parent);
        arena.extend_hashed_state(&child_state);

        assert!(arena.compute_root_fast(&qmdb).unwrap().is_none());
    }

    #[test]
    fn qmdb_overlay_arena_fast_root_filters_noop_writes() {
        let (_tempdir, qmdb, genesis_head) = open_test_qmdb("arena-fast-noop");

        let hashed_address = B256::repeat_byte(0xc2);
        let hashed_slot = B256::repeat_byte(0xd2);
        let mut base_state = HashedPostState::default();
        base_state
            .accounts
            .insert(hashed_address, Some(test_account(7)));
        base_state.storages.insert(
            hashed_address,
            HashedStorage::from_iter(false, [(hashed_slot, U256::from(8))]),
        );
        let head = qmdb
            .commit_block(
                QmdbBlock {
                    number: 1,
                    hash: B256::with_last_byte(12),
                    parent_hash: genesis_head.hash,
                },
                base_state.clone(),
            )
            .expect("base block should commit");

        let mut arena = QmdbOverlayArena::new(head);
        arena.extend_hashed_state(&base_state);
        let (_, arena_commit, mutations) = arena
            .compute_root_fast(&qmdb)
            .expect("fast arena root should compute")
            .expect("flat mutations should be usable");
        let direct_commit = qmdb
            .overlay_root(base_state)
            .expect("direct QMDB root should compute successfully");

        assert_eq!(arena_commit.root, head.root);
        assert_eq!(arena_commit.entries, 0);
        assert!(mutations.is_empty());
        assert_eq!(direct_commit.entries, 0);
        assert_eq!(arena_commit.root, direct_commit.root);
    }

    #[test]
    fn qmdb_overlay_arena_fast_root_handles_explicit_slots_with_wipe_flag() {
        let (_tempdir, qmdb, head) = open_test_qmdb("arena-fast-wipe");
        let hashed_address = B256::repeat_byte(0xc3);
        let hashed_slot = B256::repeat_byte(0xd3);
        let mut hashed_state = HashedPostState::default();
        hashed_state.storages.insert(
            hashed_address,
            HashedStorage::from_iter(true, [(hashed_slot, U256::from(1))]),
        );

        let mut arena = QmdbOverlayArena::new(head);
        arena.extend_hashed_state(&hashed_state);

        let (_, arena_commit, mutations) = arena
            .compute_root_fast(&qmdb)
            .expect("fast arena root should compute")
            .expect("wipe flags are treated as sparse slot updates");
        let direct_commit = qmdb
            .overlay_root(hashed_state)
            .expect("direct QMDB root should compute successfully");

        assert_eq!(arena_commit.root, direct_commit.root);
        assert_eq!(mutations.len(), direct_commit.entries);
    }

    #[test]
    fn qmdb_parent_overlay_normalizes_storage_wipe_flags() {
        let (_tempdir, qmdb, genesis_head) = open_test_qmdb("arena-parent-wipe");

        let hashed_address = B256::repeat_byte(0xc6);
        let slot_a = B256::repeat_byte(0xd6);
        let slot_b = B256::repeat_byte(0xd7);
        let slot_c = B256::repeat_byte(0xd8);
        let mut base_state = HashedPostState::default();
        base_state.storages.insert(
            hashed_address,
            HashedStorage::from_iter(false, [(slot_a, U256::from(11))]),
        );
        let base_block = QmdbBlock {
            number: 1,
            hash: B256::with_last_byte(21),
            parent_hash: genesis_head.hash,
        };
        let anchor_head = qmdb
            .commit_block(base_block, base_state.clone())
            .expect("anchor base block should commit");

        let mut parent_state = HashedPostState::default();
        parent_state.storages.insert(
            hashed_address,
            HashedStorage::from_iter(true, [(slot_b, U256::from(17))]),
        );
        let parent_block = QmdbBlock {
            number: 2,
            hash: B256::with_last_byte(22),
            parent_hash: anchor_head.hash,
        };
        qmdb.commit_block(parent_block, parent_state.clone())
            .expect("parent block should commit");

        let mut child_state = HashedPostState::default();
        child_state.storages.insert(
            hashed_address,
            HashedStorage::from_iter(false, [(slot_c, U256::from(19))]),
        );

        let direct_commit = qmdb
            .overlay_root(child_state.clone())
            .expect("direct child root should compute after parent commit");
        let mut arena = QmdbOverlayArena::new(anchor_head);
        arena.push_parent_overlay(Arc::new(parent_overlay_commit(
            anchor_head,
            Arc::new(parent_state.clone()),
        )));
        arena.extend_hashed_state(&child_state);
        let effective = effective_qmdb_root_arena(
            &qmdb,
            arena,
            vec![QmdbParentOverlay {
                block: parent_block,
                hashed_state: Arc::new(parent_state),
            }],
        )
        .expect("effective arena should wait for and skip committed parent");
        let arena_commit = effective
            .compute_root(&qmdb)
            .expect("arena root should compute on committed parent");

        assert_eq!(arena_commit.root, direct_commit.root);
    }

    #[test]
    fn qmdb_root_handle_merges_parent_overlay_messages() {
        let (_tempdir, qmdb, head) = open_test_qmdb("root-handle");
        let hashed_address = B256::repeat_byte(0xee);
        let mut parent_state = HashedPostState::default();
        parent_state
            .accounts
            .insert(hashed_address, Some(test_account(11)));

        let mut handle = spawn_qmdb_root_handle(qmdb.clone(), head, Vec::new());
        handle
            .updates_tx()
            .send(QmdbRootMessage::ParentOverlay(Arc::new(
                parent_state.clone(),
            )))
            .expect("parent overlay should send");
        handle
            .updates_tx()
            .send(QmdbRootMessage::FinishedStateUpdates)
            .expect("finish should send");

        let outcome = handle.state_root().expect("QMDB root task should finish");
        let direct = qmdb
            .overlay_root(parent_state)
            .expect("direct QMDB root should compute");

        assert_eq!(handle.anchor, head);
        assert_eq!(outcome.root, direct.root);
        assert_eq!(outcome.entries, direct.entries);
        assert_eq!(outcome.commit.root, direct.root);
        assert_eq!(outcome.commit.entries, direct.entries);
        assert_eq!(outcome.stats.overlay_entries, direct.entries);
    }

    #[test]
    fn qmdb_shared_state_root_handle_accepts_hashed_state_updates() {
        let (_tempdir, qmdb, head) = open_test_qmdb("shared-root-handle");
        let hashed_address = B256::repeat_byte(0xef);
        let hashed_slot = B256::repeat_byte(0xfe);
        let mut hashed_state = HashedPostState::default();
        hashed_state
            .accounts
            .insert(hashed_address, Some(test_account(12)));
        hashed_state.storages.insert(
            hashed_address,
            HashedStorage::from_iter(false, [(hashed_slot, U256::from(12))]),
        );

        let pending_blocks = PendingQmdbBlocks::default();
        let mut handle =
            spawn_qmdb_state_root_handle(qmdb.clone(), head, Vec::new(), pending_blocks.clone());
        handle
            .updates_tx()
            .send(SharedStateRootMessage::HashedStateUpdate(
                hashed_state.clone(),
            ))
            .expect("hashed state should send");
        handle
            .updates_tx()
            .send(SharedStateRootMessage::FinishedStateUpdates)
            .expect("finish should send");

        let outcome = handle
            .state_root()
            .expect("state root handle should receive an outcome");
        let direct = qmdb
            .overlay_root(hashed_state)
            .expect("direct QMDB root should compute");

        assert_eq!(outcome.state_root, direct.root);
        let cached = pending_blocks
            .inner
            .lock()
            .expect("pending QMDB blocks mutex poisoned")
            .by_root
            .get(&direct.root)
            .cloned()
            .expect("shared root task should cache flat QMDB mutations");
        assert_eq!(cached.root, direct.root);
        assert_eq!(
            cached
                .mutations
                .as_ref()
                .expect("cached commit should contain mutations")
                .len(),
            direct.entries
        );
    }

    #[test]
    fn qmdb_engine_config_enables_qmdb_shared_root_payload_builder() {
        let tree_config = qmdb_engine_tree_config(
            TreeConfig::default()
                .with_persistence_threshold(1)
                .with_memory_block_buffer_target(24)
                .with_share_sparse_trie_with_payload_builder(false)
                .with_suppress_persistence_during_build(true),
        );

        assert_eq!(
            tree_config.persistence_threshold(),
            QMDB_ENGINE_PERSISTENCE_THRESHOLD
        );
        assert_eq!(
            tree_config.memory_block_buffer_target(),
            QMDB_ENGINE_MEMORY_BLOCK_BUFFER_TARGET
        );
        assert!(tree_config.share_sparse_trie_with_payload_builder());
        assert!(!tree_config.suppress_persistence_during_build());

        let mut engine = EngineArgs {
            persistence_threshold: 42,
            memory_block_buffer_target: 24,
            share_sparse_trie_with_payload_builder: false,
            suppress_persistence_during_build: true,
            ..Default::default()
        };
        configure_qmdb_engine_args(&mut engine);

        assert_eq!(
            engine.persistence_threshold,
            QMDB_ENGINE_PERSISTENCE_THRESHOLD
        );
        assert_eq!(
            engine.memory_block_buffer_target,
            QMDB_ENGINE_MEMORY_BLOCK_BUFFER_TARGET
        );
        assert!(engine.share_sparse_trie_with_payload_builder);
        assert!(!engine.suppress_persistence_during_build);
    }
}
