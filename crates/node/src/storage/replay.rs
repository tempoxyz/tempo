use super::backend::ReplayStorage;
use alloy_primitives::{B256, U256, keccak256};
use reth_chainspec::EthChainSpec;
use reth_db_api::{
    DatabaseError, cursor::DbCursorRO, models::StoredBlockBodyIndices, tables, transaction::DbTx,
};
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{
    BlockHashReader, HeaderProvider, ProviderError, TransactionsProvider,
    providers::StaticFileProviderBuilder,
};
use std::{
    path::Path,
    sync::{Arc, Mutex, Weak},
};
use tempo_chainspec::{TempoChainSpec, TempoHardforks};
use tempo_precompiles::{
    EXPIRING_NONCE_PRECOMPILE_ADDRESS,
    expiring_nonce::ExpiringNonceManager,
    storage::{Handler, StorageCtx},
};
use tempo_primitives::TempoPrimitives;

/// Hashed slot keys, ordered for storage cursor seeks. Cloning shares unmodified tree nodes.
pub(super) type Slots = imbl::OrdMap<B256, U256>;

#[derive(Clone, Debug)]
pub(super) struct Snapshot {
    pub number: u64,
    pub hash: B256,
    pub slots: Slots,
    pub(super) deployed: bool,
}

/// Retains the latest snapshot and, during commit preparation, its predecessor.
/// Transactions lease immutable snapshots; weak references let concurrent readers
/// reuse older versions until their last lease ends.
#[derive(Default, Debug)]
pub(super) struct Published {
    latest: Option<Arc<Snapshot>>,
    // Keep the still-visible state available while its successor is prepared
    // but the persistence transaction has not committed yet.
    pending_base: Option<Arc<Snapshot>>,
    leased: Vec<Weak<Snapshot>>,
    pub computations: u64,
    pub replayed_blocks: u64,
}

/// Publication is separate from computation: readers can lease a published
/// snapshot while the sole writer is preparing its successor.
#[derive(Default, Debug)]
pub(super) struct Cache {
    pub(super) computation: Mutex<()>,
    pub(super) published: Mutex<Published>,
}

/// These cursors retain the originating database view without opening another
/// transaction. They are read only when a cursor actually touches replay storage.
pub(super) struct Source {
    number: u64,
    hashes: Mutex<Box<dyn DbCursorRO<tables::HeaderNumbers> + Send>>,
    bodies: Mutex<Box<dyn DbCursorRO<tables::BlockBodyIndices> + Send>>,
}
impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Source")
            .field("number", &self.number)
            .finish_non_exhaustive()
    }
}
impl Source {
    pub(super) fn new(tx: &(impl DbTx + 'static), genesis: u64) -> Result<Self, DatabaseError> {
        Ok(Self {
            number: tx
                .get::<tables::StageCheckpoints>("Finish".to_owned())?
                .map_or(genesis, |finish| finish.block_number.max(genesis)),
            hashes: Mutex::new(Box::new(tx.cursor_read::<tables::HeaderNumbers>()?)),
            bodies: Mutex::new(Box::new(tx.cursor_read::<tables::BlockBodyIndices>()?)),
        })
    }
    fn header_number(&self, hash: B256) -> Result<Option<u64>, DatabaseError> {
        Ok(self
            .hashes
            .lock()
            .unwrap()
            .seek_exact(hash)?
            .map(|(_, number)| number))
    }
    fn body(&self, number: u64) -> Result<Option<StoredBlockBodyIndices>, DatabaseError> {
        Ok(self
            .bodies
            .lock()
            .unwrap()
            .seek_exact(number)?
            .map(|(_, body)| body))
    }
}

impl Snapshot {
    fn canonical(&self, tx: &Source, genesis: u64) -> Result<bool, DatabaseError> {
        Ok(self.number == genesis || tx.header_number(self.hash)? == Some(self.number))
    }
}

fn error(err: impl std::fmt::Display) -> DatabaseError {
    DatabaseError::Other(format!("derived replay storage: {err}"))
}

impl Published {
    pub(super) fn find(
        &mut self,
        tx: &Source,
        genesis: u64,
    ) -> Result<Option<Arc<Snapshot>>, DatabaseError> {
        self.leased.retain(|state| state.strong_count() != 0);
        for state in self
            .latest
            .iter()
            .cloned()
            .chain(self.leased.iter().filter_map(Weak::upgrade))
        {
            if state.number == tx.number && state.canonical(tx, genesis)? {
                return Ok(Some(state));
            }
        }
        Ok(None)
    }
}

impl Cache {
    pub(super) fn get(
        &self,
        tx: &Source,
        chain: &TempoChainSpec,
        path: &Path,
    ) -> Result<Arc<Snapshot>, DatabaseError> {
        let genesis = chain.genesis_header().number();
        let number = tx.number;
        if let Some(state) = self.published.lock().unwrap().find(tx, genesis)? {
            return Ok(state);
        }
        let started = std::time::Instant::now();
        let _guard = self.computation.lock().unwrap();
        metrics::histogram!("tempo_replay_cache_wait_seconds")
            .record(started.elapsed().as_secs_f64());
        self.compute(tx, chain, path, number)
    }

    pub(super) fn prepare(
        &self,
        tx: &(impl DbTx + 'static),
        chain: &TempoChainSpec,
        path: &Path,
    ) -> Result<(), DatabaseError> {
        let _guard = self.computation.lock().unwrap();
        {
            let mut published = self.published.lock().unwrap();
            published.pending_base = published.latest.clone();
        }
        let source = Source::new(tx, chain.genesis_header().number())?;
        self.compute(&source, chain, path, source.number)?;
        Ok(())
    }

    pub(super) fn persisted(&self) {
        let previous = self.published.lock().unwrap().pending_base.take();
        drop(previous);
    }

    // Called only with the computation lock held. Recheck after waiting, and
    // publish only complete states; a failed replay leaves the cache usable.
    fn compute(
        &self,
        tx: &Source,
        chain: &TempoChainSpec,
        path: &Path,
        number: u64,
    ) -> Result<Arc<Snapshot>, DatabaseError> {
        let genesis_number = chain.genesis_header().number();
        if let Some(state) = self.published.lock().unwrap().find(tx, genesis_number)? {
            return Ok(state);
        }
        let started = std::time::Instant::now();
        let latest = self.published.lock().unwrap().latest.clone();
        let base = latest
            .as_ref()
            .filter(|state| state.number < number)
            .map(|state| {
                state
                    .canonical(tx, genesis_number)
                    .map(|ok| ok.then(|| state.as_ref().clone()))
            })
            .transpose()?
            .flatten();
        let mut state = base.unwrap_or_else(|| {
            let account = chain
                .genesis()
                .alloc
                .get(&EXPIRING_NONCE_PRECOMPILE_ADDRESS);
            Snapshot {
                number: genesis_number,
                hash: chain.genesis_hash(),
                slots: account
                    .and_then(|a| a.storage.as_ref())
                    .into_iter()
                    .flatten()
                    .filter(|(_, value)| !value.is_zero())
                    .map(|(key, value)| (keccak256(key), U256::from_be_slice(value.as_slice())))
                    .collect(),
                deployed: account
                    .and_then(|a| a.code.as_ref())
                    .is_some_and(|code| !code.is_empty()),
            }
        });
        let start = state.number;
        if number > start {
            // MDBX readers prevent reorg truncation of these files. The canonical hash index
            // belongs to the same MDBX view as Finish, including for old read transactions.
            let source = StaticFileProviderBuilder::read_only(path)
                .with_genesis_block_number(genesis_number)
                .build::<TempoPrimitives>()
                .map_err(error)?;
            let mut storage = ReplayStorage::new(chain.chain().id(), state.slots);
            for block in start + 1..=number {
                let header = source
                    .header_by_number(block)
                    .map_err(error)?
                    .ok_or_else(|| error(format!("missing header {block}")))?;
                let spec = chain.tempo_hardfork_at(header.timestamp());
                let body = tx
                    .body(block)?
                    .ok_or_else(|| error(format!("missing body indices {block}")))?;
                let transactions = source
                    .transactions_by_tx_range(body.tx_num_range())
                    .map_err(error)?;
                if transactions.len() as u64 != body.tx_count {
                    return Err(error(format!("incomplete transactions for block {block}")));
                }
                // Read senders with one static-file cursor per block, rather than
                // reopening a cursor for every expiring-nonce transaction.
                let senders = if spec.is_t1b() && body.tx_count != 0 {
                    match source.senders_by_tx_range(body.tx_num_range()) {
                        Ok(senders) if senders.len() == transactions.len() => senders,
                        Ok(_) | Err(ProviderError::MissingStaticFileTx(_, _)) => Vec::new(),
                        Err(err) => return Err(error(err)),
                    }
                } else {
                    Vec::new()
                };
                storage.env.set_block_number(block);
                storage.env.set_timestamp(U256::from(header.timestamp()));
                storage.env.set_spec(spec);
                StorageCtx::enter(&mut storage, || -> Result<(), DatabaseError> {
                    let mut manager = ExpiringNonceManager::new();
                    if !state.deployed {
                        manager.oldest_unpruned_block.write(block).map_err(error)?;
                        state.deployed = true;
                    }
                    manager.prune().map_err(error)?;
                    for (index, transaction) in transactions.into_iter().enumerate() {
                        let Some(signed) = transaction.as_aa() else {
                            continue;
                        };
                        if !spec.is_t1() || !signed.tx().is_expiring_nonce_tx() {
                            continue;
                        }
                        let hash = if spec.is_t1b() {
                            match senders.get(index) {
                                Some(sender) => signed.expiring_nonce_hash(*sender),
                                None => signed
                                    .recover_signer_with_expiring_nonce_hash()
                                    .map_err(error)?
                                    .1
                                    .ok_or_else(|| error("missing replay hash"))?,
                            }
                        } else {
                            *signed.hash()
                        };
                        let expiry = signed
                            .tx()
                            .valid_before
                            .ok_or_else(|| error("missing expiry"))?;
                        manager
                            .check_and_mark_expiring_nonce(hash, expiry.get())
                            .map_err(error)?;
                    }
                    Ok(())
                })?;
            }
            state.slots = storage.slots;
            state.number = number;
            state.hash = source
                .block_hash(number)
                .map_err(error)?
                .ok_or_else(|| error("missing tip hash"))?;
            if !state.canonical(tx, genesis_number)? {
                return Err(error("static-file tip does not match database snapshot"));
            }
        }
        let mut published = self.published.lock().unwrap();
        published.computations += 1;
        published.replayed_blocks += number - start;
        metrics::counter!("tempo_replay_cache_blocks_total").increment(number - start);
        metrics::histogram!("tempo_replay_cache_compute_seconds")
            .record(started.elapsed().as_secs_f64());
        let state = Arc::new(state);
        if let Some(previous) = published.latest.replace(state.clone()) {
            published.leased.push(Arc::downgrade(&previous));
        }
        Ok(state)
    }
}
