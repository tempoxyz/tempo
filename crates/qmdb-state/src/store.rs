//! The QMDB database, its unapplied per-block batches, and the thread that runs them.

use std::{
    collections::HashMap,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    path::PathBuf,
    sync::{Arc, mpsc},
    thread::JoinHandle,
};

use alloy_primitives::B256;
use commonware_cryptography::{Hasher, Sha256};
use commonware_parallel::Rayon;
use commonware_runtime::{
    Runner as _, Strategizer as _, Supervisor as _,
    buffer::paged::CacheRef,
    tokio::{Config as RuntimeConfig, Context, Runner},
};
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig,
    merkle::{full::Config as MerkleConfig, mmb},
    qmdb::{
        self,
        any::ordered::fixed::Update,
        current::{FixedConfig, batch::MerkleizedBatch, ordered::fixed::partitioned},
    },
    translator::EightCap,
};
use futures::{StreamExt as _, channel::mpsc as async_mpsc};
use tracing::{debug, error};

use crate::layout::{self, Key, Value, Write};

type Family = mmb::Family;
/// Bitmap chunk size in bytes of the `current` layer.
const CHUNK: usize = 32;
/// Index partitions are selected by the first two key bytes (65,536 partitions).
const PARTITION_BYTES: usize = 2;
const PAGE_SIZE: NonZeroU16 = NonZeroU16::new(16_384).expect("non-zero");
const ITEMS_PER_BLOB: NonZeroU64 = NonZeroU64::new(1 << 23).expect("non-zero");
const IO_BUFFER: NonZeroUsize = NonZeroUsize::new(2 << 20).expect("non-zero");

type Db =
    partitioned::Db<Family, Context, Key, Value, Sha256, EightCap, PARTITION_BYTES, CHUNK, Rayon>;
type Batch =
    Arc<MerkleizedBatch<Family, <Sha256 as Hasher>::Digest, Update<Key, Value>, CHUNK, Rayon>>;
type Reply<T> = Box<dyn FnOnce(Result<T, Error>) + Send>;

/// Configuration of a [`Store`].
#[derive(Clone, Debug)]
pub struct Config {
    /// Directory holding the database files.
    pub directory: PathBuf,
    /// Threads that merkleize batches and rebuild the index on open.
    pub threads: NonZeroUsize,
    /// Pages of the database's own page cache, each 16 KiB.
    pub page_cache_pages: NonZeroUsize,
    /// Most unapplied batches kept in memory. Building another fails with
    /// [`Error::TooManyPending`] until finalization applies some.
    pub max_pending: NonZeroUsize,
}

/// The block a batch belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockRef {
    /// Block number, committed as the batch's metadata.
    pub number: u64,
    /// Block hash, which later batches name as their parent.
    pub hash: B256,
    /// Hash of the parent block.
    pub parent_hash: B256,
}

/// A block's merkleized QMDB batch, not yet applied to disk.
///
/// Cheap to clone. The engine carries it on the block as its reth `BlockExt`, so the
/// persistence hook applies exactly the batch the block was validated with.
#[derive(Clone)]
pub struct QmdbBatch {
    number: u64,
    parent_hash: B256,
    batch: Batch,
}

impl QmdbBatch {
    /// Number of the block the batch belongs to.
    pub const fn number(&self) -> u64 {
        self.number
    }

    /// State root of the block.
    pub fn root(&self) -> B256 {
        digest_to_b256(self.batch.root())
    }
}

impl std::fmt::Debug for QmdbBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QmdbBatch")
            .field("number", &self.number)
            .field("parent_hash", &self.parent_hash)
            .field("root", &self.root())
            .finish()
    }
}

/// Snapshot of a [`Store`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    /// Number of the last block applied to disk, `None` before the import.
    pub applied: Option<u64>,
    /// Hash of the last applied block, `None` until [`Store::set_base`] or a finalization binds it.
    pub base: Option<B256>,
    /// Root of the applied state: the state root of block `applied`.
    pub root: B256,
    /// Unapplied batches held in memory.
    pub pending: usize,
}

/// Error of a [`Store`] operation.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The database failed.
    #[error("qmdb failed")]
    Qmdb(#[from] qmdb::Error<Family>),
    /// The parent of a block has neither a batch nor is the applied block.
    #[error("parent {parent_hash} of block {number} ({hash}) has no batch")]
    UnknownParent {
        /// Number of the block.
        number: u64,
        /// Hash of the block.
        hash: B256,
        /// Hash of its parent.
        parent_hash: B256,
    },
    /// No batch exists for a block.
    #[error("block {0} has no batch")]
    UnknownBlock(B256),
    /// A batch was built for a block at or below the applied block.
    #[error("block {number} is at or below the applied block {applied}")]
    AlreadyApplied {
        /// Number of the block.
        number: u64,
        /// Number of the applied block.
        applied: u64,
    },
    /// [`Config::max_pending`] unapplied batches are held already.
    #[error("{0} unapplied batches are held, the configured bound")]
    TooManyPending(usize),
    /// A snapshot was imported into a database that already holds state.
    #[error("the database already holds state up to block {0}")]
    NotEmpty(u64),
    /// A block was built before the applied block's hash was bound.
    #[error("the applied block's hash is not bound; call set_base first")]
    NoBase,
    /// The store thread stopped, so the operation did not run.
    #[error("the store thread stopped")]
    Stopped,
}

/// Handle to the QMDB state, run on its own commonware runtime thread.
///
/// Blocks build on their parents' unapplied batches in memory. [`Self::finalize`] applies them
/// to disk and drops the batches of forks that can no longer become canonical.
#[derive(Debug)]
pub struct Store {
    commands: async_mpsc::UnboundedSender<Command>,
    thread: Option<JoinHandle<()>>,
}

impl Store {
    /// Opens or creates the database in [`Config::directory`] and starts its thread.
    pub fn open(config: Config) -> Result<Self, Error> {
        let (commands, receiver) = async_mpsc::unbounded();
        let (opened_tx, opened_rx) = mpsc::channel();
        let runtime = RuntimeConfig::new().with_storage_directory(config.directory.clone());
        let thread = std::thread::Builder::new()
            .name("qmdb-state".into())
            .spawn(move || {
                Runner::new(runtime).start(|context| async move {
                    match Actor::init(context, &config).await {
                        Ok(actor) => {
                            if opened_tx.send(Ok(())).is_ok() {
                                actor.run(receiver).await;
                            }
                        }
                        Err(err) => {
                            // The receiver only disconnects if `open` already returned.
                            if let Err(mpsc::SendError(Err(err))) = opened_tx.send(Err(err)) {
                                error!(%err, "QMDB failed to open after its caller gave up");
                            }
                        }
                    }
                })
            })
            .expect("spawning a thread only fails when the OS is out of resources");
        opened_rx.recv().map_err(|_| Error::Stopped)??;
        Ok(Self {
            commands,
            thread: Some(thread),
        })
    }

    /// Returns the applied block, its root and the number of unapplied batches.
    pub fn status(&self) -> Result<Status, Error> {
        self.call(|reply| Command::Status { reply })
    }

    /// Binds `hash` as the hash of the applied block, so blocks can build on it.
    ///
    /// Call after opening or importing, with the canonical hash of [`Status::applied`]: the
    /// metadata on disk holds only the block number.
    pub fn set_base(&self, hash: B256) -> Result<(), Error> {
        self.call(|reply| Command::SetBase { hash, reply })
    }

    /// Builds the batch of `block` from its sorted `writes`, registers it under the block's hash,
    /// and returns it.
    ///
    /// Blocks until the batch is merkleized. Building a block again replaces its batch.
    pub fn build(&self, block: BlockRef, writes: Vec<Write>) -> Result<QmdbBatch, Error> {
        self.call(|reply| Command::Build {
            block,
            writes,
            reply,
        })
    }

    /// Builds the batch of a block whose hash is not known yet, without registering it.
    ///
    /// The payload builder needs the root to assemble the header, which fixes the hash; it then
    /// calls [`Self::register`] so children can build on the block.
    pub fn build_unregistered(
        &self,
        number: u64,
        parent_hash: B256,
        writes: Vec<Write>,
    ) -> Result<QmdbBatch, Error> {
        self.call(|reply| Command::BuildUnregistered {
            number,
            parent_hash,
            writes,
            reply,
        })
    }

    /// Registers `batch` as the batch of block `hash`, replacing any earlier one.
    pub fn register(&self, hash: B256, batch: QmdbBatch) -> Result<(), Error> {
        self.call(|reply| Command::Register { hash, batch, reply })
    }

    /// Like [`Self::build`], but returns at once and passes the outcome to `on_done` on the store
    /// thread. Blocks build in the order they are sent.
    pub fn build_detached(
        &self,
        block: BlockRef,
        writes: Vec<Write>,
        on_done: impl FnOnce(Result<B256, Error>) + Send + 'static,
    ) -> Result<(), Error> {
        self.send(Command::Build {
            block,
            writes,
            reply: Box::new(move |result| on_done(result.map(|batch| batch.root()))),
        })
    }

    /// Returns the state root of an unapplied block, or of the applied block, if known.
    pub fn root(&self, hash: B256) -> Result<Option<B256>, Error> {
        self.call(|reply| Command::Root { hash, reply })
    }

    /// Applies the batches up to block `hash` to disk, commits them, and drops batches that do
    /// not descend from it.
    ///
    /// Finalizing the applied block again does nothing.
    pub fn finalize(&self, hash: B256) -> Result<(), Error> {
        self.call(|reply| Command::Finalize { hash, reply })
    }

    /// Applies one chunk of a snapshot import directly to disk.
    ///
    /// `writes` must be sorted and above every key of earlier chunks. The final chunk passes
    /// `end`, the snapshot block's number, which commits it as the applied block. Fails with
    /// [`Error::NotEmpty`] once a block is applied.
    pub fn import_chunk(&self, writes: Vec<Write>, end: Option<u64>) -> Result<(), Error> {
        self.call(|reply| Command::Import { writes, end, reply })
    }

    fn call<T: Send + 'static>(
        &self,
        command: impl FnOnce(Reply<T>) -> Command,
    ) -> Result<T, Error> {
        let (tx, rx) = mpsc::channel();
        self.send(command(Box::new(move |result| {
            // The caller is blocked on `rx` below, so it is only gone if it panicked.
            if tx.send(result).is_err() {
                debug!("QMDB caller went away before its reply");
            }
        })))?;
        rx.recv().map_err(|_| Error::Stopped)?
    }

    fn send(&self, command: Command) -> Result<(), Error> {
        self.commands
            .unbounded_send(command)
            .map_err(|_| Error::Stopped)
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        self.commands.close_channel();
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            error!("QMDB store thread panicked");
        }
    }
}

enum Command {
    Status {
        reply: Reply<Status>,
    },
    SetBase {
        hash: B256,
        reply: Reply<()>,
    },
    Build {
        block: BlockRef,
        writes: Vec<Write>,
        reply: Reply<QmdbBatch>,
    },
    BuildUnregistered {
        number: u64,
        parent_hash: B256,
        writes: Vec<Write>,
        reply: Reply<QmdbBatch>,
    },
    Register {
        hash: B256,
        batch: QmdbBatch,
        reply: Reply<()>,
    },
    Root {
        hash: B256,
        reply: Reply<Option<B256>>,
    },
    Finalize {
        hash: B256,
        reply: Reply<()>,
    },
    Import {
        writes: Vec<Write>,
        end: Option<u64>,
        reply: Reply<()>,
    },
}

struct Actor {
    /// Always `Some` between commands: applying and committing consume the database.
    db: Option<Db>,
    applied: Option<u64>,
    base: Option<B256>,
    pending: HashMap<B256, QmdbBatch>,
    max_pending: usize,
}

impl Actor {
    async fn init(context: Context, config: &Config) -> Result<Self, Error> {
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, config.page_cache_pages);
        let db_config = FixedConfig {
            merkle_config: MerkleConfig {
                journal_partition: "state-merkle-journal".into(),
                metadata_partition: "state-merkle-metadata".into(),
                items_per_blob: ITEMS_PER_BLOB,
                write_buffer: IO_BUFFER,
                replay_buffer: IO_BUFFER,
                strategy: context.strategy(config.threads),
                page_cache: page_cache.clone(),
            },
            journal_config: JournalConfig {
                partition: "state-log".into(),
                items_per_blob: ITEMS_PER_BLOB,
                page_cache,
                write_buffer: IO_BUFFER,
                replay_buffer: IO_BUFFER,
            },
            grafted_metadata_partition: "state-grafted-metadata".into(),
            translator: EightCap,
            init_cache_size: None,
            init_buffer: IO_BUFFER,
            init_concurrency: config.threads,
        };
        let db = Db::init(context.child("qmdb"), db_config).await?;
        let applied = db
            .get_metadata()
            .await?
            .as_ref()
            .map(layout::decode_block_metadata);
        Ok(Self {
            db: Some(db),
            applied,
            base: None,
            pending: HashMap::new(),
            max_pending: config.max_pending.get(),
        })
    }

    async fn run(mut self, mut commands: async_mpsc::UnboundedReceiver<Command>) {
        while let Some(command) = commands.next().await {
            match command {
                Command::Status { reply } => reply(Ok(self.status())),
                Command::SetBase { hash, reply } => {
                    self.base = Some(hash);
                    reply(Ok(()));
                }
                Command::Build {
                    block,
                    writes,
                    reply,
                } => reply(self.build(block, writes).await),
                Command::BuildUnregistered {
                    number,
                    parent_hash,
                    writes,
                    reply,
                } => reply(self.merkleize(number, parent_hash, writes).await),
                Command::Register { hash, batch, reply } => reply(self.register(hash, batch)),
                Command::Root { hash, reply } => reply(Ok(self.root(hash))),
                Command::Finalize { hash, reply } => reply(self.finalize(hash).await),
                Command::Import { writes, end, reply } => reply(self.import(writes, end).await),
            }
        }
        if let Some(db) = self.db.take()
            && let Err(err) = db.sync().await
        {
            error!(%err, "failed syncing QMDB on shutdown");
        }
    }

    fn db(&self) -> &Db {
        self.db.as_ref().expect("restored after every command")
    }

    fn status(&self) -> Status {
        Status {
            applied: self.applied,
            base: self.base,
            root: digest_to_b256(self.db().root()),
            pending: self.pending.len(),
        }
    }

    fn root(&self, hash: B256) -> Option<B256> {
        if self.base == Some(hash) {
            return Some(digest_to_b256(self.db().root()));
        }
        self.pending
            .get(&hash)
            .map(|pending| digest_to_b256(pending.batch.root()))
    }

    async fn build(&mut self, block: BlockRef, writes: Vec<Write>) -> Result<QmdbBatch, Error> {
        let batch = self
            .merkleize(block.number, block.parent_hash, writes)
            .await
            .map_err(|err| match err {
                Error::UnknownParent {
                    number,
                    parent_hash,
                    ..
                } => Error::UnknownParent {
                    number,
                    hash: block.hash,
                    parent_hash,
                },
                err => err,
            })?;
        self.register(block.hash, batch.clone())?;
        Ok(batch)
    }

    /// Merkleizes block `number`'s `writes` on its parent's batch, or on the applied state.
    async fn merkleize(
        &self,
        number: u64,
        parent_hash: B256,
        writes: Vec<Write>,
    ) -> Result<QmdbBatch, Error> {
        let base = self.base.ok_or(Error::NoBase)?;
        if let Some(applied) = self.applied
            && number <= applied
        {
            return Err(Error::AlreadyApplied { number, applied });
        }
        let db = self.db();
        let mut batch = if parent_hash == base {
            db.new_batch()
        } else {
            let parent = self.pending.get(&parent_hash).ok_or(Error::UnknownParent {
                number,
                hash: B256::ZERO,
                parent_hash,
            })?;
            parent.batch.new_batch::<Sha256>()
        };
        for write in writes {
            batch = batch.write(write.key, write.value);
        }
        let batch = batch
            .merkleize(db, Some(layout::block_metadata(number)))
            .await?;
        Ok(QmdbBatch {
            number,
            parent_hash,
            batch,
        })
    }

    fn register(&mut self, hash: B256, batch: QmdbBatch) -> Result<(), Error> {
        if !self.pending.contains_key(&hash) && self.pending.len() >= self.max_pending {
            return Err(Error::TooManyPending(self.pending.len()));
        }
        self.pending.insert(hash, batch);
        Ok(())
    }

    async fn finalize(&mut self, hash: B256) -> Result<(), Error> {
        if self.base == Some(hash) {
            return Ok(());
        }
        let pending = self.pending.get(&hash).ok_or(Error::UnknownBlock(hash))?;
        let (number, batch) = (pending.number, pending.batch.clone());
        let db = self.db.take().expect("restored after every command");
        // Applying consumes the database: on failure it is gone and the store must be reopened,
        // so every later command fails until then.
        let (db, _) = db.apply_batch(batch).await?;
        let db = db.commit().await?;
        self.db = Some(db);
        self.applied = Some(number);
        self.base = Some(hash);

        let descends = |mut hash: B256, pending: &HashMap<B256, QmdbBatch>| loop {
            if hash == self.base.expect("set above") {
                return true;
            }
            match pending.get(&hash) {
                Some(entry) => hash = entry.parent_hash,
                None => return false,
            }
        };
        let keep: Vec<B256> = self
            .pending
            .iter()
            .filter(|(_, entry)| {
                entry.number > number && descends(entry.parent_hash, &self.pending)
            })
            .map(|(hash, _)| *hash)
            .collect();
        self.pending.retain(|hash, _| keep.contains(hash));
        Ok(())
    }

    async fn import(&mut self, writes: Vec<Write>, end: Option<u64>) -> Result<(), Error> {
        if let Some(applied) = self.applied {
            return Err(Error::NotEmpty(applied));
        }
        let db = self.db();
        let mut batch = db.new_batch();
        for write in writes {
            batch = batch.write(write.key, write.value);
        }
        let batch = batch.merkleize(db, end.map(layout::block_metadata)).await?;
        let db = self.db.take().expect("restored after every command");
        let (db, _) = db.apply_batch(batch).await?;
        let db = if end.is_some() {
            db.commit().await?.sync().await?
        } else {
            db
        };
        self.db = Some(db);
        self.applied = end;
        Ok(())
    }
}

fn digest_to_b256(digest: <Sha256 as Hasher>::Digest) -> B256 {
    B256::from_slice(digest.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    fn config(directory: &std::path::Path, max_pending: usize) -> Config {
        Config {
            directory: directory.to_path_buf(),
            threads: NonZeroUsize::new(2).unwrap(),
            page_cache_pages: NonZeroUsize::new(64).unwrap(),
            max_pending: NonZeroUsize::new(max_pending).unwrap(),
        }
    }

    fn write(key: u8, value: Option<u64>) -> Write {
        Write {
            key: Key::new([key; 32]),
            value: value.map(|value| layout::slot_value(U256::from(value))),
        }
    }

    fn block(number: u64, hash: u8, parent: u8) -> BlockRef {
        BlockRef {
            number,
            hash: B256::repeat_byte(hash),
            parent_hash: B256::repeat_byte(parent),
        }
    }

    /// Opens a store holding keys 1..=3 as the state of block 0, with hash 0x00.
    fn imported(directory: &std::path::Path, max_pending: usize) -> Store {
        let store = Store::open(config(directory, max_pending)).unwrap();
        store
            .import_chunk(
                vec![write(1, Some(1)), write(2, Some(2)), write(3, Some(3))],
                Some(0),
            )
            .unwrap();
        store.set_base(B256::ZERO).unwrap();
        store
    }

    #[test]
    fn chained_blocks_build_on_unapplied_parents() {
        let dir = tempfile::tempdir().unwrap();
        let store = imported(dir.path(), 8);
        let genesis_root = store.status().unwrap().root;

        let root1 = store
            .build(block(1, 1, 0), vec![write(2, Some(20))])
            .unwrap()
            .root();
        let root2 = store
            .build(block(2, 2, 1), vec![write(3, None)])
            .unwrap()
            .root();
        assert_ne!(root1, genesis_root);
        assert_ne!(root2, root1);
        assert_eq!(store.root(B256::repeat_byte(2)).unwrap(), Some(root2));
        // Nothing is applied before finalization.
        assert_eq!(store.status().unwrap().applied, Some(0));
        assert_eq!(store.status().unwrap().root, genesis_root);

        store.finalize(B256::repeat_byte(2)).unwrap();
        let status = store.status().unwrap();
        assert_eq!(status.applied, Some(2));
        assert_eq!(status.root, root2);
        assert_eq!(status.pending, 0);
    }

    #[test]
    fn roots_are_deterministic_across_stores() {
        let roots = |dir: &std::path::Path| {
            let store = imported(dir, 8);
            let a = store
                .build(block(1, 1, 0), vec![write(4, Some(4))])
                .unwrap()
                .root();
            let b = store
                .build(block(2, 2, 1), vec![write(1, None), write(5, Some(5))])
                .unwrap()
                .root();
            store.finalize(B256::repeat_byte(1)).unwrap();
            let c = store
                .build(block(3, 3, 2), vec![write(2, Some(7))])
                .unwrap()
                .root();
            (a, b, c)
        };
        let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        assert_eq!(roots(dir_a.path()), roots(dir_b.path()));
    }

    #[test]
    fn block_number_is_part_of_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let store = imported(dir.path(), 8);
        let at_one = store
            .build(block(1, 1, 0), vec![write(4, Some(4))])
            .unwrap()
            .root();
        let at_two = store
            .build(block(2, 9, 0), vec![write(4, Some(4))])
            .unwrap()
            .root();
        assert_ne!(at_one, at_two);
    }

    #[test]
    fn finalizing_drops_forks_that_do_not_descend_from_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = imported(dir.path(), 8);
        store
            .build(block(1, 1, 0), vec![write(4, Some(4))])
            .unwrap()
            .root();
        store
            .build(block(1, 0xa1, 0), vec![write(4, Some(5))])
            .unwrap()
            .root();
        store
            .build(block(2, 0xa2, 0xa1), vec![write(4, Some(6))])
            .unwrap()
            .root();
        let root2 = store
            .build(block(2, 2, 1), vec![write(5, Some(5))])
            .unwrap()
            .root();

        store.finalize(B256::repeat_byte(1)).unwrap();
        assert_eq!(store.status().unwrap().pending, 1);
        assert_eq!(store.root(B256::repeat_byte(0xa2)).unwrap(), None);
        assert_eq!(store.root(B256::repeat_byte(2)).unwrap(), Some(root2));
        assert!(matches!(
            store.build(block(3, 0xa3, 0xa2), vec![]),
            Err(Error::UnknownParent { number: 3, .. })
        ));
        // The surviving child still extends the applied state.
        store.finalize(B256::repeat_byte(2)).unwrap();
        assert_eq!(store.status().unwrap().root, root2);
    }

    #[test]
    fn applied_state_survives_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let root = {
            let store = imported(dir.path(), 8);
            let root = store
                .build(block(1, 1, 0), vec![write(4, Some(4))])
                .unwrap()
                .root();
            store
                .build(block(2, 2, 1), vec![write(5, Some(5))])
                .unwrap()
                .root();
            store.finalize(B256::repeat_byte(1)).unwrap();
            root
        };
        let store = Store::open(config(dir.path(), 8)).unwrap();
        let status = store.status().unwrap();
        // The unapplied block 2 is gone; block 1 is applied, but its hash must be bound again.
        assert_eq!(
            status,
            Status {
                applied: Some(1),
                base: None,
                root,
                pending: 0
            }
        );
        assert!(matches!(
            store.build(block(2, 2, 1), vec![]),
            Err(Error::NoBase)
        ));
        store.set_base(B256::repeat_byte(1)).unwrap();
        store
            .build(block(2, 2, 1), vec![write(5, Some(5))])
            .unwrap()
            .root();
    }

    #[test]
    fn rejects_blocks_at_or_below_the_applied_block() {
        let dir = tempfile::tempdir().unwrap();
        let store = imported(dir.path(), 8);
        assert!(matches!(
            store.build(block(0, 1, 0), vec![]),
            Err(Error::AlreadyApplied {
                number: 0,
                applied: 0
            })
        ));
    }

    #[test]
    fn bounds_unapplied_batches() {
        let dir = tempfile::tempdir().unwrap();
        let store = imported(dir.path(), 2);
        store.build(block(1, 1, 0), vec![]).unwrap().root();
        store.build(block(2, 2, 1), vec![]).unwrap().root();
        // Rebuilding a held block replaces it instead of counting against the bound.
        store
            .build(block(2, 2, 1), vec![write(4, Some(4))])
            .unwrap()
            .root();
        assert!(matches!(
            store.build(block(3, 3, 2), vec![]),
            Err(Error::TooManyPending(2))
        ));
    }

    #[test]
    fn unregistered_batch_extends_once_registered() {
        let dir = tempfile::tempdir().unwrap();
        let store = imported(dir.path(), 8);
        let batch = store
            .build_unregistered(1, B256::ZERO, vec![write(4, Some(4))])
            .unwrap();
        // Same writes on the same parent give the same root as a registered build.
        let registered = store
            .build(block(1, 1, 0), vec![write(4, Some(4))])
            .unwrap();
        assert_eq!(batch.root(), registered.root());
        assert!(matches!(
            store.build(block(2, 2, 0xb1), vec![]),
            Err(Error::UnknownParent { number: 2, .. })
        ));

        store.register(B256::repeat_byte(0xb1), batch).unwrap();
        let child = store
            .build(block(2, 2, 0xb1), vec![write(5, Some(5))])
            .unwrap();
        store.finalize(B256::repeat_byte(2)).unwrap();
        assert_eq!(store.status().unwrap().root, child.root());
    }

    #[test]
    fn import_requires_an_empty_database() {
        let dir = tempfile::tempdir().unwrap();
        let store = imported(dir.path(), 8);
        assert!(matches!(
            store.import_chunk(vec![], Some(1)),
            Err(Error::NotEmpty(0))
        ));
    }

    #[test]
    fn build_detached_reports_on_the_store_thread() {
        let dir = tempfile::tempdir().unwrap();
        let store = imported(dir.path(), 8);
        let (tx, rx) = mpsc::channel();
        store
            .build_detached(block(1, 1, 0), vec![write(4, Some(4))], move |root| {
                tx.send(root.map_err(|err| err.to_string())).unwrap();
            })
            .unwrap();
        let root = rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .unwrap()
            .unwrap();
        assert_eq!(store.root(B256::repeat_byte(1)).unwrap(), Some(root));
    }
}
