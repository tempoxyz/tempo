//! The two QMDB databases, their unapplied per-block batches, and the thread that runs them.

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
    journal::{
        self,
        contiguous::{
            Contiguous as _,
            fixed::{self, Config as JournalConfig},
        },
    },
    merkle::{Location, full::Config as MerkleConfig, mmb},
    qmdb::{
        self,
        any::ordered::fixed::Update,
        current::{FixedConfig, batch::MerkleizedBatch, ordered::fixed::partitioned},
    },
    translator::EightCap,
};
use commonware_utils::sequence::FixedBytes;
use futures::{StreamExt as _, channel::mpsc as async_mpsc, try_join};
use tracing::{debug, error, warn};

use crate::layout::{self, ACCOUNT_LEN, AccountValue, Key, SLOT_LEN, SlotValue, Write, Writes};

type Family = mmb::Family;
/// Bitmap chunk size in bytes of the `current` layer.
const CHUNK: usize = 32;
/// Index partitions of the accounts database: the first two key bytes (65,536 partitions).
const ACCOUNT_PARTITION_BYTES: usize = 2;
/// Index partitions of the slots database: the first three key bytes (16.8M partitions, about
/// 0.8 GB of fixed memory). A partition that outgrows 512 entries converts to a `BTreeMap` with
/// a heap `Vec` per key, about 85 bytes per key against 16 inline, which two-byte partitions do
/// for every partition past about 33M keys; three-byte ones only past about 8.5B.
const SLOT_PARTITION_BYTES: usize = 3;
const PAGE_SIZE: NonZeroU16 = NonZeroU16::new(16_384).expect("non-zero");
const ITEMS_PER_BLOB: NonZeroU64 = NonZeroU64::new(1 << 23).expect("non-zero");
const IO_BUFFER: NonZeroUsize = NonZeroUsize::new(2 << 20).expect("non-zero");
/// Encoded size of a [`Commit`]: number (8) ‖ hash (32) ‖ accounts size (8) ‖ slots size (8).
const COMMIT_LEN: usize = 56;
const COMMITS_PER_BLOB: NonZeroU64 = NonZeroU64::new(1 << 16).expect("non-zero");
const COMMITS_WRITE_BUFFER: NonZeroUsize = NonZeroUsize::new(4096).expect("non-zero");

type Db<const N: usize, const P: usize> =
    partitioned::Db<Family, Context, Key, FixedBytes<N>, Sha256, EightCap, P, CHUNK, Rayon>;
type AccountsDb = Db<ACCOUNT_LEN, ACCOUNT_PARTITION_BYTES>;
type SlotsDb = Db<SLOT_LEN, SLOT_PARTITION_BYTES>;
type Batch<const N: usize> = Arc<
    MerkleizedBatch<Family, <Sha256 as Hasher>::Digest, Update<Key, FixedBytes<N>>, CHUNK, Rayon>,
>;
type Commits = fixed::Journal<Context, FixedBytes<COMMIT_LEN>>;
type Reply<T> = Box<dyn FnOnce(Result<T, Error>) + Send>;

/// Configuration of a [`Store`].
#[derive(Clone, Debug)]
pub struct Config {
    /// Directory holding the database files.
    pub directory: PathBuf,
    /// Threads that merkleize batches and rebuild the indexes on open.
    pub threads: NonZeroUsize,
    /// Pages of each database's own page cache, each 16 KiB.
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

/// A block's merkleized QMDB batches, one per database, not yet applied to disk.
///
/// Cheap to clone. The engine carries it on the block as its reth `BlockExt`, so the
/// persistence hook applies exactly the batches the block was validated with.
#[derive(Clone)]
pub struct QmdbBatch {
    number: u64,
    parent_hash: B256,
    accounts: Batch<ACCOUNT_LEN>,
    slots: Batch<SLOT_LEN>,
}

impl QmdbBatch {
    /// Number of the block the batch belongs to.
    pub const fn number(&self) -> u64 {
        self.number
    }

    /// State root of the block.
    pub fn root(&self) -> B256 {
        layout::state_root(
            digest_to_b256(self.accounts.root()),
            digest_to_b256(self.slots.root()),
        )
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
    /// Hash of the last applied block, `None` when the commit journal has no record of it and
    /// neither [`Store::set_base`], an import nor a finalization bound it since opening.
    pub base: Option<B256>,
    /// Root of the applied state: the state root of block `applied`.
    pub root: B256,
    /// Unapplied batches held in memory.
    pub pending: usize,
}

/// Error of a [`Store`] operation.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A database failed.
    #[error("qmdb failed")]
    Qmdb(#[from] qmdb::Error<Family>),
    /// The commit journal failed.
    #[error("the commit journal failed")]
    Journal(#[from] journal::Error),
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
    /// The commit journal holds no record of an applied block to rewind to.
    #[error("block {0} has no recorded commit")]
    UnknownCommit(u64),
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
    /// The two databases end at different blocks and the commit journal has no block both can
    /// rewind to, such as after a crash during the import.
    #[error("the accounts database is at block {accounts:?} and the slots database at {slots:?}")]
    OutOfStep {
        /// Block the accounts database ends at.
        accounts: Option<u64>,
        /// Block the slots database ends at.
        slots: Option<u64>,
    },
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
    /// Opens or creates the databases in [`Config::directory`] and starts their thread.
    ///
    /// Binds the applied block's hash from the commit journal when its latest record is the
    /// applied block, so [`Self::set_base`] is only needed when the journal lacks it. A crash
    /// between committing the two databases leaves them at different blocks: opening rewinds both
    /// to the latest recorded block.
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
    /// Only needed when [`Status::base`] is `None` after opening, with the canonical hash of
    /// [`Status::applied`]: the commit journal had no record of it.
    pub fn set_base(&self, hash: B256) -> Result<(), Error> {
        self.call(|reply| Command::SetBase { hash, reply })
    }

    /// Builds the batch of `block` from its sorted `writes`, registers it under the block's hash,
    /// and returns it.
    ///
    /// Blocks until both databases' batches are merkleized, which runs in parallel. Building a
    /// block again replaces its batch.
    pub fn build(&self, block: BlockRef, writes: Writes) -> Result<QmdbBatch, Error> {
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
        writes: Writes,
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
        writes: Writes,
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

    /// Applies the batches up to block `hash` to disk, commits them, records each applied block
    /// in the commit journal, and drops batches that do not descend from it.
    ///
    /// The records are durable when this returns. Finalizing the applied block again does nothing.
    pub fn finalize(&self, hash: B256) -> Result<(), Error> {
        self.call(|reply| Command::Finalize { hash, reply })
    }

    /// Applies one chunk of a snapshot import directly to disk.
    ///
    /// Each database's writes must be sorted and above every key of its earlier chunks. The final
    /// chunk passes `end`, the snapshot block's number and hash, which commits both databases at
    /// that block, binds its hash as [`Status::base`] and records it in the commit journal.
    /// Fails with [`Error::NotEmpty`] once a block is applied.
    pub fn import_chunk(&self, writes: Writes, end: Option<(u64, B256)>) -> Result<(), Error> {
        self.call(|reply| Command::Import { writes, end, reply })
    }

    /// Rewinds the applied state to block `number`, an earlier finalized or imported block.
    ///
    /// Drops every unapplied batch, binds the block's recorded hash as [`Status::base`] and
    /// forgets the records above it, durably before returning. Rewinding to the applied block
    /// does nothing. Fails with [`Error::UnknownCommit`] when the commit journal has no record of
    /// `number`, such as a block above the applied one.
    pub fn rewind_to(&self, number: u64) -> Result<(), Error> {
        self.call(|reply| Command::RewindTo { number, reply })
    }

    /// Returns the value of account `key` in the applied state, ignoring unapplied batches.
    pub fn get_account(&self, key: Key) -> Result<Option<AccountValue>, Error> {
        Ok(self.get_accounts(vec![key])?.pop().flatten())
    }

    /// Returns the values of account `keys` in the applied state, in the same order, ignoring
    /// unapplied batches.
    pub fn get_accounts(&self, keys: Vec<Key>) -> Result<Vec<Option<AccountValue>>, Error> {
        self.call(|reply| Command::GetAccounts { keys, reply })
    }

    /// Returns the value of slot `key` in the applied state, ignoring unapplied batches.
    pub fn get_slot(&self, key: Key) -> Result<Option<SlotValue>, Error> {
        Ok(self.get_slots(vec![key])?.pop().flatten())
    }

    /// Returns the values of slot `keys` in the applied state, in the same order, ignoring
    /// unapplied batches.
    pub fn get_slots(&self, keys: Vec<Key>) -> Result<Vec<Option<SlotValue>>, Error> {
        self.call(|reply| Command::GetSlots { keys, reply })
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
        writes: Writes,
        reply: Reply<QmdbBatch>,
    },
    BuildUnregistered {
        number: u64,
        parent_hash: B256,
        writes: Writes,
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
        writes: Writes,
        end: Option<(u64, B256)>,
        reply: Reply<()>,
    },
    RewindTo {
        number: u64,
        reply: Reply<()>,
    },
    GetAccounts {
        keys: Vec<Key>,
        reply: Reply<Vec<Option<AccountValue>>>,
    },
    GetSlots {
        keys: Vec<Key>,
        reply: Reply<Vec<Option<SlotValue>>>,
    },
}

struct Actor {
    /// Always `Some` between commands: applying and committing consume the databases.
    accounts: Option<AccountsDb>,
    /// Always `Some` between commands, like `accounts`.
    slots: Option<SlotsDb>,
    /// Applied blocks in ascending order. Always `Some` between commands, like `accounts`.
    commits: Option<Commits>,
    applied: Option<u64>,
    base: Option<B256>,
    pending: HashMap<B256, QmdbBatch>,
    max_pending: usize,
}

impl Actor {
    async fn init(context: Context, config: &Config) -> Result<Self, Error> {
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, config.page_cache_pages);
        let db_config = |name: &str| FixedConfig {
            merkle_config: MerkleConfig {
                journal_partition: format!("{name}-merkle-journal"),
                metadata_partition: format!("{name}-merkle-metadata"),
                items_per_blob: ITEMS_PER_BLOB,
                write_buffer: IO_BUFFER,
                replay_buffer: IO_BUFFER,
                strategy: context.strategy(config.threads),
                page_cache: page_cache.clone(),
            },
            journal_config: JournalConfig {
                partition: format!("{name}-log"),
                items_per_blob: ITEMS_PER_BLOB,
                page_cache: page_cache.clone(),
                write_buffer: IO_BUFFER,
                replay_buffer: IO_BUFFER,
            },
            grafted_metadata_partition: format!("{name}-grafted-metadata"),
            translator: EightCap,
            init_cache_size: None,
            init_buffer: IO_BUFFER,
            init_concurrency: config.threads,
        };
        let commits_config = JournalConfig {
            partition: "state-commits".into(),
            items_per_blob: COMMITS_PER_BLOB,
            page_cache: page_cache.clone(),
            write_buffer: COMMITS_WRITE_BUFFER,
            replay_buffer: IO_BUFFER,
        };
        let (mut accounts, mut slots) = try_join!(
            AccountsDb::init(context.child("accounts"), db_config("accounts")),
            SlotsDb::init(context.child("slots"), db_config("slots")),
        )?;
        let mut commits = Commits::init(context.child("commits"), commits_config).await?;
        let accounts_applied = applied_block(&accounts).await?;
        let slots_applied = applied_block(&slots).await?;
        let applied = accounts_applied.min(slots_applied);

        // A crash between applying blocks to the databases and recording them leaves the journal
        // behind them; one during a rewind leaves records above them.
        let sizes = (*accounts.bounds().end, *slots.bounds().end);
        let mut kept = commits.size();
        let mut latest = None;
        while kept > commits.bounds().start {
            let commit = Commit::decode(&commits.read(kept - 1).await?);
            if commit.accounts_size <= sizes.0
                && commit.slots_size <= sizes.1
                && applied.is_some_and(|applied| commit.number <= applied)
            {
                latest = Some(commit);
                break;
            }
            kept -= 1;
        }
        if kept < commits.size() {
            commits = commits.rewind(kept).await?.commit().await?;
        }

        // A crash between committing the two databases leaves one a block ahead.
        let mut applied = applied;
        if accounts_applied != slots_applied {
            let Some(commit) = latest else {
                return Err(Error::OutOfStep {
                    accounts: accounts_applied,
                    slots: slots_applied,
                });
            };
            warn!(
                accounts = ?accounts_applied,
                slots = ?slots_applied,
                to = commit.number,
                "QMDB databases are out of step, rewinding both to the latest recorded block"
            );
            (accounts, slots) = try_join!(
                rewind_db(accounts, commit.accounts_size),
                rewind_db(slots, commit.slots_size),
            )?;
            applied = Some(commit.number);
        }

        let sizes = (*accounts.bounds().end, *slots.bounds().end);
        let base = latest
            .filter(|commit| {
                Some(commit.number) == applied && (commit.accounts_size, commit.slots_size) == sizes
            })
            .map(|commit| commit.hash);

        Ok(Self {
            accounts: Some(accounts),
            slots: Some(slots),
            commits: Some(commits),
            applied,
            base,
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
                Command::RewindTo { number, reply } => reply(self.rewind_to(number).await),
                Command::GetAccounts { keys, reply } => {
                    let keys: Vec<&Key> = keys.iter().collect();
                    reply(self.accounts().get_many(&keys).await.map_err(Error::from));
                }
                Command::GetSlots { keys, reply } => {
                    let keys: Vec<&Key> = keys.iter().collect();
                    reply(self.slots().get_many(&keys).await.map_err(Error::from));
                }
            }
        }
        if let Some(db) = self.accounts.take()
            && let Err(err) = db.sync().await
        {
            error!(%err, "failed syncing the QMDB accounts on shutdown");
        }
        if let Some(db) = self.slots.take()
            && let Err(err) = db.sync().await
        {
            error!(%err, "failed syncing the QMDB slots on shutdown");
        }
        if let Some(commits) = self.commits.take()
            && let Err(err) = commits.sync().await
        {
            error!(%err, "failed syncing the QMDB commit journal on shutdown");
        }
    }

    fn accounts(&self) -> &AccountsDb {
        self.accounts
            .as_ref()
            .expect("restored after every command")
    }

    fn slots(&self) -> &SlotsDb {
        self.slots.as_ref().expect("restored after every command")
    }

    fn applied_root(&self) -> B256 {
        layout::state_root(
            digest_to_b256(self.accounts().root()),
            digest_to_b256(self.slots().root()),
        )
    }

    fn status(&self) -> Status {
        Status {
            applied: self.applied,
            base: self.base,
            root: self.applied_root(),
            pending: self.pending.len(),
        }
    }

    fn root(&self, hash: B256) -> Option<B256> {
        if self.base == Some(hash) {
            return Some(self.applied_root());
        }
        self.pending.get(&hash).map(QmdbBatch::root)
    }

    async fn build(&mut self, block: BlockRef, writes: Writes) -> Result<QmdbBatch, Error> {
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

    /// Merkleizes block `number`'s `writes` on its parent's batches, or on the applied state.
    async fn merkleize(
        &self,
        number: u64,
        parent_hash: B256,
        writes: Writes,
    ) -> Result<QmdbBatch, Error> {
        let base = self.base.ok_or(Error::NoBase)?;
        if let Some(applied) = self.applied
            && number <= applied
        {
            return Err(Error::AlreadyApplied { number, applied });
        }
        let parent = if parent_hash == base {
            None
        } else {
            Some(self.pending.get(&parent_hash).ok_or(Error::UnknownParent {
                number,
                hash: B256::ZERO,
                parent_hash,
            })?)
        };
        let (accounts, slots) = try_join!(
            merkleize_db(
                self.accounts(),
                parent.map(|parent| &parent.accounts),
                writes.accounts,
                Some(number),
            ),
            merkleize_db(
                self.slots(),
                parent.map(|parent| &parent.slots),
                writes.slots,
                Some(number),
            ),
        )?;
        Ok(QmdbBatch {
            number,
            parent_hash,
            accounts,
            slots,
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
        let (number, accounts_batch, slots_batch) = (
            pending.number,
            pending.accounts.clone(),
            pending.slots.clone(),
        );
        // Applying a batch applies its unapplied ancestors too: record each of them.
        let mut applied = Vec::new();
        let mut next = Some((hash, pending));
        while let Some((hash, pending)) = next {
            applied.push(Commit {
                number: pending.number,
                hash,
                accounts_size: *pending.accounts.bounds().tip.size,
                slots_size: *pending.slots.bounds().tip.size,
            });
            next = if Some(pending.parent_hash) == self.base {
                None
            } else {
                self.pending
                    .get(&pending.parent_hash)
                    .map(|parent| (pending.parent_hash, parent))
            };
        }
        let accounts = self.accounts.take().expect("restored after every command");
        let slots = self.slots.take().expect("restored after every command");
        // Applying consumes the databases: on failure they are gone and the store must be
        // reopened, so every later command fails until then.
        let (accounts, slots) = try_join!(
            apply_db(accounts, accounts_batch),
            apply_db(slots, slots_batch),
        )?;
        self.accounts = Some(accounts);
        self.slots = Some(slots);
        self.applied = Some(number);
        self.base = Some(hash);
        self.record(applied.into_iter().rev()).await?;

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

    async fn import(&mut self, writes: Writes, end: Option<(u64, B256)>) -> Result<(), Error> {
        if let Some(applied) = self.applied {
            return Err(Error::NotEmpty(applied));
        }
        let number = end.map(|(number, _)| number);
        // A database without writes in a chunk only takes the final, committing batch.
        let (accounts_batch, slots_batch) = try_join!(
            async {
                match writes.accounts.is_empty() && end.is_none() {
                    true => Ok(None),
                    false => merkleize_db(self.accounts(), None, writes.accounts, number)
                        .await
                        .map(Some),
                }
            },
            async {
                match writes.slots.is_empty() && end.is_none() {
                    true => Ok(None),
                    false => merkleize_db(self.slots(), None, writes.slots, number)
                        .await
                        .map(Some),
                }
            },
        )?;
        let accounts = self.accounts.take().expect("restored after every command");
        let slots = self.slots.take().expect("restored after every command");
        // Committing every chunk flushes the Merkle nodes the chunk added out of memory, which
        // otherwise stay resident until the import ends: about 64 bytes per imported key.
        let (accounts, slots) = try_join!(
            async {
                match accounts_batch {
                    Some(batch) => apply_db(accounts, batch).await,
                    None => Ok(accounts),
                }
            },
            async {
                match slots_batch {
                    Some(batch) => apply_db(slots, batch).await,
                    None => Ok(slots),
                }
            },
        )?;
        let Some((number, hash)) = end else {
            self.accounts = Some(accounts);
            self.slots = Some(slots);
            return Ok(());
        };
        let (accounts, slots) = try_join!(accounts.sync(), slots.sync())?;
        let commit = Commit {
            number,
            hash,
            accounts_size: *accounts.bounds().end,
            slots_size: *slots.bounds().end,
        };
        self.accounts = Some(accounts);
        self.slots = Some(slots);
        self.applied = Some(number);
        self.base = Some(hash);
        self.record([commit]).await
    }

    async fn rewind_to(&mut self, number: u64) -> Result<(), Error> {
        if self.applied == Some(number) {
            return Ok(());
        }
        let (position, commit) = self
            .find_commit(number)
            .await?
            .ok_or(Error::UnknownCommit(number))?;
        // Batches built on the current state cannot apply to the rewound one.
        self.pending.clear();
        let accounts = self.accounts.take().expect("restored after every command");
        let slots = self.slots.take().expect("restored after every command");
        // Like applying, a failed rewind consumes the databases until the store is reopened.
        let (accounts, slots) = try_join!(
            rewind_db(accounts, commit.accounts_size),
            rewind_db(slots, commit.slots_size),
        )?;
        self.accounts = Some(accounts);
        self.slots = Some(slots);
        self.applied = Some(commit.number);
        self.base = Some(commit.hash);
        let commits = self.commits.take().expect("restored after every command");
        self.commits = Some(commits.rewind(position + 1).await?.commit().await?);
        Ok(())
    }

    /// Finds the record of block `number` and its position in the commit journal.
    async fn find_commit(&self, number: u64) -> Result<Option<(u64, Commit)>, Error> {
        let commits = self.commits.as_ref().expect("restored after every command");
        // Records are in ascending block order.
        let (mut low, mut high) = (commits.bounds().start, commits.size());
        while low < high {
            let middle = low + (high - low) / 2;
            let commit = Commit::decode(&commits.read(middle).await?);
            match commit.number.cmp(&number) {
                std::cmp::Ordering::Less => low = middle + 1,
                std::cmp::Ordering::Greater => high = middle,
                std::cmp::Ordering::Equal => return Ok(Some((middle, commit))),
            }
        }
        Ok(None)
    }

    /// Appends `records` to the commit journal and makes them durable.
    async fn record(&mut self, records: impl IntoIterator<Item = Commit>) -> Result<(), Error> {
        let mut commits = self.commits.take().expect("restored after every command");
        for record in records {
            (commits, _) = commits.append(&record.encode()).await?;
        }
        self.commits = Some(commits.commit().await?);
        Ok(())
    }
}

/// Returns the block a database's last commit ended at, `None` before the import.
async fn applied_block<const N: usize, const P: usize>(
    db: &Db<N, P>,
) -> Result<Option<u64>, Error> {
    Ok(db
        .get_metadata()
        .await?
        .as_ref()
        .map(layout::decode_block_metadata))
}

/// Merkleizes `writes` on `parent`, or on the database's applied state, committing to block
/// `number` as metadata when given.
async fn merkleize_db<const N: usize, const P: usize>(
    db: &Db<N, P>,
    parent: Option<&Batch<N>>,
    writes: Vec<Write<FixedBytes<N>>>,
    number: Option<u64>,
) -> Result<Batch<N>, Error> {
    let mut batch = match parent {
        Some(parent) => parent.new_batch::<Sha256>(),
        None => db.new_batch(),
    };
    for write in writes {
        batch = batch.write(write.key, write.value);
    }
    Ok(batch
        .merkleize(db, number.map(layout::block_metadata::<N>))
        .await?)
}

/// Applies `batch` to `db` and commits it, which also flushes its Merkle nodes out of memory.
async fn apply_db<const N: usize, const P: usize>(
    db: Db<N, P>,
    batch: Batch<N>,
) -> Result<Db<N, P>, Error> {
    let (db, _) = db.apply_batch(batch).await?;
    Ok(db.commit().await?)
}

/// Rewinds `db` to `size` operations and commits the rewind.
async fn rewind_db<const N: usize, const P: usize>(
    db: Db<N, P>,
    size: u64,
) -> Result<Db<N, P>, Error> {
    Ok(db.rewind(Location::new(size)).await?.commit().await?)
}

/// The commit journal's record of an applied block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Commit {
    number: u64,
    hash: B256,
    /// Operations in the accounts database right after the block's commit, its rewind target.
    accounts_size: u64,
    /// Operations in the slots database right after the block's commit, its rewind target.
    slots_size: u64,
}

impl Commit {
    fn encode(&self) -> FixedBytes<COMMIT_LEN> {
        let mut out = [0u8; COMMIT_LEN];
        out[..8].copy_from_slice(&self.number.to_be_bytes());
        out[8..40].copy_from_slice(self.hash.as_slice());
        out[40..48].copy_from_slice(&self.accounts_size.to_be_bytes());
        out[48..].copy_from_slice(&self.slots_size.to_be_bytes());
        FixedBytes::new(out)
    }

    fn decode(bytes: &FixedBytes<COMMIT_LEN>) -> Self {
        let word = |range: std::ops::Range<usize>| {
            u64::from_be_bytes(bytes[range].try_into().expect("8 bytes"))
        };
        Self {
            number: word(0..8),
            hash: B256::from_slice(&bytes[8..40]),
            accounts_size: word(40..48),
            slots_size: word(48..56),
        }
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

    fn write(key: u8, value: Option<u64>) -> Write<SlotValue> {
        Write {
            key: Key::new([key; 32]),
            value: value.map(|value| layout::slot_value(U256::from(value))),
        }
    }

    impl From<Vec<Write<SlotValue>>> for Writes {
        fn from(slots: Vec<Write<SlotValue>>) -> Self {
            Self {
                accounts: Vec::new(),
                slots,
            }
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
                vec![write(1, Some(1)), write(2, Some(2)), write(3, Some(3))].into(),
                Some((0, B256::ZERO)),
            )
            .unwrap();
        store
    }

    #[test]
    fn chained_blocks_build_on_unapplied_parents() {
        let dir = tempfile::tempdir().unwrap();
        let store = imported(dir.path(), 8);
        let genesis_root = store.status().unwrap().root;

        let root1 = store
            .build(block(1, 1, 0), vec![write(2, Some(20))].into())
            .unwrap()
            .root();
        let root2 = store
            .build(block(2, 2, 1), vec![write(3, None)].into())
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
                .build(block(1, 1, 0), vec![write(4, Some(4))].into())
                .unwrap()
                .root();
            let b = store
                .build(
                    block(2, 2, 1),
                    vec![write(1, None), write(5, Some(5))].into(),
                )
                .unwrap()
                .root();
            store.finalize(B256::repeat_byte(1)).unwrap();
            let c = store
                .build(block(3, 3, 2), vec![write(2, Some(7))].into())
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
            .build(block(1, 1, 0), vec![write(4, Some(4))].into())
            .unwrap()
            .root();
        let at_two = store
            .build(block(2, 9, 0), vec![write(4, Some(4))].into())
            .unwrap()
            .root();
        assert_ne!(at_one, at_two);
    }

    #[test]
    fn finalizing_drops_forks_that_do_not_descend_from_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = imported(dir.path(), 8);
        store
            .build(block(1, 1, 0), vec![write(4, Some(4))].into())
            .unwrap()
            .root();
        store
            .build(block(1, 0xa1, 0), vec![write(4, Some(5))].into())
            .unwrap()
            .root();
        store
            .build(block(2, 0xa2, 0xa1), vec![write(4, Some(6))].into())
            .unwrap()
            .root();
        let root2 = store
            .build(block(2, 2, 1), vec![write(5, Some(5))].into())
            .unwrap()
            .root();

        store.finalize(B256::repeat_byte(1)).unwrap();
        assert_eq!(store.status().unwrap().pending, 1);
        assert_eq!(store.root(B256::repeat_byte(0xa2)).unwrap(), None);
        assert_eq!(store.root(B256::repeat_byte(2)).unwrap(), Some(root2));
        assert!(matches!(
            store.build(block(3, 0xa3, 0xa2), Writes::default()),
            Err(Error::UnknownParent { number: 3, .. })
        ));
        // The surviving child still extends the applied state.
        store.finalize(B256::repeat_byte(2)).unwrap();
        assert_eq!(store.status().unwrap().root, root2);
    }

    #[test]
    fn applied_state_and_base_survive_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let root = {
            let store = imported(dir.path(), 8);
            let root = store
                .build(block(1, 1, 0), vec![write(4, Some(4))].into())
                .unwrap()
                .root();
            store
                .build(block(2, 2, 1), vec![write(5, Some(5))].into())
                .unwrap()
                .root();
            store.finalize(B256::repeat_byte(1)).unwrap();
            root
        };
        let store = Store::open(config(dir.path(), 8)).unwrap();
        // The unapplied block 2 is gone; the commit journal binds block 1's hash again.
        assert_eq!(
            store.status().unwrap(),
            Status {
                applied: Some(1),
                base: Some(B256::repeat_byte(1)),
                root,
                pending: 0
            }
        );
        store
            .build(block(2, 2, 1), vec![write(5, Some(5))].into())
            .unwrap()
            .root();
    }

    #[test]
    fn imported_base_survives_reopening() {
        let dir = tempfile::tempdir().unwrap();
        drop(imported(dir.path(), 8));
        let store = Store::open(config(dir.path(), 8)).unwrap();
        assert_eq!(store.status().unwrap().base, Some(B256::ZERO));
        store.build(block(1, 1, 0), Writes::default()).unwrap();
    }

    #[test]
    fn without_a_record_the_base_must_be_set() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(config(dir.path(), 8)).unwrap();
        assert!(matches!(
            store.build(block(1, 1, 0), Writes::default()),
            Err(Error::NoBase)
        ));
        store.set_base(B256::ZERO).unwrap();
        assert_eq!(store.status().unwrap().base, Some(B256::ZERO));
    }

    #[test]
    fn reopening_repairs_a_journal_out_of_step_with_the_database() {
        /// Moves the commit journal of `from` into `to`, replacing its own.
        fn move_journal(from: &std::path::Path, to: &std::path::Path) {
            for entry in std::fs::read_dir(to).unwrap() {
                let path = entry.unwrap().path();
                if path
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("state-commits")
                {
                    std::fs::remove_dir_all(path).unwrap();
                }
            }
            for entry in std::fs::read_dir(from).unwrap() {
                let path = entry.unwrap().path();
                let name = path.file_name().unwrap().to_owned();
                if name.to_str().unwrap().starts_with("state-commits") {
                    std::fs::rename(&path, to.join(name)).unwrap();
                }
            }
        }

        // Both apply the same block 1; only `two` applies block 2.
        let (one, two, swap) = (
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
        );
        let root1 = {
            let store = imported(one.path(), 8);
            let root1 = store
                .build(block(1, 1, 0), vec![write(4, Some(4))].into())
                .unwrap()
                .root();
            store.finalize(B256::repeat_byte(1)).unwrap();
            root1
        };
        {
            let store = imported(two.path(), 8);
            store
                .build(block(1, 1, 0), vec![write(4, Some(4))].into())
                .unwrap();
            store
                .build(block(2, 2, 1), vec![write(5, Some(5))].into())
                .unwrap();
            store.finalize(B256::repeat_byte(2)).unwrap();
        }
        move_journal(two.path(), swap.path());
        move_journal(one.path(), two.path());
        move_journal(swap.path(), one.path());

        // A journal behind the database cannot bind the base, but still rewinds.
        let store = Store::open(config(two.path(), 8)).unwrap();
        let status = store.status().unwrap();
        assert_eq!((status.applied, status.base), (Some(2), None));
        store.rewind_to(1).unwrap();
        let status = store.status().unwrap();
        assert_eq!(
            (status.base, status.root),
            (Some(B256::repeat_byte(1)), root1)
        );

        // A journal ahead of the database drops the records above it.
        let store = Store::open(config(one.path(), 8)).unwrap();
        assert_eq!(store.status().unwrap().base, Some(B256::repeat_byte(1)));
        assert!(matches!(store.rewind_to(2), Err(Error::UnknownCommit(2))));
    }

    #[test]
    fn rewinds_across_finalized_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let store = imported(dir.path(), 8);
        let genesis_root = store.status().unwrap().root;
        let root1 = store
            .build(block(1, 1, 0), vec![write(2, Some(20))].into())
            .unwrap()
            .root();
        store.finalize(B256::repeat_byte(1)).unwrap();
        store
            .build(
                block(2, 2, 1),
                vec![write(3, None), write(4, Some(4))].into(),
            )
            .unwrap()
            .root();
        store.finalize(B256::repeat_byte(2)).unwrap();
        store
            .build(block(3, 3, 2), Writes::default())
            .unwrap()
            .root();

        store.rewind_to(0).unwrap();
        assert_eq!(
            store.status().unwrap(),
            Status {
                applied: Some(0),
                base: Some(B256::ZERO),
                root: genesis_root,
                pending: 0
            }
        );
        assert_eq!(
            store
                .get_slots(vec![
                    write(2, None).key,
                    write(3, None).key,
                    write(4, None).key
                ])
                .unwrap(),
            vec![write(2, Some(2)).value, write(3, Some(3)).value, None]
        );
        // A different child of block 0 builds and finalizes; rebuilding the old one matches root1.
        let other = store
            .build(block(1, 0xc1, 0), vec![write(5, Some(5))].into())
            .unwrap()
            .root();
        assert_ne!(other, root1);
        let rebuilt = store
            .build(block(1, 1, 0), vec![write(2, Some(20))].into())
            .unwrap()
            .root();
        assert_eq!(rebuilt, root1);
        store.finalize(B256::repeat_byte(0xc1)).unwrap();
        assert_eq!(store.status().unwrap().root, other);

        // The rewound records are gone and the new one survives reopening.
        drop(store);
        let store = Store::open(config(dir.path(), 8)).unwrap();
        assert_eq!(store.status().unwrap().base, Some(B256::repeat_byte(0xc1)));
        assert!(matches!(store.rewind_to(2), Err(Error::UnknownCommit(2))));
        store.rewind_to(0).unwrap();
        assert_eq!(store.status().unwrap().root, genesis_root);
    }

    #[test]
    fn rewinds_to_a_block_finalized_through_a_descendant() {
        let dir = tempfile::tempdir().unwrap();
        let store = imported(dir.path(), 8);
        let root1 = store
            .build(block(1, 1, 0), vec![write(4, Some(4))].into())
            .unwrap()
            .root();
        store
            .build(block(2, 2, 1), vec![write(5, Some(5))].into())
            .unwrap()
            .root();
        store.finalize(B256::repeat_byte(2)).unwrap();

        store.rewind_to(1).unwrap();
        let status = store.status().unwrap();
        assert_eq!(
            (status.applied, status.base, status.root),
            (Some(1), Some(B256::repeat_byte(1)), root1)
        );
    }

    #[test]
    fn rewind_to_an_unrecorded_block_fails() {
        let dir = tempfile::tempdir().unwrap();
        let store = imported(dir.path(), 8);
        store.build(block(1, 1, 0), Writes::default()).unwrap();
        assert!(matches!(store.rewind_to(1), Err(Error::UnknownCommit(1))));
        assert!(matches!(store.rewind_to(7), Err(Error::UnknownCommit(7))));
        // Rewinding to the applied block keeps the unapplied batches.
        store.rewind_to(0).unwrap();
        assert_eq!(store.status().unwrap().pending, 1);
    }

    #[test]
    fn get_reads_only_the_applied_state() {
        let dir = tempfile::tempdir().unwrap();
        let store = imported(dir.path(), 8);
        store
            .build(
                block(1, 1, 0),
                vec![write(1, None), write(4, Some(4))].into(),
            )
            .unwrap();
        assert_eq!(
            store.get_slot(write(1, None).key).unwrap(),
            write(1, Some(1)).value
        );
        assert_eq!(store.get_slot(write(4, None).key).unwrap(), None);

        store.finalize(B256::repeat_byte(1)).unwrap();
        assert_eq!(
            store
                .get_slots(vec![write(1, None).key, write(4, None).key])
                .unwrap(),
            vec![None, write(4, Some(4)).value]
        );
    }

    #[test]
    fn rejects_blocks_at_or_below_the_applied_block() {
        let dir = tempfile::tempdir().unwrap();
        let store = imported(dir.path(), 8);
        assert!(matches!(
            store.build(block(0, 1, 0), Writes::default()),
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
        store
            .build(block(1, 1, 0), Writes::default())
            .unwrap()
            .root();
        store
            .build(block(2, 2, 1), Writes::default())
            .unwrap()
            .root();
        // Rebuilding a held block replaces it instead of counting against the bound.
        store
            .build(block(2, 2, 1), vec![write(4, Some(4))].into())
            .unwrap()
            .root();
        assert!(matches!(
            store.build(block(3, 3, 2), Writes::default()),
            Err(Error::TooManyPending(2))
        ));
    }

    #[test]
    fn unregistered_batch_extends_once_registered() {
        let dir = tempfile::tempdir().unwrap();
        let store = imported(dir.path(), 8);
        let batch = store
            .build_unregistered(1, B256::ZERO, vec![write(4, Some(4))].into())
            .unwrap();
        // Same writes on the same parent give the same root as a registered build.
        let registered = store
            .build(block(1, 1, 0), vec![write(4, Some(4))].into())
            .unwrap();
        assert_eq!(batch.root(), registered.root());
        assert!(matches!(
            store.build(block(2, 2, 0xb1), Writes::default()),
            Err(Error::UnknownParent { number: 2, .. })
        ));

        store.register(B256::repeat_byte(0xb1), batch).unwrap();
        let child = store
            .build(block(2, 2, 0xb1), vec![write(5, Some(5))].into())
            .unwrap();
        store.finalize(B256::repeat_byte(2)).unwrap();
        assert_eq!(store.status().unwrap().root, child.root());
    }

    #[test]
    fn import_requires_an_empty_database() {
        let dir = tempfile::tempdir().unwrap();
        let store = imported(dir.path(), 8);
        assert!(matches!(
            store.import_chunk(Writes::default(), Some((1, B256::repeat_byte(1)))),
            Err(Error::NotEmpty(0))
        ));
    }

    #[test]
    fn build_detached_reports_on_the_store_thread() {
        let dir = tempfile::tempdir().unwrap();
        let store = imported(dir.path(), 8);
        let (tx, rx) = mpsc::channel();
        store
            .build_detached(
                block(1, 1, 0),
                vec![write(4, Some(4))].into(),
                move |root| {
                    tx.send(root.map_err(|err| err.to_string())).unwrap();
                },
            )
            .unwrap();
        let root = rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .unwrap()
            .unwrap();
        assert_eq!(store.root(B256::repeat_byte(1)).unwrap(), Some(root));
    }

    #[test]
    fn writes_reach_their_own_database() {
        let dir = tempfile::tempdir().unwrap();
        let store = imported(dir.path(), 8);
        let account = layout::AccountRecord::new(5, U256::ZERO, None, &[])
            .unwrap()
            .encode();
        let writes = Writes {
            accounts: vec![Write {
                key: Key::new([1; 32]),
                value: Some(account.clone()),
            }],
            slots: vec![write(4, Some(4))],
        };
        let root = store.build(block(1, 1, 0), writes).unwrap().root();
        store.finalize(B256::repeat_byte(1)).unwrap();
        assert_eq!(store.status().unwrap().root, root);
        // The same key holds independent values in the two databases.
        assert_eq!(store.get_account(Key::new([1; 32])).unwrap(), Some(account));
        assert_eq!(
            store.get_slot(Key::new([1; 32])).unwrap(),
            write(1, Some(1)).value
        );
        assert_eq!(store.get_account(Key::new([4; 32])).unwrap(), None);
        assert_eq!(
            store.get_slot(Key::new([4; 32])).unwrap(),
            write(4, Some(4)).value
        );
    }

    #[test]
    fn reopening_rewinds_databases_left_out_of_step() {
        // Both apply the same block 1; only `two` applies block 2.
        let (one, two) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let root1 = {
            let store = imported(one.path(), 8);
            let root1 = store
                .build(block(1, 1, 0), vec![write(4, Some(4))].into())
                .unwrap()
                .root();
            store.finalize(B256::repeat_byte(1)).unwrap();
            root1
        };
        {
            let store = imported(two.path(), 8);
            store
                .build(block(1, 1, 0), vec![write(4, Some(4))].into())
                .unwrap();
            store
                .build(block(2, 2, 1), vec![write(5, Some(5))].into())
                .unwrap();
            store.finalize(B256::repeat_byte(2)).unwrap();
        }
        // `one` takes `two`'s slots, as if it crashed after committing only them for block 2.
        for entry in std::fs::read_dir(one.path()).unwrap() {
            let path = entry.unwrap().path();
            if path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("slots-")
            {
                std::fs::remove_dir_all(path).unwrap();
            }
        }
        for entry in std::fs::read_dir(two.path()).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_owned();
            if name.to_str().unwrap().starts_with("slots-") {
                std::fs::rename(&path, one.path().join(name)).unwrap();
            }
        }

        let store = Store::open(config(one.path(), 8)).unwrap();
        assert_eq!(
            store.status().unwrap(),
            Status {
                applied: Some(1),
                base: Some(B256::repeat_byte(1)),
                root: root1,
                pending: 0
            }
        );
        assert_eq!(store.get_slot(Key::new([5; 32])).unwrap(), None);
    }
}
