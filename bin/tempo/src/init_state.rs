//! Initialize state from a binary dump file.
//!
//! This command loads TIP20 storage slots from a binary file and applies them
//! to the genesis state. The binary format is produced by `tempo-xtask generate-state-bloat`.

use std::{
    fs::File,
    io::{BufReader, Read},
    path::PathBuf,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use alloy_primitives::{
    B256, U256, keccak256,
    map::{AddressMap, Entry},
};
use clap::Parser;
use eyre::{Context as _, ensure};
use reth_chainspec::EthereumHardforks;
use reth_cli_commands::common::{AccessRights, CliNodeTypes, EnvironmentArgs};
use reth_db_api::{
    cursor::{DbCursorRO, DbCursorRW, DbDupCursorRW},
    models::CompactU256,
    table::Decompress,
    tables,
    transaction::{DbTx, DbTxMut},
};
use reth_ethereum::{chainspec::EthChainSpec, tasks::Runtime};
use reth_etl::Collector;
use reth_primitives_traits::{Account, StorageEntry};
use reth_provider::{BlockNumReader, DatabaseProviderFactory, HashingWriter};
use reth_storage_api::{DBProvider, StorageSettingsCache, TrieWriter};
use reth_trie::{IntermediateStateRootState, StateRootProgress};
use reth_trie_db::DatabaseStateRoot;
use tempo_chainspec::spec::TempoChainSpecParser;
use tracing::info;

/// Magic bytes for the state bloat binary format (8 bytes)
const MAGIC: &[u8; 8] = b"TEMPOSB\x00";

/// Expected format version
const VERSION: u16 = 1;

/// ETL collector file size (200 MiB per temp file before spilling a new one).
const ETL_FILE_SIZE: usize = 200 * 1024 * 1024;

/// Maximum number of storage entries to hash per worker batch.
const WORKER_CHUNK_SIZE: usize = 4096;

/// Bounded channel depth for the hashing worker thread.
const HASH_WORKER_QUEUE_DEPTH: usize = 256;

/// Statistics returned after a storage load operation.
pub(crate) struct LoadStats {
    pub(crate) total_entries: u64,
    pub(crate) state_root: B256,
}

/// Encapsulates ETL collection, hashing, genesis merge, DB writes, and trie
/// computation for bulk-loading TIP20 storage into the database.
pub(crate) struct StorageLoader {
    plain_collector: Collector<Vec<u8>, CompactU256>,
    hash_chunk: Vec<(alloy_primitives::Address, B256, CompactU256)>,
    hash_tx: mpsc::SyncSender<Vec<(alloy_primitives::Address, B256, CompactU256)>>,
    hash_worker: Option<thread::JoinHandle<eyre::Result<Collector<Vec<u8>, CompactU256>>>>,
    accounts_seen: AddressMap<Account>,
    total_entries: u64,
}

impl StorageLoader {
    /// Create a new `StorageLoader`, spawning the background hash worker.
    pub(crate) fn new() -> Self {
        let plain_collector: Collector<Vec<u8>, CompactU256> =
            Collector::new(ETL_FILE_SIZE, None);
        let hash_chunk: Vec<(alloy_primitives::Address, B256, CompactU256)> =
            Vec::with_capacity(WORKER_CHUNK_SIZE);

        let (hash_tx, hash_rx) = mpsc::sync_channel::<
            Vec<(alloy_primitives::Address, B256, CompactU256)>,
        >(HASH_WORKER_QUEUE_DEPTH);
        let hash_worker =
            thread::spawn(move || -> eyre::Result<Collector<Vec<u8>, CompactU256>> {
                let mut hashed_collector: Collector<Vec<u8>, CompactU256> =
                    Collector::new(ETL_FILE_SIZE, None);
                while let Ok(chunk) = hash_rx.recv() {
                    let mut last_addr = alloy_primitives::Address::ZERO;
                    let mut hashed_addr = B256::ZERO;
                    for (address, slot, value) in chunk {
                        if address != last_addr {
                            last_addr = address;
                            hashed_addr = keccak256(address);
                        }
                        let mut hashed_key = Vec::with_capacity(65);
                        hashed_key.extend_from_slice(hashed_addr.as_slice());
                        hashed_key.extend_from_slice(keccak256(slot).as_slice());
                        hashed_key.push(0x01);
                        hashed_collector
                            .insert(hashed_key, value)
                            .wrap_err("hashed ETL insert failed")?;
                    }
                }
                Ok(hashed_collector)
            });

        Self {
            plain_collector,
            hash_chunk,
            hash_tx,
            hash_worker: Some(hash_worker),
            accounts_seen: AddressMap::default(),
            total_entries: 0,
        }
    }

    /// Ensure the given address exists in `PlainAccountState`, caching it for
    /// later hashed-account writes. No-ops if the address has already been seen.
    pub(crate) fn ensure_account<P>(&mut self, provider: &P, address: alloy_primitives::Address) -> eyre::Result<()>
    where
        P: DBProvider<Tx: DbTxMut>,
    {
        if let Entry::Vacant(e) = self.accounts_seen.entry(address) {
            let tx = provider.tx_ref();
            let mut account_cursor = tx.cursor_write::<tables::PlainAccountState>()?;
            let account = match account_cursor.seek_exact(address)? {
                Some((_, account)) => account,
                None => {
                    let account = Account::default();
                    account_cursor.upsert(address, &account)?;
                    account
                }
            };
            e.insert(account);
        }
        Ok(())
    }

    /// Feed a single (address, slot, value) entry into the plain collector and
    /// the hash worker. Increments the total entry counter.
    pub(crate) fn push_entry(
        &mut self,
        address: alloy_primitives::Address,
        slot: B256,
        value: U256,
    ) -> eyre::Result<()> {
        let compact_value = CompactU256::from(value);

        // Append a 0x01 priority suffix so dump entries sort after genesis
        // entries (which use 0x00) for the same base key. The dedup logic in
        // `load_etl_to_cursor` keeps the last value, so dump wins.
        let mut plain_key = Vec::with_capacity(53);
        plain_key.extend_from_slice(address.as_slice());
        plain_key.extend_from_slice(slot.as_slice());
        plain_key.push(0x01);
        self.plain_collector
            .insert(plain_key, compact_value.clone())
            .wrap_err("ETL insert failed")?;

        self.hash_chunk.push((address, slot, compact_value));
        if self.hash_chunk.len() >= WORKER_CHUNK_SIZE {
            let chunk =
                std::mem::replace(&mut self.hash_chunk, Vec::with_capacity(WORKER_CHUNK_SIZE));
            self.hash_tx.send(chunk).wrap_err("hash worker disconnected")?;
        }

        self.total_entries += 1;
        Ok(())
    }

    /// Return the number of entries pushed so far.
    pub(crate) fn total_entries(&self) -> u64 {
        self.total_entries
    }

    /// Finish the load: join the hash worker, merge genesis storage, bulk-write
    /// both tables, write hashed accounts, and compute the state root.
    pub(crate) fn finish<P>(mut self, provider_rw: &P) -> eyre::Result<LoadStats>
    where
        P: DBProvider<Tx: DbTxMut> + HashingWriter + TrieWriter + StorageSettingsCache,
    {
        // Send any remaining entries to the worker and join.
        if !self.hash_chunk.is_empty() {
            self.hash_tx
                .send(std::mem::take(&mut self.hash_chunk))
                .wrap_err("hash worker disconnected")?;
        }
        drop(self.hash_tx);
        let mut hashed_collector = self
            .hash_worker
            .take()
            .expect("hash_worker must be Some")
            .join()
            .map_err(|_| eyre::eyre!("hash worker panicked"))??;

        info!(
            target: "tempo::cli",
            total_entries = self.total_entries,
            "Entries collected, merging genesis storage into ETL collectors..."
        );

        // Merge existing genesis plain storage into the collector so it survives
        // the clear + append_dup bulk load.
        {
            let tx = provider_rw.tx_ref();
            let mut cursor = tx.cursor_read::<tables::PlainStorageState>()?;
            let mut genesis_count = 0usize;
            let walker = cursor.walk(None)?;
            for row in walker {
                let (address, entry) = row?;
                let mut key = Vec::with_capacity(53);
                key.extend_from_slice(address.as_slice());
                key.extend_from_slice(entry.key.as_slice());
                key.push(0x00); // lower priority than dump entries
                self.plain_collector
                    .insert(key, CompactU256::from(entry.value))
                    .wrap_err("ETL insert of genesis plain storage failed")?;
                genesis_count += 1;
            }
            info!(
                target: "tempo::cli",
                genesis_count,
                "Genesis plain storage entries merged into collector"
            );
        }

        // Merge existing genesis hashed storage into the collector.
        {
            let tx = provider_rw.tx_ref();
            let mut cursor = tx.cursor_read::<tables::HashedStorages>()?;
            let mut genesis_count = 0usize;
            let walker = cursor.walk(None)?;
            for row in walker {
                let (hashed_address, entry) = row?;
                let mut key = Vec::with_capacity(65);
                key.extend_from_slice(hashed_address.as_slice());
                key.extend_from_slice(entry.key.as_slice());
                key.push(0x00); // lower priority than dump entries
                hashed_collector
                    .insert(key, CompactU256::from(entry.value))
                    .wrap_err("ETL insert of genesis hashed storage failed")?;
                genesis_count += 1;
            }
            info!(
                target: "tempo::cli",
                genesis_count,
                "Genesis hashed storage entries merged into collector"
            );
        }

        // Load sorted entries from each ETL collector into its database table.
        let total_plain = self.plain_collector.len();
        provider_rw.tx_ref().clear::<tables::PlainStorageState>()?;
        let mut plain_cursor = provider_rw
            .tx_ref()
            .cursor_dup_write::<tables::PlainStorageState>()?;
        load_etl_to_cursor(
            &mut self.plain_collector,
            total_plain,
            "plain storage",
            |k, v| {
                plain_cursor.append_dup(
                    alloy_primitives::Address::from_slice(&k[..20]),
                    StorageEntry {
                        key: B256::from_slice(&k[20..]),
                        value: v,
                    },
                )
            },
        )?;
        drop(plain_cursor);

        info!(
            target: "tempo::cli",
            total_plain,
            "Plain storage written, loading hashed storage from ETL..."
        );

        let total_hashes = hashed_collector.len();
        provider_rw.tx_ref().clear::<tables::HashedStorages>()?;
        let mut hashed_cursor = provider_rw
            .tx_ref()
            .cursor_dup_write::<tables::HashedStorages>()?;
        load_etl_to_cursor(
            &mut hashed_collector,
            total_hashes,
            "hashed storage",
            |k, v| {
                hashed_cursor.append_dup(
                    B256::from_slice(&k[..32]),
                    StorageEntry {
                        key: B256::from_slice(&k[32..]),
                        value: v,
                    },
                )
            },
        )?;
        drop(hashed_cursor);

        info!(
            target: "tempo::cli",
            total_plain,
            total_hashes,
            "Storage written, writing hashed accounts..."
        );

        // Write hashed account entries using the real account metadata from plain state.
        provider_rw.insert_account_for_hashing(
            self.accounts_seen
                .iter()
                .map(|(addr, account)| (*addr, Some(*account))),
        )?;

        info!(
            target: "tempo::cli",
            addresses = self.accounts_seen.len(),
            "Hashed accounts written, computing state root and trie nodes..."
        );

        // Rebuild the merkle trie from scratch.
        let trie_start = Instant::now();
        provider_rw.tx_ref().clear::<tables::AccountsTrie>()?;
        provider_rw.tx_ref().clear::<tables::StoragesTrie>()?;

        let mut resume: Option<IntermediateStateRootState> = None;
        let mut trie_writes = 0usize;

        let state_root = reth_trie_db::with_adapter!(provider_rw, |A| {
            use reth_trie_db::{DatabaseHashedCursorFactory, DatabaseTrieCursorFactory};
            type DbStateRoot<'a, TX, Adapter> = reth_trie::StateRoot<
                DatabaseTrieCursorFactory<&'a TX, Adapter>,
                DatabaseHashedCursorFactory<&'a TX>,
            >;

            loop {
                match DbStateRoot::<_, A>::from_tx(provider_rw.tx_ref())
                    .with_intermediate_state(resume)
                    .root_with_progress()?
                {
                    StateRootProgress::Progress(state, _, updates) => {
                        trie_writes += provider_rw.write_trie_updates(updates)?;
                        info!(
                            target: "tempo::cli",
                            last_key = %state.account_root_state.last_hashed_key,
                            trie_writes,
                            elapsed = ?trie_start.elapsed(),
                            "Flushing trie updates"
                        );
                        resume = Some(*state);
                    }
                    StateRootProgress::Complete(root, _, updates) => {
                        trie_writes += provider_rw.write_trie_updates(updates)?;
                        break root;
                    }
                }
            }
        });

        info!(
            target: "tempo::cli",
            %state_root,
            trie_writes,
            elapsed = ?trie_start.elapsed(),
            "State root computed"
        );

        Ok(LoadStats {
            total_entries: self.total_entries,
            state_root,
        })
    }
}

/// Initialize state from a binary dump file.
#[derive(Debug, Parser)]
pub(crate) struct InitFromBinaryDump<C: reth_cli::chainspec::ChainSpecParser = TempoChainSpecParser>
{
    #[command(flatten)]
    env: EnvironmentArgs<C>,

    /// Path to the binary state dump file.
    ///
    /// The file should be generated by `tempo-xtask generate-state-bloat`.
    #[arg(value_name = "BINARY_DUMP_FILE")]
    state: PathBuf,
}

impl<C: reth_cli::chainspec::ChainSpecParser<ChainSpec: EthChainSpec + EthereumHardforks>>
    InitFromBinaryDump<C>
{
    /// Execute the init-from-binary-dump command.
    pub(crate) async fn execute<N>(self, runtime: Runtime) -> eyre::Result<()>
    where
        N: CliNodeTypes<ChainSpec = C::ChainSpec>,
    {
        info!(target: "tempo::cli", "Tempo init-from-binary-dump starting");

        let environment = self.env.init::<N>(AccessRights::RW, runtime)?;
        let provider_factory = environment.provider_factory;

        let provider_rw = provider_factory.database_provider_rw()?;

        // Verify we're at genesis (block 0)
        let last_block = provider_rw.last_block_number()?;
        ensure!(
            last_block == 0,
            "init-from-binary-dump must be run on a freshly initialized database at block 0, \
             but found block {last_block}"
        );

        info!(target: "tempo::cli", path = %self.state.display(), "Loading binary state dump");

        let file = File::open(&self.state)
            .wrap_err_with(|| format!("failed to open {}", self.state.display()))?;
        let mut reader = BufReader::with_capacity(64 * 1024 * 1024, file);

        let mut loader = StorageLoader::new();
        let mut total_blocks = 0u64;

        // Process blocks from binary file
        loop {
            // Read next block header; EOF means no more blocks.
            let mut header_buf = [0u8; 40];
            match reader.read_exact(&mut header_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e).wrap_err("failed to read block header"),
            }

            // Validate magic
            ensure!(
                &header_buf[..8] == MAGIC,
                "invalid magic bytes in block header"
            );

            // Validate version
            let version = u16::from_be_bytes([header_buf[8], header_buf[9]]);
            ensure!(
                version == VERSION,
                "unsupported binary format version {version}, expected {VERSION}"
            );

            // Skip flags (2 bytes at offset 10)

            // Read address (20 bytes at offset 12)
            let mut address_bytes = [0u8; 20];
            address_bytes.copy_from_slice(&header_buf[12..32]);
            let address = alloy_primitives::Address::from(address_bytes);

            // Read pair count (8 bytes at offset 32)
            let pair_count = u64::from_be_bytes(header_buf[32..40].try_into().unwrap());

            info!(
                target: "tempo::cli",
                %address,
                pair_count,
                "Processing token storage block"
            );

            loader.ensure_account(&provider_rw, address)?;

            // Read entries into both ETL collectors
            let mut entry_buf = [0u8; 64];
            let start = Instant::now();
            let mut last_log = start;

            for i in 0..pair_count {
                reader
                    .read_exact(&mut entry_buf)
                    .wrap_err("failed to read storage entry")?;

                let slot = B256::from_slice(&entry_buf[..32]);
                let value = U256::from_be_bytes::<32>(entry_buf[32..64].try_into().unwrap());

                // Skip zero values (they represent deletion)
                if value.is_zero() {
                    continue;
                }

                loader.push_entry(address, slot, value)?;

                log_collection_progress(&address, i, pair_count, start, &mut last_log);
            }

            total_blocks += 1;
        }

        let stats = loader.finish(&provider_rw)?;

        // Final commit
        provider_rw.commit()?;

        info!(
            target: "tempo::cli",
            total_blocks,
            total_entries = stats.total_entries,
            state_root = %stats.state_root,
            "Binary state dump loaded successfully"
        );

        Ok(())
    }
}

/// Iterate a sorted ETL collector, deduplicate consecutive entries with the same
/// base key (ignoring the trailing priority suffix byte), keeping the last value
/// (highest priority), and call `append` for each unique entry with the suffix
/// stripped.
fn load_etl_to_cursor(
    collector: &mut Collector<Vec<u8>, CompactU256>,
    total: usize,
    label: &str,
    mut append: impl FnMut(&[u8], U256) -> Result<(), reth_db_api::DatabaseError>,
) -> eyre::Result<()> {
    let interval = (total / 10).max(1);
    let mut pending: Option<(Vec<u8>, Vec<u8>)> = None;
    for (index, item) in collector.iter()?.enumerate() {
        if index > 0 && index % interval == 0 {
            info!(
                target: "tempo::cli",
                progress = format_args!("{:.2}%", (index as f64 / total as f64) * 100.0),
                "Inserting {label}"
            );
        }

        let (key, value) = item.wrap_err("ETL iteration failed")?;
        if let Some((ref prev_key, ref prev_val)) = pending
            && prev_key[..prev_key.len() - 1] != key[..key.len() - 1]
        {
            let base_key = &prev_key[..prev_key.len() - 1];
            append(
                base_key,
                CompactU256::decompress_owned(prev_val.clone())?.into(),
            )
            .wrap_err("cursor append failed")?;
        }
        pending = Some((key, value));
    }
    if let Some((key, val)) = pending {
        let base_key = &key[..key.len() - 1];
        append(base_key, CompactU256::decompress_owned(val)?.into())
            .wrap_err("cursor append failed")?;
    }
    Ok(())
}

/// Log collection progress every 5 seconds and on the final entry.
fn log_collection_progress(
    address: &alloy_primitives::Address,
    index: u64,
    total: u64,
    start: Instant,
    last_log: &mut Instant,
) {
    if last_log.elapsed() >= Duration::from_secs(5) || index + 1 == total {
        let pct = ((index + 1) as f64 / total as f64) * 100.0;
        let elapsed = start.elapsed();
        let pairs_per_sec = (index + 1) as f64 / elapsed.as_secs_f64();
        info!(
            target: "tempo::cli",
            %address,
            progress = format_args!("{}/{} ({pct:.0}%)", index + 1, total),
            elapsed = ?elapsed,
            pairs_per_sec = pairs_per_sec as u64,
            "Collecting storage"
        );
        *last_log = Instant::now();
    }
}
