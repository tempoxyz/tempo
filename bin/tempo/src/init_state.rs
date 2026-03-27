//! TIP20 state initialization commands.
//!
//! - [`InitFromBinaryDump`]: loads TIP20 storage slots from a binary file produced
//!   by `tempo-xtask generate-state-bloat` and applies them to the genesis state.
//! - [`GenerateStateBloat`]: derives TIP20 storage slots directly and writes them
//!   into the database, bypassing the intermediate binary file.

use std::{
    fs::File,
    io::{BufReader, Read},
    path::PathBuf,
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};

use alloy_primitives::{
    B256, U256, keccak256,
    map::{AddressMap, Entry},
};
use alloy_signer::utils::secret_key_to_address;
use alloy_signer_local::coins_bip39::{English, Mnemonic};
use clap::Parser;
use coins_bip32::prelude::*;
use eyre::{Context as _, ensure};
use rayon::prelude::*;
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
use reth_provider::{BlockNumReader, DBProvider, DatabaseProviderFactory, HashingWriter};
use reth_storage_api::{StorageSettingsCache, TrieWriter};
use reth_trie::{IntermediateStateRootState, StateRootProgress};
use reth_trie_db::DatabaseStateRoot;
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_precompiles::tip20::tip20_slots;
use tempo_primitives::transaction::TIP20_PAYMENT_PREFIX;
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

/// Result type for the hash worker thread.
type HashWorkerResult = eyre::Result<Collector<Vec<u8>, CompactU256>>;

/// Encapsulates ETL collection, hashing, genesis merge, DB writes, and trie
/// computation for bulk-loading TIP20 storage into the database.
struct StorageLoader {
    plain_collector: Collector<Vec<u8>, CompactU256>,
    hash_chunk: Vec<(alloy_primitives::Address, B256, CompactU256)>,
    hash_tx: mpsc::SyncSender<Vec<(alloy_primitives::Address, B256, CompactU256)>>,
    hash_worker: Option<thread::JoinHandle<HashWorkerResult>>,
    /// Track addresses and their account data for hashing
    accounts_seen: AddressMap<Account>,
    total_entries: u64,
}

impl StorageLoader {
    /// Create a new `StorageLoader`, spawning the background hash worker.
    fn new() -> Self {
        // ETL collectors: accumulate entries sorted, spill to disk when full
        let plain_collector: Collector<Vec<u8>, CompactU256> = Collector::new(ETL_FILE_SIZE, None);
        let hash_chunk: Vec<(alloy_primitives::Address, B256, CompactU256)> =
            Vec::with_capacity(WORKER_CHUNK_SIZE);

        // Single worker thread for keccak hashing: owns the hashed ETL collector, receives
        // batches over a bounded channel, and returns the collector when the sender drops.
        let (hash_tx, hash_rx) = mpsc::sync_channel::<
            Vec<(alloy_primitives::Address, B256, CompactU256)>,
        >(HASH_WORKER_QUEUE_DEPTH);
        let hash_worker = thread::spawn(move || -> HashWorkerResult {
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

    /// Ensure the address has an entry in `PlainAccountState`, reading the
    /// existing genesis account (preserving its bytecode hash) or inserting a
    /// default. No-ops on subsequent calls for the same address.
    fn ensure_account<P>(
        &mut self,
        provider: &P,
        address: alloy_primitives::Address,
    ) -> eyre::Result<()>
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
    fn push_entry(
        &mut self,
        address: alloy_primitives::Address,
        slot: B256,
        value: U256,
    ) -> eyre::Result<()> {
        // Zero values mean deletion, so both direct generation and binary loading
        // must skip them to preserve the historical loader semantics.
        if value.is_zero() {
            return Ok(());
        }

        let compact_value = CompactU256::from(value);

        // Plain key = address ++ slot ++ 0x01 priority suffix (genesis uses 0x00).
        // `load_etl_to_cursor` keeps the last value per base key, so dump wins.
        let mut plain_key = Vec::with_capacity(53);
        plain_key.extend_from_slice(address.as_slice());
        plain_key.extend_from_slice(slot.as_slice());
        plain_key.push(0x01);
        self.plain_collector
            .insert(plain_key, compact_value.clone())
            .wrap_err("ETL insert failed")?;

        // Queue raw data for parallel hashing
        self.hash_chunk.push((address, slot, compact_value));
        // Send full batches to the hashing worker thread.
        if self.hash_chunk.len() >= WORKER_CHUNK_SIZE {
            let chunk =
                std::mem::replace(&mut self.hash_chunk, Vec::with_capacity(WORKER_CHUNK_SIZE));
            self.hash_tx
                .send(chunk)
                .wrap_err("hash worker disconnected")?;
        }

        self.total_entries += 1;
        Ok(())
    }

    /// Return the number of entries pushed so far.
    fn total_entries(&self) -> u64 {
        self.total_entries
    }

    /// Finish the load: join the hash worker, merge genesis storage, bulk-write
    /// both tables, write hashed accounts, and compute the state root.
    fn finish<P>(mut self, provider_rw: &P) -> eyre::Result<B256>
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
        // Strategy: iterate the sorted collector, deduplicate consecutive entries with
        // the same composite key, and bulk-insert via append_dup.
        // The table is cleared first so append_dup ordering is guaranteed.
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
        // This preserves bytecode_hash for genesis accounts (e.g. TIP20 tokens with 0xEF code).
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

        // Rebuild the merkle trie from scratch so the sparse trie cache on
        // block 1 doesn't hit stale genesis nodes and stall on a full rebuild.
        let trie_start = Instant::now();
        provider_rw.tx_ref().clear::<tables::AccountsTrie>()?;
        provider_rw.tx_ref().clear::<tables::StoragesTrie>()?;

        let mut resume: Option<IntermediateStateRootState> = None;
        let mut trie_writes = 0usize;

        // Incrementally compute the merkle root over all hashed accounts/storage,
        // using the correct DB adapter (v2 vs legacy) resolved at runtime by the macro.
        let state_root = reth_trie_db::with_adapter!(provider_rw, |A| {
            use reth_trie_db::{DatabaseHashedCursorFactory, DatabaseTrieCursorFactory};
            type DbStateRoot<'a, TX, Adapter> = reth_trie::StateRoot<
                DatabaseTrieCursorFactory<&'a TX, Adapter>,
                DatabaseHashedCursorFactory<&'a TX>,
            >;

            // Compute state root in chunks, flushing trie nodes to disk between iterations.
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

        Ok(state_root)
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

        let total_entries = loader.total_entries();
        let state_root = loader.finish(&provider_rw)?;

        // Final commit
        provider_rw.commit()?;

        info!(
            target: "tempo::cli",
            total_blocks,
            total_entries,
            state_root = %state_root,
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

/// Default chunk size: 256k entries per chunk.
const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// Generate TIP20 state bloat directly into the database.
#[derive(Debug, Parser)]
pub(crate) struct GenerateStateBloat<C: reth_cli::chainspec::ChainSpecParser = TempoChainSpecParser>
{
    #[command(flatten)]
    env: EnvironmentArgs<C>,

    /// Mnemonic to use for account generation.
    #[arg(
        short,
        long,
        default_value = "test test test test test test test test test test test junk"
    )]
    mnemonic: String,

    /// Target state size in MiB (controls number of accounts per token).
    #[arg(short, long, default_value = "1024")]
    size: u64,

    /// Token IDs to generate storage for (can be specified multiple times).
    /// Uses reserved TIP20 addresses: 0x20C0...{token_id}
    #[arg(short, long, default_values_t = vec![0u64])]
    token: Vec<u64>,

    /// Balance value to assign to each account (in smallest units).
    #[arg(long, default_value = "1000000")]
    balance: u64,

    /// Number of addresses to derive using proper BIP32 (signable).
    /// Remaining addresses use fast keccak-based derivation (not signable).
    #[arg(long, default_value = "10000")]
    signable_count: usize,

    /// Number of entries to process per chunk. Controls peak memory usage.
    #[arg(long, default_value_t = DEFAULT_CHUNK_SIZE)]
    chunk_size: usize,
}

impl<C: reth_cli::chainspec::ChainSpecParser<ChainSpec: EthChainSpec + EthereumHardforks>>
    GenerateStateBloat<C>
{
    /// Execute the generate-state-bloat command.
    pub(crate) async fn execute<N>(self, runtime: Runtime) -> eyre::Result<()>
    where
        N: CliNodeTypes<ChainSpec = C::ChainSpec>,
    {
        info!(target: "tempo::cli", "Tempo generate-state-bloat starting");

        let environment = self.env.init::<N>(AccessRights::RW, runtime)?;
        let provider_factory = environment.provider_factory;
        let provider_rw = provider_factory.database_provider_rw()?;

        // Verify we're at genesis (block 0)
        let last_block = provider_rw.last_block_number()?;
        ensure!(
            last_block == 0,
            "generate-state-bloat must be run on a freshly initialized database at block 0, \
             but found block {last_block}"
        );

        ensure!(
            !self.token.is_empty(),
            "at least one token ID must be specified"
        );
        ensure!(self.size > 0, "size must be greater than 0");
        ensure!(self.chunk_size > 0, "chunk_size must be greater than 0");

        let target_bytes = self.size * 1024 * 1024;
        let num_tokens = self.token.len() as u64;

        // Calculate number of accounts needed (same formula as xtask).
        let header_size = 40u64;
        let entry_size = 64u64;
        let overhead_per_token = header_size + entry_size;
        let available_for_balances = target_bytes.saturating_sub(num_tokens * overhead_per_token);
        let total_balance_entries = available_for_balances / entry_size;
        let accounts_per_token = total_balance_entries / num_tokens;

        ensure!(
            accounts_per_token > 0,
            "target size too small for the number of tokens"
        );

        let total_accounts = accounts_per_token as usize;
        let actual_signable = self.signable_count.min(total_accounts);
        let num_chunks = total_accounts.div_ceil(self.chunk_size);

        // Derive parent key
        let parent_key = derive_parent_key(&self.mnemonic)?;
        let parent_key = Arc::new(parent_key);
        let seed = keccak256(self.mnemonic.as_bytes());

        // Generate token addresses
        let token_addresses: Vec<alloy_primitives::Address> =
            self.token.iter().map(|&id| token_address(id)).collect();

        // Precompute constants
        let balance_value = U256::from(self.balance);
        let total_supply = balance_value * U256::from(total_accounts);

        info!(
            target: "tempo::cli",
            num_tokens,
            accounts_per_token,
            num_chunks,
            chunk_size = self.chunk_size,
            "Generating state bloat"
        );

        let mut loader = StorageLoader::new();
        let mut is_first_chunk = true;

        for (chunk_idx, chunk_start) in (0..total_accounts).step_by(self.chunk_size).enumerate() {
            let chunk_end = (chunk_start + self.chunk_size).min(total_accounts);
            let chunk_indices: Vec<usize> = (chunk_start..chunk_end).collect();
            let chunk_len = chunk_indices.len();

            // Parallel address derivation + slot computation
            let parent_key_ref = Arc::clone(&parent_key);
            let slot_bytes: Vec<[u8; 32]> = chunk_indices
                .into_par_iter()
                .map(|i| {
                    let addr = if i < actual_signable {
                        let child = parent_key_ref
                            .derive_child(i as u32)
                            .expect("child derivation should not fail");
                        let key: &coins_bip32::prelude::SigningKey = child.as_ref();
                        let credential =
                            k256::ecdsa::SigningKey::from_bytes(&key.to_bytes()).unwrap();
                        secret_key_to_address(&credential)
                    } else {
                        derive_address_fast(&seed, i as u64)
                    };
                    compute_mapping_slot(addr, tip20_slots::BALANCES).to_be_bytes::<32>()
                })
                .collect();

            // Write entries for each token
            for token_addr in &token_addresses {
                loader.ensure_account(&provider_rw, *token_addr)?;

                // Only write total_supply in the first chunk
                if is_first_chunk {
                    loader.push_entry(
                        *token_addr,
                        B256::from(tip20_slots::TOTAL_SUPPLY.to_be_bytes::<32>()),
                        total_supply,
                    )?;
                }

                // Write balance entries
                for slot in &slot_bytes {
                    loader.push_entry(*token_addr, B256::from(*slot), balance_value)?;
                }
            }

            is_first_chunk = false;

            info!(
                target: "tempo::cli",
                chunk = chunk_idx + 1,
                num_chunks,
                entries = chunk_len,
                total_entries = loader.total_entries(),
                "Chunk processed"
            );
        }

        let total_entries = loader.total_entries();
        let state_root = loader.finish(&provider_rw)?;

        provider_rw.commit()?;

        info!(
            target: "tempo::cli",
            total_entries,
            state_root = %state_root,
            "State bloat generated successfully"
        );

        Ok(())
    }
}

/// Compute a reserved TIP20 token address from a token ID.
fn token_address(token_id: u64) -> alloy_primitives::Address {
    let mut bytes = [0u8; 20];
    bytes[..12].copy_from_slice(&TIP20_PAYMENT_PREFIX);
    bytes[12..].copy_from_slice(&token_id.to_be_bytes());
    alloy_primitives::Address::from(bytes)
}

/// Fast address derivation using keccak256(seed || index).
fn derive_address_fast(seed: &[u8; 32], index: u64) -> alloy_primitives::Address {
    let mut buf = [0u8; 40];
    buf[..32].copy_from_slice(seed);
    buf[32..].copy_from_slice(&index.to_be_bytes());
    let hash = keccak256(buf);
    alloy_primitives::Address::from_slice(&hash[12..])
}

/// Derive the parent key for BIP44 Ethereum path: m/44'/60'/0'/0
fn derive_parent_key(mnemonic_phrase: &str) -> eyre::Result<coins_bip32::prelude::XPriv> {
    let mnemonic = Mnemonic::<English>::new_from_phrase(mnemonic_phrase)
        .map_err(|e| eyre::eyre!("invalid mnemonic: {e}"))?;

    let master: coins_bip32::prelude::XPriv = mnemonic
        .derive_key("m/44'/60'/0'/0", None)
        .map_err(|e| eyre::eyre!("key derivation failed: {e}"))?;

    Ok(master)
}

/// Compute a Solidity mapping slot: keccak256(pad32(key) || pad32(base_slot))
fn compute_mapping_slot(key: alloy_primitives::Address, base_slot: U256) -> U256 {
    let mut buf = [0u8; 64];
    buf[12..32].copy_from_slice(key.as_slice());
    buf[32..].copy_from_slice(&base_slot.to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(buf).0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_loader_skips_zero_value_entries() {
        let mut loader = StorageLoader::new();

        loader
            .push_entry(alloy_primitives::Address::ZERO, B256::ZERO, U256::ZERO)
            .unwrap();

        assert_eq!(loader.total_entries(), 0);
        assert_eq!(loader.plain_collector.len(), 0);
        assert!(loader.hash_chunk.is_empty());
    }

    #[test]
    fn load_etl_to_cursor_keeps_highest_priority_value() {
        let mut collector = Collector::new(ETL_FILE_SIZE, None);
        let mut winning_key = vec![0x12; 52];
        let mut losing_key = winning_key.clone();
        losing_key.push(0x00);
        winning_key.push(0x01);

        collector
            .insert(losing_key, CompactU256::from(U256::from(7u64)))
            .unwrap();
        collector
            .insert(winning_key, CompactU256::from(U256::from(9u64)))
            .unwrap();

        let mut written = Vec::new();
        let total = collector.len();
        load_etl_to_cursor(&mut collector, total, "test", |key, value| {
            written.push((key.to_vec(), value));
            Ok(())
        })
        .unwrap();

        assert_eq!(written.len(), 1);
        assert_eq!(written[0].0, vec![0x12; 52]);
        assert_eq!(written[0].1, U256::from(9u64));
    }
}
