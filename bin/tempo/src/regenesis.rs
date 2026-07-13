//! Patch a virgin block-0 database to use a new genesis header.
//!
//! It replaces the header static file segment and rewrites the hash-to-number index.
//! When requested, it can also replace selected genesis accounts from the new chain spec and
//! update hashed state, trie, and block-0 history without rebuilding unrelated bloat state.

use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use alloy_genesis::{Genesis, GenesisAccount};
use alloy_primitives::{Address, B256, U256, keccak256};
use clap::Parser;
use eyre::{ensure, eyre};
use reth_chainspec::EthChainSpec;
use reth_cli_commands::common::{CliNodeTypes, EnvironmentArgs};
use reth_codecs::Compact;
use reth_db::{
    DatabaseEnv, open_db,
    static_file::{AccountChangesetMask, StaticFileCursor, StorageChangesetMask},
};
use reth_db_api::{
    cursor::{DbCursorRO, DbCursorRW, DbDupCursorRW},
    models::{
        AccountBeforeTx, ShardedKey, StorageBeforeTx, storage_sharded_key::StorageShardedKey,
    },
    tables,
    transaction::{DbTx, DbTxMut},
};
use reth_ethereum::tasks::Runtime;
use reth_nippy_jar::{DataReader, NippyJar, NippyJarWriter};
use reth_node_builder::NodeTypesWithDBAdapter;
use reth_primitives_traits::{Account, AlloyBlockHeader, Bytecode, NodePrimitives, StorageEntry};
use reth_provider::{
    BlockNumReader, DatabaseProviderFactory, LatestStateProviderRef, ProviderFactory,
    RocksDBProviderFactory, StaticFileProviderBuilder, StaticFileProviderFactory,
    StaticFileSegment, StaticFileWriter, StorageSettingsCache, TrieWriter,
    providers::{RocksDBProvider, StaticFileJarProvider},
};
use reth_static_file_types::{ChangesetOffset, SegmentHeader};
use reth_storage_api::{DBProvider, StateRootProvider};
use reth_trie::{HashedPostState, HashedStorage};
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_contracts::precompiles::VALIDATOR_CONFIG_V2_ADDRESS;
use tracing::{info, warn};

/// Patch a block-0 database to use a new genesis header.
#[derive(Debug, Parser)]
pub struct Regenesis<C: reth_cli::chainspec::ChainSpecParser = TempoChainSpecParser> {
    #[command(flatten)]
    env: EnvironmentArgs<C>,

    /// Replace ValidatorConfigV2 storage from the new --chain genesis.
    ///
    /// Use this when the cached block-0 database was built with a different
    /// validator ingress/egress set. Generate a fresh genesis with the desired
    /// validator endpoints, then run regenesis with this flag.
    #[arg(long)]
    sync_validator_config_v2: bool,

    /// Replace a genesis account from the new --chain genesis.
    ///
    /// This is an escape hatch for other small genesis-owned accounts. The
    /// account's existing hashed storage and block-0 history are wiped and
    /// replaced from the provided genesis. This requires storage v2.
    #[arg(long, value_name = "ADDRESS", value_delimiter = ',')]
    sync_genesis_account: Vec<Address>,
}

impl<C> Regenesis<C>
where
    C: reth_cli::chainspec::ChainSpecParser,
    C::ChainSpec: EthChainSpec,
{
    pub(crate) async fn execute<N>(self, runtime: Runtime) -> eyre::Result<()>
    where
        N: CliNodeTypes<ChainSpec = C::ChainSpec>,
        C::ChainSpec: EthChainSpec<Header = <N::Primitives as NodePrimitives>::BlockHeader>,
    {
        let sync_accounts = self.sync_accounts();
        let new_genesis_hash = self.env.chain.genesis_hash();
        let genesis_header = self.env.chain.genesis_header();
        let genesis_block_number = genesis_header.number();
        ensure!(
            genesis_block_number == 0,
            "regenesis only supports block-0 genesis headers, found genesis block {genesis_block_number}"
        );

        let data_dir = self
            .env
            .datadir
            .clone()
            .resolve_datadir(self.env.chain.chain());
        fs::create_dir_all(data_dir.static_files())?;
        fs::create_dir_all(data_dir.rocksdb())?;

        let db = open_db(data_dir.db(), self.env.db.database_args())?;
        let static_file_provider = StaticFileProviderBuilder::read_write(data_dir.static_files())
            .with_metrics()
            .with_genesis_block_number(genesis_block_number)
            .build()?;
        let rocksdb_provider = RocksDBProvider::builder(data_dir.rocksdb())
            .with_default_tables()
            .with_database_log_level(self.env.db.log_level)
            .build()?;

        let provider_factory = ProviderFactory::<NodeTypesWithDBAdapter<N, DatabaseEnv>>::new(
            db,
            self.env.chain.clone(),
            static_file_provider,
            rocksdb_provider,
            runtime,
        )?;
        let provider_rw = provider_factory.database_provider_rw()?;

        let last_block = provider_rw.last_block_number()?;
        ensure!(
            last_block == 0,
            "regenesis only supports virgin block-0 databases, found block {last_block}"
        );

        let tx = provider_rw.tx_ref();
        let (stored_genesis_hash, stored_block_number) = {
            let mut cursor = tx.cursor_read::<tables::HeaderNumbers>()?;
            let entry = cursor.first()?.ok_or_else(|| {
                eyre!("regenesis requires exactly one HeaderNumbers entry, found none")
            })?;
            ensure!(
                cursor.next()?.is_none(),
                "regenesis requires exactly one HeaderNumbers entry, found more than one"
            );
            entry
        };
        ensure!(
            stored_block_number == 0,
            "only HeaderNumbers entry maps to block {stored_block_number}, expected block 0"
        );

        let mut synced_state_root = None;
        if !sync_accounts.is_empty() {
            synced_state_root = sync_genesis_accounts(
                &provider_rw,
                self.env.chain.genesis(),
                genesis_header.state_root(),
                &sync_accounts,
            )?;
        }

        if stored_genesis_hash == new_genesis_hash {
            info!(
                target: "tempo::cli",
                old_genesis_hash = %stored_genesis_hash,
                %new_genesis_hash,
                synced_state_root = synced_state_root.map(|root| root.to_string()),
                "Genesis hash already matches"
            );
            if sync_accounts.is_empty() {
                return Ok(());
            }
        } else {
            let static_file_provider = provider_rw.static_file_provider();
            static_file_provider.delete_segment(StaticFileSegment::Headers)?;
            {
                let mut writer = static_file_provider
                    .get_writer(genesis_block_number, StaticFileSegment::Headers)?;
                writer.append_header(genesis_header, &new_genesis_hash)?;
            }

            tx.delete::<tables::HeaderNumbers>(stored_genesis_hash, None)?;
            tx.put::<tables::HeaderNumbers>(new_genesis_hash, 0)?;
            tx.put::<tables::BlockBodyIndices>(0, Default::default())?;
        }

        provider_rw.commit()?;

        info!(
            target: "tempo::cli",
            old_genesis_hash = %stored_genesis_hash,
            %new_genesis_hash,
            synced_state_root = synced_state_root.map(|root| root.to_string()),
            synced_accounts = sync_accounts.len(),
            "Regenesis complete"
        );

        Ok(())
    }

    fn sync_accounts(&self) -> Vec<Address> {
        sync_accounts(self.sync_validator_config_v2, &self.sync_genesis_account)
    }
}

fn sync_accounts(sync_validator_config_v2: bool, sync_genesis_account: &[Address]) -> Vec<Address> {
    let mut accounts = sync_genesis_account.to_vec();
    if sync_validator_config_v2 {
        accounts.push(VALIDATOR_CONFIG_V2_ADDRESS);
    }
    accounts.sort_unstable();
    accounts.dedup();
    accounts
}

fn sync_genesis_accounts<P>(
    provider_rw: &P,
    genesis: &Genesis,
    genesis_state_root: B256,
    accounts: &[Address],
) -> eyre::Result<Option<B256>>
where
    P: DBProvider
        + StorageSettingsCache
        + TrieWriter
        + StaticFileProviderFactory
        + RocksDBProviderFactory,
    P::Tx: DbTxMut,
{
    if accounts.is_empty() {
        return Ok(None);
    }

    let storage_settings = provider_rw.cached_storage_settings();
    ensure!(
        storage_settings.storage_v2 && storage_settings.use_hashed_state(),
        "regenesis account sync requires a storage v2 database with hashed state enabled"
    );

    let replacements = genesis_account_replacements(genesis, accounts)?;
    let synced_addresses = replacements
        .iter()
        .map(|replacement| replacement.address)
        .collect::<BTreeSet<_>>();

    let hashed_state = replacement_hashed_post_state(&replacements);
    let (state_root, trie_updates) = {
        let latest = LatestStateProviderRef::new(provider_rw);
        latest.state_root_with_updates(hashed_state)?
    };

    replace_hashed_accounts(provider_rw, &replacements)?;
    replace_hashed_storage(provider_rw, &replacements)?;
    provider_rw.write_trie_updates(trie_updates)?;
    let old_storage_history_keys =
        replace_block_zero_static_changesets(provider_rw, &synced_addresses, &replacements)?;
    sync_genesis_account_history(provider_rw, &replacements, old_storage_history_keys)?;

    if state_root != genesis_state_root {
        warn!(
            target: "tempo::cli",
            %state_root,
            %genesis_state_root,
            "Synced account state root differs from --chain genesis state root; preserving regenesis header hash behavior"
        );
    }

    info!(
        target: "tempo::cli",
        %state_root,
        accounts = accounts.len(),
        "Synced genesis account state"
    );

    Ok(Some(state_root))
}

#[derive(Clone, Debug)]
struct GenesisAccountReplacement {
    address: Address,
    hashed_address: B256,
    account: Account,
    bytecode: Option<(B256, Bytecode)>,
    storage: Vec<StorageEntry>,
    hashed_storage: Vec<StorageEntry>,
}

#[derive(Clone, Debug)]
struct StaticChangesetFile {
    path: PathBuf,
    cache_block_end: u64,
    offset: ChangesetOffset,
}

struct OpenStaticChangesetFile {
    jar: NippyJar<SegmentHeader>,
    reader: Arc<DataReader>,
    offset: ChangesetOffset,
}

#[derive(Clone, Debug)]
struct StaticTailReplacementPlan {
    path: PathBuf,
    cache_block_end: u64,
    row_offset: u64,
    rows_to_prune: usize,
    new_num_changes: u64,
}

#[derive(Clone, Debug)]
struct AccountTailReplacementPlan {
    static_plan: StaticTailReplacementPlan,
    appended_changes: Vec<AccountBeforeTx>,
}

#[derive(Clone, Debug)]
struct StorageTailReplacementPlan {
    static_plan: StaticTailReplacementPlan,
    appended_changes: Vec<StorageBeforeTx>,
    old_storage_history_keys: Vec<StorageShardedKey>,
}

fn genesis_account_replacements(
    genesis: &Genesis,
    accounts: &[Address],
) -> eyre::Result<Vec<GenesisAccountReplacement>> {
    accounts
        .iter()
        .map(|&address| {
            let genesis_account = genesis
                .alloc
                .get(&address)
                .ok_or_else(|| eyre!("genesis account {address} is missing from --chain alloc"))?;
            genesis_account_replacement(address, genesis_account)
        })
        .collect()
}

fn genesis_account_replacement(
    address: Address,
    genesis_account: &GenesisAccount,
) -> eyre::Result<GenesisAccountReplacement> {
    let bytecode = if let Some(code) = &genesis_account.code {
        let bytecode = Bytecode::new_raw_checked(code.clone())
            .map_err(|err| eyre!("invalid genesis bytecode for account {address}: {err}"))?;
        Some((bytecode.hash_slow(), bytecode))
    } else {
        None
    };
    let account = Account {
        nonce: genesis_account.nonce.unwrap_or_default(),
        balance: genesis_account.balance,
        bytecode_hash: bytecode.as_ref().map(|(hash, _)| *hash),
    };
    let storage = genesis_storage_entries(genesis_account);
    let mut hashed_storage = storage
        .iter()
        .map(|entry| StorageEntry {
            key: keccak256(entry.key),
            value: entry.value,
        })
        .collect::<Vec<_>>();
    hashed_storage.sort_unstable_by_key(|entry| entry.key);

    Ok(GenesisAccountReplacement {
        address,
        hashed_address: keccak256(address),
        account,
        bytecode,
        storage,
        hashed_storage,
    })
}

fn replacement_hashed_post_state(replacements: &[GenesisAccountReplacement]) -> HashedPostState {
    HashedPostState::default()
        .with_accounts(
            replacements
                .iter()
                .map(|replacement| (replacement.hashed_address, Some(replacement.account))),
        )
        .with_storages(replacements.iter().map(|replacement| {
            let storage = HashedStorage::from_iter(
                true,
                replacement
                    .hashed_storage
                    .iter()
                    .map(|entry| (entry.key, entry.value)),
            );
            (replacement.hashed_address, storage)
        }))
}

fn replacement_account_changeset_entries(
    replacements: &[GenesisAccountReplacement],
) -> Vec<AccountBeforeTx> {
    let mut changeset = replacements
        .iter()
        .map(|replacement| AccountBeforeTx {
            address: replacement.address,
            info: None,
        })
        .collect::<Vec<_>>();
    changeset.sort_unstable_by_key(|change| change.address);
    changeset
}

fn replacement_storage_changeset_entries(
    replacements: &[GenesisAccountReplacement],
) -> Vec<StorageBeforeTx> {
    let mut changeset = replacements
        .iter()
        .flat_map(|replacement| {
            replacement.storage.iter().map(|entry| StorageBeforeTx {
                address: replacement.address,
                key: entry.key,
                value: U256::ZERO,
            })
        })
        .collect::<Vec<_>>();
    changeset.sort_unstable_by_key(|change| (change.address, change.key));
    changeset
}

fn sync_genesis_account_history<P>(
    provider_rw: &P,
    replacements: &[GenesisAccountReplacement],
    mut old_storage_history_keys: Vec<StorageShardedKey>,
) -> eyre::Result<()>
where
    P: RocksDBProviderFactory,
{
    old_storage_history_keys.sort_unstable();
    old_storage_history_keys.dedup();

    provider_rw.with_rocksdb_batch(|mut batch| {
        let block_zero_history =
            tables::BlockNumberList::new([0]).expect("single block always fits");
        for replacement in replacements {
            batch.delete::<tables::AccountsHistory>(ShardedKey::last(replacement.address))?;
            batch.put::<tables::AccountsHistory>(
                ShardedKey::last(replacement.address),
                &block_zero_history,
            )?;
        }

        for key in old_storage_history_keys {
            batch.delete::<tables::StoragesHistory>(key)?;
        }
        for replacement in replacements {
            for entry in &replacement.storage {
                batch.put::<tables::StoragesHistory>(
                    StorageShardedKey::last(replacement.address, entry.key),
                    &block_zero_history,
                )?;
            }
        }

        Ok(((), Some(batch.into_inner())))
    })?;

    Ok(())
}

fn replace_block_zero_static_changesets<P>(
    provider_rw: &P,
    synced_addresses: &BTreeSet<Address>,
    replacements: &[GenesisAccountReplacement],
) -> eyre::Result<Vec<StorageShardedKey>>
where
    P: StaticFileProviderFactory,
{
    let static_file_provider = provider_rw.static_file_provider();
    // A jar provider holds a shard read guard on the provider's jar cache (a dashmap). Acquiring
    // another segment's provider can insert into that map via `entry()`, which takes a shard
    // write lock and self-deadlocks whenever both cache keys land in the same shard. Extract the
    // owned metadata and drop each provider before touching the cache again.
    let old_account_static = {
        let provider = static_file_provider
            .get_maybe_segment_provider(StaticFileSegment::AccountChangeSets, 0)?;
        block_zero_static_changeset_file(provider.as_ref())?
    };
    let old_storage_static = {
        let provider = static_file_provider
            .get_maybe_segment_provider(StaticFileSegment::StorageChangeSets, 0)?;
        block_zero_static_changeset_file(provider.as_ref())?
    };

    let replacement_account_changes = replacement_account_changeset_entries(replacements);
    let replacement_storage_changes = replacement_storage_changeset_entries(replacements);

    let fast_account_plan = account_tail_replacement_plan(
        old_account_static.as_ref(),
        synced_addresses,
        &replacement_account_changes,
    )?;
    let fast_storage_plan = storage_tail_replacement_plan(
        old_storage_static.as_ref(),
        synced_addresses,
        &replacement_storage_changes,
    )?;

    if let (Some(account_plan), Some(storage_plan)) = (fast_account_plan, fast_storage_plan) {
        static_file_provider.remove_cached_provider(
            StaticFileSegment::AccountChangeSets,
            account_plan.static_plan.cache_block_end,
        );
        static_file_provider.remove_cached_provider(
            StaticFileSegment::StorageChangeSets,
            storage_plan.static_plan.cache_block_end,
        );
        replace_static_changeset_tail(
            &account_plan.static_plan,
            &account_plan.appended_changes,
            "account changeset",
        )?;
        replace_static_changeset_tail(
            &storage_plan.static_plan,
            &storage_plan.appended_changes,
            "storage changeset",
        )?;

        return Ok(storage_plan.old_storage_history_keys);
    }

    let old_account_file = open_static_changeset_file(old_account_static.as_ref())?;
    let old_storage_file = open_static_changeset_file(old_storage_static.as_ref())?;

    static_file_provider.delete_segment(StaticFileSegment::AccountChangeSets)?;
    static_file_provider.delete_segment(StaticFileSegment::StorageChangeSets)?;

    {
        let mut writer =
            provider_rw.get_static_file_writer(0, StaticFileSegment::AccountChangeSets)?;
        writer.begin_account_changeset(0)?;

        let mut replacement_changes = replacement_account_changes.into_iter().peekable();

        if let Some(file) = old_account_file.as_ref() {
            let mut cursor = StaticFileCursor::new(&file.jar, Arc::clone(&file.reader))?;
            for row in file.offset.changeset_range() {
                let Some(change) = cursor.get_one::<AccountChangesetMask>(row.into())? else {
                    continue;
                };
                if synced_addresses.contains(&change.address) {
                    continue;
                }
                while let Some(replacement) = replacement_changes.peek() {
                    if replacement.address >= change.address {
                        break;
                    }
                    writer.append_account_changeset_entry(replacement_changes.next().unwrap())?;
                }
                writer.append_account_changeset_entry(change)?;
            }
        }

        for change in replacement_changes {
            writer.append_account_changeset_entry(change)?;
        }
    }

    let mut old_storage_history_keys = Vec::new();
    {
        let mut writer =
            provider_rw.get_static_file_writer(0, StaticFileSegment::StorageChangeSets)?;
        writer.begin_storage_changeset(0)?;

        let mut replacement_changes = replacement_storage_changes.into_iter().peekable();

        if let Some(file) = old_storage_file.as_ref() {
            let mut cursor = StaticFileCursor::new(&file.jar, Arc::clone(&file.reader))?;
            for row in file.offset.changeset_range() {
                let Some(change) = cursor.get_one::<StorageChangesetMask>(row.into())? else {
                    continue;
                };
                if synced_addresses.contains(&change.address) {
                    old_storage_history_keys
                        .push(StorageShardedKey::last(change.address, change.key));
                    continue;
                }
                while let Some(replacement) = replacement_changes.peek() {
                    if (replacement.address, replacement.key) >= (change.address, change.key) {
                        break;
                    }
                    writer.append_storage_changeset_entry(replacement_changes.next().unwrap())?;
                }
                writer.append_storage_changeset_entry(change)?;
            }
        }

        for change in replacement_changes {
            writer.append_storage_changeset_entry(change)?;
        }
    }

    Ok(old_storage_history_keys)
}

fn block_zero_static_changeset_file<N: NodePrimitives>(
    provider: Option<&StaticFileJarProvider<'_, N>>,
) -> eyre::Result<Option<StaticChangesetFile>> {
    provider
        .map(|provider| -> eyre::Result<_> {
            Ok(provider
                .read_changeset_offset(0)?
                .map(|offset| StaticChangesetFile {
                    path: provider.data_path().to_path_buf(),
                    cache_block_end: provider.user_header().expected_block_end(),
                    offset,
                }))
        })
        .transpose()
        .map(Option::flatten)
}

fn open_static_changeset_file(
    file: Option<&StaticChangesetFile>,
) -> eyre::Result<Option<OpenStaticChangesetFile>> {
    file.map(|file| -> eyre::Result<_> {
        let jar = NippyJar::load(&file.path)?;
        let reader = Arc::new(jar.open_data_reader()?);
        Ok(OpenStaticChangesetFile {
            jar,
            reader,
            offset: file.offset.clone(),
        })
    })
    .transpose()
}

fn account_tail_replacement_plan(
    file: Option<&StaticChangesetFile>,
    synced_addresses: &BTreeSet<Address>,
    replacement_changes: &[AccountBeforeTx],
) -> eyre::Result<Option<AccountTailReplacementPlan>> {
    let Some(file) = file else {
        return Ok(None);
    };
    let Some(first_synced_address) = synced_addresses.first().copied() else {
        return Ok(None);
    };

    let jar = NippyJar::load(&file.path)?;
    if file.offset.changeset_range().end != jar.rows() as u64 {
        return Ok(None);
    }
    let reader = Arc::new(jar.open_data_reader()?);
    let mut cursor = StaticFileCursor::new(&jar, Arc::clone(&reader))?;

    let Some(tail_start) =
        find_account_changeset_tail_start(&mut cursor, file.offset.clone(), first_synced_address)?
    else {
        return Ok(None);
    };

    let mut appended_changes = replacement_changes.to_vec();
    for row in tail_start..file.offset.changeset_range().end {
        let Some(change) = cursor.get_one::<AccountChangesetMask>(row.into())? else {
            return Ok(None);
        };
        if !synced_addresses.contains(&change.address) {
            appended_changes.push(change);
        }
    }
    appended_changes.sort_unstable_by_key(|change| change.address);

    let rows_to_prune = (file.offset.changeset_range().end - tail_start) as usize;
    Ok(Some(AccountTailReplacementPlan {
        static_plan: StaticTailReplacementPlan {
            path: file.path.clone(),
            cache_block_end: file.cache_block_end,
            row_offset: file.offset.offset(),
            rows_to_prune,
            new_num_changes: file.offset.num_changes() - rows_to_prune as u64
                + appended_changes.len() as u64,
        },
        appended_changes,
    }))
}

fn storage_tail_replacement_plan(
    file: Option<&StaticChangesetFile>,
    synced_addresses: &BTreeSet<Address>,
    replacement_changes: &[StorageBeforeTx],
) -> eyre::Result<Option<StorageTailReplacementPlan>> {
    let Some(file) = file else {
        return Ok(None);
    };
    let Some(first_synced_address) = synced_addresses.first().copied() else {
        return Ok(None);
    };

    let jar = NippyJar::load(&file.path)?;
    if file.offset.changeset_range().end != jar.rows() as u64 {
        return Ok(None);
    }
    let reader = Arc::new(jar.open_data_reader()?);
    let mut cursor = StaticFileCursor::new(&jar, Arc::clone(&reader))?;

    let Some(tail_start) = find_storage_changeset_tail_start(
        &mut cursor,
        file.offset.clone(),
        first_synced_address,
        B256::ZERO,
    )?
    else {
        return Ok(None);
    };

    let mut appended_changes = replacement_changes.to_vec();
    let mut old_storage_history_keys = Vec::new();
    for row in tail_start..file.offset.changeset_range().end {
        let Some(change) = cursor.get_one::<StorageChangesetMask>(row.into())? else {
            return Ok(None);
        };
        if synced_addresses.contains(&change.address) {
            old_storage_history_keys.push(StorageShardedKey::last(change.address, change.key));
        } else {
            appended_changes.push(change);
        }
    }
    appended_changes.sort_unstable_by_key(|change| (change.address, change.key));

    let rows_to_prune = (file.offset.changeset_range().end - tail_start) as usize;
    Ok(Some(StorageTailReplacementPlan {
        static_plan: StaticTailReplacementPlan {
            path: file.path.clone(),
            cache_block_end: file.cache_block_end,
            row_offset: file.offset.offset(),
            rows_to_prune,
            new_num_changes: file.offset.num_changes() - rows_to_prune as u64
                + appended_changes.len() as u64,
        },
        appended_changes,
        old_storage_history_keys,
    }))
}

fn find_account_changeset_tail_start(
    cursor: &mut StaticFileCursor<'_>,
    offset: ChangesetOffset,
    address: Address,
) -> eyre::Result<Option<u64>> {
    let mut low = offset.changeset_range().start;
    let mut high = offset.changeset_range().end;

    while low < high {
        let mid = low + (high - low) / 2;
        let Some(change) = cursor.get_one::<AccountChangesetMask>(mid.into())? else {
            return Ok(None);
        };
        if change.address < address {
            low = mid + 1;
        } else {
            high = mid;
        }
    }

    Ok(Some(low))
}

fn find_storage_changeset_tail_start(
    cursor: &mut StaticFileCursor<'_>,
    offset: ChangesetOffset,
    address: Address,
    key: B256,
) -> eyre::Result<Option<u64>> {
    let mut low = offset.changeset_range().start;
    let mut high = offset.changeset_range().end;

    while low < high {
        let mid = low + (high - low) / 2;
        let Some(change) = cursor.get_one::<StorageChangesetMask>(mid.into())? else {
            return Ok(None);
        };
        if (change.address, change.key) < (address, key) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }

    Ok(Some(low))
}

fn replace_static_changeset_tail<T>(
    plan: &StaticTailReplacementPlan,
    replacement_changes: &[T],
    label: &'static str,
) -> eyre::Result<()>
where
    T: Compact,
{
    let jar = NippyJar::<SegmentHeader>::load(&plan.path)?;
    let mut writer = NippyJarWriter::new(jar)?;
    if plan.rows_to_prune > 0 {
        writer.prune_rows(plan.rows_to_prune)?;
    }

    let mut buf = Vec::new();
    for change in replacement_changes {
        buf.clear();
        change.to_compact(&mut buf);
        writer.append_column(Some(Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
            &buf,
        )))?;
    }
    writer.commit()?;
    write_block_zero_changeset_offset(&plan.path, plan.row_offset, plan.new_num_changes)?;

    info!(
        target: "tempo::cli",
        rows_to_prune = plan.rows_to_prune,
        replacement_rows = replacement_changes.len(),
        %label,
        "Replaced block-0 static changeset tail"
    );

    Ok(())
}

fn write_block_zero_changeset_offset(
    path: &Path,
    row_offset: u64,
    num_changes: u64,
) -> eyre::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path.with_extension("csoff"))?;
    file.write_all(&row_offset.to_le_bytes())?;
    file.write_all(&num_changes.to_le_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn replace_hashed_accounts<P>(
    provider_rw: &P,
    replacements: &[GenesisAccountReplacement],
) -> eyre::Result<()>
where
    P: DBProvider,
    P::Tx: DbTxMut,
{
    let tx = provider_rw.tx_ref();
    for replacement in replacements {
        if let Some((hash, bytecode)) = &replacement.bytecode {
            tx.put::<tables::Bytecodes>(*hash, bytecode.clone())?;
        }
        tx.put::<tables::HashedAccounts>(replacement.hashed_address, replacement.account)?;
    }

    Ok(())
}

fn replace_hashed_storage<P>(
    provider_rw: &P,
    replacements: &[GenesisAccountReplacement],
) -> eyre::Result<()>
where
    P: DBProvider,
    P::Tx: DbTxMut,
{
    let tx = provider_rw.tx_ref();
    let mut cursor = tx.cursor_dup_write::<tables::HashedStorages>()?;

    for replacement in replacements {
        if cursor.seek_exact(replacement.hashed_address)?.is_some() {
            cursor.delete_current_duplicates()?;
        }

        for entry in &replacement.hashed_storage {
            cursor.upsert(replacement.hashed_address, entry)?;
        }
    }

    Ok(())
}

fn genesis_storage_entries(account: &GenesisAccount) -> Vec<StorageEntry> {
    let mut entries = account
        .storage
        .as_ref()
        .into_iter()
        .flat_map(|storage| storage.iter())
        .filter_map(|(slot, value)| {
            let value = U256::from_be_slice(value.as_slice());
            (!value.is_zero()).then_some(StorageEntry { key: *slot, value })
        })
        .collect::<Vec<_>>();

    entries.sort_unstable_by_key(|entry| entry.key);
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_provider::{
        ProviderResult,
        providers::{StaticFileProvider, StaticFileProviderRWRefMut},
    };
    use reth_storage_api::{ChangeSetReader, NodePrimitivesProvider, StorageChangeSetReader};
    use std::collections::{BTreeMap, BTreeSet};
    use tempo_primitives::TempoPrimitives;

    #[derive(Clone)]
    struct StaticOnlyProvider {
        provider: StaticFileProvider<TempoPrimitives>,
    }

    impl NodePrimitivesProvider for StaticOnlyProvider {
        type Primitives = TempoPrimitives;
    }

    impl StaticFileProviderFactory for StaticOnlyProvider {
        fn static_file_provider(&self) -> StaticFileProvider<Self::Primitives> {
            self.provider.clone()
        }

        fn get_static_file_writer(
            &self,
            block: u64,
            segment: StaticFileSegment,
        ) -> ProviderResult<StaticFileProviderRWRefMut<'_, Self::Primitives>> {
            self.provider.get_writer(block, segment)
        }
    }

    #[test]
    fn sync_accounts_deduplicates_validator_config() {
        assert_eq!(
            sync_accounts(
                true,
                &[VALIDATOR_CONFIG_V2_ADDRESS, Address::repeat_byte(0x42)]
            ),
            vec![VALIDATOR_CONFIG_V2_ADDRESS, Address::repeat_byte(0x42)]
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn genesis_account_replacement_hashes_slots_and_skips_zeroes() {
        let raw_slot = B256::repeat_byte(0x11);
        let zero_slot = B256::repeat_byte(0x22);
        let value = B256::repeat_byte(0x33);
        let account = GenesisAccount {
            storage: Some(BTreeMap::from([(raw_slot, value), (zero_slot, B256::ZERO)])),
            ..Default::default()
        };

        let replacement = genesis_account_replacement(Address::ZERO, &account).unwrap();

        assert_eq!(replacement.hashed_storage.len(), 1);
        assert_eq!(replacement.hashed_storage[0].key, keccak256(raw_slot));
        assert_eq!(
            replacement.hashed_storage[0].value,
            U256::from_be_slice(value.as_slice())
        );
    }

    #[test]
    fn replacement_changeset_entries_are_sorted_and_genesis_owned() {
        let high_address = Address::repeat_byte(0x22);
        let low_address = Address::repeat_byte(0x11);
        let high_slot = B256::repeat_byte(0x66);
        let low_slot = B256::repeat_byte(0x55);
        let value = B256::repeat_byte(0x77);

        let high_replacement = genesis_account_replacement(
            high_address,
            &GenesisAccount {
                storage: Some(BTreeMap::from([(high_slot, value)])),
                ..Default::default()
            },
        )
        .unwrap();
        let low_replacement = genesis_account_replacement(
            low_address,
            &GenesisAccount {
                storage: Some(BTreeMap::from([(low_slot, value)])),
                ..Default::default()
            },
        )
        .unwrap();

        let replacements = vec![high_replacement, low_replacement];

        assert_eq!(
            replacement_account_changeset_entries(&replacements),
            vec![
                AccountBeforeTx {
                    address: low_address,
                    info: None,
                },
                AccountBeforeTx {
                    address: high_address,
                    info: None,
                },
            ]
        );
        assert_eq!(
            replacement_storage_changeset_entries(&replacements),
            vec![
                StorageBeforeTx {
                    address: low_address,
                    key: low_slot,
                    value: U256::ZERO,
                },
                StorageBeforeTx {
                    address: high_address,
                    key: high_slot,
                    value: U256::ZERO,
                },
            ]
        );
    }

    /// Regression test for a probabilistic self-deadlock.
    ///
    /// `replace_block_zero_static_changesets` used to hold the AccountChangeSets jar provider —
    /// a dashmap shard read guard on the static-file jar cache — while acquiring the
    /// StorageChangeSets provider, whose first load inserts into the same dashmap via `entry()`
    /// (a shard write lock). When both cache keys hashed to the same shard the thread blocked
    /// on itself forever.
    ///
    /// The jar cache hasher is foldhash, whose seed mixes a thread-local chain that only
    /// advances on the constructing thread, so the fresh provider for each iteration must be
    /// built on the test thread for the shard assignment to re-roll (each regenesis process
    /// re-rolls it via ASLR). Only the call under test runs on a watchdogged worker thread.
    #[test]
    fn replace_block_zero_static_changesets_does_not_self_deadlock() {
        use std::{sync::mpsc, time::Duration};

        let iterations = 512;
        let (sender, receiver) = mpsc::channel();

        for iteration in 0..iterations {
            let synced_address = Address::repeat_byte(0x22);
            let static_dir = tempfile::tempdir().unwrap();
            {
                let provider: StaticFileProvider<TempoPrimitives> =
                    StaticFileProviderBuilder::read_write(static_dir.path())
                        .build()
                        .unwrap();
                {
                    let mut writer = provider
                        .get_writer(0, StaticFileSegment::AccountChangeSets)
                        .unwrap();
                    writer
                        .append_account_changeset(
                            vec![AccountBeforeTx {
                                address: synced_address,
                                info: None,
                            }],
                            0,
                        )
                        .unwrap();
                }
                {
                    let mut writer = provider
                        .get_writer(0, StaticFileSegment::StorageChangeSets)
                        .unwrap();
                    writer
                        .append_storage_changeset(
                            vec![StorageBeforeTx {
                                address: synced_address,
                                key: B256::repeat_byte(0x33),
                                value: U256::ZERO,
                            }],
                            0,
                        )
                        .unwrap();
                }
                provider.commit().unwrap();
            }

            // A fresh provider has an empty jar cache with a fresh hasher seed, matching a
            // regenesis process opening a cached snapshot.
            let provider: StaticFileProvider<TempoPrimitives> =
                StaticFileProviderBuilder::read_write(static_dir.path())
                    .build()
                    .unwrap();
            let replacement = genesis_account_replacement(
                synced_address,
                &GenesisAccount {
                    storage: Some(BTreeMap::from([(
                        B256::repeat_byte(0x55),
                        B256::repeat_byte(0x77),
                    )])),
                    ..Default::default()
                },
            )
            .unwrap();

            let sender = sender.clone();
            let handle = std::thread::spawn(move || {
                replace_block_zero_static_changesets(
                    &StaticOnlyProvider { provider },
                    &BTreeSet::from([synced_address]),
                    &[replacement],
                )
                .unwrap();
                drop(static_dir);
                sender.send(iteration).unwrap();
            });

            if receiver.recv_timeout(Duration::from_secs(30)).is_err() {
                panic!("replace_block_zero_static_changesets deadlocked on iteration {iteration}");
            }
            handle.join().unwrap();
        }
    }

    #[test]
    fn replace_block_zero_static_changesets_streams_existing_entries() {
        let synced_address = Address::repeat_byte(0x22);
        let before_address = Address::repeat_byte(0x11);
        let after_address = Address::repeat_byte(0x33);
        let old_synced_slot = B256::repeat_byte(0x33);
        let stale_synced_slot = B256::repeat_byte(0x44);
        let new_synced_slot = B256::repeat_byte(0x55);
        let before_slot = B256::repeat_byte(0x66);
        let after_slot = B256::repeat_byte(0x88);
        let value = B256::repeat_byte(0x77);

        let static_dir = tempfile::tempdir().unwrap();
        let provider: StaticFileProvider<TempoPrimitives> =
            StaticFileProviderBuilder::read_write(static_dir.path())
                .build()
                .unwrap();
        {
            let mut writer = provider
                .get_writer(0, StaticFileSegment::AccountChangeSets)
                .unwrap();
            writer
                .append_account_changeset(
                    vec![
                        AccountBeforeTx {
                            address: before_address,
                            info: None,
                        },
                        AccountBeforeTx {
                            address: synced_address,
                            info: Some(Account::default()),
                        },
                        AccountBeforeTx {
                            address: after_address,
                            info: Some(Account::default()),
                        },
                    ],
                    0,
                )
                .unwrap();
        }
        {
            let mut writer = provider
                .get_writer(0, StaticFileSegment::StorageChangeSets)
                .unwrap();
            writer
                .append_storage_changeset(
                    vec![
                        StorageBeforeTx {
                            address: before_address,
                            key: before_slot,
                            value: U256::ZERO,
                        },
                        StorageBeforeTx {
                            address: synced_address,
                            key: old_synced_slot,
                            value: U256::ZERO,
                        },
                        StorageBeforeTx {
                            address: synced_address,
                            key: stale_synced_slot,
                            value: U256::ZERO,
                        },
                        StorageBeforeTx {
                            address: after_address,
                            key: after_slot,
                            value: U256::ZERO,
                        },
                    ],
                    0,
                )
                .unwrap();
        }
        provider.commit().unwrap();

        let replacement = genesis_account_replacement(
            synced_address,
            &GenesisAccount {
                storage: Some(BTreeMap::from([(new_synced_slot, value)])),
                ..Default::default()
            },
        )
        .unwrap();
        let provider_wrapper = StaticOnlyProvider {
            provider: provider.clone(),
        };

        let mut old_storage_history_keys = replace_block_zero_static_changesets(
            &provider_wrapper,
            &BTreeSet::from([synced_address]),
            &[replacement],
        )
        .unwrap();
        provider.commit().unwrap();

        old_storage_history_keys.sort_unstable();
        assert_eq!(
            old_storage_history_keys,
            vec![
                StorageShardedKey::last(synced_address, old_synced_slot),
                StorageShardedKey::last(synced_address, stale_synced_slot),
            ]
        );
        assert_eq!(
            provider.account_block_changeset(0).unwrap(),
            vec![
                AccountBeforeTx {
                    address: before_address,
                    info: None,
                },
                AccountBeforeTx {
                    address: synced_address,
                    info: None,
                },
                AccountBeforeTx {
                    address: after_address,
                    info: Some(Account::default()),
                },
            ]
        );
        assert_eq!(
            provider.storage_block_changeset(0).unwrap(),
            vec![
                StorageBeforeTx {
                    address: before_address,
                    key: before_slot,
                    value: U256::ZERO,
                },
                StorageBeforeTx {
                    address: synced_address,
                    key: new_synced_slot,
                    value: U256::ZERO,
                },
                StorageBeforeTx {
                    address: after_address,
                    key: after_slot,
                    value: U256::ZERO,
                },
            ]
        );
    }
}
