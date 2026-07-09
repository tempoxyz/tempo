//! Patch a virgin block-0 database to use a new genesis header.
//!
//! It replaces the header static file segment and rewrites the hash-to-number index.
//! When requested, it can also replace selected genesis accounts from the new chain spec and
//! update hashed state, trie, and block-0 history without rebuilding unrelated bloat state.

use std::{collections::BTreeSet, fs, sync::Arc};

use alloy_genesis::{Genesis, GenesisAccount};
use alloy_primitives::{Address, B256, U256, keccak256};
use clap::Parser;
use eyre::{ensure, eyre};
use reth_chainspec::EthChainSpec;
use reth_cli_commands::common::{CliNodeTypes, EnvironmentArgs};
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
use reth_nippy_jar::NippyJar;
use reth_node_builder::NodeTypesWithDBAdapter;
use reth_primitives_traits::{Account, AlloyBlockHeader, Bytecode, NodePrimitives, StorageEntry};
use reth_provider::{
    BlockNumReader, DatabaseProviderFactory, LatestStateProviderRef, ProviderFactory,
    RocksDBProviderFactory, StaticFileProviderBuilder, StaticFileProviderFactory,
    StaticFileSegment, StaticFileWriter, StorageSettingsCache, TrieWriter,
    providers::RocksDBProvider,
};
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
    let old_account_static = static_file_provider
        .get_maybe_segment_provider(StaticFileSegment::AccountChangeSets, 0)?
        .map(|provider| -> eyre::Result<_> {
            Ok((
                provider.data_path().to_path_buf(),
                provider.read_changeset_offset(0)?,
            ))
        })
        .transpose()?;
    let old_storage_static = static_file_provider
        .get_maybe_segment_provider(StaticFileSegment::StorageChangeSets, 0)?
        .map(|provider| -> eyre::Result<_> {
            Ok((
                provider.data_path().to_path_buf(),
                provider.read_changeset_offset(0)?,
            ))
        })
        .transpose()?;

    let old_account_file = old_account_static
        .map(|(path, offset)| -> eyre::Result<_> {
            let jar = NippyJar::load(&path)?;
            let reader = Arc::new(jar.open_data_reader()?);
            Ok((jar, reader, offset))
        })
        .transpose()?;
    let old_storage_file = old_storage_static
        .map(|(path, offset)| -> eyre::Result<_> {
            let jar = NippyJar::load(&path)?;
            let reader = Arc::new(jar.open_data_reader()?);
            Ok((jar, reader, offset))
        })
        .transpose()?;

    static_file_provider.delete_segment(StaticFileSegment::AccountChangeSets)?;
    static_file_provider.delete_segment(StaticFileSegment::StorageChangeSets)?;

    {
        let mut writer =
            provider_rw.get_static_file_writer(0, StaticFileSegment::AccountChangeSets)?;
        writer.begin_account_changeset(0)?;

        let mut replacement_changes = replacement_account_changeset_entries(replacements)
            .into_iter()
            .peekable();

        if let Some((jar, reader, Some(offset))) = old_account_file.as_ref() {
            let mut cursor = StaticFileCursor::new(jar, Arc::clone(reader))?;
            for row in offset.changeset_range() {
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

        let mut replacement_changes = replacement_storage_changeset_entries(replacements)
            .into_iter()
            .peekable();

        if let Some((jar, reader, Some(offset))) = old_storage_file.as_ref() {
            let mut cursor = StaticFileCursor::new(jar, Arc::clone(reader))?;
            for row in offset.changeset_range() {
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

    #[test]
    fn replace_block_zero_static_changesets_streams_existing_entries() {
        let synced_address = Address::repeat_byte(0x22);
        let other_address = Address::repeat_byte(0x11);
        let old_synced_slot = B256::repeat_byte(0x33);
        let stale_synced_slot = B256::repeat_byte(0x44);
        let new_synced_slot = B256::repeat_byte(0x55);
        let other_slot = B256::repeat_byte(0x66);
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
                            address: other_address,
                            info: None,
                        },
                        AccountBeforeTx {
                            address: synced_address,
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
                            address: other_address,
                            key: other_slot,
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
                    address: other_address,
                    info: None,
                },
                AccountBeforeTx {
                    address: synced_address,
                    info: None,
                },
            ]
        );
        assert_eq!(
            provider.storage_block_changeset(0).unwrap(),
            vec![
                StorageBeforeTx {
                    address: other_address,
                    key: other_slot,
                    value: U256::ZERO,
                },
                StorageBeforeTx {
                    address: synced_address,
                    key: new_synced_slot,
                    value: U256::ZERO,
                },
            ]
        );
    }
}
