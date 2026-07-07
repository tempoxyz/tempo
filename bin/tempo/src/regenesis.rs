//! Patch a virgin block-0 database to use a new genesis header.
//!
//! It replaces the header static file segment and rewrites the hash-to-number index.
//! When requested, it can also replace selected genesis accounts from the new chain spec and
//! update hashed state, trie, and block-0 history without rebuilding unrelated bloat state.

use std::fs;

use alloy_genesis::{Genesis, GenesisAccount};
use alloy_primitives::{Address, B256, U256, keccak256};
use clap::Parser;
use eyre::{ensure, eyre};
use reth_chainspec::EthChainSpec;
use reth_cli_commands::common::{CliNodeTypes, EnvironmentArgs};
use reth_db::{DatabaseEnv, open_db};
use reth_db_api::{
    cursor::{DbCursorRO, DbCursorRW, DbDupCursorRW},
    models::{
        AccountBeforeTx, ShardedKey, StorageBeforeTx, storage_sharded_key::StorageShardedKey,
    },
    tables,
    transaction::{DbTx, DbTxMut},
};
use reth_ethereum::tasks::Runtime;
use reth_node_builder::NodeTypesWithDBAdapter;
use reth_primitives_traits::{Account, AlloyBlockHeader, Bytecode, NodePrimitives, StorageEntry};
use reth_provider::{
    BlockNumReader, DatabaseProviderFactory, LatestStateProviderRef, ProviderFactory,
    RocksDBProviderFactory, StaticFileProviderBuilder, StaticFileProviderFactory,
    StaticFileSegment, StaticFileWriter, StorageSettingsCache, TrieWriter,
    providers::RocksDBProvider,
};
use reth_storage_api::{ChangeSetReader, DBProvider, StateRootProvider, StorageChangeSetReader};
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
        + RocksDBProviderFactory
        + ChangeSetReader
        + StorageChangeSetReader,
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
        .collect();
    let old_account_changeset = provider_rw.account_block_changeset(0)?;
    let old_storage_changeset = provider_rw.storage_block_changeset(0)?;
    let (account_changeset, storage_changeset) = replacement_block_zero_changesets(
        &synced_addresses,
        &replacements,
        old_account_changeset,
        old_storage_changeset.clone(),
    );

    let hashed_state = replacement_hashed_post_state(&replacements);
    let (state_root, trie_updates) = {
        let latest = LatestStateProviderRef::new(provider_rw);
        latest.state_root_with_updates(hashed_state)?
    };

    replace_hashed_accounts(provider_rw, &replacements)?;
    replace_hashed_storage(provider_rw, &replacements)?;
    provider_rw.write_trie_updates(trie_updates)?;
    sync_genesis_account_history(
        provider_rw,
        &replacements,
        old_storage_changeset
            .iter()
            .filter(|change| synced_addresses.contains(&change.address)),
    )?;
    replace_block_zero_static_changesets(provider_rw, account_changeset, storage_changeset)?;

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
    let hashed_storage = hashed_genesis_storage_entries(genesis_account);

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

fn replacement_block_zero_changesets(
    synced_addresses: &std::collections::BTreeSet<Address>,
    replacements: &[GenesisAccountReplacement],
    old_account_changeset: Vec<AccountBeforeTx>,
    old_storage_changeset: Vec<StorageBeforeTx>,
) -> (Vec<AccountBeforeTx>, Vec<StorageBeforeTx>) {
    let mut account_changeset = old_account_changeset
        .into_iter()
        .filter(|change| !synced_addresses.contains(&change.address))
        .collect::<Vec<_>>();
    account_changeset.extend(replacements.iter().map(|replacement| AccountBeforeTx {
        address: replacement.address,
        info: None,
    }));
    account_changeset.sort_unstable_by_key(|change| change.address);

    let mut storage_changeset = old_storage_changeset
        .into_iter()
        .filter(|change| !synced_addresses.contains(&change.address))
        .collect::<Vec<_>>();
    storage_changeset.extend(replacements.iter().flat_map(|replacement| {
        replacement.storage.iter().map(|entry| StorageBeforeTx {
            address: replacement.address,
            key: entry.key,
            value: U256::ZERO,
        })
    }));
    storage_changeset.sort_unstable_by_key(|change| (change.address, change.key));

    (account_changeset, storage_changeset)
}

fn sync_genesis_account_history<'a, P>(
    provider_rw: &P,
    replacements: &[GenesisAccountReplacement],
    old_storage_changeset: impl IntoIterator<Item = &'a StorageBeforeTx>,
) -> eyre::Result<()>
where
    P: RocksDBProviderFactory,
{
    let mut old_storage_history_keys = old_storage_changeset
        .into_iter()
        .map(|change| StorageShardedKey::last(change.address, change.key))
        .collect::<Vec<_>>();
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
    account_changeset: Vec<AccountBeforeTx>,
    storage_changeset: Vec<StorageBeforeTx>,
) -> eyre::Result<()>
where
    P: StaticFileProviderFactory,
{
    let static_file_provider = provider_rw.static_file_provider();
    static_file_provider.delete_segment(StaticFileSegment::AccountChangeSets)?;
    static_file_provider.delete_segment(StaticFileSegment::StorageChangeSets)?;

    {
        let mut writer =
            provider_rw.get_static_file_writer(0, StaticFileSegment::AccountChangeSets)?;
        writer.append_account_changeset(account_changeset, 0)?;
    }
    {
        let mut writer =
            provider_rw.get_static_file_writer(0, StaticFileSegment::StorageChangeSets)?;
        writer.append_storage_changeset(storage_changeset, 0)?;
    }

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

fn hashed_genesis_storage_entries(account: &GenesisAccount) -> Vec<StorageEntry> {
    let mut entries = genesis_storage_entries(account)
        .into_iter()
        .map(|entry| StorageEntry {
            key: keccak256(entry.key),
            value: entry.value,
        })
        .collect::<Vec<_>>();

    entries.sort_unstable_by_key(|entry| entry.key);
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

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
    fn hashed_genesis_storage_entries_hashes_slots_and_skips_zeroes() {
        let raw_slot = B256::repeat_byte(0x11);
        let zero_slot = B256::repeat_byte(0x22);
        let value = B256::repeat_byte(0x33);
        let account = GenesisAccount {
            storage: Some(BTreeMap::from([(raw_slot, value), (zero_slot, B256::ZERO)])),
            ..Default::default()
        };

        let entries = hashed_genesis_storage_entries(&account);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, keccak256(raw_slot));
        assert_eq!(entries[0].value, U256::from_be_slice(value.as_slice()));
    }

    #[test]
    fn replacement_block_zero_changesets_replace_synced_account_only() {
        let synced_address = Address::repeat_byte(0x11);
        let other_address = Address::repeat_byte(0x22);
        let old_synced_slot = B256::repeat_byte(0x33);
        let stale_synced_slot = B256::repeat_byte(0x44);
        let new_synced_slot = B256::repeat_byte(0x55);
        let other_slot = B256::repeat_byte(0x66);
        let value = B256::repeat_byte(0x77);

        let replacement = genesis_account_replacement(
            synced_address,
            &GenesisAccount {
                storage: Some(BTreeMap::from([(new_synced_slot, value)])),
                ..Default::default()
            },
        )
        .unwrap();

        let (account_changeset, storage_changeset) = replacement_block_zero_changesets(
            &BTreeSet::from([synced_address]),
            &[replacement],
            vec![
                AccountBeforeTx {
                    address: synced_address,
                    info: Some(Account::default()),
                },
                AccountBeforeTx {
                    address: other_address,
                    info: None,
                },
            ],
            vec![
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
                    address: other_address,
                    key: other_slot,
                    value: U256::ZERO,
                },
            ],
        );

        assert_eq!(
            account_changeset,
            vec![
                AccountBeforeTx {
                    address: synced_address,
                    info: None,
                },
                AccountBeforeTx {
                    address: other_address,
                    info: None,
                },
            ]
        );
        assert_eq!(
            storage_changeset,
            vec![
                StorageBeforeTx {
                    address: synced_address,
                    key: new_synced_slot,
                    value: U256::ZERO,
                },
                StorageBeforeTx {
                    address: other_address,
                    key: other_slot,
                    value: U256::ZERO,
                },
            ]
        );
    }
}
