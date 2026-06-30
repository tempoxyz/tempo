//! Patch a virgin block-0 database to use a new genesis header.
//!
//! It replaces the header static file segment and rewrites the hash-to-number index.
//! When requested, it can also replace selected genesis storage accounts from the
//! new chain spec and update hashed state/trie tables without rebuilding bloat state.

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
    tables,
    transaction::{DbTx, DbTxMut},
};
use reth_ethereum::tasks::Runtime;
use reth_node_builder::NodeTypesWithDBAdapter;
use reth_primitives_traits::{AlloyBlockHeader, NodePrimitives};
use reth_provider::{
    BlockNumReader, DatabaseProviderFactory, LatestStateProviderRef, ProviderFactory,
    StaticFileProviderBuilder, StaticFileProviderFactory, StaticFileSegment, StaticFileWriter,
    StorageSettingsCache, TrieWriter, providers::RocksDBProvider,
};
use reth_storage_api::{DBProvider, StateRootProvider};
use reth_trie::{HashedPostState, HashedStorage};
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_contracts::precompiles::VALIDATOR_CONFIG_V2_ADDRESS;
use tracing::info;

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

    /// Replace all storage for a genesis account from the new --chain genesis.
    ///
    /// This is an escape hatch for other small genesis-owned accounts. The
    /// account's existing hashed storage is wiped and replaced with the nonzero
    /// storage entries from the provided genesis. This requires storage v2.
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
            synced_state_root = sync_genesis_account_storage(
                &provider_rw,
                self.env.chain.genesis(),
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

fn sync_genesis_account_storage<P>(
    provider_rw: &P,
    genesis: &Genesis,
    accounts: &[Address],
) -> eyre::Result<Option<B256>>
where
    P: DBProvider + StorageSettingsCache + TrieWriter,
    P::Tx: DbTxMut,
{
    if accounts.is_empty() {
        return Ok(None);
    }

    ensure!(
        provider_rw.cached_storage_settings().use_hashed_state(),
        "regenesis storage sync requires a storage v2 database with hashed state enabled"
    );

    let mut replacements = Vec::with_capacity(accounts.len());
    let mut overlay_storages = Vec::with_capacity(accounts.len());

    for &address in accounts {
        let genesis_account = genesis
            .alloc
            .get(&address)
            .ok_or_else(|| eyre!("genesis account {address} is missing from --chain alloc"))?;
        let entries = hashed_genesis_storage_entries(genesis_account);
        let hashed_address = keccak256(address);
        let overlay =
            HashedStorage::from_iter(true, entries.iter().map(|entry| (entry.key, entry.value)));

        replacements.push((hashed_address, entries));
        overlay_storages.push((hashed_address, overlay));
    }

    let hashed_state = HashedPostState::default().with_storages(overlay_storages);
    let (state_root, trie_updates) = {
        let latest = LatestStateProviderRef::new(provider_rw);
        latest.state_root_with_updates(hashed_state)?
    };

    replace_hashed_storage(provider_rw, replacements)?;
    provider_rw.write_trie_updates(trie_updates)?;

    info!(
        target: "tempo::cli",
        %state_root,
        accounts = accounts.len(),
        "Synced genesis account storage"
    );

    Ok(Some(state_root))
}

fn replace_hashed_storage<P>(
    provider_rw: &P,
    replacements: Vec<(B256, Vec<reth_primitives_traits::StorageEntry>)>,
) -> eyre::Result<()>
where
    P: DBProvider,
    P::Tx: DbTxMut,
{
    let tx = provider_rw.tx_ref();
    let mut cursor = tx.cursor_dup_write::<tables::HashedStorages>()?;

    for (hashed_address, entries) in replacements {
        if cursor.seek_exact(hashed_address)?.is_some() {
            cursor.delete_current_duplicates()?;
        }

        for entry in entries {
            cursor.upsert(hashed_address, &entry)?;
        }
    }

    Ok(())
}

fn hashed_genesis_storage_entries(
    account: &GenesisAccount,
) -> Vec<reth_primitives_traits::StorageEntry> {
    let mut entries = account
        .storage
        .as_ref()
        .into_iter()
        .flat_map(|storage| storage.iter())
        .filter_map(|(slot, value)| {
            let value = U256::from_be_slice(value.as_slice());
            (!value.is_zero()).then_some(reth_primitives_traits::StorageEntry {
                key: keccak256(slot),
                value,
            })
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
}
