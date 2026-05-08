//! Patch a virgin block-0 database to use a new genesis header.
//!
//! It replaces the header static file segment and rewrites the hash-to-number index
//! without touching state, hash, or trie tables.

use std::fs;

use clap::Parser;
use eyre::{ensure, eyre};
use reth_chainspec::EthChainSpec;
use reth_cli_commands::common::{CliNodeTypes, EnvironmentArgs};
use reth_db::{DatabaseEnv, open_db};
use reth_db_api::{
    cursor::DbCursorRO,
    tables,
    transaction::{DbTx, DbTxMut},
};
use reth_ethereum::tasks::Runtime;
use reth_node_builder::NodeTypesWithDBAdapter;
use reth_primitives_traits::{AlloyBlockHeader, NodePrimitives};
use reth_provider::{
    BlockNumReader, DatabaseProviderFactory, ProviderFactory, StaticFileProviderBuilder,
    StaticFileProviderFactory, StaticFileSegment, StaticFileWriter, providers::RocksDBProvider,
};
use reth_storage_api::DBProvider;
use tempo_chainspec::spec::TempoChainSpecParser;
use tracing::info;

/// Patch a block-0 database to use a new genesis header.
#[derive(Debug, Parser)]
pub(crate) struct Regenesis<C: reth_cli::chainspec::ChainSpecParser = TempoChainSpecParser> {
    #[command(flatten)]
    env: EnvironmentArgs<C>,
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
        let mut rocksdb_builder = RocksDBProvider::builder(data_dir.rocksdb())
            .with_default_tables()
            .with_database_log_level(self.env.db.log_level);
        if let Some(cache_size) = self.env.db.rocksdb_block_cache_size {
            rocksdb_builder = rocksdb_builder.with_block_cache_size(cache_size);
        }
        let rocksdb_provider = rocksdb_builder.build()?;

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

        {
            let static_file_provider = provider_rw.static_file_provider();
            static_file_provider.delete_segment(StaticFileSegment::Headers)?;
            let mut writer = static_file_provider
                .get_writer(genesis_block_number, StaticFileSegment::Headers)?;
            writer.append_header(genesis_header, &new_genesis_hash)?;
        }

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

        if stored_genesis_hash == new_genesis_hash {
            info!(
                target: "tempo::cli",
                old_genesis_hash = %stored_genesis_hash,
                %new_genesis_hash,
                "Genesis hash already matches, skipping patch"
            );
            return Ok(());
        }

        tx.delete::<tables::HeaderNumbers>(stored_genesis_hash, None)?;
        tx.put::<tables::HeaderNumbers>(new_genesis_hash, 0)?;
        tx.put::<tables::BlockBodyIndices>(0, Default::default())?;
        provider_rw.commit()?;

        info!(
            target: "tempo::cli",
            old_genesis_hash = %stored_genesis_hash,
            %new_genesis_hash,
            "Patched genesis header index"
        );

        Ok(())
    }
}
