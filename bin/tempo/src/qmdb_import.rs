//! Imports the node's persisted state into a fresh QMDB, so the node can run with
//! `--qmdb.state-backend` from its current tip.

use std::{
    num::NonZeroUsize,
    path::{Path, PathBuf},
    time::Instant,
};

use clap::Parser;
use eyre::{OptionExt as _, WrapErr as _, bail};
use reth_chainspec::EthChainSpec as _;
use reth_cli_commands::common::{AccessRights, EnvironmentArgs};
use reth_ethereum::tasks::Runtime;
use reth_provider::{
    BlockHashReader as _, BlockNumReader as _, DBProvider as _, DatabaseProviderFactory as _,
};
use reth_trie_db::DatabaseHashedCursorFactory;
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_node::node::TempoNode;
use tempo_qmdb_state::{Config, Store, import};
use tracing::info;

/// Import the hashed state at the database's persisted tip into `<datadir>/qmdb`.
#[derive(Debug, Parser)]
pub struct QmdbImport {
    /// Chain and database environment to import from.
    #[command(flatten)]
    env: EnvironmentArgs<TempoChainSpecParser>,
}

impl QmdbImport {
    pub(crate) async fn execute(self, runtime: Runtime) -> eyre::Result<()> {
        let qmdb_dir = self
            .env
            .datadir
            .clone()
            .resolve_datadir(self.env.chain.chain())
            .data_dir()
            .join("qmdb");
        let environment = self.env.init::<TempoNode>(AccessRights::RO, runtime)?;
        let provider = environment
            .provider_factory
            .database_provider_ro()
            .wrap_err("failed opening the database")?
            // The import streams the whole hashed state through one read transaction, which
            // outlives MDBX's long-read timeout on large states. The node is offline here.
            .disable_long_read_transaction_safety();
        let tip = provider
            .best_block_number()
            .wrap_err("failed reading the persisted tip")?;
        let tip_hash = provider
            .block_hash(tip)
            .wrap_err("failed reading the persisted tip's hash")?
            .ok_or_eyre("the persisted tip has no canonical hash")?;

        let store =
            Store::open(store_config(&qmdb_dir)).wrap_err("failed opening the QMDB state")?;
        if let Some(applied) = store.status()?.applied {
            bail!(
                "{} already holds state up to block {applied}; remove it to import again",
                qmdb_dir.display()
            );
        }

        info!(target: "tempo::cli", tip, %tip_hash, dir = %qmdb_dir.display(), "importing state into QMDB");
        let started = Instant::now();
        let keys = import::import(
            &DatabaseHashedCursorFactory::new(provider.tx_ref()),
            &store,
            tip,
            tip_hash,
            Some(import_sort_dir(&qmdb_dir)),
        )
        .wrap_err("failed importing the state")?;
        let root = store.status()?.root;
        info!(
            target: "tempo::cli",
            tip,
            %tip_hash,
            keys,
            %root,
            elapsed = ?started.elapsed(),
            "imported state into QMDB"
        );
        Ok(())
    }
}

/// Returns the configuration of the node's QMDB in `qmdb_dir` (`<datadir>/qmdb`).
pub(crate) fn store_config(qmdb_dir: &Path) -> Config {
    Config {
        directory: qmdb_dir.join("db"),
        threads: std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN),
        // 1 GiB of 4 KiB pages: merkleize reads predecessor and floor-raise ops by location,
        // and every miss is a blob read on the finish path.
        page_cache_pages: NonZeroUsize::new(1 << 18).expect("non-zero"),
        max_pending: NonZeroUsize::new(1024).expect("non-zero"),
    }
}

/// Returns the directory for the import's temporary sort files in `qmdb_dir`.
pub(crate) fn import_sort_dir(qmdb_dir: &Path) -> PathBuf {
    qmdb_dir.join("import")
}
