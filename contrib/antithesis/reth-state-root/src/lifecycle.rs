use crate::Config;
use eyre::{ensure, Result};
use reth_chainspec::ChainSpec;
use reth_db::DatabaseEnv;
use reth_db_api::{
    database::Database,
    tables::Tables,
    tables_to_generic,
    transaction::{DbTx, DbTxMut},
};
use reth_node_core::dirs::{ChainPath, DataDirPath};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
};

/// A round remains active across restarts until its verified final flush is retired.
pub(crate) struct Campaign {
    root: PathBuf,
    active: PathBuf,
    retired: PathBuf,
    initial_config: serde_json::Value,
}

impl Campaign {
    /// Capture the original configuration before per-round paths and input are changed.
    pub(crate) fn new(config: &Config) -> Result<Self> {
        let root = config.datadir.clone().unwrap_or_else(|| PathBuf::from("/data/reth-state-root"));
        fs::create_dir_all(&root)?;
        Ok(Self {
            active: root.join("active"),
            retired: root.join("retired"),
            root,
            initial_config: serde_json::to_value(config)?,
        })
    }

    /// The MDBX environment outlives round-local journals, static files and RocksDB.
    pub(crate) fn database_path(&self) -> Result<PathBuf> {
        let legacy = ChainPath::<DataDirPath>::new(
            self.active.to_string_lossy().parse()?,
            ChainSpec::<alloy_consensus::Header>::default().chain,
            Default::default(),
        );
        ensure!(
            !legacy.db().exists(),
            "legacy active-round database layout; resume with the old workload or use a fresh datadir"
        );
        let database = self.root.join("db");
        let ownership = self.root.join("database-owner.json");
        if ownership.exists() {
            let saved: String = serde_json::from_slice(&fs::read(&ownership)?)?;
            ensure!(saved == "reth-state-root-antithesis", "unrecognized campaign database owner");
        } else {
            ensure!(
                !database.exists(),
                "refusing to adopt an existing database without campaign ownership"
            );
            persist_json(&ownership, &"reth-state-root-antithesis")?;
        }
        Ok(database)
    }

    /// Resume the active round or durably create it, rejecting changed restart configuration.
    pub(crate) fn start(&self, db: &DatabaseEnv) -> Result<PathBuf> {
        // The durable retirement marker authorizes an idempotent reset, including after a crash.
        if self.retired.exists() {
            let tx = db.tx_mut()?;
            for table in Tables::ALL {
                tables_to_generic!(table, |T| tx.clear::<T>())?;
            }
            tx.commit()?;
            fs::remove_dir_all(&self.retired)?;
            fs::File::open(&self.root)?.sync_all()?;
        }
        fs::create_dir_all(&self.active)?;
        let config_path = self.active.join("config.json");
        if config_path.exists() {
            let saved: serde_json::Value = serde_json::from_slice(&fs::read(&config_path)?)?;
            ensure!(
                saved == self.initial_config,
                "restart must use the original workload configuration"
            );
        } else {
            persist_json(&config_path, &self.initial_config)?;
            fs::File::open(&self.root)?.sync_all()?;
        }
        Ok(self.active.clone())
    }

    /// Durably mark a completed round; the next start resets MDBX before deleting its files.
    pub(crate) fn retire(&self) -> Result<()> {
        fs::rename(&self.active, &self.retired)?;
        fs::File::open(&self.root)?.sync_all()?;
        Ok(())
    }
}

/// Atomically replace a campaign file, syncing its contents before its directory entry.
pub(crate) fn persist_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let temporary = path.with_extension("tmp");
    let mut file = fs::File::create(&temporary)?;
    serde_json::to_writer(&mut file, value)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    fs::File::open(path.parent().expect("campaign file has a parent"))?.sync_all()?;
    Ok(())
}
