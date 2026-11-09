use crate::Config;
use eyre::{ensure, Result};
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
        let root = config.datadir.clone().unwrap_or_else(|| PathBuf::from("/data/reth-trie"));
        fs::create_dir_all(&root)?;
        Ok(Self {
            active: root.join("active"),
            retired: root.join("retired"),
            root,
            initial_config: serde_json::to_value(config)?,
        })
    }

    /// Resume the active round or durably create it, rejecting changed restart configuration.
    pub(crate) fn start(&self) -> Result<PathBuf> {
        // A retired directory can only belong to a fully verified round, so recovery may delete it.
        if self.retired.exists() {
            fs::remove_dir_all(&self.retired)?;
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

    /// Durably remove a completed round from the active name before deleting its files.
    pub(crate) fn retire(&self) -> Result<()> {
        fs::rename(&self.active, &self.retired)?;
        fs::File::open(&self.root)?.sync_all()?;
        fs::remove_dir_all(&self.retired)?;
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
