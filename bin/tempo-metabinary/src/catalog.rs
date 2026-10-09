//! Release metadata. Runtime node options remain owned by Tempo's ordinary CLI.

use std::path::{Path, PathBuf};

use alloy_primitives::{B256, U64};
use eyre::{Context, ensure};
use serde::{Deserialize, Serialize};

use crate::manifest::{resolve_path, validate_schedule};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub chains: Vec<ChainEras>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChainEras {
    pub chain_id: U64,
    pub genesis_hash: B256,
    /// Includes the active era as the last entry, with no executable path.
    pub eras: Vec<ReleaseEra>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseEra {
    pub name: String,
    pub start_timestamp: u64,
    /// Frozen executable, resolved relative to the release catalog.
    #[serde(default)]
    pub binary: Option<PathBuf>,
}

impl Catalog {
    pub fn load(path: &Path) -> eyre::Result<Self> {
        let mut catalog: Self = serde_json::from_slice(&std::fs::read(path)?)
            .wrap_err_with(|| format!("invalid era catalog {}", path.display()))?;
        catalog.validate()?;
        let parent = path
            .canonicalize()?
            .parent()
            .expect("catalog has parent")
            .to_owned();
        for chain in &mut catalog.chains {
            for era in &mut chain.eras {
                if let Some(binary) = &mut era.binary {
                    resolve_path(&parent, binary);
                }
            }
        }
        Ok(catalog)
    }

    pub fn validate(&self) -> eyre::Result<()> {
        for (index, chain) in self.chains.iter().enumerate() {
            chain.validate()?;
            ensure!(
                !self.chains[..index]
                    .iter()
                    .any(|previous| previous.chain_id == chain.chain_id
                        && previous.genesis_hash == chain.genesis_hash),
                "duplicate chain identity in era catalog"
            );
        }
        Ok(())
    }

    pub fn for_chain(&self, chain_id: u64, genesis_hash: B256) -> Option<&ChainEras> {
        let chain_id = U64::from(chain_id);
        self.chains
            .iter()
            .find(|chain| chain.chain_id == chain_id && chain.genesis_hash == genesis_hash)
    }
}

impl ChainEras {
    pub fn validate(&self) -> eyre::Result<()> {
        validate_schedule(
            self.eras
                .iter()
                .map(|era| (era.name.as_str(), era.start_timestamp)),
        )?;
        for (index, era) in self.eras.iter().enumerate() {
            if index + 1 == self.eras.len() {
                ensure!(
                    era.binary.is_none(),
                    "active era uses the running Tempo binary"
                );
            } else {
                ensure!(
                    era.binary
                        .as_ref()
                        .is_some_and(|path| !path.as_os_str().is_empty()),
                    "frozen era requires an executable"
                );
            }
        }
        Ok(())
    }

    pub fn era_for_timestamp(&self, timestamp: u64) -> usize {
        self.eras
            .partition_point(|era| era.start_timestamp <= timestamp)
            .saturating_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_and_order_are_release_bound() {
        let mut catalog: Catalog = serde_json::from_value(serde_json::json!({
            "chains":[{"chain_id":"0x1", "genesis_hash":format!("0x{:064x}", 1), "eras":[
                {"name":"old", "start_timestamp":0, "binary":"old-tempo"},
                {"name":"live", "start_timestamp":100}
            ]}]
        }))
        .unwrap();
        catalog.validate().unwrap();
        assert!(catalog.for_chain(1, B256::ZERO).is_none());
        let chain = catalog
            .for_chain(1, catalog.chains[0].genesis_hash)
            .unwrap();
        for (timestamp, era) in [(0, 0), (99, 0), (100, 1), (u64::MAX, 1)] {
            assert_eq!(chain.era_for_timestamp(timestamp), era);
        }
        catalog.chains[0].eras[1].start_timestamp = 0;
        assert!(catalog.validate().is_err());
        catalog.chains[0].eras[1].start_timestamp = 100;
        let mut duplicate = serde_json::to_value(&catalog.chains[0]).unwrap();
        duplicate["chain_id"] = serde_json::json!("0x01");
        catalog
            .chains
            .push(serde_json::from_value(duplicate).unwrap());
        assert!(catalog.validate().is_err());
    }
}
