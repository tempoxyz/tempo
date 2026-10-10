//! Release metadata. Runtime node options remain owned by Tempo's ordinary CLI.

use crate::manifest::{resolve_path, validate_schedule};
use alloy_eips::BlockNumHash;
use alloy_primitives::{B256, U64};
use eyre::{Context, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

/// Release era schedules and frozen executables indexed by chain identity.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub chains: Vec<ChainEras>,
}

impl Catalog {
    pub fn load(path: &Path) -> eyre::Result<Self> {
        let mut catalog: Self = serde_json::from_slice(&std::fs::read(path)?)
            .wrap_err_with(|| format!("invalid era catalog {}", path.display()))?;
        catalog.validate()?;
        let parent = path.canonicalize()?.with_file_name("");
        catalog.resolve_binaries(&parent);
        Ok(catalog)
    }

    pub fn resolve_binaries(&mut self, parent: &Path) {
        for binary in self
            .chains
            .iter_mut()
            .flat_map(|chain| &mut chain.eras)
            .filter_map(|era| era.binary.as_mut())
        {
            resolve_path(parent, binary);
        }
    }

    pub fn validate(&self) -> eyre::Result<()> {
        let mut identities = HashSet::new();
        for chain in &self.chains {
            chain.validate()?;
            ensure!(
                identities.insert((chain.chain_id, chain.genesis_hash)),
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

/// Ordered release eras for a chain identified by its chain ID and genesis hash.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChainEras {
    pub chain_id: U64,
    pub genesis_hash: B256,
    /// Includes the active era as the last entry, with no executable path.
    pub eras: Vec<ReleaseEra>,
}

impl ChainEras {
    pub fn validate(&self) -> eyre::Result<()> {
        validate_schedule(
            self.eras
                .iter()
                .map(|era| (era.name.as_str(), era.start_timestamp)),
        )?;
        let (active, frozen) = self.eras.split_last().expect("validated schedule");
        for era in frozen {
            ensure!(
                era.binary
                    .as_ref()
                    .is_some_and(|path| !path.as_os_str().is_empty()),
                "frozen era requires an executable"
            );
        }
        ensure!(
            active.binary.is_none(),
            "active era uses the running Tempo binary"
        );
        Ok(())
    }

    pub fn era_for_timestamp(&self, timestamp: u64) -> usize {
        self.eras
            .partition_point(|era| era.start_timestamp <= timestamp)
            .saturating_sub(1)
    }
}

/// An era's activation timestamp and optional frozen executable.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseEra {
    pub name: String,
    pub start_timestamp: u64,
    /// Frozen executable, resolved relative to the release catalog.
    #[serde(default)]
    pub binary: Option<PathBuf>,
    /// Last canonical block to execute before handing storage to the next era.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<BlockNumHash>,
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
