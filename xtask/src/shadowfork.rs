use std::path::Path;

use eyre::{OptionExt as _, WrapErr as _, eyre};

pub(crate) const SHADOWFORK_SIGNING_KEY_SECRET: &str = "tempo-shadowfork-signing-key-secret";
pub(crate) const SHADOW_CHAINSPEC_FILE: &str = "shadowfork-chain.json";
pub(crate) const SHADOW_EPOCH: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SnapshotManifestInfo {
    pub(crate) chain_id: u64,
    pub(crate) block_number: u64,
}

pub(crate) fn parse_snapshot_manifest_url(url: &str) -> Option<SnapshotManifestInfo> {
    let path = url.split_once('?').map_or(url, |(path, _)| path);
    for segment in path
        .split('/')
        .filter(|segment| segment.starts_with("tempo-"))
    {
        let mut parts = segment.split('-');
        if parts.next()? != "tempo" {
            continue;
        }

        let (Some(chain_id), Some(block_number)) = (parts.next(), parts.next()) else {
            continue;
        };
        let (Ok(chain_id), Ok(block_number)) = (chain_id.parse(), block_number.parse()) else {
            continue;
        };

        return Some(SnapshotManifestInfo {
            chain_id,
            block_number,
        });
    }
    None
}

pub(crate) fn source_chain_cli_arg(
    source_chain: &str,
    source_chain_id: u64,
) -> Option<&'static str> {
    match source_chain.to_ascii_lowercase().as_str() {
        "mainnet" | "presto" => Some("mainnet"),
        "moderato" | "testnet" => Some("moderato"),
        "dev" => Some("dev"),
        _ if source_chain_id == 4217 => Some("mainnet"),
        _ if source_chain_id == 42431 => Some("moderato"),
        _ => None,
    }
}

pub(crate) fn write_shadow_chainspec(
    path: &Path,
    source_chain: &str,
    source_chain_id: u64,
    shadow_epoch_length: u64,
) -> eyre::Result<()> {
    let mut genesis = source_genesis_json(source_chain, source_chain_id)?;
    let config = genesis
        .get_mut("config")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_eyre("source genesis JSON does not contain an object at `config`")?;
    config.insert(
        "epochLength".to_string(),
        serde_json::Value::from(shadow_epoch_length),
    );

    let json = serde_json::to_string_pretty(&genesis)
        .wrap_err("failed serializing shadow chainspec JSON")?;
    std::fs::write(path, json)
        .wrap_err_with(|| format!("failed writing shadow chainspec to `{}`", path.display()))
}

fn source_genesis_json(
    source_chain: &str,
    source_chain_id: u64,
) -> eyre::Result<serde_json::Value> {
    let genesis = match source_chain.to_ascii_lowercase().as_str() {
        "mainnet" | "presto" => include_str!("../../crates/chainspec/src/genesis/presto.json"),
        "moderato" | "testnet" => include_str!("../../crates/chainspec/src/genesis/moderato.json"),
        "dev" => include_str!("../../crates/chainspec/src/genesis/dev.json"),
        _ if source_chain_id == 4217 => {
            include_str!("../../crates/chainspec/src/genesis/presto.json")
        }
        _ if source_chain_id == 42431 => {
            include_str!("../../crates/chainspec/src/genesis/moderato.json")
        }
        _ => {
            return Err(eyre!(
                "cannot infer source chainspec for source_chain `{source_chain}` and chain id `{source_chain_id}`"
            ));
        }
    };

    serde_json::from_str(genesis).wrap_err("failed parsing bundled source genesis JSON")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_source_chain_to_execution_chain() {
        assert_eq!(source_chain_cli_arg("mainnet", 0), Some("mainnet"));
        assert_eq!(source_chain_cli_arg("presto", 0), Some("mainnet"));
        assert_eq!(source_chain_cli_arg("moderato", 0), Some("moderato"));
        assert_eq!(source_chain_cli_arg("testnet", 0), Some("moderato"));
        assert_eq!(source_chain_cli_arg("dev", 0), Some("dev"));
        assert_eq!(source_chain_cli_arg("custom", 4217), Some("mainnet"));
        assert_eq!(source_chain_cli_arg("custom", 42431), Some("moderato"));
        assert_eq!(source_chain_cli_arg("custom", 1), None);
    }

    #[test]
    fn parses_snapshot_manifest_url() {
        assert_eq!(
            parse_snapshot_manifest_url(
                "https://tempo-node-snapshots.tempoxyz.dev/tempo-42431-20230873-1780289911/manifest.json"
            ),
            Some(SnapshotManifestInfo {
                chain_id: 42431,
                block_number: 20230873,
            })
        );
        assert_eq!(
            parse_snapshot_manifest_url("https://example.com/manifest.json"),
            None
        );
    }
}
