use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
};

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

pub(crate) fn consensus_listen_addr(advertised_addr: SocketAddr, listen_port: u16) -> SocketAddr {
    if advertised_addr.ip().is_loopback() {
        return SocketAddr::new(advertised_addr.ip(), listen_port);
    }

    match advertised_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), listen_port),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), listen_port),
    }
}

pub(crate) fn should_allow_private_ips(ips: impl IntoIterator<Item = IpAddr>) -> bool {
    ips.into_iter().any(is_private_or_loopback)
}

fn is_private_or_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

pub(crate) fn render_script_header() -> String {
    r#"#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -n "${TEMPO_BIN:-}" ]]; then
  TEMPO_CMD=("$TEMPO_BIN")
else
  TEMPO_CMD=(cargo run --bin tempo --)
fi

run_tempo() {
  "${TEMPO_CMD[@]}" "$@"
}

PIDS=()

shutdown_nodes() {
  local status="$1"
  trap - INT TERM
  if ((${#PIDS[@]})); then
    kill "${PIDS[@]}" 2>/dev/null || true
    wait "${PIDS[@]}" 2>/dev/null || true
  fi
  exit "$status"
}

trap 'shutdown_nodes 130' INT
trap 'shutdown_nodes 143' TERM

"#
    .to_string()
}

pub(crate) fn render_script_footer() -> String {
    r#"echo "started ${#PIDS[@]} nodes; press Ctrl-C to stop"
wait "${PIDS[@]}"
"#
    .to_string()
}

pub(crate) fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(unix)]
pub(crate) fn mark_executable(path: &Path) -> eyre::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = std::fs::metadata(path)
        .wrap_err_with(|| format!("failed reading metadata for `{}`", path.display()))?
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions)
        .wrap_err_with(|| format!("failed marking `{}` executable", path.display()))
}

#[cfg(not(unix))]
pub(crate) fn mark_executable(_path: &Path) -> eyre::Result<()> {
    Ok(())
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

    #[test]
    fn binds_non_loopback_consensus_on_unspecified_interface() {
        assert_eq!(
            consensus_listen_addr("10.0.1.10:7000".parse().unwrap(), 7000),
            "0.0.0.0:7000".parse().unwrap(),
        );
        assert_eq!(
            consensus_listen_addr("[fd00::1]:7000".parse().unwrap(), 7000),
            "[::]:7000".parse().unwrap(),
        );
    }
}
