//! Shared admin configuration loading and CLI/TOML merge rules.

use std::{
    collections::HashSet,
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use alloy::primitives::{Address, B256};
use eyre::{Context as _, ensure, eyre};
use serde::Deserialize;

use crate::zone_utils::MODERATO_ZONE_FACTORY;

/// Connection and identity inputs shared by every admin command.
#[derive(Debug, Clone, clap::Args)]
pub(crate) struct SharedAdminArgs {
    /// Optional TOML file containing public operational inputs.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Expected Zone ID. Overrides `zone.id` from --config.
    #[arg(long)]
    pub zone_id: Option<u32>,

    /// Optional expected deployed Zone manifest. Overrides `zone.manifest` from --config.
    #[arg(long)]
    pub zone_manifest: Option<PathBuf>,

    /// Tempo L1 HTTP RPC URL. Overrides `l1.rpc_url` from --config.
    #[arg(long)]
    pub l1_rpc_url: Option<String>,

    /// ZoneFactory address. Overrides `l1.zone_factory` from --config.
    #[arg(long)]
    pub zone_factory: Option<Address>,

    /// Expected ZonePortal address. It must match ZoneFactory when supplied.
    #[arg(long)]
    pub portal: Option<Address>,

    /// Operator RPC endpoint, optionally labeled NAME=URL. Repeat to replace config nodes.
    #[arg(long = "operator-rpc", value_name = "[NAME=]URL")]
    pub operator_rpcs: Vec<OperatorEndpoint>,

    /// Timeout applied to each operator snapshot and Portal snapshot.
    #[arg(long, default_value = "10s", value_parser = parse_nonzero_duration)]
    pub rpc_timeout: Duration,

    /// Emit a stable machine-readable report.
    #[arg(long)]
    pub json: bool,
}

impl SharedAdminArgs {
    pub(crate) fn load(&self) -> eyre::Result<EffectiveConfig> {
        load_effective_config(self)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct EffectiveConfig {
    pub zone_id: u32,
    pub manifest: Option<PathBuf>,
    pub l1_rpc_url: String,
    pub zone_factory: Address,
    pub portal: Option<Address>,
    pub nodes: Vec<OperatorEndpoint>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileConfig {
    #[serde(default)]
    pub zone: FileZone,
    #[serde(default)]
    pub l1: FileL1,
    #[serde(default)]
    pub nodes: Vec<FileNode>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileZone {
    pub id: Option<u32>,
    pub manifest: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileL1 {
    pub rpc_url: Option<String>,
    pub zone_factory: Option<Address>,
    pub portal: Option<Address>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileNode {
    pub name: Option<String>,
    pub operator_rpc_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OperatorEndpoint {
    pub name: Option<String>,
    pub url: String,
}

impl OperatorEndpoint {
    pub(crate) fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.url)
    }
}

impl FromStr for OperatorEndpoint {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (name, url) = match value.split_once('=') {
            Some((name, url)) if url.starts_with("http://") || url.starts_with("https://") => {
                if name.trim().is_empty() {
                    return Err("operator RPC label cannot be empty".to_owned());
                }
                (Some(name.to_owned()), url)
            }
            _ => (None, value),
        };
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err("operator RPC must be an http:// or https:// URL".to_owned());
        }
        Ok(Self {
            name,
            url: url.to_owned(),
        })
    }
}

impl fmt::Display for OperatorEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.name {
            Some(name) => write!(formatter, "{name}={}", self.url),
            None => formatter.write_str(&self.url),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExpectedEncryptionKey {
    pub x: B256,
    pub y_parity: u8,
}

pub(crate) fn load_file_config(path: &Path) -> eyre::Result<(FileConfig, PathBuf)> {
    let input = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("failed reading config {}", path.display()))?;
    let file = toml::from_str::<FileConfig>(&input)
        .wrap_err_with(|| format!("failed parsing config {}", path.display()))?;
    let config_dir = path.parent().unwrap_or_else(|| Path::new(".")).to_owned();
    Ok((file, config_dir))
}

fn load_effective_config(args: &SharedAdminArgs) -> eyre::Result<EffectiveConfig> {
    let (file, config_dir) = match &args.config {
        Some(path) => load_file_config(path)?,
        None => (FileConfig::default(), PathBuf::from(".")),
    };
    merge_effective_config(
        &config_dir,
        file,
        args.zone_id,
        args.zone_manifest.clone(),
        args.l1_rpc_url.clone(),
        args.zone_factory,
        args.portal,
        &args.operator_rpcs,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn merge_effective_config(
    config_dir: &Path,
    file: FileConfig,
    zone_id: Option<u32>,
    zone_manifest: Option<PathBuf>,
    l1_rpc_url: Option<String>,
    zone_factory: Option<Address>,
    portal: Option<Address>,
    operator_rpcs: &[OperatorEndpoint],
) -> eyre::Result<EffectiveConfig> {
    let zone_id = zone_id
        .or(file.zone.id)
        .ok_or_else(|| eyre!("missing Zone ID; pass --zone-id or set zone.id in --config"))?;
    let l1_rpc_url = l1_rpc_url.or(file.l1.rpc_url).ok_or_else(|| {
        eyre!("missing Tempo L1 RPC URL; pass --l1-rpc-url or set l1.rpc_url in --config")
    })?;
    let manifest = zone_manifest.or_else(|| {
        file.zone.manifest.map(|path| {
            if path.is_relative() {
                config_dir.join(path)
            } else {
                path
            }
        })
    });
    let nodes = if operator_rpcs.is_empty() {
        file.nodes
            .into_iter()
            .map(|node| OperatorEndpoint {
                name: node.name,
                url: node.operator_rpc_url,
            })
            .collect()
    } else {
        operator_rpcs.to_vec()
    };
    validate_endpoints(&nodes)?;
    ensure!(
        !nodes.is_empty(),
        "missing operator RPCs; repeat --operator-rpc or configure [[nodes]]"
    );

    Ok(EffectiveConfig {
        zone_id,
        manifest,
        l1_rpc_url,
        zone_factory: zone_factory
            .or(file.l1.zone_factory)
            .unwrap_or(MODERATO_ZONE_FACTORY),
        portal: portal.or(file.l1.portal),
        nodes,
    })
}

pub(crate) fn validate_endpoints(nodes: &[OperatorEndpoint]) -> eyre::Result<()> {
    let mut urls = HashSet::new();
    let mut names = HashSet::new();
    for node in nodes {
        ensure!(
            node.url.starts_with("http://") || node.url.starts_with("https://"),
            "operator RPC must be an http:// or https:// URL: {}",
            node.url
        );
        ensure!(
            urls.insert(&node.url),
            "duplicate operator RPC URL: {}",
            node.url
        );
        if let Some(name) = &node.name {
            ensure!(
                !name.trim().is_empty(),
                "operator RPC label cannot be empty"
            );
            ensure!(names.insert(name), "duplicate operator RPC label: {name}");
        }
    }
    Ok(())
}

pub(crate) fn parse_duration(value: &str) -> Result<Duration, String> {
    let value = value.trim();
    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, 1_u64)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1_000)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, 60_000)
    } else if let Some(number) = value.strip_suffix('h') {
        (number, 3_600_000)
    } else {
        return Err("duration must end in ms, s, m, or h".to_owned());
    };
    let number = number
        .parse::<u64>()
        .map_err(|_| format!("invalid duration: {value}"))?;
    number
        .checked_mul(multiplier)
        .map(Duration::from_millis)
        .ok_or_else(|| format!("duration is too large: {value}"))
}

pub(crate) fn parse_nonzero_duration(value: &str) -> Result<Duration, String> {
    let duration = parse_duration(value)?;
    if duration.is_zero() {
        return Err("duration must be greater than zero".to_owned());
    }
    Ok(duration)
}

pub(crate) fn parse_encryption_key(value: &str) -> Result<ExpectedEncryptionKey, String> {
    let (x, parity) = value
        .rsplit_once(':')
        .ok_or_else(|| "expected X:PARITY".to_owned())?;
    let x = x.parse::<B256>().map_err(|error| error.to_string())?;
    let y_parity = if let Some(hex) = parity.strip_prefix("0x") {
        u8::from_str_radix(hex, 16).map_err(|_| "invalid parity".to_owned())?
    } else {
        parity
            .parse::<u8>()
            .map_err(|_| "invalid parity".to_owned())?
    };
    let y_parity = normalize_y_parity(y_parity).map_err(|err| err.to_string())?;
    Ok(ExpectedEncryptionKey { x, y_parity })
}

fn normalize_y_parity(y_parity: u8) -> eyre::Result<u8> {
    match y_parity {
        0x02 | 0x03 => Ok(y_parity),
        0 | 1 => Ok(0x02 + y_parity),
        _ => Err(eyre!(
            "invalid yParity {y_parity:#x}; expected 0/1 or 0x02/0x03"
        )),
    }
}

pub(crate) fn format_duration(duration: Duration) -> String {
    if duration.as_millis().is_multiple_of(1_000) {
        format!("{}s", duration.as_secs())
    } else {
        format!("{}ms", duration.as_millis())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use clap::Parser as _;

    use super::*;

    static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug, clap::Parser)]
    struct SharedParser {
        #[command(flatten)]
        shared: SharedAdminArgs,
    }

    fn shared() -> SharedAdminArgs {
        SharedAdminArgs {
            config: None,
            zone_id: Some(7),
            zone_manifest: None,
            l1_rpc_url: Some("https://l1.example".to_owned()),
            zone_factory: None,
            portal: None,
            operator_rpcs: vec!["node-a=https://node-a.example".parse().unwrap()],
            rpc_timeout: Duration::from_secs(10),
            json: false,
        }
    }

    #[test]
    fn cli_only_configuration_is_valid() {
        let config = shared().load().unwrap();
        assert_eq!(config.zone_id, 7);
        assert_eq!(config.nodes[0].name.as_deref(), Some("node-a"));
        assert_eq!(config.zone_factory, MODERATO_ZONE_FACTORY);
    }

    #[test]
    fn cli_values_override_file_and_cli_nodes_replace_file_nodes() {
        let sequence = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "tempo-xtask-admin-config-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let config_path = directory.join("admin.toml");
        std::fs::write(
            &config_path,
            r#"
[zone]
id = 6
manifest = "expected.toml"

[l1]
rpc_url = "https://file-l1.example"

[[nodes]]
name = "old"
operator_rpc_url = "https://old.example"
"#,
        )
        .unwrap();

        let mut args = shared();
        args.config = Some(config_path);
        let config = args.load().unwrap();
        assert_eq!(config.zone_id, 7);
        assert_eq!(config.l1_rpc_url, "https://l1.example");
        assert_eq!(
            config.nodes,
            vec!["node-a=https://node-a.example".parse().unwrap()]
        );
        assert_eq!(config.manifest, Some(directory.join("expected.toml")));

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn file_nodes_are_used_when_cli_omits_operator_rpcs() {
        let sequence = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "tempo-xtask-admin-config-nodes-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let config_path = directory.join("admin.toml");
        std::fs::write(
            &config_path,
            r#"
[zone]
id = 6

[l1]
rpc_url = "https://file-l1.example"

[[nodes]]
name = "file-a"
operator_rpc_url = "https://file-a.example"
"#,
        )
        .unwrap();

        let args = SharedAdminArgs {
            config: Some(config_path),
            zone_id: None,
            zone_manifest: None,
            l1_rpc_url: None,
            zone_factory: None,
            portal: None,
            operator_rpcs: Vec::new(),
            rpc_timeout: Duration::from_secs(10),
            json: false,
        };
        let config = args.load().unwrap();
        assert_eq!(config.nodes[0].name.as_deref(), Some("file-a"));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn parses_supported_durations() {
        assert_eq!(parse_duration("0s").unwrap(), Duration::ZERO);
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert!(parse_nonzero_duration("0s").is_err());
    }

    #[test]
    fn parses_labeled_and_unlabeled_operator_endpoints() {
        let labeled: OperatorEndpoint = "node-a=https://node-a.example".parse().unwrap();
        assert_eq!(labeled.name.as_deref(), Some("node-a"));
        let unlabeled: OperatorEndpoint = "http://127.0.0.1:9000".parse().unwrap();
        assert_eq!(unlabeled.name, None);
    }

    #[test]
    fn clap_accepts_emergency_cli_without_config_or_manifest() {
        let command = SharedParser::try_parse_from([
            "check",
            "--zone-id",
            "7",
            "--l1-rpc-url",
            "https://l1.example",
            "--operator-rpc",
            "node-a=https://node-a.example",
            "--operator-rpc",
            "https://node-b.example",
            "--json",
        ])
        .unwrap();
        assert_eq!(command.shared.zone_id, Some(7));
        assert_eq!(command.shared.operator_rpcs.len(), 2);
        assert!(command.shared.zone_manifest.is_none());
        assert!(command.shared.json);
    }
}
