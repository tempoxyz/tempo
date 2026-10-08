//! The wrapper's only knowledge of execution history: ordered binaries and activation times.

use eyre::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Built-in chain name or chain specification path.
    pub chain: String,
    /// Shared data directory. Binary and datadir paths are manifest-relative.
    pub datadir: PathBuf,
    /// Expected Ethereum quantity, checked against every worker before serving.
    pub chain_id: String,
    pub genesis_hash: String,
    pub eras: Vec<Era>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Era {
    pub name: String,
    /// Inclusive activation timestamp; the next era's activation is the exclusive end.
    pub start_timestamp: u64,
    pub binary: PathBuf,
    /// Ordinary node arguments. Only the live era may have these.
    #[serde(default)]
    pub node_args: Vec<String>,
    /// Private HTTP endpoint used only by the wrapper.
    pub rpc_port: u16,
    /// Optional private WebSocket endpoint for live subscriptions.
    #[serde(default)]
    pub ws_port: Option<u16>,
    /// Optional sequential genesis bootstrap from canonical block files.
    #[serde(default)]
    pub bootstrap: Option<Bootstrap>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    /// Starts with `import`. The wrapper adds shared storage and validation flags.
    pub args: Vec<String>,
    /// Operator-pinned last canonical block owned by this era.
    pub terminal_block_number: u64,
    pub terminal_block_hash: String,
}

impl Manifest {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)
            .wrap_err_with(|| format!("cannot read manifest {}", path.display()))?;
        let mut manifest: Self = serde_json::from_slice(&bytes)
            .wrap_err_with(|| format!("invalid manifest {}", path.display()))?;
        manifest.validate()?;
        let parent = path
            .canonicalize()?
            .parent()
            .expect("manifest has parent")
            .to_owned();
        resolve_path(&parent, &mut manifest.datadir);
        for era in &mut manifest.eras {
            resolve_path(&parent, &mut era.binary);
        }
        // Built-in names have no path separator. Explicit spec paths are manifest-relative.
        if manifest.chain.contains(std::path::MAIN_SEPARATOR) || manifest.chain.ends_with(".json") {
            let mut chain_path = PathBuf::from(&manifest.chain);
            resolve_path(&parent, &mut chain_path);
            manifest.chain = chain_path.to_string_lossy().into_owned();
        }
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(!self.chain.is_empty(), "chain must not be empty");
        ensure!(
            !self.datadir.as_os_str().is_empty(),
            "datadir must not be empty"
        );
        parse_quantity(&self.chain_id).wrap_err("invalid chain_id")?;
        validate_hash(&self.genesis_hash).wrap_err("invalid genesis_hash")?;
        ensure!(!self.eras.is_empty(), "manifest needs at least one era");
        ensure!(
            self.eras[0].start_timestamp == 0,
            "first era must start at timestamp zero"
        );
        let mut names = HashSet::new();
        let mut ports = HashSet::new();
        for (index, era) in self.eras.iter().enumerate() {
            ensure!(!era.name.trim().is_empty(), "era name must not be empty");
            ensure!(names.insert(&era.name), "duplicate era name: {}", era.name);
            ensure!(
                !era.binary.as_os_str().is_empty(),
                "era {} has no binary",
                era.name
            );
            ensure!(
                era.rpc_port != 0,
                "era {} needs a nonzero private RPC port",
                era.name
            );
            ensure!(
                ports.insert(era.rpc_port),
                "duplicate private RPC port: {}",
                era.rpc_port
            );
            if let Some(port) = era.ws_port {
                ensure!(
                    port != 0 && ports.insert(port),
                    "invalid or duplicate private WebSocket port: {port}"
                );
            }
            if index > 0 {
                ensure!(
                    self.eras[index - 1].start_timestamp < era.start_timestamp,
                    "era activation timestamps must strictly increase"
                );
            }
            if index + 1 < self.eras.len() {
                ensure!(
                    era.node_args.is_empty(),
                    "historical era {} cannot have node_args",
                    era.name
                );
                ensure!(
                    era.ws_port.is_none(),
                    "historical era {} cannot have ws_port",
                    era.name
                );
            } else {
                ensure!(
                    era.bootstrap.is_none(),
                    "live era must be started with serve, not bootstrap"
                );
            }
            reject_reserved(&era.node_args)
                .wrap_err_with(|| format!("invalid node_args for {}", era.name))?;
            if let Some(bootstrap) = &era.bootstrap {
                bootstrap
                    .validate()
                    .wrap_err_with(|| format!("invalid bootstrap for {}", era.name))?;
            }
        }
        let mut previous_checkpoint = None;
        for bootstrap in self.eras.iter().filter_map(|era| era.bootstrap.as_ref()) {
            if let Some(previous) = previous_checkpoint {
                ensure!(
                    previous < bootstrap.terminal_block_number,
                    "bootstrap terminal block numbers must strictly increase"
                );
            }
            previous_checkpoint = Some(bootstrap.terminal_block_number);
        }
        Ok(())
    }

    pub fn validate_bootstrap(&self) -> Result<()> {
        self.validate()?;
        for era in &self.eras[..self.eras.len() - 1] {
            ensure!(
                era.bootstrap.is_some(),
                "era {} has no bootstrap command/checkpoint",
                era.name
            );
        }
        Ok(())
    }

    pub fn live(&self) -> &Era {
        self.eras
            .last()
            .expect("validated manifest contains an era")
    }

    pub fn era_for_timestamp(&self, timestamp: u64) -> usize {
        self.eras
            .partition_point(|era| era.start_timestamp <= timestamp)
            .saturating_sub(1)
    }
}

impl Era {
    pub fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.rpc_port)
    }
}

impl Bootstrap {
    fn validate(&self) -> Result<()> {
        validate_hash(&self.terminal_block_hash).wrap_err("invalid terminal_block_hash")?;
        ensure!(
            self.args.first().map(String::as_str) == Some("import"),
            "bootstrap args must start with import"
        );
        reject_reserved(&self.args[1..])?;
        // Import must execute state, validate blocks, and stop at the pinned file boundary.
        for arg in &self.args[1..] {
            let key = arg.split('=').next().unwrap_or(arg);
            ensure!(key != "--no-state", "bootstrap import must execute state");
            ensure!(
                !matches!(
                    key,
                    "--debug.max-block" | "--debug.terminate" | "--fail-on-invalid-block"
                ),
                "bootstrap owns flag {key}"
            );
        }
        Ok(())
    }
}

fn resolve_path(parent: &Path, path: &mut PathBuf) {
    if path.is_relative() {
        *path = parent.join(&*path);
    }
}

/// Reject flags that could bypass the wrapper's private transport or shared database.
fn reject_reserved(args: &[String]) -> Result<()> {
    for arg in args {
        let key = arg.split('=').next().unwrap_or(arg);
        if matches!(
            key,
            "--" | "--chain" | "--datadir" | "--http" | "--ws" | "--ipcdisable" | "--ipcpath"
        ) || key.starts_with("--datadir.")
            || key.starts_with("--http.")
            || key.starts_with("--ws.")
            || key == "--authrpc.addr"
        {
            bail!("wrapper owns flag {key}");
        }
    }
    Ok(())
}

pub fn parse_quantity(value: &str) -> Result<u64> {
    let digits = value
        .strip_prefix("0x")
        .ok_or_else(|| eyre::eyre!("expected 0x-prefixed quantity"))?;
    ensure!(!digits.is_empty(), "quantity must contain hex digits");
    ensure!(
        digits.len() == 1 || !digits.starts_with('0'),
        "quantity must not have leading zeros"
    );
    Ok(u64::from_str_radix(digits, 16)?)
}

fn validate_hash(value: &str) -> Result<()> {
    let digits = value
        .strip_prefix("0x")
        .ok_or_else(|| eyre::eyre!("expected 0x-prefixed hash"))?;
    ensure!(
        digits.len() == 64 && digits.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "expected a 32-byte hexadecimal hash"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn manifest() -> Manifest {
        Manifest {
            chain: "tempo".into(),
            datadir: "/tmp/tempo-test".into(),
            chain_id: "0xa5bd".into(),
            genesis_hash: format!("0x{}", "00".repeat(32)),
            eras: vec![
                Era {
                    name: "frozen".into(),
                    start_timestamp: 0,
                    binary: "/bin/false".into(),
                    node_args: vec![],
                    rpc_port: 18545,
                    ws_port: None,
                    bootstrap: Some(Bootstrap {
                        args: vec!["import".into(), "blocks.rlp".into()],
                        terminal_block_number: 10,
                        terminal_block_hash: format!("0x{}", "11".repeat(32)),
                    }),
                },
                Era {
                    name: "live".into(),
                    start_timestamp: 100,
                    binary: "/bin/false".into(),
                    node_args: vec![],
                    rpc_port: 18546,
                    ws_port: None,
                    bootstrap: None,
                },
            ],
        }
    }

    #[test]
    fn routes_exact_activation_to_successor() {
        let manifest = manifest();
        manifest.validate_bootstrap().unwrap();
        assert_eq!(manifest.era_for_timestamp(0), 0);
        assert_eq!(manifest.era_for_timestamp(99), 0);
        assert_eq!(manifest.era_for_timestamp(100), 1);
        assert_eq!(manifest.era_for_timestamp(u64::MAX), 1);
    }

    #[test]
    fn rejects_ambiguous_or_uncovered_eras() {
        let mut manifest = manifest();
        manifest.eras[0].start_timestamp = 1;
        assert!(manifest.validate().is_err());
        manifest.eras[0].start_timestamp = 0;
        manifest.eras[1].start_timestamp = 0;
        assert!(manifest.validate().is_err());
        manifest.eras[1].start_timestamp = 100;
        manifest.eras[1].rpc_port = manifest.eras[0].rpc_port;
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn rejects_private_rpc_and_storage_overrides() {
        for flag in [
            "--http.addr=0.0.0.0",
            "--http.port",
            "--ws",
            "--chain=other",
            "--datadir",
            "--ipcpath",
        ] {
            let mut manifest = manifest();
            manifest.eras[1].node_args = vec![flag.into()];
            assert!(manifest.validate().is_err(), "accepted {flag}");
        }
    }

    #[test]
    fn bootstrap_requires_execution_and_operator_checkpoint() {
        let mut manifest = manifest();
        manifest.eras[0].bootstrap.as_mut().unwrap().args = vec!["node".into()];
        assert!(manifest.validate_bootstrap().is_err());
        for flag in [
            "--no-state",
            "--no-state=true",
            "--no-state=false",
            "--debug.max-block=42",
            "--fail-on-invalid-block=false",
        ] {
            manifest.eras[0].bootstrap.as_mut().unwrap().args =
                vec!["import".into(), flag.into(), "blocks.rlp".into()];
            assert!(manifest.validate_bootstrap().is_err(), "accepted {flag}");
        }
        manifest.eras[0].bootstrap = None;
        manifest.validate().unwrap();
        assert!(manifest.validate_bootstrap().is_err());
    }

    #[test]
    fn paths_are_relative_to_manifest_not_working_directory() {
        let temp = tempfile::tempdir().unwrap();
        let mut manifest = manifest();
        manifest.datadir = "data".into();
        manifest.chain = "./chain.json".into();
        manifest.eras[0].binary = "frozen".into();
        let path = temp.path().join("eras.json");
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let loaded = Manifest::load(path).unwrap();
        let directory = temp.path().canonicalize().unwrap();
        assert_eq!(loaded.datadir, directory.join("data"));
        assert_eq!(loaded.eras[0].binary, directory.join("frozen"));
        assert_eq!(PathBuf::from(loaded.chain), directory.join("./chain.json"));
    }
}
