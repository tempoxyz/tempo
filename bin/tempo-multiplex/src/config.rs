use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};

/// Both children must use independent, consistently checkpointed data directories.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Backend {
    pub rpc: String,
    pub binary: PathBuf,
    pub args: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_shared_or_nested_data_directories() {
        let root = tempfile::tempdir().unwrap();
        let v1 = root.path().join("v1");
        let v2 = root.path().join("v2");
        std::fs::create_dir(&v1).unwrap();
        std::fs::create_dir(&v2).unwrap();
        let mut config = Config {
            listen: "127.0.0.1:8545".parse().unwrap(),
            cutover_block: 10,
            parent_hash: format!("0x{:064x}", 9),
            v1: Backend {
                rpc: "http://127.0.0.1:8546".into(),
                binary: "tempo-v1".into(),
                args: vec!["--datadir".into(), v1.display().to_string()],
            },
            v2: Backend {
                rpc: "http://127.0.0.1:8547".into(),
                binary: "tempo-v2".into(),
                args: vec!["--datadir".into(), v2.display().to_string()],
            },
        };
        config.validate().unwrap();
        config.v2.args[1] = v1.display().to_string();
        assert!(config.validate().is_err());
        config.v2.args[1] = root.path().display().to_string();
        assert!(config.validate().is_err());
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub listen: SocketAddr,
    /// First block executed by v2; equality belongs to v2.
    pub cutover_block: u64,
    /// Hash of cutover_block - 1, present in both databases.
    pub parent_hash: String,
    pub v1: Backend,
    pub v2: Backend,
}

impl Config {
    pub(crate) fn validate(&self) -> eyre::Result<()> {
        eyre::ensure!(self.cutover_block > 0, "cutover_block must be positive");
        eyre::ensure!(
            self.parent_hash.len() == 66
                && self.parent_hash.starts_with("0x")
                && self.parent_hash[2..].bytes().all(|b| b.is_ascii_hexdigit()),
            "parent_hash must be a full block hash"
        );
        eyre::ensure!(self.v1.rpc != self.v2.rpc, "backends must be distinct");
        let datadir = |backend: &Backend| -> eyre::Result<PathBuf> {
            let path = backend
                .args
                .iter()
                .enumerate()
                .find_map(|(i, arg)| {
                    arg.strip_prefix("--datadir=")
                        .map(str::to_owned)
                        .or_else(|| {
                            (arg == "--datadir")
                                .then(|| backend.args.get(i + 1).cloned())
                                .flatten()
                        })
                })
                .ok_or_else(|| eyre::eyre!("each child needs an explicit --datadir"))?;
            // Checkpoint directories must already exist; resolve symlinks before comparing.
            Ok(std::fs::canonicalize(path)?)
        };
        let v1_dir = datadir(&self.v1)?;
        let v2_dir = datadir(&self.v2)?;
        eyre::ensure!(
            !v1_dir.starts_with(&v2_dir) && !v2_dir.starts_with(&v1_dir),
            "child data directories must be separate and non-nested"
        );
        for backend in [&self.v1, &self.v2] {
            let url = reqwest::Url::parse(&backend.rpc)?;
            eyre::ensure!(url.scheme() == "http", "child RPC must use HTTP");
            eyre::ensure!(
                matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost")),
                "child RPC must bind to loopback"
            );
            eyre::ensure!(
                url.username().is_empty() && url.password().is_none(),
                "RPC credentials are not supported"
            );
        }
        Ok(())
    }
}
