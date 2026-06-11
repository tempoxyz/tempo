use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};

use eyre::{OptionExt as _, WrapErr as _, eyre};

pub(crate) const SHADOWFORK_SIGNING_KEY_SECRET: &str = "tempo-shadowfork-signing-key-secret";
pub(crate) const SHADOW_CHAINSPEC_FILE: &str = "shadowfork-chain.json";
pub(crate) const SHADOW_EPOCH: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SourceExecutionDataDir {
    pub(crate) db_path: PathBuf,
    pub(crate) static_files_path: PathBuf,
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

pub(crate) fn source_chain_id(source_chain: &str) -> Option<u64> {
    match source_chain.to_ascii_lowercase().as_str() {
        "mainnet" | "presto" => Some(4217),
        "moderato" | "testnet" => Some(42431),
        "dev" => Some(1337),
        _ => None,
    }
}

pub(crate) fn resolve_source_execution_data_dir(
    path: &Path,
    source_chain: &str,
    source_chain_id: u64,
) -> eyre::Result<SourceExecutionDataDir> {
    let mut candidates = Vec::new();
    if path.file_name() == Some(OsStr::new("db")) {
        candidates.push(path.to_path_buf());
    }
    candidates.push(path.join("db"));
    if let Some(chain_dir) = source_chain_cli_arg(source_chain, source_chain_id) {
        candidates.push(path.join(chain_dir).join("db"));
    }
    candidates.push(path.join(source_chain_id.to_string()).join("db"));

    for db_path in &candidates {
        if db_path.exists() {
            let static_files_path = db_path
                .parent()
                .ok_or_else(|| {
                    eyre!(
                        "execution database path `{}` has no parent directory",
                        db_path.display(),
                    )
                })?
                .join("static_files");
            return Ok(SourceExecutionDataDir {
                db_path: db_path.clone(),
                static_files_path,
            });
        }
    }

    let candidates = candidates
        .iter()
        .map(|path| format!("`{}`", path.display()))
        .collect::<Vec<_>>()
        .join(", ");
    Err(eyre!(
        "could not find execution database under `{}`; looked for {candidates}",
        path.display(),
    ))
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
    fn maps_source_chain_to_chain_id() {
        assert_eq!(source_chain_id("mainnet"), Some(4217));
        assert_eq!(source_chain_id("presto"), Some(4217));
        assert_eq!(source_chain_id("moderato"), Some(42431));
        assert_eq!(source_chain_id("testnet"), Some(42431));
        assert_eq!(source_chain_id("dev"), Some(1337));
        assert_eq!(source_chain_id("custom"), None);
    }
}
