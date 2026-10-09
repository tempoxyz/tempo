//! Ordered binaries and bounded imports for bootstrapping shared execution storage.

use alloy_primitives::{B256, U64};
use eyre::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

/// Ordered era executables and bounded imports for a chain's shared storage.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Built-in chain name or chain specification path.
    pub chain: String,
    /// Shared data directory. Binary and datadir paths are manifest-relative.
    pub datadir: PathBuf,
    /// Expected identity, checked against each era's storage before advancing.
    pub chain_id: U64,
    pub genesis_hash: B256,
    pub eras: Vec<Era>,
}

/// An era's executable, activation timestamp, and optional bootstrap plan.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Era {
    pub name: String,
    /// Inclusive activation timestamp; the next era's activation is the exclusive end.
    pub start_timestamp: u64,
    pub binary: PathBuf,
    /// Optional sequential genesis bootstrap from canonical block files.
    #[serde(default)]
    pub bootstrap: Option<Bootstrap>,
}

/// A finite import command and the canonical checkpoint it must reach.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    /// Starts with `import`. The wrapper adds shared storage and validation flags.
    pub args: Vec<String>,
    /// Operator-pinned last canonical block owned by this era.
    pub terminal_block_number: u64,
    pub terminal_block_hash: B256,
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
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(!self.chain.is_empty(), "chain must not be empty");
        ensure!(
            !self.datadir.as_os_str().is_empty(),
            "datadir must not be empty"
        );
        validate_schedule(
            self.eras
                .iter()
                .map(|era| (era.name.as_str(), era.start_timestamp)),
        )?;
        for (index, era) in self.eras.iter().enumerate() {
            ensure!(
                !era.binary.as_os_str().is_empty(),
                "era {} has no binary",
                era.name
            );
            if index + 1 == self.eras.len() {
                ensure!(
                    era.bootstrap.is_none(),
                    "active era must be started with tempo node, not bootstrap"
                );
            } else {
                ensure!(
                    era.bootstrap.is_some(),
                    "era {} needs a bootstrap command/checkpoint",
                    era.name
                );
            }
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
}

impl Bootstrap {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.args.first().map(String::as_str) == Some("import"),
            "bootstrap args must start with import"
        );
        // Import must execute state, validate blocks, and stop at the pinned file boundary.
        for arg in &self.args[1..] {
            let key = arg.split('=').next().unwrap_or(arg);
            ensure!(
                !matches!(key, "--" | "--chain" | "--datadir") && !key.starts_with("--datadir."),
                "bootstrap owns flag {key}"
            );
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

pub(crate) fn validate_schedule<'a>(eras: impl IntoIterator<Item = (&'a str, u64)>) -> Result<()> {
    let mut names = HashSet::new();
    let mut previous = None;
    for (name, timestamp) in eras {
        ensure!(
            !name.trim().is_empty() && names.insert(name),
            "era names must be unique and nonempty"
        );
        ensure!(
            previous.map_or(timestamp == 0, |start| start < timestamp),
            "era activations must start at zero and strictly increase"
        );
        previous = Some(timestamp);
    }
    ensure!(previous.is_some(), "schedule needs at least one era");
    Ok(())
}

pub(crate) fn resolve_path(parent: &Path, path: &mut PathBuf) {
    if path.is_relative() {
        *path = parent.join(&*path);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn manifest() -> Manifest {
        let mut manifest: Manifest =
            serde_json::from_str(include_str!("../examples/eras.json")).unwrap();
        manifest.eras[1].start_timestamp = 100;
        manifest
    }

    #[test]
    fn rejects_invalid_eras_and_bootstrap_options() {
        let mut manifest = manifest();
        manifest.eras[0].start_timestamp = 1;
        assert!(manifest.validate().is_err());
        manifest.eras[0].start_timestamp = 0;
        manifest.eras[1].start_timestamp = 0;
        assert!(manifest.validate().is_err());
        manifest.eras[1].start_timestamp = 100;
        manifest.eras[0].bootstrap.as_mut().unwrap().args = vec!["node".into()];
        assert!(manifest.validate().is_err());
        for flag in [
            "--chain=other",
            "--datadir",
            "--datadir.static-files=other",
            "--",
            "--no-state",
            "--no-state=true",
            "--no-state=false",
            "--debug.max-block=42",
            "--fail-on-invalid-block=false",
        ] {
            manifest.eras[0].bootstrap.as_mut().unwrap().args =
                vec!["import".into(), flag.into(), "blocks.rlp".into()];
            assert!(manifest.validate().is_err(), "accepted {flag}");
        }
        manifest.eras[0].bootstrap = None;
        assert!(manifest.validate().is_err());
        let value = serde_json::to_value(&manifest).unwrap();
        for (field, malformed) in [
            ("chain_id", "0x10000000000000000"),
            ("genesis_hash", "0x01"),
        ] {
            let mut invalid = value.clone();
            invalid[field] = serde_json::json!(malformed);
            assert!(serde_json::from_value::<Manifest>(invalid).is_err());
        }
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
