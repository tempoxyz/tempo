//! Safe, disposable Zone genesis initialization from Tempo's TIP20 dump format.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use alloy_consensus::BlockHeader;
use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256};
use eyre::{Context as _, ensure};
use reth_chainspec::EthChainSpec;
use reth_cli_commands::common::{AccessRights, EnvironmentArgs};
use reth_db_api::{cursor::DbCursorRO, tables, transaction::DbTx};
use reth_provider::{BlockHashReader, DatabaseProviderFactory, HeaderProvider};
use reth_tasks::Runtime;
use reth_trie::{
    StateRoot,
    prefix_set::{PrefixSet, TriePrefixSets},
};
use reth_trie_db::{
    DatabaseHashedCursorFactory, DatabaseStateRoot, DatabaseTrieCursorFactory, PackedKeyAdapter,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tempo_precompiles::{NONCE_PRECOMPILE_ADDRESS, PATH_USD_ADDRESS, tip20::is_tip20_prefix};
use tempo_state_bloat::read_dump;
use zone_chainspec::{ZoneChainSpec, ZoneChainSpecParser};

use crate::ZoneNode;

/// Initialize a fresh Zone database with TIP20 bloat committed in block zero.
#[derive(Debug, clap::Parser)]
pub struct InitZoneFromBinaryDump {
    #[command(flatten)]
    env: EnvironmentArgs<ZoneChainSpecParser>,
    /// A Tempo generate-state-bloat dump for one or more tokens.
    state: PathBuf,
    /// Write the resulting chain specification here; use it for every node restart.
    #[arg(long)]
    output_genesis: PathBuf,
    /// Write verified initialization evidence here. Existing files are never replaced.
    #[arg(long)]
    manifest: PathBuf,
}

impl InitZoneFromBinaryDump {
    /// Merge allocations before Reth writes any header, history, or trie state.
    pub async fn execute(self, runtime: Runtime) -> eyre::Result<()> {
        let started = Instant::now();
        ensure!(self.env.storage.v2, "Zone state bloat requires storage v2");
        // Freshness checks, cleanup, and size evidence cover only the datadir.
        ensure!(
            self.env.datadir.static_files_path.is_none() && self.env.datadir.rocksdb_path.is_none(),
            "state bloat requires static files and RocksDB inside the datadir"
        );
        let datadir = self
            .env
            .datadir
            .clone()
            .resolve_datadir(self.env.chain.chain())
            .data_dir()
            .to_path_buf();
        ensure!(
            self.env.chain.genesis_header().number() == 0,
            "state bloat requires block-zero genesis"
        );
        let mut created = Vec::new();
        let result = async {
            // Reserve every output atomically and only clean up paths we own.
            // A concurrent initializer must never remove another process's outputs.
            // Files go first so an existing output fails before any directory is created.
            let genesis_file =
                File::create_new(&self.output_genesis).wrap_err("creating output genesis")?;
            created.push(self.output_genesis.clone());
            let manifest_file =
                File::create_new(&self.manifest).wrap_err("creating initialization manifest")?;
            created.push(self.manifest.clone());
            if let Some(parent) = datadir.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::create_dir(&datadir).wrap_err_with(|| {
                format!(
                    "state bloat requires a nonexistent datadir: {}",
                    datadir.display()
                )
            })?;
            created.push(datadir.clone());
            self.initialize(started, &datadir, runtime, genesis_file, manifest_file)
                .await
        }
        .await;
        if result.is_err() {
            // Everything below was created by this command; leave no partial state behind.
            for path in created {
                let removed = if path.is_dir() {
                    fs::remove_dir_all(&path)
                } else {
                    fs::remove_file(&path)
                };
                if let Err(error) = removed
                    && error.kind() != std::io::ErrorKind::NotFound
                {
                    tracing::warn!(path = %path.display(), %error, "failed to remove partial state bloat output");
                }
            }
        }
        result
    }

    async fn initialize(
        mut self,
        started: Instant,
        datadir: &Path,
        runtime: Runtime,
        genesis_file: File,
        manifest_file: File,
    ) -> eyre::Result<()> {
        let mut genesis = self.env.chain.genesis().clone();
        // Hash exactly the bytes we import; benchmark sizing is a caller policy.
        let dump = fs::read(&self.state)?;
        let dump_bytes = dump.len() as u64;
        let dump_sha256 = format!("{:x}", Sha256::digest(&dump));
        let tokens = apply_dump(&mut genesis, dump.as_slice())?;
        drop(dump);
        let entries = tokens.values().sum::<u64>();
        self.env.chain = Arc::new(ZoneChainSpec::from_genesis(genesis)?);
        let expected = self.env.chain.genesis_header().state_root();
        // Persist the exact specification that normal node startup must reopen.
        let mut output = BufWriter::new(genesis_file);
        serde_json::to_writer(&mut output, self.env.chain.genesis())?;
        output.flush()?;
        output.get_ref().sync_all()?;
        let environment = self
            .env
            .init::<ZoneNode>(AccessRights::RW, runtime.clone())?;
        let provider = environment.provider_factory.database_provider_ro()?;
        // Force a full traversal of hashed state rather than trusting cached trie nodes.
        let mut prefixes = TriePrefixSets {
            account_prefix_set: PrefixSet::all_paths(),
            ..Default::default()
        };
        for row in provider
            .tx_ref()
            .cursor_read::<tables::HashedAccounts>()?
            .walk(None)?
        {
            prefixes
                .storage_prefix_sets
                .insert(row?.0, PrefixSet::all_paths());
        }
        let root = StateRoot::<
            DatabaseTrieCursorFactory<_, PackedKeyAdapter>,
            DatabaseHashedCursorFactory<_>,
        >::from_tx(provider.tx_ref())
        .with_prefix_sets(prefixes)
        .root()?;
        let header = environment
            .provider_factory
            .header_by_number(0)?
            .ok_or_else(|| eyre::eyre!("missing genesis header"))?;
        let hash = environment
            .provider_factory
            .block_hash(0)?
            .ok_or_else(|| eyre::eyre!("missing genesis hash"))?;
        ensure!(
            root == expected
                && header.state_root() == root
                && hash == self.env.chain.genesis_hash(),
            "genesis header/database/chain-spec mismatch"
        );
        drop(provider);
        drop(environment);
        // Reopen all stores through the normal genesis-validation path.
        let reopened = self.env.init::<ZoneNode>(AccessRights::RW, runtime)?;
        ensure!(
            reopened.provider_factory.block_hash(0)? == Some(hash),
            "genesis hash changed on reopen"
        );
        drop(reopened);
        let manifest = json!({
            "schema": 1, "dump_sha256": dump_sha256, "dump_bytes": dump_bytes,
            "tokens": tokens, "entry_count": entries, "database_bytes": directory_bytes(datadir)?,
            "genesis_hash": hash, "committed_state_root": expected, "database_state_root": root,
            "reopened": true, "import_seconds": started.elapsed().as_secs_f64(),
            "genesis_config_sha256": format!("{:x}", Sha256::digest(serde_json::to_vec(&self.env.chain.genesis().config)?)),
        });
        serde_json::to_writer_pretty(manifest_file, &manifest)?;
        Ok(())
    }
}

/// Add isolated TIP20 working sets before constructing the Zone chain spec.
///
/// PathUSD must already be deployed in genesis. Other TIP20 tokens are seeded as storage-only
/// accounts with nonce 1: they stay uninitialized until the portal enables them, and the Zone inbox's
/// initialization writes metadata and roles without touching the seeded supply or balances.
///
/// Existing nonzero state and duplicate entries are rejected, not overwritten.
/// On error the caller must discard the modified in-memory genesis.
/// Returns the number of imported entries per token.
pub fn apply_dump(
    genesis: &mut Genesis,
    reader: impl Read,
) -> eyre::Result<BTreeMap<Address, u64>> {
    ensure!(
        genesis
            .alloc
            .get(&PATH_USD_ADDRESS)
            .and_then(|token| token.code.as_ref())
            .is_some_and(|code| !code.is_empty()),
        "PathUSD has no genesis code"
    );
    let mut seen = BTreeSet::new();
    let mut tokens = BTreeMap::new();
    read_dump(reader, |address, slot, value| {
        ensure!(
            address != NONCE_PRECOMPILE_ADDRESS,
            "Zone genesis cannot hold the expiring nonce ring; generate the dump with --no-nonce-ring"
        );
        ensure!(is_tip20_prefix(address), "{address} is not a TIP20 address");
        let account = genesis.alloc.entry(address).or_default();
        // Genesis code would make the token usable before the portal enables it.
        ensure!(
            address == PATH_USD_ADDRESS || account.code.as_ref().is_none_or(|code| code.is_empty()),
            "token {address} must be enabled through the portal, not deployed in genesis"
        );
        // revm treats a nonce-0, code-less account as empty and, once enablement installs code,
        // serves its unloaded storage from cache as zero; a nonzero nonce keeps the seeded slots.
        if address != PATH_USD_ADDRESS && account.nonce.unwrap_or_default() == 0 {
            account.nonce = Some(1);
        }
        ensure!(
            seen.insert((address, slot)),
            "duplicate dump slot {slot} for token {address}"
        );
        ensure!(!value.is_zero(), "zero dump values are not supported");
        let storage = account.storage.get_or_insert_default();
        ensure!(
            storage.get(&slot).is_none_or(|value| value.is_zero()),
            "dump conflicts with genesis slot {slot} for token {address}"
        );
        storage.insert(slot, B256::from(value.to_be_bytes::<32>()));
        *tokens.entry(address).or_default() += 1;
        Ok(())
    })?;
    Ok(tokens)
}

fn directory_bytes(path: &Path) -> eyre::Result<u64> {
    let mut bytes = 0;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        bytes += if metadata.is_dir() {
            directory_bytes(&entry.path())?
        } else {
            metadata.len()
        };
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_genesis::GenesisAccount;
    use alloy_primitives::{Bytes, U256, address};
    use clap::Parser;
    use tempo_state_bloat::GenerateStateBloat;

    const TOKEN: Address = address!("20c0000000000000000000000000000000000009");

    fn genesis() -> Genesis {
        let mut genesis = Genesis::default();
        genesis.alloc.insert(
            PATH_USD_ADDRESS,
            GenesisAccount::default().with_code(Some(Bytes::from_static(&[0xef]))),
        );
        genesis
    }

    fn dump(blocks: &[(Address, &[(u8, u8)])]) -> Vec<u8> {
        let mut dump = Vec::new();
        for (address, entries) in blocks {
            dump.extend_from_slice(b"TEMPOSB\0\0\x01\0\0");
            dump.extend_from_slice(address.as_slice());
            dump.extend_from_slice(&(entries.len() as u64).to_be_bytes());
            for (slot, value) in *entries {
                dump.extend_from_slice(B256::with_last_byte(*slot).as_slice());
                dump.extend_from_slice(&U256::from(*value).to_be_bytes::<32>());
            }
        }
        dump
    }

    #[test]
    fn apply_dump_seeds_tip20_storage() {
        let mut genesis = genesis();
        let tokens = apply_dump(
            &mut genesis,
            dump(&[(PATH_USD_ADDRESS, &[(1, 7)]), (TOKEN, &[(1, 8), (2, 9)])]).as_slice(),
        )
        .unwrap();
        assert_eq!(tokens, BTreeMap::from([(PATH_USD_ADDRESS, 1), (TOKEN, 2)]));
        let storage = genesis.alloc[&TOKEN].storage.as_ref().unwrap();
        assert_eq!(storage[&B256::with_last_byte(2)], B256::with_last_byte(9));
        assert!(genesis.alloc[&TOKEN].code.is_none());
        assert_eq!(genesis.alloc[&TOKEN].nonce, Some(1));
    }

    #[test]
    fn apply_dump_rejects_unsafe_entries() {
        let mut deployed = genesis();
        deployed.alloc.insert(
            TOKEN,
            GenesisAccount::default().with_code(Some(Bytes::from_static(&[0xef]))),
        );
        let mut seeded = genesis();
        seeded.alloc.get_mut(&PATH_USD_ADDRESS).unwrap().storage = Some(BTreeMap::from([(
            B256::with_last_byte(1),
            B256::with_last_byte(1),
        )]));
        let cases = [
            (Genesis::default(), dump(&[(TOKEN, &[(1, 1)])]), "PathUSD has no genesis code".to_owned()),
            (
                genesis(),
                dump(&[(NONCE_PRECOMPILE_ADDRESS, &[(1, 1)])]),
                "Zone genesis cannot hold the expiring nonce ring; generate the dump with --no-nonce-ring".to_owned(),
            ),
            (genesis(), dump(&[(Address::ZERO, &[(1, 1)])]), format!("{} is not a TIP20 address", Address::ZERO)),
            (
                deployed,
                dump(&[(TOKEN, &[(1, 1)])]),
                format!("token {TOKEN} must be enabled through the portal, not deployed in genesis"),
            ),
            (
                genesis(),
                dump(&[(TOKEN, &[(1, 1), (1, 2)])]),
                format!("duplicate dump slot {} for token {TOKEN}", B256::with_last_byte(1)),
            ),
            (genesis(), dump(&[(TOKEN, &[(1, 0)])]), "zero dump values are not supported".to_owned()),
            (
                seeded,
                dump(&[(PATH_USD_ADDRESS, &[(1, 2)])]),
                format!("dump conflicts with genesis slot {} for token {PATH_USD_ADDRESS}", B256::with_last_byte(1)),
            ),
        ];
        for (mut genesis, dump, expected) in cases {
            let error = apply_dump(&mut genesis, dump.as_slice()).unwrap_err();
            assert_eq!(error.to_string(), expected);
        }
    }

    #[derive(Parser)]
    struct GeneratorCli {
        #[command(flatten)]
        args: GenerateStateBloat,
    }

    /// Initialize a fresh Zone in `directory` from its `dump.bin`.
    async fn init(directory: &Path, extra: &[String]) -> eyre::Result<()> {
        let mut genesis: serde_json::Value =
            serde_json::from_str(include_str!("../assets/zone-dev-genesis.json"))?;
        genesis["config"]["chainId"] = json!(zone_primitives::constants::zone_chain_id(1337, 11)?);
        fs::write(directory.join("genesis.json"), genesis.to_string())?;
        let path = |name: &str| directory.join(name).to_str().unwrap().to_owned();
        let args = [
            "init-from-binary-dump".to_owned(),
            "--chain".to_owned(),
            path("genesis.json"),
            "--datadir".to_owned(),
            path("parent/db"),
            "--output-genesis".to_owned(),
            path("bloated.json"),
            "--manifest".to_owned(),
            path("manifest.json"),
            path("dump.bin"),
        ];
        InitZoneFromBinaryDump::try_parse_from(args.into_iter().chain(extra.iter().cloned()))?
            .execute(Runtime::test())
            .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn imports_a_generated_dump_end_to_end() {
        let directory = tempfile::tempdir().unwrap();
        let dump = directory.path().join("dump.bin");
        let generator = [
            "generate",
            "--size",
            "1",
            "--signable-count",
            "1",
            "--no-nonce-ring",
            "--out",
        ];
        GeneratorCli::parse_from(generator.into_iter().chain([dump.to_str().unwrap()]))
            .args
            .run()
            .await
            .unwrap();
        init(directory.path(), &[]).await.unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.path().join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["entry_count"], 16_383);
        let bloated: Genesis =
            serde_json::from_slice(&fs::read(directory.path().join("bloated.json")).unwrap())
                .unwrap();
        assert_eq!(
            manifest["genesis_hash"],
            json!(ZoneChainSpec::from_genesis(bloated).unwrap().genesis_hash())
        );
    }

    /// Extra CLI args, pathUSD dump entries, expected error, and paths left in the directory.
    type Case<'a> = (&'a [&'a str], &'a [(u8, u8)], &'a str, &'a [&'a str]);

    #[tokio::test(flavor = "multi_thread")]
    async fn failed_import_leaves_only_preexisting_paths() {
        let entries = |dir: &Path| {
            let mut names: Vec<_> = fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        };
        let cases: [Case<'_>; 2] = [
            // `create_dir_all` leaves the datadir's parent; every reserved output is removed.
            (
                &[],
                &[(1, 0)],
                "zero dump values are not supported",
                &["dump.bin", "genesis.json", "parent"],
            ),
            (
                &["--datadir.static-files", "{dir}/static"],
                &[(1, 1)],
                "state bloat requires static files and RocksDB inside the datadir",
                &["dump.bin", "genesis.json"],
            ),
        ];
        for (extra, entries_in_dump, expected, remaining) in cases {
            let directory = tempfile::tempdir().unwrap();
            fs::write(
                directory.path().join("dump.bin"),
                dump(&[(PATH_USD_ADDRESS, entries_in_dump)]),
            )
            .unwrap();
            let dir = directory.path().to_str().unwrap();
            let extra: Vec<_> = extra.iter().map(|arg| arg.replace("{dir}", dir)).collect();
            let error = init(directory.path(), &extra).await.unwrap_err();
            assert_eq!(error.to_string(), expected);
            assert_eq!(entries(directory.path()), remaining);
            if remaining.contains(&"parent") {
                assert!(entries(&directory.path().join("parent")).is_empty());
            }
        }
    }
}
