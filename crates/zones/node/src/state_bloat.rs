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
use tempo_precompiles::{PATH_USD_ADDRESS, tip20::is_tip20_prefix};
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
        let datadir = self
            .env
            .datadir
            .clone()
            .resolve_datadir(self.env.chain.chain())
            .data_dir()
            .to_path_buf();
        ensure!(
            !datadir.exists(),
            "state bloat requires a nonexistent datadir: {}",
            datadir.display()
        );
        ensure!(
            !self.output_genesis.exists() && !self.manifest.exists(),
            "output genesis and manifest must not exist"
        );
        ensure!(
            self.output_genesis != self.manifest,
            "genesis and manifest paths must differ"
        );
        ensure!(
            self.env.chain.genesis_header().number() == 0,
            "state bloat requires block-zero genesis"
        );
        let mut created = Vec::new();
        let result = async {
            // Reserve every output atomically and only clean up paths we own.
            // A concurrent initializer must never remove another process's outputs.
            if let Some(parent) = datadir.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::create_dir(&datadir)?;
            created.push(datadir.clone());
            let genesis_file =
                File::create_new(&self.output_genesis).wrap_err("creating output genesis")?;
            created.push(self.output_genesis.clone());
            let manifest_file =
                File::create_new(&self.manifest).wrap_err("creating initialization manifest")?;
            created.push(self.manifest.clone());
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
/// accounts: they stay uninitialized until the portal enables them, and the Zone inbox's
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
        ensure!(is_tip20_prefix(address), "{address} is not a TIP20 address");
        let account = genesis.alloc.entry(address).or_default();
        // Genesis code would make the token usable before the portal enables it.
        ensure!(
            address == PATH_USD_ADDRESS || account.code.as_ref().is_none_or(|code| code.is_empty()),
            "token {address} must be enabled through the portal, not deployed in genesis"
        );
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
