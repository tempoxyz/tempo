use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    path::{Path, PathBuf},
};

use alloy_consensus::Sealable as _;
use alloy_primitives::{Address, B256, Bytes, LogData, U256, keccak256};
use commonware_codec::{Encode as _, EncodeSize, RangeCfg, Read, ReadExt, Write};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::{
        dkg::Output,
        primitives::{group::Share, sharing::ModeVersion, variant::MinSig},
    },
    ed25519::PublicKey,
    transcript::Summary,
};
use commonware_math::algebra::Random as _;
use commonware_runtime::{Metrics as _, Runner as _};
use commonware_storage::metadata::{Config as MetadataConfig, Metadata};
use commonware_utils::{NZU32, ordered};
use eyre::{Context as _, OptionExt as _, ensure, eyre};
use rand_08::SeedableRng as _;
use reth_db::{mdbx::DatabaseArguments, open_db};
use reth_db_api::{
    cursor::{DbCursorRO as _, DbCursorRW as _, DbDupCursorRO as _, DbDupCursorRW as _},
    database::Database as _,
    models::StorageSettings,
    tables,
    transaction::{DbTx, DbTxMut},
};
use reth_primitives_traits::StorageEntry;
use reth_provider::{
    BlockHashReader as _, HeaderProvider as _, StaticFileProviderBuilder, StaticFileSegment,
    StaticFileWriter as _,
};
use revm::{
    context::{BlockEnv, journaled_state::JournalCheckpoint},
    state::{AccountInfo, Bytecode},
};
use serde::Deserialize;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_consensus_config::{SigningKey, SigningKeyPassphrase, SigningShare};
use tempo_contracts::precompiles::VALIDATOR_CONFIG_V2_ADDRESS;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_precompiles::{
    error::TempoPrecompileError,
    storage::{PrecompileStorageProvider, StorageCtx},
    validator_config_v2::ValidatorConfigV2,
};
use tempo_primitives::{TempoBlockEnv, TempoPrimitives};

use crate::shadowfork::{
    SHADOW_CHAINSPEC_FILE, SHADOW_EPOCH, SHADOWFORK_SIGNING_KEY_SECRET,
    resolve_source_execution_data_dir, write_shadow_chainspec as write_shadow_chainspec_file,
};

const DKG_STATES_METADATA_PARTITION: &str = "engine_dkg_manager_states_metadata";
const MAXIMUM_VALIDATORS: NonZeroU32 = NZU32!(u16::MAX as u32);

/// Reanchors generated shadow-fork artifacts onto a local source execution datadir.
#[derive(Debug, clap::Parser)]
pub(crate) struct BootstrapShadowfork {
    /// Path to the manifest written by `generate-shadowfork`.
    #[arg(long, value_name = "FILE")]
    manifest: PathBuf,

    /// Bootstrap only this validator index.
    #[arg(long, value_name = "INDEX")]
    node_index: Option<usize>,

    /// Source execution datadir, chain datadir, or db directory to patch.
    ///
    /// If omitted, uses the source execution datadir recorded by `generate-shadowfork`.
    #[arg(long, value_name = "DIR")]
    execution_datadir: Option<PathBuf>,

    /// Override the generated node artifact directory for --node-index.
    #[arg(long, value_name = "DIR", requires = "node_index")]
    node_artifact_dir: Option<PathBuf>,

    /// Overwrite an existing shadow chainspec or DKG state metadata.
    #[arg(long)]
    force: bool,

    /// Deterministic seed for per-node DKG state randomness.
    #[arg(long, default_value_t = 0)]
    seed: u64,
}

impl BootstrapShadowfork {
    pub(crate) fn run(self) -> eyre::Result<()> {
        let Self {
            manifest,
            node_index,
            execution_datadir,
            node_artifact_dir: node_artifact_dir_override,
            force,
            seed,
        } = self;

        let manifest_path = manifest;
        let manifest_dir = manifest_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let manifest = read_manifest(&manifest_path)?;
        let target_nodes = target_nodes(&manifest, node_index)?;
        ensure!(
            target_nodes.len() == 1,
            "bootstrap-shadowfork patches one local execution datadir at a time; pass --node-index when the manifest contains multiple validators",
        );
        let shadow_epoch = manifest.shadow_epoch.unwrap_or(SHADOW_EPOCH);
        ensure!(
            shadow_epoch == SHADOW_EPOCH,
            "unsupported shadow epoch `{}`; expected `{SHADOW_EPOCH}`",
            shadow_epoch
        );

        let execution_datadir = execution_datadir
            .or_else(|| manifest.source_execution_datadir.clone())
            .ok_or_eyre(
                "missing source execution datadir; pass --execution-datadir or regenerate the manifest",
            )?;
        let execution_datadir = resolve_source_execution_data_dir(
            &execution_datadir,
            &manifest.source_chain,
            manifest.source_chain_id,
        )?;

        let reanchor_block_number = manifest.fork_block_number;
        let fallback_shadow_epoch_length = reanchor_block_number
            .checked_add(1)
            .ok_or_eyre("fork block number overflowed shadow epoch length")?;
        let shadow_epoch_length = fallback_shadow_epoch_length;
        if let Some(manifest_shadow_epoch_length) = manifest.shadow_epoch_length
            && manifest_shadow_epoch_length != shadow_epoch_length
        {
            eprintln!(
                "warning: manifest shadow_epoch_length is `{manifest_shadow_epoch_length}`, but bootstrap needs `{shadow_epoch_length}` for the selected boundary block",
            );
        }

        let chainspec_path =
            write_shadow_chainspec(&manifest, manifest_dir, shadow_epoch_length, force)?;
        let outcome = if let Some(outcome) = &manifest.shadow_dkg_outcome {
            decode_outcome(outcome)?
        } else {
            read_private_genesis_outcome(manifest_dir)?
        };

        ensure!(
            outcome.epoch == Epoch::new(SHADOW_EPOCH),
            "shadow DKG outcome is for epoch `{}`, expected `{SHADOW_EPOCH}`",
            outcome.epoch,
        );

        let shadow_validators = shadow_validator_registrations(&manifest)?;
        let shadow_validator_config_v2_storage =
            shadow_validator_config_v2_storage(&manifest, manifest_dir)?;
        let target_node = target_nodes[0];
        patch_execution_validator_registry(
            &execution_datadir.db_path,
            manifest.source_chain_id,
            reanchor_block_number,
            &shadow_validator_config_v2_storage,
            &shadow_validators,
            &outcome,
        )
        .wrap_err_with(|| {
            format!(
                "failed patching ValidatorConfigV2 in node-{} execution database `{}`",
                target_node.index,
                execution_datadir.db_path.display(),
            )
        })?;

        for validator in &target_nodes {
            let node_dir = node_artifact_dir(
                manifest_dir,
                validator,
                node_artifact_dir_override.as_deref(),
            );
            let consensus_dir = node_dir.join("consensus");
            let signing_key = SigningKey::read_from_file_encrypted(
                node_dir.join("signing.key"),
                SigningKeyPassphrase::from(SHADOWFORK_SIGNING_KEY_SECRET),
            )
            .wrap_err_with(|| {
                format!(
                    "failed reading encrypted signing key for node-{}",
                    validator.index
                )
            })?;
            let public_key: B256 = signing_key
                .public_key()
                .encode()
                .as_ref()
                .try_into()
                .expect("ed25519 public keys are 32 bytes");
            ensure!(
                public_key == validator.validator_public_key,
                "node-{} signing key public key `{}` does not match manifest public key `{}`",
                validator.index,
                public_key,
                validator.validator_public_key,
            );

            let signing_share = SigningShare::read_from_file(node_dir.join("signing.share"))
                .wrap_err_with(|| {
                    format!("failed reading signing share for node-{}", validator.index)
                })?
                .into_inner();

            ensure!(
                share_matches_outcome(&outcome, &signing_share),
                "node-{} signing share does not match the generated shadow DKG outcome",
                validator.index,
            );

            seed_consensus_state(
                &consensus_dir,
                outcome.clone(),
                signing_share,
                seed.saturating_add(validator.index as u64),
                force,
            )
            .wrap_err_with(|| {
                format!(
                    "failed seeding consensus state for node-{} at `{}`",
                    validator.index,
                    consensus_dir.display(),
                )
            })?;
        }

        println!("wrote shadow chainspec to `{}`", chainspec_path.display());
        println!(
            "seeded DKG state for {} validators at epoch {SHADOW_EPOCH}",
            target_nodes.len()
        );
        println!(
            "patched ValidatorConfigV2 in `{}`",
            execution_datadir.db_path.display()
        );
        Ok(())
    }
}

fn read_manifest(path: &Path) -> eyre::Result<ShadowForkManifest> {
    let json = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("failed reading manifest `{}`", path.display()))?;
    serde_json::from_str(&json)
        .wrap_err_with(|| format!("failed parsing manifest `{}`", path.display()))
}

fn target_nodes(
    manifest: &ShadowForkManifest,
    node_index: Option<usize>,
) -> eyre::Result<Vec<&NodeManifest>> {
    if let Some(index) = node_index {
        let node = manifest
            .validators
            .iter()
            .find(|validator| validator.index == index)
            .ok_or_else(|| eyre!("manifest does not contain node index `{index}`"))?;
        Ok(vec![node])
    } else {
        Ok(manifest.validators.iter().collect())
    }
}

fn node_artifact_dir(
    manifest_dir: &Path,
    node: &NodeManifest,
    node_artifact_dir: Option<&Path>,
) -> PathBuf {
    if let Some(node_artifact_dir) = node_artifact_dir {
        if node_artifact_dir.is_absolute() {
            node_artifact_dir.to_path_buf()
        } else {
            manifest_dir.join(node_artifact_dir)
        }
    } else {
        manifest_dir.join(format!("node-{}", node.index))
    }
}

fn write_shadow_chainspec(
    manifest: &ShadowForkManifest,
    manifest_dir: &Path,
    shadow_epoch_length: u64,
    force: bool,
) -> eyre::Result<PathBuf> {
    let chainspec_path = manifest_dir.join(SHADOW_CHAINSPEC_FILE);
    ensure!(
        force || !chainspec_path.exists(),
        "shadow chainspec `{}` already exists; rerun with --force to overwrite",
        chainspec_path.display(),
    );
    write_shadow_chainspec_file(
        &chainspec_path,
        &manifest.source_chain,
        manifest.source_chain_id,
        shadow_epoch_length,
    )?;
    Ok(chainspec_path)
}

fn storage_key(slot: U256) -> B256 {
    B256::from(slot.to_be_bytes::<32>())
}

fn parse_storage_word(value: &str) -> eyre::Result<U256> {
    let bytes = const_hex::decode(value.trim_start_matches("0x"))?;
    ensure!(
        bytes.len() <= 32,
        "storage word has {} bytes, expected at most 32",
        bytes.len(),
    );

    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(U256::from_be_bytes(padded))
}

fn read_storage_settings<TX: DbTx>(tx: &TX) -> eyre::Result<StorageSettings> {
    let value = tx.get::<tables::Metadata>("storage_settings".to_string())?;
    Ok(value
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_else(StorageSettings::v1))
}

type StorageSlot = (Address, U256);
type StorageOverlay = HashMap<StorageSlot, U256>;
type EmittedEvents = Vec<(Address, LogData)>;
type StorageSnapshot = (StorageOverlay, EmittedEvents);

struct DbStorageOverlay<'tx, TX> {
    tx: &'tx TX,
    chain_id: u64,
    block_env: TempoBlockEnv,
    storage_settings: StorageSettings,
    overlay: StorageOverlay,
    events: EmittedEvents,
    snapshots: Vec<StorageSnapshot>,
}

impl<'tx, TX> DbStorageOverlay<'tx, TX>
where
    TX: DbTx + DbTxMut,
{
    fn new(
        tx: &'tx TX,
        chain_id: u64,
        block_number: u64,
        storage_settings: StorageSettings,
    ) -> Self {
        Self {
            tx,
            chain_id,
            block_env: TempoBlockEnv {
                inner: BlockEnv {
                    number: U256::from(block_number),
                    ..Default::default()
                },
                ..Default::default()
            },
            storage_settings,
            overlay: HashMap::new(),
            events: Vec::new(),
            snapshots: Vec::new(),
        }
    }

    fn read_db_storage(&self, address: Address, slot: U256) -> Result<U256, TempoPrecompileError> {
        let key = storage_key(slot);
        if self.storage_settings.use_hashed_state() {
            let hashed_address = keccak256(address);
            let hashed_key = keccak256(key);
            let mut cursor = self
                .tx
                .cursor_dup_read::<tables::HashedStorages>()
                .map_err(db_precompile_error)?;
            if let Some(entry) = cursor
                .seek_by_key_subkey(hashed_address, hashed_key)
                .map_err(db_precompile_error)?
                && entry.key == hashed_key
            {
                return Ok(entry.value);
            }
        } else {
            let mut cursor = self
                .tx
                .cursor_dup_read::<tables::PlainStorageState>()
                .map_err(db_precompile_error)?;
            if let Some(entry) = cursor
                .seek_by_key_subkey(address, key)
                .map_err(db_precompile_error)?
                && entry.key == key
            {
                return Ok(entry.value);
            }
        }
        Ok(U256::ZERO)
    }

    fn read_db_account_info(&self, address: Address) -> Result<AccountInfo, TempoPrecompileError> {
        let account = if self.storage_settings.use_hashed_state() {
            self.tx
                .get::<tables::HashedAccounts>(keccak256(address))
                .map_err(db_precompile_error)?
        } else {
            self.tx
                .get::<tables::PlainAccountState>(address)
                .map_err(db_precompile_error)?
        };

        Ok(account.map(AccountInfo::from).unwrap_or_default())
    }

    fn clear_db_storage(&self, address: Address) -> eyre::Result<()> {
        if self.storage_settings.use_hashed_state() {
            let hashed_address = keccak256(address);
            let mut cursor = self.tx.cursor_dup_write::<tables::HashedStorages>()?;
            if cursor.seek_exact(hashed_address)?.is_some() {
                cursor.delete_current_duplicates()?;
            }
        } else {
            let mut cursor = self.tx.cursor_dup_write::<tables::PlainStorageState>()?;
            if cursor.seek_exact(address)?.is_some() {
                cursor.delete_current_duplicates()?;
            }
        }
        Ok(())
    }

    fn write_db_storage(&self, address: Address, slot: U256, value: U256) -> eyre::Result<()> {
        let key = storage_key(slot);
        if self.storage_settings.use_hashed_state() {
            let hashed_address = keccak256(address);
            let hashed_key = keccak256(key);
            let mut cursor = self.tx.cursor_dup_write::<tables::HashedStorages>()?;
            if cursor
                .seek_by_key_subkey(hashed_address, hashed_key)?
                .is_some_and(|entry| entry.key == hashed_key)
            {
                cursor.delete_current()?;
            }
            if !value.is_zero() {
                cursor.upsert(
                    hashed_address,
                    &StorageEntry {
                        key: hashed_key,
                        value,
                    },
                )?;
            }
        } else {
            let mut cursor = self.tx.cursor_dup_write::<tables::PlainStorageState>()?;
            if cursor
                .seek_by_key_subkey(address, key)?
                .is_some_and(|entry| entry.key == key)
            {
                cursor.delete_current()?;
            }
            if !value.is_zero() {
                cursor.upsert(address, &StorageEntry { key, value })?;
            }
        }
        Ok(())
    }
}

fn db_precompile_error(err: impl std::fmt::Display) -> TempoPrecompileError {
    TempoPrecompileError::Fatal(err.to_string())
}

impl<TX> PrecompileStorageProvider for DbStorageOverlay<'_, TX>
where
    TX: DbTx + DbTxMut,
{
    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn block_env(&self) -> &TempoBlockEnv {
        &self.block_env
    }

    fn set_code(&mut self, _address: Address, _code: Bytecode) -> Result<(), TempoPrecompileError> {
        Ok(())
    }

    fn with_account_info(
        &mut self,
        address: Address,
        f: &mut dyn FnMut(&AccountInfo),
    ) -> Result<(), TempoPrecompileError> {
        let account = self.read_db_account_info(address)?;
        f(&account);
        Ok(())
    }

    fn sload(&mut self, address: Address, key: U256) -> Result<U256, TempoPrecompileError> {
        if let Some(value) = self.overlay.get(&(address, key)) {
            return Ok(*value);
        }
        self.read_db_storage(address, key)
    }

    fn tload(&mut self, _address: Address, _key: U256) -> Result<U256, TempoPrecompileError> {
        Ok(U256::ZERO)
    }

    fn sstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        self.overlay.insert((address, key), value);
        Ok(())
    }

    fn tstore(
        &mut self,
        _address: Address,
        _key: U256,
        _value: U256,
    ) -> Result<(), TempoPrecompileError> {
        Ok(())
    }

    fn emit_event(&mut self, address: Address, event: LogData) -> Result<(), TempoPrecompileError> {
        self.events.push((address, event));
        Ok(())
    }

    fn deduct_gas(&mut self, _gas: u64) -> Result<(), TempoPrecompileError> {
        Ok(())
    }

    fn refund_gas(&mut self, _gas: i64) {}

    fn gas_limit(&self) -> u64 {
        u64::MAX
    }

    fn gas_used(&self) -> u64 {
        0
    }

    fn state_gas_used(&self) -> u64 {
        0
    }

    fn gas_refunded(&self) -> i64 {
        0
    }

    fn reservoir(&self) -> u64 {
        0
    }

    fn spec(&self) -> TempoHardfork {
        TempoHardfork::T2
    }

    fn amsterdam_eip8037_enabled(&self) -> bool {
        false
    }

    fn is_static(&self) -> bool {
        false
    }

    fn checkpoint(&mut self) -> JournalCheckpoint {
        let idx = self.snapshots.len();
        self.snapshots
            .push((self.overlay.clone(), self.events.clone()));
        JournalCheckpoint {
            log_i: 0,
            journal_i: idx,
            selfdestructed_i: 0,
        }
    }

    fn checkpoint_commit(&mut self, checkpoint: JournalCheckpoint) {
        assert_eq!(
            checkpoint.journal_i,
            self.snapshots.len() - 1,
            "out-of-order checkpoint commit",
        );
        self.snapshots.pop();
    }

    fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint) {
        assert_eq!(
            checkpoint.journal_i,
            self.snapshots.len() - 1,
            "out-of-order checkpoint revert",
        );
        let (overlay, events) = self.snapshots.remove(checkpoint.journal_i);
        self.overlay = overlay;
        self.events = events;
    }

    fn set_tip1060_storage_credits(&mut self, _enabled: bool) {
        // DbStorageOverlay does not run TIP-1060 accounting.
    }
}

fn read_private_genesis_outcome(manifest_dir: &Path) -> eyre::Result<OnchainDkgOutcome> {
    let genesis_path = manifest_dir.join("genesis.json");
    let json = std::fs::read_to_string(&genesis_path)
        .wrap_err_with(|| format!("failed reading `{}`", genesis_path.display()))?;
    let genesis: serde_json::Value = serde_json::from_str(&json)
        .wrap_err_with(|| format!("failed parsing `{}`", genesis_path.display()))?;
    let extra_data = genesis
        .get("extraData")
        .and_then(serde_json::Value::as_str)
        .ok_or_eyre("shadow genesis JSON does not contain string field `extraData`")?;
    let mut outcome = decode_outcome(extra_data)?;
    outcome.epoch = Epoch::new(SHADOW_EPOCH);
    Ok(outcome)
}

fn decode_outcome(hex: &str) -> eyre::Result<OnchainDkgOutcome> {
    let bytes = const_hex::decode(hex.trim_start_matches("0x"))
        .wrap_err("failed decoding shadow_dkg_outcome hex")?;
    OnchainDkgOutcome::read(&mut bytes.as_slice())
        .wrap_err("failed decoding shadow_dkg_outcome payload")
}

#[derive(Clone, Debug)]
struct ShadowValidatorRegistration {
    index: usize,
    public_key: B256,
    validator_address: Address,
    fee_recipient: Address,
    ingress: SocketAddr,
    egress: IpAddr,
}

fn shadow_validator_registrations(
    manifest: &ShadowForkManifest,
) -> eyre::Result<Vec<ShadowValidatorRegistration>> {
    manifest
        .validators
        .iter()
        .map(|validator| {
            const_hex::decode(validator.validator_add_signature.trim_start_matches("0x"))
                .wrap_err_with(|| {
                    format!(
                        "failed decoding addValidator signature for node-{}",
                        validator.index
                    )
                })?;

            Ok(ShadowValidatorRegistration {
                index: validator.index,
                public_key: validator.validator_public_key,
                validator_address: validator.validator_address,
                fee_recipient: validator.fee_recipient,
                ingress: validator.validator_addr,
                egress: validator.validator_addr.ip(),
            })
        })
        .collect()
}

fn shadow_validator_config_v2_storage(
    manifest: &ShadowForkManifest,
    manifest_dir: &Path,
) -> eyre::Result<Vec<(U256, U256)>> {
    let storage = if let Some(storage) = &manifest.shadow_validator_config_v2_storage {
        storage.clone()
    } else {
        read_generated_validator_config_v2_storage(manifest_dir)?
    };

    storage
        .iter()
        .map(|(slot, value)| {
            Ok((
                parse_storage_word(slot)
                    .wrap_err_with(|| format!("failed parsing ValidatorConfigV2 slot `{slot}`"))?,
                parse_storage_word(value).wrap_err_with(|| {
                    format!("failed parsing ValidatorConfigV2 value at slot `{slot}`")
                })?,
            ))
        })
        .collect()
}

fn read_generated_validator_config_v2_storage(
    manifest_dir: &Path,
) -> eyre::Result<BTreeMap<String, String>> {
    let genesis_path = manifest_dir.join("genesis.json");
    let json = std::fs::read_to_string(&genesis_path)
        .wrap_err_with(|| format!("failed reading `{}`", genesis_path.display()))?;
    let genesis: serde_json::Value = serde_json::from_str(&json)
        .wrap_err_with(|| format!("failed parsing `{}`", genesis_path.display()))?;

    let registry_address = VALIDATOR_CONFIG_V2_ADDRESS.to_string().to_ascii_lowercase();
    let storage = genesis
        .get("alloc")
        .and_then(serde_json::Value::as_object)
        .and_then(|alloc| alloc.get(&registry_address))
        .and_then(|account| account.get("storage"))
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            eyre!(
                "generated genesis `{}` does not contain ValidatorConfigV2 storage at `{registry_address}`",
                genesis_path.display(),
            )
        })?;

    storage
        .iter()
        .map(|(slot, value)| {
            Ok((
                slot.clone(),
                value
                    .as_str()
                    .ok_or_else(|| {
                        eyre!("generated ValidatorConfigV2 storage value is not a string")
                    })?
                    .to_string(),
            ))
        })
        .collect()
}

fn patch_execution_validator_registry(
    db_path: &Path,
    chain_id: u64,
    block_number: u64,
    validator_config_storage: &[(U256, U256)],
    validators: &[ShadowValidatorRegistration],
    outcome: &OnchainDkgOutcome,
) -> eyre::Result<()> {
    ensure!(
        db_path.exists(),
        "execution database `{}` does not exist; pass --execution-datadir pointing at a stopped Tempo datadir, chain datadir, or db directory",
        db_path.display(),
    );

    let db = open_db(db_path, DatabaseArguments::default())?;
    let tx = db.tx_mut()?;
    let storage_settings = read_storage_settings(&tx)?;
    let mut storage = DbStorageOverlay::new(&tx, chain_id, block_number, storage_settings);

    storage.clear_db_storage(VALIDATOR_CONFIG_V2_ADDRESS)?;
    for &(slot, value) in validator_config_storage {
        storage.write_db_storage(VALIDATOR_CONFIG_V2_ADDRESS, slot, value)?;
    }

    StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
        let config = ValidatorConfigV2::default();
        ensure!(
            config.is_initialized()?,
            "patched ValidatorConfigV2 is not initialized",
        );
        let active = config
            .get_active_validators()
            .wrap_err("patched ValidatorConfigV2 active set is unreadable")?;
        ensure!(
            active.len() == validators.len(),
            "patched ValidatorConfigV2 active set has {} validators, expected {}",
            active.len(),
            validators.len(),
        );

        for validator in validators {
            let current = config
                .validator_by_public_key(validator.public_key)
                .wrap_err_with(|| {
                    format!(
                        "patched ValidatorConfigV2 has no entry for node-{} public key `{}`",
                        validator.index, validator.public_key,
                    )
                })?;
            ensure!(
                current.validatorAddress == validator.validator_address,
                "node-{} public key has validator address `{}`, expected `{}`",
                validator.index,
                current.validatorAddress,
                validator.validator_address,
            );
            ensure!(
                current.feeRecipient == validator.fee_recipient,
                "node-{} public key has fee recipient `{}`, expected `{}`",
                validator.index,
                current.feeRecipient,
                validator.fee_recipient,
            );
            ensure!(
                current.ingress == validator.ingress.to_string(),
                "node-{} public key has ingress `{}`, expected `{}`",
                validator.index,
                current.ingress,
                validator.ingress,
            );
            ensure!(
                current.egress == validator.egress.to_string(),
                "node-{} public key has egress `{}`, expected `{}`",
                validator.index,
                current.egress,
                validator.egress,
            );
            ensure!(
                current.deactivatedAtHeight == 0,
                "node-{} public key is deactivated at height `{}`",
                validator.index,
                current.deactivatedAtHeight,
            );
        }

        Ok(())
    })?;

    if let Some((old_hash, new_hash)) = patch_boundary_header(db_path, &tx, block_number, outcome)?
    {
        println!(
            "patched boundary header at block {block_number} in `{}`: {old_hash} -> {new_hash}",
            db_path.display(),
        );
    }
    reanchor_execution_finality(&tx, block_number)?;

    tx.commit()?;

    println!(
        "replaced ValidatorConfigV2 storage in `{}` with {} shadow validators",
        db_path.display(),
        validators.len(),
    );
    println!(
        "reanchored execution safe/finalized block in `{}` to {block_number}",
        db_path.display(),
    );
    Ok(())
}

fn reanchor_execution_finality<TX>(tx: &TX, block_number: u64) -> eyre::Result<()>
where
    TX: DbTx + DbTxMut,
{
    tx.put::<tables::ChainState>(tables::ChainStateKey::LastFinalizedBlock, block_number)
        .wrap_err("failed reanchoring execution finalized block")?;
    tx.put::<tables::ChainState>(tables::ChainStateKey::LastSafeBlock, block_number)
        .wrap_err("failed reanchoring execution safe block")?;

    ensure!(
        tx.get::<tables::ChainState>(tables::ChainStateKey::LastFinalizedBlock)?
            == Some(block_number),
        "execution finalized block was not reanchored to `{block_number}`",
    );
    ensure!(
        tx.get::<tables::ChainState>(tables::ChainStateKey::LastSafeBlock)? == Some(block_number),
        "execution safe block was not reanchored to `{block_number}`",
    );

    Ok(())
}

fn patch_boundary_header<TX>(
    db_path: &Path,
    tx: &TX,
    block_number: u64,
    outcome: &OnchainDkgOutcome,
) -> eyre::Result<Option<(B256, B256)>>
where
    TX: DbTx + DbTxMut,
{
    let static_files_path = execution_static_files_path(db_path)?;
    ensure!(
        static_files_path.exists(),
        "execution static files directory `{}` does not exist; pass --execution-datadir pointing at a stopped Tempo datadir, chain datadir, or db directory",
        static_files_path.display(),
    );

    let static_file_provider = StaticFileProviderBuilder::read_write(&static_files_path)
        .build::<TempoPrimitives>()
        .wrap_err_with(|| {
            format!(
                "failed opening execution static files at `{}`",
                static_files_path.display(),
            )
        })?;
    let highest_header = static_file_provider
        .get_highest_static_file_block(StaticFileSegment::Headers)
        .ok_or_else(|| eyre!("execution static files contain no headers"))?;
    ensure!(
        highest_header == block_number,
        "shadow fork bootstrap can only patch a local execution datadir whose tip is the fork block. static files tip is `{highest_header}`, expected `{block_number}`. Stop the source node at the fork block or rerun generate-shadowfork against this datadir before bootstrapping.",
    );

    let mut header = static_file_provider
        .header_by_number(block_number)
        .wrap_err_with(|| format!("failed reading boundary header at block `{block_number}`"))?
        .ok_or_else(|| eyre!("boundary header at block `{block_number}` was not found"))?;
    let old_hash = static_file_provider
        .block_hash(block_number)
        .wrap_err_with(|| {
            format!("failed reading canonical hash for boundary block `{block_number}`")
        })?
        .unwrap_or_else(|| header.hash_slow());

    let extra_data = Bytes::from(outcome.encode());
    if header.inner.extra_data == extra_data {
        tx.delete::<tables::HeaderNumbers>(old_hash, None)?;
        tx.put::<tables::HeaderNumbers>(old_hash, block_number)?;
        verify_boundary_header_patch(
            &static_files_path,
            tx,
            block_number,
            old_hash,
            None,
            outcome,
        )?;
        println!(
            "verified boundary header at block {block_number} in `{}` already contains the generated shadow DKG outcome",
            db_path.display(),
        );
        return Ok(None);
    }

    header.inner.extra_data = extra_data;
    let new_hash = header.hash_slow();
    {
        let mut writer = static_file_provider.latest_writer(StaticFileSegment::Headers)?;
        writer.prune_headers(1)?;
        writer.commit()?;
    }
    {
        let mut writer = static_file_provider.latest_writer(StaticFileSegment::Headers)?;
        writer.append_header(&header, &new_hash)?;
        writer.commit()?;
    }

    tx.delete::<tables::HeaderNumbers>(old_hash, None)?;
    tx.put::<tables::HeaderNumbers>(new_hash, block_number)?;

    verify_boundary_header_patch(
        &static_files_path,
        tx,
        block_number,
        new_hash,
        Some(old_hash),
        outcome,
    )?;

    Ok(Some((old_hash, new_hash)))
}

fn verify_boundary_header_patch<TX>(
    static_files_path: &Path,
    tx: &TX,
    block_number: u64,
    expected_hash: B256,
    previous_hash: Option<B256>,
    expected_outcome: &OnchainDkgOutcome,
) -> eyre::Result<()>
where
    TX: DbTx,
{
    let static_file_provider = StaticFileProviderBuilder::read_write(static_files_path)
        .build::<TempoPrimitives>()
        .wrap_err_with(|| {
            format!(
                "failed reopening execution static files at `{}` for boundary verification",
                static_files_path.display(),
            )
        })?;

    let header = static_file_provider
        .header_by_number(block_number)
        .wrap_err_with(|| {
            format!("failed rereading patched boundary header at block `{block_number}`")
        })?
        .ok_or_else(|| eyre!("patched boundary header at block `{block_number}` was not found"))?;
    let actual_hash = header.hash_slow();
    ensure!(
        actual_hash == expected_hash,
        "patched boundary header at block `{block_number}` has hash `{actual_hash}`, expected `{expected_hash}`",
    );

    let canonical_hash = static_file_provider
        .block_hash(block_number)
        .wrap_err_with(|| {
            format!("failed rereading canonical hash for boundary block `{block_number}`")
        })?
        .ok_or_else(|| {
            eyre!("patched boundary block `{block_number}` has no canonical hash in static files")
        })?;
    ensure!(
        canonical_hash == expected_hash,
        "patched boundary block `{block_number}` has canonical hash `{canonical_hash}`, expected `{expected_hash}`",
    );

    let decoded = OnchainDkgOutcome::read(&mut header.inner.extra_data.as_ref())
        .wrap_err("patched boundary header did not contain a valid generated shadow DKG outcome")?;
    ensure!(
        decoded.players() == expected_outcome.players()
            && decoded.next_players() == expected_outcome.next_players()
            && decoded.dealers() == expected_outcome.dealers(),
        "patched boundary header DKG peers do not match generated shadow validators: dealers={:?}, players={:?}, next_players={:?}, expected_dealers={:?}, expected_players={:?}, expected_next_players={:?}",
        decoded.dealers(),
        decoded.players(),
        decoded.next_players(),
        expected_outcome.dealers(),
        expected_outcome.players(),
        expected_outcome.next_players(),
    );
    ensure!(
        &decoded == expected_outcome,
        "patched boundary header DKG outcome does not match the generated shadow DKG outcome",
    );

    let mapped_number = tx
        .get::<tables::HeaderNumbers>(expected_hash)
        .wrap_err_with(|| format!("failed reading HeaderNumbers entry for `{expected_hash}`"))?;
    ensure!(
        mapped_number == Some(block_number),
        "HeaderNumbers maps patched boundary hash `{expected_hash}` to `{:?}`, expected `{block_number}`",
        mapped_number,
    );

    if let Some(previous_hash) = previous_hash.filter(|hash| *hash != expected_hash) {
        let mapped_number = tx
            .get::<tables::HeaderNumbers>(previous_hash)
            .wrap_err_with(|| {
                format!(
                    "failed reading HeaderNumbers entry for old boundary hash `{previous_hash}`"
                )
            })?;
        ensure!(
            mapped_number.is_none(),
            "HeaderNumbers still maps old boundary hash `{previous_hash}` to `{:?}` after patching",
            mapped_number,
        );
    }

    Ok(())
}

fn execution_static_files_path(db_path: &Path) -> eyre::Result<PathBuf> {
    let chain_dir = db_path.parent().ok_or_else(|| {
        eyre!(
            "execution database path `{}` has no parent directory",
            db_path.display(),
        )
    })?;
    Ok(chain_dir.join("static_files"))
}

fn share_matches_outcome(outcome: &OnchainDkgOutcome, share: &Share) -> bool {
    outcome
        .sharing()
        .partial_public(share.index)
        .is_ok_and(|partial| share.public::<MinSig>() == partial)
}

fn seed_consensus_state(
    consensus_dir: &Path,
    outcome: OnchainDkgOutcome,
    signing_share: Share,
    seed: u64,
    force: bool,
) -> eyre::Result<()> {
    std::fs::create_dir_all(consensus_dir).wrap_err_with(|| {
        format!(
            "failed creating consensus directory `{}`",
            consensus_dir.display()
        )
    })?;

    let consensus_dir = consensus_dir.to_path_buf();
    std::thread::Builder::new()
        .name("shadowfork-bootstrap-commonware".to_string())
        .spawn(move || {
            let runner = commonware_runtime::tokio::Runner::new(
                commonware_runtime::tokio::Config::default().with_storage_directory(consensus_dir),
            );

            runner.start(|context| async move {
                let mut states = Metadata::<_, u64, BootstrapDkgState>::init(
                    context.with_label("states"),
                    MetadataConfig {
                        partition: DKG_STATES_METADATA_PARTITION.to_string(),
                        codec_config: MAXIMUM_VALIDATORS,
                    },
                )
                .await
                .map_err(eyre::Report::from)
                .wrap_err("unable to initialize DKG states metadata")?;

                let existing = states.keys().copied().collect::<Vec<_>>();
                ensure!(
                    force || existing.is_empty(),
                    "DKG states metadata already contains epochs {existing:?}; rerun with --force to overwrite",
                );
                if !existing.is_empty() {
                    states.clear();
                }

                let mut rng = rand_08::rngs::StdRng::seed_from_u64(seed);
                let state = BootstrapDkgState {
                    epoch: outcome.epoch,
                    seed: Summary::random(&mut rng),
                    output: outcome.output,
                    share: BootstrapShareState::Plaintext(Some(signing_share)),
                    players: outcome.next_players,
                    is_full_dkg: outcome.is_next_full_dkg,
                };

                states
                    .put_sync(SHADOW_EPOCH, state)
                    .await
                    .map_err(eyre::Report::from)
                    .wrap_err("unable to write shadow DKG state metadata")
            })
        })
        .wrap_err("failed spawning commonware bootstrap thread")?
        .join()
        .map_err(|_| eyre!("commonware bootstrap thread panicked"))?
}

#[derive(Debug, Deserialize)]
struct ShadowForkManifest {
    source_chain: String,
    source_chain_id: u64,
    source_execution_datadir: Option<PathBuf>,
    fork_block_number: u64,
    shadow_epoch: Option<u64>,
    shadow_epoch_length: Option<u64>,
    shadow_dkg_outcome: Option<String>,
    shadow_validator_config_v2_storage: Option<BTreeMap<String, String>>,
    validators: Vec<NodeManifest>,
}

#[derive(Debug, Deserialize)]
struct NodeManifest {
    index: usize,
    validator_addr: SocketAddr,
    validator_public_key: B256,
    validator_address: Address,
    fee_recipient: Address,
    validator_add_signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum BootstrapShareState {
    Plaintext(Option<Share>),
}

impl EncodeSize for BootstrapShareState {
    fn encode_size(&self) -> usize {
        match self {
            Self::Plaintext(share) => 1 + share.encode_size(),
        }
    }
}

impl Write for BootstrapShareState {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Plaintext(share) => {
                0u8.write(buf);
                share.write(buf);
            }
        }
    }
}

impl Read for BootstrapShareState {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let tag = u8::read(buf)?;
        match tag {
            0 => Ok(Self::Plaintext(ReadExt::read(buf)?)),
            other => Err(commonware_codec::Error::InvalidEnum(other)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BootstrapDkgState {
    epoch: Epoch,
    seed: Summary,
    output: Output<MinSig, PublicKey>,
    share: BootstrapShareState,
    players: ordered::Set<PublicKey>,
    is_full_dkg: bool,
}

impl BootstrapDkgState {
    fn legacy_syncers(&self) -> ordered::Set<PublicKey> {
        ordered::Set::default()
    }
}

impl EncodeSize for BootstrapDkgState {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.seed.encode_size()
            + self.output.encode_size()
            + self.share.encode_size()
            + self.players.encode_size()
            + self.legacy_syncers().encode_size()
            + self.is_full_dkg.encode_size()
    }
}

impl Write for BootstrapDkgState {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.epoch.write(buf);
        self.seed.write(buf);
        self.output.write(buf);
        self.share.write(buf);
        self.players.write(buf);
        self.legacy_syncers().write(buf);
        self.is_full_dkg.write(buf);
    }
}

impl Read for BootstrapDkgState {
    type Cfg = NonZeroU32;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let epoch = ReadExt::read(buf)?;
        let seed = ReadExt::read(buf)?;
        let output = Read::read_cfg(buf, &(*cfg, ModeVersion::v0()))?;
        let share = ReadExt::read(buf)?;
        let players = Read::read_cfg(buf, &(RangeCfg::from(1..=(u16::MAX as usize)), ()))?;
        ordered::Set::<PublicKey>::read_cfg(buf, &(RangeCfg::from(0..=(u16::MAX as usize)), ()))?;
        let is_full_dkg = ReadExt::read(buf)?;

        Ok(Self {
            epoch,
            seed,
            output,
            share,
            players,
            is_full_dkg,
        })
    }
}
