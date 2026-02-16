use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use alloy_consensus::BlockHeader;
use alloy_primitives::{Address, B256};
use commonware_codec::DecodeExt as _;
use commonware_consensus::types::Height;
use commonware_cryptography::ed25519::PublicKey;
use commonware_utils::{TryFromIterator, ordered};
use eyre::{OptionExt as _, WrapErr as _};
use prometheus_client::metrics::counter::Counter;
use reth_ethereum::{
    evm::revm::{State, database::StateProviderDatabase},
    network::NetworkInfo,
};
use reth_node_builder::{Block as _, ConfigureEvm as _};
use reth_provider::{
    BlockHashReader as _, BlockIdReader as _, BlockNumReader as _, BlockReader as _, BlockSource,
    StateProviderFactory as _,
};
use tempo_chainspec::hardfork::TempoHardforks as _;
use tempo_node::TempoFullNode;
use tempo_precompiles::{
    storage::StorageCtx,
    validator_config::{IValidatorConfig, ValidatorConfig},
    validator_config_v2::{IValidatorConfigV2, ValidatorConfigV2},
};

use tempo_primitives::TempoHeader;
use tracing::{Level, info, instrument, warn};

pub(crate) fn v2_activation_height(node: &TempoFullNode, height: u64) -> eyre::Result<u64> {
    read_validator_config_at_height(node, height, |config: &ValidatorConfigV2| {
        config
            .get_initialized_at_height()
            .map_err(eyre::Report::new)
    })
    .map(|(_, _, activation_height)| activation_height)
}

pub(crate) fn is_v2_active(node: &TempoFullNode, height: u64) -> eyre::Result<bool> {
    read_validator_config_at_height(node, height, |config: &ValidatorConfigV2| {
        config.is_initialized().map_err(eyre::Report::new)
    })
    .map(|(_, _, activated)| activated)
}

/// Reads the `nextFullDkgCeremony` epoch value from the ValidatorConfig precompile.
///
/// This is used to determine if the next DKG ceremony should be a full ceremony
/// (new polynomial) instead of a reshare.
#[instrument(
    skip_all,
    fields(
        at_height,
    ),
    err,
    ret(level = Level::INFO)
)]
pub(crate) fn read_re_dkg_epoch(node: &TempoFullNode, at_height: u64) -> eyre::Result<u64> {
    if at_height
        >= v2_activation_height(node, at_height).wrap_err(
            "failed reading contract to determine validator config v2 activation height",
        )?
    {
        read_validator_config_at_height(node, at_height, |config: &ValidatorConfigV2| {
            config
                .get_next_full_dkg_ceremony()
                .map_err(eyre::Report::new)
        })
        .map(|(_, _, epoch)| epoch)
    } else {
        read_validator_config_at_height(node, at_height, |config: &ValidatorConfig| {
            config
                .get_next_full_dkg_ceremony()
                .map_err(eyre::Report::new)
        })
        .map(|(_, _, epoch)| epoch)
    }
}

pub(crate) enum ReadTarget {
    AtLeast { height: Height },
}

/// Attempts to read the validator config from the smart contract, retrying
/// until the required block height is available.
///
/// Uses the timestamp of `reference_header` to decide whether to read validator
/// config v1 or v2.
pub(crate) async fn read_validator_config_with_retry(
    context: &impl commonware_runtime::Clock,
    node: &TempoFullNode,
    reference_header: &TempoHeader,
    target: ReadTarget,
    total_attempts: &Counter,
) -> (u64, B256, Validators) {
    let mut attempts = 0;
    const MIN_RETRY: Duration = Duration::from_secs(1);
    const MAX_RETRY: Duration = Duration::from_secs(30);

    'read_contract: loop {
        total_attempts.inc();
        attempts += 1;

        let target_height = match target {
            ReadTarget::AtLeast { height } => node
                .provider
                .best_block_number()
                .ok()
                .map(Height::new)
                .filter(|best| best >= &height)
                .unwrap_or(height),
        };

        if let Ok(validators) =
            read_from_contract_at_height(attempts, node, target_height.get(), reference_header)
        {
            break 'read_contract validators;
        }

        let retry_after = MIN_RETRY.saturating_mul(attempts).min(MAX_RETRY);
        let is_syncing = node.network.is_syncing();
        let best_block = node.provider.best_block_number();
        let blocks_behind = best_block
            .as_ref()
            .ok()
            .map(|best| target_height.get().saturating_sub(*best));
        tracing::warn_span!("read_validator_config_with_retry").in_scope(|| {
            warn!(
                attempts,
                retry_after = %tempo_telemetry_util::display_duration(retry_after),
                is_syncing,
                best_block = %tempo_telemetry_util::display_result(&best_block),
                %target_height,
                blocks_behind = %tempo_telemetry_util::display_option(&blocks_behind),
                "reading validator config from contract failed; will retry",
            );
        });
        context.sleep(retry_after).await;
    }
}

/// Reads state from the ValidatorConfig precompile at a given block height.
pub(crate) fn read_validator_config_at_height<C, T>(
    node: &TempoFullNode,
    height: u64,
    read_fn: impl FnOnce(&C) -> eyre::Result<T>,
) -> eyre::Result<(u64, B256, T)>
where
    C: Default,
{
    // Try mapping the block height to a hash tracked by reth.
    //
    // First check the canonical chain, then fallback to pending block state.
    //
    // Necessary because the DKG and application actors process finalized block concurrently.
    let block_hash = if let Some(hash) = node
        .provider
        .block_hash(height)
        .wrap_err_with(|| format!("failed reading block hash at height `{height}`"))?
    {
        hash
    } else if let Some(pending) = node
        .provider
        .pending_block_num_hash()
        .wrap_err("failed reading pending block state")?
        && pending.number == height
    {
        pending.hash
    } else {
        return Err(eyre::eyre!("block not found at height `{height}`"));
    };

    let block = node
        .provider
        .find_block_by_hash(block_hash, BlockSource::Any)
        .map_err(Into::<eyre::Report>::into)
        .and_then(|maybe| maybe.ok_or_eyre("execution layer returned empty block"))
        .wrap_err_with(|| format!("failed reading block with hash `{block_hash}`"))?;

    let db = State::builder()
        .with_database(StateProviderDatabase::new(
            node.provider
                .state_by_block_hash(block_hash)
                .wrap_err_with(|| {
                    format!("failed to get state from node provider for hash `{block_hash}`")
                })?,
        ))
        .build();

    let mut evm = node
        .evm_config
        .evm_for_block(db, block.header())
        .wrap_err("failed instantiating evm for block")?;

    let height = block.number();
    let hash = block.seal_slow().hash();

    let ctx = evm.ctx_mut();
    let res = StorageCtx::enter_evm(
        &mut ctx.journaled_state,
        &ctx.block,
        &ctx.cfg,
        &ctx.tx,
        || read_fn(&C::default()),
    )?;
    Ok((height, hash, res))
}

pub(crate) enum Validators {
    V1(ordered::Map<PublicKey, DecodedValidatorV1>),
    V2(ordered::Map<PublicKey, DecodedValidatorV2>),
}

/// Reads the validator config at `height`.
///
/// Uses `reference_header` to determine whether to read validators from
/// validator config v1 or v2.
///
/// Note that this returns all validators, active and inactive.
#[instrument(
    skip_all,
    fields(
        attempt = _attempt,
        %height,
    ),
    err
)]
pub(crate) fn read_from_contract_at_height(
    _attempt: u32,
    node: &TempoFullNode,
    height: u64,
    reference_header: &TempoHeader,
) -> eyre::Result<(u64, B256, Validators)> {
    let vals = if node
        .chain_spec()
        .is_t2_active_at_timestamp(reference_header.timestamp())
        && height
            >= v2_activation_height(node, height).wrap_err(
                "failed reading from validator config v2 activity state after hardfork activation",
            )? {
        let (read_height, hash, raw_validators) =
            read_validator_config_at_height(node, height, |config: &ValidatorConfigV2| {
                config
                    .get_validators()
                    .wrap_err("failed to query contract for validator config")
            })?;

        info!(
            ?raw_validators,
            "read validators from validator config v2 contract",
        );

        let decoded_validators = raw_validators
            .into_iter()
            .map(|raw| DecodedValidatorV2::decode_from_contract(raw))
            .collect::<Result<Vec<_>, _>>()
            .wrap_err("failed an entry in the on-chain validator set")?;

        (
            read_height,
            hash,
            Validators::V2(
                ordered::Map::try_from_iter(
                    decoded_validators
                        .into_iter()
                        .map(|validator| (validator.public_key.clone(), validator)),
                )
                .wrap_err("contract contained validators with duplicate public keys")?,
            ),
        )
    } else {
        let (read_height, hash, raw_validators) =
            read_validator_config_at_height(node, height, |config: &ValidatorConfig| {
                config
                    .get_validators()
                    .wrap_err("failed to query contract for validator config")
            })?;
        info!(
            ?raw_validators,
            "read validators from validator config v1 contract",
        );
        (
            read_height,
            hash,
            Validators::V1(decode_from_contract(raw_validators)),
        )
    };
    Ok(vals)
}

#[instrument(skip_all, fields(validators_to_decode = contract_vals.len()))]
pub(crate) fn decode_from_contract(
    contract_vals: Vec<IValidatorConfig::Validator>,
) -> ordered::Map<PublicKey, DecodedValidatorV1> {
    let mut decoded = HashMap::new();
    for val in contract_vals.into_iter() {
        // NOTE: not reporting errors because `decode_from_contract` emits
        // events on success and error
        if let Ok(val) = DecodedValidatorV1::decode_from_contract(val)
            && let Some(old) = decoded.insert(val.public_key.clone(), val)
        {
            warn!(
                %old,
                new = %decoded.get(&old.public_key).expect("just inserted it"),
                "replaced peer because public keys were duplicated",
            );
        }
    }
    ordered::Map::from_iter_dedup(decoded)
}

/// A ContractValidator is a peer read from the validator config smart const.
///
/// The inbound and outbound addresses stored herein are guaranteed to be of the
/// form `<host>:<port>` for inbound, and `<ip>:<port>` for outbound. Here,
/// `<host>` is either an IPv4 or IPV6 address, or a fully qualified domain name.
/// `<ip>` is an IPv4 or IPv6 address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DecodedValidatorV1 {
    pub(crate) active: bool,
    /// The `publicKey` field of the contract. Used by other validators to
    /// identify a peer by verifying the signatures of its p2p messages and
    /// as a dealer/player/participant in DKG ceremonies and consensus for a
    /// given epoch. Part of the set registered with the lookup p2p manager.
    pub(crate) public_key: PublicKey,
    /// The `inboundAddress` field of the contract. Used by other validators
    /// to dial a peer and ensure that messages from that peer are coming from
    /// this address. Part of the set registered with the lookup p2p manager.
    pub(crate) inbound: SocketAddr,
    /// The `outboundAddress` field of the contract. Currently ignored because
    /// all p2p communication is symmetric (outbound and inbound) via the
    /// `inboundAddress` field.
    pub(crate) outbound: SocketAddr,
    /// The `index` field of the contract. Not used by consensus and just here
    /// for debugging purposes to identify the contract entry. Emitted in
    /// tracing events.
    pub(crate) index: u64,
    /// The `address` field of the contract. Not used by consensus and just here
    /// for debugging purposes to identify the contract entry. Emitted in
    /// tracing events.
    pub(crate) address: Address,
}

impl DecodedValidatorV1 {
    /// Attempts to decode a single validator from the values read in the smart contract.
    ///
    /// This function does not perform hostname lookup on either of the addresses.
    /// Instead, only the shape of the addresses are checked for whether they are
    /// socket addresses (IP:PORT pairs), or fully qualified domain names.
    #[instrument(ret(Display, level = Level::DEBUG), err(level = Level::WARN))]
    fn decode_from_contract(
        IValidatorConfig::Validator {
            active,
            publicKey,
            index,
            validatorAddress,
            inboundAddress,
            outboundAddress,
        }: IValidatorConfig::Validator,
    ) -> eyre::Result<Self> {
        let public_key = PublicKey::decode(publicKey.as_ref())
            .wrap_err("failed decoding publicKey field as ed25519 public key")?;
        let inbound = inboundAddress
            .parse()
            .wrap_err("inboundAddress was not valid")?;
        let outbound = outboundAddress
            .parse()
            .wrap_err("outboundAddress was not valid")?;
        Ok(Self {
            active,
            public_key,
            inbound,
            outbound,
            index,
            address: validatorAddress,
        })
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active
    }
}

impl std::fmt::Display for DecodedValidatorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "public key = `{}`, inbound = `{}`, outbound = `{}`, index = `{}`, address = `{}`",
            self.public_key, self.inbound, self.outbound, self.index, self.address
        ))
    }
}

/// An entry in the validator config v2 contract with all its fields decoded
/// into Rust types.
pub(crate) struct DecodedValidatorV2 {
    public_key: PublicKey,
    ingress: SocketAddr,
    egress: IpAddr,
    added_at_height: u64,
    deleted_at_height: u64,
    index: u64,
    address: Address,
}

impl DecodedValidatorV2 {
    pub(crate) fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub(crate) fn ingress(&self) -> SocketAddr {
        self.ingress
    }

    pub(crate) fn egress(&self) -> IpAddr {
        self.egress
    }

    pub(crate) fn is_active(&self) -> bool {
        self.deleted_at_height == 0
    }

    pub(crate) fn is_active_at_height(&self, height: u64) -> bool {
        self.added_at_height <= height
            && (self.deleted_at_height == 0 || self.deleted_at_height > height)
    }

    #[instrument(ret(Display, level = Level::DEBUG), err(level = Level::WARN))]
    pub(crate) fn decode_from_contract(
        IValidatorConfigV2::Validator {
            publicKey,
            validatorAddress: address,
            ingress,
            egress,
            index,
            addedAtHeight: added_at_height,
            deactivatedAtHeight: deleted_at_height,
        }: IValidatorConfigV2::Validator,
    ) -> eyre::Result<Self> {
        let public_key = PublicKey::decode(publicKey.as_ref())
            .wrap_err("failed decoding publicKey field as ed25519 public key")?;
        let ingress = ingress.parse().wrap_err("ingress was not valid")?;
        let egress = egress.parse().wrap_err("egress was not valid")?;
        Ok(Self {
            public_key,
            ingress,
            egress,
            added_at_height,
            deleted_at_height,
            index,
            address,
        })
    }
}
impl std::fmt::Display for DecodedValidatorV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "public key = `{}`, ingress = `{}`, egress = `{}`, added_at_height: `{}`, deleted_at_height = `{}`, index = `{}`, address = `{}`",
            self.public_key,
            self.ingress,
            self.egress,
            self.added_at_height,
            self.deleted_at_height,
            self.index,
            self.address
        ))
    }
}
