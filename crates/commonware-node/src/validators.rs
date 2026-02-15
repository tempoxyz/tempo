use std::{collections::HashMap, net::SocketAddr, time::Duration};

use alloy_primitives::Address;
use commonware_codec::DecodeExt as _;
use commonware_consensus::types::Height;
use commonware_cryptography::ed25519::PublicKey;
use commonware_utils::ordered;
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
use tempo_node::TempoFullNode;
use tempo_precompiles::{
    storage::StorageCtx,
    validator_config::{IValidatorConfig, ValidatorConfig},
};

use tracing::{Level, info, instrument, warn};

pub(crate) enum ReadTarget {
    AtLeast { height: Height },
    Exact { height: Height },
}

/// Attempts to read the validator config from the smart contract, retrying
/// until the required block height is available.
pub(crate) async fn read_validator_config_with_retry(
    context: &impl commonware_runtime::Clock,
    node: &TempoFullNode,
    target: ReadTarget,
    total_attempts: &Counter,
) -> ordered::Map<PublicKey, DecodedValidatorV1> {
    let mut attempts = 0;
    const MIN_RETRY: Duration = Duration::from_secs(1);
    const MAX_RETRY: Duration = Duration::from_secs(30);

    'read_contract: loop {
        total_attempts.inc();
        attempts += 1;

        let target_height = match target {
            ReadTarget::Exact { height } => height,
            ReadTarget::AtLeast { height } => node
                .provider
                .best_block_number()
                .ok()
                .map(Height::new)
                .filter(|best| best >= &height)
                .unwrap_or(height),
        };

        if let Ok(validators) = read_from_contract_at_height(attempts, node, target_height).await {
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
pub(crate) fn read_validator_config_at_height<T>(
    node: &TempoFullNode,
    height: Height,
    read_fn: impl FnOnce(&ValidatorConfig) -> eyre::Result<T>,
) -> eyre::Result<T> {
    // Try mapping the block height to a hash tracked by reth.
    //
    // First check the canonical chain, then fallback to pending block state.
    //
    // Necessary because the DKG and application actors process finalized block concurrently.
    let block_hash = if let Some(hash) = node
        .provider
        .block_hash(height.get())
        .wrap_err_with(|| format!("failed reading block hash at height `{height}`"))?
    {
        hash
    } else if let Some(pending) = node
        .provider
        .pending_block_num_hash()
        .wrap_err("failed reading pending block state")?
        && pending.number == height.get()
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

    let ctx = evm.ctx_mut();
    StorageCtx::enter_evm(
        &mut ctx.journaled_state,
        &ctx.block,
        &ctx.cfg,
        &ctx.tx,
        || read_fn(&ValidatorConfig::new()),
    )
}

/// Reads the validator config from the boundary block of `epoch`.
///
/// If `epoch` is not set, reads the genesis block.
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
pub(crate) async fn read_from_contract_at_height(
    _attempt: u32,
    node: &TempoFullNode,
    height: Height,
) -> eyre::Result<ordered::Map<PublicKey, DecodedValidatorV1>> {
    let raw_validators = read_validator_config_at_height(node, height, |config| {
        config
            .get_validators()
            .wrap_err("failed to query contract for validator config")
    })?;

    info!(?raw_validators, "read validators from contract",);

    Ok(decode_from_contract(raw_validators).await)
}

#[instrument(skip_all, fields(validators_to_decode = contract_vals.len()))]
async fn decode_from_contract(
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
    #[instrument(ret(Display, level = Level::INFO), err(level = Level::WARN))]
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
}

impl std::fmt::Display for DecodedValidatorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "public key = `{}`, inbound = `{}`, outbound = `{}`, index = `{}`, address = `{}`",
            self.public_key, self.inbound, self.outbound, self.index, self.address
        ))
    }
}
