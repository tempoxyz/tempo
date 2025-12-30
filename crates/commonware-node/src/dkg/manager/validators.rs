use std::{collections::HashMap, net::SocketAddr};

use alloy_primitives::Address;
use commonware_codec::DecodeExt as _;
use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher};
use commonware_cryptography::ed25519::PublicKey;
use commonware_utils::ordered;
use eyre::{OptionExt as _, WrapErr as _};
use reth_ethereum::evm::revm::{State, database::StateProviderDatabase};
use reth_node_builder::{Block as _, ConfigureEvm as _};
use reth_provider::{
    BlockHashReader, BlockIdReader as _, BlockReader as _, BlockSource, StateProviderFactory as _,
};
use tempo_node::TempoFullNode;
use tempo_precompiles::{
    storage::StorageCtx,
    validator_config::{IValidatorConfig, ValidatorConfig},
};

use tracing::{Level, info, instrument, warn};

/// Reads the validator config from the boundary block of `epoch`.
///
/// If `epoch` is not set, reads the genesis block.
///
/// Note that this returns all validators, active and inactive.
#[instrument(
    skip_all,
    fields(
        attempt = _attempt,
        epoch = epoch.map(tracing::field::display),
    ),
    err
)]
pub(super) async fn read_from_contract_on_epoch_boundary(
    _attempt: u32,
    node: &TempoFullNode,
    epoch: Option<Epoch>,
    epoch_strategy: &FixedEpocher,
) -> eyre::Result<ordered::Map<PublicKey, DecodedValidator>> {
    let last_height = epoch.map_or(0, |epoch| {
        epoch_strategy
            .last(epoch)
            .expect("epoch strategy covers all epochs")
    });
    info!(
        last_height,
        "will read contract state from last height of epoch"
    );

    // Try mapping the block height to a hash tracked by reth.
    //
    // First check the canonical chain, then fallback to pending block state.
    //
    // Necessary because the DKG and application actors process finalized block concurrently.
    let block_hash = if let Some(hash) = node
        .provider
        .block_hash(last_height)
        .wrap_err_with(|| format!("failed reading block hash at height `{last_height}`"))?
    {
        hash
    } else if let Some(pending) = node
        .provider
        .pending_block_num_hash()
        .wrap_err("failed reading pending block state")?
        && pending.number == last_height
    {
        pending.hash
    } else {
        return Err(eyre::eyre!("block not found at height `{last_height}`"));
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

    // XXX: Ensure that evm and internals go out of scope before the await point
    // below.
    let raw_validators = {
        let mut evm = node
            .evm_config
            .evm_for_block(db, block.header())
            .wrap_err("failed instantiating evm for genesis block")?;

        let ctx = evm.ctx_mut();
        StorageCtx::enter_evm(&mut ctx.journaled_state, &ctx.block, &ctx.cfg, || {
            let validator_config = ValidatorConfig::new();
            validator_config
                .get_validators()
                .wrap_err("failed to query contract for validator config")
        })
    }?;

    info!(?raw_validators, "read validators from contract",);

    Ok(decode_from_contract(raw_validators).await)
}

#[instrument(skip_all, fields(validators_to_decode = contract_vals.len()))]
async fn decode_from_contract(
    contract_vals: Vec<IValidatorConfig::Validator>,
) -> ordered::Map<PublicKey, DecodedValidator> {
    let mut decoded = HashMap::new();
    for val in contract_vals.into_iter() {
        // NOTE: not reporting errors because `decode_from_contract` emits
        // events on success and error
        if let Ok(val) = DecodedValidator::decode_from_contract(val)
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
pub(super) struct DecodedValidator {
    pub(super) active: bool,
    /// The `publicKey` field of the contract. Used by other validators to
    /// identify a peer by verifying the signatures of its p2p messages and
    /// as a dealer/player/participant in DKG ceremonies and consensus for a
    /// given epoch. Part of the set registered with the lookup p2p manager.
    pub(super) public_key: PublicKey,
    /// The `inboundAddress` field of the contract. Used by other validators
    /// to dial a peer and ensure that messages from that peer are coming from
    /// this address. Part of the set registered with the lookup p2p manager.
    pub(super) inbound: SocketAddr,
    /// The `outboundAddress` field of the contract. Currently ignored because
    /// all p2p communication is symmetric (outbound and inbound) via the
    /// `inboundAddress` field.
    pub(super) outbound: SocketAddr,
    /// The `index` field of the contract. Not used by consensus and just here
    /// for debugging purposes to identify the contract entry. Emitted in
    /// tracing events.
    pub(super) index: u64,
    /// The `address` field of the contract. Not used by consensus and just here
    /// for debugging purposes to identify the contract entry. Emitted in
    /// tracing events.
    pub(super) address: Address,
}

impl DecodedValidator {
    /// Attempts to decode a single validator from the values read in the smart contract.
    ///
    /// This function does not perform hostname lookup on either of the addresses.
    /// Instead, only the shape of the addresses are checked for whether they are
    /// socket addresses (IP:PORT pairs), or fully qualified domain names.
    #[instrument(ret(Display, level = Level::INFO), err(level = Level::WARN))]
    pub(super) fn decode_from_contract(
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

impl std::fmt::Display for DecodedValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "public key = `{}`, inbound = `{}`, outbound = `{}`, index = `{}`, address = `{}`",
            self.public_key, self.inbound, self.outbound, self.index, self.address
        ))
    }
}
