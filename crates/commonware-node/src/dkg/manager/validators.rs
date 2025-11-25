use std::collections::HashMap;

use alloy_evm::EvmInternals;
use alloy_primitives::Address;
use commonware_codec::DecodeExt as _;
use commonware_consensus::{types::Epoch, utils};
use commonware_cryptography::ed25519::PublicKey;
use commonware_utils::set::OrderedAssociated;
use eyre::{OptionExt as _, WrapErr as _, ensure};
use reth_ethereum::evm::revm::{State, database::StateProviderDatabase};
use reth_node_builder::{Block as _, ConfigureEvm as _};
use reth_provider::{BlockNumReader as _, BlockReader as _, StateProviderFactory as _};
use std::net::SocketAddr;
pub(super) use tempo_dkg_onchain_artifacts::{DecodedValidator, ValidatorState};
use tempo_node::TempoFullNode;
use tempo_precompiles::{
    storage::evm::EvmPrecompileStorageProvider,
    validator_config::{IValidatorConfig, ValidatorConfig},
};

use tracing::{Level, info, instrument, warn};

/// Reads the validator config of `epoch`.
///
/// The validator config for `epoch` is always read from the last height of
/// `epoch-1`.
#[instrument(
    skip_all,
    fields(
        attempt = _attempt,
        for_epoch,
        from_block = last_height_before_epoch(for_epoch, epoch_length),
    ),
    err
)]
pub(super) async fn read_from_contract(
    _attempt: u32,
    node: &TempoFullNode,
    for_epoch: Epoch,
    epoch_length: u64,
) -> eyre::Result<OrderedAssociated<PublicKey, DecodedValidator>> {
    let last_height = last_height_before_epoch(for_epoch, epoch_length);
    let block = node
        .provider
        .block_by_number(last_height)
        .map_err(Into::<eyre::Report>::into)
        .and_then(|maybe| maybe.ok_or_eyre("execution layer returned empty block"))
        .wrap_err_with(|| format!("failed reading block at height `{last_height}`"))?;

    let db = State::builder()
        .with_database(StateProviderDatabase::new(
            node.provider
                .state_by_block_id(last_height.into())
                .wrap_err_with(|| {
                    format!("failed to get state from node provider for height `{last_height}`")
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
        let internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
        let mut provider = EvmPrecompileStorageProvider::new_max_gas(internals, &ctx.cfg);

        let mut validator_config = ValidatorConfig::new(&mut provider);
        validator_config
            .get_validators(IValidatorConfig::getValidatorsCall {})
            .wrap_err("failed to query contract for validator config")?
    };

    info!(?raw_validators, "read validators from contract",);

    Ok(decode_from_contract(raw_validators).await)
}

#[instrument(skip_all, fields(validators_to_decode = contract_vals.len()))]
async fn decode_from_contract(
    contract_vals: Vec<IValidatorConfig::Validator>,
) -> OrderedAssociated<PublicKey, DecodedValidator> {
    let mut decoded = HashMap::new();
    for val in contract_vals.into_iter().filter(|val| val.active) {
        // NOTE: not reporting errors because `decode_validator_from_contract` emits
        // events on success and error
        if let Ok(val) = decode_validator_from_contract(val)
            && let Some(old) = decoded.insert(val.public_key.clone(), val)
        {
            warn!(
                %old,
                new = %decoded.get(&old.public_key).expect("just inserted it"),
                "replaced peer because public keys were duplicated",
            );
        }
    }
    decoded.into_iter().collect::<_>()
}

/// Reads validators from the contract at the latest block.
pub(super) async fn read_from_latest_block(
    node: &TempoFullNode,
) -> eyre::Result<OrderedAssociated<PublicKey, DecodedValidator>> {
    let latest_block_number = node
        .provider
        .best_block_number()
        .wrap_err("failed to get latest block number")?;

    let block = node
        .provider
        .block_by_number(latest_block_number)
        .map_err(Into::<eyre::Report>::into)
        .and_then(|maybe| maybe.ok_or_eyre("execution layer returned empty block"))
        .wrap_err_with(|| format!("failed reading block at height `{latest_block_number}`"))?;

    let db = State::builder()
        .with_database(StateProviderDatabase::new(
            node.provider
                .state_by_block_id(latest_block_number.into())
                .wrap_err_with(|| {
                    format!(
                        "failed to get state from node provider for height `{latest_block_number}`"
                    )
                })?,
        ))
        .build();

    // XXX: Ensure that evm and internals go out of scope before the await point
    // below.
    let raw_validators = {
        let mut evm = node
            .evm_config
            .evm_for_block(db, block.header())
            .wrap_err("failed instantiating evm for block")?;

        let ctx = evm.ctx_mut();
        let internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
        let mut provider = EvmPrecompileStorageProvider::new_max_gas(internals, &ctx.cfg);

        let mut validator_config = ValidatorConfig::new(&mut provider);
        validator_config
            .get_validators(IValidatorConfig::getValidatorsCall {})
            .wrap_err("failed to query contract for validator config")?
    };

    info!(
        latest_block_number,
        ?raw_validators,
        "read validators from contract at latest block",
    );

    Ok(decode_from_contract(raw_validators).await)
}

/// Attempts to decode a single validator from the values read in the smart contract.
#[instrument(ret(Display, level = Level::INFO), err(level = Level::WARN))]
fn decode_validator_from_contract(
    IValidatorConfig::Validator {
        publicKey,
        active,
        index,
        validatorAddress,
        inboundAddress,
        outboundAddress,
        ..
    }: IValidatorConfig::Validator,
) -> eyre::Result<DecodedValidator> {
    ensure!(
        active,
        "field `active` is set to false; this method should only be called \
        for active validators"
    );
    let public_key = PublicKey::decode(publicKey.as_ref())
        .wrap_err("failed decoding publicKey field as ed25519 public key")?;
    Ok(DecodedValidator {
        public_key,
        inbound: inboundAddress,
        outbound: outboundAddress,
        index,
        address: validatorAddress,
    })
}

/// Returns a validator state with only public key and inbound address set.
///
/// All other values take default values.
pub(super) fn validator_state_with_unknown_contract_state(
    validators: OrderedAssociated<PublicKey, SocketAddr>,
) -> ValidatorState {
    let validators = validators
        .iter_pairs()
        .map(|(key, addr): (&PublicKey, &SocketAddr)| {
            let key = key.clone();
            let validator = DecodedValidator {
                public_key: key.clone(),
                inbound: addr.to_string(),
                outbound: String::new(),
                index: 0,
                address: Address::ZERO,
            };
            (key, validator)
        })
        .collect();
    ValidatorState::new(validators)
}

fn last_height_before_epoch(epoch: Epoch, epoch_length: u64) -> u64 {
    epoch
        .checked_sub(1)
        .map_or(0, |epoch| utils::last_block_in_epoch(epoch_length, epoch))
}

#[cfg(test)]
mod tests {
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::{PrivateKeyExt, Signer, ed25519::PrivateKey};
    use tempo_dkg_onchain_artifacts::DecodedValidator;

    #[test]
    fn roundtrip_decoded_validator() {
        let private_key = PrivateKey::from_seed(42);
        let decoded_validator = DecodedValidator {
            public_key: private_key.public_key(),
            inbound: "localhost:1234".to_string(),
            outbound: "127.0.0.1:4321".to_string(),
            index: 42,
            address: alloy_primitives::Address::ZERO,
        };
        assert_eq!(
            decoded_validator,
            DecodedValidator::decode(&mut decoded_validator.encode().freeze()).unwrap()
        );
    }
}
