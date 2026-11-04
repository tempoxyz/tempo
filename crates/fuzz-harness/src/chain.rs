//! The chain blocks execute on, and the headers they execute with.

use alloy_consensus::{Header, constants::EMPTY_ROOT_HASH};
use alloy_eips::eip7685::EMPTY_REQUESTS_HASH;
use alloy_primitives::B256;
use reth_chainspec::ForkCondition;
use tempo_chainspec::{
    TempoChainSpec,
    hardfork::{TempoHardfork, TempoHardforks},
};
use tempo_fuzz_types::{BlockContextInput, BlockHeaderInput, ChainSpecInput, ErrorClass};
use tempo_primitives::TempoHeader;

/// The dev chain spec with `input`'s chain ID and hardfork schedule, as [`ChainSpecInput`]
/// describes.
pub(crate) fn chain_spec(input: &ChainSpecInput) -> Result<TempoChainSpec, ErrorClass> {
    let mut spec = tempo_chainspec::spec::DEV.as_ref().clone();
    spec.inner.chain = input.chain_id.into();
    let mut previous = 0;
    for &fork in TempoHardfork::VARIANTS {
        let activation = match input.hardforks.get(&fork) {
            // Only a listed activation can go back in time.
            Some(&activation) if activation < previous => return Err(ErrorClass::InvalidInput),
            Some(&activation) => activation,
            None => previous.max(u64::from(fork.variant_index())),
        };
        spec.inner
            .hardforks
            .insert(fork, ForkCondition::Timestamp(activation));
        previous = activation;
    }
    Ok(spec)
}

/// The header `input` describes. A context header has no transactions root yet: the block that
/// holds the transactions computes it.
pub(crate) fn header(
    spec: &TempoChainSpec,
    input: &BlockHeaderInput,
) -> Result<TempoHeader, ErrorClass> {
    match input {
        BlockHeaderInput::Rlp(rlp) => {
            alloy_rlp::decode_exact(rlp).map_err(|_| ErrorClass::RlpDecode)
        }
        BlockHeaderInput::Context(context) => Ok(context_header(spec, context)),
    }
}

/// A header at the latest timestamp no earlier than `context.timestamp` where `context.hardfork` is
/// active. Hardforks that share its activation are active too.
fn context_header(spec: &TempoChainSpec, context: &BlockContextInput) -> TempoHeader {
    let activation = |fork| {
        spec.tempo_fork_activation(fork)
            .as_timestamp()
            .expect("the harness schedules every hardfork by timestamp")
    };
    let start = activation(context.hardfork);
    let end = TempoHardfork::VARIANTS
        .iter()
        .copied()
        .map(activation)
        .filter(|timestamp| *timestamp > start)
        .min();
    let timestamp = context.timestamp.max(start);
    let timestamp = end.map_or(timestamp, |end| timestamp.min(end - 1));

    let shared_gas_limit = spec.shared_gas_limit_at(timestamp, context.gas_limit);
    TempoHeader {
        general_gas_limit: spec.general_gas_limit_at(
            timestamp,
            context.gas_limit,
            shared_gas_limit,
        ),
        shared_gas_limit,
        timestamp_millis_part: context.timestamp_millis_part,
        inner: Header {
            number: context.block_number,
            timestamp,
            gas_limit: context.gas_limit,
            base_fee_per_gas: Some(context.basefee),
            beneficiary: context.beneficiary,
            parent_beacon_block_root: Some(B256::ZERO),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            requests_hash: Some(EMPTY_REQUESTS_HASH),
            extra_data: context.extra_data.clone(),
            ..Default::default()
        },
        consensus_context: None,
    }
}
