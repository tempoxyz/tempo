pub(crate) mod manager;

use alloy_consensus::BlockHeader as _;
use tempo_chainspec::TempoChainSpec;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_primitives::TempoHeader;

/// Decodes the DKG outcome in the `extra_data` of the boundary block `header`,
/// with the encoding that the boundary block's own timestamp selects (TIP-1123).
pub(crate) fn decode_boundary_outcome(
    chain_spec: &TempoChainSpec,
    header: &TempoHeader,
) -> Result<OnchainDkgOutcome, commonware_codec::Error> {
    OnchainDkgOutcome::decode_extra_data(
        header.extra_data().as_ref(),
        chain_spec.dkg_outcome_encoding_at(header.timestamp()),
    )
}
