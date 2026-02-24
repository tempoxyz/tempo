pub(super) use crate::validators::read_from_contract_at_height;

use commonware_consensus::types::Height;
use eyre::WrapErr as _;
use tempo_node::TempoFullNode;
use tracing::{Level, instrument};

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
pub(super) fn read_next_full_dkg_ceremony(
    node: &TempoFullNode,
    at_height: Height,
) -> eyre::Result<u64> {
    crate::validators::read_validator_config_at_height(node, at_height, |config| {
        config
            .get_next_full_dkg_ceremony()
            .wrap_err("failed to query contract for next full dkg ceremony")
    })
}
