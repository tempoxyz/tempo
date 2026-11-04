//! Builds a boundary block's DKG outcome. Before TIP-1123, part of it comes
//! from the post-state of the boundary block's parent.

use std::sync::Arc;

use commonware_consensus::{
    Heightable as _,
    types::{Epocher as _, FixedEpocher, Height},
};
use commonware_cryptography::{
    bls12381::{dkg::feldman_desmedt::Output, primitives::variant::MinSig},
    ed25519::PublicKey,
};
use commonware_utils::ordered;
use eyre::{Report, WrapErr as _};
use reth_provider::StateProvider as _;
use tempo_dkg_onchain_artifacts::{DkgCeremony, OnchainDkgOutcome, OutcomeEncoding};
use tempo_node::{ExecutedState, TempoFullNode};
use tempo_precompiles::validator_config_v2::ValidatorConfigV2;
use tracing::{Level, debug, info, instrument};

use crate::{
    consensus::block::Block,
    validators::{read_active_peers, read_validator_config_with_state},
};

/// Reads the post-state of a boundary block's parent through
/// [`ExecutedState`], so a parent on a fork that is not canonical has its
/// state too. The reads fail until the engine has executed the parent.
#[derive(Clone)]
pub(crate) struct TempoParentState {
    pub(crate) node: Arc<TempoFullNode>,
    pub(crate) executed_state: ExecutedState,
}

impl TempoParentState {
    /// Returns the DKG outcome with `encoding` of a boundary block on top of
    /// `parent`, made from the ceremony `output`.
    ///
    /// A legacy outcome also carries the next ceremony, read from the
    /// post-state of `parent`: call this only after the engine has executed
    /// `parent`, before that the state reads fail. A TIP-1123 outcome reads no
    /// state.
    pub(super) fn boundary_outcome(
        &self,
        epoch_strategy: &FixedEpocher,
        parent: &Block,
        output: Output<MinSig, PublicKey>,
        encoding: OutcomeEncoding,
    ) -> eyre::Result<OnchainDkgOutcome> {
        let outcome =
            assemble_boundary_outcome(epoch_strategy, parent.height(), output, encoding, || {
                let next_full_dkg_epoch = self
                    .next_full_dkg_epoch(parent)
                    .wrap_err("could not determine the next full DKG epoch")?;
                let next_players = self
                    .next_players(parent)
                    .wrap_err("could not determine who the next players are supposed to be")?;
                Ok((next_players, next_full_dkg_epoch))
            })?;
        if let Some(ceremony) = &outcome.next_ceremony {
            info!(
                ceremony.is_full_dkg,
                next_epoch = %outcome.epoch(),
                "determined if the next epoch will be a reshare or full re-dkg process",
            );
        }
        Ok(outcome)
    }

    /// Returns the validators that are active in the validator config at
    /// `parent`. They are the players of the ceremony in the next epoch.
    #[instrument(
        skip_all,
        fields(parent.height = %parent.height()),
        err(level = Level::WARN),
    )]
    fn next_players(&self, parent: &Block) -> eyre::Result<ordered::Set<PublicKey>> {
        let next_players = self
            .read_validator_config(parent, read_active_peers)
            .wrap_err("failed reading peers from validator config v2")?
            .into_keys();

        debug!(?next_players, "determined next players");
        Ok(next_players)
    }

    /// Returns the epoch of the next full DKG ceremony, as the validator
    /// config at `parent` schedules it. In all other epochs, the ceremony
    /// reshares the current polynomial.
    #[instrument(
        skip_all,
        fields(parent.height = %parent.height()),
        err(level = Level::WARN),
        ret
    )]
    fn next_full_dkg_epoch(&self, parent: &Block) -> eyre::Result<u64> {
        self.read_validator_config(parent, |config| {
            config
                .get_next_network_identity_rotation_epoch()
                .map_err(Report::new)
        })
    }

    fn read_validator_config<T>(
        &self,
        parent: &Block,
        read_fn: impl FnOnce(&ValidatorConfigV2) -> eyre::Result<T>,
    ) -> eyre::Result<T> {
        let state = self
            .executed_state
            .state_by_block_hash(self.node.provider.clone(), parent.digest().0)?;
        read_validator_config_with_state(
            self.node.as_ref(),
            Box::new(state.into_evm_state_provider()),
            parent.header(),
            read_fn,
        )
    }
}

/// Returns the DKG outcome with `encoding` of a boundary block whose parent
/// is at `parent_height`. The outcome is for the epoch after the parent's
/// epoch.
///
/// Only a legacy outcome calls `read_parent_state`, for the next players and
/// the epoch of the next full DKG.
fn assemble_boundary_outcome(
    epoch_strategy: &FixedEpocher,
    parent_height: Height,
    output: Output<MinSig, PublicKey>,
    encoding: OutcomeEncoding,
    read_parent_state: impl FnOnce() -> eyre::Result<(ordered::Set<PublicKey>, u64)>,
) -> eyre::Result<OnchainDkgOutcome> {
    let next_epoch = epoch_strategy
        .containing(parent_height)
        .expect("epoch strategy is for all heights")
        .epoch()
        .next();

    let next_ceremony = match encoding {
        OutcomeEncoding::Legacy => {
            let (players, next_full_dkg_epoch) = read_parent_state()?;
            Some(DkgCeremony {
                players,
                is_full_dkg: next_full_dkg_epoch == next_epoch.get(),
            })
        }
        OutcomeEncoding::CeremonyInState => None,
    };

    Ok(OnchainDkgOutcome {
        epoch: next_epoch.get(),
        output,
        next_ceremony,
    })
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use commonware_consensus::types::Epoch;
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use commonware_utils::TryFromIterator as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::test_utils::dkg_fixture;

    #[test]
    fn boundary_outcome_is_for_the_next_epoch_and_uses_the_parent_state() {
        let epoch_strategy = FixedEpocher::new(NonZeroU64::new(10).unwrap());
        let output = dkg_fixture(&mut StdRng::seed_from_u64(0), Epoch::new(2))
            .outcome
            .output;
        let next_players = ordered::Set::try_from_iter(
            (10..13).map(|seed| PrivateKey::from_seed(seed).public_key()),
        )
        .unwrap();

        // With an epoch length of 10, height 18 is the parent of the boundary
        // block of epoch 1.
        for (next_full_dkg_epoch, is_full_dkg) in [(2, true), (1, false), (3, false)] {
            assert_eq!(
                assemble_boundary_outcome(
                    &epoch_strategy,
                    Height::new(18),
                    output.clone(),
                    OutcomeEncoding::Legacy,
                    || Ok((next_players.clone(), next_full_dkg_epoch)),
                )
                .unwrap(),
                OnchainDkgOutcome {
                    epoch: 2,
                    output: output.clone(),
                    next_ceremony: Some(DkgCeremony {
                        players: next_players.clone(),
                        is_full_dkg,
                    }),
                },
                "full DKG scheduled for epoch {next_full_dkg_epoch}",
            );
        }
    }

    #[test]
    fn ceremony_in_state_boundary_outcome_reads_no_parent_state() {
        let epoch_strategy = FixedEpocher::new(NonZeroU64::new(10).unwrap());
        let output = dkg_fixture(&mut StdRng::seed_from_u64(0), Epoch::new(2))
            .outcome
            .output;

        let outcome = assemble_boundary_outcome(
            &epoch_strategy,
            Height::new(18),
            output.clone(),
            OutcomeEncoding::CeremonyInState,
            || panic!("a TIP-1123 outcome must not read the parent state"),
        )
        .unwrap();
        assert_eq!(
            outcome,
            OnchainDkgOutcome {
                epoch: 2,
                output,
                next_ceremony: None,
            },
        );
        assert_eq!(outcome.encoding(), OutcomeEncoding::CeremonyInState);
    }

    #[test]
    fn legacy_boundary_outcome_fails_when_parent_state_is_unavailable() {
        let epoch_strategy = FixedEpocher::new(NonZeroU64::new(10).unwrap());
        let output = dkg_fixture(&mut StdRng::seed_from_u64(0), Epoch::new(2))
            .outcome
            .output;

        let error = assemble_boundary_outcome(
            &epoch_strategy,
            Height::new(18),
            output,
            OutcomeEncoding::Legacy,
            || Err(eyre::eyre!("parent not executed")),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "parent not executed");
    }
}
