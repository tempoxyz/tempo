use std::future::Future;

use super::Tx;
use crate::dkg::manager::{
    DkgOutcome,
    actor::{post_allegretto, pre_allegretto},
};
use commonware_runtime::{Clock, Metrics, Storage};
use eyre::Result;
use tempo_dkg_onchain_artifacts::PublicOutcome;

const DKG_OUTCOME_KEY: &str = "dkg_outcome";

/// Trait for DKG outcome database operations.
pub trait DkgOutcomeStore<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    /// Get the current DKG outcome.
    fn get_dkg_outcome(&mut self) -> impl Future<Output = Result<Option<DkgOutcome>>> + Send;

    /// Set the current DKG outcome.
    fn set_dkg_outcome(&mut self, outcome: DkgOutcome) -> Result<()>;

    /// Remove the current DKG outcome.
    fn remove_dkg_outcome(&mut self);

    /// Get the public outcome, checking post-allegretto first, then pre-allegretto.
    ///
    /// For post-allegretto, this checks `dkg_outcome` first, then falls back to
    /// the epoch state. For pre-allegretto, it reads from the epoch state directly.
    fn get_public_outcome(&mut self) -> impl Future<Output = Result<Option<PublicOutcome>>> + Send;
}

impl<TContext> DkgOutcomeStore<TContext> for Tx<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    async fn get_dkg_outcome(&mut self) -> Result<Option<DkgOutcome>> {
        self.get(DKG_OUTCOME_KEY).await
    }

    fn set_dkg_outcome(&mut self, outcome: DkgOutcome) -> Result<()> {
        self.insert(DKG_OUTCOME_KEY, outcome)
    }

    fn remove_dkg_outcome(&mut self) {
        self.remove(DKG_OUTCOME_KEY)
    }

    async fn get_public_outcome(&mut self) -> Result<Option<PublicOutcome>> {
        if let Some(dkg_outcome) = self.get_dkg_outcome().await? {
            return Ok(Some(PublicOutcome {
                epoch: dkg_outcome.epoch,
                participants: dkg_outcome.participants,
                public: dkg_outcome.public,
            }));
        }

        if let Some(epoch_state) = self.get_epoch::<post_allegretto::EpochState>().await? {
            return Ok(Some(PublicOutcome {
                epoch: epoch_state.dkg_outcome.epoch,
                participants: epoch_state.dkg_outcome.participants,
                public: epoch_state.dkg_outcome.public,
            }));
        }

        if let Some(epoch_state) = self.get_epoch::<pre_allegretto::EpochState>().await? {
            return Ok(Some(PublicOutcome {
                epoch: epoch_state.epoch,
                participants: epoch_state.participants,
                public: epoch_state.public,
            }));
        }

        Ok(None)
    }
}
