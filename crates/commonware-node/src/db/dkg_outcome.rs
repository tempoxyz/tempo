use std::future::Future;

use super::Tx;
use crate::dkg::manager::DkgOutcome;
use commonware_runtime::{Clock, Metrics, Storage};
use eyre::Result;

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
}
