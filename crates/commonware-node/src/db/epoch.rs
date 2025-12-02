use std::future::Future;

use super::Tx;
use crate::dkg::{HardforkRegime, RegimeEpochState};
use commonware_runtime::{Clock, Metrics, Storage};
use eyre::Result;

fn current_epoch_key(regime: HardforkRegime) -> &'static str {
    match regime {
        HardforkRegime::PreAllegretto => "pre_allegretto_epoch_current",
        HardforkRegime::PostAllegretto => "post_allegretto_epoch_current",
    }
}

fn previous_epoch_key(regime: HardforkRegime) -> &'static str {
    match regime {
        HardforkRegime::PreAllegretto => "pre_allegretto_epoch_previous",
        HardforkRegime::PostAllegretto => "post_allegretto_epoch_previous",
    }
}

/// Trait for epoch-related database operations.
pub trait DkgEpochStore<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    /// Get the current epoch state for the given hardfork regime.
    fn get_epoch<S: RegimeEpochState>(&mut self) -> impl Future<Output = Result<Option<S>>> + Send;

    /// Set the current epoch state for the given hardfork regime.
    fn set_epoch<S: RegimeEpochState>(&mut self, state: S) -> Result<()>;

    /// Get the previous epoch state for the given hardfork regime.
    fn get_previous_epoch<S: RegimeEpochState>(
        &mut self,
    ) -> impl Future<Output = Result<Option<S>>> + Send;

    /// Set the previous epoch state for the given hardfork regime.
    fn set_previous_epoch<S: RegimeEpochState>(&mut self, state: S) -> Result<()>;

    /// Remove the previous epoch state for the given hardfork regime.
    fn remove_previous_epoch(&mut self, regime: HardforkRegime);

    /// Remove the current epoch state for the given hardfork regime.
    fn remove_epoch(&mut self, regime: HardforkRegime);

    /// Check if a post-allegretto epoch state exists.
    fn has_post_allegretto_state(&mut self) -> impl Future<Output = bool> + Send;

    /// Check if a pre-allegretto epoch state exists.
    fn has_pre_allegretto_state(&mut self) -> impl Future<Output = bool> + Send;
}

impl<TContext> DkgEpochStore<TContext> for Tx<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    async fn get_epoch<S: RegimeEpochState>(&mut self) -> Result<Option<S>> {
        self.get(current_epoch_key(S::REGIME)).await
    }

    fn set_epoch<S: RegimeEpochState>(&mut self, state: S) -> Result<()> {
        self.insert(current_epoch_key(S::REGIME), state)
    }

    async fn get_previous_epoch<S: RegimeEpochState>(&mut self) -> Result<Option<S>> {
        self.get(previous_epoch_key(S::REGIME)).await
    }

    fn set_previous_epoch<S: RegimeEpochState>(&mut self, state: S) -> Result<()> {
        self.insert(previous_epoch_key(S::REGIME), state)
    }

    fn remove_previous_epoch(&mut self, regime: HardforkRegime) {
        self.remove(previous_epoch_key(regime))
    }

    fn remove_epoch(&mut self, regime: HardforkRegime) {
        self.remove(current_epoch_key(regime))
    }

    async fn has_post_allegretto_state(&mut self) -> bool {
        self.exists(current_epoch_key(HardforkRegime::PostAllegretto))
            .await
    }

    async fn has_pre_allegretto_state(&mut self) -> bool {
        self.exists(current_epoch_key(HardforkRegime::PreAllegretto))
            .await
    }
}
