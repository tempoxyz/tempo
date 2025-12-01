use std::future::Future;

use super::Tx;
use crate::dkg::HardforkRegime;
use commonware_codec::{EncodeSize, Read, Write};
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
    fn get_epoch<S>(
        &mut self,
        regime: HardforkRegime,
    ) -> impl Future<Output = Result<Option<S>>> + Send
    where
        S: Read<Cfg = ()>;

    /// Set the current epoch state for the given hardfork regime.
    fn set_epoch<S>(&mut self, regime: HardforkRegime, state: S) -> Result<()>
    where
        S: Write + EncodeSize;

    /// Get the previous epoch state for the given hardfork regime.
    fn get_previous_epoch<S>(
        &mut self,
        regime: HardforkRegime,
    ) -> impl Future<Output = Result<Option<S>>> + Send
    where
        S: Read<Cfg = ()>;

    /// Set the previous epoch state for the given hardfork regime.
    fn set_previous_epoch<S>(&mut self, regime: HardforkRegime, state: S) -> Result<()>
    where
        S: Write + EncodeSize;

    /// Remove the previous epoch state for the given hardfork regime.
    fn remove_previous_epoch(&mut self, regime: HardforkRegime);
}

impl<TContext> DkgEpochStore<TContext> for Tx<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    async fn get_epoch<S>(&mut self, regime: HardforkRegime) -> Result<Option<S>>
    where
        S: Read<Cfg = ()>,
    {
        self.get(current_epoch_key(regime)).await
    }

    fn set_epoch<S>(&mut self, regime: HardforkRegime, state: S) -> Result<()>
    where
        S: Write + EncodeSize,
    {
        self.insert(current_epoch_key(regime), state)
    }

    async fn get_previous_epoch<S>(&mut self, regime: HardforkRegime) -> Result<Option<S>>
    where
        S: Read<Cfg = ()>,
    {
        self.get(previous_epoch_key(regime)).await
    }

    fn set_previous_epoch<S>(&mut self, regime: HardforkRegime, state: S) -> Result<()>
    where
        S: Write + EncodeSize,
    {
        self.insert(previous_epoch_key(regime), state)
    }

    fn remove_previous_epoch(&mut self, regime: HardforkRegime) {
        self.remove(previous_epoch_key(regime))
    }
}
