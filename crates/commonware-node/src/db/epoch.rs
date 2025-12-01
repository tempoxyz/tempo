use std::future::Future;

use super::Tx;
use crate::dkg::HardforkRegime;
use commonware_codec::{EncodeSize, Read, Write};
use commonware_runtime::{Clock, Metrics, Storage};
use eyre::Result;

const PRE_ALLEGRETTO_EPOCH_KEY: &str = "pre_allegretto_epoch";
const POST_ALLEGRETTO_EPOCH_KEY: &str = "post_allegretto_epoch";

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
}

impl<TContext> DkgEpochStore<TContext> for Tx<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    async fn get_epoch<S>(&mut self, regime: HardforkRegime) -> Result<Option<S>>
    where
        S: Read<Cfg = ()>,
    {
        let key = match regime {
            HardforkRegime::PreAllegretto => PRE_ALLEGRETTO_EPOCH_KEY,
            HardforkRegime::PostAllegretto => POST_ALLEGRETTO_EPOCH_KEY,
        };
        self.get(key).await
    }

    fn set_epoch<S>(&mut self, regime: HardforkRegime, state: S) -> Result<()>
    where
        S: Write + EncodeSize,
    {
        let key = match regime {
            HardforkRegime::PreAllegretto => PRE_ALLEGRETTO_EPOCH_KEY,
            HardforkRegime::PostAllegretto => POST_ALLEGRETTO_EPOCH_KEY,
        };
        self.insert(key, state)
    }
}
