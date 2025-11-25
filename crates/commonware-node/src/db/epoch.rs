use std::future::Future;

use super::Tx;
use crate::dkg::EpochState;
use commonware_runtime::{Clock, Metrics, Storage};
use eyre::Result;

const CURRENT_EPOCH_KEY: &str = "dkg_epoch_store_current";
const PREVIOUS_EPOCH_KEY: &str = "dkg_epoch_store_previous";

/// Trait for epoch-related database operations.
pub trait DkgEpochStore<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    /// Get the current epoch state.
    fn get_epoch(&mut self) -> impl Future<Output = Result<Option<EpochState>>> + Send;

    /// Set the current epoch state.
    fn set_epoch(&mut self, state: EpochState) -> Result<()>;

    /// Get the previous epoch state.
    fn get_previous_epoch(&mut self) -> impl Future<Output = Result<Option<EpochState>>> + Send;

    /// Set the previous epoch state.
    fn set_previous_epoch(&mut self, state: EpochState) -> Result<()>;

    /// Remove the previous epoch state.
    fn remove_previous_epoch(&mut self);
}

impl<TContext> DkgEpochStore<TContext> for Tx<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    async fn get_epoch(&mut self) -> Result<Option<EpochState>> {
        self.get(CURRENT_EPOCH_KEY).await
    }

    fn set_epoch(&mut self, state: EpochState) -> Result<()> {
        self.insert(CURRENT_EPOCH_KEY, state)
    }

    async fn get_previous_epoch(&mut self) -> Result<Option<EpochState>> {
        self.get(PREVIOUS_EPOCH_KEY).await
    }

    fn set_previous_epoch(&mut self, state: EpochState) -> Result<()> {
        self.insert(PREVIOUS_EPOCH_KEY, state)
    }

    fn remove_previous_epoch(&mut self) {
        self.remove(PREVIOUS_EPOCH_KEY)
    }
}
