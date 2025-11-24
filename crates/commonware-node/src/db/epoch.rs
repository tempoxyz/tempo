use super::Tx;
use crate::dkg::EpochState;
use commonware_runtime::{Clock, Metrics, Storage};
use eyre::Result;

const EPOCH_KEY: &str = "epoch";

/// Trait for epoch-related database operations.
pub trait DkgEpochStore<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    /// Get the current epoch state.
    fn get_epoch(&mut self) -> Result<Option<EpochState>>;

    /// Set the current epoch state.
    fn set_epoch(&mut self, state: EpochState) -> Result<()>;
}

impl<TContext> DkgEpochStore<TContext> for Tx<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    fn get_epoch(&mut self) -> Result<Option<EpochState>> {
        self.get(&EPOCH_KEY)
    }

    fn set_epoch(&mut self, state: EpochState) -> Result<()> {
        self.insert(EPOCH_KEY, state)
    }
}
