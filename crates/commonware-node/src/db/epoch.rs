use super::Tx;
use crate::dkg::EpochState;
use commonware_runtime::{Clock, Metrics, Storage};
use eyre::Result;

const CURRENT_EPOCH_KEY: &str = "current_epoch";
const PREVIOUS_EPOCH_KEY: &str = "previous_epoch";

/// Trait for epoch-related database operations.
pub trait DkgEpochStore<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    /// Get the current epoch state.
    fn get_epoch(&mut self) -> Result<Option<EpochState>>;

    /// Set the current epoch state.
    fn set_epoch(&mut self, state: EpochState) -> Result<()>;

    /// Get the previous epoch state.
    fn get_previous_epoch(&mut self) -> Result<Option<EpochState>>;

    /// Set the previous epoch state.
    fn set_previous_epoch(&mut self, state: EpochState) -> Result<()>;

    /// Remove the previous epoch state.
    fn remove_previous_epoch(&mut self) -> Result<()>;
}

impl<TContext> DkgEpochStore<TContext> for Tx<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    fn get_epoch(&mut self) -> Result<Option<EpochState>> {
        self.get(CURRENT_EPOCH_KEY)
    }

    fn set_epoch(&mut self, state: EpochState) -> Result<()> {
        self.insert(CURRENT_EPOCH_KEY, state)
    }

    fn get_previous_epoch(&mut self) -> Result<Option<EpochState>> {
        self.get(PREVIOUS_EPOCH_KEY)
    }

    fn set_previous_epoch(&mut self, state: EpochState) -> Result<()> {
        self.insert(PREVIOUS_EPOCH_KEY, state)
    }

    fn remove_previous_epoch(&mut self) -> Result<()> {
        self.remove(PREVIOUS_EPOCH_KEY)
    }
}
