use std::future::Future;

use super::Tx;
use crate::dkg::manager::ValidatorState;
use commonware_runtime::{Clock, Metrics, Storage};
use eyre::Result;

fn validators_key(epoch: u64) -> String {
    format!("validators_{epoch}")
}

/// Trait for validators-related database operations.
pub trait ValidatorsStore<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    /// Get validators state for a specific epoch.
    fn get_validators(
        &self,
        epoch: u64,
    ) -> impl Future<Output = Result<Option<ValidatorState>>> + Send;

    /// Set validators state for a specific epoch.
    fn set_validators(&mut self, epoch: u64, state: ValidatorState);

    /// Remove validators state for a specific epoch.
    fn remove_validators(&mut self, epoch: u64);
}

impl<TContext> ValidatorsStore<TContext> for Tx<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    async fn get_validators(&self, epoch: u64) -> Result<Option<ValidatorState>> {
        self.get(validators_key(epoch)).await
    }

    fn set_validators(&mut self, epoch: u64, state: ValidatorState) {
        self.insert(validators_key(epoch), state)
    }

    fn remove_validators(&mut self, epoch: u64) {
        self.remove(validators_key(epoch))
    }
}
