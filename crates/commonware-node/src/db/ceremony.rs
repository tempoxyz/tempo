use std::future::Future;

use super::Tx;
use crate::dkg::ceremony;
use commonware_runtime::{Clock, Metrics, Storage};
use eyre::Result;

fn ceremony_key(epoch: u64) -> String {
    format!("ceremony_{epoch}")
}

/// Trait for ceremony-related database operations.
pub trait CeremonyStore<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    /// Get ceremony state for a specific epoch.
    fn get_ceremony(
        &self,
        epoch: u64,
    ) -> impl Future<Output = Result<Option<ceremony::State>>> + Send;

    /// Set ceremony state for a specific epoch.
    fn set_ceremony(&mut self, epoch: u64, state: ceremony::State);

    /// Remove ceremony state for a specific epoch.
    fn remove_ceremony(&mut self, epoch: u64);

    /// Update ceremony state for a specific epoch using a closure.
    ///
    /// This reads the current state (or creates a default if none exists),
    fn update_ceremony<F>(&mut self, epoch: u64, f: F) -> impl Future<Output = Result<()>> + Send
    where
        F: FnOnce(&mut ceremony::State) + Send;
}

impl<TContext> CeremonyStore<TContext> for Tx<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    async fn get_ceremony(&self, epoch: u64) -> Result<Option<ceremony::State>> {
        self.get(ceremony_key(epoch)).await
    }

    fn set_ceremony(&mut self, epoch: u64, state: ceremony::State) {
        self.insert(ceremony_key(epoch), state)
    }

    fn remove_ceremony(&mut self, epoch: u64) {
        self.remove(ceremony_key(epoch))
    }

    async fn update_ceremony<F>(&mut self, epoch: u64, f: F) -> Result<()>
    where
        F: FnOnce(&mut ceremony::State) + Send,
    {
        let mut state = self.get_ceremony(epoch).await?.unwrap_or_default();
        f(&mut state);
        self.set_ceremony(epoch, state);
        Ok(())
    }
}
