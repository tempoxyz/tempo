use super::Tx;
use crate::dkg::CeremonyState;
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
    fn get_ceremony(&mut self, epoch: u64) -> Result<Option<CeremonyState>>;

    /// Set ceremony state for a specific epoch.
    fn set_ceremony(&mut self, epoch: u64, state: CeremonyState) -> Result<()>;

    /// Remove ceremony state for a specific epoch.
    fn remove_ceremony(&mut self, epoch: u64) -> Result<()>;
}

impl<TContext> CeremonyStore<TContext> for Tx<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    fn get_ceremony(&mut self, epoch: u64) -> Result<Option<CeremonyState>> {
        self.get(&ceremony_key(epoch))
    }

    fn set_ceremony(&mut self, epoch: u64, state: CeremonyState) -> Result<()> {
        self.insert(ceremony_key(epoch), state)
    }

    fn remove_ceremony(&mut self, epoch: u64) -> Result<()> {
        self.remove(ceremony_key(epoch))
    }
}
