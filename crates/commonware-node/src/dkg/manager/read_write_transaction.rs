use crate::{
    db,
    dkg::{
        ceremony,
        manager::{ValidatorState, actor},
    },
};
use commonware_runtime::{Clock, Metrics, Storage};

// Key helpers for typed storage
fn ceremony_key(epoch: u64) -> String {
    format!("ceremony_{epoch}")
}

fn validators_key(epoch: u64) -> String {
    format!("validators_{epoch}")
}

const LAST_PROCESSED_HEIGHT_KEY: &str = "last_processed_height";
const CURRENT_EPOCH_KEY: &str = "current_epoch";
const PREVIOUS_EPOCH_KEY: &str = "previous_epoch";

/// A DKG-specific transaction wrapper around the generic database transaction.
pub(crate) struct DkgReadWriteTransaction<TContext>(db::ReadWriteTransaction<TContext>)
where
    TContext: Clock + Metrics + Storage;

impl<TContext> DkgReadWriteTransaction<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    /// Create a new DKG transaction from a database transaction.
    pub(super) fn new(tx: db::ReadWriteTransaction<TContext>) -> Self {
        Self(tx)
    }

    #[expect(dead_code, reason = "unused right now, but important in the future")]
    /// Get the node version from the database.
    pub(super) async fn get_node_version(&self) -> Result<Option<String>, eyre::Error> {
        self.0.get_node_version().await
    }

    /// Set the node version in the database.
    pub(super) fn set_node_version(&mut self, version: String) {
        self.0.set_node_version(version)
    }

    /// Commit the transaction.
    pub(super) async fn commit(self) -> Result<(), eyre::Error> {
        self.0.commit().await
    }

    // ── Replay Protection ────────────────────────────────────────────────────

    /// Get the last processed block height.
    pub(super) async fn get_last_processed_height(&self) -> Result<Option<u64>, eyre::Error> {
        self.0.get(LAST_PROCESSED_HEIGHT_KEY).await
    }

    /// Set the last processed block height.
    pub(super) fn set_last_processed_height(&mut self, height: u64) {
        self.0.insert(LAST_PROCESSED_HEIGHT_KEY, height)
    }

    // ── Ceremony Store ──────────────────────────────────────────────────────

    /// Get ceremony state for a specific epoch.
    pub(in crate::dkg) async fn get_ceremony(
        &self,
        epoch: u64,
    ) -> Result<Option<ceremony::State>, eyre::Error> {
        self.0.get(ceremony_key(epoch)).await
    }

    /// Set ceremony state for a specific epoch.
    pub(in crate::dkg) fn set_ceremony(&mut self, epoch: u64, state: ceremony::State) {
        self.0.insert(ceremony_key(epoch), state)
    }

    /// Remove ceremony state for a specific epoch.
    pub(super) fn remove_ceremony(&mut self, epoch: u64) {
        self.0.remove(ceremony_key(epoch))
    }

    /// Update ceremony state for a specific epoch using a closure.
    pub(in crate::dkg) async fn update_ceremony<F>(
        &mut self,
        epoch: u64,
        f: F,
    ) -> Result<(), eyre::Error>
    where
        F: FnOnce(&mut ceremony::State) + Send,
    {
        let mut state = self.get_ceremony(epoch).await?.unwrap_or_default();
        f(&mut state);
        self.set_ceremony(epoch, state);
        Ok(())
    }

    // ── Validators Store ────────────────────────────────────────────────────

    /// Get validators state for a specific epoch.
    pub(super) async fn get_validators(
        &self,
        epoch: u64,
    ) -> Result<Option<ValidatorState>, eyre::Error> {
        self.0.get(validators_key(epoch)).await
    }

    /// Set validators state for a specific epoch.
    pub(super) fn set_validators(&mut self, epoch: u64, state: ValidatorState) {
        self.0.insert(validators_key(epoch), state)
    }

    /// Remove validators state for a specific epoch.
    pub(super) fn remove_validators(&mut self, epoch: u64) {
        self.0.remove(validators_key(epoch))
    }

    // ── DKG Epoch Store ─────────────────────────────────────────────────────

    /// Get the current epoch state for the given hardfork regime.
    pub(super) async fn get_actor_state(&self) -> Result<Option<actor::State>, eyre::Error> {
        self.0.get(CURRENT_EPOCH_KEY).await
    }

    /// Set the current epoch state for the given hardfork regime.
    pub(super) fn set_actor_state(&mut self, state: actor::State) {
        self.0.insert(CURRENT_EPOCH_KEY, state)
    }

    /// Get the previous epoch state for the given hardfork regime.
    pub(super) async fn get_previous_actor_state(
        &self,
    ) -> Result<Option<actor::State>, eyre::Error> {
        self.0.get(PREVIOUS_EPOCH_KEY).await
    }

    /// Set the previous epoch state for the given hardfork regime.
    pub(super) fn set_previous_actor_state(&mut self, state: actor::State) {
        self.0.insert(PREVIOUS_EPOCH_KEY, state)
    }

    /// Remove the previous epoch state for the given hardfork regime.
    pub(super) fn remove_previous_actor_state(&mut self) {
        self.0.remove(PREVIOUS_EPOCH_KEY)
    }

    /// Check if an epoch state exists in the database.
    pub(super) async fn has_actor_state(&self) -> bool {
        self.0.contains_key(CURRENT_EPOCH_KEY).await
    }
}
