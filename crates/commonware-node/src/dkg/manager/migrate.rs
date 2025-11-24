use commonware_runtime::{Clock, ContextCell, Metrics, Storage};
use commonware_storage::metadata::Metadata;
use commonware_utils::sequence::U64;
use eyre::Result;

use crate::{
    db::{CeremonyStore, DkgEpochStore},
    dkg::{CeremonyState, EpochState},
};

const CURRENT_EPOCH_KEY: U64 = U64::new(0);
const PREVIOUS_EPOCH_KEY: U64 = U64::new(1);

/// Migrate data from the old metadata stores to the new unified database.
///
/// This function checks if migration has already been performed by checking for
/// an existing node version. If a version exists, it returns early without migrating.
///
/// This function:
/// 1. Checks if node version exists (return early if yes)
/// 2. Initializes ceremony_metadata and epoch_metadata stores internally
/// 3. Reads the current and previous epoch states from epoch_metadata
/// 4. Reads recent ceremony states from ceremony_metadata
/// 5. Writes them to the provided transaction
///
/// The caller is responsible for setting the version and committing the transaction.
pub(super) async fn maybe_migrate_to_db<TContext>(
    context: &ContextCell<TContext>,
    partition_prefix: &str,
    tx: &mut crate::db::Tx<ContextCell<TContext>>,
) -> Result<()>
where
    TContext: Clock + Metrics + Storage,
{
    // Check if already migrated
    if tx.get_node_version()?.is_some() {
        return Ok(());
    }
    // Initialize ceremony metadata
    let ceremony_metadata: Metadata<ContextCell<TContext>, U64, CeremonyState> = Metadata::init(
        context.with_label("ceremony_metadata"),
        commonware_storage::metadata::Config {
            partition: format!("{partition_prefix}_ceremony"),
            codec_config: (),
        },
    )
    .await
    .expect("must be able to initialize metadata on disk to function");

    // Initialize epoch metadata
    let epoch_metadata: Metadata<ContextCell<TContext>, U64, EpochState> = Metadata::init(
        context.with_label("epoch_metadata"),
        commonware_storage::metadata::Config {
            partition: format!("{partition_prefix}_current_epoch"),
            codec_config: (),
        },
    )
    .await
    .expect("must be able to initialize metadata on disk to function");

    if let Some(current_epoch) = epoch_metadata.get(&CURRENT_EPOCH_KEY) {
        tx.set_epoch(current_epoch.clone())?;

        // Migrate previous epoch if it exists
        if let Some(previous_epoch) = epoch_metadata.get(&PREVIOUS_EPOCH_KEY) {
            tx.set_previous_epoch(previous_epoch.clone())?;
        }

        // Migrate ceremony states
        // Only migrate recent ceremonies since older ones are pruned
        let current_epoch_num = current_epoch.epoch;
        for offset in 0..=3 {
            if let Some(epoch) = current_epoch_num.checked_sub(offset)
                && let Some(ceremony_state) = ceremony_metadata.get(&U64::from(epoch))
            {
                tx.set_ceremony(epoch, ceremony_state.clone())?;
            }
        }
    }

    Ok(())
}
