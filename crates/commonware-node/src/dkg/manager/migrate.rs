use commonware_codec::EncodeSize;
use commonware_runtime::{Clock, ContextCell, Metrics, Storage};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::sequence::U64;
use eyre::Result;
use tracing::{info, instrument};

use crate::{
    db::ReadWriteTransaction,
    dkg::{
        ceremony,
        manager::{
            DkgOutcome,
            actor::{post_allegretto, pre_allegretto},
            validators::ValidatorState,
        },
    },
};

const CURRENT_EPOCH_KEY: U64 = U64::new(0);
const PREVIOUS_EPOCH_KEY: U64 = U64::new(1);
const DKG_OUTCOME_KEY: U64 = U64::new(0);

/// Helper to initialize a metadata store for migration.
async fn init_metadata<TContext, V>(
    context: &ContextCell<TContext>,
    label: &str,
    partition: String,
) -> Metadata<ContextCell<TContext>, U64, V>
where
    TContext: Clock + Metrics + Storage,
    V: commonware_codec::Read<Cfg = ()> + commonware_codec::Write + EncodeSize,
{
    Metadata::init(
        context.with_label(label),
        metadata::Config {
            partition,
            codec_config: (),
        },
    )
    .await
    .expect("must be able to initialize metadata on disk to function")
}

/// Migrate data from the old metadata stores to the new unified database.
///
/// This function checks if migration has already been performed by checking for
/// an existing node version. If a version exists, it returns early without migrating.
///
/// This function migrates the following old metadata stores:
/// 1. `{prefix}_ceremony` - ceremony state per epoch
/// 2. `{prefix}_current_epoch` - pre-allegretto epoch state (current/previous)
/// 3. `{prefix}_post_allegretto_current_epoch` - post-allegretto epoch state (current/previous)
/// 4. `{prefix}_next_dkg_outcome` - DKG outcome
/// 5. `{prefix}_validators` - validator state per epoch
///
/// The caller is responsible for setting the version and committing the transaction.
#[instrument(skip_all, err)]
pub(super) async fn maybe_migrate_to_db<TContext>(
    context: &ContextCell<TContext>,
    partition_prefix: &str,
    tx: &mut ReadWriteTransaction<ContextCell<TContext>>,
) -> Result<()>
where
    TContext: Clock + Metrics + Storage,
{
    // Check if already migrated
    if tx.get_node_version().await?.is_some() {
        return Ok(());
    }

    info!("migrating old metadata stores to unified database");

    let current_epoch = get_current_epoch_for_migration(context, partition_prefix).await;

    migrate_ceremony_metadata(context, partition_prefix, tx, current_epoch).await?;
    migrate_pre_allegretto_epoch_metadata(context, partition_prefix, tx).await?;
    migrate_post_allegretto_epoch_metadata(context, partition_prefix, tx).await?;
    migrate_dkg_outcome_metadata(context, partition_prefix, tx).await?;
    migrate_validators_metadata(context, partition_prefix, tx, current_epoch).await?;

    info!("migration completed");

    Ok(())
}

/// Determines the current epoch from existing metadata stores for bounding migration.
async fn get_current_epoch_for_migration<TContext>(
    context: &ContextCell<TContext>,
    partition_prefix: &str,
) -> Option<u64>
where
    TContext: Clock + Metrics + Storage,
{
    let post_metadata: Metadata<ContextCell<TContext>, U64, post_allegretto::EpochState> =
        init_metadata(
            context,
            "post_allegretto_epoch_metadata",
            format!("{partition_prefix}_post_allegretto_current_epoch"),
        )
        .await;

    if let Some(state) = post_metadata.get(&CURRENT_EPOCH_KEY) {
        return Some(state.epoch());
    }

    let pre_metadata: Metadata<ContextCell<TContext>, U64, pre_allegretto::EpochState> =
        init_metadata(
            context,
            "post_allegretto_epoch_metadata",
            format!("{partition_prefix}_current_epoch"),
        )
        .await;

    pre_metadata.get(&CURRENT_EPOCH_KEY).map(|s| s.epoch)
}

async fn migrate_ceremony_metadata<TContext>(
    context: &ContextCell<TContext>,
    partition_prefix: &str,
    tx: &mut ReadWriteTransaction<ContextCell<TContext>>,
    current_epoch: Option<u64>,
) -> Result<()>
where
    TContext: Clock + Metrics + Storage,
{
    let ceremony_metadata: Metadata<ContextCell<TContext>, U64, ceremony::State> = init_metadata(
        context,
        "ceremony_metadata",
        format!("{partition_prefix}_ceremony"),
    )
    .await;

    // Ceremonies are pruned after ~2 epochs, so only recent ones exist.
    if let Some(current) = current_epoch {
        for epoch in current.saturating_sub(2)..=current {
            if let Some(state) = ceremony_metadata.get(&U64::from(epoch)) {
                info!(epoch, "migrating ceremony state");
                tx.set_ceremony(epoch, state.clone());
            }
        }
    }

    Ok(())
}

async fn migrate_pre_allegretto_epoch_metadata<TContext>(
    context: &ContextCell<TContext>,
    partition_prefix: &str,
    tx: &mut ReadWriteTransaction<ContextCell<TContext>>,
) -> Result<()>
where
    TContext: Clock + Metrics + Storage,
{
    let epoch_metadata: Metadata<ContextCell<TContext>, U64, pre_allegretto::EpochState> =
        init_metadata(
            context,
            "post_allegretto_epoch_metadata",
            format!("{partition_prefix}_current_epoch"),
        )
        .await;

    migrate_epoch_states(&epoch_metadata, tx, |s| s.epoch)?;

    Ok(())
}

async fn migrate_post_allegretto_epoch_metadata<TContext>(
    context: &ContextCell<TContext>,
    partition_prefix: &str,
    tx: &mut ReadWriteTransaction<ContextCell<TContext>>,
) -> Result<()>
where
    TContext: Clock + Metrics + Storage,
{
    let epoch_metadata: Metadata<ContextCell<TContext>, U64, post_allegretto::EpochState> =
        init_metadata(
            context,
            "post_allegretto_epoch_metadata",
            format!("{partition_prefix}_post_allegretto_current_epoch"),
        )
        .await;

    migrate_epoch_states(&epoch_metadata, tx, |s| s.epoch())?;

    Ok(())
}

/// Helper to migrate current and previous epoch states for a given regime.
fn migrate_epoch_states<TContext, E>(
    epoch_metadata: &Metadata<ContextCell<TContext>, U64, E>,
    tx: &mut ReadWriteTransaction<ContextCell<TContext>>,
    get_epoch: impl Fn(&E) -> u64,
) -> Result<()>
where
    TContext: Clock + Metrics + Storage,
    E: Clone + crate::dkg::RegimeEpochState,
{
    if let Some(current_epoch) = epoch_metadata.get(&CURRENT_EPOCH_KEY) {
        info!(
            epoch = get_epoch(current_epoch),
            regime = ?E::REGIME,
            "migrating current epoch state"
        );
        tx.set_epoch(current_epoch.clone());
    }

    if let Some(previous_epoch) = epoch_metadata.get(&PREVIOUS_EPOCH_KEY) {
        info!(
            epoch = get_epoch(previous_epoch),
            regime = ?E::REGIME,
            "migrating previous epoch state"
        );
        tx.set_previous_epoch(previous_epoch.clone());
    }

    Ok(())
}

async fn migrate_dkg_outcome_metadata<TContext>(
    context: &ContextCell<TContext>,
    partition_prefix: &str,
    tx: &mut ReadWriteTransaction<ContextCell<TContext>>,
) -> Result<()>
where
    TContext: Clock + Metrics + Storage,
{
    let dkg_outcome_metadata: Metadata<ContextCell<TContext>, U64, DkgOutcome> = init_metadata(
        context,
        "dkg_outcome_metadata",
        format!("{partition_prefix}_next_dkg_outcome"),
    )
    .await;

    if let Some(outcome) = dkg_outcome_metadata.get(&DKG_OUTCOME_KEY) {
        info!(epoch = outcome.epoch, "migrating DKG outcome");
        tx.set_dkg_outcome(outcome.clone());
    }

    Ok(())
}

async fn migrate_validators_metadata<TContext>(
    context: &ContextCell<TContext>,
    partition_prefix: &str,
    tx: &mut ReadWriteTransaction<ContextCell<TContext>>,
    current_epoch: Option<u64>,
) -> Result<()>
where
    TContext: Clock + Metrics + Storage,
{
    let validators_metadata: Metadata<ContextCell<TContext>, U64, ValidatorState> = init_metadata(
        context,
        "validators__metadata",
        format!("{partition_prefix}_validators"),
    )
    .await;

    // Validators are tracked for current and last 2-3 epochs.
    if let Some(current) = current_epoch {
        for epoch in current.saturating_sub(3)..=current {
            if let Some(state) = validators_metadata.get(&U64::from(epoch)) {
                info!(epoch, "migrating validators state");
                tx.set_validators(epoch, state.clone());
            }
        }
    }

    Ok(())
}
