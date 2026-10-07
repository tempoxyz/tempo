//! Checker metrics and verified protocol activity logs.

use std::fmt;

use alloy_primitives::B256;
use reth_metrics::{
    Metrics,
    metrics::{Counter, Gauge},
};

use crate::{
    l1::{L1BlockEvidence, L1PortalEvent},
    l2::{
        DepositResult, L2BlockEvidence, L2BridgeAction, WithdrawalBounceBackStatus,
        WithdrawalOrigin,
    },
    persistence::{BlockRef, Snapshot, Status},
};

const ACTIVITY_SCHEMA_VERSION: u64 = 1;

mod activity_event {
    pub(super) const PORTAL_DEPOSIT_ACCOUNTED: &str = "portal_deposit_accounted";
    pub(super) const PORTAL_TOKEN_ENABLED: &str = "portal_token_enabled";
    pub(super) const PORTAL_WITHDRAWAL_PROCESSED: &str = "portal_withdrawal_processed";
    pub(super) const PORTAL_WITHDRAWAL_BOUNCE_BACK: &str = "portal_withdrawal_bounce_back";
    pub(super) const PORTAL_DEPOSIT_BOUNCE_BACK: &str = "portal_deposit_bounce_back";
    pub(super) const PORTAL_DEPOSIT_BOUNCE_BACK_PENDING: &str =
        "portal_deposit_bounce_back_pending";
    pub(super) const PORTAL_REFUND_ACCOUNTED: &str = "portal_refund_accounted";
    pub(super) const ZONE_DEPOSIT_MINTED: &str = "zone_deposit_minted";
    pub(super) const ZONE_DEPOSIT_FAILED: &str = "zone_deposit_failed";
    pub(super) const ZONE_DEPOSIT_BOUNCE_BACK_REQUESTED: &str =
        "zone_deposit_bounce_back_requested";
    pub(super) const ZONE_WITHDRAWAL_BURNED: &str = "zone_withdrawal_burned";
    pub(super) const ZONE_WITHDRAWAL_BOUNCE_BACK_MINTED: &str =
        "zone_withdrawal_bounce_back_minted";
    pub(super) const ZONE_WITHDRAWAL_BOUNCE_BACK_PENDING: &str =
        "zone_withdrawal_bounce_back_pending";
    pub(super) const ZONE_REFUND_MINTED: &str = "zone_refund_minted";
}

/// Protocol source of an activity within a verified Zone block.
#[derive(Clone, Copy)]
enum ActivitySource {
    Tempo,
    Zone,
}

impl ActivitySource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Tempo => "tempo",
            Self::Zone => "zone",
        }
    }
}

/// Coordinates shared by one structured activity log.
struct ActivityContext {
    zone: BlockRef,
    source: ActivitySource,
    index: u64,
}

impl ActivityContext {
    const fn new(zone: BlockRef, source: ActivitySource, index: u64) -> Self {
        Self {
            zone,
            source,
            index,
        }
    }

    const fn id(&self) -> ActivityId {
        ActivityId {
            zone_hash: self.zone.hash,
            source: self.source,
            index: self.index,
        }
    }
}

/// Replay-stable identifier for one activity schema version.
struct ActivityId {
    zone_hash: B256,
    source: ActivitySource,
    index: u64,
}

impl fmt::Display for ActivityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "v{ACTIVITY_SCHEMA_VERSION}:{}:{}:{}",
            self.zone_hash,
            self.source.as_str(),
            self.index
        )
    }
}

macro_rules! activity_log {
    ($context:expr, $event:expr, $($fields:tt)*) => {{
        let context = $context;
        tracing::info!(
            target: "zone::checker",
            activity_event = $event,
            activity_id = %context.id(),
            $($fields)*
        )
    }};
}

#[derive(Metrics, Clone)]
#[metrics(scope = "tempo_zone_checker")]
pub(crate) struct CheckerMetrics {
    /// Highest durably verified Zone block.
    pub(crate) verified_zone_height: Gauge,
    /// Last Tempo block accounted for by a verified full import.
    pub(crate) imported_tempo_height: Gauge,
    /// Highest Zone block delivered to the checker.
    pub(crate) observed_zone_height: Gauge,
    /// Delivered blocks not yet verified.
    pub(crate) verification_lag_blocks: Gauge,
    /// One when a deterministic finding has stopped verification.
    pub(crate) divergence_active: Gauge,
    /// One when an unrecoverable checker error has disabled verification.
    pub(crate) disabled: Gauge,
    /// Number of transient acquisition retries.
    pub(crate) acquisition_retries_total: Counter,
    /// Number of verified Zone blocks.
    pub(crate) verified_zone_blocks_total: Counter,
    /// Number of checker-state rebuilds after local history changes.
    pub(crate) recovery_rebuilds_total: Counter,
}

impl CheckerMetrics {
    /// Publish the latest durable checker state.
    pub(crate) fn update(&self, snapshot: &Snapshot) {
        let verified = snapshot.metadata.verified_zone.number;
        let observed = snapshot.metadata.observed_zone.number;
        self.verified_zone_height.set(verified as f64);
        self.imported_tempo_height
            .set(snapshot.metadata.imported_tempo.number as f64);
        self.observed_zone_height.set(observed as f64);
        self.verification_lag_blocks
            .set(observed.saturating_sub(verified) as f64);
        self.divergence_active.set(
            if matches!(&snapshot.metadata.status, Status::Diverged { .. }) {
                1.0
            } else {
                0.0
            },
        );
    }
}

/// Log authenticated protocol activity after a Zone block is verified.
pub(crate) fn log_verified_activity(tempo: &L1BlockEvidence, l2: &L2BlockEvidence, zone: BlockRef) {
    for (index, event) in (0u64..).zip(tempo.portal_events()) {
        log_tempo_event(
            event,
            &ActivityContext::new(zone, ActivitySource::Tempo, index),
        );
    }
    for (index, action) in (0u64..).zip(l2.bridge_actions()) {
        log_zone_action(
            action,
            &ActivityContext::new(zone, ActivitySource::Zone, index),
        );
    }
}

fn log_tempo_event(event: &L1PortalEvent, context: &ActivityContext) {
    match event {
        L1PortalEvent::DepositMade { .. } => {
            activity_log!(context, activity_event::PORTAL_DEPOSIT_ACCOUNTED,)
        }
        L1PortalEvent::TokenEnabled { .. } => {
            activity_log!(context, activity_event::PORTAL_TOKEN_ENABLED,)
        }
        L1PortalEvent::WithdrawalProcessed {
            callback_success, ..
        } => activity_log!(
            context,
            activity_event::PORTAL_WITHDRAWAL_PROCESSED,
            callback_success,
        ),
        L1PortalEvent::WithdrawalBounceBack { .. } => {
            activity_log!(context, activity_event::PORTAL_WITHDRAWAL_BOUNCE_BACK,)
        }
        L1PortalEvent::DepositBounceBack { .. } => {
            activity_log!(context, activity_event::PORTAL_DEPOSIT_BOUNCE_BACK,)
        }
        L1PortalEvent::DepositBounceBackPending { .. } => {
            activity_log!(context, activity_event::PORTAL_DEPOSIT_BOUNCE_BACK_PENDING,)
        }
        L1PortalEvent::RefundClaimed { amount: 0, .. } => {}
        L1PortalEvent::RefundClaimed { .. } => {
            activity_log!(context, activity_event::PORTAL_REFUND_ACCOUNTED,)
        }
    }
}

fn log_zone_action(action: &L2BridgeAction, context: &ActivityContext) {
    match action {
        L2BridgeAction::Deposit {
            result: DepositResult::Processed { .. },
            ..
        } => activity_log!(context, activity_event::ZONE_DEPOSIT_MINTED,),
        L2BridgeAction::Deposit {
            result: DepositResult::Failed,
            ..
        } => activity_log!(context, activity_event::ZONE_DEPOSIT_FAILED,),
        L2BridgeAction::WithdrawalRequested { origin, .. } => match origin {
            WithdrawalOrigin::DepositBounceBack => {
                activity_log!(context, activity_event::ZONE_DEPOSIT_BOUNCE_BACK_REQUESTED,)
            }
            WithdrawalOrigin::User { .. } => {
                activity_log!(context, activity_event::ZONE_WITHDRAWAL_BURNED,)
            }
        },
        L2BridgeAction::WithdrawalBounceBack {
            status: WithdrawalBounceBackStatus::Processed,
            ..
        } => activity_log!(context, activity_event::ZONE_WITHDRAWAL_BOUNCE_BACK_MINTED,),
        L2BridgeAction::WithdrawalBounceBack {
            status: WithdrawalBounceBackStatus::Pending,
            ..
        } => activity_log!(context, activity_event::ZONE_WITHDRAWAL_BOUNCE_BACK_PENDING,),
        L2BridgeAction::RefundClaimed { .. } => {
            activity_log!(context, activity_event::ZONE_REFUND_MINTED,)
        }
    }
}
