use commonware_runtime::{
    Metrics as RuntimeMetrics,
    telemetry::metrics::{Counter, Gauge, MetricsExt as _},
};

pub(super) struct Metrics {
    pub(super) peers: Gauge,
    pub(super) slots: Gauge,
    pub(super) quarantined: Gauge,
    pub(super) latest_verified_epoch: Gauge,
    pub(super) latest_verified_view: Gauge,
    pub(super) dispatched: Counter,
    pub(super) settled: Counter,
    pub(super) invalid: Counter,
    pub(super) needs_scheme: Counter,
    pub(super) shed: Counter,
    pub(super) unanswered: Counter,
    pub(super) relayed: Counter,
    pub(super) relay_dropped: Counter,
    pub(super) penalties: Counter,
    pub(super) boundary_scheme_events: Counter,
    pub(super) dropped_disconnected_peer: Counter,
    pub(super) dropped_replay: Counter,
    pub(super) dropped_malformed: Counter,
    pub(super) dropped_stale: Counter,
    pub(super) dropped_locked_replacement: Counter,
}

impl Metrics {
    pub(super) fn init(context: &impl RuntimeMetrics) -> Self {
        Self {
            peers: context.gauge("peers", "peers offering tempo/1"),
            slots: context.gauge("slots", "peers with a candidate or quarantined certificate"),
            quarantined: context.gauge(
                "quarantined",
                "peer certificates waiting for an authenticated boundary scheme",
            ),
            // A round is (epoch, view). View resets each epoch, so it is only
            // meaningful next to the epoch; exposing both keeps the pair
            // monotonic instead of jumping backward at an epoch boundary.
            latest_verified_epoch: context
                .gauge("latest_verified_epoch", "latest verified round epoch"),
            latest_verified_view: context.gauge(
                "latest_verified_view",
                "latest verified view within `latest_verified_epoch`",
            ),
            dispatched: context.counter("dispatched", "certificates sent for judgement"),
            settled: context.counter(
                "settled",
                "certificates accepted or already known by the driver",
            ),
            invalid: context.counter(
                "invalid",
                "certificates rejected by an installed epoch scheme",
            ),
            needs_scheme: context.counter(
                "needs_scheme",
                "certificates held back for want of a scheme; rising while settled stays flat \
                 may mean this node is behind an identity rotation",
            ),
            shed: context.counter("shed", "judgements delayed by the verify budget"),
            unanswered: context.counter(
                "unanswered",
                "certificates the driver never judged, which on a publish-only node \
                 means gossip ingest was enabled without anything able to verify",
            ),
            relayed: context.counter("relayed", "durable certificate frames offered to peers"),
            relay_dropped: context.counter(
                "relay_dropped",
                "durable publications rejected because a peer's queue was full or closed",
            ),
            penalties: context.counter("penalties", "peer reputation penalties applied"),
            boundary_scheme_events: context.counter(
                "boundary_scheme_events",
                "authenticated boundary scheme events that triggered quarantine scans",
            ),
            dropped_disconnected_peer: context.counter(
                "dropped_disconnected_peer",
                "frames received after their logical peer disconnected",
            ),
            dropped_replay: context.counter(
                "dropped_replay",
                "frames at or below the peer's highest seen round",
            ),
            dropped_malformed: context.counter("dropped_malformed", "frames that did not decode"),
            dropped_stale: context.counter(
                "dropped_stale",
                "frames at or below the latest verified round on arrival",
            ),
            dropped_locked_replacement: context.counter(
                "dropped_locked_replacement",
                "well-formed frames rejected while the peer's slot is being judged or quarantined",
            ),
        }
    }
}
