use commonware_runtime::{
    Metrics as RuntimeMetrics,
    telemetry::metrics::{Counter, Gauge, MetricsExt as _},
};

pub(super) struct Metrics {
    pub(super) peers: Gauge,
    pub(super) slots: Gauge,
    pub(super) quarantined: Gauge,
    pub(super) watermark_epoch: Gauge,
    pub(super) watermark_view: Gauge,
    pub(super) dispatched: Counter,
    pub(super) admitted: Counter,
    pub(super) stale: Counter,
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
            watermark_epoch: context.gauge("watermark_epoch", "highest applied round epoch"),
            watermark_view: context.gauge(
                "watermark_view",
                "highest applied view within `watermark_epoch`",
            ),
            dispatched: context.counter("dispatched", "certificates sent for judgement"),
            admitted: context.counter("admitted", "certificates verified and applied"),
            stale: context.counter("stale", "certificates judged at or below the watermark"),
            invalid: context.counter(
                "invalid",
                "certificates rejected by an installed epoch scheme",
            ),
            needs_scheme: context.counter(
                "needs_scheme",
                "certificates held back for want of a scheme; rising while admitted stays flat \
                 may mean this node is behind an identity rotation",
            ),
            shed: context.counter("shed", "judgements delayed by the verify budget"),
            unanswered: context.counter(
                "unanswered",
                "certificates the driver never judged, which on a publish-only node \
                 means gossip ingest was enabled without anything able to verify",
            ),
            relayed: context.counter("relayed", "frames relayed to peers"),
            relay_dropped: context.counter(
                "relay_dropped",
                "relays rejected because a peer's queue was full or closed",
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
            dropped_replay: context
                .counter("dropped_replay", "frames already settled or published"),
            dropped_malformed: context.counter("dropped_malformed", "frames that did not decode"),
            dropped_stale: context.counter(
                "dropped_stale",
                "frames at or below the watermark on arrival",
            ),
            dropped_locked_replacement: context.counter(
                "dropped_locked_replacement",
                "well-formed frames rejected while the peer's slot is being judged or quarantined",
            ),
        }
    }
}
