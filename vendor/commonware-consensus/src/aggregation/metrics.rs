use commonware_runtime::{
    telemetry::metrics::{histogram, status, Counter, Gauge, MetricsExt as _},
    Metrics as RuntimeMetrics,
};

/// Metrics for the [super::Engine].
pub struct Metrics {
    /// Lowest height without a certificate
    pub tip: Gauge,
    /// Number of digests returned by the automaton by status
    pub digest: status::Counter,
    /// Number of [super::types::Ack] messages processed by status
    pub acks: status::Counter,
    /// Number of certificates produced
    pub certificates: Counter,
    /// Histogram of application digest durations
    pub digest_duration: histogram::Timed,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init(context: &impl RuntimeMetrics) -> Self {
        let tip = context.gauge("tip", "Lowest height without a certificate");
        let digest = context.family(
            "digest",
            "Number of digests returned by the automaton by status",
        );
        let acks = context.family("acks", "Number of Ack messages processed by status");
        let certificates = context.counter("certificates", "Number of certificates produced");
        let digest_duration = context.histogram(
            "digest_duration",
            "Histogram of application digest durations",
            histogram::Buckets::LOCAL,
        );

        Self {
            tip,
            digest,
            acks,
            certificates,
            digest_duration: histogram::Timed::new(digest_duration),
        }
    }
}
