use commonware_cryptography::PublicKey;
use commonware_runtime::{
    telemetry::metrics::{histogram, status, Counter, EncodeStruct, GaugeFamily, MetricsExt as _},
    Metrics as RuntimeMetrics,
};

/// Per-sequencer label.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeStruct)]
pub struct Sequencer<P: PublicKey> {
    pub sequencer: P,
}

/// Metrics for the [super::Engine]
pub struct Metrics<P: PublicKey> {
    /// Height per sequencer
    pub sequencer_heights: GaugeFamily<Sequencer<P>>,
    /// Number of acks processed by status
    pub acks: status::Counter,
    /// Number of nodes processed by status
    pub nodes: status::Counter,
    /// Number of application verifications by status
    pub verify: status::Counter,
    /// Number of certificates produced
    pub certificates: Counter,
    /// Number of propose attempts by status
    pub propose: status::Counter,
    /// Number of rebroadcast attempts by status
    pub rebroadcast: status::Counter,
    /// Histogram of application verification durations
    pub verify_duration: histogram::Timed,
    /// Histogram of time from new proposal to certificate generation
    pub e2e_duration: histogram::Timed,
}

impl<P: PublicKey> Metrics<P> {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init<E: RuntimeMetrics>(context: &E) -> Self {
        let sequencer_heights = context.family("sequencer_heights", "Height per sequencer tracked");
        let acks = context.family("acks", "Number of acks processed by status");
        let nodes = context.family("nodes", "Number of nodes processed by status");
        let verify = context.family("verify", "Number of application verifications by status");
        let certificates = context.counter("certificates", "Number of certificates produced");
        let propose = context.family("propose", "Number of propose attempts by status");
        let rebroadcast = context.family("rebroadcast", "Number of rebroadcast attempts by status");
        let verify_duration = context.histogram(
            "verify_duration",
            "Histogram of application verification durations",
            histogram::Buckets::LOCAL,
        );
        let e2e_duration = context.histogram(
            "e2e_duration",
            "Histogram of time from new proposal to certificate generation",
            histogram::Buckets::NETWORK,
        );

        Self {
            sequencer_heights,
            acks,
            nodes,
            verify,
            certificates,
            propose,
            rebroadcast,
            verify_duration: histogram::Timed::new(verify_duration),
            e2e_duration: histogram::Timed::new(e2e_duration),
        }
    }
}
