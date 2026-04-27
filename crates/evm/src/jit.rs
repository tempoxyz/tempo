//! revmc JIT metrics and helpers.

pub use tempo_revm::{
    CompilationEvent, JitBackend, RuntimeConfig, RuntimeStatsSnapshot, RuntimeTuning,
};

/// Prometheus metrics for revmc JIT runtime stats.
#[derive(reth_metrics::Metrics, Clone)]
#[metrics(scope = "revmc.jit")]
pub struct RevmcMetrics {
    /// Total lookups that returned a compiled function.
    pub lookup_hits: metrics::Gauge,
    /// Total lookups that returned interpret (not ready).
    pub lookup_misses: metrics::Gauge,
    /// Lookup-observed events successfully enqueued.
    pub events_sent: metrics::Gauge,
    /// Lookup-observed events dropped (channel full).
    pub events_dropped: metrics::Gauge,
    /// Number of entries in the resident compiled map.
    pub resident_entries: metrics::Gauge,
    /// Approximate total bytes of compiled machine code.
    pub jit_code_bytes: metrics::Gauge,
    /// Approximate total bytes of JIT-related data.
    pub jit_data_bytes: metrics::Gauge,
    /// Number of pending JIT compilation jobs.
    pub jit_queue_len: metrics::Gauge,
    /// Total number of entries evicted.
    pub evictions: metrics::Gauge,
    /// Total compilations dispatched.
    pub compilations_dispatched: metrics::Gauge,
    /// Total successful compilations.
    pub compilations_succeeded: metrics::Gauge,
    /// Total failed compilations.
    pub compilations_failed: metrics::Gauge,
    /// Histogram of JIT compilation durations (seconds).
    pub jit_compilation_duration: metrics::Histogram,
    /// Duration of the last JIT compilation (seconds).
    pub jit_compilation_duration_last: metrics::Gauge,
    /// Histogram of parse phase durations (seconds).
    pub jit_parse_duration: metrics::Histogram,
    /// Histogram of translate phase durations (seconds).
    pub jit_translate_duration: metrics::Histogram,
    /// Histogram of optimize phase durations (seconds).
    pub jit_optimize_duration: metrics::Histogram,
    /// Histogram of codegen phase durations (seconds).
    pub jit_codegen_duration: metrics::Histogram,
}

impl RevmcMetrics {
    /// Records a [`RuntimeStatsSnapshot`] into the metrics.
    pub fn record(&self, stats: &RuntimeStatsSnapshot) {
        let RuntimeStatsSnapshot {
            lookup_hits,
            lookup_misses,
            events_sent,
            events_dropped,
            resident_entries,
            jit_code_bytes,
            jit_data_bytes,
            jit_queue_len,
            evictions,
            compilations_dispatched,
            compilations_succeeded,
            compilations_failed,
        } = *stats;
        self.lookup_hits.set(lookup_hits as f64);
        self.lookup_misses.set(lookup_misses as f64);
        self.events_sent.set(events_sent as f64);
        self.events_dropped.set(events_dropped as f64);
        self.resident_entries.set(resident_entries as f64);
        self.jit_code_bytes.set(jit_code_bytes as f64);
        self.jit_data_bytes.set(jit_data_bytes as f64);
        self.jit_queue_len.set(jit_queue_len as f64);
        self.evictions.set(evictions as f64);
        self.compilations_dispatched
            .set(compilations_dispatched as f64);
        self.compilations_succeeded
            .set(compilations_succeeded as f64);
        self.compilations_failed.set(compilations_failed as f64);
    }

    /// Records a [`CompilationEvent`] into the histogram metrics.
    pub fn record_compilation(&self, event: &CompilationEvent) {
        let duration_secs = event.duration.as_secs_f64();
        self.jit_compilation_duration.record(duration_secs);
        self.jit_compilation_duration_last.set(duration_secs);
        self.jit_parse_duration
            .record(event.timings.parse.as_secs_f64());
        self.jit_translate_duration
            .record(event.timings.translate.as_secs_f64());
        self.jit_optimize_duration
            .record(event.timings.optimize.as_secs_f64());
        self.jit_codegen_duration
            .record(event.timings.codegen.as_secs_f64());
    }
}
