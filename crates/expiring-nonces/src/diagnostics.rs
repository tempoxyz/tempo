//! Nonce overhead measurements. Per-transaction timers sample one in 1,024 calls
//! on each thread; block/cache/expiry timers record every call. Counters for
//! sampled operations advance by 1,024 and can have an unfinished thread-local
//! tail. All labels have fixed cardinality. Slow operations retain tracing's
//! enclosing block/hash context for correlation with block gaps.

use std::{
    cell::Cell,
    time::{Duration, Instant},
};

thread_local! {
    static SAMPLES: Cell<[u16; 4]> = const { Cell::new([0; 4]) };
    static CHECK_SITES: Cell<[u16; 3]> = const { Cell::new([0; 3]) };
}

/// Independently sampled hot paths.
#[derive(Clone, Copy)]
pub enum Sample {
    Check,
    Insert,
    RecoverSigner,
    Membership,
}

impl Sample {
    fn name(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Insert => "insert_updates",
            Self::RecoverSigner => "recover_signer",
            Self::Membership => "membership_lookup",
        }
    }
}

#[derive(Clone, Copy)]
pub enum CheckSite {
    Executor,
    Handler,
    Insert,
}

pub fn check_site(site: CheckSite) {
    let selected = CHECK_SITES.with(|sites| {
        let mut counters = sites.get();
        let counter = &mut counters[site as usize];
        *counter = (*counter + 1) & 1023;
        let selected = *counter == 0;
        sites.set(counters);
        selected
    });
    if selected {
        event(
            match site {
                CheckSite::Executor => "checks_executor",
                CheckSite::Handler => "checks_handler",
                CheckSite::Insert => "checks_insert",
            },
            1024,
        );
    }
}

/// Records an operation's latency, including error/early-return paths.
pub struct Timer {
    start: Instant,
    operation: &'static str,
    weight: u64,
    elapsed: Option<Duration>,
}

impl Timer {
    pub fn start(operation: &'static str) -> Self {
        Self {
            start: Instant::now(),
            operation,
            weight: 1,
            elapsed: None,
        }
    }

    pub fn sampled(operation: Sample) -> Option<Self> {
        let selected = SAMPLES.with(|samples| {
            let mut counters = samples.get();
            let counter = &mut counters[operation as usize];
            *counter = (*counter + 1) & 1023;
            let selected = *counter == 0;
            samples.set(counters);
            selected
        });
        selected.then(|| Self {
            start: Instant::now(),
            operation: operation.name(),
            weight: 1024,
            elapsed: None,
        })
    }

    /// Times a substage only when its containing hot operation was sampled.
    pub fn substage(sample: &Option<Self>, operation: &'static str) -> Option<Self> {
        sample.as_ref().map(|_| Self {
            start: Instant::now(),
            operation,
            weight: 1024,
            elapsed: None,
        })
    }

    /// Stop before publishing nested measurements, keeping recorder overhead out
    /// of the measured per-transaction stages and their containing operation.
    pub fn stop(&mut self) {
        self.elapsed = Some(self.start.elapsed());
    }

    pub fn stop_sample(sample: &mut Option<Self>) {
        if let Some(timer) = sample {
            timer.stop();
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        let elapsed = self.elapsed.unwrap_or_else(|| self.start.elapsed());
        metrics::histogram!("tempo_expiring_nonce_duration_seconds", "operation" => self.operation)
            .record(elapsed.as_secs_f64());
        metrics::counter!("tempo_expiring_nonce_operations_total", "operation" => self.operation)
            .increment(self.weight);
        if elapsed.as_millis() >= 10 {
            tracing::info!(
                target: "tempo::expiring_nonces",
                operation = self.operation,
                elapsed_ms = elapsed.as_secs_f64() * 1000.0,
                "Slow expiring nonce operation"
            );
        }
    }
}

pub fn event(event: &'static str, count: u64) {
    metrics::counter!("tempo_expiring_nonce_events_total", "event" => event).increment(count);
}

pub fn items(operation: &'static str, count: usize) {
    metrics::histogram!("tempo_expiring_nonce_items", "operation" => operation)
        .record(count as f64);
}
