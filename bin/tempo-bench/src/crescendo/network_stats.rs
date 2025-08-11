use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use crossbeam_utils::CachePadded;
use thousands::Separable;

pub struct NetworkStats {
    requests: AtomicU64,
    errors: AtomicU64,
}

// Depending on build config, false sharing with this static and some
// other frequently accessed memory can occur. To mitigate, we pad stats
// to the length of a full cache line to avoid conflict. This is measured
// to increase RPS by >10% in the release profile at the time of writing.
pub static NETWORK_STATS: CachePadded<NetworkStats> = CachePadded::new(NetworkStats {
    requests: AtomicU64::new(0),
    errors: AtomicU64::new(0),
});

impl NetworkStats {
    pub fn inc_requests_by(&self, count: usize) {
        self.requests.fetch_add(count as u64, Ordering::Relaxed);
    }

    pub fn inc_errors_by(&self, count: usize) {
        self.errors.fetch_add(count as u64, Ordering::Relaxed);
    }

    pub async fn start_reporter(&self, measurement_interval: Duration) {
        let mut last_requests = 0u64;
        let mut last_errors = 0u64;
        let mut interval = tokio::time::interval(measurement_interval);
        interval.tick().await;
        loop {
            interval.tick().await;
            let requests = self.requests.load(Ordering::Relaxed);
            let errors = self.errors.load(Ordering::Relaxed);
            let rps = (requests - last_requests) / measurement_interval.as_secs();
            let eps = (errors - last_errors) / measurement_interval.as_secs();
            println!(
                "[*] RPS: {}, EPS: {}, Total requests: {}, Total errors: {}",
                rps.separate_with_commas(),
                eps.separate_with_commas(),
                requests.separate_with_commas(),
                errors.separate_with_commas()
            );
            last_requests = requests;
            last_errors = errors;
        }
    }
}
