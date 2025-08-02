use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use ratelimit::Ratelimiter;
use thousands::Separable;

use crate::config;

pub struct TxQueue {
    // TODO: RwLock? Natively concurrent deque?
    queue: Mutex<VecDeque<Vec<u8>>>,
    total_added: AtomicU64,
    total_popped: AtomicU64,
    rate_limiter: Ratelimiter,
}

impl TxQueue {
    fn new() -> Self {
        let initial_ratelimit = config::get().rate_limiting.initial_ratelimit;

        let rate_limiter = Ratelimiter::builder(initial_ratelimit, Duration::from_secs(1))
            .max_tokens(initial_ratelimit)
            .build()
            .unwrap();

        Self {
            queue: Mutex::new(VecDeque::new()),
            total_added: AtomicU64::new(0),
            total_popped: AtomicU64::new(0),
            rate_limiter,
        }
    }
}

pub static TX_QUEUE: std::sync::LazyLock<TxQueue> = std::sync::LazyLock::new(TxQueue::new);

impl TxQueue {
    pub fn push_txs(&self, txs: Vec<Vec<u8>>) {
        self.total_added.fetch_add(txs.len() as u64, Ordering::Relaxed);
        self.queue.lock().extend(txs);
    }

    pub fn queue_len(&self) -> usize {
        self.queue.lock().len()
    }

    pub async fn pop_at_most(&self, max_count: usize) -> Option<Vec<Vec<u8>>> {
        // Assume the queue has sufficient items for now.
        let allowed = (0..max_count).take_while(|_| self.rate_limiter.try_wait().is_ok()).count();
        if allowed == 0 {
            return None;
        }

        // Scope to release lock asap.
        let drained = {
            let mut queue = self.queue.lock();
            let to_drain = allowed.min(queue.len());
            if to_drain == 0 {
                return None;
            }
            queue.drain(..to_drain).collect::<Vec<_>>()
        };

        self.total_popped.fetch_add(drained.len() as u64, Ordering::Relaxed);

        Some(drained)
    }

    pub async fn start_reporter(&self, measurement_interval: std::time::Duration) {
        let mut last_total_added = 0u64;
        let mut last_total_popped = 0u64;
        let mut last_queue_len = 0usize;
        let mut interval = tokio::time::interval(measurement_interval);
        interval.tick().await;
        loop {
            interval.tick().await;
            let total_added = self.total_added.load(Ordering::Relaxed);
            let total_popped = self.total_popped.load(Ordering::Relaxed);
            let current_queue_len = self.queue_len();
            let added_per_second = (total_added - last_total_added) / measurement_interval.as_secs();
            let popped_per_second = (total_popped - last_total_popped) / measurement_interval.as_secs();
            let delta_per_second =
                ((current_queue_len as i64 - last_queue_len as i64) as f64 / measurement_interval.as_secs_f64()) as i64;

            // Adjust rate limit based on total popped transactions and thresholds.
            let rate_config = &config::get().rate_limiting;
            let new_rate_limit = rate_config
                .ratelimit_thresholds
                .iter()
                .rev()
                .find(|(threshold, _)| total_popped >= (*threshold as u64))
                .map(|(_, rate_limit)| *rate_limit)
                .unwrap_or(rate_config.initial_ratelimit);

            if self.rate_limiter.refill_amount() != new_rate_limit {
                println!("[+] Adjusting rate limit to {} txs/s", new_rate_limit.separate_with_commas());
                self.rate_limiter.set_max_tokens(new_rate_limit).unwrap(); // Burst limit must be set first.
                self.rate_limiter.set_refill_amount(new_rate_limit).unwrap();
                self.rate_limiter.set_available(0).unwrap(); // Prevent bursts.
            }

            println!(
                "[*] TxQueue +/s: {}, -/s: {}, Δ/s: {}, Length: {}, Rate limit: {}/s",
                added_per_second.separate_with_commas(),
                popped_per_second.separate_with_commas(),
                delta_per_second.separate_with_commas(),
                current_queue_len.separate_with_commas(),
                self.rate_limiter.refill_amount().separate_with_commas()
            );

            last_total_added = total_added;
            last_total_popped = total_popped;
            last_queue_len = current_queue_len;
        }
    }
}
