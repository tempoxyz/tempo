//! Retry utilities with exponential backoff for transient RPC failures.

use rand::Rng;
use std::time::Duration;
use tracing::{debug, warn};

const INITIAL_DELAY_MS: u64 = 100;
const MAX_DELAY_MS: u64 = 30_000;
const MAX_RETRIES: usize = 10;

fn is_transient_error(err: &eyre::Error) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("connection")
        || msg.contains("timeout")
        || msg.contains("rate limit")
        || msg.contains("too many requests")
        || msg.contains("429")
        || msg.contains("503")
        || msg.contains("502")
        || msg.contains("504")
        || msg.contains("temporarily unavailable")
        || msg.contains("network")
        || msg.contains("reset by peer")
        || msg.contains("broken pipe")
        || msg.contains("eof")
}

fn compute_delay(attempt: usize) -> Duration {
    let base_delay = INITIAL_DELAY_MS.saturating_mul(1 << attempt.min(10));
    let capped_delay = base_delay.min(MAX_DELAY_MS);
    let jitter = rand::thread_rng().gen_range(0..=capped_delay / 4);
    Duration::from_millis(capped_delay + jitter)
}

pub async fn with_retry<F, Fut, T>(operation_name: &str, mut f: F) -> eyre::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = eyre::Result<T>>,
{
    let mut attempt = 0;

    loop {
        match f().await {
            Ok(result) => return Ok(result),
            Err(err) => {
                if !is_transient_error(&err) {
                    debug!(
                        operation = %operation_name,
                        error = %err,
                        "Non-transient error, not retrying"
                    );
                    return Err(err);
                }

                if attempt >= MAX_RETRIES {
                    warn!(
                        operation = %operation_name,
                        attempts = %attempt,
                        error = %err,
                        "Max retries exceeded"
                    );
                    return Err(err);
                }

                let delay = compute_delay(attempt);
                warn!(
                    operation = %operation_name,
                    attempt = %(attempt + 1),
                    max_attempts = %MAX_RETRIES,
                    delay_ms = %delay.as_millis(),
                    error = %err,
                    "Transient RPC error, retrying"
                );

                tokio::time::sleep(delay).await;
                attempt += 1;
            }
        }
    }
}
