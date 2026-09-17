//! Optional process-wide pacing for public upstream RPCs, shared across reconnects.

use std::{num::NonZeroU32, sync::OnceLock};

use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};

pub(super) async fn wait() {
    static LIMITER: OnceLock<Option<DefaultDirectRateLimiter>> = OnceLock::new();
    let limiter = LIMITER.get_or_init(|| {
        let value = std::env::var("TEMPO_FOLLOW_RPC_REQUESTS_PER_SECOND").ok();
        parse_quota(value.as_deref())
            .expect("TEMPO_FOLLOW_RPC_REQUESTS_PER_SECOND must be between 1 and 1000")
            .map(|quota| {
                tracing::info!(
                    interval_ms = quota.replenish_interval().as_millis(),
                    burst = quota.burst_size().get(),
                    "pacing follower RPC requests"
                );
                RateLimiter::direct(quota)
            })
    });
    if let Some(limiter) = limiter {
        limiter.until_ready().await;
    }
}

fn parse_quota(value: Option<&str>) -> Result<Option<Quota>, &'static str> {
    let Some(value) = value else { return Ok(None) };
    let rate = value.parse::<NonZeroU32>().map_err(|_| "invalid rate")?;
    if rate.get() > 1000 {
        return Err("rate exceeds 1000");
    }
    Ok(Some(Quota::per_second(rate).allow_burst(NonZeroU32::MIN)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn pacing_is_opt_in_and_does_not_allow_bursts() {
        assert_eq!(parse_quota(None).unwrap(), None);
        let quota = parse_quota(Some("50")).unwrap().unwrap();
        assert_eq!(quota.replenish_interval(), Duration::from_millis(20));
        assert_eq!(quota.burst_size().get(), 1);
    }

    #[test]
    fn pacing_rejects_invalid_rates() {
        for value in ["0", "-1", "", "oops", "1001", "4294967296"] {
            assert!(parse_quota(Some(value)).is_err());
        }
        assert!(parse_quota(Some("1")).is_ok());
        assert!(parse_quota(Some("1000")).is_ok());
    }
}
