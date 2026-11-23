//! Bounded, age-limited samples and nearest-rank estimates.

use std::{
    collections::VecDeque,
    ops::{Add, Sub},
    time::{Duration, Instant},
};

pub(crate) fn percentile_rank(len: usize, numerator: usize, denominator: usize) -> Option<usize> {
    debug_assert!(numerator > 0 && numerator <= denominator);
    if len == 0 {
        return None;
    }
    Some((len * numerator).div_ceil(denominator))
}

/// A clock reading can precede an observation slightly when it was taken before a lock.
pub(crate) fn is_expired(at: Instant, now: Instant, ttl: Duration) -> bool {
    now.saturating_duration_since(at) > ttl
}

pub(crate) fn prune_samples<T>(samples: &mut VecDeque<(Instant, T)>, now: Instant, ttl: Duration) {
    samples.retain(|(at, _)| !is_expired(*at, now, ttl));
}

pub(crate) fn record_sample<T, const CAPACITY: usize>(
    samples: &mut VecDeque<(Instant, T)>,
    now: Instant,
    value: T,
    ttl: Duration,
) {
    debug_assert!(CAPACITY > 0);
    prune_samples(samples, now, ttl);
    if samples.len() == CAPACITY {
        samples.pop_front();
    }
    samples.push_back((now, value));
}

pub(crate) fn sample_percentile<T: Copy + Ord>(
    samples: &VecDeque<(Instant, T)>,
    percentile: usize,
) -> Option<T> {
    let rank = percentile_rank(samples.len(), percentile, 100)?;
    let mut values: Vec<T> = samples.iter().map(|(_, value)| *value).collect();
    values.sort_unstable();
    Some(values[rank - 1])
}

pub(crate) fn step_toward<T>(current: T, target: T, max_step: T) -> T
where
    T: Copy + Ord + Add<Output = T> + Sub<Output = T>,
{
    if target >= current {
        current + (target - current).min(max_step)
    } else {
        current - (current - target).min(max_step)
    }
}
