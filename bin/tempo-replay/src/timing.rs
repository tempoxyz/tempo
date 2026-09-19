use crate::{
    config::Timing,
    model::{Phase, now_ms},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::Instant;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Segment {
    pub phase: Phase,
    pub first_height: u64,
    pub source_ms: u64,
    pub anchor_wall_ms: u64,
    pub speed: f64,
    pub reason: String,
}
pub struct Pacer {
    pub segment: Segment,
    anchor: Instant,
    previous: Option<(u64, Instant)>,
    pub consecutive_slips: u64,
}
impl Pacer {
    pub fn new(c: &Timing, phase: Phase, height: u64, source_ms: u64, reason: &str) -> Self {
        let now = now_ms();
        let delay = if phase == Phase::Live {
            c.guard_ms.max(
                source_ms
                    .saturating_add(c.target_lag_ms)
                    .saturating_sub(now),
            )
        } else {
            c.guard_ms
        };
        Self {
            segment: Segment {
                speed: if phase == Phase::Live {
                    1.
                } else {
                    c.max_catch_up_speed
                },
                phase,
                first_height: height,
                source_ms,
                anchor_wall_ms: now.saturating_add(delay),
                reason: reason.into(),
            },
            anchor: Instant::now() + Duration::from_millis(delay),
            previous: None,
            consecutive_slips: 0,
        }
    }
    pub fn due(&self, source_ms: u64) -> Result<Instant> {
        ensure!(
            source_ms >= self.segment.source_ms,
            "pacing timestamp regression"
        );
        self.anchor
            .checked_add(scaled(
                source_ms - self.segment.source_ms,
                self.segment.speed,
            )?)
            .ok_or_else(|| anyhow::anyhow!("pacing deadline overflow"))
    }
    pub fn release_at(&self, source_ms: u64) -> Result<Instant> {
        let due = self.due(source_ms)?;
        if let Some((previous_ms, previous_release)) = self.previous {
            ensure!(source_ms >= previous_ms, "release timestamp regression");
            Ok(due.max(
                previous_release
                    .checked_add(scaled(source_ms - previous_ms, self.segment.speed)?)
                    .ok_or_else(|| anyhow::anyhow!("release deadline overflow"))?,
            ))
        } else {
            Ok(due)
        }
    }
    pub fn released(&mut self, source_ms: u64, c: &Timing) -> Result<u64> {
        let now = Instant::now();
        let slip = now
            .saturating_duration_since(self.due(source_ms)?)
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        self.consecutive_slips = if slip > c.slip_warn_ms {
            self.consecutive_slips + 1
        } else {
            0
        };
        self.previous = Some((source_ms, now));
        Ok(slip)
    }
}
fn scaled(ms: u64, speed: f64) -> Result<Duration> {
    ensure!(speed.is_finite() && speed >= 1., "invalid pacing speed");
    Ok(Duration::from_millis((ms as f64 / speed).ceil() as u64))
}
