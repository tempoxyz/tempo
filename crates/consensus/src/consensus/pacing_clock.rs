//! Monotonic proposal timing for production and deterministic runtimes.

use std::{
    future::Future,
    time::{Duration, SystemTime},
};

use tokio::time::Instant;

use commonware_runtime::{Clock, deterministic};

/// A runtime clock whose pacing samples are independent of wall-clock adjustments.
///
/// `Clock::current` remains the wall-clock source for block headers; `Clock::sleep`
/// must wait a relative duration on the same time axis as these samples.
pub trait PacingClock: Clock {
    /// A sample from this runtime's monotonic time axis.
    type PacingInstant: Copy + Send + Sync;

    /// Samples monotonic time for proposal preparation and pacing.
    fn pacing_now(&self) -> Self::PacingInstant;

    /// Returns the monotonic time elapsed since a sample from this runtime.
    fn pacing_elapsed(&self, since: Self::PacingInstant) -> Duration;

    /// Sleeps only for the part of `duration` not already spent since `started`.
    /// Wall-clock changes cannot extend or shorten this relative wait.
    fn sleep_remaining(
        &self,
        started: Self::PacingInstant,
        duration: Duration,
    ) -> impl Future<Output = ()> + Send + 'static {
        self.sleep(duration.saturating_sub(self.pacing_elapsed(started)))
    }
}

impl PacingClock for commonware_runtime::tokio::Context {
    type PacingInstant = Instant;

    fn pacing_now(&self) -> Instant {
        Instant::now()
    }

    fn pacing_elapsed(&self, since: Instant) -> Duration {
        since.elapsed()
    }
}

impl PacingClock for deterministic::Context {
    // The deterministic executor's virtual time only advances, unlike the OS wall clock.
    type PacingInstant = SystemTime;

    fn pacing_now(&self) -> SystemTime {
        self.current()
    }

    fn pacing_elapsed(&self, since: SystemTime) -> Duration {
        self.current()
            .duration_since(since)
            .expect("deterministic runtime time never regresses")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::Runner as _;
    use futures::FutureExt as _;
    use std::sync::atomic::{AtomicI64, Ordering};

    struct AdjustableWallClock {
        inner: deterministic::Context,
        wall_offset_seconds: AtomicI64,
    }

    impl governor::clock::Clock for AdjustableWallClock {
        type Instant = SystemTime;

        fn now(&self) -> SystemTime {
            self.current()
        }
    }

    impl governor::clock::ReasonablyRealtime for AdjustableWallClock {}

    impl Clock for AdjustableWallClock {
        fn current(&self) -> SystemTime {
            let baseline = self.inner.current() + Duration::from_secs(120);
            let offset = self.wall_offset_seconds.load(Ordering::Relaxed);
            if offset < 0 {
                baseline - Duration::from_secs(offset.unsigned_abs())
            } else {
                baseline + Duration::from_secs(offset.unsigned_abs())
            }
        }

        fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
            self.inner.sleep(duration)
        }

        fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static {
            // Match the production adapter so an absolute wall deadline fails this test.
            self.sleep(deadline.duration_since(self.current()).unwrap_or_default())
        }
    }

    impl PacingClock for AdjustableWallClock {
        type PacingInstant = SystemTime;

        fn pacing_now(&self) -> SystemTime {
            self.inner.pacing_now()
        }

        fn pacing_elapsed(&self, since: SystemTime) -> Duration {
            self.inner.pacing_elapsed(since)
        }
    }

    #[test]
    fn wall_clock_steps_do_not_change_remaining_pacing() {
        for offset in [-60, 60] {
            deterministic::Runner::default().start(|context| async move {
                let clock = AdjustableWallClock {
                    inner: context,
                    wall_offset_seconds: AtomicI64::new(0),
                };
                let opened = clock.pacing_now();
                clock.sleep(Duration::from_millis(100)).await;
                clock.wall_offset_seconds.store(offset, Ordering::Relaxed);
                let wait = clock.sleep_remaining(opened, Duration::from_millis(350));
                futures::pin_mut!(wait);
                assert!(wait.as_mut().now_or_never().is_none());
                clock.sleep(Duration::from_millis(249)).await;
                assert!(wait.as_mut().now_or_never().is_none());
                clock.sleep(Duration::from_millis(1)).await;
                assert_eq!(wait.as_mut().now_or_never(), Some(()));
            });
        }
    }

    #[test]
    fn exhausted_windows_do_not_add_a_delay() {
        deterministic::Runner::default().start(|context| async move {
            let opened = context.pacing_now();
            context.sleep(Duration::from_millis(400)).await;
            assert_eq!(
                context
                    .sleep_remaining(opened, Duration::from_millis(350))
                    .now_or_never(),
                Some(())
            );
            assert_eq!(
                context
                    .sleep_remaining(opened, Duration::ZERO)
                    .now_or_never(),
                Some(())
            );
        });
    }
}
