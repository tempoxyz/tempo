//! Sparse paired CPU/wall observations for opt-in execution diagnostics.

use std::{
    fmt,
    time::{Duration, Instant},
};

/// Each stage samples its first call, then approximately 1/64 calls using a mixed
/// invocation index. The first observation covers rare error paths; it also means
/// these observations must not be multiplied by 64 to estimate total CPU time.
#[derive(Default)]
pub(super) struct SampledCpuTimings {
    pub(super) calls: u64,
    attempts: u64,
    samples: u64,
    failed_samples: u64,
    unavailable: u64,
    invalid: u64,
    cpu: Duration,
    wall: Duration,
}

pub(super) struct CpuSample {
    wall: Instant,
    cpu: Option<Duration>,
}

impl CpuSample {
    fn start() -> Self {
        // Wall time encloses both CPU clock reads. Both clocks must be read on
        // the same thread; these scopes enclose synchronous execution only.
        Self {
            wall: Instant::now(),
            cpu: thread_cpu_time(),
        }
    }
}

impl SampledCpuTimings {
    pub(super) fn start(&mut self) -> Option<CpuSample> {
        self.calls += 1;
        if self.calls != 1 && mix(self.calls) & 63 != 0 {
            return None;
        }
        self.attempts += 1;
        Some(CpuSample::start())
    }

    pub(super) fn finish(&mut self, sample: Option<CpuSample>, failed: bool) {
        if let Some(sample) = sample {
            let end = thread_cpu_time();
            self.record(sample.cpu, end, sample.wall.elapsed(), failed);
        }
    }

    fn record(
        &mut self,
        start: Option<Duration>,
        end: Option<Duration>,
        wall: Duration,
        failed: bool,
    ) {
        let (Some(start), Some(end)) = (start, end) else {
            self.unavailable += 1;
            return;
        };
        let Some(cpu) = end.checked_sub(start).filter(|cpu| *cpu <= wall) else {
            self.invalid += 1;
            return;
        };
        self.samples += 1;
        self.failed_samples += u64::from(failed);
        self.cpu += cpu;
        self.wall += wall;
    }
}

impl fmt::Debug for SampledCpuTimings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CpuSamples")
            .field("calls", &self.calls)
            .field("attempts", &self.attempts)
            .field("samples", &self.samples)
            .field("failed_samples", &self.failed_samples)
            .field("unavailable", &self.unavailable)
            .field("invalid", &self.invalid)
            .field("cpu_ns", &self.cpu.as_nanos())
            .field("wall_ns", &self.wall.as_nanos())
            .finish()
    }
}

// SplitMix64's finalizer avoids a fixed periodic alignment with workload types.
// This is a deterministic diagnostic selector, not a source of random samples.
fn mix(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(target_os = "linux")]
fn thread_cpu_time() -> Option<Duration> {
    use rustix::time::{ClockId, DynamicClockId, clock_gettime_dynamic};
    let time = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    let seconds = u64::try_from(time.tv_sec).ok()?;
    let nanos = u32::try_from(time.tv_nsec)
        .ok()
        .filter(|n| *n < 1_000_000_000)?;
    Some(Duration::new(seconds, nanos))
}

#[cfg(not(target_os = "linux"))]
fn thread_cpu_time() -> Option<Duration> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_or_missing_cpu_readings_do_not_enter_paired_totals() {
        let mut timings = SampledCpuTimings::default();
        let us = |value| Some(Duration::from_micros(value));
        timings.record(us(10), us(13), Duration::from_micros(9), false);
        timings.record(us(13), us(15), Duration::from_micros(4), true);
        timings.record(None, us(20), Duration::from_micros(9), false);
        timings.record(us(20), None, Duration::from_micros(9), false);
        timings.record(us(20), us(19), Duration::from_micros(9), false);
        timings.record(us(20), us(30), Duration::from_micros(9), false);
        assert_eq!(timings.samples, 2);
        assert_eq!(timings.failed_samples, 1);
        assert_eq!(timings.cpu, Duration::from_micros(5));
        assert_eq!(timings.wall, Duration::from_micros(13));
        assert_eq!(timings.unavailable, 2);
        assert_eq!(timings.invalid, 2);
    }

    #[test]
    fn sampling_keeps_population_and_completion_counts_separate() {
        let mut timings = SampledCpuTimings::default();
        for _ in 0..16_384 {
            let sample = timings.start();
            timings.finish(sample, false);
        }
        assert_eq!(timings.calls, 16_384);
        assert!((128..384).contains(&timings.attempts));
        assert_eq!(
            timings.attempts,
            timings.samples + timings.unavailable + timings.invalid
        );
        assert_eq!(timings.failed_samples, 0);
        let before = timings.samples;
        timings.finish(None, true);
        assert_eq!(timings.samples, before);
        assert_eq!(timings.failed_samples, 0);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sleeping_is_wall_time_without_equivalent_thread_cpu() {
        let mut timings = SampledCpuTimings::default();
        let sample = timings.start();
        std::thread::sleep(Duration::from_millis(20));
        timings.finish(sample, false);
        assert_eq!(timings.samples, 1);
        assert!(timings.wall >= Duration::from_millis(20));
        assert!(timings.cpu < timings.wall / 2);
    }

    #[test]
    #[ignore = "Run on the benchmark validator affinity to measure the paired-clock floor"]
    fn execution_cpu_clock_floor() {
        let mut timings = SampledCpuTimings::default();
        for _ in 0..16_384 {
            // Force an empty sample, without changing the production selector.
            timings.calls += 1;
            timings.attempts += 1;
            let sample = Some(CpuSample::start());
            timings.finish(sample, false);
        }
        println!("execution_cpu_clock_floor {timings:?}");
        assert_eq!(timings.attempts, 16_384);
        assert_eq!(timings.invalid, 0);
        #[cfg(target_os = "linux")]
        assert_eq!(timings.samples, 16_384);
    }
}
