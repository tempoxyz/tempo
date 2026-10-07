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
    pub(super) resources: ResourceSamples,
}

pub(super) struct CpuSample {
    wall: Instant,
    cpu: Option<Duration>,
    resources: Option<ThreadResources>,
}

impl CpuSample {
    fn start() -> Self {
        // Wall time encloses both CPU clock reads. Both clocks must be read on
        // the same thread; these scopes enclose synchronous execution only.
        Self {
            wall: Instant::now(),
            cpu: thread_cpu_time(),
            resources: thread_resources(),
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
            let resources = thread_resources();
            let end = thread_cpu_time();
            let wall = sample.wall.elapsed();
            if let Some(cpu) = self.record(sample.cpu, end, wall, failed) {
                self.resources
                    .record(sample.resources, resources, cpu, wall, failed);
            }
        }
    }

    fn record(
        &mut self,
        start: Option<Duration>,
        end: Option<Duration>,
        wall: Duration,
        failed: bool,
    ) -> Option<Duration> {
        let (Some(start), Some(end)) = (start, end) else {
            self.unavailable += 1;
            return None;
        };
        let Some(cpu) = end.checked_sub(start).filter(|cpu| *cpu <= wall) else {
            self.invalid += 1;
            return None;
        };
        self.samples += 1;
        self.failed_samples += u64::from(failed);
        self.cpu += cpu;
        self.wall += wall;
        Some(cpu)
    }
}

/// Event counts enclose synchronous work inside the CPU/wall envelopes:
/// wall -> CPU -> resources -> work -> resources -> CPU -> wall.
/// Switches at the edges can therefore be missing from the event counters.
/// Counts indicate association, not the duration or cause of individual waits.
#[derive(Debug, Default)]
pub(super) struct ResourceSamples {
    samples: u64,
    failed_samples: u64,
    unavailable: u64,
    invalid: u64,
    // Voluntary switches, involuntary switches, minor faults, major faults.
    events: [u64; 4],
    // Mask bits match `events`; each bucket is [samples, CPU ns, wall ns].
    // Every paired sample with valid resource counters enters exactly one bucket.
    buckets: [[u128; 3]; 16],
}

#[derive(Clone, Copy, Default)]
struct ThreadResources([u64; 4]);

impl ResourceSamples {
    fn record(
        &mut self,
        start: Option<ThreadResources>,
        end: Option<ThreadResources>,
        cpu: Duration,
        wall: Duration,
        failed: bool,
    ) {
        let (Some(start), Some(end)) = (start, end) else {
            self.unavailable += 1;
            return;
        };
        let mut delta = [0; 4];
        for (index, value) in delta.iter_mut().enumerate() {
            let Some(difference) = end.0[index].checked_sub(start.0[index]) else {
                self.invalid += 1;
                return;
            };
            *value = difference;
        }
        let mut mask = 0;
        for (index, value) in delta.into_iter().enumerate() {
            self.events[index] += value;
            if value != 0 {
                mask |= 1 << index;
            }
        }
        self.samples += 1;
        self.failed_samples += u64::from(failed);
        let bucket = &mut self.buckets[mask];
        bucket[0] += 1;
        bucket[1] += cpu.as_nanos();
        bucket[2] += wall.as_nanos();
    }
}

#[cfg(target_os = "linux")]
fn thread_resources() -> Option<ThreadResources> {
    use nix::sys::resource::{UsageWho, getrusage};
    let usage = getrusage(UsageWho::RUSAGE_THREAD).ok()?;
    Some(ThreadResources([
        u64::try_from(usage.voluntary_context_switches()).ok()?,
        u64::try_from(usage.involuntary_context_switches()).ok()?,
        u64::try_from(usage.minor_page_faults()).ok()?,
        u64::try_from(usage.major_page_faults()).ok()?,
    ]))
}

#[cfg(not(target_os = "linux"))]
fn thread_resources() -> Option<ThreadResources> {
    None
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
        assert!(
            timings
                .record(us(10), us(13), Duration::from_micros(9), false)
                .is_some()
        );
        assert!(
            timings
                .record(us(13), us(15), Duration::from_micros(4), true)
                .is_some()
        );
        assert!(
            timings
                .record(None, us(20), Duration::from_micros(9), false)
                .is_none()
        );
        assert!(
            timings
                .record(us(20), None, Duration::from_micros(9), false)
                .is_none()
        );
        assert!(
            timings
                .record(us(20), us(19), Duration::from_micros(9), false)
                .is_none()
        );
        assert!(
            timings
                .record(us(20), us(30), Duration::from_micros(9), false)
                .is_none()
        );
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
        assert_eq!(
            timings.samples,
            timings.resources.samples + timings.resources.unavailable + timings.resources.invalid
        );
        assert_eq!(timings.resources.failed_samples, 0);
        let before = timings.samples;
        timings.finish(None, true);
        assert_eq!(timings.samples, before);
        assert_eq!(timings.failed_samples, 0);
        assert_eq!(timings.resources.failed_samples, 0);
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
        assert_eq!(timings.resources.samples, 1);
        assert!(timings.resources.events[0] >= 1);
        assert_eq!(
            timings.resources.buckets.iter().map(|b| b[0]).sum::<u128>(),
            1
        );
    }

    #[test]
    fn resource_events_partition_samples_without_double_counting() {
        let mut resources = ResourceSamples::default();
        for mask in 0..16 {
            let end = ThreadResources(std::array::from_fn(|index| {
                if mask & (1 << index) != 0 { 2 } else { 0 }
            }));
            resources.record(
                Some(ThreadResources::default()),
                Some(end),
                Duration::from_nanos(7),
                Duration::from_nanos(10),
                mask == 3,
            );
        }
        assert_eq!(resources.samples, 16);
        assert_eq!(resources.failed_samples, 1);
        assert_eq!(resources.events, [16; 4]);
        assert_eq!(resources.buckets, [[1, 7, 10]; 16]);
    }

    #[test]
    fn invalid_resource_counters_do_not_partially_update_buckets() {
        let mut resources = ResourceSamples::default();
        let zero = Some(ThreadResources::default());
        for (start, end) in [(None, zero), (zero, None)] {
            resources.record(start, end, Duration::ZERO, Duration::ZERO, false);
        }
        resources.record(
            Some(ThreadResources([0, 0, 0, 1])),
            Some(ThreadResources([2, 3, 4, 0])),
            Duration::from_nanos(7),
            Duration::from_nanos(10),
            true,
        );
        assert_eq!(resources.unavailable, 2);
        assert_eq!(resources.invalid, 1);
        assert_eq!(resources.samples, 0);
        assert_eq!(resources.failed_samples, 0);
        assert_eq!(resources.events, [0; 4]);
        assert_eq!(resources.buckets, [[0; 3]; 16]);
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
        println!("execution_resource_clock_floor {:?}", timings.resources);
        assert_eq!(timings.attempts, 16_384);
        assert_eq!(timings.invalid, 0);
        #[cfg(target_os = "linux")]
        {
            assert_eq!(timings.samples, 16_384);
            assert_eq!(timings.resources.samples, 16_384);
        }
    }
}
