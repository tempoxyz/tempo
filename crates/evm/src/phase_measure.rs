//! Benchmark-only sampled phase measurements. No clock syscalls on x86-64.
use std::{cell::Cell, sync::OnceLock};

thread_local! { static SEQUENCE: Cell<u64> = const { Cell::new(0) }; }

#[derive(Clone, Copy)]
pub(crate) struct Stamp {
    ticks: u64,
    cpu: u32,
}
impl Stamp {
    #[inline]
    pub(crate) fn read() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            // Measurement branches run on CPUs with RDTSCP. LFENCE prevents the measured
            // loads from crossing the timestamp boundary; AUX detects thread migration.
            let mut cpu = 0;
            let ticks = unsafe {
                core::arch::x86_64::_mm_lfence();
                let ticks = core::arch::x86_64::__rdtscp(&mut cpu);
                core::arch::x86_64::_mm_lfence();
                ticks
            };
            Self { ticks, cpu }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Self { ticks: 0, cpu: 0 }
        }
    }
    fn elapsed(self, end: Self) -> Option<u64> {
        (self.cpu == end.cpu)
            .then(|| end.ticks.checked_sub(self.ticks))
            .flatten()
    }
}

#[derive(Default)]
pub(crate) struct PhaseMeasurements {
    pub(crate) attempted: u64,
    pub(crate) executed: u64,
    pub(crate) committed: u64,
    pub(crate) execution_samples: u64,
    pub(crate) execution_sample_gas: u64,
    pub(crate) commit_samples: u64,
    pub(crate) commit_sample_gas: u64,
    pub(crate) prepare_ticks: u64,
    pub(crate) execute_ticks: u64,
    pub(crate) validate_ticks: u64,
    pub(crate) commit_ticks: u64,
    pub(crate) dropped_samples: u64,
}
impl PhaseMeasurements {
    pub(crate) fn sample(&self) -> Option<Stamp> {
        if !cfg!(target_arch = "x86_64") {
            return None;
        }
        let chosen = SEQUENCE.with(|seq| {
            let mut value = seq.get().wrapping_add(1);
            seq.set(value);
            // Avoid periodically sampling the same position in a repeating workload.
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
            ((value ^ (value >> 31)) & 63) == 0
        });
        chosen.then(Stamp::read)
    }
    pub(crate) fn execution(&mut self, stamps: Option<[Stamp; 4]>, gas: u64) {
        self.executed += 1;
        if let Some([start, prepared, executed, validated]) = stamps {
            if let (Some(prepare), Some(execute), Some(validate)) = (
                start.elapsed(prepared),
                prepared.elapsed(executed),
                executed.elapsed(validated),
            ) {
                self.prepare_ticks += prepare;
                self.execute_ticks += execute;
                self.validate_ticks += validate;
                self.execution_samples += 1;
                self.execution_sample_gas += gas;
            } else {
                self.dropped_samples += 1;
            }
        }
    }
    pub(crate) fn commit(&mut self, start: Option<Stamp>, gas: u64) {
        self.committed += 1;
        if let Some(start) = start {
            if let Some(ticks) = start.elapsed(Stamp::read()) {
                self.commit_ticks += ticks;
                self.commit_samples += 1;
                self.commit_sample_gas += gas;
            } else {
                self.dropped_samples += 1;
            }
        }
    }
    pub(crate) fn finish(self, start: Stamp, gas: u64) {
        let finish_ticks = start.elapsed(Stamp::read()).unwrap_or_default();
        static OVERHEAD: OnceLock<u64> = OnceLock::new();
        let timer_pair_ticks = *OVERHEAD.get_or_init(|| {
            (0..1024)
                .filter_map(|_| {
                    let start = Stamp::read();
                    start.elapsed(Stamp::read())
                })
                .min()
                .unwrap_or_default()
        });
        let env = ENV_STATS.with(|stats| std::mem::take(&mut *stats.borrow_mut()));
        tracing::info!(target: "tempo_phase_measure", thread_id = ?std::thread::current().id(),
            thread_name = std::thread::current().name().unwrap_or("unknown"), env_count = env.count,
            env_samples = env.samples, env_ticks = env.ticks, env_dropped = env.dropped,
            attempted = self.attempted,
            executed = self.executed, committed = self.committed,
            execution_samples = self.execution_samples, execution_sample_gas = self.execution_sample_gas,
            commit_samples = self.commit_samples, commit_sample_gas = self.commit_sample_gas,
            prepare_ticks = self.prepare_ticks, execute_ticks = self.execute_ticks,
            validate_ticks = self.validate_ticks, commit_ticks = self.commit_ticks,
            finish_ticks, gas, dropped_samples = self.dropped_samples, timer_pair_ticks,
            "tempo phase measurement");
    }
}

#[derive(Default)]
struct EnvStats {
    count: u64,
    samples: u64,
    ticks: u64,
    dropped: u64,
}
thread_local! { static ENV_STATS: std::cell::RefCell<EnvStats> = std::cell::RefCell::new(EnvStats::default()); }
pub(crate) fn env_start() -> Option<Stamp> {
    ENV_STATS.with(|stats| {
        let mut stats = stats.borrow_mut();
        stats.count += 1;
        (cfg!(target_arch = "x86_64") && stats.count % 64 == 0).then(Stamp::read)
    })
}
pub(crate) fn env_end(start: Option<Stamp>) {
    if let Some(start) = start {
        let end = Stamp::read();
        ENV_STATS.with(|stats| {
            let mut stats = stats.borrow_mut();
            if let Some(ticks) = start.elapsed(end) {
                stats.samples += 1;
                stats.ticks += ticks;
            } else {
                stats.dropped += 1;
            }
        });
    }
}
