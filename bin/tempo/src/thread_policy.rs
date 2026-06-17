//! Linux thread scheduling policy for latency-sensitive engine work.

use std::{fmt, str::FromStr, time::Duration};

use eyre::bail;

/// Command line arguments for the Linux thread policy supervisor.
#[derive(Debug, Clone, clap::Args)]
pub(crate) struct ThreadPolicyArgs {
    /// Enable the Linux thread policy supervisor.
    ///
    /// When enabled, Tempo periodically scans `/proc/self/task/*/comm` and
    /// applies scheduling policy by thread name. This covers threads created by
    /// dependencies where Tempo does not control the spawn site.
    #[arg(
        long = "thread-policy.enabled",
        default_value_t = false,
        env = "TEMPO_THREAD_POLICY_ENABLED"
    )]
    pub(crate) enabled: bool,

    /// Nice value for the engine thread. Requires CAP_SYS_NICE for negative values.
    #[arg(
        long = "thread-policy.engine-nice",
        default_value_t = -20,
        env = "TEMPO_THREAD_POLICY_ENGINE_NICE"
    )]
    pub(crate) engine_nice: i32,

    /// Scheduler policy for the engine thread.
    ///
    /// `fifo` and `rr` require CAP_SYS_NICE. Keep the priority conservative;
    /// Linux real-time scheduling can starve lower-priority work on the same CPU.
    #[arg(
        long = "thread-policy.engine-scheduler",
        default_value_t = SchedulerPolicy::Other,
        value_name = "POLICY",
        env = "TEMPO_THREAD_POLICY_ENGINE_SCHEDULER"
    )]
    pub(crate) engine_scheduler: SchedulerPolicy,

    /// Real-time scheduler priority for the engine thread when using `fifo` or `rr`.
    #[arg(
        long = "thread-policy.engine-priority",
        default_value_t = 10,
        env = "TEMPO_THREAD_POLICY_ENGINE_PRIORITY"
    )]
    pub(crate) engine_priority: i32,

    /// Nice value for the tx-iterator thread.
    ///
    /// When omitted, tx-iterator inherits `thread-policy.worker-nice`.
    #[arg(
        long = "thread-policy.tx-iterator-nice",
        value_name = "NICE",
        env = "TEMPO_THREAD_POLICY_TX_ITERATOR_NICE"
    )]
    pub(crate) tx_iterator_nice: Option<i32>,

    /// Scheduler policy for the tx-iterator thread.
    ///
    /// This thread feeds validated transactions back to engine execution, so
    /// engine latency can depend directly on how quickly it runs after wakeup.
    #[arg(
        long = "thread-policy.tx-iterator-scheduler",
        default_value_t = SchedulerPolicy::Other,
        value_name = "POLICY",
        env = "TEMPO_THREAD_POLICY_TX_ITERATOR_SCHEDULER"
    )]
    pub(crate) tx_iterator_scheduler: SchedulerPolicy,

    /// Real-time scheduler priority for tx-iterator when using `fifo` or `rr`.
    ///
    /// When omitted, this defaults to one below `thread-policy.engine-priority`.
    #[arg(
        long = "thread-policy.tx-iterator-priority",
        value_name = "PRIORITY",
        env = "TEMPO_THREAD_POLICY_TX_ITERATOR_PRIORITY"
    )]
    pub(crate) tx_iterator_priority: Option<i32>,

    /// Nice value for the payload-builder thread.
    ///
    /// When omitted, payload-builder inherits `thread-policy.worker-nice`.
    #[arg(
        long = "thread-policy.payload-builder-nice",
        value_name = "NICE",
        env = "TEMPO_THREAD_POLICY_PAYLOAD_BUILDER_NICE"
    )]
    pub(crate) payload_builder_nice: Option<i32>,

    /// Scheduler policy for the payload-builder thread.
    ///
    /// This thread builds execution payloads and can sit in the wakeup path for
    /// consensus-visible block production latency.
    #[arg(
        long = "thread-policy.payload-builder-scheduler",
        default_value_t = SchedulerPolicy::Other,
        value_name = "POLICY",
        env = "TEMPO_THREAD_POLICY_PAYLOAD_BUILDER_SCHEDULER"
    )]
    pub(crate) payload_builder_scheduler: SchedulerPolicy,

    /// Real-time scheduler priority for payload-builder when using `fifo` or `rr`.
    ///
    /// When omitted, this defaults to two below `thread-policy.engine-priority`.
    #[arg(
        long = "thread-policy.payload-builder-priority",
        value_name = "PRIORITY",
        env = "TEMPO_THREAD_POLICY_PAYLOAD_BUILDER_PRIORITY"
    )]
    pub(crate) payload_builder_priority: Option<i32>,

    /// Nice value for payload prewarming coordinator and worker threads.
    ///
    /// When omitted, prewarming threads inherit `thread-policy.worker-nice`.
    #[arg(
        long = "thread-policy.prewarm-nice",
        value_name = "NICE",
        env = "TEMPO_THREAD_POLICY_PREWARM_NICE"
    )]
    pub(crate) prewarm_nice: Option<i32>,

    /// Scheduler policy for payload prewarming coordinator and worker threads.
    ///
    /// These threads feed warmed transactions back to payload-builder, so
    /// payload-builder latency can depend on how quickly they run after wakeup.
    #[arg(
        long = "thread-policy.prewarm-scheduler",
        default_value_t = SchedulerPolicy::Other,
        value_name = "POLICY",
        env = "TEMPO_THREAD_POLICY_PREWARM_SCHEDULER"
    )]
    pub(crate) prewarm_scheduler: SchedulerPolicy,

    /// Real-time scheduler priority for prewarming threads when using `fifo` or `rr`.
    ///
    /// When omitted, this defaults to three below `thread-policy.engine-priority`.
    #[arg(
        long = "thread-policy.prewarm-priority",
        value_name = "PRIORITY",
        env = "TEMPO_THREAD_POLICY_PREWARM_PRIORITY"
    )]
    pub(crate) prewarm_priority: Option<i32>,

    /// Nice value for background execution and builder worker threads.
    #[arg(
        long = "thread-policy.worker-nice",
        default_value_t = 5,
        env = "TEMPO_THREAD_POLICY_WORKER_NICE"
    )]
    pub(crate) worker_nice: i32,

    /// Optional CPU list for the engine thread, for example `0` or `0-1`.
    #[arg(
        long = "thread-policy.engine-cpus",
        value_name = "CPUS",
        env = "TEMPO_THREAD_POLICY_ENGINE_CPUS"
    )]
    pub(crate) engine_cpus: Option<CpuList>,

    /// Optional CPU list for tx-iterator.
    ///
    /// When omitted, tx-iterator inherits `thread-policy.worker-cpus`.
    #[arg(
        long = "thread-policy.tx-iterator-cpus",
        value_name = "CPUS",
        env = "TEMPO_THREAD_POLICY_TX_ITERATOR_CPUS"
    )]
    pub(crate) tx_iterator_cpus: Option<CpuList>,

    /// Optional CPU list for payload-builder.
    ///
    /// When omitted, payload-builder inherits `thread-policy.worker-cpus`.
    #[arg(
        long = "thread-policy.payload-builder-cpus",
        value_name = "CPUS",
        env = "TEMPO_THREAD_POLICY_PAYLOAD_BUILDER_CPUS"
    )]
    pub(crate) payload_builder_cpus: Option<CpuList>,

    /// Optional CPU list for payload prewarming coordinator and worker threads.
    ///
    /// When omitted, prewarming threads inherit `thread-policy.worker-cpus`.
    #[arg(
        long = "thread-policy.prewarm-cpus",
        value_name = "CPUS",
        env = "TEMPO_THREAD_POLICY_PREWARM_CPUS"
    )]
    pub(crate) prewarm_cpus: Option<CpuList>,

    /// Optional CPU list for background execution and builder worker threads.
    #[arg(
        long = "thread-policy.worker-cpus",
        value_name = "CPUS",
        env = "TEMPO_THREAD_POLICY_WORKER_CPUS"
    )]
    pub(crate) worker_cpus: Option<CpuList>,

    /// Thread policy scan interval in milliseconds.
    #[arg(
        long = "thread-policy.scan-interval-ms",
        default_value_t = 250,
        env = "TEMPO_THREAD_POLICY_SCAN_INTERVAL_MS"
    )]
    pub(crate) scan_interval_ms: u64,
}

impl ThreadPolicyArgs {
    fn validate(&self) -> eyre::Result<()> {
        validate_nice("thread-policy.engine-nice", self.engine_nice)?;
        if let Some(tx_iterator_nice) = self.tx_iterator_nice {
            validate_nice("thread-policy.tx-iterator-nice", tx_iterator_nice)?;
        }
        if let Some(payload_builder_nice) = self.payload_builder_nice {
            validate_nice("thread-policy.payload-builder-nice", payload_builder_nice)?;
        }
        if let Some(prewarm_nice) = self.prewarm_nice {
            validate_nice("thread-policy.prewarm-nice", prewarm_nice)?;
        }
        validate_nice("thread-policy.worker-nice", self.worker_nice)?;
        if self.engine_scheduler.is_realtime() && !(1..=99).contains(&self.engine_priority) {
            bail!(
                "thread-policy.engine-priority must be between 1 and 99 for {}, got {}",
                self.engine_scheduler,
                self.engine_priority
            );
        }

        if self.tx_iterator_scheduler.is_realtime() {
            let tx_iterator_priority = self.tx_iterator_realtime_priority();
            if !(1..=99).contains(&tx_iterator_priority) {
                bail!(
                    "thread-policy.tx-iterator-priority must be between 1 and 99 for {}, got {}",
                    self.tx_iterator_scheduler,
                    tx_iterator_priority
                );
            }
        }

        if self.payload_builder_scheduler.is_realtime() {
            let payload_builder_priority = self.payload_builder_realtime_priority();
            if !(1..=99).contains(&payload_builder_priority) {
                bail!(
                    "thread-policy.payload-builder-priority must be between 1 and 99 for {}, got {}",
                    self.payload_builder_scheduler,
                    payload_builder_priority
                );
            }
        }

        if self.prewarm_scheduler.is_realtime() {
            let prewarm_priority = self.prewarm_realtime_priority();
            if !(1..=99).contains(&prewarm_priority) {
                bail!(
                    "thread-policy.prewarm-priority must be between 1 and 99 for {}, got {}",
                    self.prewarm_scheduler,
                    prewarm_priority
                );
            }
        }

        if self.scan_interval_ms == 0 {
            bail!("thread-policy.scan-interval-ms must be greater than zero");
        }

        Ok(())
    }

    fn scan_interval(&self) -> Duration {
        Duration::from_millis(self.scan_interval_ms)
    }

    fn tx_iterator_nice(&self) -> i32 {
        self.tx_iterator_nice.unwrap_or(self.worker_nice)
    }

    fn tx_iterator_realtime_priority(&self) -> i32 {
        self.tx_iterator_priority
            .unwrap_or_else(|| (self.engine_priority - 1).max(1))
    }

    fn payload_builder_nice(&self) -> i32 {
        self.payload_builder_nice.unwrap_or(self.worker_nice)
    }

    fn payload_builder_realtime_priority(&self) -> i32 {
        self.payload_builder_priority
            .unwrap_or_else(|| (self.engine_priority - 2).max(1))
    }

    fn prewarm_nice(&self) -> i32 {
        self.prewarm_nice.unwrap_or(self.worker_nice)
    }

    fn prewarm_realtime_priority(&self) -> i32 {
        self.prewarm_priority
            .unwrap_or_else(|| (self.engine_priority - 3).max(1))
    }
}

/// Linux scheduler policy for a classified thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SchedulerPolicy {
    Other,
    Fifo,
    RoundRobin,
}

impl SchedulerPolicy {
    fn is_realtime(self) -> bool {
        matches!(self, Self::Fifo | Self::RoundRobin)
    }

    #[cfg(target_os = "linux")]
    fn to_linux(self) -> libc::c_int {
        match self {
            Self::Other => libc::SCHED_OTHER,
            Self::Fifo => libc::SCHED_FIFO,
            Self::RoundRobin => libc::SCHED_RR,
        }
    }
}

impl fmt::Display for SchedulerPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Other => "other",
            Self::Fifo => "fifo",
            Self::RoundRobin => "rr",
        })
    }
}

impl FromStr for SchedulerPolicy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "other" | "normal" | "cfs" => Ok(Self::Other),
            "fifo" => Ok(Self::Fifo),
            "rr" | "round-robin" | "roundrobin" => Ok(Self::RoundRobin),
            value => Err(format!(
                "invalid scheduler policy '{value}', expected other, fifo, or rr"
            )),
        }
    }
}

/// A parsed Linux CPU list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CpuList {
    cpus: Vec<usize>,
}

impl CpuList {
    fn cpus(&self) -> &[usize] {
        &self.cpus
    }
}

impl fmt::Display for CpuList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (idx, cpu) in self.cpus.iter().enumerate() {
            if idx > 0 {
                f.write_str(",")?;
            }
            write!(f, "{cpu}")?;
        }
        Ok(())
    }
}

impl FromStr for CpuList {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut cpus = Vec::new();

        for item in value.split(',') {
            let item = item.trim();
            if item.is_empty() {
                return Err("CPU list contains an empty item".to_string());
            }

            if let Some((start, end)) = item.split_once('-') {
                let start = parse_cpu(start)?;
                let end = parse_cpu(end)?;
                if start > end {
                    return Err(format!("invalid CPU range {start}-{end}"));
                }
                cpus.extend(start..=end);
            } else {
                cpus.push(parse_cpu(item)?);
            }
        }

        cpus.sort_unstable();
        cpus.dedup();

        if cpus.is_empty() {
            return Err("CPU list must contain at least one CPU".to_string());
        }

        Ok(Self { cpus })
    }
}

fn parse_cpu(value: &str) -> Result<usize, String> {
    value
        .trim()
        .parse::<usize>()
        .map_err(|err| format!("invalid CPU '{value}': {err}"))
}

fn validate_nice(name: &str, value: i32) -> eyre::Result<()> {
    if !(-20..=19).contains(&value) {
        bail!("{name} must be between -20 and 19, got {value}");
    }
    Ok(())
}

/// Handle for the background thread policy supervisor.
#[cfg(target_os = "linux")]
pub(crate) type ThreadPolicyHandle = linux::ThreadPolicyHandle;

/// Handle for the background thread policy supervisor.
#[cfg(not(target_os = "linux"))]
pub(crate) struct ThreadPolicyHandle;

/// Starts the thread policy supervisor when enabled.
pub(crate) fn spawn(args: ThreadPolicyArgs) -> eyre::Result<Option<ThreadPolicyHandle>> {
    if !args.enabled {
        return Ok(None);
    }

    args.validate()?;

    #[cfg(target_os = "linux")]
    {
        Ok(Some(linux::spawn(args)?))
    }

    #[cfg(not(target_os = "linux"))]
    {
        tracing::warn!(
            "thread policy supervisor is only supported on Linux; ignoring configuration"
        );
        Ok(None)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThreadClass {
    Engine,
    PayloadBuilder,
    Prewarm,
    TxIterator,
    Worker,
}

fn classify_thread(comm: &str) -> Option<ThreadClass> {
    let comm = comm.trim();

    if comm == "engine" || comm.starts_with("engine-") {
        return Some(ThreadClass::Engine);
    }

    if comm == "tx-iterator" {
        return Some(ThreadClass::TxIterator);
    }

    if comm == "payload-builder" {
        return Some(ThreadClass::PayloadBuilder);
    }

    if is_prewarm_thread(comm) {
        return Some(ThreadClass::Prewarm);
    }

    if is_worker_thread(comm) {
        return Some(ThreadClass::Worker);
    }

    None
}

fn is_prewarm_thread(comm: &str) -> bool {
    comm == "builder-prewarm" || comm == "prewarm" || comm.starts_with("prewarm-")
}

fn is_worker_thread(comm: &str) -> bool {
    const EXACT: &[&str] = &[
        "account-workers",
        "deferred-trie",
        "drop",
        "hash-post-state",
        "payload-convert",
        "receipt-root",
        "sparse-trie",
        "storage-workers",
        "trie-hashing",
    ];
    const TRUNCATED: &[&str] = &["builder-bal-tas", "builder-roots-t"];
    const PREFIXES: &[&str] = &[
        "builder-",
        "cpu-",
        "proof-acct-",
        "proof-strg-",
        "rayon-",
        "state-ovly-",
        "txgen-sign-",
    ];

    EXACT.contains(&comm)
        || TRUNCATED.contains(&comm)
        || PREFIXES.iter().any(|prefix| comm.starts_with(prefix))
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        collections::{HashMap, HashSet},
        fs, mem,
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread::{self, JoinHandle},
    };

    use eyre::WrapErr as _;
    use tracing::{debug, info, warn};

    use super::{CpuList, SchedulerPolicy, ThreadClass, ThreadPolicyArgs, classify_thread};

    /// Handle for the background thread policy supervisor.
    pub(crate) struct ThreadPolicyHandle {
        stop: Arc<AtomicBool>,
        join: Option<JoinHandle<()>>,
    }

    impl Drop for ThreadPolicyHandle {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);

            if let Some(join) = self.join.take()
                && let Err(unwind) = join.join()
            {
                debug!(?unwind, "thread policy supervisor panicked during shutdown");
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct DesiredPolicy {
        class: ThreadClass,
        scheduler: SchedulerPolicy,
        reset_on_fork: bool,
        priority: i32,
        nice: i32,
        cpus: Option<CpuList>,
    }

    pub(crate) fn spawn(args: ThreadPolicyArgs) -> eyre::Result<ThreadPolicyHandle> {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();

        let join = thread::Builder::new()
            .name("thread-policy".to_string())
            .spawn(move || run(args, thread_stop))
            .wrap_err("failed spawning thread policy supervisor")?;

        Ok(ThreadPolicyHandle {
            stop,
            join: Some(join),
        })
    }

    fn run(args: ThreadPolicyArgs, stop: Arc<AtomicBool>) {
        info!(
            engine_nice = args.engine_nice,
            engine_scheduler = %args.engine_scheduler,
            engine_priority = args.engine_priority,
            tx_iterator_nice = args.tx_iterator_nice(),
            tx_iterator_scheduler = %args.tx_iterator_scheduler,
            tx_iterator_priority = if args.tx_iterator_scheduler.is_realtime() {
                args.tx_iterator_realtime_priority()
            } else {
                0
            },
            payload_builder_nice = args.payload_builder_nice(),
            payload_builder_scheduler = %args.payload_builder_scheduler,
            payload_builder_priority = if args.payload_builder_scheduler.is_realtime() {
                args.payload_builder_realtime_priority()
            } else {
                0
            },
            prewarm_nice = args.prewarm_nice(),
            prewarm_scheduler = %args.prewarm_scheduler,
            prewarm_priority = if args.prewarm_scheduler.is_realtime() {
                args.prewarm_realtime_priority()
            } else {
                0
            },
            worker_nice = args.worker_nice,
            engine_cpus = args.engine_cpus.as_ref().map(ToString::to_string),
            tx_iterator_cpus = args
                .tx_iterator_cpus
                .as_ref()
                .or(args.worker_cpus.as_ref())
                .map(ToString::to_string),
            payload_builder_cpus = args
                .payload_builder_cpus
                .as_ref()
                .or(args.worker_cpus.as_ref())
                .map(ToString::to_string),
            prewarm_cpus = args
                .prewarm_cpus
                .as_ref()
                .or(args.worker_cpus.as_ref())
                .map(ToString::to_string),
            worker_cpus = args.worker_cpus.as_ref().map(ToString::to_string),
            scan_interval_ms = args.scan_interval_ms,
            "started thread policy supervisor"
        );

        let mut attempted = HashMap::new();
        let mut scan_failed = false;

        while !stop.load(Ordering::Relaxed) {
            match scan_once(&args, &mut attempted) {
                Ok(()) => scan_failed = false,
                Err(err) => {
                    if !scan_failed {
                        warn!(%err, "thread policy scan failed");
                    }
                    scan_failed = true;
                }
            }

            thread::sleep(args.scan_interval());
        }
    }

    fn scan_once(
        args: &ThreadPolicyArgs,
        attempted: &mut HashMap<libc::pid_t, DesiredPolicy>,
    ) -> eyre::Result<()> {
        let mut seen = HashSet::new();

        for entry in fs::read_dir("/proc/self/task").wrap_err("failed reading /proc/self/task")? {
            let entry = entry.wrap_err("failed reading /proc/self/task entry")?;
            let Some(tid) = parse_tid(&entry.file_name()) else {
                continue;
            };

            let comm = match read_comm(&entry.path()) {
                Ok(comm) => comm,
                Err(err) => {
                    debug!(tid, %err, "failed reading thread comm");
                    continue;
                }
            };

            let Some(class) = classify_thread(&comm) else {
                continue;
            };

            let desired = desired_policy(args, class);
            seen.insert(tid);

            if attempted.get(&tid) == Some(&desired) {
                continue;
            }

            match apply_policy(tid, &desired) {
                Ok(()) => {
                    info!(
                        tid,
                        comm = comm.trim(),
                        class = ?desired.class,
                        scheduler = %desired.scheduler,
                        reset_on_fork = desired.reset_on_fork,
                        priority = desired.priority,
                        nice = desired.nice,
                        cpus = desired.cpus.as_ref().map(ToString::to_string),
                        "applied thread policy"
                    );
                }
                Err(err) => {
                    warn!(
                        tid,
                        comm = comm.trim(),
                        class = ?desired.class,
                        scheduler = %desired.scheduler,
                        reset_on_fork = desired.reset_on_fork,
                        priority = desired.priority,
                        nice = desired.nice,
                        cpus = desired.cpus.as_ref().map(ToString::to_string),
                        %err,
                        "failed applying thread policy"
                    );
                }
            }

            attempted.insert(tid, desired);
        }

        attempted.retain(|tid, _| seen.contains(tid));

        Ok(())
    }

    fn parse_tid(value: &std::ffi::OsStr) -> Option<libc::pid_t> {
        value.to_str()?.parse().ok()
    }

    fn read_comm(task_dir: &Path) -> std::io::Result<String> {
        fs::read_to_string(task_dir.join("comm"))
    }

    fn desired_policy(args: &ThreadPolicyArgs, class: ThreadClass) -> DesiredPolicy {
        match class {
            ThreadClass::Engine => DesiredPolicy {
                class,
                scheduler: args.engine_scheduler,
                reset_on_fork: args.engine_scheduler.is_realtime(),
                priority: if args.engine_scheduler.is_realtime() {
                    args.engine_priority
                } else {
                    0
                },
                nice: args.engine_nice,
                cpus: args.engine_cpus.clone(),
            },
            ThreadClass::TxIterator => DesiredPolicy {
                class,
                scheduler: args.tx_iterator_scheduler,
                reset_on_fork: args.tx_iterator_scheduler.is_realtime(),
                priority: if args.tx_iterator_scheduler.is_realtime() {
                    args.tx_iterator_realtime_priority()
                } else {
                    0
                },
                nice: args.tx_iterator_nice(),
                cpus: args
                    .tx_iterator_cpus
                    .clone()
                    .or_else(|| args.worker_cpus.clone()),
            },
            ThreadClass::PayloadBuilder => DesiredPolicy {
                class,
                scheduler: args.payload_builder_scheduler,
                reset_on_fork: args.payload_builder_scheduler.is_realtime(),
                priority: if args.payload_builder_scheduler.is_realtime() {
                    args.payload_builder_realtime_priority()
                } else {
                    0
                },
                nice: args.payload_builder_nice(),
                cpus: args
                    .payload_builder_cpus
                    .clone()
                    .or_else(|| args.worker_cpus.clone()),
            },
            ThreadClass::Prewarm => DesiredPolicy {
                class,
                scheduler: args.prewarm_scheduler,
                reset_on_fork: args.prewarm_scheduler.is_realtime(),
                priority: if args.prewarm_scheduler.is_realtime() {
                    args.prewarm_realtime_priority()
                } else {
                    0
                },
                nice: args.prewarm_nice(),
                cpus: args
                    .prewarm_cpus
                    .clone()
                    .or_else(|| args.worker_cpus.clone()),
            },
            ThreadClass::Worker => DesiredPolicy {
                class,
                scheduler: SchedulerPolicy::Other,
                reset_on_fork: false,
                priority: 0,
                nice: args.worker_nice,
                cpus: args.worker_cpus.clone(),
            },
        }
    }

    fn apply_policy(tid: libc::pid_t, policy: &DesiredPolicy) -> Result<(), String> {
        let mut errors = Vec::new();

        if let Err(err) = set_scheduler(tid, policy) {
            errors.push(err);
        }

        if unsafe { libc::setpriority(libc::PRIO_PROCESS, tid as libc::id_t, policy.nice) } == -1 {
            errors.push(format!(
                "setpriority failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        if let Some(cpus) = &policy.cpus
            && let Err(err) = set_affinity(tid, cpus)
        {
            errors.push(err);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    fn set_scheduler(tid: libc::pid_t, policy: &DesiredPolicy) -> Result<(), String> {
        let param = libc::sched_param {
            sched_priority: policy.priority,
        };
        let mut scheduler = policy.scheduler.to_linux();
        if policy.reset_on_fork {
            scheduler |= libc::SCHED_RESET_ON_FORK;
        }

        if unsafe { libc::sched_setscheduler(tid, scheduler, &param) } == -1 {
            return Err(format!(
                "sched_setscheduler({}, reset_on_fork {}, priority {}) failed: {}",
                policy.scheduler,
                policy.reset_on_fork,
                policy.priority,
                std::io::Error::last_os_error()
            ));
        }

        Ok(())
    }

    fn set_affinity(tid: libc::pid_t, cpus: &CpuList) -> Result<(), String> {
        let mut set = new_cpu_set(cpus)?;

        if unsafe {
            libc::sched_setaffinity(
                tid,
                mem::size_of::<libc::cpu_set_t>(),
                &mut set as *mut libc::cpu_set_t,
            )
        } == -1
        {
            return Err(format!(
                "sched_setaffinity failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(())
    }

    fn new_cpu_set(cpus: &CpuList) -> Result<libc::cpu_set_t, String> {
        let mut set = unsafe { mem::zeroed::<libc::cpu_set_t>() };
        unsafe { libc::CPU_ZERO(&mut set) };

        for &cpu in cpus.cpus() {
            if cpu >= libc::CPU_SETSIZE as usize {
                return Err(format!(
                    "CPU {cpu} is outside libc CPU_SETSIZE {}",
                    libc::CPU_SETSIZE
                ));
            }
            unsafe { libc::CPU_SET(cpu, &mut set) };
        }

        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    use super::{CpuList, SchedulerPolicy, ThreadClass, ThreadPolicyArgs, classify_thread};

    #[test]
    fn cpu_list_parses_ranges_and_deduplicates() {
        let cpus = "3,1-2,2".parse::<CpuList>().unwrap();
        assert_eq!(cpus.cpus(), &[1, 2, 3]);
        assert_eq!(cpus.to_string(), "1,2,3");
    }

    #[test]
    fn cpu_list_rejects_bad_ranges() {
        assert!("3-1".parse::<CpuList>().is_err());
        assert!("1,,2".parse::<CpuList>().is_err());
        assert!("".parse::<CpuList>().is_err());
    }

    #[test]
    fn thread_names_are_classified() {
        assert_eq!(classify_thread("engine\n"), Some(ThreadClass::Engine));
        assert_eq!(
            classify_thread("tx-iterator"),
            Some(ThreadClass::TxIterator)
        );
        assert_eq!(
            classify_thread("payload-builder"),
            Some(ThreadClass::PayloadBuilder)
        );
        assert_eq!(
            classify_thread("builder-prewarm"),
            Some(ThreadClass::Prewarm)
        );
        assert_eq!(classify_thread("prewarm"), Some(ThreadClass::Prewarm));
        assert_eq!(classify_thread("prewarm-15"), Some(ThreadClass::Prewarm));
        assert_eq!(classify_thread("prewarm-txs"), Some(ThreadClass::Prewarm));
        assert_eq!(classify_thread("cpu-09"), Some(ThreadClass::Worker));
        assert_eq!(classify_thread("deferred-trie"), Some(ThreadClass::Worker));
        assert_eq!(classify_thread("drop"), Some(ThreadClass::Worker));
        assert_eq!(
            classify_thread("hash-post-state"),
            Some(ThreadClass::Worker)
        );
        assert_eq!(
            classify_thread("payload-convert"),
            Some(ThreadClass::Worker)
        );
        assert_eq!(classify_thread("state-ovly-00"), Some(ThreadClass::Worker));
        assert_eq!(
            classify_thread("storage-workers"),
            Some(ThreadClass::Worker)
        );
        assert_eq!(
            classify_thread("builder-roots-t"),
            Some(ThreadClass::Worker)
        );
        assert_eq!(classify_thread("proof-strg-0"), Some(ThreadClass::Worker));
        assert_eq!(classify_thread("tokio-rt"), None);
    }

    #[test]
    fn scheduler_policy_parses_aliases() {
        assert_eq!(
            "other".parse::<SchedulerPolicy>().unwrap(),
            SchedulerPolicy::Other
        );
        assert_eq!(
            "fifo".parse::<SchedulerPolicy>().unwrap(),
            SchedulerPolicy::Fifo
        );
        assert_eq!(
            "rr".parse::<SchedulerPolicy>().unwrap(),
            SchedulerPolicy::RoundRobin
        );
        assert_eq!(
            "round-robin".parse::<SchedulerPolicy>().unwrap(),
            SchedulerPolicy::RoundRobin
        );
        assert!("batch".parse::<SchedulerPolicy>().is_err());
    }

    #[test]
    fn realtime_scheduler_priority_is_validated() {
        let mut args = ThreadPolicyArgs {
            enabled: true,
            engine_nice: -20,
            engine_scheduler: SchedulerPolicy::Fifo,
            engine_priority: 10,
            tx_iterator_nice: None,
            tx_iterator_scheduler: SchedulerPolicy::Other,
            tx_iterator_priority: None,
            payload_builder_nice: None,
            payload_builder_scheduler: SchedulerPolicy::Other,
            payload_builder_priority: None,
            prewarm_nice: None,
            prewarm_scheduler: SchedulerPolicy::Other,
            prewarm_priority: None,
            worker_nice: 5,
            engine_cpus: None,
            tx_iterator_cpus: None,
            payload_builder_cpus: None,
            prewarm_cpus: None,
            worker_cpus: None,
            scan_interval_ms: 250,
        };

        assert!(args.validate().is_ok());
        args.engine_priority = 0;
        assert!(args.validate().is_err());
        args.engine_scheduler = SchedulerPolicy::Other;
        assert!(args.validate().is_ok());

        args.tx_iterator_scheduler = SchedulerPolicy::Fifo;
        args.tx_iterator_priority = Some(0);
        assert!(args.validate().is_err());
        args.tx_iterator_priority = Some(9);
        assert!(args.validate().is_ok());

        args.payload_builder_scheduler = SchedulerPolicy::Fifo;
        args.payload_builder_priority = Some(0);
        assert!(args.validate().is_err());
        args.payload_builder_priority = Some(8);
        assert!(args.validate().is_ok());

        args.prewarm_scheduler = SchedulerPolicy::Fifo;
        args.prewarm_priority = Some(0);
        assert!(args.validate().is_err());
        args.prewarm_priority = Some(7);
        assert!(args.validate().is_ok());
    }
}
