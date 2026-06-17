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
        validate_nice("thread-policy.worker-nice", self.worker_nice)?;
        if self.engine_scheduler.is_realtime() && !(1..=99).contains(&self.engine_priority) {
            bail!(
                "thread-policy.engine-priority must be between 1 and 99 for {}, got {}",
                self.engine_scheduler,
                self.engine_priority
            );
        }

        if self.scan_interval_ms == 0 {
            bail!("thread-policy.scan-interval-ms must be greater than zero");
        }

        Ok(())
    }

    fn scan_interval(&self) -> Duration {
        Duration::from_millis(self.scan_interval_ms)
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
    Worker,
}

fn classify_thread(comm: &str) -> Option<ThreadClass> {
    let comm = comm.trim();

    if comm == "engine" || comm.starts_with("engine-") {
        return Some(ThreadClass::Engine);
    }

    if is_worker_thread(comm) {
        return Some(ThreadClass::Worker);
    }

    None
}

fn is_worker_thread(comm: &str) -> bool {
    const EXACT: &[&str] = &[
        "account-workers",
        "builder-prewarm",
        "deferred-trie",
        "payload-builder",
        "payload-convert",
        "prewarm",
        "receipt-root",
        "sparse-trie",
        "trie-hashing",
        "tx-iterator",
    ];
    const TRUNCATED: &[&str] = &["builder-bal-tas", "builder-roots-t"];
    const PREFIXES: &[&str] = &[
        "builder-",
        "cpu-",
        "prewarm-",
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
            worker_nice = args.worker_nice,
            engine_cpus = args.engine_cpus.as_ref().map(ToString::to_string),
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
        assert_eq!(classify_thread("cpu-09"), Some(ThreadClass::Worker));
        assert_eq!(classify_thread("prewarm"), Some(ThreadClass::Worker));
        assert_eq!(
            classify_thread("payload-builder"),
            Some(ThreadClass::Worker)
        );
        assert_eq!(classify_thread("deferred-trie"), Some(ThreadClass::Worker));
        assert_eq!(
            classify_thread("payload-convert"),
            Some(ThreadClass::Worker)
        );
        assert_eq!(classify_thread("state-ovly-00"), Some(ThreadClass::Worker));
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
            worker_nice: 5,
            engine_cpus: None,
            worker_cpus: None,
            scan_interval_ms: 250,
        };

        assert!(args.validate().is_ok());
        args.engine_priority = 0;
        assert!(args.validate().is_err());
        args.engine_scheduler = SchedulerPolicy::Other;
        assert!(args.validate().is_ok());
    }
}
