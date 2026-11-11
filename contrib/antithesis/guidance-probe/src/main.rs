use antithesis_sdk::serde_json::json;
use guidance_probe::Probe;
use std::{
    env, fs,
    io::{self, Write},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

const CADENCE: Duration = Duration::from_millis(100);
const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(30);
static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

fn install_signals() -> io::Result<()> {
    // SAFETY: initialized sigaction, C ABI handler only stores a lock-free atomic.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = stop as *const () as usize;
        if libc::sigemptyset(&mut action.sa_mask) != 0 {
            return Err(io::Error::last_os_error());
        }
        for signal in [libc::SIGTERM, libc::SIGINT] {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

fn emit_guidance(label: &str) {
    antithesis_sdk::guidance_helper!(
        GuidanceType::Json,
        "Probe state shape",
        false,
        json!({"label": label})
    );
}

fn wait_for_activation(path: &Path, timeout: Duration, stop: &AtomicBool) -> io::Result<bool> {
    let started = Instant::now();
    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(false);
        }
        if path.try_exists()? {
            return Ok(true);
        }
        let remaining = timeout.checked_sub(started.elapsed()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "first_start_workload did not activate the probe",
            )
        })?;
        thread::sleep(CADENCE.min(remaining));
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    install_signals()?;
    // This executable is copied as the only first_ test command; no shell needed.
    if env::args().next().is_some_and(|p| {
        Path::new(&p)
            .file_name()
            .is_some_and(|n| n == "first_start_workload")
    }) {
        fs::write("/workload-active", b"active\n")?;
        return Ok(());
    }
    let dynamic = match env::var("PROBE_MODE").as_deref() {
        Ok("dynamic") => true,
        Ok("constant") => false,
        _ => return Err("PROBE_MODE must be dynamic or constant".into()),
    };
    let mut steps: Option<u64> = None;
    let mut tape_path = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--steps" => steps = Some(args.next().ok_or("missing --steps value")?.parse()?),
            "--tape" => tape_path = Some(args.next().ok_or("missing --tape path")?),
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }
    // Tape is an explicitly bounded local test facility, never used in launch configs.
    let tape = if let Some(path) = tape_path {
        let count = steps.ok_or("--tape requires --steps")?;
        let values = fs::read_to_string(path)?
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()?;
        if (values.len() as u64) < count {
            return Err("input tape shorter than --steps".into());
        }
        Some(values)
    } else {
        None
    };
    let mut probe = Probe::new(dynamic);
    antithesis_sdk::assert_always!(true, "Probe process healthy", &json!({}));
    antithesis_sdk::lifecycle::setup_complete(&json!({"probe": "json-guidance-ab-v1"}));
    // Wait for the first_ command after the root snapshot; bounded local tests skip it.
    if steps.is_none()
        && !wait_for_activation(Path::new("/workload-active"), ACTIVATION_TIMEOUT, &STOP)?
    {
        return Ok(());
    }
    let mut step = 0_u64;
    while !STOP.load(Ordering::Relaxed) && steps.is_none_or(|count| step < count) {
        // Each SDK draw is consumed immediately in the transition, never seeded/cached.
        let (state, label) = match &tape {
            Some(values) => probe.step(values[step as usize]),
            None => probe.step(antithesis_sdk::random::get_random()),
        };
        emit_guidance(label);
        // Ordinary stdout only: actual state is identical telemetry in both arms.
        println!("{{\"probe_step\":{step},\"actual_state\":{state}}}");
        io::stdout().flush()?;
        step = step.wrapping_add(1);
        // Yield after EVERY emission, including the final bounded test emission.
        thread::sleep(CADENCE);
    }
    Ok(())
}

fn main() {
    // SDK init registers guidance/assertion catalogs before any setup-complete call.
    antithesis_sdk::antithesis_init();
    if let Err(error) = run() {
        eprintln!("guidance-probe: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_activation_times_out() {
        let path = env::temp_dir().join(format!("guidance-probe-absent-{}", std::process::id()));
        assert!(!path.exists());
        let error =
            wait_for_activation(&path, Duration::ZERO, &AtomicBool::new(false)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            error.to_string(),
            "first_start_workload did not activate the probe"
        );
    }

    #[test]
    fn shutdown_interrupts_activation() {
        assert!(
            !wait_for_activation(Path::new("."), ACTIVATION_TIMEOUT, &AtomicBool::new(true))
                .unwrap()
        );
    }

    #[test]
    fn existing_activation_is_ready() {
        assert!(
            wait_for_activation(Path::new("."), ACTIVATION_TIMEOUT, &AtomicBool::new(false))
                .unwrap()
        );
    }
}
