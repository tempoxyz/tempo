# Opt-in scheduler diagnostic

`profiling=lifecycle-scheduler` adds anonymous scheduler context to full lifecycle capture. It is an isolated diagnostic, disabled by default. It changes observation overhead and must not be compared as if it were an ordinary performance run. No kernel stack, syscall, file, network payload, address, command name, native PID or native TID is exported.

The runner must have passwordless root access, Python, bpftrace, BTF, readable scheduler tracepoints, GCC, Rust and objdump. Preflight deliberately fails closed when capabilities or the scheduler state format differ from the tested format. It does not change perf sysctls or install tools. Local proof used bpftrace 0.20.2 on Linux 6.8. `perf` was unavailable for the running kernel, so this implementation does not depend on it.

Run the isolated proof without launching validators:

```sh
python3 contrib/bench/lifecycle/scheduler/diagnostic.py --output /tmp/scheduler-proof.json
python3 -m unittest discover -s contrib/bench/lifecycle/scheduler
```

The proof verifies that the monotonic BPF helper is used (bare `nsecs` has a different clock), checks C and Rust registration calls survive optimized/LTO compilation, and runs three synthetic threads with blocked and runnable intervals. Its events after a synthetic cutoff are kept only in private memory and removed before writing the sanitized result. It does not prove that a particular validator binary or runner can be traced; the runtime repeats capability and marker-call checks against the actual binary.

For a local benchmark, pass `--lifecycle --lifecycle-scheduler` to `bench-e2e.nu e2e`. The runtime requires full detail. An instrumented binary must advertise `scheduler=registered_threads_v1` in its lifecycle header. The hook is enabled only by `TEMPO_LIFECYCLE_SCHEDULER=registered_threads_v1`, and receives only the collector thread ordinal and private phase epoch. A `black_box` operation prevents elimination of the hook; presence of the symbol alone is insufficient, so preflight verifies an actual call in the final binary.

Each validator has its own BPF supervisor. The pinned [bpftrace attach/run order](https://github.com/bpftrace/bpftrace/blob/v0.20.2/src/bpftrace.cpp#L1223-L1265) starts the child only after attachment; its [child implementation](https://github.com/bpftrace/bpftrace/blob/v0.20.2/src/child.cpp#L132-L158) waits on a private event before exec. It launches one stopped child, attaches before execution, and uses `exec` to retain that process incarnation through the shell and CPU affinity wrapper. Admission is sealed at the leader’s kernel exit before its PID can be reaped or reused; late registration after leader exit is unsupported and fails source-coverage checks. Admission checks the child process and the phase epoch. Kernel mapping keys contain that process plus native TID; `sched_process_exit` removes a thread before the TID can be reused. Ordinals never repeat in a process. The two validators are separate anonymous process namespaces in the exported traces. No arbitrary existing process, forked subprocess or late attachment is supported.

The launch command is carried in a memory-only memfd script, not a temporary command file. This also avoids bpftrace 0.20.2's `-c` quoting limitation. BPF output, including unexpected diagnostics or map dumps, is drained into bounded private memory; core dumps are disabled. There is no raw perf file or native identity mapping file. Any tool diagnostic, lost event/count mismatch, missing registration, missing exit, malformed event, map-helper error or memory limit failure rejects the scheduler diagnostic. No automatic fallback presents incomplete data as a complete capture.

After both lifecycle footers are present, the supervisor recomputes the earliest backpressure boundary from both final source streams and the load window. Every at/post-cutoff event is discarded. Closed intervals end at most one nanosecond before that cutoff, with zero-width results discarded; unclosed intervals are excluded, never extended to an invented endpoint. Without backpressure, the diagnostic ends at the load-window end. Report publication rechecks the exact cutoff, schema, process namespace and source-thread registrations before copying either scheduler source into the artifact.

Open `scheduler.html` in the downloaded artifact. Its Perfetto files combine existing block lifecycle lanes with anonymous scheduler tracks during each block's lifecycle. The percentile links select exactly the same actual complete blocks as the ordinary report. Focus clipping is explicitly marked separately from cutoff censoring. `scheduler-a.json`, `scheduler-b.json` and `scheduler-summary.json` retain all sanitized scheduler intervals and quality information, including times outside individual block windows.

Interpret the states conservatively:

- `scheduled_on_cpu` is scheduler residency, including kernel execution and interrupts. It is not a measurement of user/task CPU time.
- `runnable_off_cpu` is a preempted/runnable thread waiting to be scheduled.
- A blocked interval splits into `blocked_before_wakeup` and `runnable_after_wakeup` only when the corresponding wakeup and switch-in are observed. A missing wakeup remains `off_cpu_unsplit` and makes completeness false.
- Time before thread registration, missing edges, unclosed intervals and threads that never emit lifecycle records are unavailable. First source timestamps can precede their registration hook; the summary counts those records and their maximum gap.
- Ordinals allow intersection with raw lifecycle `enter`/`exit` windows. A span's creation thread or reference lifetime alone does not establish ownership of an async task, and awaiting tasks without a thread have no scheduler attribution. This first report therefore labels scheduler tracks as temporal context, not block causality.
- Thread totals and overlapping scopes are not additive critical-path time. This diagnostic distinguishes scheduling states, not the reason for a blocked wait or an optimization opportunity.

All ordinary lifecycle privacy, stop-at-first-backpressure, snapshot-reset and artifact-isolation paths remain active. No production scheduling, persistence, chunk-size, consensus or durability behavior is changed.
The release marker check accepts a direct call or an x86-64 RIP-relative indirect
call through a GOT slot whose ELF relocation points exactly to the marker. An
unused marker symbol alone does not pass. Startup failures expose only fixed
categories (`configuration`, `capability`, `marker`, `capture`, `cutoff`, `decode`,
`publish`) and fixed subcategories for buffer limits, source footer/integrity,
tool exit/diagnostics, schema, clock, registration/exit, and missing switch edges.
Both startup and report finalization expose this closed vocabulary; unknown
exception text or file contents cannot become a category. Private tool output
and commands are never printed. Any such failure still rejects scheduler data.

This experimental transport pairs switch-out and switch-in deliveries while
preserving both original timestamps, the switch-out state and the count of each
original edge. Wakeups and migrations remain independent. Pending or duplicate
switch-outs are emitted separately; missing edges still fail strict validation.
The decoder expands pairs before applying the unchanged source cutoff and
artifact schema. This reduces delivery count but does not establish loss-free
capacity: a sustained 153-thread synthetic stress still overflowed the BPF
transport with both the default ring and a 16 MiB ring. Increasing the transport
buffer or combining records must never be treated as permission to accept loss.
