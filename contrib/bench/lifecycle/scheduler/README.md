# Opt-in scheduler diagnostic

`profiling=lifecycle-scheduler` adds anonymous scheduler context to full lifecycle capture. It is an isolated diagnostic, disabled by default. It changes observation overhead and must not be compared as if it were an ordinary performance run. No kernel stack, syscall, file, network payload, address, command name, native PID or native TID is exported.

The runner must have passwordless root access, Python with BCC bindings/libbcc, bpftrace for the existing clock/format preflight, BTF, readable scheduler tracepoints, GCC, Rust and objdump. Preflight deliberately fails closed when capabilities or the scheduler state format differ from the tested format. It does not change perf sysctls, kernel configuration or services. Local proof used PythonBCC/libbcc0.29.1, libbpf1.3.0 and bpftrace0.20.2 on Linux6.8. Only `lifecycle-scheduler` runs provision missing dependencies; other benchmark modes never execute setup. The supervisor and preflight use `/usr/bin/python3`, matching the distribution bindings. Runner availability is rechecked on every scheduler job. On the local Ubuntu system the additional bindings/runtime packages are `python3-bpfcc` and `libbpfcc`, with their distribution dependencies. The runtime checks import, BPF compilation and native callback compilation before launch, then attaches the full program before resuming the stopped child. The scheduler-only setup installs missing BCC packages or C compiler support through the distro package manager, with service restart handling disabled. Package logs are discarded; setup emits closed categories for package availability/install, BCC import/API, C compilation and BPF compilation. Unsupported kernel compile support or capabilities reject capture; no kernel/header installation or capability fallback occurs. The workflow then runs both the original capability proof and the live binary attach/capture test before node launch. `perf` was unavailable for the running kernel, so this implementation does not depend on it.

Run the isolated proof without launching validators:

```sh
python3 contrib/bench/lifecycle/scheduler/diagnostic.py --output /tmp/scheduler-proof.json
python3 -m unittest discover -s contrib/bench/lifecycle/scheduler
sudo -n env TEMPO_SCHEDULER_LIVE_TEST=1 /usr/bin/python3 -m unittest discover -s contrib/bench/lifecycle/scheduler
```

The standalone text-transport proof verifies that the monotonic BPF helper is used (bare `nsecs` has a different clock), checks C and Rust registration calls survive optimized/LTO compilation, and runs three synthetic threads with blocked and runnable intervals. Its events after a synthetic cutoff are kept only in private memory and removed before writing the sanitized result. It does not prove that a particular validator binary or runner can be traced; the runtime repeats capability and marker-call checks against the actual binary.

The optional live unit test separately exercises the binary helper's stopped-child launcher and complete scheduler decoding against three synthetic threads, using a midpoint cutoff derived from observed endpoints. Actual benchmarks still use the earliest source backpressure boundary from both validators.

For a local benchmark, pass `--lifecycle --lifecycle-scheduler` to `bench-e2e.nu e2e`. The runtime requires full detail. An instrumented binary must advertise `scheduler=registered_threads_v1` in its lifecycle header. The hook is enabled only by `TEMPO_LIFECYCLE_SCHEDULER=registered_threads_v1`, and receives only the collector thread ordinal and private phase epoch. A `black_box` operation prevents elimination of the hook; presence of the symbol alone is insufficient, so preflight verifies an actual call in the final binary.

Each validator has its own BCC/BPF supervisor. It launches one stopped child, attaches before execution, and uses `exec` to retain that process incarnation through the shell and CPU affinity wrapper. Admission is sealed at the leader’s kernel exit before its PID can be reaped or reused; late registration after leader exit is unsupported and fails source-coverage checks. Admission checks the child process and the phase epoch. Each private kernel map belongs to one watched process incarnation and keys its native TIDs; `sched_process_exit` removes a thread before the TID can be reused. Ordinals never repeat in a process. The two validators are separate anonymous process namespaces in the exported traces. No arbitrary existing process, forked subprocess or late attachment is supported.

The launch command is carried in a memory-only memfd script, not a temporary command file. The helper forks a stopped child, installs scheduler probes and the epoch-checked registration uprobe, then resumes it. Parent death kills an unreaped child. A native C callback drains the16MiB BPF ring through a64KiB buffer into an unlinked, fixed16-byte ordinal/time/state spool, capped at1GiB per validator. Its file descriptor is not inherited by the compiler or node after exec. Scratch storage is explicitly beneath the guarded phase directory; it never defaults to `/tmp`. The successful capture stdout pipe contains only an80-byte fixed numeric footer; unexpected tool diagnostics remain bounded in private memory. No native PID/TID is present in the spool. Native maps and unexpected compiler diagnostics remain private. Core dumps are disabled. There is no raw perf file or native identity mapping file. Any tool diagnostic, lost event/count mismatch, missing registration, missing exit, malformed event, map-helper error, I/O error or storage budget failure rejects the scheduler diagnostic. No automatic fallback presents incomplete data as a complete capture.

After both lifecycle footers are present, the supervisor recomputes the earliest backpressure boundary from both final source streams and the load window. Every at/post-cutoff event is discarded. Closed intervals end at most one nanosecond before that cutoff, with zero-width results discarded; unclosed intervals are excluded, never extended to an invented endpoint. Without backpressure, the diagnostic ends at the load-window end. Report publication rechecks the exact cutoff, schema, process namespace and source-thread registrations before copying either scheduler source into the artifact.

Open `scheduler.html` in the downloaded artifact. Its Perfetto files combine existing block lifecycle lanes with anonymous scheduler tracks during each block's lifecycle. The percentile links select exactly the same actual complete blocks as the ordinary report. Focus clipping is explicitly marked separately from cutoff censoring. `scheduler-a.json.gz`, `scheduler-b.json.gz` and `scheduler-summary.json` retain all sanitized scheduler intervals and quality information, including times outside individual block windows. Focused files are `perfetto-scheduler-block-N.json.gz`; open them directly in Perfetto. Compression preserves the exact JSON schema and rows, with no filename or wall-clock timestamp in the gzip header. Synthetic gzip traces were imported in the actual Perfetto browser UI; this is format validation, not evidence of a complete validator capture.

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

The binary transport retains every scheduler edge; it does not sample or coalesce.
A private numeric footer records emitted/collected counts, failed kernel output,
invalid records, spool overflow, I/O failure, callback record count and observed-duration difference; child exit status is checked separately. Any loss, truncation or failure
rejects capture before the existing edge/cutoff decoder runs. After child exit,
the helper drains the ring to empty before reading counters. The published JSON
record/interval shapes and source-coverage, pruning and Perfetto gates are preserved;
schema2 adds the explicit probe-miss quality proof described below.
The isolated153-thread,2-second throughput proof collected all7,471,733 emitted
records with zero reported loss; this synthetic result is not validator capture
validation or an application performance claim.


After shutdown, bounded external sorting preserves timestamp order and original
arrival order for ties. Streaming decoding validates every retained edge,
including edges beyond the cutoff, before publishing only the allowed prefix.
Compact temporary row/interval spools preserve every exact edge; nothing is
sampled, rounded or coalesced. All anonymous temporary files are closed on failure.

The source gzip is capped at2GiB per validator (12GiB decompressed JSON), and each
report index at6GiB with an8MiB SQLite page cache. The native source cap remains
1GiB per validator (67,108,864 records); compact retained records use at most1GiB
and compact intervals at most about1.63GiB. Sorting can temporarily retain both
its input and merge outputs on that same scratch filesystem. Focused gzip files
share an8GiB compressed budget per phase and each has an8GiB decompressed cap. These are limits, not expected usage or a promise
that a busy runner has enough free space. The48GiB capture guard is unchanged;
any allocation, disk-full, cap or integrity error rejects the diagnostic. Indexes
live in the private phase directory, outside the upload tree, and are closed
before reporting returns. No raw spool/index is part of the published inventory.

A17,000,066-edge synthetic sizing exercise (beyond the prior16,777,216-record
memory limit) retained13,599,999 pre-cutoff edges with peak RSS95,964KiB through
uncompressed source publication and report indexing. Decode/publication took
102.16s and indexing111.22s on that local machine. This supports a separate,
bounded900s post-shutdown scheduler-publication wait; the lifecycle footer gate
remains90s. It is not an application performance measurement. The index streams
source rows and preserves their order; per-thread range queries retrieve only
intervals intersecting a selected block, and focused Perfetto serialization is
streamed instead of accumulating another trace-sized Python list.

Failure summaries expose only allowlisted numeric counters and closed failure
categories. `kept`/`pruned` on a rejected capture describe retained source records
relative to the established cutoff; they do not turn a failed capture into valid
data. No exception strings, raw diagnostics, commands, paths or native identities
are included in that evidence.

The same17M-edge fixture on the final compact-spool/gzip path used96,104KiB
peak RSS,105.07s for decode/publication and110.14s for indexing. The source gzip
was168,674,805 bytes versus2,101,248,873 uncompressed; its decompressed rows and
index size were unchanged. These are local synthetic sizing results, not expected
runner rates. A live shutdown/churn matrix also exercised handled SIGINT, process
exit,513 registered threads and two concurrent33-thread processes. All five had
matching emitted/received/retained counts and zero transport loss, overflow or
I/O failures. Four classified every pre-cutoff interval. One concurrent case
correctly reported two unsplit off-CPU intervals and completeness=false; an
independent audit must reject that capture as complete. Transport capacity alone
does not prove every scheduler wakeup can be classified.

A separate six-second153-thread live native proof collected21,941,138 edges
(about3.66million/second), beyond the old16,777,216-record cap, with zero kernel
loss, malformed records, spool overflow or I/O errors. The1GiB spool holds about
18.35seconds at that deliberately extreme synthetic rate; this is not a measured
validator rate or a guarantee for a120-second workload. The strict decoder kept
all observed endpoints before its synthetic cutoff and produced a209,349,035-byte
gzip. It also correctly reported73 unsplit off-CPU intervals, so this was a
transport-capacity proof, not a complete scheduler-attribution result.


### Probe suppression and schema2

The ordinary perf tracepoint path in Linux6.8 uses a CPU-wide BPF recursion guard.
An interrupt can therefore suppress a different probe before this diagnostic's
emitted/ring-loss counters execute. A six-second153-thread reproduction observed
91 `sched_wakeup` and199 `sched_migrate_task` recursion misses, with46 unsplit
waits in the pre-cutoff half. The absence of ring-buffer loss did not establish
probe completeness; migration omissions could be silent in interval quality.

Wakeup and migration now attach as raw tracepoints, whose recursion guard is per
program. They still observe the same kernel events: `sched_wakeup` means the task
has become TASK_RUNNING; `sched_waking` is not substituted. Native task-ID reads
are checked and remain in kernel memory. The switch-state encoding, registration,
process-incarnation admission, ordinal reuse/exit checks and cutoff are unchanged.
A matching synthetic comparison collected21,372,628 edges with zero recursion
misses, zero ring/collector loss, and all pre-cutoff intervals classified. This
supports the mechanism correction, not a claim that real captures always succeed.

Every attached program's kernel `recursion_misses` counter is read before the
stopped child resumes. After the child and all its threads exit, all owned probes
are detached, the ring is drained, and final counters are checked. Detachment
uses the owned uprobe link, without looking up a PID after reaping. Unavailable,
reset or positive counter deltas reject capture, including omissions after the
cutoff that could affect shutdown/closing-edge validation. The check is
conservative: a miss affecting an unregistered task during that window also
rejects the diagnostic. No perf/sysctl/statistics setting is changed.

The private footer is `SCHEDS02`,80 bytes, with an added numeric `probe_misses`.
Published scheduler source schema2 requires `quality.probe_misses` to be the
unsigned integer zero. The current producer/report require schema2 on both
validators; legacy schema1 decoding remains available only for explicit old
fixtures/audits. A matching transport footer can never override probe misses.

Primary kernel references:
- [perf tracepoint recursion guard](https://github.com/torvalds/linux/blob/v6.8/kernel/trace/bpf_trace.c#L110-L120)
- [raw tracepoint per-program guard](https://github.com/torvalds/linux/blob/v6.8/kernel/trace/bpf_trace.c#L2232-L2243)
- [TASK_RUNNING wakeup boundary](https://github.com/torvalds/linux/blob/v6.8/kernel/sched/core.c#L3545-L3549)

The final implementation, including counter snapshots, detachment and schema2
publication, also passed a separate six-second153-thread proof with22,417,631
emitted/received/retained edges, zero ring/collector/probe misses, and zero unsplit,
unclosed or unmatched intervals. The pre-cutoff gzip was212,480,903 bytes. Real
validator capture remains subject to the same strict gates and still needs a
successful benchmark run; synthetic completeness is not a replacement for it.

The final gated shutdown matrix also passed all five cases: handled SIGINT,
process exit, 513-thread churn, and two concurrent 33-thread captures. Each had
matching emitted/received/retained counts, zero probe/transport losses and zero
unsplit, unclosed or unmatched intervals. Every published record and interval
endpoint remained strictly before its synthetic cutoff.
