# Private kernel wait-path feasibility probe

This directory is a standalone synthetic experiment. It changes no scheduler
runtime, benchmark workflow, node binary, capture schema, or existing artifact.
It cannot explain a previous capture: the schema-3 records contain scheduler
states, not sampled kernel stacks. A new opt-in capture is required.

Run the seven unit tests with:

```
python3 -m unittest discover -s contrib/bench/lifecycle/scheduler/wait_reason_probe -q
```

Run the short synthetic probe with:

```
sudo -n env PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 contrib/bench/lifecycle/scheduler/wait_reason_probe/probe.py
```

The process creates its own three-thread child and no node. Each synthetic
thread registers a run-local ordinal and performs timer sleep, timed futex wait,
or pipe read. The child stops before probe attachment; parent-death protection,
private temporary files, bounded child wait, and owned-child cleanup contain the
experiment. Compiler/BCC diagnostics are discarded; failure emits a fixed enum.

A sleeping `sched_switch` (`prev_state` exactly 1 or 2) records a kernel stack
into a 1,024-entry immutable stack map. Flags are zero: neither stack ID reuse
nor hash-only comparison is allowed. A 4,096-entry map counts samples by private
stack ID and ordinal. Native IDs, addresses, stack IDs and resolved symbols stay
in kernel/private process memory and disappear at teardown. Only fixed numeric
reason enums and aggregate integrity counters are output. There are no ring
records, spool files, raw symbol dumps, user stacks, paths or payload collection.

The exact symbol allowlist classifies positive observations as futex wait,
kernel `io_schedule` path, timer sleep, pipe read, or poll wait. No match, symbol
variants, failed stacks and conflicting categories remain unknown. A runnable
or preempted switch-out never receives a blocking category. `io_schedule` is an
observed kernel scheduling path, **not** proof of disk I/O, a particular device,
persistence work, or the cause of an application stall. A futex frame does not
identify a lock, owner, dependency, or the responsible application operation.

The final local synthetic run admitted all three ordinals exactly once and
observed 72 sleeping samples: 24 timer, 24 futex, 24 pipe. Stack/map/registration
errors and BPF recursion misses were zero. No markers or missing role samples
cannot count as success. These results prove local stack/category feasibility;
they do not prove full scheduler edge coverage, source cutoff handling,
benchmark-runner support, bounded overhead under node load, or application
cause attribution. The pure `admit_sample` cutoff fixture is only a proposed
contract, not runtime integration. Poll and IO paths were not live-tested.

## Historical production design

The sibling scheduler implementation now implements the reviewed runtime path;
see [its schema4 contract](../README.md#optional-sleeping-kernel-paths-schema4).
This standalone prototype remains unchanged. Its original design notes follow.

1. Keep this opt-in and retain the existing stopped-child, process-incarnation,
   ordinal, exit, sealed-registration and probe-miss gates. Retain schema-3
   wake semantics, including separately counted on-CPU wakeups. Do not reopen
   accepted captures or infer old wait reasons retrospectively.
2. Sample only a registered thread's sleeping switch-out at that exact event
   boundary. Keep its timestamp and ordinal with the sample; never join a
   reason to the nearest timestamp. Retain preemption/runnable classification.
   Record state and stack at this boundary before any asynchronous processing.
3. Use a bounded immutable stack map without reuse/hash-only flags. Collision,
   full map, helper error, truncation/unknown symbol and conflicting-category
   outcomes need explicit closed status counters. A failed stack must remain
   unknown rather than a known category. Any transport or integrity loss still
   rejects complete capture. Unknown categories are measured coverage limits.
4. Resolve each immutable stack once in a private callback cache. A production
   native callback could read the kernel map and compare frames with privately
   resolved, exact allowlisted symbol ranges; no raw frame/stack ID needs to
   enter the retained spool. This requires its own reviewed range-resolution
   logic. Do not run Python symbolization per switch. A simpler bounded private
   callback prototype can first quantify overhead before native integration.
5. Version the binary transport and published JSON. Preserve original scheduler
   state separately from reason/status. Emit only numeric enum/status fields on
   sleeping switch-out records; every other record must reject these fields.
   Extend the native/producer/footer/external audits together. Do not reuse a
   previously published schema to silently add meanings to state bits.
6. The exact switch-out owns the category for its matched
   `blocked_before_wakeup` interval. Runnable-after-wakeup time does not inherit
   the wait category. Preserve source ordering, duplicate/unknown-edge checks,
   strict at/post-cutoff pruning and existing right-censor semantics. Extend the
   independent auditor to recompute category joins, coverage and counters.
7. Intersect these qualified intervals with exact entered executor scopes on
   the same pseudonymous thread. Label results **observed kernel wait path**,
   not task CPU, lock ownership, instruction attribution or causal diagnosis.
   This can separate observed futex versus kernel IO paths within EVM wall time
   without changing execution, storage or persistence behavior.
8. Run a matched observer comparison and high-event-rate synthetic capacity
   test before relying on timings. Stack unwinding and symbol resolution add
   work; even sleeping-only sampling can perturb scheduling and caches. Keep
   both runtime binaries and all source gates identical for such comparison.

An application alternative is a precisely parented span around a known blocking
wait, but that requires first identifying the wait site. Broad EVM wall and
scheduler state alone do not establish which provider, lock, page fault or
other path blocked. Private positive kernel categories can guide that narrower
instrumentation without speculative application attribution.

Primary sources: Linux's
[scheduler tracepoint definition](https://github.com/torvalds/linux/blob/v6.8/include/trace/events/sched.h)
separates preemption from sleeping state; BCC's
[off-CPU implementation](https://github.com/iovisor/bcc/blob/master/tools/offcputime.py)
uses kernel stack maps and describes unavailable/colliding stack outcomes.
