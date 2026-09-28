# Bytecode latency decomposition

These controls distinguish serial storage waits from CPU/database/codec work.
They are not an end-to-end EVM throughput measurement. The results from
2026-09-27 are in `bench-results/bytecode-latency-breakdown-20260927`.

## Controls

`bytecode-latency-diagnostic.c` reuses the record extraction and safe private
fixture lifecycle from `bytecode-page-diagnostic.c`. It reads 512 actual encoded
24 KiB contracts from the stopped history-path fixture, then tests nine rotated
trials of ten modes on a disposable 4 KiB-page MDBX database:

- MDBX prefix-only, full serial copy, and full copy with the current late hint.
- An early-hint oracle, using previously saved value offsets before `mdbx_get`.
- Buffered `pread` of 4 KiB, 28 KiB, or two sequential reads of 4 + 24 KiB.
- The same three layouts using `O_DIRECT`, bypassing the OS page cache and MDBX.

Every cold trial closes and syncs only the disposable database, evicts that file
with `POSIX_FADV_DONTNEED`, and requires zero resident pages via `mincore`.
General read-ahead remains disabled. Each pass verifies every returned byte
range. A warm repeat must generate no physical reads for buffered/mapped modes;
direct-I/O repeats deliberately still read storage.

Per-operation timers report lookup/read, prefetch, and copy wall/thread-CPU time.
Whole-pass `getrusage` reports user/kernel CPU, faults, and context switches.
Dedicated-cgroup device I/O supplies physical request counts and read bytes.
Open/table setup is excluded; a small number of initially cold index leaves
remain included. Timing overhead is calibrated (about 0.10 us per timed stage
in the saved run) and is not subtracted. Verification is in whole-pass time but
outside the stage times. Do not add stage CPU to whole-pass CPU.

The early-hint oracle is an upper-bound mechanism test, not a provider API or
implemented MDBX optimization. It already knows the file offset. A real fix
would only know that offset after finding the leaf entry, before validating
the first overflow page.

`BYTECODE_WIDE_ONLY=1` instead measures raw lookups across 65,536 sampled keys
in each actual `HashedAccounts` and `Bytecodes` table. Each of five measured
trials performs 524,288 lookups after conditioning. It must have zero physical
reads/major faults. It measures the real B-tree depth and a broader in-memory
working set, but does not measure the complete EVM or Reth caches.

`bytecode-codec-diagnostic.rs` invokes the actual compiled
`reth_primitives_traits::Bytecode::from_compact`, including byte allocation,
jump-table reconstruction, and deallocation. It compares 512 records (~14 MiB)
and 8,192 separately allocated records (~216 MiB), immediate release versus
retention in 2,250-value batches, and jemalloc versus the system allocator.
The larger corpus exceeds either CPU L3 domain. Input loading and corpus
construction are outside measurement; anonymous allocation faults remain inside.

`bytecode-block-latency.bt` correlates block issue/completion by kernel request
pointer for the isolated single-threaded reader. The analyzer requires
matching counts, zero errors, no partial completions, no correlation collisions,
and no outstanding requests. Requeued/partially completed requests require extra
handling before using this tool on unrestricted workloads. These tracepoints measure issue-to-driver-completion latency,
not raw NAND latency or PCIe transfer time. See the
[kernel tracepoint documentation](https://cdn.kernel.org/doc/html/latest/core-api/tracepoint.html).

## Reproduction

Run only while other benchmarks are stopped, using the shared coordination lock.
The source must be a stopped prepared history-path scratch database. It is read
only and never evicted; only new private control files are written/evicted.
No node or system-wide cache settings are changed.

Build the pinned node and helpers using the [setup runbook](state-access-reproduction.md),
then build the diagnostics. The builder selects exact library artifacts from
Cargo's JSON output instead of relying on machine-specific `.rlib` hashes:

```sh
node contrib/bench/build-bytecode-diagnostics.cjs
```

The exported record filename must not exist. For a new results directory:

```sh
flock --nonblock /tmp/tempo-general-state-access-20260922.lock \
  sudo -n systemd-run --scope --quiet --collect \
    --unit tempo-bytecode-io-latency-NEW \
    taskset -c 8 "$PWD/target/state-access-deps/tools/bytecode-latency-diagnostic" \
    /reth-bench-b/tempo_e2e_100000mb_state_access_isolated_roles_history_paths/db \
    /mnt2 /absolute/path/to/new-results/records.bin \
    > /absolute/path/to/new-results/latency-a.jsonl
```

Repeat on `/mnt` with CPU 0 for the builder-device control. Add
`env BYTECODE_WIDE_ONLY=1` before `taskset` for the wide read-only lookup control
(the export-file argument is unused in that mode).

The same build command also builds both codec allocator variants using the
node's exact compiled dependencies. Run `bytecode-codec-system` for the system
allocator control and `bytecode-codec-jemalloc` for jemalloc:

```sh
flock --nonblock /tmp/tempo-general-state-access-20260922.lock \
  taskset -c 8 target/state-access-deps/tools/bytecode-codec-jemalloc /absolute/path/to/results/records.bin
```

For tracing, use `bpftrace -f json -o block-latency.jsonl -c '/bin/bash RUNNER'`
with `contrib/bench/bytecode-block-latency.bt`. `RUNNER` must acquire the same lock
and run the C tool in its dedicated scope. The saved `run-traced.sh` is an exact
workspace-specific example; use fresh export names when repeating it.

With the result names used in the saved experiment, validate and summarize:

```sh
node contrib/bench/analyze-bytecode-latency.cjs /absolute/path/to/results
```

The analyzer writes `summary.json` and rejects incomplete/invalid controls.
Source fixture preparation, trials, tracing, and codec runs should be sequential
so the diagnostic does not create its own competing I/O or allocator load.
