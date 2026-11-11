# JSON-guidance A/B probe

Isolated experiment, not a Tempo SUT test. One binary/image, two compose configs;
only `PROBE_MODE` differs. Its nested Cargo workspace deliberately avoids Tempo's
workspace, coverage, and dependency features. No Hegel, instrumentation runtime,
state-dependent assertion, fault injector, or network client is included.

## Design

State starts at zero. Each step immediately consumes one fresh SDK random draw:
low two bits zero reset to zero; otherwise advance by one, capped at 63 (3/4
advance probability for uniform draws). Mode is resolved once before setup:
`dynamic` labels the actual state, while `constant` always labels state zero.
Both modes use the same transition and emit at the same callsite, followed by
ordinary stdout `{"probe_step":0,"actual_state":1}` and a fixed 100 ms sleep,
including after the final bounded-test emission. Actual state is never sent as
an SDK assertion detail or other guidance payload.

Labels are the nonmonotonic permutation `(37 * state + 19) % 64`, formatted as
exactly two lowercase hex digits. The SDK JSON guidance has stable identity
`Probe state shape`, `maximize: false`, and shape `{"label":"xx"}`. Only the two
label bytes vary. `antithesis_init()` registers catalogs before the fixed true
`Probe process healthy` property and `setup_complete`. The exported internal
`guidance_helper!` API is intentionally pinned to real `antithesis_sdk =0.3.0`;
`libc =0.2.190` and the copied lockfile pin the rest. No stub SDK is used.

After setup, `/opt/antithesis/test/v1/main/first_start_workload` (an identical copy
of the binary, not a shell script) creates `/workload-active`. The main process
waits for activation or SIGTERM/SIGINT, checking shutdown with bounded 100 ms
sleeps. There is no activation deadline: the [test composer reference](https://antithesis.com/docs/product/writing_tests/test_templates/test_composer_reference/)
requires a driver or anytime command and runs `first` only when its template is
selected after setup; it does not guarantee activation within 30 seconds.
`anytime_probe_health` is another identical copy of the binary that returns zero
without consulting mode or state, writing a marker, or invoking the SDK/RNG.
Both test commands dispatch by basename before SDK initialization. PID 1 alone
owns the state walk and telemetry, and emits neither steps nor guidance hits
before activation. External validation timeouts and authorized run limits bound
waiting and fuzzing; a branch without a selected first command remains idle and
interruptible. Each fuzz-loop sleep is bounded at 100 ms and checks shutdown
before the next draw. Missing/invalid mode in PID 1 and other errors exit with
code 2.

## Build and publication: CI only

Opt in to `guidance_probe: true` when manually dispatching
[`antithesis-reth-state-root.yml`](../../../.github/workflows/antithesis-reth-state-root.yml).
It defaults off. The build context is this directory, not the repository root.
Do not compile, build an image, or upload it on a developer/agent host. CI builds
and uploads images only; it must not start paid Antithesis runs.

The multi-stage Dockerfile pins the existing Rust 1.96 Bookworm image by digest.
Only nightly-2026-11-10 rustfmt is installed separately for repository formatting;
tests, Clippy (`-D warnings`), and `cargo build --release --locked` use stable
1.96.0. Dependencies are fetched from the public registry with lockfile checksums;
no private credentials, host cache, build artifact, or helper script is copied.
The allowlist `.dockerignore` excludes everything except build inputs.

No `RUSTFLAGS`, sanitizer-coverage flags, `-Zinstrument-coverage`, Hegel, or
`antithesis-instrumentation` dependency is intended. Docker build gates inspect
`nm`, `readelf`, and the dependency tree for coverage hooks, then use `objdump`
to reject jumps in the transition and mode-masked label selection. The final
image uses a digest-pinned Debian Bookworm slim runtime, matching the builder's
Debian release. Preserve its full glibc runtime: the platform injects dependencies
such as `libm.so.6` and `libpthread.so.0` that a local `ldd` of the probe does not
reveal. Only the probe and identical first/anytime commands are copied from the
builder; no source, compiler, SDK cache, or build output directory is copied.

Required CI checks: formatting; four copied state/label tests plus activation
ready/timeout/shutdown tests; Clippy; locked release build; no-coverage and
branchless disassembly gates; a 78-step/arm deterministic SDK/stdout equivalence
and cadence preflight; image construction/upload. CI runtime gates verify idle
startup beyond the former 30-second deadline with no telemetry/guidance hits,
first-command activation, clean shutdown both before and after activation, and
zero-exit anytime health with invalid mode and no SDK output. Compose validation
must discover exactly one first and one anytime command. Run these gates against
the CI-built immutable image before treating it as launch-ready. Earlier
standalone host validation is not evidence for this new toolchain/image. No CI
result is claimed here.

The existing `--steps N` option skips activation and bounds a deterministic
preflight; `--tape PATH` requires steps and reads whitespace-separated u64 draws.
Neither launch config enables these facilities. Use the same tape to compare
actual-state stdout and SDK events between arms; only guidance label bytes should
differ. SDK local-output files append, so use a fresh file for each arm.

## Separately authorized comparison

The compose files use the same placeholder `guidance-probe:0.1.0`. Before launch,
replace it in **both** configs with the same CI-published immutable image digest;
do not rebuild or retag between arms. Preserve every other config field.

After separate approval only: launch the arms sequentially, on standard tier,
with `--fault-tolerance none` explicitly set. Cap each arm at 12 compute-hours
(24 total); standard has 48 cores, so 15 minutes is the nominal maximum fuzzing
duration before setup/other overhead. Reserve overhead, inspect actual usage,
and cancel before the cap. Match all other launch parameters. Never auto-launch
these runs from image publication CI. `snouty launch` can push images and spend
compute; this README does not authorize it.

Record run IDs, immutable image digest, exact state counts, maximum reached state,
and tail-state counts (for prespecified thresholds, e.g. 32, 48, 63). Use exact
run-wide counts, not the default 50-event sample. For example, for each arm:

```sh
# Read-only; run after an authorized test. Repeat for both run IDs.
for state in $(seq 0 63); do
  printf 'state=%s ' "$state"
  snouty --json runs search "$RUN_ID" \
    "filter(ev => { try { return JSON.parse(ev.output_text).actual_state === $state; } catch (_) { return false; } })" \
    --count
done
# Exact tail endpoint; repeat with >= 48 and === 63.
snouty --json runs search "$RUN_ID" \
  'filter(ev => { try { return JSON.parse(ev.output_text).actual_state >= 32; } catch (_) { return false; } })' \
  --count
```

These counts span explored timelines, not one linear execution, and are not
independent samples. Also verify the same registered identity/JSON shape and
multiple dynamic labels versus one constant label. **Ingestion is not novelty:**
accepted guidance payloads alone do not establish that novelty scheduling uses
them. Differences in state tails are a capped smoke comparison, not statistically
significant proof. The standard `Software was instrumented` property is expected
to be unmet; do not instrument either arm to satisfy it.
