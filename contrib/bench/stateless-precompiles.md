# Stateless precompile benchmark results

The `stateless_precompiles` target measures precompiles directly through Tempo's resolved
`revm` registry. It does not include EVM call overhead, transaction execution, block
validation, or state-root work. Keep results from those future benchmark layers separate.

CodSpeed runs this target on pull requests and `main` to detect relative performance
regressions. Absolute wall-time results come from the manually dispatched or reusable
`Stateless precompile benchmarks` workflow on `bare-metal-dual-schelk`. Do not use CodSpeed
simulation measurements as absolute gas-per-second results.

## Case and resolver boundaries

Tempo's materialized `StatelessPrecompileCase` is the canonical runner input. The Identity cases
are native Rust definitions with deterministic zero-filled input; this PR needs no general input,
transaction, or payload generator. The `0`, `32`, `256`, and `1024` byte cases carry provenance
for the pinned EEST benchmark release, but neither the model nor the benchmark has a runtime
dependency on EEST's fixture format. Future EEST adapters and Tempo-native generators should
translate their outputs into the same materialized case model.

The current direct resolver uses `EthPrecompiles` with the Ethereum precompile spec selected for
the explicit Tempo hardfork. More Ethereum built-ins therefore require only new cases. A future
Tempo-native custom stateless precompile, such as a zones proof verifier, will also require a
resolver adapter; adding its cases alone will not make it resolvable through `EthPrecompiles`.

## Native run

The workflow runs the equivalent of:

```bash
export RUSTFLAGS='-C target-cpu=native'
export CRITERION_HOME="$PWD/bench-results/stateless-precompiles/criterion"
export TEMPO_BENCH_MANIFEST="$PWD/bench-results/stateless-precompiles/cases.json"

cargo bench \
  -p tempo-precompiles \
  --features test-utils \
  --bench stateless_precompiles

python3 contrib/bench/export-stateless-precompiles.py \
  --manifest "$TEMPO_BENCH_MANIFEST" \
  --criterion-dir "$CRITERION_HOME" \
  --output bench-results/stateless-precompiles/report.json \
  --rows-output bench-results/stateless-precompiles/clickhouse-rows.jsonl \
  --profile bench \
  --features tempo-precompiles/test-utils \
  --allocator tikv-jemallocator/0.6.1 \
  --warmup-seconds 3 \
  --measurement-seconds 10 \
  --sample-size 100
```

Set `TEMPO_BENCH_MACHINE_ID` to a stable identifier when results may be published. Set
`TEMPO_BENCH_CPU_SET` and invoke the benchmark through `taskset` if a runner has an assigned
benchmark CPU. Both values are recorded in the report. Do not guess a CPU: coordinate an
isolated CPU set for the runner. Local artifact-only runs may omit it; the GitHub workflow
requires an explicit CPU set for every native run.

The workflow deletes its Criterion result directory before every run. This is important:
the exporter rejects measurements not declared by the current benchmark manifest and rejects
manifest cases without a measurement.

## Artifact contract

Each workflow artifact contains:

- `cases.json`: benchmark-owned case semantics emitted after correctness preflight.
- `criterion/`: raw native Criterion estimates and samples.
- `report.json`: canonical, self-contained Tempo report.
- `clickhouse-rows.jsonl`: deterministic one-result-per-line projection for ClickHouse
  `JSONEachRow` ingestion.

`report.json` is the source of truth. JSON stores run and host metadata once and keeps the
case/result relationship explicit. The JSONL file is only a transport projection; it can be
regenerated from the report and should not become a second benchmark schema.

### `report.json` schema version 1

The top-level object contains:

| Field | Meaning |
| --- | --- |
| `schema_version` | Version of the report and JSONEachRow projection. Bump for incompatible changes. |
| `run` | Run ID, start time, repository, git SHA/ref, workflow URL, and workflow attempt. |
| `build` | Cargo profile, enabled features, allocator, Rust/Cargo versions, target, `RUSTFLAGS`, wrapper, and relevant locked dependency versions. |
| `host` | Stable machine ID plus runner, OS, kernel, CPU, microcode, CPU set, governor, and raw turbo-control state. |
| `configuration` | Measurement mode (`wall_time`) plus requested Criterion warm-up time, measurement time, and sample size. |
| `suite` | Benchmark-owned suite ID/version and benchmark layer. |
| `results` | One entry for every case declared by the benchmark manifest. |

Each `results[]` entry contains:

| Field | Meaning |
| --- | --- |
| `case` | Tempo-owned case definition: stable IDs, precompile, protocol context, input parameters, gas, expected outcome, and optional provenance. |
| `measurement.unit` | `nanoseconds`; Criterion's estimates are time per benchmark iteration. |
| `measurement.typical_statistic` | `slope` for Criterion linear sampling, otherwise `mean`. |
| `measurement.typical` | Point estimate, standard error, confidence level, and lower/upper confidence bounds. |
| `measurement.median` | Median time estimate and confidence interval. |
| `measurement.std_dev` | Standard-deviation estimate and confidence interval. |
| `measurement.sample_count` | Number of Criterion samples, not the number of timed iterations. |
| `measurement.sampling_mode` | Criterion sampling mode used for the case. |
| `metrics.mgas_per_second` | `gas_used * 1000 / estimate_ns`. |
| `metrics.conservative_mgas_per_second` | `gas_used * 1000 / upper_confidence_bound_ns`. |
| `metrics.nanoseconds_per_gas` | Typical estimate divided by charged gas. |
| `metrics.gibibytes_per_second` | Input bytes processed per second, expressed as GiB/s. |

Time and charged gas are both retained because changing gas prices changes gas/s without
changing execution time. A dashboard should graph `estimate_ns` as well as gas-derived metrics.
There is no mandatory input digest: native/generated cases are identified by the versioned case
ID and their parameters. External fixture adapters may include an artifact checksum in case
metadata when integrity requires it.

### ClickHouse handoff

`clickhouse-rows.jsonl` repeats run, build, and host dimensions on every result and flattens the
stable fields required for filtering and charting. Optional fields are emitted as JSON `null`,
not omitted. The complete case is also retained in `case_metadata_json` so a supplemental input
source can add metadata without requiring an immediate table migration.

The projected columns are grouped as follows:

- Run: `run_id`, `started_at`, `repository`, `git_sha`, `git_ref`, `workflow_url`,
  `workflow_run_attempt`.
- Suite/case: `suite_id`, `suite_version`, `benchmark_layer`, `measurement_mode`, `case_id`, `criterion_id`,
  run configuration, precompile address/name/registry ID, hardfork/spec, input kind/length, charged,
  state, and refunded gas fields, expected outcome, and provenance.
- Measurement: typical estimate and confidence interval, median, standard deviation, sample
  count/mode, and derived gas/byte rates.
- Build/host: profile, features, allocator, tool/dependency versions, target/Rust flags, machine,
  CPU, microcode, CPU set/governor/turbo state, OS, and kernel.

The versioned table DDL is
`contrib/bench/clickhouse/001_execution_microbench_results.sql`. Apply it once with an administrative
account, for example:

```bash
clickhouse-client \
  --queries-file contrib/bench/clickhouse/001_execution_microbench_results.sql
```

The benchmark workflow never runs DDL. Its narrowly scoped account needs `INSERT` and `SELECT`
on `tempo_execution_microbench_results`: `INSERT` publishes the batch and `SELECT` verifies the
deduplicated row count. With `CLICKHOUSE_URL`,
`CLICKHOUSE_USER`, and `CLICKHOUSE_PASSWORD` configured, it publishes rows through
`contrib/bench/upload-execution-microbench-results.sh`; `CLICKHOUSE_DATABASE` is a repository
variable and defaults to `tempo_repricing`. ClickHouse credentials are scoped only to the publication
step in a separate GitHub-hosted job. The credential-free self-hosted job uploads its artifact;
the hosted job downloads, validates, and publishes it. Publication runs only from
`refs/heads/main`; dispatch the workflow on `main` to seed or update dashboard data. The
self-hosted native job does not execute feature-branch or PR code, and CodSpeed remains the
feature-branch regression signal. Local native runs can still produce an artifact without
ClickHouse credentials.

`CLICKHOUSE_URL` must use HTTPS. Plain HTTP is rejected except for an explicit loopback address
used in local testing; credentials are never exposed to feature-branch benchmark code.

The uploader refuses publication unless a CPU set was explicitly selected, every observed CPU
governor is `performance`, and any detected Intel or AMD turbo control shows turbo disabled.
Artifact-only runs remain permissive. The table's `ReplacingMergeTree` key is
`(run_id, case_id)`; dashboard queries that must deduplicate retries immediately should use
`FINAL` or an equivalent `argMax` query.

These rows do not match the existing block/TPS benchmark tables. Comparisons must filter to the
same `benchmark_layer`, machine, hardfork, precompile spec, allocator, build profile, and CPU
controls.
