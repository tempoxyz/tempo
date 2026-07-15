-- Native execution microbenchmarks. A run uses a stable (run_id, case_id)
-- identity, and ReplacingMergeTree makes retried inserts idempotent after merge.
-- Queries that must observe deduplication immediately should use FINAL.
CREATE DATABASE IF NOT EXISTS tempo_repricing;

CREATE TABLE IF NOT EXISTS tempo_repricing.tempo_execution_microbench_results
(
    schema_version UInt16,
    run_id String,
    started_at DateTime64(3, 'UTC'),
    repository Nullable(String),
    git_sha Nullable(String),
    git_ref Nullable(String),
    workflow_url Nullable(String),
    workflow_run_attempt Nullable(UInt32),

    suite_id LowCardinality(String),
    suite_version UInt16,
    benchmark_layer LowCardinality(String),
    measurement_mode LowCardinality(String),
    warmup_seconds Float64,
    measurement_seconds Float64,
    requested_sample_size UInt32,

    case_id String,
    criterion_id String,
    precompile LowCardinality(String),
    precompile_address String,
    precompile_registry_id LowCardinality(String),
    tempo_hardfork LowCardinality(String),
    precompile_spec LowCardinality(String),
    input_kind LowCardinality(String),
    input_length UInt64,
    state_gas_reservoir UInt64,
    gas_limit UInt64,
    gas_used UInt64,
    state_gas_used UInt64,
    gas_refunded Int64,
    expected_status LowCardinality(String),
    expected_output_length UInt64,
    state_gas_reservoir_remaining UInt64,
    provenance_source Nullable(String),
    provenance_reference Nullable(String),

    typical_statistic LowCardinality(String),
    estimate_ns Float64,
    estimate_standard_error_ns Float64,
    estimate_confidence_level Float64,
    estimate_lower_bound_ns Float64,
    estimate_upper_bound_ns Float64,
    median_ns Float64,
    std_dev_ns Float64,
    sample_count UInt32,
    sampling_mode Nullable(String),
    mgas_per_second Float64,
    conservative_mgas_per_second Float64,
    nanoseconds_per_gas Float64,
    gibibytes_per_second Nullable(Float64),

    profile LowCardinality(String),
    features String,
    allocator LowCardinality(String),
    rustc Nullable(String),
    cargo Nullable(String),
    target Nullable(String),
    rustflags Nullable(String),
    revm_version Nullable(String),
    revm_precompile_version Nullable(String),
    criterion_compat_version Nullable(String),

    machine_id LowCardinality(String),
    runner_name Nullable(String),
    os Nullable(String),
    architecture Nullable(String),
    cpu_model Nullable(String),
    microcode Nullable(String),
    logical_cpu_count Nullable(UInt32),
    cpu_set Nullable(String),
    kernel Nullable(String),
    cpu_governors Nullable(String),
    turbo_control_json Nullable(String),
    case_metadata_json String,

    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(started_at)
ORDER BY (run_id, case_id);
