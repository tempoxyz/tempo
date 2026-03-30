-- Add run attribution columns to tempo_bench_runs
-- Run against the ClickHouse cluster before deploying this change

ALTER TABLE tempo_bench_runs ADD COLUMN IF NOT EXISTS run_label String DEFAULT '' AFTER benchmark_mode;
ALTER TABLE tempo_bench_runs ADD COLUMN IF NOT EXISTS pr_number String DEFAULT '' AFTER run_label;
ALTER TABLE tempo_bench_runs ADD COLUMN IF NOT EXISTS baseline_ref String DEFAULT '' AFTER pr_number;
ALTER TABLE tempo_bench_runs ADD COLUMN IF NOT EXISTS feature_ref String DEFAULT '' AFTER baseline_ref;
ALTER TABLE tempo_bench_runs ADD COLUMN IF NOT EXISTS triggered_by String DEFAULT '' AFTER feature_ref;
ALTER TABLE tempo_bench_runs ADD COLUMN IF NOT EXISTS run_type String DEFAULT 'manual' AFTER triggered_by;
ALTER TABLE tempo_bench_runs ADD COLUMN IF NOT EXISTS github_run_id String DEFAULT '' AFTER run_type;
ALTER TABLE tempo_bench_runs ADD COLUMN IF NOT EXISTS github_run_url String DEFAULT '' AFTER github_run_id;
