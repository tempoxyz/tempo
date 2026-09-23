# Benchmark presets

All benchmark entry points select `default` unless explicitly overridden.
`aliases.json` is the single source of truth for what `default` means; both
the local Nushell harness and the multi-region runner read it from Tempo's
txgen assets. It currently resolves to `public-mix.yml`, which owns the workload
weights and includes. Change the alias here to change the default everywhere.

`public-mix` remains a supported explicit name for that workload. It requires
nonzero state bloat; local `tempo.nu bench` and `bench-txgen.nu run` callers
must supply `--bloat` (in MiB). `bench-e2e.nu` and CI already default to nonzero bloat.

For the previous transfer-only default, explicitly select
`tip20:recipient=existing,fee-token=any_tip20` (local) or
`tip20_existing_recipients` (both runners). `public`/`tip20` and `mix` remain
separate, opt-in workloads. Scheduled runs use only `default`.

Reports may retain the requested alias as the scenario; workload category
metadata and the resolved preset identify the concrete workload.
