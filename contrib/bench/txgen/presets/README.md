# Benchmark presets

All benchmark entry points select `default` unless explicitly overridden.
`aliases.json` is the single source of truth for what `default` means; both
the local Nushell harness and the multi-region runner read it from Tempo's
txgen assets. It currently resolves to `public-mix.yml`, which owns the workload
weights and includes. Change the alias here to change the default everywhere.

`public-mix` remains a supported explicit name for that workload. It requires
nonzero state bloat; local `tempo.nu bench` and `bench-txgen.nu run` default
to 1024 MiB. `bench-e2e.nu` and CI already default to nonzero bloat.
Existing localnet databases with unknown or different bloat fail; use
`nu tempo.nu bench --force` to rebuild them. Comparison snapshot rebuilds
regenerate the bloat file for the requested size.

For the previous transfer-only default, explicitly select
`tip20:recipient=existing,fee-token=any_tip20` (local) or
`tip20_existing_recipients` (both runners). `public`/`tip20` and `mix` remain
separate, opt-in workloads. Scheduled runs use only `default`.

Reports resolve aliases to the concrete scenario and record the selected preset.
The original alias is retained separately as `requested_preset`; workload category
metadata describes the mix without changing historical transfer-only labels.
