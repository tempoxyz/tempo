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

Generated bloat also fills the expiring nonce ring and its seen map with expired
entries, so nonce eviction is exercised from the first transaction. This adds
about 36.6 MiB before T11 or 366.2 MiB from T11 on top of the requested TIP20 size.
The generator accepts `--nonce-ring-hardfork` (default: latest); comparisons use
the higher hardfork for their shared dump. Cached bloat and snapshots must match
the current bloat version and selected ring hardfork to be reused.

All txgen bench presets and scenarios interpret mix weights as target gas shares
by default (`public-mix`: transfer 80%, mint 5%, MPP 15%), in both local and
e2e runners. The harness confirms setup, reuses the setup bindings,
and invokes txgen with `--gas-weighted-mix`. Txgen simulates one workload item
per kind at startup and every 10 seconds; a sampling failure aborts the run.
Actual included shares are recorded in the report's `block_composition` and
copied to `summary.json` under `per_run[].block_composition` (the report's
measured block window, before any additional summary-only warmup trimming).

For the previous transfer-only default, explicitly select
`tip20:recipient=existing,fee-token=any_tip20` (local) or
`tip20_existing_recipients` (both runners). `public`/`tip20` and `mix` remain
separate, opt-in workloads. Scheduled runs use `default`; the e2e nightly
also keeps the transfer-only series under its existing state key.

Reports resolve aliases to the concrete scenario and record the selected preset.
The original alias is retained separately as `requested_preset`; workload category
metadata describes the mix without changing historical transfer-only labels.

`tip20-policy` isolates the successful policy-heavy payment case: pathUSD transfers
to configured receivers in a disjoint account pool, paid in AlphaUSD through the FeeAMM, with protocol nonces.
It requires at least two selected tokens. Setup installs distinct blacklist leaves
under a separate compound issuer policy per token and both address-level receiver
filters, using the current TIP-403 APIs on T13 and T14. Empty blacklists
allow every user while forcing membership reads. All account pools are faucet-funded
even with state bloat, so receiver setup can pay fees. Setup runs outside measurement.
Runs require nonzero submitted payments, full inclusion, and no reverted receipts.
For example: `derek bench preset=tip20-policy bloat=100` (E2E), or
`nu tempo.nu bench --preset tip20-policy` (local). Compare the same preset on
`main` and candidate changes; the policy-payment snapshots record storage actions
and transaction gas on T13/T14, while benchmark timings use normal node caches.
The snapshots create a fresh recipient balance and initial validator fee accrual;
benchmark receivers already have balances from faucet funding.
