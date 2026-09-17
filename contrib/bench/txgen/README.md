# Rendering benchmark workloads

Render a workload before starting benchmark phases:

```sh
nu bench-e2e.nu render-txgen-spec --preset public-mix \
  --accounts 1000 --tps 50000 --duration 30 --chain-id 1337 \
  --out-dir .bench-tmp/txgen-specs
```

The command prints the spec path. For `public-mix`, `zones`, `vault-deposit`, and
`vault-withdraw`, it expands fixture setup and per-user/portal templates using the
supplied sizes. Public mix retains its aggregate category weights after expansion.
`TXGEN_ZONE_COUNT`, `TXGEN_ZONE_SETTLEMENT_WINDOW_MS`, and `TXGEN_ZONE_MODE` are read
at render time; the mode applies to the standalone zones preset.

The e2e workflow and local benchmark commands use this same renderer. A supplied
`--preset-path` must already be rendered with the intended workload sizes. The
runner consumes it unchanged, performs live chain/fixture checks, and funds the
accounts. Vault's separate setup and workload phases exchange txgen setup state
instead of deleting setup from the spec, allowing each repetition to reuse the
same rendered input. Included fixture files and normal txgen environment
placeholders still resolve when txgen reads the spec.

Run the renderer regression checks from the repository root:

```sh
nu .github/scripts/bench-txgen-render-test.nu
```
