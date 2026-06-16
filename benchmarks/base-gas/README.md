# Base-Style Gas Benchmarks

This project benchmarks Base-style ERC20 implementations of the four TIP-1060 gas use cases.
It is a controlled surrogate, not a replay of the same Tempo transactions on Base.

The Base measured boundary is business call execution gas only. Setup, deployment, account
abstraction wrapping, and Base L1 data fees are excluded. The Tempo comparison script uses the
top-level use-case metric from the existing snapshots so TIP-1060 settled-credit effects are
included; the `call(s)` column describes the business flow being compared.

## Run

```sh
cd benchmarks/base-gas
./scripts/run-base-gas.sh
```

By default the runner starts an anvil instance forked from `https://mainnet.base.org`.
For an offline/local EVM run with Base chain id and Cancun rules:

```sh
BASE_RPC_URL=none ./scripts/run-base-gas.sh
```

Outputs:

- `out/base-gas.json`
- `out/base-gas.md`

## Compare With Tempo

```sh
./scripts/compare-gas.sh \
  --tip1060-snapshots /tmp/tempo-rus-tip1060-gas/crates/node/tests/it/gas/snapshots
```

Outputs:

- `out/comparison.md`

The comparison script reads current Tempo snapshots from
`crates/node/tests/it/gas/snapshots` in the repo root.
