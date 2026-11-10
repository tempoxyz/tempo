# Antithesis targets

Each directory is one Antithesis target with its own workload image, config image
(`docker-compose.yaml` and `Dockerfile.config`) and publishing workflow.

| Target | What it tests | Workflow |
|---|---|---|
| [`reth-proofs`](reth-proofs) | `eth_getMultiProof`-style account and storage proofs against the state root | [`antithesis-reth-proofs.yml`](../../.github/workflows/antithesis-reth-proofs.yml) |
| [`reth-state-root`](reth-state-root) | Sparse-trie state root computation, persistence and restart recovery | [`antithesis-reth-state-root.yml`](../../.github/workflows/antithesis-reth-state-root.yml) |
| [`zones`](zones) | A Tempo L1 and zones network running deposits, withdrawals and transfers | [`antithesis-zones.yml`](../../.github/workflows/antithesis-zones.yml) |

The zones workload drivers live in `xtask/src/zones/antithesis`; see [`zones/README.md`](zones/README.md).
