# Light-client smoke measurements

These are **debug-build, loopback smoke measurements**, not production budgets or a complete
performance evaluation. The reproducible harness is `scripts/light-client-devnet.py`; see
[operation and trust documentation](light-client.md). The task remains open for sustained load,
proof-generation CPU/IO, memory/bandwidth profiling, cold reads, multi-token scaling and a fair
unverified-read baseline.

## Recorded run

- Hardware: Apple M4 Max, 14 logical CPUs, 36 GiB RAM.
- OS: macOS 26.7 arm64; Rust 1.96.0; default Cargo development build.
- Four real local validator processes, loopback HTTP; no network latency/TLS simulation.
- Requested block cadence: 200 ms; epoch length: 100 blocks. This is a target, not measured
  sustained cadence. RPC nodes allow a recent 128-block proof window.
- Daemon polls every 100 ms; default read deadline/concurrency and cache limits.
- The host also ran Cargo checks; CPU/memory were not isolated.

| Measurement | Observed |
| --- | ---: |
| Fresh daemon start to authenticated durable head (validators already running) | 319 ms |
| Restart/catch-up across one offline full-DKG signing-key rotation | 342 ms |
| Four-read batch latency, p50 (100 sequential samples) | 0.310 ms |
| Four-read batch latency, p95 | 0.471 ms |
| Four-read batch latency, maximum | 4.417 ms |

The sampled batch contained two balances, one allowance and total supply for one token. Samples
were predominantly same-head cache hits with a small number of proof refetches as heads changed;
these are not cold-read latency distributions or concurrent throughput measurements.

Across the exercised smoke scenarios, the first-provider proxy observed 76 compact header
responses (174,666 serialized JSON bytes) and 11 multiproof responses (71,135 bytes). These totals
include transaction checks, catch-up and adversarial proof attempts; they exclude the direct
second provider and HTTP framing, and are **not** steady-state bandwidth estimates. Final status
reported three account-root entries, five raw-slot entries and two rejected proof batches.

Mint, transfer, approve and burn reads matched full-node calls pinned to the exact reported block.
The signing identity changed in a real full DKG; disk-backed restart authenticated the new key.
The proxy changed genuine storage-proof scalar values: verification rejected them, a separate
provider supplied valid proofs, and removing that honest provider produced an explicit integrity
error rather than a forged/zero fallback. The light datadir contained only its lock and checkpoint.

The run's public header, transition and native storage evidence is retained in
`crates/light/fixtures/devnet-tip20-v1.json` and independently verified by the Rust conformance test.
It uses public development credentials and is not a production trust anchor. Every rerun emits its
own `report.json` and `conformance.json` in the chosen fresh workdir.

No numerical production resource/performance guarantees are inferred from these results.
Current resource ceilings remain provisional safety limits pending representative measurements.
