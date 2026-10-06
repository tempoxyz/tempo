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

## Historical account-only scheduling follow-up

These runs used the former speculative account-only scheduler, which has since been removed.
The current light client requests full proofs for missing slots directly.
The timings below do not qualify that policy or active-payment workloads.

The expanded real-validator harness also passed with account-only cache scheduling enabled. It
forced a new global state root by transferring another token, authenticated AlphaUSD's unchanged
storage root, and reused its raw slots. Both real proxies then rejected account-only requests;
full hash-pinned proofs still produced verified reads. A genuine held proof returned its original
block/zero balance while a concurrent real mint advanced the head; the subsequent read returned
999 at the changed root. A corrupted remaining-slot proof in a mixed cached/new-slot batch produced
an integrity error without publishing the new account mapping or a partial result.

On the same host/debug/loopback setup, this expanded run observed 228 ms startup, 418 ms restart,
and four-read predominantly warm p50/p95/max of 0.265/0.335/7.708 ms (100 sequential samples).
The first proxy observed 11 account-only requests, including one deliberately rejected request;
the second proxy also rejected that optimization request. The harness uses a 10-second upstream
request timeout for its deliberate hold test and a shared 15-second read deadline. The scenarios
and request totals differ from the baseline above, so these figures are not a controlled speedup
or bandwidth comparison. Representative active-token/root-change workloads still require
measurement.

## Shared state-proof implementation smoke run

Before removing speculative scheduling, after migrating to `tempo-state-proof`, the same expanded four-validator debug/loopback harness
passed again: mint/transfer/approve/burn comparisons, unrelated-token root reuse, rejected optional
probes, slow snapshot retention, failed mixed-batch atomicity, full DKG rotation/restart, and corrupt
proof failover. Artifacts for this local run are `/tmp/tempo-state-proof-devnet.UPJKXf`.

| Measurement | Observed |
| --- | ---: |
| Startup to authenticated durable head | 238 ms |
| Restart/catch-up across rotation | 211 ms |
| Four-read predominantly warm p50 / p95 / maximum (100 samples) | 0.268 / 0.454 / 8.499 ms |
| First-proxy account-only requests / deliberately rejected | 11 / 1 |

The first proxy observed 96 compact-header responses (220,267 JSON bytes) and 27 multiproof
responses (112,578 bytes), including adversarial scenarios. Final cache counts were three account
mappings and nine word/root versions. These are scenario totals, not steady-state bandwidth or a
controlled old/new comparison. In particular, p95 differs from the preceding run; small loopback
samples with changing heads and no load isolation do not establish a regression tolerance or
production parity.

## Direct-only scheduling smoke run

After removing speculative account-only scheduling, the updated
four-validator debug/loopback harness passed exact-block mint/transfer/approve/burn comparisons,
fresh full proofs after unrelated-token mutations, retained slow snapshots, failed mixed-batch
atomicity, DKG rotation/restart and malicious-proof failover. Both proxies observed **zero
account-only requests**. Artifacts: `/tmp/tempo-direct-proofs-devnet.Pr6rBw`. A temporary launcher
disabled validator IPC to avoid collisions on the shared default socket; light startup was unchanged.

Startup/restart were 425/328 ms; 100 predominantly warm four-read batches had p50/p95/max
0.291/0.418/4.885 ms. The first proxy observed 14 multiproof responses (86,390 JSON bytes), including
adversarial attempts. These scenario totals and warm timings are not a controlled comparison with
the historical runs or qualification of sustained active-token workloads.

No numerical production resource/performance guarantees are inferred from these results.
Current resource ceilings remain provisional safety limits pending representative measurements.
