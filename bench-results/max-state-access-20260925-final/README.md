# Near-30M State-Access Pair, 2026-09-25

Both loads ran for 1200 seconds. The headline measures exactly seconds
600-1200, including all idle and nullified-round time.

| Case | Accesses/tx | Mean gas/tx | Completed builder execution Mgas/s | Follower execution Mgas/s | Chain Mgas/s | Included txs in measured window |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| SLOAD | 13800 | 29945642 | 34.462 | 35.503 | 5.24049 | 105 |
| Bytecode | 10800 | 29858475 | 64.413 | 10.577 | 0.099528 | 2 |

**Bytecode nearly stalls the chain, approximately 52.7x below SLOAD. Its
64.4 Mgas/s builder number is not capacity:** only two successful builds are
represented. The measured window contains 500 new payload jobs, 498 nullified
rounds and two completed builds. SLOAD has 516 jobs, 411 nullifications and
105 completed builds. Cancellation can return before gas/duration metrics
are recorded. Nullification counts are not themselves an instrumented count
of canceled EVM executions.

The four bytecode inclusions across the whole load are 280-284 seconds apart.
Each follows admission errors caused by fresh expiring-nonce transactions
being more than 300 seconds ahead of the stalled chain timestamp. There are
12610 such logged rejections in the measured window and 31452 failed RPC
submissions out of 1200000 across the whole load. These observations suggest
a feedback loop between proposal failure, admission and cache pressure;
they do not isolate the causal contribution of each component.

The builder reads approximately 1.9 GB/s during bytecode, versus about
0.64 GB/s during SLOAD. Whole-builder reads per included Mgas are 19160.9 MB
and 122.3 MB respectively. The bytecode ratio has a tiny successful-gas
denominator and includes speculative/unsuccessful work; it is not intrinsic
physical amplification per opcode. See `throughput.md`, `throughput.json`
and `consensus.json` for the complete counters and scopes.

## Controls And Validation

- Same node binary SHA256 `5e4752f9d04cf152486487c6d4a33c91fa31011e6df9e7fa3760d0acd39b9f2d`.
- Same populated storage and unique 24 KiB bytecode corpora, each 100000 MiB;
  router-only fixture update, root `0x8440accb8cbcabe16279e2978c303d9194cc56ad224978dd16a46c2bb9a1a513`.
- Fresh per-case restores with verified cold file caches; fixed CPU/device
  roles; 20 GiB total memory per node, no swap, no OOMs.
- Prewarming and targeted bytecode page prefetch remain enabled; no deadline
  changes. Offered load is 1000 TPS, 1000 signers, 25-second transaction expiry.
- Both transaction gas limits are 30M. Sample generated transactions are
  283 encoded bytes; calldata is compact. These target execution-gas size,
  not the encoded transaction byte-size ceiling.
- SLOAD traces verify 13800 unique, populated, cold reads at 2100 gas each.
- All four included bytecode transactions were audited, including warmup:
  successful near-cap receipts, 10800 copies each, 10780-10791 unique cold
  targets, real/replayed access-set and output equality, distinct populated
  24 KiB contracts, and full cursor reconciliation.
- Both cases have 0% within-block history eligibility. Do not describe them
  as proven within-block history bypass at this size.
- Both nodes persisted all included work after load. Bytecode's durable
  frontier stayed flat during the measured window; post-load catch-up is
  not a claim of sustained durable throughput.

## Recovery And Reproduction

The original manifests retain their failures. v1 sent no timed workload
because the initial cursor creation exceeded the gas budget; a small excluded
initialization transaction fixes this. v2 completed SLOAD, then required an
RPC-only sender-nonce override for legacy trace replay of actual AA calls.
The same preserved database was re-audited. v3 bytecode sent zero transactions
because its new preset had a malformed fee-token address; it is excluded.
v4 used the corrected preset and fresh restores, completed its full load,
and failed the standard minimum-eight-receipt audit. `audit-sparse-bytecode.cjs`
subsequently checked every inclusion without changing performance data.

The bench tool trimmed raw scrape archives before the last block. Headline
rates therefore use complete logs and the original metric clock over an
exact 600-second window. `full-window.cjs` verifies its logged execution
durations and gas against the retained metric interval. This changes the
earlier SLOAD chain figure from 5.28 Mgas/s over 590 seconds to 5.24 Mgas/s
over the complete 600 seconds. In `throughput.json`, `full_window` is
authoritative; original trimmed metric analysis remains available separately.

Run the saved configurations with the prepared fixture and helper environment
documented in `contrib/bench/max-state-access.md`:

```sh
nu bench-e2e.nu state-access-bloat-worst-case \
  --max-transaction-size --baseline HEAD --feature HEAD
```

The fixed-binary commands used `run-sload-size-isolation.cjs` with
`--max-transaction-size`, and `--max-transaction-size bytecode` for the
corrected bytecode-only retry. Source archives, live limit evidence and
original logs are retained in the v2/v4 experiment directories.

Rebuild this combined report, without rerunning the loads:

```sh
node bench-results/max-state-access-20260925-final/combine.cjs
node bench-results/max-state-access-20260925-final/combine-sparse.cjs
node bench-results/max-state-access-20260925-final/consensus.cjs
```

The exhaustive audit restart must not be run during another benchmark.
Its RPC response-size limit was raised only after timing, to accommodate
large opcode traces. This is one sequential pair, not replicated confidence
intervals or a proof of universal worst case.
