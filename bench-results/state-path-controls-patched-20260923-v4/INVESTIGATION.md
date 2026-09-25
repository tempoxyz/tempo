# Stall fixes and successful control reruns

Date: 2026-09-23 UTC. These are bounded ordinary contract controls, not
cache-evading or worst-case state-access workloads.

## Fixes and evidence

The initial stopped run exposed cancellation/resource-lifecycle gaps: resolution
registration was deferred until polling, abandoned queued builds retained
resources while awaiting a permit, and completion waits did not observe
cancellation. These are patched in Tempo and its isolated pinned Reth checkout.
Accepted payloads still require completed valid roots. The saved initial-stall
artifacts do not prove the exact blocked interleaving; the reruns demonstrate
that the stall did not recur in these two controls.

A subsequent follower stall was independently traced to RocksDB index-cache
thrashing and repeated decompression. Multi-megabyte legacy index blocks were
larger than the default 2 MiB cache shards. The fix uses eight 16 MiB shards
within the SAME 128 MiB total budget. Production prewarming is unchanged.
The failed attempt recorded 948186 index misses versus 15219 hits and about
6.47 TB of cumulative inserted index bytes. That byte counter is logical cache
insertion, NOT physical disk reads. The successful read run's final periodic
statistics record 65 misses versus 5414369 hits; writes record 38 versus 5962852.
Large index blocks remained resident, and both followers kept up without
pipeline catch-up.

Harness fixes ensure privileged scratch directories are actually removed,
failed restores abort, copies cannot nest, and both Finish checkpoints are at
genesis before startup. Preserved virgin snapshots were not modified. Live
checkpoint probes now use a read-only MDBX helper without initializing static
files or RocksDB. The runner verifies binary/helper hashes and cleans up on
failure. Failed attempts remain marked invalid and are excluded from results.

## Validated results

Both loads ran for 1200 seconds on the 100 GB storage-bloated snapshot; the
first 600 seconds were excluded. Rates below use canonical included gas,
not RPC acceptance or arithmetic averages of per-block throughput.

| Control | Canonical Mgas/s | Follower read I/Os/Mgas | Follower write bytes/Mgas |
| --- | ---: | ---: | ---: |
| Ordinary getter reads | 86.8287 | 0.005860 | 267790.58 |
| Ordinary allowance writes | 78.3238 | 0 | 304582.22 |

Read results: `../20260923-140758-180`.
Write results: `../20260923-144318-555`.
Each audit checked 7200 successful receipts and three real call/storage-diff
traces against a 7514-byte deployed runtime. The read quiet-tail target was
block 2562, with both persisted state frontiers reaching 2576. The write target
was 2559, with both persisted state frontiers reaching 2560. No checkpoint
errors were recorded. Persistence advanced throughout both measured windows.

Every measured builder block hit the 900-transaction cap, not the build-time
budget. These are cap-limited resident-working-set controls, NOT maximum
execution capacity or cold-state worst-case results. The lower write gas rate
must not be interpreted as evidence of a disk bottleneck. Whole-node cgroup
I/O includes prewarming, trie/persistence, and other database-device work;
payload-thread major faults have narrower coverage. Writes had zero measured
follower database-device reads and zero payload-thread major faults.

The SLOAD reference in `throughput.md` is historical and unpatched. It is not
a same-binary comparison, and its device-wide I/O scope differs from these
per-node cgroup measurements. No new adversarial SLOAD run was performed.

## Verification and reproduction

Focused tests passed: 26 Tempo payload-builder tests, 3 Reth queue-lifecycle
tests, 2 Reth payload-service tests, 52 RocksDB-provider tests, and 33 measurement
tests after the final report-labeling regression test. Three disposable restore
checks, Rust formatting, shell/Nushell syntax, and whitespace checks also passed.
The full workspace suite was not run.

Node SHA256: `57169b32c8d0867ce3768af7f9c0cc7d36146fe7dcadecaed45064ee1479d4f6`.
Tempo base: `f62969a95e8a787d2956f3509d25c533bdaac746`.
Reth base: `dfcb10454cabf4ce778e0dedfe79c512b37f2c8c`.
The local Reth fixes are in `/home/ubuntu/repos/reth-payload-cancel-fix`;
build with `--config contrib/bench/payload-cancel-patches.toml`. A default build
without that configuration does not incorporate the dependency fix.

`build-manifest.json` identifies the archived node and source patches under
`../build-payload-cancel-20260923-v3`. `observer-manifest.json` identifies the
read-only checkpoint helper. The suite separately archives the executed harness
and its hashes, plus final analysis sources in `analysis-source/` and
`analysis-manifest.json`. The post-load reporting correction changes provenance
wording, not numerical analysis or the executed workloads. Final suite status
is recorded in `exit-code` and both case statuses in `manifest.json`.
