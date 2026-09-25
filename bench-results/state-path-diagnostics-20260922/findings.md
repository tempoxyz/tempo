# Bounded state-path storage diagnostics

Date: 2026-09-22. These are storage-engine controls, not EVM benchmarks.
They do not establish that bytecode access or writes are worse per gas than
the existing SLOAD workload. No contracts or transactions were generated,
no prewarming-evasion experiment was performed, and Merkle updates were not
measured. The 100 GB node fixtures were not changed.

## Method

- Linked the existing bundled MDBX 0.13.12 static library; kernel 6.8.0-139-generic.
- Used disposable fixtures on /mnt2, backed by /dev/nvme2n1, the follower's SSD.
- Matched the node's WRITEMAP mode and disabled-read-ahead setting; enabled
  read-ahead only as an explicit comparison. Used MDBX default durable commits.
- Three trials, each with 2048 ordinary records of 32, 1024, or 24576 bytes.
  Keys are eight bytes, values are raw bytes, and the table is not DUPSORT.
  These are not Reth's serialized Bytecodes or HashedStorages table formats.
- Read every record in a fixed permutation and verified every byte. Cold
  measurements include environment opening as well as lookups. Warm measurements
  use the same open environment. Timing includes correctness checks.
- Before each cold control, closed and synced only its private fixture, requested
  file-specific eviction, and verified zero resident file pages with mincore.
  No global cache flushing. All 21 cold-residency checks passed.
- Writes overwrite the 32-byte records in batches of 128, with durable commit
  inside the measured interval. Eight rounds per trial; values verified before
  overwriting and again after closing and reopening the database.
- Maximum database geometry is 256 MiB per fixture. All temporary database
  files are deleted after successful verification.

## Record reads

Aggregate means over three trials (6144 record reads per row):

| Record size | Read-ahead | Cold major faults / record | Cold read bytes / record | Warm major faults / storage read bytes |
| --- | --- | ---: | ---: | --- |
| 32 B | Disabled | 0.013672 | 80 | 0 / 0 |
| 32 B | Enabled | 0 | 80 | 0 / 0 |
| 1 KiB | Disabled | 0.415527 | 1726 | 0 / 0 |
| 1 KiB | Enabled | 0.014160 | 1726 | 0 / 0 |
| 24 KiB | Disabled | 7.004395 | 28714 | 0 / 0 |
| 24 KiB | Enabled | 0.213379 | 28714.667 | 0 / 0 |

The 24 KiB fixture had 14336 overflow pages for 2048 records, or seven
4 KiB overflow pages per record, plus 16 leaf pages and one branch page.
Thus adjacent overflow pages do not guarantee a single major fault under this
configuration. Read-ahead reduced faults considerably without materially reducing
total read bytes. We did not count block-device read requests or SSD-internal work.

The small-record rows share pages heavily across the full pass. They are not
comparable to independent cold storage accesses in the large SLOAD fixture.
Nor does a cold start on a small database demonstrate sustained cache misses.

## Ordinary durable updates

| Interval | Updates | Major faults | Read bytes | Accounted write bytes |
| --- | ---: | ---: | ---: | ---: |
| First round, all three trials | 6144 | 39 | 344064 | 7335936 |
| Rounds 2-8, all three trials | 43008 | 0 | 0 | 51351552 |

Both intervals accounted for 1194 write bytes per 32-byte replacement. This is
MDBX/filesystem write overhead in this particular small, batched fixture, not
Merkle amplification, SSD NAND amplification, or a per-gas result. The working
set becomes resident: the later rounds perform real durable writes without
additional storage reads. This does not predict the read behavior of a large
write-heavy node workload. Write rounds exclude environment-opening overhead.

The write result supports measuring persistence rather than assuming deferred
writes disappear. It does not test whether Merkle-path reads increase sustained
page misses in the 100 GB fixture. That remains unanswered.

## Counter interpretation

Major faults use getrusage(RUSAGE_SELF). Read/write byte deltas use /proc/self/io.
Linux accounts read_bytes at storage submission and write_bytes at page-dirtying
time; these are not exact device request counts or NAND byte counts. Durable
commits complete inside each update measurement, and fixture deletion occurs
after the measurements. See the
[Linux I/O counter definitions](https://docs.kernel.org/filesystems/proc.html#proc-pid-io-display-the-io-accounting-fields).

Each cold total was checked against its open plus lookup counters. All warm
passes had zero major faults and zero accounted storage reads. Opening the
WRITEMAP environment accounts for a small amount of write traffic, retained in
the raw cold_total rows rather than classified as a read-operation write.

## Artifacts

- Final raw results: mdbx-io-final.jsonl (130 JSON lines).
- Validated aggregate results: summary.json.
- Earlier mdbx-io.jsonl and mdbx-io-v2.jsonl are pilot measurements, not the final
  configuration. The first omitted cold-open attribution; both lacked WRITEMAP.
- Source: [mdbx-io-diagnostic.c](../../contrib/bench/mdbx-io-diagnostic.c).
- Node settings: [MDBX environment setup](/home/ubuntu/.cargo/git/checkouts/reth-e231042ee7db3fb7/dfcb104/crates/storage/db/src/implementation/mdbx/mod.rs:407)
  and [read-ahead setting](/home/ubuntu/.cargo/git/checkouts/reth-e231042ee7db3fb7/dfcb104/crates/storage/db/src/implementation/mdbx/mod.rs:471).

Build from the benchmark worktree, then run with a disposable-file parent directory:

```sh
cc -O2 -Wall -Wextra -Werror -Wno-deprecated-declarations \
  -I /home/ubuntu/.cargo/git/checkouts/reth-e231042ee7db3fb7/dfcb104/crates/storage/libmdbx-rs/mdbx-sys/libmdbx \
  contrib/bench/mdbx-io-diagnostic.c \
  target/profiling/build/reth-mdbx-sys-38b243668ec2762b/out/libmdbx.a \
  -pthread -lm -ldl -o /tmp/tempo-mdbx-io-diagnostic
/tmp/tempo-mdbx-io-diagnostic /mnt2
```
