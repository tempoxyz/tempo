# Bytecode page-read diagnostic

`bytecode-page-diagnostic.c` isolates storage-engine behavior behind the
history-dependent bytecode workload. It is not an EVM throughput benchmark or
a replacement for `state-access-bloat-worst-case`.

The source must be a stopped, prepared `history_paths` scratch database. The tool
opens it read-only, reads table statistics, and selects 512 distinct 24 KiB
contract records through deterministic pseudorandom hash seeks. Selection uses
the next record after each hash, not a strictly uniform sample of record IDs.
It preserves their exact serialized values and 32-byte keys in a new, private
MDBX database, using 4 KiB pages and the node's WRITEMAP/COALESCE settings.

Three trials compare these access modes with read-ahead disabled and enabled:

- Read 32 bytes at the same code offset as the EVM workload, without decoding.
- Copy and verify the whole serialized value, modeling the decoder's page footprint.
- Copy the whole value after `MADV_WILLNEED` on only its page-aligned extent.

Before each cold trial, the tool closes and syncs only its disposable database,
uses file-specific `POSIX_FADV_DONTNEED`, and asserts zero resident file pages
with `mincore`. Each cold pass has a same-environment warm control. Both partial
and full reads verify the returned bytes against the extracted source records.
The tool deletes its own database on success. A failure leaves it for inspection.
It never flushes host-wide caches, evicts the source, or changes node settings.

## Build and Run

Build against the same bundled MDBX library as the node. These paths describe
the existing benchmark workspace; adjust the build-output hash for other builds.

```sh
cc -O2 -Wall -Wextra -Werror -Wno-deprecated-declarations \
  -I ../reth-payload-cancel-fix/crates/storage/libmdbx-rs/mdbx-sys/libmdbx \
  contrib/bench/bytecode-page-diagnostic.c \
  target/profiling/build/reth-mdbx-sys-38b243668ec2762b/out/libmdbx.a \
  -pthread -lm -ldl -o /tmp/tempo-bytecode-page-diagnostic

flock --nonblock /tmp/tempo-general-state-access-20260922.lock \
  sudo -n systemd-run --scope --quiet --collect \
    --unit tempo-bytecode-io-$(date -u +%Y%m%d-%H%M%S) \
    /tmp/tempo-bytecode-page-diagnostic \
    /reth-bench-b/tempo_e2e_100000mb_state_access_isolated_roles_history_paths/db \
    /mnt2
```

Run only when other benchmarks are stopped. The dedicated `tempo-bytecode-io-*`
cgroup is mandatory: its database-device `io.stat` supplies read-request counts
and bytes without attributing unrelated host I/O to the experiment. The source
and temporary parent must be on suitable local filesystems; use the benchmark's
NVMe device for meaningful timings, not tmpfs.

Output is JSONL: metadata, table statistics, 512 record-layout descriptions,
18 cold-residency checks, and 36 cold/warm measurements. Every group has three
trials of 512 reads. Cold measurements include environment opening and table
metadata. Timings also include byte verification; this is not the Rust decoder.

Major faults, read requests, and bytes are separate measurements. Targeted
prefetch can reduce fault/request counts without reducing bytes. General
read-ahead on the small copy can warm neighboring records, so its speedup must
not be extrapolated to random accesses across the full bloated database.
