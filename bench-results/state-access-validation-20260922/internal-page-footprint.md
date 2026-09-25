# Internal-page footprint

Inspected on 2026-09-22 using metadata-only, read-only `tempo db stats
--skip-consistency-checks` on the restored A database. Confirmed both nodes'
live counts from the dependent-repeat archive, offsets 600000-1200000 ms,
120 scrapes per series.

## Counts during the measured load

Database pages are 4096 bytes. Both nodes had the same ranges below.

| MDBX table/scope | Internal pages per node | Maximum footprint per node |
| --- | ---: | ---: |
| HashedStorages | 214016-214018 | 836.008 MiB |
| StoragesTrie | 475671-475672 | 1.814545 GiB |
| All MDBX tables | 689690-689693 | 2.630970 GiB |

The three other internal pages were one each in BlockBodyIndices, HeaderNumbers,
and TransactionBlocks. These are MDBX B-tree branch pages, not a count of logical
Ethereum trie nodes. The bundled MDBX checker compares the reported branch total
with top-level plus nested-tree branch pages, so the counts include nested
duplicate trees.

For two distinct database copies, the storage-read branch footprint is about
1.633 GiB; all MDBX branch pages together are about 5.262 GiB. HashedStorages is
the populated latest-state storage table; PlainStorageState is empty. StoragesTrie
is a separate table used for trie/state-root work, not a mandatory trie walk for
each SLOAD.

The restored snapshot had 214009 HashedStorages branch pages and 18618205 leaf
pages. Its storage leaf footprint alone is 71.023 GiB per node. The small branch
count increase during the run does not materially affect the capacity conclusion.

## Actual host memory during the same interval

| Host metric | Minimum | Median | Maximum |
| --- | ---: | ---: | ---: |
| MemTotal | 62.403 GiB | 62.403 GiB | 62.403 GiB |
| Cached | 46.813 GiB | 47.138 GiB | 47.474 GiB |
| AnonPages | 5.088 GiB | 5.252 GiB | 5.593 GiB |
| MemAvailable | 48.202 GiB | 48.575 GiB | 48.731 GiB |

Linux Cached includes file cache and tmpfs/shared memory; Shmem was only about
2.4 MiB here. Cached and MemAvailable overlap and must not be added together.
See the [Linux memory-counter definitions](https://docs.kernel.org/filesystems/proc.html#meminfo).

Both nodes' storage-read branch pages amount to about 3.5% of the observed host
Cached footprint. Even all MDBX branch pages for both nodes amount to about 11.2%.
The host-wide file cache is not a reserved per-node allocation, but the index
footprint is comfortably below the observed cache capacity.

## Interpretation

Capacity does not appear to make sustained internal-page thrashing a realistic
primary explanation for this fixture. Internal pages serve many leaf lookups and
are generally reused more often than individual leaves. Combined with their small
footprint, this suggests most hot index pages should remain resident after warmup.
The much larger leaf working set is the more plausible source of sustained cold
reads. This is an inference, not measured fault attribution by page type.

Transient internal-page evictions remain possible: fitting in RAM does not pin
pages or guarantee their residency. No eviction experiment, cache flush, full
database scan, or workload modification was performed. Directly proving the
branch-versus-leaf fault split would require additional page-type attribution.

## Evidence

- Runtime metrics: `reth_db_table_pages{type="branch",node="a"|"b",table=...}`.
- Host metrics: `node_memory_{MemTotal,Cached,AnonPages,MemAvailable,Shmem}_bytes`.
- Archive: `bench-results/20260922-152637-070/report-feature-1.samples.ndjson.gz`.
- Snapshot: `/reth-bench-a/tempo_e2e_100000mb_state_access_isolated_roles`.
- Bundled MDBX source: `mdbx.c` lines 14945-14955 checks branch counts against
  top-level plus nested branches. No full checker traversal was run.
