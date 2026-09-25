# Preliminary Treatment Stopped: Pipeline Coverage Gap

The baseline completed and passed correctness/durability validation. The
treatment was intentionally stopped during excluded warmup, before collecting
a complete measured window. This directory is not a completed A/B comparison.

The initial hook explicitly required a read-only MDBX transaction. Pipeline
catch-up constructs `StateProviderDatabase(LatestStateProviderRef::new(provider))`
using a writable provider in Reth's execution stage. The faster builder caused
the follower to enter this path, which still demand-loaded the bytecode pages.
The follower's hint counter stopped growing while its execution gas continued
to increase in pipeline mode.

One warmup observer snapshot showed builder/follower heads 715/257 and recent
gas-processing wall rates 17.98/6.73 Mgas/s. These are progress diagnostics,
not sustained throughput results. A subsequent metrics snapshot showed three
pipeline runs, 2,073,935,050 executed gas, only 241,586 prefetch hints, and zero
hint errors. The hypothesis was corroborated by the explicit RO gate in the
archived source and the execution-stage writable-provider path.

The corrected experiment in `../bytecode-prefetch-e2e-20260924-v2` moves the
hook into a raw-value decoder that can use `mdbx_is_dirty` before any copy.
Clean mapped values are eligible in both RO and RW transactions; dirty values
are excluded. Writable-transaction hints have a separate counter. Both control
and treatment are rerun with that same corrected binary, rather than comparing
different builds or reporting the incomplete treatment as an outcome.
