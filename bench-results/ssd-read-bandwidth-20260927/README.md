# SSD read bandwidth versus small-request latency

Measured 2026-09-27 11:04:32-11:08:13 UTC, after the bytecode latency
decomposition. Both benchmark SSDs are Micron MTFDKCC3T8TGP-1BK1DABYY,
firmware E3MQ005, negotiated PCIe 4.0 x4 (16 GT/s, width 4).

## Sequential throughput

GB/s below is decimal. Queue depth is the number of outstanding fio operations.

| Request size | Queue depth | Builder GB/s | Follower GB/s |
| --- | ---: | ---: | ---: |
| 4 KiB | 1 | 0.403 | 0.471 |
| 28 KiB | 1 | 1.518 | 1.583 |
| 128 KiB | 1 | 2.108 | 2.116 |
| 1 MiB | 1 | 2.472 | 2.544 |
| 128 KiB | 32 | 6.852 | 6.849 |
| 1 MiB | 32 | 6.854 | 6.855 |

The kernel's maximum hardware request size is 512 KiB on both devices, so a
1 MiB fio operation is split. Use the 128 KiB rows when discussing a nominally
single hardware request. Observed fio depth was 100% at the requested level.

## Random single-request latency

These fio total mean latencies include submission and completion, unlike the
earlier kernel issue-to-completion measurements. They independently agree with
the earlier direct-I/O bytecode controls.

| Read size | Builder latency | Follower latency |
| --- | ---: | ---: |
| 4 KiB | 63.90 us | 63.90 us |
| 24 KiB | 92.55 us | 92.52 us |
| 28 KiB | 97.59 us | 97.50 us |

Increasing a random request from 4 to 28 KiB adds 24 KiB and 33.59-33.68 us:

```text
24 * 1024 bytes / 33.6 us = approximately 0.73 GB/s
```

This is an empirical marginal rate for small isolated random requests, not
the SSD's sustained sequential capacity. The corresponding marginal rate
between 4 and 24 KiB is about 0.715 GB/s. At the measured sequential peak,
24 KiB represents only about 3.59 us of aggregate data throughput.

Thus a ~1 GB/s effective single-request model is of the right order, but a
drive-wide 1 GB/s bandwidth ceiling is ruled out. The extra wait depends on
the size/access pattern of the storage request. These host measurements do
not identify which internal NAND/controller/completion mechanism causes it,
and are not proof of saturated bandwidth in the EVM benchmark.

## Method and validation

- Existing stopped benchmark databases, one SSD at a time, under the shared
  `/tmp/tempo-general-state-access-20260922.lock` benchmark lock.
- fio 3.36, libaio, `--readonly --direct=1 --allow_file_create=0 --invalidate=0`.
  The read-only flag prevents write/trim workloads; see the
  [fio documentation](https://fio.readthedocs.io/en/latest/fio_doc.html#cmdoption-readonly).
- A 32 GiB file range starting at offset 8 GiB. Saved FIEMAP output verifies
  complete allocation with no holes or unwritten extents in that range.
- CPU 0 for builder, CPU 8 for follower; one fio job per test.
- Each case measured for 10 seconds following a 2-second ramp.
- Nine cases per device, all errors zero, write/trim bytes zero, actual device
  reads nonzero, requested queue depth achieved, file size/mtime unchanged.
- O_DIRECT bypasses the OS page cache, not any SSD-internal caching/read-ahead.
  These are short baseline measurements, not steady-state endurance testing
  or statistical confidence intervals.
- Health snapshot: zero media errors, critical warnings, or thermal-throttle
  transitions. PCIe links were not degraded to a lower speed/width.

`run.cjs` contains the exact locked commands and refuses to overwrite result
files. `manifest.json` records each command and result. `hardware.json` records
hardware and health. Raw per-case fio JSON and file extent maps are retained.
`node analyze.cjs` revalidates the completed sweep and regenerates `summary.json`.
For a new run, use the portable runner below rather than the original host-specific script.

## Fresh-checkout entry point

For a new read-only run, use `node contrib/bench/run-ssd-read-bandwidth.cjs --help`
from the repository root. It requires explicit source files and a new results
directory; the original `run.cjs` records the measurement host and must not
be rerun in this archived directory. `node analyze.cjs` recomputes the saved
summary from checked-in fio output, or pass a new results directory to analyze it.
