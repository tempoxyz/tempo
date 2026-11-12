# Antithesis targets

Each directory is one Antithesis target with its own workload image, config image
(`docker-compose.yaml` and `Dockerfile.config`) and publishing workflow.

| Target | What it tests | Workflow |
|---|---|---|
| [`reth-state-root`](reth-state-root) | Sparse-trie state root computation, `eth_getMultiProof`-style account and storage proofs (and the same proofs rebuilt from an execution witness) over the same blocks, persistence and restart recovery | [`antithesis-reth-state-root.yml`](../../.github/workflows/antithesis-reth-state-root.yml) |
| [`zones`](zones) | A Tempo L1 and zones network running deposits, withdrawals and transfers | [`antithesis-zones.yml`](../../.github/workflows/antithesis-zones.yml) |

[`trie-shapes`](trie-shapes) is the library the reth target uses: it generates writes in trie shape templates
(spikes, fans, nested groups, a dense storage trie) and reports the shapes each block reaches.

The reth target runs a `serve` process that owns the database and the model and builds blocks only
when a test template command asks over a Unix socket (`trie-shapes/src/harness.rs`). The commands, in
`test/v1/<template>/`, are subcommands of a separate binary (`<target>-commands` in `trie-shapes/src/bin`)
built without coverage instrumentation, so only the server reports coverage and has its threads paused:

| Command | What it does |
|---|---|
| `first_genesis` | Waits for the server and builds the first block |
| `parallel_driver_writes` | Draws one trie-shapes step against the tip state and queues its writes |
| `parallel_driver_blocks` | Builds 1 to 4 blocks from queued writes, padded with random ones |
| `parallel_driver_proofs` | Proofs and the execution witness at random blocks, verified against the model's root |
| `anytime_root` | The root the overlay serves at the tip equals the model's |
| `eventually_persisted` | Flushes to the head; the persisted state, the tip root and proofs must match the model |
| `finally_recovered` | The same once the server is back after the last fault |

Launch the reth target with `--fault-tolerance legacy` (network faults and thread pauses, no container
kills), which leaves restart recovery unexercised: "Restart recovers persisted blocks" stays unreached. A command that finds the server down exits successfully, so a restart is not a failure. Run one
locally with `ANTITHESIS_TRIE_SOCKET=/tmp/trie.sock` set for both the server and the commands.

The zones workload drivers live in `xtask/zones-antithesis`, also built uninstrumented; see [`zones/README.md`](zones/README.md).

## Sparse branch and proof-target coverage buckets

The reth workload image patches the **pinned** Reth arena at dirty-branch RLP
encoding and at blinded proof-target emission. This is a standalone alternative to JSON tuple guidance: there is no
per-observation SDK JSON emission. The hook and source-hash guards are Docker-only;
normal Tempo/Reth builds and trie behavior are unchanged. The callback is included
in the workload binary but ordinary builds never call it.

Measurements come from live arena handles, not sorted model keys. Depth is the
logical branch path length including its short key (0..63); `is_root` means depth
zero. State means occupied children; revealed means arena-backed children; leaf
means a revealed leaf, including a lower-subtrie leaf root. The required runtime
relationship is `leaf ⊆ revealed ⊆ state`. Derived masks are occupied-unrevealed
(`state & !revealed`) and revealed-nonleaf (`revealed & !leaf`); these are disjoint.
All masks refer to the 16 child nibble positions.

### Finite coverage design

`generate_sparse_buckets.py` emits macro invocations and explicit dispatch arms.
The original encoder bank retains **543 valid functions plus one invalid control = 544**.
Two proof-target banks add **44,352** functions, with two proof controls, for
**44,898 distinct functions** total.
Every valid encoder observation calls **26 functions**, not a Cartesian product of exact
masks. Numeric suffixes in generated names are the zero-based bucket indices below.

- Count: 0, 1, 2–4, 5–8, 9–16 (popcount).
- Shape: empty, singleton, contiguous, scattered, full, in that index order.
  Full and singleton take precedence over contiguous; contiguous is a single
  non-wrapping run at any position (0x8001 is scattered, not contiguous).
- Depth: 0, 1, 2–4, 5–8, 9–16, 17–32, 33–63. Root: false, true.

| Coverage family | Functions |
| --- | ---: |
| Depth and root independent ladders | 7 + 2 = 9 |
| Count and shape independent ladders for all five masks | 5 × (5 + 5) = 50 |
| Count × shape per mask, only 9 feasible pairs | 5 × 9 = 45 |
| Depth × count × shape, for all five masks | 5 × 7 × 9 = 315 |
| State count × revealed count; revealed count × leaf count | 15 + 15 = 30 |
| Occupied-unrevealed count × revealed-nonleaf count | 24 |
| Root × state count × revealed count × leaf count | 2 × 35 = 70 |
| Invalid depth, root, or subset relationship | 1 |
| **Total** | **544** |

The nine count/shape pairs are empty/empty, one/singleton, each of 2–4 and 5–8
with contiguous or scattered, and 9–16 with contiguous, scattered or full. Subset
count pairs/triples are non-increasing bucket indices. Disjoint relationship count
pairs omit only (9–16, 9–16), whose minimum combined count exceeds 16. No exact-mask Cartesian products are generated. Empty/singleton branch buckets may
not occur at this encoding site, but the helpers are reachable and tested; not every
mathematically feasible bucket is promised to be attainable in a real workload.

Each macro generates a named `#[inline(never)]` function accessing its own atomic
slot and passing its address and identity through `black_box`. Docker verifies all
44,898 optimized symbols have distinct addresses, each has a unique entry guard, and
each function entry appears in the runtime PC table. These are real coverage locations,
**not** SDK assertions or an official
`sometimes_each!` API; whether the extra locations improve search remains empirical.
The 26 relaxed atomic updates per branch add overhead, which comparisons must include.

### Proof-target banks

Only the workload-only arena patch calls `antithesis_sparse_proof_target`, where a
proof request originates: blinded traversal in both upper and lower tries, a leaf
removal requiring its blinded sibling, and a subtrie collapse requiring its blinded
sibling. Deferred proof drains do not duplicate observations. The tuple is the emitted
blinded child nibble, logical parent depth (including compressed short keys), and
that parent's local occupied/revealed/leaf masks, read before mutation. No model keys,
emission reason, exact-mask banks, or JSON guidance are added. Subtrie leaf roots
are classified through the same local arena handles as the encoder hook.

- **Local:** 7 depth buckets × 16 target nibbles × 4⁴ = **28,672** functions.
  The ordered positions are target−2, target−1, target+1, target+2. Their classes are
  absent (0), blinded (1), revealed nonleaf (2), revealed leaf (3), encoded little-endian
  in base four. Out-of-range positions are absent, never wrapped; target nibble stays
  a dimension so boundary padding is unambiguous. The finite bank includes padded
  combinations that cannot occur at boundaries.
- **Sandwich:** 7 depth buckets × 1,120 ordered triples × 2 revealed-child leaf
  states = **15,680** functions. For each emitted target i, reveal j and other blinded
  occupied child k, j must be strictly between i and k in either direction. Every
  qualifying triple hits its own function; multiple triples can hit per request.
  In particular target 5 / revealed a / blinded c differs from target c / revealed a /
  blinded 5, and leaf/nonleaf at a is independent.
- A parentless blinded root has one separate bounded control; malformed masks,
  depths, target nibbles or non-blinded targets hit one invalid-proof control.

Stable IDs 0–543 retain the encoder bank, 544–29,215 are local, 29,216–44,895
are sandwich, and 44,896–44,897 are parentless/invalid-proof controls. The generated
source is finite and about 4.6 MB, with shared arithmetic dispatch and a constant
triple-rank table rather than a huge exact-mask match. All functions use the same
noinline/unique atomic slot/black-box anti-folding instrumentation as before.

### Bounded diagnostics and checks

Each function emits its first hit only, with its ID and raw runtime tuple: at most
544 `sparse_bucket_v1` lines and 44,354 `sparse_proof_bucket_v1` lines per process. `sparse_observations_v1` reports the cumulative
valid branch observation count at powers of two (at most 64 lines); the latest value
is a lower bound, not an exact final count. Restarts reset both bounds. No masks are
used as dynamic SDK guidance. Existing workload SDK assertions remain unchanged.

Run `python3 -B contrib/antithesis/reth-state-root/test_sparse_buckets.py` for
standalone optimized Rust tests (no Reth build): all 65,536 masks, all 4^8 subset
assignments in each half, sixteen-position relationship/depth fixtures, all generated
arms and unique counters/function pointers, all 28,672 local mappings with boundary
padding, all 15,680 sandwich mappings, actual bounded diagnostic output, runtime
entry-guard callback hits in both sandwich directions, and
per-function sancov verification. Image smoke requires actual proof-hook/local-bank
evidence; sandwich evidence is validated when present but is not mandatory in a
short randomized run. Deterministic callback tests cover sandwich directions and
leaf states. Run `test_patch_sparse_trie.py` for fail-closed
patch guards, a hash-checked compressed copy of the actual pinned arena source,
ABI/mask helper execution and instrumentation-only byte-for-byte preservation; regenerate with `generate_sparse_buckets.py` after changing the design.
Use `generate_sparse_buckets.py --metadata` for the JSON ID/name manifest, arm count
and family count when reclassifying comparison data. CI selects Rust 1.96 to match
the Docker compiler for standalone checks.

Push/dispatch CI checks generation/tests, builds and uploads the workload, verifies
optimized symbols, then pulls the **immutable digest** and drives a finite full-trie
round. The smoke gate independently classifies every first-hit tuple, rejects invalid
subsets/root/depth, duplicates, stale JSON guidance, hit unreachable assertions and
missing runtime families, and checks
setup, workload assertions and verified completion before publishing the paired config.
A reused workload digest must pass the same gate. CI is still needed to validate the
actual pinned dependency and image; source-only tests are not an image smoke test.
