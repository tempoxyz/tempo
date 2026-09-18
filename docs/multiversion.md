# Per-hardfork executables

Status: experimental bundle tooling. This is **not yet a replacement for the Tempo
node or the release workflow**. It does not yet build fork-specialized nodes, route
historical execution, or remove pre-T12 code from the current executable.

The intended unit is one executable per protocol hardfork, not one per release
tag. The canonical list is `TempoHardfork::VARIANTS`: Genesis, T0, T1, T1A, T1B,
T1C, T2 through T12. Genesis is necessary for chains whose history starts before
T0. Executable names are generated from that list, rather than maintained separately.

The packaging follows the flat-bundle approach in
[TigerBeetle's upgrade design](https://github.com/tigerbeetle/tigerbeetle/blob/47aeb2212a255273dda508288412e537d11e4b7c/docs/internals/upgrades.md).
The launcher, each embedded executable, and the archive format are separate from
the protocol's execution and activation policy.

## Bundle tooling

Build the development tool with:

```sh
cargo build --locked --bin tempo-multiversion
target/debug/tempo-multiversion forks
```

Given a directory with one **independently validated** native executable for each
of the printed names:

```sh
target/debug/tempo-multiversion pack --input-dir hardfork-binaries --output tempo-bundle
./tempo-bundle inspect
./tempo-bundle extract T12 --output tempo-t12
./tempo-bundle run T12 -- --help
```

`run` requires an explicit fork and currently supports Linux only. It verifies the
selected payload, seals it in an anonymous file, and replaces the launcher process.
It needs Linux memfd support and `/proc/self/fd`. macOS can pack, inspect, and
extract Mach-O bundles but still needs a native launch and code-signing implementation.
Do not replace a production `tempo` with this tool.

The packer requires all known forks, in canonical order, and rejects inputs with a
different native architecture from its launcher. It **cannot prove** a file named
`tempo-t12` implements only T12. It must not be used to relabel ordinary multi-fork
nodes as specialized executables. Rebuilding the bundle uses the unbundled launcher
and flat input files; it never embeds an earlier bundle recursively.

All integers in the archive are little-endian. Its layout is:

| Region | Fields |
| --- | --- |
| Launcher | Native executable bytes |
| Payloads | One nonempty executable per fork, in canonical order |
| Index header | Launcher length (`u64`), entry count (`u32`) |
| Index entry | Fork index (`u8`), absolute offset (`u64`), length (`u64`), SHA-256 (32 bytes) |
| Footer | `TEMPMV01` (8 bytes), index offset (`u64`), index length (`u64`), index SHA-256 (32 bytes) |

The reader bounds the index before allocating, rejects duplicates, gaps, overlaps,
unknown fork IDs, unsupported formats, overflows, and trailing bytes, and checks
payload hashes before successful extraction or execution. It can read an older
bundle ending before the latest fork, but never substitutes a different executable
for a missing requested fork. Payloads are streamed with bounded memory.

Checksums detect corruption; they do not authenticate the publisher. Release
checksums, signatures, SBOMs, and attestations must cover the **finished bundle**,
including its launcher. Packing happens before those release steps. The current
release workflow remains unchanged until the execution requirements below pass.

## Execution work required before T12-only cleanup

Tempo selects EVM rules using the block timestamp in `TempoEvmConfig::evm_env`
and `next_evm_env`. Historical calls and traces can request old rules while the
node is following the current chain. Choosing a binary once at startup is not
sufficient. T12 has no built-in mainnet or Moderato activation timestamp in this
source snapshot; dispatch must use the configured chain schedule, not the date,
the highest installed binary, or a guessed activation height.

The intended execution boundary is:

1. The node owns consensus, networking, RPC, and persistent database writes. A
   dispatcher derives the fork from the requested block's chain schedule and
   selects the matching bundled execution worker.
2. A worker receives versioned execution input and accesses the exact parent-state
   snapshot through a stable interface. It returns receipts, state changes, gas
   accounting, and errors for the node to validate and commit. Historical reads
   must not open the database with a second writer or a different schema version.
3. Calls, estimates, traces, imports, replay, payload building, system transactions,
   and pool validation must all use the same dispatch contract. Tracing currently
   uses generic Rust inspectors; serializing transactions alone does not preserve
   these callbacks or arbitrary Rust embedding APIs.
4. Each worker rejects inputs for another fork. At T12 activation, the T12 worker
   applies the T12 runtime migration against T11 parent state. Earlier initialization
   remains available for genesis and custom chains that activate multiple forks at
   timestamp zero. Fork metadata and old serialized data formats remain readable.
5. Only after dispatch works, specialize the T12 worker and remove superseded
   execution branches and inactive features. Keep protocol functionality inherited
   from earlier forks that is still active in T12. Preserve the general SDK's
   historical hardfork predicates; making them unconditionally true would silently
   change callers' semantics.

This requires a process protocol: the current EVM interface borrows mutable state,
generic databases, and inspectors in-process. The bundle tool does not introduce a
pretend IPC boundary or rewrite the hardfork predicates to bypass that constraint.

## Acceptance gates for release integration

- Replay from genesis across every fork boundary with identical block/state roots,
  receipts, gas, and errors to the existing node; include T1A/T1B/T1C.
- Historical calls, estimates, and supported traces during T12 execution agree with
  the existing node, including concurrent requests for different forks.
- Test custom genesis schedules, equal activation timestamps, boundary migrations,
  invalid payloads, and speculative state without committing partial worker output.
- Interrupt workers and restart the node before/after commit and at each boundary;
  verify database recovery and consensus restart. Never switch database writers
  while a previous process retains ownership.
- Missing/corrupt/wrong-architecture workers fail before executing or writing state.
- Build and exercise real specialized workers for every supported release target;
  verify the T12 artifact no longer contains obsolete execution implementations.
- Package and attest the final bundle, exercise installation through containers and
  tempoup, and test the macOS signature and launch path.

Until these gates pass, deleting historical execution code would break existing
node behavior. The experimental tool is deliberately not wired into production
releases and its tests are not evidence that those node-level gates have passed.
