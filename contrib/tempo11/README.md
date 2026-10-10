# tempo11

An experimental COBOL block follower and 256-bit stack interpreter. Every block
closes the books.

**This is a runnable prototype, not a validating Tempo node.** The follower
trusts an upstream JSON-RPC provider for block contents, hashes, and finality.
It checks height and parent-hash continuity, but does not recompute block hashes,
verify finality certificates, execute transactions, or verify state roots. The
standalone interpreter is not connected to block ingestion.

## Build and run

Requires GnuCOBOL 3.1+, a C compiler, Make, and Python 3.10+ through `uv`.
On Ubuntu 24.04, install `gnucobol3` and `build-essential` with your package manager.

```sh
cd contrib/tempo11
make
make test

# Execute PUSH1 2; PUSH1 3; ADD; STOP in COBOL.
uv run python tempo11.py evm 0x600260030100
# STACK 1
# 0000000000000000000000000000000000000000000000000000000000000005

# Replay the explicitly synthetic demo chain. Use a fresh database.
uv run python tempo11.py replay --chain-id 4217 \
  --blocks fixtures/demo.jsonl --database demo.sqlite

# Follow up to 100 finalized blocks from a trusted Tempo RPC, starting at genesis.
# Supply the expected chain ID yourself; a mismatch aborts ingestion.
uv run python tempo11.py follow --rpc https://rpc.tempo.xyz \
  --chain-id 4217 --database tempo11.sqlite --once --limit 100
```

Remove `--once` to poll until `--limit` new blocks have been persisted. The default
limit is 1,000 per invocation. Restarting resumes after the durable head; it
rechecks that head against the upstream before accepting more blocks. An upstream
that does not serve historical blocks or the `finalized` tag is unsupported.

The synthetic fixture is for exercising ingestion only. Its hashes are labels,
not cryptographic block hashes. Never reuse its database for a real chain.

`fixtures/zone-e-headers.jsonl` contains real Zone E block 1 and 2 header fields,
queried from TIDX chain `zone_e` (chain ID `421700001`) on 2026-10-10 with
`SELECT num, hash, parent_hash FROM blocks WHERE num < 3 ORDER BY num ASC`.
The test explicitly trusts block 1 as an anchor and checks the link to block 2;
this is not a finality or execution test. Live mainnet following was attempted
from the development sandbox but its RPC request returned HTTP 403.

## Architecture and trust

```text
JSON-RPC / replay file
        |
        v
Python transport: strict envelope / quantity / hash-shape checks
        |
        v
COBOL ledger: contiguous heights + exact parent-hash equality
        |
        v
SQLite: atomic durable append
```

`src/ledger.cob` owns the continuity checks. Python handles HTTP, JSON, subprocess
I/O, and SQLite through its standard library. Each accepted block is committed in
a transaction with WAL and `synchronous=FULL`; rejected blocks are not committed.
Already committed blocks remain after a later block fails. A transactional head
check prevents concurrent processes from appending conflicting branches.

The database stores the expected chain ID and fetched block JSON, including
transaction hashes rather than full transactions. Existing local data is trusted;
the COBOL process is anchored to the last durable record on restart. The chain ID
alone does not authenticate a network, and a malicious upstream can fabricate an
entire internally consistent chain. Conflicting upstream history halts ingestion;
there is no automatic rewind. There is no P2P, transaction submission, RPC server,
validator signing, or production service deployment.

The private COBOL line protocol accepts `BLOCK <decimal-height> <hash> <parent>`
and one initial `ANCHOR` with the same fields. Hashes are 64 lowercase hex digits,
without `0x`. `ANCHOR` is for restoring trusted local state, not a finality proof.
An `OK` response authorizes the Python driver to attempt a durable append. If that
append fails, the command exits; a fresh process restores the actual durable head.

## Standalone interpreter

`src/evm.cob` implements STOP, ADD, MUL, SUB, LT, GT, EQ, ISZERO, AND, OR, XOR,
NOT, BYTE, POP, PC, PUSH0–PUSH32, DUP1–DUP16, and SWAP1–SWAP16. Words are 32-byte
big-endian values; arithmetic wraps modulo 2^256. Execution uses a 1,024-word stack
and accepts up to 32 KiB of bytecode. Missing PUSH immediate bytes are zero-padded.
Output lists the final stack from bottom to top.

Unsupported instructions, malformed hex, stack underflow, and stack overflow exit
nonzero. There is **no gas accounting**, memory, storage, calls, logs, transaction
context, or Tempo precompile execution. This is an opcode experiment, not an
implementation of `eth_call` or an EVM conformance claim.

Tests compare arithmetic and bitwise operations against an independent Python
integer model, including unsigned overflow and noncommutative operand ordering.
They also exercise a local JSON-RPC server through the CLI, process restart,
concurrent writes, malformed inputs, and conflicts without rewriting saved blocks.

## Next milestones

1. Pin a Tempo protocol revision and build execution fixtures from the reference
   client. Add gas, memory, storage, control flow, and transaction semantics.
2. Implement Tempo transactions, system contracts, and authenticated state;
   compare state roots, receipt roots, logs, and gas with the reference client.
3. Verify consensus finality certificates and network identity transitions;
   authenticate checkpoints and snapshots.
4. Add independent block acquisition, serving RPC, a transaction pool, and only
   then validator participation.

Protocol reference: [Tempo](https://github.com/tempoxyz/tempo).
Compiler reference: [GnuCOBOL](https://gnucobol.sourceforge.io/).
