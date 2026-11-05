# Kaizen for Simplex: a verified Tempo follower core

This directory applies the Kaizen method ([Kalim et al.](https://muraliadithya.github.io/static/kaizen.pdf)) to Commonware's Simplex consensus as Tempo runs it. The protocol is proved in an interactive prover. The follower's decision logic is refined to executable code that is proved equal to its spec. That code is compiled to C and wrapped in an unverified shim. The result syncs Tempo testnet from its public consensus RPC.

| Kaizen stage | Here | Files |
|---|---|---|
| I. Abstract protocol and proofs | Lean 4 + Mathlib | `Kaizen/Simplex/`, `Kaizen/Follower/Spec*.lean`, `Kaizen/Glue.lean` |
| II. Verified executable refinement | Lean 4 (UInt64, ByteArray, HashMap) | `Kaizen/Follower/{Codec,Impl,Refinement,CodecProofs}.lean`, `Kaizen/FFI.lean` |
| III. Unverified shim | Rust, linked to the Lean-generated C | `shim/` |

## What is proved

The proofs use no `sorry` and no axioms beyond Lean's standard `propext`, `Classical.choice` and `Quot.sound`.

- `Kaizen.Simplex.safety`: Simplex is modelled as a state-transition system with n validators, at most f of them Byzantine, and quorums q with n + f < 2q (n - f when n ≥ 3f + 1). Honest validators follow Commonware's voter rules for notarize, nullify and finalize. In every reachable state, any two finalized proposals lie on one chain. `finalized_unique_at_height` is the corollary that two finalized proposals at the same height are equal.
- `Kaizen.Follower`: the follower's step function decodes the certificate, checks that the payload is the block digest, the epoch contains the height, the identity is right for the epoch, and the threshold signature is valid. It also checks linkage (height is tip + 1, parent is the tip, round increases) and, at a boundary block, takes the next epoch's DKG identity. On any input sequence, including adversarial ones, every accepted tip is finalized (`run_tip_finalized`) and the accepted chain is parent-linked (`run_linked`). Two followers never accept different digests at the same height (`agreement`), and a genuine next block whose signature and execution both verify is always accepted (`step_progress`).
- Execution: the tip records the accepted block's state root (`run_tip_state_root`). After the signature check, a block is accepted only if the `kz_verify_execution` oracle says executing it on the tip's state root yields its header's state root (code 12 otherwise); the first accepted block's root is the trusted anchor. Under oracle soundness, every consecutive pair of accepted blocks is a valid state transition, so the accepted chain is an execution chain from the anchor (`run_executed`, `Kaizen.FFI.kz_run_executed`).
- Codec: the certificate decoder (LEB128 varints, 32-byte payload, 96-byte signature) round-trips. It rejects non-canonical varints, overflow and trailing bytes, and its ByteArray implementation refines the list spec (`decodeCert_refines`).
- Refinement: `implStep_refines` shows the executable state and step equal the spec under the abstraction function. `Kaizen.FFI.kzStep_refines` shows the same for the exported C entry points.
- `Kaizen.Glue.extracted_followers_agree`: this ties the pieces together. Tempo is modelled as one reachable Simplex instance per epoch. Two runs of the exported core, on arbitrary inputs, never finalize different digests at the same height. `extracted_followers_agree_state` adds that tips at the same height have the same state root, given that the committed header binds the state root to the digest.

## Trusted computing base

These are the assumptions of the theorems, as Kaizen lists its own:

- BLS threshold soundness: a certificate that verifies under an epoch's identity means a quorum signed the finalize vote. The shim checks this with Commonware's `Finalization::verify`, called from Lean as the `kz_verify_finalization` oracle.
- Execution soundness: when `kz_verify_execution` returns true for a pre-state root, block digest and header state root, executing that block from that state is valid and yields that root. The trusted anchor is the first accepted block's state root.
- The compiled-in network identity (`testnet-network-identity.json`) is correct from its `from_epoch` onward. A DKG outcome in a finalized boundary block is correct for the next epoch.
- Execution oracle soundness: `kz_verify_execution` answers true only if the shim re-executed the block to that root. The shim reads the parent state through `eth_getProof` from an untrusted RPC, keeps every proof node keyed by its own hash so each read is checked against the parent's state root, executes with Tempo's `TempoEvmConfig` block executor, checks gas, receipts root and bloom with `TempoConsensus::validate_block_post_execution`, and recomputes the post-state root over those nodes (`shim/src/mpt.rs`, tested against alloy's `HashBuilder`). A deletion that merges a sibling the pre-state proofs did not reveal takes that sibling from post-state proofs of the deleted key. Those nodes are used only when their hash matches, so a lying RPC can stall the follower but cannot make a wrong root match. BLOCKHASH answers come from the 256 previous headers, each checked against its successor's parent hash.
- The shim binds each candidate's fields to the block. It computes the digest as keccak(RLP header) itself, takes the parent, height and state root from that header, checks the body against the header's transactions, ommers and withdrawals roots, and parses the DKG outcome from the header's extra_data.
- The Lean compiler, the C compiler, the Rust code and the RPC transport. The upstream RPC is untrusted: it can only stall the follower, not make it accept a wrong block.
- Model scope: one static validator set per epoch, term length 1 (no stable-leader terms), and application certification abstracted as notarized-or-finalized. The model checks safety only. Liveness is the acceptance lemma above, not a network-level argument.

## Differential fuzzing

`fuzz/` runs the extracted core next to an independent Rust reference written from Tempo's and Commonware's code (Commonware's own certificate decoder, `FixedEpocher`, `FinalizationVerifier`'s identity rules). It compares result codes, tips (height, digest, state root) and every oracle call after each step. `fuzz/README.md` describes the generators and how to run them. So far it has found no divergence in:

- about 120M deterministic steps, over 3 seeds
- a 20-minute libFuzzer run with SanitizerCoverage on the Lean-generated C (7.4M inputs)
- 4,800 real testnet blocks across two epoch boundaries, with real BLS, plus 14,394 mutations

The only inputs left uncompared are ones Tempo itself panics on: epoch length 1, and heights in the final partial epoch below `u64::MAX`.

Execution is checked against Tempo's own nodes: every re-executed block must reach the state root in the header that validators finalized. All 1,203 testnet blocks re-executed in two live runs matched, with none failing.

## Build and run

```sh
lake exe cache get && lake build            # check every proof (Lean toolchain from lean-toolchain)
cd shim && cargo build --release            # build.rs runs lake for the C targets and links libleanshared
./target/release/kaizen-follower --from latest                 # follow testnet head, re-executing every block
./target/release/kaizen-follower --from epoch:1972 --count 30000 --trust-execution # history (proofs reach ~recent blocks only)
./target/release/kaizen-follower --check-oracle                 # BLS oracle vs. Commonware's own decode
./target/release/kaizen-follower --check-exec 20                # re-execute the last 20 blocks, compare state roots
./target/release/kaizen-follower --from latest --trust-execution  # consensus only (oracle answers true)
```

The shim has its own Cargo workspace, with Tempo's lockfile and patches, so Tempo's workspace and CI never need Lean.

Execution checking needs `eth_getProof` for each block's parent. The public testnet RPC answers it only for roughly the last few hundred blocks, and rate-limits it. Historical sync therefore runs with `--trust-execution`, and at the head the follower re-executes every block. On the public RPC that runs at about 1.2 blocks/s against the chain's ~1.7, so it falls behind. Point `--proof-rpc` at a node without rate limits to keep up.
