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
- `Kaizen.Follower`: the follower's step function decodes the certificate, checks that the payload is the block digest, the epoch contains the height, the identity is right for the epoch, and the threshold signature is valid. It also checks linkage (height is tip + 1, parent is the tip, round increases) and, at a boundary block, takes the next epoch's DKG identity. On any input sequence, including adversarial ones, every accepted tip is finalized (`run_tip_finalized`) and the accepted chain is parent-linked (`run_linked`). Two followers never accept different digests at the same height (`agreement`), and a genuine next block is always accepted (`step_progress`).
- Codec: the certificate decoder (LEB128 varints, 32-byte payload, 96-byte signature) round-trips. It rejects non-canonical varints, overflow and trailing bytes, and its ByteArray implementation refines the list spec (`decodeCert_refines`).
- Refinement: `implStep_refines` shows the executable state and step equal the spec under the abstraction function. `Kaizen.FFI.kzStep_refines` shows the same for the exported C entry points.
- `Kaizen.Glue.extracted_followers_agree`: this ties the pieces together. Tempo is modelled as one reachable Simplex instance per epoch. Two runs of the exported core, on arbitrary inputs, never finalize different digests at the same height.

## Trusted computing base

These are the assumptions of the theorems, as Kaizen lists its own:

- BLS threshold soundness: a certificate that verifies under an epoch's identity means a quorum signed the finalize vote. The shim checks this with Commonware's `Finalization::verify`, called from Lean as the `kz_verify_finalization` oracle.
- The compiled-in network identity (`testnet-network-identity.json`) is correct from its `from_epoch` onward. A DKG outcome in a finalized boundary block is correct for the next epoch.
- The shim binds each candidate's fields to the block. It computes the digest as keccak(RLP header) itself, takes the parent and height from that header, checks the body against the header's transactions, ommers and withdrawals roots, and parses the DKG outcome from the header's extra_data.
- The Lean compiler, the C compiler, the Rust code and the RPC transport. The upstream RPC is untrusted: it can only stall the follower, not make it accept a wrong block.
- Model scope: one static validator set per epoch, term length 1 (no stable-leader terms), and application certification abstracted as notarized-or-finalized. The model checks safety only. Liveness is the acceptance lemma above, not a network-level argument.

## Build and run

```sh
lake exe cache get && lake build            # check every proof (Lean toolchain from lean-toolchain)
cd shim && cargo build --release            # build.rs runs lake for the C targets and links libleanshared
./target/release/kaizen-follower --from latest                 # follow testnet head
./target/release/kaizen-follower --from epoch:1972 --count 30000 # sync history across epoch boundaries
./target/release/kaizen-follower --check-oracle                 # BLS oracle vs. Commonware's own decode
```

The shim has its own Cargo workspace, with Tempo's lockfile and patches, so Tempo's workspace and CI never need Lean.
