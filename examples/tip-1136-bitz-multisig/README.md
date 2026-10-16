# TIP-1136 private multisig on Lean / BitZ / binary WHIR

This is a port of the [`tip-1136-private-multisig`](../tip-1136-private-multisig) Noir circuit to the stack that may succeed Noir/Spartan/WHIR:

| Layer | Noir reference | This example |
| --- | --- | --- |
| Specification and gadget proofs | Noir source | Lean 4: relation spec and gadget lemmas in [`lean/`](lean); the P-256 and SHA-256 gadgets are ports of [Freigen](https://github.com/reilabs/freigen)'s verified Lean circuits |
| Arithmetization | R1CS over BN254 | [BitZ](https://github.com/worldfnd/BitZ) ([paper](https://eprint.iacr.org/2026/2141)): integer R1CS over bit-decomposed witnesses, so range checks are free |
| Commitment and opening | WHIR over a prime field | GF(2^128) commitment, ring switching, and Ligerito (binary-field WHIR-style) openings through Flock |

> Research reference. Unaudited, **not zero-knowledge**, test keys only. Not for custody.

## Relation

The public statement and the private witness are the same as in the Noir example: a hidden, committed roster of members with hidden weights reaches a hidden threshold, and each counted member approved the exact `authorization_digest`.

Hashing changes from Poseidon2 to SHA-256. SHA-256 is native to the binary-field backend, and Poseidon2 is not:

```text
leaf              = SHA256("tempo:member:v1\0" || kind || weight_be32 || 0^11 || pkX || pkY || rpIdHash)
roster_root       = depth-4 SHA-256 Merkle tree (16 slots; unused = 0^32)
policy_commitment = SHA256("tempo:policy:v1\0" || threshold_be32 || 0^12 || roster_root || salt)
```

Slots follow one of two public circuit profiles:

| Profile | Slots | ECDSA verifiers | Constraints |
| --- | --- | --- | --- |
| `Mixed` | 4 of any kind | 8 | 80,134 |
| `Split` | 2 secp256k1 + 2 passkey | 4 | 44,390 |

- **`Mixed`:** each slot runs one secp256k1 verifier and one P-256 verifier. A verifier that does not match the slot's kind, and both verifiers of a disabled slot, check the trivial signature `(Q = G, r = Gx, s = e + r)`, which anyone can produce. Only the matching verifier is tied to the member's committed key.
- **`Split`:** each slot runs only its kind's verifier. This halves the circuit, but a single proof can then carry at most two approvals of each kind. Ordering is enforced within each group. A member cannot be counted in both groups because its leaf commits to its kind.

The commitment and digest are public input bits checked by a PCS opening, and `base64url(digest)` is computed in-circuit. The constraint system is therefore identical for every statement.

The checks are the same as in the Noir example:

- **Policy opening.** The commitment opens, and `threshold >= 1`.
- **Membership.** Each enabled slot is a Merkle member, and its leaf commits to the member's kind and weight.
- **Ordering.** Enabled slots are packed first with strictly increasing roster positions.
- **Signatures.**
  - secp256k1 members sign the digest directly.
  - Passkey members use strict WebAuthn: the `clientDataJSON` must start with the canonical prefix, with `challenge` equal to `base64url(digest)`. The committed RP ID hash and the UP and UV flags are required, and the signature is P-256 over `sha256(authData || sha256(clientDataJSON))`. The SHA-256 padding of `clientDataJSON` is constrained in-circuit, so the hashed blocks are exactly `SHA256(clientDataJSON)` for a message that contains the checked prefix.
- **Threshold.** The enabled weights sum to at least the threshold.

## Lean

`lake build` in [`lean/`](lean) checks three files. The only axioms are Lean's standard `propext`, `Quot.sound`, and `Classical.choice`, and there is no `sorry`.

- **`Tip1136/Relation.lean`** abstracts the hashes and signatures:
  - `quorum_of_holds` proves that any satisfying assignment exhibits pairwise-distinct roster positions whose approving members' committed weights reach the threshold. Padding contributes nothing.
  - `holds_of_quorum` proves the converse: any such quorum, listed in increasing order, can be encoded.
- **`Tip1136/Split.lean`** proves `quorum_of_holds_split`: in the `Split` profile, positions stay pairwise distinct across the two groups, because members in different groups have different committed kinds.
- **`Tip1136/Arithmetic.lean`** proves the integer gadgets in `src/relation.rs` sound modulo `Q100 = 2^100 - 15`, given the lifted-bit widths: gated 64-bit chunk equality (`gated_chunk_eq`), the Merkle direction selector, `threshold >= 1`, the slack-based threshold comparison, packing, and the ordering gap. The one-hot lookup that computes `base64url(digest)` in-circuit is not yet covered.

The Lean model is written separately from the Rust circuit. It does not verify the Rust code, which was neither extracted from Lean nor checked against it. Closing that gap means expressing this circuit in Freigen and loading Freigen's exported `M`, `A`, `B`, and `C` matrices into BitZ; BitZ `main` cannot load that format yet.

## ECDSA gadget

[`src/ecdsa_fast.rs`](src/ecdsa_fast.rs) ports the optimized ECDSA-P256 verifier from [reilabs/freigen#14](https://github.com/reilabs/freigen/pull/14) at `24fa108`. Freigen proves `verifyDigest_sound`, `verifyDigest_complete`, and `verifyDigest_wf` for that circuit. The proofs build against `24fa108`, but they assume primality of the P-256 base and scalar moduli as axioms (`baseModulus_prime`, `scalarModulus_prime`) and rely on `native_decide`, which trusts Lean's compiler. Compared with the original Freigen circuit, it needs 874,763 lifted bits and 7,954 R1CS rows per verification instead of 1,215,663 and 7,061.

The gadget uses:
- a mixed-width fixed-base comb for `u1·G`;
- signed radix-32 recoding for `u2·Q`;
- collapsed complete-add selectors;
- checked incomplete additions where exceptional cases are unreachable.

For P-256, the Rust gadget's constraint matrices are **byte-identical** to the ones Freigen exports for its verified `verifyDigestCS` (116,067,650 bytes, covering M, A, B, and C). To reproduce the check:

```sh
# In a Freigen checkout at PR #14 (24fa108), with lean/freigen-export/ExportEcdsaCS.lean
# copied to the root and `lean_exe ecdsa_cs_export where root := `ExportEcdsaCS` added to lakefile.lean:
ulimit -s unlimited && lake exe ecdsa_cs_export verify_digest_cs.bin
FREIGEN_ECDSA_CS=/path/to/verify_digest_cs.bin cargo test --release --lib byte_identical -- --nocapture
```

The test is skipped when the export is absent.

## BitZ revision

The crate pins [`decofe/BitZ@bf2a79e`](https://github.com/decofe/BitZ/compare/d7e7257...bf2a79e), which is BitZ `d7e7257` plus five commits:

| Commit | Effect |
| --- | --- |
| `feat(field): add PCLMULQDQ GF(2^128) kernel for x86_64` | Upstream uses hardware carryless multiplication only on aarch64; on x86-64 every GF(2^128) multiply was a 64-step software loop. Proving is about 25x faster, and BitZ's own `sha256-2kb` proves in 127 ms instead of 3.45 s. |
| `feat(cli): check public inputs with a PCS opening` | Statement values become leading input bits, checked by one random multilinear opening, instead of circuit constants. Setup runs once per profile instead of once per proof. |
| `feat(circuit): cache the virtual map digest` | The bit-to-integer map is fixed per circuit, but its digest was rehashed on every proof and verification. |
| `feat(cli): use the reference row/column split for the claim shape` | The fold round sends one element per column. With 128-bit rows that was 2^17 elements (2.1 MB). `Shape::for_log_bits` sends 2^9 instead. |
| `feat(prover): parallelize grand-product setup and transpose factored claims` | The grand-product leaves, layers, and bit-table transpose were sequential. The opening claim's tensor weights were also flattened into a 128 MB table before the bit-to-integer map was applied; they are now applied factored. |

`.cargo/config.toml` enables `pclmulqdq` on x86-64. Without it, the crate silently builds the slow portable kernel.

## Run

The toolchain is pinned to Rust 1.97.1 by `rust-toolchain.toml`, matching BitZ.

```sh
cargo test --release                       # both profiles: accepting and rejected witnesses, prove/verify
RAYON_NUM_THREADS=8 cargo run --release --example bench -- split   # or mixed
cargo run --release --example profile -- split                     # per-stage timing tree
(cd lean && lake build)                    # Lean 4 v4.31.0-rc1, no mathlib
```

## Measurements

Approval by alice (secp256k1), carol (passkey), and eve (secp256k1), on an AMD EPYC 9255 sandbox with a 100-bit PCS round budget:

| | `Split`, 1 thread | `Split`, 8 threads | `Mixed`, 1 thread | `Mixed`, 8 threads |
| --- | --- | --- | --- | --- |
| Committed bits (padded) | 3,900,766 (2^22) | | 7,471,144 (2^23) | |
| Prove | 1.04 s | 0.42 s | 2.10 s | 0.87 s |
| Verify | 0.23 s | 0.07 s | 0.43 s | 0.14 s |
| Proof | 264 KB | | 299 KB | |
| Setup, once per profile | 6.6 s | | 12.2 s | |

Best of five runs.

Before the BitZ changes, `Mixed` took 64 s to prove and 6.6 s to verify on one thread, produced a 2.26 MB proof, and ran a 10.8 s setup for every proof.

**Where the time goes now:**
- **Proving:** Spartan, the integer-to-binary bridge (grand-product GKR and inner-product sumcheck), and witness generation. Ligerito itself takes milliseconds.
- **Verification:** the verifier evaluates the sparse constraint matrices and applies the bit-to-integer map to a 2^23-element weight vector. Both are linear in circuit size.
- **Proof size:** about 275 KB of the 300 KB is Ligerito Merkle openings from two PCS openings: the public-input check and the main opening. Batching them into one opening needs a batched-evaluation sumcheck in BitZ's PCS.
- **Thread scaling:** speedup flattens beyond about 8 threads.

## Gaps before this can replace the Noir path

1. **Zero knowledge.** The BitZ prover and the Ligerito openings do not hide the witness. TIP-1136 requires the inner proof itself to hide the policy and credentials. Until then, a proof leaks information about the roster, the keys, and which members signed. [`ZK.md`](ZK.md) lists what each stage reveals and the work needed.
2. **Proof size and verification.** A 300 KB proof with linear-time verification is not usable onchain. A fixed onchain verifier needs either the paper's optimizations or a recursive wrapper. A Groth16 wrapper would reintroduce the BN254/setup assumptions that a hash-based stack avoids.
3. **secp256k1.** Freigen's ECDSA proofs cover P-256 only, so the secp256k1 instantiation of [`src/ecdsa_fast.rs`](src/ecdsa_fast.rs) is unverified. Its only shape change is a 17-byte final comparator, because `p - n` needs 129 bits on secp256k1.
4. Origin checks, signature counters, and the OIDC and SMS factors are out of scope, as in the Noir example.
