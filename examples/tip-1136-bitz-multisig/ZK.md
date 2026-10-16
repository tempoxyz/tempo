# Witness hiding for the BitZ path

TIP-1136 requires the inner proof itself to hide the policy and credentials. Neither the BitZ pipeline pinned here nor its commitment dependency, Flock's Ligerito, implements zero knowledge. It is the main remaining blocker to replacing the Noir/ProveKit path; the others are listed in the README. Closing it needs new protocol work and review, not configuration.

## What a proof reveals today

Each message in the proof is a deterministic function of the witness and the verifier's challenges:

| Stage | Prover sends | Leaks |
| --- | --- | --- |
| Public-input opening, main opening (Ligerito via `flock-core`) | Merkle-opened codeword columns, folded rows, and sumcheck rounds in each recursion level | Queried positions of the encoded witness matrix, which directly exposes packed witness bits and linear combinations of them |
| BitZ fold round | One `Fq` fold per column: `sum_r w_r * h[r, j]` | 2^9 random linear combinations of assignment bits |
| Grand-product GKR | Layer sumcheck rounds and claims | Evaluations derived from the column images |
| Post-GKR inner-product sumcheck | Round polynomials over GF(2^128) | Witness-dependent evaluations |
| Spartan outer and inner sumchecks | Round polynomials, `Az(r)`, `Bz(r)`, `Cz(r)`, `h(r)` | Witness-dependent evaluations |

A proof therefore leaks information about roster keys, weights, signatures, the salt, and which slots signed. Treat it as public witness data.

## Required work

1. **Hiding commitment and opening (Ligerito, inside `flock-core`).**
   - Encode each row as `message || random` before the Reed–Solomon extension, with at least as many random coefficients as opened positions per level.
   - Salt the Merkle leaves.
   - Mask every verifier-requested linear combination with a committed random row.
   - Apply all of this at every recursion level, because each level commits to a new folded polynomial.
2. **Zero-knowledge sumchecks** for Spartan, the post-GKR inner product, and Ligerito's internal rounds. Use the standard masking-polynomial construction (as in Libra or Chiesa–Forbes–Spooner), with the mask committed under item 1 and batched with a random coefficient.
3. **The BitZ fold and grand-product GKR.**
   - Either append random bit rows to every column, so that each fold is statistically masked under the verifier's random row weights (this needs a subset-sum statistical-distance bound over `Fq`),
   - or replace the fold/GKR exchange with a ZK GKR (Libra-style masking).
4. **Masked terminal evaluations.** Extend `f` and `h` with random entries that no constraint touches, so that the final evaluations at random points are uniformly distributed.
5. **A proof.** Write a simulator argument covering the composed protocol, with the statistical bounds instantiated for `Q100` and GF(2^128) at the chosen query counts, and have it reviewed.

Items 1–2 are standard and expected to cost a constant-factor overhead. Item 3 is specific to BitZ and is the research part.

## Alternatives

- **Client-side zero-knowledge wrapper.** The wallet proves "a valid BitZ proof exists for this statement" inside an existing zero-knowledge system, and only the wrapper proof is published. This is sound as long as the client produces the wrapper itself. However, a BitZ verifier, with its GF(2^128) arithmetic and BLAKE3 hashing, is a very large circuit, and it reintroduces the outer system's assumptions.
- **Coordinate upstream.** BitZ, Flock/Ligerito, and ProveKit's WHIR are maintained by the teams moving toward this stack (World Foundation and others), and ProveKit already has zero-knowledge WHIR work. A hiding Ligerito and a ZK BitZ belong upstream and should be reviewed there.
