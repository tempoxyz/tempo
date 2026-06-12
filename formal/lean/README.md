# Tempo Formal Proofs

This directory contains Lean models and machine-checked proofs for small
protocol-critical Tempo components.

The first target is the nonce/replay transition in
`crates/precompiles/src/nonce/mod.rs`. The model abstracts away EVM storage,
events, ABI decoding, and cryptographic hash collision behavior so the proof
can focus on the state-machine invariants:

- protocol nonce key `0` is rejected by the 2D nonce manager
- valid nonce increments advance by exactly one
- nonce overflow is rejected
- expiring nonce writes enforce `now < valid_before <= now + 30`
- unexpired seen hashes are rejected as replays
- circular-buffer slots are overwritten only when empty or expired
- accepted expiring nonce writes record the hash and keep the pointer in bounds

Run the checker from the repository root:

```sh
./scripts/check-formal.sh
```
