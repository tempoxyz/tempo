# tempo-state-proof

Exact-target Ethereum secure-MPT verification and one bounded authenticated raw-state cache,
shared by Tempo light and Zones. This crate does **not** authenticate root finality, ancestry,
execution validity, chain identity or freshness. The consumer selects an authoritative root.

## Features

- No default features: canonical keys/targets plus alloc-compatible verification, private verified
  batches, root-bound composition and exact consumed-word comparison, without `std`.
- `serde`: canonical key serialization; verified evidence is never deserializable.
- `cache`: host-only synchronous cache; enables `std`.
- `test-utils`: proof fixtures for tests.
- Default: `std`, `cache`.

Alloc builds are checked on the host; this does not qualify every embedded/prover target.

## Consumer workflow

1. Select the root from an immutable authoritative header/checkpoint. An RPC `finalized` tag or
   sealed hash alone is not independent authentication.
2. Use exact deduplicated `ProofTargets`; empty slot sets request account-only evidence.
3. Bound transport responses before JSON decoding. `ProofLimits` separately bound verification
   work and charge every repeated proof-node occurrence before cryptographic work.
4. Start `VerifiedBatch::empty(root)` and optionally `VerifiedCache::stage` authenticated cache
   evidence into it. Prove remaining targets with `verify_multi_proof` and `merge` the result.
5. Perform application-specific decoding/acceptance; speculative consumers also use
   `check_consumed` against exactly the values execution consumed.
6. `publish` all accepted root/batch pairs and their retention delta together. Binding, conflict,
   budget or retention rejection leaves shared state and recency unchanged.

Account mappings use `(state_root, account)`; words use `(account, slot, storage_root)`. An old word
is reusable only with account evidence at the selected root. Presence is checked before absence,
including present empty accounts. Authenticated empty storage derives zero without retaining words.

The consumer owns synchronization, transport, scheduling, checkpoint/attempt lifetimes and metrics.
Required account mappings can be retained independently of the ordinary LRU.
Released mappings may be discarded immediately; old-root words and operation-owned evidence survive.
Allocation failures are not recoverable transactional errors. Caches are disposable, not witnesses,
archives or persisted trust anchors.

See [`docs/state-proof-design.md`](../../docs/state-proof-design.md) for integration rationale,
retention/publication budgets, tests, and outstanding publication/performance qualification gates.
