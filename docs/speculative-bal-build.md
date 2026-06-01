# Speculative BAL Payload Builds

Tempo can opt in to building the next proposal while the parent block is still
being validated with `--consensus.speculative-bal-build`. The flag is disabled
by default.

The optimistic path only starts when the parent block carries a block access
list sidecar. Tempo decodes the sidecar, verifies it against the parent header's
BAL hash, and asks Reth to build the child payload over a `PayloadStateAnchor`
whose state provider is `parent.parent + parent.BAL`. Tempo also passes a
`PayloadValidityToken` so Reth can discard the child if parent validation later
fails.

Tempo owns scheduling policy, fallback, and cancellation:

- start the speculative child build before calling `newPayload` for the parent;
- mark the validity token invalid and cancel the payload job if parent
  validation fails;
- mark the token invalid and fall back if the executor does not register a
  speculative payload id promptly, or if the completed payload cannot be
  resolved within the remaining proposal budget;
- mark the token valid, canonicalize the parent, and resolve the already-running
  child payload when validation succeeds;
- use the speculative child only if the resolved block still matches the active
  parent hash, timestamp, millisecond timestamp part, and consensus context;
- fall back to the existing serial validate-then-build path when no BAL exists,
  speculative setup fails, canonicalization fails, or the speculative payload
  cannot be resolved.

Reth owns the execution semantics and speculative state plumbing:

- `PayloadStateAnchor`, `SpeculativePayloadState`, and `SpeculativeStateProvider`
  carry the explicit state anchor into payload jobs;
- `BalStateOverlay` materializes final writes from the parent BAL over the base
  parent state provider;
- the payload builder checks the validity token during build cancellation and
  uses the supplied state provider instead of reopening canonical parent state.

Speculative builds still use the normal best-transaction iterator. Invalid
transaction feedback and state-aware filtering are local to that iterator, and
Tempo disables live pool updates for speculative iterators so a failed parent
cannot affect which later transactions a discarded child observes. Payload
prewarming is also disabled for speculative builds so it does not read or prime
canonical-parent state while the child is anchored to the BAL overlay.

Reth owns generic execution-cache generation, sparse trie sharing, and BAL
overlay internals. Tempo only supplies the parent BAL, validity dependency, and
scheduling policy for when a speculative child is allowed to be used.

The path emits `speculative_bal_build_attempts`,
`speculative_bal_build_started`, `speculative_bal_build_used`,
`speculative_bal_build_cancelled`, and `speculative_bal_build_fallbacks` metrics.
Logs include parent validation and payload build timing when a speculative
payload is used.
