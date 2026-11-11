# Trie shape exploration (experimental)

`ShapeTracker` keeps the existing pass/fail `assert_sometimes!` coverage goals and also uses a
local `sometimes_each!(message, shape)` macro to send structural JSON guidance. The macro
uses the **implementation API** in `antithesis_sdk` 0.3.0: `guidance_helper!` catalogs
`GuidanceType::Json` with `hit=false` on `antithesis_init()` (or the first regular assertion)
and calls `guidance_impl` with `hit=true` on every observation and `maximize=false`. The caller
must initialize the SDK first; the workload server already does so. A const message is the stable guidance ID; key hashes,
account addresses, block numbers and other unbounded identities are not included. There is no
first-hit suppression, value deduplication, or ever-growing local set.

The name expresses the experiment's intent, not a platform guarantee that every JSON value will
be explored. The SDK serializes these records; accepting and using them as categorical exploration
feedback still requires an Antithesis run. This is not a new SDK assertion or a replacement for the
existing correctness checks. The crate already unconditionally enables the SDK's `full` feature;
there is no SDK-disabled configuration for this local macro.

Observations are reconstructed from the model's complete post-block leaf sets (and replay baseline),
not the collider's requested templates or the implementation's cached sparse nodes:

- root kind: empty, leaf, extension, or branch, separated into account and storage tries;
- branch depth in nibbles, whether it is the root, and a 16-bit occupied-child `state_mask`;
- extension starting depth, root status and length in nibbles;
- leaf depth, root status and storage-leaf embedding (RLP length below 32 bytes, below a parent).
  Account embedding is `null` because callers may omit account values.

Runtime `leaf_mask`, `tree_mask` and `hash_mask` are not reported: the model walker does not
inspect the sparse implementation's cached nodes or masks. All nodes are reported on every walk, so identical observations repeat;
this favors an honest initial experiment over an unvalidated sampling or deduplication policy.
Large tries may produce substantial guidance output. Measure that cost and confirm platform
behavior before treating this as production instrumentation.

`tests/guidance.rs` runs the real SDK in local-output mode in a child process, then checks the
catalog and every emitted observation, stable identity, depth/root/masks, and storage encoding.
