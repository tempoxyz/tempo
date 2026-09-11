# Account-root carried policies: implemented V2 draft

Implemented in [PR #7506](https://github.com/tempoxyz/tempo/pull/7506), stacked on
[configurable-account activation #7581](https://github.com/tempoxyz/tempo/pull/7581).
This supersedes the earlier analytical tree design. V1 remains for compatibility and
comparison. This is not an activation decision or completed security/hardware review.

## Commitment and encoding

The account's existing 32-byte extension contains R, not separate authority/policy slots:

```text
R = keccak256("tempo:account-tree:v2" || RLP([
    authority, epoch, next_id, count, policies_root
]))
leaf = keccak256("tempo:account-tree:leaf:v2" || RLP([
    grant_id, policy_digest, [[spent, window], ...]
]))
branch = keccak256("tempo:account-tree:branch:v2" || left || right)
empty = keccak256("tempo:account-tree:empty:v2")
```

Authority is the existing multisig configuration commitment. Authority/policy hashes are
bytes32; epoch/allocator/grant IDs/windows are uint64; count/index are uint16; spending is
uint256. RLP integers are minimal. Usage follows the canonical sorted token list exactly;
unlimited policies have no entries. Normal balances, nonces, legacy keys and contract storage
remain outside R. No per-grant AccountKeychain storage is written, even at rollover.

The ordered dense vector is padded to the next power of two, with a canonical empty hash.
The opening authenticates count; proofs enforce depth, index, padding and current root.
Maxima are 256 active policies and 32 limited tokens, also subject to the entire signed
certificate's 4,096-byte bound. There is no separate 16KB witness allowance. Singleton/4/8/
256-policy proofs have 0/2/3/8 siblings, or 0/64/96/256 raw sibling bytes. The complete
opening (including policies_root), policy, usage and RLP overhead are additional.
The multisig owner list stays in its existing bounded sorted witness, not another tree.

The new tagged `key_authorization` RLP is:

```text
["tempo-account-key-v2", <V1 carried policy fields>, issuer_signature,
 [epoch, grant_id, [opening, index, usage_vector, siblings]]]
```

The issuer signs `keccak256("tempo:account-tree:grant:v2" || v1_policy_hash ||
epoch_be_u64 || grant_id_be_u64)`, which is also the leaf's policy_digest. V1 policy
validations remain. V2 requires the parent's current direct configurable owner quorum;
primitive parents and stored admin issuers remain V1-only. Delegates may be primitive or
configurable. Reuse still carries and verifies the issuer signature; signature elision is
not assumed. Membership, issuer authority and all policy fields must validate on every use.

## Refreshable proofs

Sender and sponsor signing preimages replace the mutable tree witness with its all-default
encoding and omit an optional issuer account opening. They retain policy, authority, epoch,
grant ID, issuer signature, nonce, calls and fees. Proof refresh therefore preserves both
approvals. The full wire hash includes every witness byte and changes on refresh. Normal
nonces prevent executing both variants. No separate canonical intent-ID RPC is added.
Different nonce lanes still share R: concurrent spends require execution-ordered proof
refresh. Installing multiple grants also serializes on the allocator; two approvals for
the same next ID cannot both install. Future-ID approvals wait for preceding IDs or an
explicit owner allocator advance. These coordination costs are not fee-free throughput.

Native multisig signatures optionally append an RLP AccountOpening after their existing
fields. Direct owner operations use it to open R; a carried issuer can use the opening in
its matching V2 grant. Legacy signatures without an opening still work against legacy
authority commitments, but cannot open R. The same draft T12 gate applies.

## Lifecycle

- Initial validated native configuration can register an empty R via its optional opening.
  Legacy authority-only commitments migrate using exactly `AccountOpening::empty(authority)`.
  Unregistered accounts must still pass initial address derivation; nonempty initial roots
  cannot be chosen without separate grant authorization.
- Install: approve the exact allocator/epoch and policy, prove the next empty position,
  append zero usage, advance allocator, then execute with separate delegate approval.
- Reuse: prove membership, enforce scopes and protocol debits, update usage and R. Periods
  use the immutable signed anchor. Transient proof positions are not grant identities.
- Remove: direct owner `removePolicy(bytes32[] leaves,uint16 index)` authenticates the full
  bounded hash vector, swap-deletes and shrinks. Moved leaves keep IDs/budgets. This rare
  management path is O(active_count), not a compact multiproof.
- Cancel unused approvals: direct owner `cancelPolicyApprovals(uint64 nextId)` must advance
  allocator. Existing leaves remain valid; lower uninstalled IDs cannot enter. IDs are never
  reused. Re-adding the same key requires a new owner-approved ID and budget.
- Parent rotation: `updateConfig` opens R, increments multisig version and epoch, changes
  authority, clears policies and preserves the allocator. Delegate rotation instead validates
  the delegate's current authority and preserves the parent's grant/usage.

Legacy witness burns/key tombstones do **not** revoke V2: its namespace is membership,
allocator and epoch under R. Clients must use V2 management. Owners can remove expired
leaves; no automatic or permissionless cleanup is implemented. Integer overflows reject.
`getConfigCommitment` returns raw R after migration, not the inner authority hash. Existing
V1 carried grants bind the authority-only state and do not automatically survive migration
to R; reissue them as V2. Legacy stored keys are not automatically migrated into the tree.

## Journal, receipts and availability

The working opening/leaf/path/tokens live only in transient storage. Each debit journals R
and transient usage together. Failed batches roll back all user debits; installation and
fee reservation precede the user checkpoint. Actual fees and nonces survive failure.
Refunds subtract only reserved-minus-actual fees in the same token/window. Sponsorship does
not debit the user's fee allowance.

AccountKeychain emits topic0 `keccak256("TempoAccountTreeTransitionV2")`, topic1 the padded
account address, and data RLP `[opening, index, [grant_id, policy_digest, usage_vector]]`.
Old paths and immutable token bytes are already in the transaction and are not logged twice.
Installation, successful debits and final self-paid fee settlement emit transitions. User
logs roll back on failure; installation/final-fee logs survive. No-op reuse needs no log.
Owner management emits ABI `AccountTreeRootUpdated(address indexed account, bytes opening)`
with an RLP opening; removal inputs supply the prior hash vector.

Clients retain policy bytes and mirror the tree from canonical transactions/receipts, with
reorg rollback. Tests reconstruct final usage from receipts and check the actual extension.
SDK JSON persistence retains V2 fields. An automatic production witness service, SDK refresh
filler, and relay/pool replacement policy are not implemented; callers supply refreshed proofs.

## Metering

Use configurable-account prices: 20k extension registration, 5k nonzero update. Unregistered
grant-and-use pays both; this is not a single cheap update. One root replacement is prepaid
per carried transaction. Transient work, hashing/parsing, signatures, events and execution
are additional. Certificate bytes retain 4/16 gas pricing; no blanket calldata discount.

Nonrecursive self-paid settlement prepays a conservative full-width record allowance:

```text
B = 256 + 120 * limited_tokens + 34 * siblings
settlement_gas = 10_000 + 400 * ceil(B/32) + 8*B + 200*siblings
```

This bounds two reads, a rewrite, parsing/hashing and the final log, with dispatch headroom.
Tests cover maximum uint256 spending/uint64 windows at token counts 1..32 and measured depths.
This gas schedule still needs production hardware calibration before activation.

At the TIP-1067 cap of 12,000,000,000 attodollars/gas, zero priority fee and six-decimal fee
token, `fee_micro = ceil(gas_used * 12_000_000_000 / 10^12)`. See the
[executed results](tip-1086-tree-results.md). The older analytical Python tree model is
retained only as historical design work, not as a source for these receipts or wire rules.
