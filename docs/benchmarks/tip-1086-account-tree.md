# Historical design: one account commitment for authority and active policies

**Superseded by the [implemented V2 draft](tip-1086-tree-implementation.md) and
[executed results](tip-1086-tree-results.md).** The text below is the earlier analytical
proposal, not the current wire format. In particular, the implementation retains a 4KB
complete certificate bound, carries the full opening, uses full-vector owner removal,
and does not implement permissionless cleanup or a witness service.

Design proposal for [TIP-1086](../../tips/tip-1086.md), co-designed with
[TIP-1108](../../tips/tip-1108.md) and [TIP-1114](../../tips/tip-1114.md).
This is a proposed successor to the PR's implemented per-grant storage counters,
not an implemented wire format, a measured receipt, or an activation decision.

## Decision

Keep **one 32-byte account-leaf extension**. Commit to authority, policy lifecycle
metadata, and a compact tree of active policies with their usage counters inside
that hash. The logical components are separate; they are not separate storage
slots. Ordinary balances, nonce state, and contract storage remain outside it.

```text
account's existing 32-byte commitment R
  = H(domain_v2 || authority_hash || policy_epoch || next_grant_id
                 || active_count || policies_root)

authority_hash = existing TIP-1108 hash of salt, version, threshold, owners

policies_root
  ├─ leaf: grant_id, policy_hash, spent/window counters
  ├─ leaf: grant_id, policy_hash, spent/window counters
  └─ ... active grants only
```

`H` is Keccak-256. The owner list stays in its existing bounded, sorted encoding:
one ordinary user need not prove membership in another owner tree. Policy bytes
are supplied when used and authenticated against `policy_hash`; unrelated policies
and their counters are represented by sibling hashes.

The existing TIP-1108 pricing is a useful starting candidate: 20,000 gas to
initialize the account extension and 5,000 gas to replace a nonzero commitment,
without a 250,000-gas SSTORE creation charge. Reusing that pricing for this new
write path needs benchmarks; proof parsing, hashing, execution, events and data
availability are additional work. One commitment does not mean unlimited free
tree growth or free account creation.

## A compact tree for small active sets

Use a dense vector of active grants, padded to the next power of two and committed
by an ordered binary Merkle tree. Empty, leaf, branch and account-envelope hashes
have distinct domains; branch order matters. The envelope authenticates the live
count, and the tree height is derived from that count. Reject noncanonical padding,
lengths and out-of-range indexes. Do not use sorted-pair proofs that discard position.

For this candidate, cap an account at 256 active policies (eight sibling hashes);
benchmark and review this limit before adoption. Capacity doubles only when needed.
It shrinks after deletions. A singleton is its leaf hash and needs no siblings;
an empty tree has a domain-separated constant root. This gives a hard logarithmic
proof bound without treating hashed-key trie depth as guaranteed `log(active_count)`.

| Active policies | Sibling hashes for one leaf | Sibling bytes | Maximum sibling-byte gas at 16/byte |
|---:|---:|---:|---:|
| 1 | 0 | 0 | 0 |
| 2 | 1 | 32 | 512 |
| 4 | 2 | 64 | 1,024 |
| 8 | 3 | 96 | 1,536 |
| 16 | 4 | 128 | 2,048 |
| 64 | 6 | 192 | 3,072 |
| 256 | 8 | 256 | 4,096 |

These are membership/update sibling bytes only. The account opening, policy, leaf
counters, indexes, lengths and delegate signature are additional. In particular,
one active policy does not imply a zero-byte witness. The account opening contains
the authority hash plus epoch, allocator and count (50 bytes using widths below);
the policy root is reconstructed from the selected leaf and path.

Proposed envelope widths are `authority_hash: bytes32`, `policy_epoch: uint64`,
`next_grant_id: uint64`, `active_count: uint16`, `policies_root: bytes32`.
Each leaf contains `grant_id: uint64`, `policy_hash: bytes32`, and a canonical usage
vector aligned with the policy's sorted token list. Keep full-width `uint256`
spending and `uint64` windows; both live inside the same committed leaf, so no
second persistent word is created at rollover. Missing/extra/reordered entries
are rejected. An unlimited policy has an empty usage vector. Start with at most
32 limited tokens and 4,096 policy bytes per leaf, plus a separately metered,
16,384-byte maximum execution-witness envelope; these are candidate bounds, not
changes to the existing PR's accepted inputs. Large policies may be general-lane
transactions even when a small-policy use qualifies as a payment.

The full usage vector is deliberately the small-policy fast path. A per-policy
token subtree may help unusually large policies, but adds proof overhead for the
common one/two-token case and is deferred.

## Lifecycle without accumulating tombstones

- **Initialize:** authenticate the existing TIP-1110 initial owner configuration
  and initialize an empty policy tree. A first-use registration plus policy use
  must explicitly authorize the added policy; the address derivation does not
  authorize an arbitrary caller-selected initial policy tree.
- **Install:** the owner quorum approves the complete immutable policy, current
  authority hash, epoch, and exact `next_grant_id`. Append the leaf with zero
  usage and advance the allocator. Inline grant-and-use retains separate owner
  and delegate approvals. Root initialization and an ensuing update are not
  silently charged as a single cheap update.
- **Spend:** prove the live grant, validate the delegate and policy, enforce every
  debit, update its usage vector, and replace the account commitment. Never
  allocate per-grant AccountKeychain storage. A policy is usable by membership,
  not by possession of an old installation signature.
- **Remove:** owner-authorized revocation removes the leaf. Anyone may remove a
  provably expired leaf through a paid cleanup operation; no automatic background
  mutation is assumed. Replace its vector position with the final live leaf,
  then truncate. Authenticate both old positions using a canonical multiproof
  or sequential proofs against the appropriate intermediate roots. Contract the
  padded tree when possible.
- **Re-add:** assign a new monotonically increasing grant ID. Never reinsert an
  old ID or accept an installation approval below the allocator. Re-adding the
  same key with a new ID is an explicitly approved new budget.
- **Owner rotation:** update the existing multisig authority version and hash,
  increment the policy epoch, and empty the v2 policy tree. This preserves the
  carried draft's parent-rotation invalidation rule. It does not silently change
  legacy stored-grant rotation semantics. Keep the grant allocator monotonic.
- **Delegate rotation:** grants identify the configurable delegate's account,
  not its changing root. Authenticate that account's current authority; retain
  the parent's grant ID, limits and usage.

Grant IDs are stable identities; vector positions are refreshable proof metadata.
Swapping the final leaf into a deleted position must not change its budget or
require its delegate to sign again. Allocator/epoch/version overflow is an error.
Explicit clearing of all policies also increments the epoch and preserves the
allocator. There is no generic `setRoot` operation that a delegate can use to
reset usage. Root transitions are derived by protocol-defined operations.

The tree contains installed, not-yet-removed policies. Expired leaves continue to
count until cleanup is included, so the count is not magically the number of
currently usable grants. Expiry/revocation can remove counters safely because an
old ID cannot be installed again. Unsubmitted installation approvals also expire;
an owner may advance the allocator through an explicitly signed cancellation
operation to invalidate outstanding IDs without allocating tombstones.

## Stable approvals, refreshable witnesses

Sign the operation intent: chain, account, existing nonce/expiry/fee fields,
authority hash/version as applicable, policy epoch, grant ID, policy hash, and
calls. Do **not** make a normal spending signature depend on the mutable outer
root, vector index, current spent value, or sibling hashes. The protocol derives
the post-state from authenticated pre-state and execution; the sender does not
authorize an arbitrary replacement root.

Owner management signs exact semantic changes and expected versions/IDs. A caller
that needs compare-and-swap semantics may additionally sign an expected root,
accepting that intervening spending invalidates that operation. Plain spending
does not imply that lock.

Use a new versioned intent/witness envelope, not an unannounced exception to the
existing transaction signing hash. Both sender and sponsor sign the immutable
intent and fee limits. Proposal for transport: a stable intent ID covers the
signed portion; the block transaction commitment covers the exact execution
witness too. SDKs, replacement rules, receipt identifiers and RPC lookup must
specify both IDs before implementation. Duplicate intent execution is still
prevented by the account's ordinary nonce rules. Bound witness sizes and charge
the submitted witness; refreshing it may exceed signed gas/fee limits and then
requires a new intent.

Validators verify proofs against the root at the transaction's actual position
in the block, not the submission-time root. A relay or builder may refresh a
witness without a new approval; it cannot change the signed operation. Stale or
unavailable witnesses cannot execute. Two transactions for different grants of
one account still conflict on its root and need sequential witness refresh.
Different accounts retain separate commitments. A configurable delegate also
needs a refreshable opening of its own account root for owner authentication.

## Execution, fees and rollback

Open required leaves into a transaction-local authenticated working tree. Debit
the selected grant for every applicable nested spending hook, preserve journaled
rollback, and recompute the account root from the final values. A second touched
leaf requires a proof/multiproof or previously authenticated material; it cannot
be supplied as an unauthenticated new value. Bound the number of affected leaves
and all root recomputations as well as total witness bytes.

Reserve sender-paid fees against the same authenticated grant before the user
execution checkpoint. A revert rolls back user spending but leaves actual fees
charged after reservation refund. An included `InstallAndUse` creates its
explicitly approved leaf and allocator advance before that checkpoint, so failed
calls can retain the fee debit; owner-management calls within execution follow
normal rollback instead. Invalid transactions leave all state unchanged.
Registration of initially unregistered configurable signers follows TIP-1114's
existing survival-on-included-failure rule.

Keep a transaction-local working commitment visible to state reads and successive
management calls. Charge initialization (20k candidate) when applicable and one
final nonzero root replacement per changed account (5k candidate), plus bounded
hashing/processing for every intermediate transition. Do not conflate many
root computations with one cheap computation. Fee reservation/refund and user
debits should coalesce into the final persisted root; measure that implementation.

If an owner-management transaction also edits policy state, updates must compose
with the latest working tree rather than overwrite another change. V1 should
permit one spending grant per sender transaction, and disallow owner-management
operations from a delegate context. Configurable signer registration is charged
once for each distinct newly initialized account; aliasing must not double-charge
or overwrite a commitment.

## Availability is part of the design

A root alone cannot produce witnesses. Every successful insertion publishes its
policy and every transition publishes sufficient authenticated leaf/index data
to reconstruct the active vector. Included failed transactions must expose their
surviving fee/installation changes too; ordinary reverted EVM logs are not enough.
Specify protocol-level transition records committed with receipts or equivalent
deterministic reconstruction from retained block witnesses.

Wallets can maintain their small account tree; relays/indexers can serve proofs.
They are not trusted for correctness, but withholding all usable tree data can
block a grant's transactions. Consensus validation should be possible from the
current account root plus bounded supplied witnesses, without requiring every
validator to maintain an unpriced full policy database. History, bandwidth,
transition records and optional indexes still grow and must be included in the
economic and availability assessment.

Owner-quorum recovery should work from a retained authority configuration and
small envelope opening, allowing an epoch reset even if leaf data is lost. If
even the opening cannot be recovered from available history, the root alone
does not provide a recovery bypass. Snapshot/sync tooling must preserve or make
those openings retrievable; an opaque snapshot of roots alone is insufficient
to promise wallet recovery.

## Integration with the existing multisig stack

| Component | V2 change |
|---|---|
| TIP-1108 | Same optional 32-byte account field, new domain-separated envelope semantics and protocol-controlled update paths. |
| TIP-1114 | Verify the existing owner config against `authority_hash`, then authenticate its envelope against the account root. Preserve owner limits and weights. |
| TIP-1109 | Rotate authority inside the envelope, compose with the current policy state, and apply the explicit carried-policy invalidation rule. |
| TIP-1110 | Preserve address derivation and cross-chain recovery inputs. Policy installation must be separately authorized. |
| TIP-1111 / TIP-1086 | Authenticate policy membership and mutable usage; parent authority binding references the stable subcommitment, not the changing account root. |
| Pool / block builder | Track intent identity, refresh witnesses and revalidate roots at execution order. |
| RPC / sync / explorer | Expose raw account commitment, authenticated authority openings and versioned transition records; distinguish V1 and V2 witnesses. |

Hardfork-gate the new witness and root interpretation. Keep V1 verification intact
for accounts whose stored value still matches the old config hash. V2 witnesses
must open the distinct V2 domain against the stored value; no heuristic
reinterpretation or silent bulk migration. An explicit owner-quorum migration
replaces the existing nonzero hash with the V2 envelope and initially empty v2
policy tree. Existing stored grants and already-consumed budgets are not imported
as fresh zero-usage grants: coexistence/import policy must be resolved explicitly
before migration is enabled.

The current `getConfigCommitment` raw return value cannot remain an unconditional
claim to be the authority hash after V2. Introduce `getAccountCommitment` for the
raw root and a witness-verified authority/config getter. Update all consumers,
including root disablement, account proofs, historical execution and legacy
signature verification. Never clear the nonzero root to regain initial authority.

## Cost target at the 12-billion basefee cap

Strictly below $0.001 allows 83,250 gas after micro-unit fee rounding. An existing
account's proposed 5k root replacement leaves 78,250 gas for everything else;
first initialization plus a 5k subsequent replacement leaves 58,250 gas. At four
active policies, sibling bytes consume at most another 1,024 gas. These are
budgets, **not predicted total transaction fees**.

This removes the reason for allocating a 250k storage word per grant/token and
the second word at periodic rollover. It does not justify subtracting 250k from
an old receipt and calling the result measured: the authentication, hashing,
fee-finalization, data and account-initialization paths change. Large owner
quorums, WebAuthn witnesses, fresh balances/accounts and many token budgets can
still exceed the target.

## Reviewable validation work

The adjacent [reference model](../../scripts/model-tip-1086-account-tree.py)
checks ordered proof replacement, append across capacity boundaries, swap-delete
and contraction, stable grant IDs, allocator replay exclusion, and failed-call
fee accounting. It uses real Keccak but is a data-structure model, not a
consensus implementation or an economic benchmark. The current model passes 1,527
proof checks across all active counts from 1 through 256, plus lifecycle and fee
rollback assertions; the sibling-size table above matches its output.

Before selecting this as the implementation, require:

1. Byte-exact domains, intent/witness encoding, transaction and receipt identifiers,
   canonical multiproof format, bounds and complete transition records.
2. Handler receipt benchmarks for 0/1/2/4/8/16/64/256 policies, one/two/many tokens,
   primitive/configurable delegates, owner quorums, all curves, first/repeat use,
   rollover, sponsorship, reverts, fresh accounts, installation, deletion and
   rotation. Report full fees at the cap and bytes separately.
3. Proof-refresh tests with consecutive same-account transactions, reorgs, missing
   witnesses, deletion compaction, owner/delegate rotation and signed fee limits.
4. Journal/invariant tests for cumulative caps, nested debits, fee settlement,
   rejected transactions, initialization, revocation, cancellation, expired
   cleanup and no resurrection of a deleted grant.
5. CPU, bandwidth, history retention and root-write calibration; recovery from
   public transition data; snapshot/state-sync compatibility.

Background references: [Ethereum's authenticated trie explanation](https://ethereum.org/developers/docs/data-structures-and-encoding/patricia-merkle-trie/)
illustrates committing mutable data with one root; [OpenZeppelin MerkleProof](https://docs.openzeppelin.com/contracts/5.x/api/utils/cryptography)
documents membership and multiproof mechanics. This candidate specifically uses
ordered dense-vector proofs, not their sorted-pair convention.
