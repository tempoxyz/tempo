# Checker design

The checker maintains an independent, durable accounting model for one Zone.
Authenticated protocol events advance this **ghost state**; exact Zone and
Tempo state reads verify it after every canonical Zone block.

```text
previous ghost state
        +
authenticated Tempo and Zone events
        ↓
candidate ghost state
        ↓
exact Zone balances and supply + exact Tempo Portal custody
        ↓
persist or record divergence
```

## Ghost state

The checker stores an expected balance for each known `(token, account)` and
five aggregate liability buckets per token:

| Bucket | Meaning |
| --- | --- |
| `account_total` | Sum of circulating Zone account entitlements |
| `pending_deposits` | Custody received on Tempo but not resolved on the Zone |
| `pending_withdrawals` | Burned on the Zone but not resolved on Tempo |
| `pending_tempo_refunds` | Deposit refunds parked on Tempo |
| `pending_zone_refunds` | Withdrawal bounce-backs returning to or parked on the Zone |

Protocol activity moves value between these buckets:

| Activity | Ghost transition |
| --- | --- |
| Tempo deposit | Increase pending deposits |
| Zone deposit mint | Credit recipient; decrease pending deposits |
| Zone transfer | Debit sender and credit recipient |
| Zone withdrawal | Debit sender; increase pending withdrawals |
| Tempo withdrawal | Decrease pending withdrawals |
| Tempo deposit refund | Move value from pending deposits to Tempo refunds |
| Zone withdrawal bounce-back | Move value from pending withdrawals to Zone refunds |
| Tempo refund claim | Settle the Tempo refund through a Portal transfer |
| Zone refund claim | Credit the Zone recipient and settle the Zone refund |

## Block verification

For each canonical Zone block, the checker:

1. Reuses the node's receipt-authenticated Tempo evidence when retained (or
   fetches and authenticates old evidence during recovery), then independently
   decodes Portal events and canonical Zone receipts.
2. Converts recognized protocol events into ordered accounting effects.
3. Applies those effects to a copy of the last verified ghost state.
4. Reads the exact Zone post-state and imported Tempo state.
5. Persists the candidate state only when every invariant passes.

The candidate is discarded on failure, leaving the last verified state intact.

For checkpoint-only blocks, the checker requires the sole `advanceTempoHeaders`
transaction and its successful `TempoBlockFinalized` event, with no bridge or
transfer events. Accounting stays at the last full import while the verified
Zone height advances. Supply is checked against the unchanged ledger, and
custody remains anchored at that full import. On the next full block, all Tempo
blocks since the accounting anchor are authenticated by their parent hashes and
their Portal effects are applied in chronological order before the Zone effects.
Keeping the existing durable Tempo coordinate as the accounting anchor prevents
checkpoint-only progress from dropping deferred work on restart.

## Invariants

### Account balances

Every account named by a TIP-20 transfer in the block is checked:

```text
Zone balance(token, account) == ghost balance(token, account)
```

Untouched accounts remain in the durable ghost ledger but are not reread every
block.

### Token supply

Every enabled token is checked every block:

```text
Zone totalSupply(token) == ghost account_total(token)
ghost account_total(token) == sum of ghost account balances(token)
```

### Portal collateral

For every enabled token at the exact imported Tempo block:

```text
Portal custody >= account_total
                + pending_deposits
                + pending_withdrawals
                + pending_tempo_refunds
                + pending_zone_refunds
```

## Event authentication

Events drive the ghost model but are not accepted in isolation. The checker
also validates relationships between independent protocol evidence, including:

- Canonical Portal creation and token-enablement events are the only source of
  tracked-token membership; other accounting effects require existing members.
- Zone genesis must anchor before Portal creation, establishing an empty
  accounting baseline before normal replay reaches the creation block.
- Processed deposit outcomes and their exact TIP-20 mints.
- User withdrawal principal and fees and their exact receipt-local TIP-20
  debits and burns.

The checker does not independently compare L1 and L2 token-enablement calldata
or validate token metadata and Inbox/Outbox issuer roles. Those properties are
outside this accounting model.

It also does not correlate individual L1 deposits with L2 outcomes by deposit
hash or authenticate cross-layer withdrawal batch identity. Batch events are
strictly decoded but do not enter ghost state. Genesis bridge cursors are used
only to establish the empty bootstrap baseline.

For a sender-paid withdrawal, the sender's debit and burn must equal principal
plus fee. Sponsored withdrawals must instead contain an exact principal debit
from the sender and a separate exact fee debit from a nonzero payer. Deposit
bounce-backs are exempt because they do not debit a Zone user.

## Failure behavior

Transient acquisition failures retry without advancing the verified tip. A
deterministic mismatch records a durable divergence and freezes verification at
the preceding block. Zones are append-only, so an unexpected revert or a saved
tip absent from local history resets the checker to authenticated genesis for
replay rather than unwinding derived state. Unrecoverable configuration,
persistence, or provider failures disable verification while the ExEx drains
notifications. Observe mode never changes Zone execution or terminates the
node.
