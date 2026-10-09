# Tempo Zone Node

A lightweight L2 node built on [reth](https://github.com/paradigmxyz/reth) that
derives its state from Tempo L1.

## Re-execution

For `tempo-zone re-execute`, set `L1_HTTP_RPC_URL` to enable anchored L1 reads.
The portal address is derived from the zone ID encoded in the `--chain` genesis;
`L1_PORTAL_ADDRESS` is not required or used by re-execution.

## Overview

A **zone** is a Tempo L2 that processes one L1 block per zone block. The
sequencer watches the L1 chain for deposit, withdrawal, and token-enablement
events, builds zone blocks that execute those events via a system transaction,
and periodically submits batch proofs back to the L1 portal contract.

## Architecture

```mermaid
graph TD
    L1["Tempo L1"]

    L1Sub["L1Subscriber<br/><i>WebSocket + backfill</i>"]
    DQ["DepositQueue"]
    Cache["L1StateCache"]

    Engine["ZoneEngine"]
    Builder["PayloadBuilder<br/><i>advanceTempo + pool txs</i>"]

    Monitor["ZoneMonitor"]
    Batch["BatchSubmitter"]
    WProc["WithdrawalProcessor"]
    Portal["ZonePortal (L1)"]

    L1 --> L1Sub
    L1Sub --> DQ
    L1Sub --> Cache
    Cache --> Builder
    DQ --> Engine
    Engine --> Builder
    Builder --> Monitor
    Monitor --> Batch
    Batch --> Portal
    Portal --> WProc
    WProc --> Portal
```

## Block Production

Each zone block processes exactly one L1 block. The flow is driven by the
`ZoneEngine`:

1. **L1Subscriber** connects to L1 via WebSocket, backfills missed blocks, and
   enqueues `L1BlockDeposits` into the `DepositQueue`.
2. **ZoneEngine** peeks the next L1 block from the queue and builds
   `ZonePayloadAttributes` containing the L1 header, deposits, and enabled
   tokens.
3. The **payload builder** constructs an `advanceTempo` system transaction that
   calls `ZoneInbox.advanceTempo(header, deposits, decryptions, enabledTokens)`.
   This is always the first transaction in a zone block.
4. Pool transactions are appended after the system transaction, followed by a
   withdrawal batch finalization if applicable.
5. After `newPayload` succeeds, the engine **confirms** the L1 block in the
   deposit queue (removing it). On failure the block stays for retry.

The zone uses **instant finality** — head, safe, and finalized all point to the
same block.

## State Derivation

Zone state is fully derived from L1 events. The `advanceTempo` system
transaction atomically:

- Advances `tempoBlockNumber` and `tempoBlockHash` in the `TempoState`
  predeploy, anchoring the zone to L1.
- Activates newly bridged TIP-20 tokens directly in the `ZoneInbox` precompile.
- Processes deposits from the L1 queue — minting zone-side tokens to recipients.
- Validates the deposit hash chain against the L1 portal's queue hash.

Chain continuity is enforced: the L1 block number must equal
`tempoBlockNumber + 1` and its parent hash must match the stored
`tempoBlockHash`.

### Deposits

Deposits can be encrypted using ECIES with the sequencer's public key. The
sequencer decrypts them off-chain and provides `DecryptionData` (ECDH shared
secret + Chaum-Pedersen proof) that the native inbox verifies before minting.

## Token Enablement

TIP-20 tokens are enabled on the zone at runtime (not at genesis). When a new
token is bridged via the L1 portal's `enableToken()`, the `L1Subscriber` picks
up the `TokenEnabled` event and includes it in the next zone block's system
transaction. The `ZoneInbox` precompile initializes the token's storage directly
and grants `ISSUER_ROLE` to the inbox (for minting on deposits) and outbox (for
burning on withdrawals).

## Batch Submission

The `ZoneMonitor` watches the zone chain for new blocks, aggregates multiple
zone blocks into a single batch, and submits it to the `ZonePortal` on L1 via
`BatchSubmitter`. Each batch contains:

- A block state transition (previous → new block hash)
- A deposit queue transition (proving which deposits were processed)
- A withdrawal hash chain (so L1 can process withdrawals back to users)

The portal verifies `tempoBlockNumber` via EIP-2935 (last 8192 block hashes).
If the zone falls behind, the submitter switches to **ancestry mode** with a
header chain linking back to the target block.

## Withdrawals

1. Users call `ZoneOutbox.requestWithdrawal()` on the zone.
2. The zone monitor collects `WithdrawalRequested` events and stores them in the
   `WithdrawalStore`.
3. At batch finalization, withdrawals are hashed into a chain and submitted to
   L1 as part of the batch proof.
4. The `WithdrawalProcessor` polls the L1 portal queue and calls
   gas-bounded `processWithdrawals` batches through an ordered, bounded in-flight queue.

## TIP-403 Policy Enforcement

The zone enforces TIP-403 transfer policies (whitelist, blacklist, compound)
using Tempo's upstream policy implementation over anchored raw L1 state:

1. **L1StateProvider** — resolves storage slots at an explicit L1 block through
   the block-versioned `L1StateCache`, falling back to an exact-block L1 RPC
   read and caching the result.
2. **L1OverlayDB** — composes ordinary zone EVM storage with the raw L1
   reader at the exact finalized block recorded in `TempoState`. TIP-403
   registry state and each token's L1-owned transfer-policy field come from L1;
   balances and all other TIP-20 state remain zone-local. Mirrored reads retain
   normal EVM gas, warming, and storage accounting, while persistent writes to
   L1-owned slots are rejected.
3. **Tempo TIP-20 and TIP-403 precompiles** — execute the upstream business
   logic against that composed storage view, without a separate zone policy
   path. Missing or invalid anchored state fails closed, and zone
   privacy, bridge authorization, admission, and fixed-gas rules remain in the
   surrounding execution layer.

## Demo: Token Creation with Transfer Policy

End-to-end walkthrough for creating a TIP-20 token on L1, assigning a
blacklist policy, enabling it on the zone, and verifying enforcement.

**Prerequisites:** `L1_RPC_URL`, `PRIVATE_KEY`, `L1_PORTAL_ADDRESS`, and
`ADMIN_KEY` env vars set. `SEQUENCER_KEY` works only for legacy zones where
admin equals sequencer. A running zone (`just zone-up <name>`).

### 1. Create a TIP-20 token on L1

```bash
just create-token "TestUSD" "TUSD"
# → Token created at 0x20C0...
```

Save the token address for subsequent steps:
```bash
export TOKEN=0x20C0...  # address from output
```

### 2. Configure the token

```bash
# Set supply cap (defaults to u128::MAX)
just set-supply-cap $TOKEN

# Grant yourself ISSUER_ROLE so you can mint
just grant-issuer-role $TOKEN

# Mint tokens to yourself
just mint-tokens $TOKEN
```

### 3. Create a blacklist policy

```bash
# type=1 for blacklist (type=0 for whitelist)
just create-policy 1
# → Policy ID: <N>
```

Save the policy ID:
```bash
export POLICY_ID=<N>  # from output
```

### 4. Blacklist an address

```bash
# Block a specific address from receiving transfers
just modify-blacklist $POLICY_ID 0x000000000000000000000000000000000000dead

# Verify
just check-authorized $POLICY_ID 0x000000000000000000000000000000000000dead
# → authorized=false
```

### 5. Assign the policy to the token

```bash
just set-transfer-policy $TOKEN $POLICY_ID

# Verify
just token-policy $TOKEN
# → transferPolicyId=<N>
```

### 6. Enable the token on the zone and deposit

```bash
# Enable the token for bridging (requires ADMIN_KEY; SEQUENCER_KEY works only for legacy zones where admin == sequencer)
just enable-token $TOKEN

# Approve the portal to spend your tokens
just max-approve-portal

# Deposit to yourself on the zone
just send-deposit 1000000 "" 0x0000000000000000000000000000000000000000000000000000000000000000 $TOKEN
```

### 7. Test enforcement on the zone

Transfers to blacklisted addresses will be rejected by upstream TIP-20 policy
logic reading raw L1 policy state at the zone's finalized Tempo anchor.

```bash
# Check balance on zone
just check-balance $(cast wallet address $PRIVATE_KEY) $TOKEN

# Transfer to a non-blacklisted address — succeeds
cast send $TOKEN "transfer(address,uint256)" <allowed_addr> 1000 \
    --rpc-url $ZONE_RPC_URL --private-key $PRIVATE_KEY

# Transfer to blacklisted address — reverts
cast send $TOKEN "transfer(address,uint256)" 0x...dead 1000 \
    --rpc-url $ZONE_RPC_URL --private-key $PRIVATE_KEY
# → reverts with Unauthorized
```

### Compound policies

For role-based policies (different rules for senders vs recipients), create
sub-policies first, then combine them:

```bash
# Allow-all senders (builtin 1), blacklist recipients
just create-compound-policy 1 $POLICY_ID
# → Compound Policy ID: <M>

just set-transfer-policy $TOKEN <M>
```

## Zone Precompiles

| Address | Precompile | Purpose |
|---------|-----------|---------|
| `0x403C…0000` | `TIP403Registry` | Upstream read-only execution over exact-block raw L1 policy state |

## EVM Configuration

`ZoneEvmConfig` wraps `TempoEvmConfig` — the zone runs the same EVM as Tempo
L1 with these differences:

- The **TIP20Factory** precompile is disabled. Zone tokens are always bridged
  from L1 and activated directly by `ZoneInbox`.
- The **TIP403Registry** uses upstream Tempo execution through a read-only
  storage overlay anchored at the finalized L1 block recorded in `TempoState`.
  Policy mutations revert because registry state is owned by L1.
- The **block executor** is simplified: no subblock ordering, shared-gas
  accounting, or end-of-block metadata system transactions — those are L1-only
  concerns.
