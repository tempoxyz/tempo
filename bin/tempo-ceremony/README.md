# Tempo Genesis Ceremony

A tool for running the initial Distributed Key Generation (DKG) ceremony with validators before mainnet/testnet genesis.

## Operator Walkthrough

### Step 1: Generate Your Keys

Each participant generates their own identity keypair:

```bash
tempo-ceremony keygen --output-dir ./my-keys
```

This creates two files:
- `identity-private.hex` - Your private key (keep this secret!)
- `identity-public.hex` - Your public key (share this with the coordinator)

### Step 2: Share Your Details

Send the following to the ceremony coordinator:
- Your `identity-public.hex` contents
- Your public IP address and port (e.g., `203.0.113.50:9000`)

Make sure the port is open and accessible from other participants.

### Step 3: Receive the Configuration

The coordinator will send you a `ceremony.toml` file containing all participants. You need to set your listen address:

```toml
namespace = "tempo-genesis-2025"

[network]
listen_address = "0.0.0.0:9000"  # Set this to your listening address & port

[[participants]]
name = "alice"
public_key = "0x..."
address = "203.0.113.50:9000"

[[participants]]
name = "bob"
public_key = "0x..."
address = "203.0.113.51:9000"

# ... more participants
```

The `listen_address` is what your node binds to locally. Each participant's `address` in the list is their public-facing address.

### Step 4: Test Connectivity (Optional)

Before the actual ceremony, verify you can connect to all participants:

```bash
tempo-ceremony test-connectivity \
  --config ceremony.toml \
  --signing-key ./my-keys/identity-private.hex
```

Wait until all participants show as connected, then exit with Ctrl+C.

### Step 5: Run the Ceremony

When all participants are ready, run:

```bash
tempo-ceremony ceremony \
  --config ceremony.toml \
  --signing-key ./my-keys/identity-private.hex \
  --output-dir ./ceremony-output
```

The ceremony progresses through several phases automatically. Wait for completion.

### Step 6: Verify Outputs

After successful completion, check your output directory for:
- `share-private.hex` - Your private signing share (keep secret!)
- `public-polynomial.hex` - Group public polynomial (shared)
- `genesis-extra-data.hex` - Data for chain genesis block (shared)
- `genesis-outcome.json` - Human-readable ceremony result (shared)
- `all-dealings.json` - All dealings for audit trail (shared)

**Important:** All participants should have identical shared files. Compare checksums to verify.

---

## Protocol Phases

The ceremony executes a Distributed Key Generation protocol where all participants collaborate to create a shared threshold signature key without any single party knowing the full private key.

### Phase Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           GENESIS CEREMONY PHASES                           │
└─────────────────────────────────────────────────────────────────────────────┘

Phase 1: Connection
═══════════════════

    ┌─────────┐         ┌─────────┐         ┌─────────┐
    │ Node A  │◄───────►│ Node B  │◄───────►│ Node C  │
    └─────────┘         └─────────┘         └─────────┘
         ▲                                       ▲
         └───────────────────────────────────────┘

    All nodes establish authenticated P2P connections.
    Each node waits until connected to all other participants.


Phase 2: Share Distribution
═══════════════════════════

    ┌─────────┐                     ┌─────────┐
    │ Node A  │────── Share_AB ────►│ Node B  │
    │ (Dealer)│────── Share_AC ────►│ Node C  │
    └─────────┘                     └─────────┘

    Each node acts as a dealer:
    1. Generates a random polynomial
    2. Computes shares for each participant
    3. Sends shares to each participant

    This happens concurrently for all nodes.


Phase 3: Acknowledgments
════════════════════════

    ┌─────────┐                     ┌─────────┐
    │ Node B  │────── Ack_AB ──────►│ Node A  │
    │         │                     │         │
    │ Node C  │────── Ack_AC ──────►│         │
    └─────────┘                     └─────────┘

    After receiving a share, each node:
    1. Verifies the share against the dealer's commitment
    2. Signs an acknowledgment
    3. Sends the ack back to the dealer

    Dealers collect acks from all participants.


Phase 4: Dealing Broadcast
══════════════════════════

    ┌─────────┐       Dealing_A        ┌─────────┐
    │ Node A  │───────────────────────►│ Node B  │
    │         │───────────────────────►│ Node C  │
    └─────────┘                        └─────────┘

    Dealing_A contains:
    ├── Commitment (public polynomial)
    └── All Acks [Ack_AB, Ack_AC]

    Each dealer broadcasts their dealing (commitment + all acks).
    All nodes collect dealings from all other participants.


Phase 5: Share Computation
══════════════════════════

    ┌─────────────────────────────────────────────┐
    │                   Node A                    │
    │                                             │
    │   Share_A = Share_AA + Share_BA + Share_CA  │
    │                                             │
    │   Public = Commit_A + Commit_B + Commit_C   │
    └─────────────────────────────────────────────┘

    Each node locally computes:
    1. Their final signing share (sum of all received shares)
    2. The group public key (sum of all commitments)


Phase 6: Outcome Verification
═════════════════════════════

    ┌─────────┐      Outcome_A       ┌─────────┐
    │ Node A  │─────────────────────►│ Node B  │
    │         │◄─────────────────────│         │
    │         │   OutcomeAck(bool)   │         │
    └─────────┘                      └─────────┘

    Outcome contains:
    ├── Group public key
    ├── Epoch (0 for genesis)
    └── Participant list

    OutcomeAck(bool):
    ├── true  = outcome matches ours
    └── false = outcome mismatch (ceremony will fail)

    Each node broadcasts their outcome, then waits for:
    1. All other nodes' outcomes (verified to match)
    2. Acks from all peers confirming they received ours

    If any mismatch is detected (either locally or via rejected ack),
    the ceremony fails after collecting all acks.


Phase 7: Output
═══════════════

    ┌─────────────────────────────────────────────────┐
    │                     Output                      │
    ├─────────────────────────────────────────────────┤
    │  share-private.hex      (private, unique)       │
    │  public-polynomial.hex  (public, shared)        │
    │  genesis-extra-data.hex (public, shared)        │
    │  genesis-outcome.json   (public, shared)        │
    │  all-dealings.json      (public, shared)        │
    └─────────────────────────────────────────────────┘

    Each node writes outputs to their configured directory.
    Shared files should be identical across all participants.
```

### Message Flow Summary

```
Time ──────────────────────────────────────────────────────────────────────►

Node A    ═══[Connect]═══►─────[Share]────►─────[Ack]─────►═══[Dealing]═══►
Node B    ═══[Connect]═══►─────[Share]────►─────[Ack]─────►═══[Dealing]═══►
Node C    ═══[Connect]═══►─────[Share]────►─────[Ack]─────►═══[Dealing]═══►

                         │                │                │
                         ▼                ▼                ▼
                    All shares       All acks         All dealings
                     received        collected         received

          ──────────────────────────────────────────────────────────────────►

Node A    ═══[Compute]═══►═══[Outcome]═══►═══[OutcomeAck]═══►═══[Write]═══►
Node B    ═══[Compute]═══►═══[Outcome]═══►═══[OutcomeAck]═══►═══[Write]═══►
Node C    ═══[Compute]═══►═══[Outcome]═══►═══[OutcomeAck]═══►═══[Write]═══►

                         │                │                  │
                         ▼                ▼                  ▼
                   Local share       Outcomes +          Ceremony
                    computed         acks received       complete
```
