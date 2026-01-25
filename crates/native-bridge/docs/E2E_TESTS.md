# Native Bridge E2E Testing

## Running Tests

```bash
# Build Solidity contracts first (required for bytecode)
cd crates/native-bridge/contracts && forge build && cd ../../..

# Run all native-bridge tests
cargo test -p tempo-native-bridge

# Run only E2E tests
cargo test -p tempo-native-bridge --test bridge_e2e

# Run with debug output
cargo test -p tempo-native-bridge --test bridge_e2e -- --nocapture
```

**Prerequisites:**
- Anvil installed (`foundryup` to install Foundry)
- Solidity contracts compiled (`forge build` in `contracts/`)

---

## Current Test Coverage

### Unit Tests

| Module | Tests | Description |
|--------|-------|-------------|
| `signer.rs` | ✅ | BLS partial signing with MinSig variant |
| `aggregator.rs` | ✅ | Threshold signature aggregation (4-of-5) |
| `eip2537.rs` | ✅ | G1/G2 compressed → EIP-2537 format conversion |
| `message.rs` | ✅ | Attestation hash computation |

### E2E Tests (`tests/bridge_e2e.rs`)

| Test | Description |
|------|-------------|
| `test_anvil_event_subscription` | WebSocket `eth_subscribe` on Anvil (Prague hardfork) |
| `test_anvil_polling_fallback` | HTTP `eth_getLogs` polling on Anvil |
| `test_tempo_event_subscription` | WebSocket event subscription on in-process Tempo node |
| `test_tempo_polling_fallback` | HTTP polling on in-process Tempo node |
| `test_full_bridge_flow_ethereum_to_tempo` | **Complete cross-chain flow** (see below) |

### Full Bridge Flow Test

The `test_full_bridge_flow_ethereum_to_tempo` test verifies the complete Ethereum → Tempo message bridge:

1. **DKG Key Generation** - Creates 5 shares with threshold 4 (MinSig: G2 pubkeys, G1 sigs)
2. **Node Startup** - Starts Anvil (Prague hardfork) and in-process Tempo node
3. **Contract Deployment** - Deploys `MessageBridge.sol` on both chains with same G2 public key
4. **Message Send** - Calls `send(messageHash, destinationChainId)` on Ethereum
5. **Threshold Signing** - 4 signers create partial G1 signatures
6. **Aggregation** - Recovers threshold signature via Lagrange interpolation
7. **EIP-2537 Conversion** - Converts compressed G1 (48 bytes) → EIP-2537 (128 bytes)
8. **Cross-chain Submission** - Calls `write(sender, messageHash, originChainId, signature)` on Tempo
9. **Verification** - Confirms `MessageReceived` event and `receivedAt()` returns non-zero timestamp

All cryptographic operations use **real BLS12-381 keys and signatures** - no mocks.

---

## Components Tested

### Rust Sidecar

| Component | File | Status |
|-----------|------|--------|
| ChainWatcher | `sidecar/watcher.rs` | ✅ Tested (WebSocket + polling) |
| BLSSigner | `signer.rs` | ✅ Tested (MinSig partial signing) |
| Aggregator | `sidecar/aggregator.rs` | ✅ Tested (threshold recovery) |
| Submitter | `sidecar/submitter.rs` | ✅ Tested (via E2E flow) |
| EIP-2537 conversion | `eip2537.rs` | ✅ Tested (G1/G2 format conversion) |

### Solidity Contracts

| Contract | File | Status |
|----------|------|--------|
| MessageBridge | `contracts/src/MessageBridge.sol` | ✅ Tested (send, write, key rotation) |
| BLS12381 | `contracts/src/BLS12381.sol` | ✅ Tested (signature verification) |
| IMessageBridge | `contracts/src/interfaces/IMessageBridge.sol` | ✅ Interface only |

---

## What's Left to Build/Test

### P2P Gossip Layer (Implemented)

Validators share partial signatures via the P2P network:

- [x] **P2P partial signature broadcast** - `P2pGossip` broadcasts to all validators via `BRIDGE_CHANNEL_IDENT`
- [x] **Gossip message format** - `BridgeGossipMessage` with attestation hash, partial signature, and context
- [ ] **Partial signature validation** - TODO: Verify `e(sig, G2) == e(H(m), pk_i)` before aggregation
- [x] **Deduplication** - `Aggregator` rejects duplicate partials from the same index

### Multi-Validator E2E Test

- [ ] **Distributed signing test** - Multiple sidecar instances coordinating
- [ ] Test with 5 validators, verify only 4 needed for threshold

### Key Rotation E2E Test

- [ ] **`rotateKey()` flow** - Old validators sign authorization for new key
- [ ] **Grace period** - Verify messages signed with old key still accepted
- [ ] **Epoch transitions** - Test key rotation during active message flow

### Bidirectional Bridge Test

- [ ] **Tempo → Ethereum flow** - Currently only Ethereum → Tempo tested
- [ ] Test `send()` on Tempo, `write()` on Anvil

### Finality Handling

- [ ] **Reorg protection** - Test `finality_blocks` config in watcher
- [ ] **Block confirmation** - Verify messages from non-finalized blocks are delayed

### Error Cases

- [ ] **Invalid signature rejection** - Wrong signer / corrupted signature
- [ ] **Replay protection** - Same message cannot be written twice
- [ ] **Paused contract** - Verify `whenNotPaused` modifier works
- [ ] **Unauthorized key rotation** - Reject rotation with invalid signature

### Metrics & Observability

- [ ] **Prometheus metrics** - Expose signing latency, success rate
- [ ] **Structured logging** - Trace IDs for cross-chain message tracking

### Production Deployment

- [ ] **Config file validation** - TOML config loading tests
- [ ] **Private key management** - Integration with secret managers
- [ ] **Gas estimation** - Verify gas limits for `write()` transactions

---

## Devnet E2E Testing Strategy

The bridge is integrated into the validator binary via `--bridge.enabled`. It reuses the same BLS key share that consensus uses and shares partial signatures via the validator's P2P network.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Validator 0                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │  tempo node --bridge.enabled                                          │ │
│  │                                                                        │ │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐    │ │
│  │  │  Consensus   │    │   Bridge     │    │  P2P Network         │    │ │
│  │  │  Engine      │    │   Service    │◄──►│  (BRIDGE_CHANNEL=7)  │    │ │
│  │  │              │    │              │    │                      │    │ │
│  │  │  signing     │───►│  signing     │    │  Broadcasts partial  │    │ │
│  │  │  share       │    │  share       │    │  Receives partials   │    │ │
│  │  └──────────────┘    └──────┬───────┘    └──────────────────────┘    │ │
│  │                             │                        ▲                │ │
│  │                             ▼                        │                │ │
│  │                      ┌──────────────┐                │                │ │
│  │                      │  Aggregator  │────────────────┘                │ │
│  │                      │  (threshold) │                                 │ │
│  │                      └──────────────┘                                 │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
          │                                                       │
          │  P2P gossip (partial signatures)                      │
          ▼                                                       ▼
┌─────────────────────┐                             ┌─────────────────────┐
│   Validator 1       │  ◄─────────────────────►    │   Validator 2       │
│   --bridge.enabled  │                             │   --bridge.enabled  │
└─────────────────────┘                             └─────────────────────┘
```

**Flow:**
1. All validators watch for `MessageSent` events on source chains
2. Each validator signs the attestation with their BLS share
3. Validators broadcast their partial signature via P2P (channel 7)
4. Each validator's aggregator collects partials from all peers
5. Once threshold (e.g., 4-of-5) partials collected, any validator can submit

### Step 1: Build Validator with Bridge Feature

```bash
# Build tempo with bridge support
cargo build -p tempo --features bridge --release
```

### Step 2: Create Bridge Config File

Create `bridge.toml` for the devnet:

```toml
[general]
log_level = "info"

# Watch Ethereum for MessageSent events
[[chains]]
name = "ethereum"
chain_id = 1
ws_url = "wss://ethereum-rpc.example.com"
rpc_url = "https://ethereum-rpc.example.com"
bridge_address = "0x..." # MessageBridge on Ethereum
finality_blocks = 12

# Submit attestations to Tempo
[[chains]]
name = "tempo"
chain_id = 12345
ws_url = "wss://tempo-devnet-nightly-rpc.tail388b2e.ts.net"
rpc_url = "https://tempo-devnet-nightly-rpc.tail388b2e.ts.net"
bridge_address = "0x..." # MessageBridge on Tempo
finality_blocks = 1

[signer]
validator_index = 0  # This validator's index

[threshold]
sharing_file = "/path/to/sharing.hex"  # DKG sharing polynomial
epoch = 1
```

### Step 3: Get DKG Sharing from Chain

Extract the DKG outcome to get the sharing polynomial:

```bash
# Get the DKG outcome from the devnet
cargo run -p xtask -- get-dkg-outcome \
  --rpc-url https://tempo-devnet-nightly-rpc.tail388b2e.ts.net \
  --epoch 1 \
  --epoch-length 100

# Output includes:
# - network_identity: Group G2 public key (96 bytes compressed)
# - threshold: Required signers
# - players: Validator public keys
```

For devnets, the sharing file is generated during `devnet-build` and stored in the validator config.

### Step 4: Deploy MessageBridge Contracts

Deploy MessageBridge on both chains with the group public key:

```bash
# Convert G2 to EIP-2537 format (256 bytes) and deploy
# The network_identity from get-dkg-outcome needs conversion

# On Tempo devnet
forge create MessageBridge \
  --rpc-url https://tempo-devnet-nightly-rpc.tail388b2e.ts.net \
  --private-key <funded-key> \
  --constructor-args <owner> 1 0x<g2-pubkey-256-bytes>

# On Ethereum testnet (e.g., Sepolia with Prague)
forge create MessageBridge \
  --rpc-url https://sepolia-rpc.example.com \
  --private-key <funded-key> \
  --constructor-args <owner> 1 0x<g2-pubkey-256-bytes>
```

### Step 5: Run Validator with Bridge Enabled

```bash
tempo node \
  --consensus.signing-key /path/to/signing.key \
  --consensus.signing-share /path/to/signing.share \
  --consensus.fee-recipient 0x... \
  --bridge.enabled \
  --bridge.config /path/to/bridge.toml
```

### Step 6: Test the Flow

1. **Send message on Ethereum:**
   ```bash
   cast send <bridge-address> "send(bytes32,uint64)" \
     0xabcd...1234 12345 \
     --rpc-url https://sepolia-rpc.example.com \
     --private-key <key>
   ```

2. **All validators detect the event** - Bridge services watch for `MessageSent`

3. **Each validator signs and broadcasts:**
   - Signs attestation with their BLS share
   - Broadcasts partial signature via P2P channel 7
   - Receives partial signatures from other validators

4. **Threshold aggregation:**
   - Each validator's aggregator collects partials
   - Once threshold reached (e.g., 4-of-5), aggregates into threshold signature
   - First validator to reach threshold submits to destination chain

5. **Submit to Tempo** - Aggregated signature submitted via `write()`

6. **Verify receipt:**
   ```bash
   cast call <tempo-bridge-address> \
     "receivedAt(uint64,address,bytes32)(uint256)" \
     1 <sender> 0xabcd...1234 \
     --rpc-url https://tempo-devnet-nightly-rpc.tail388b2e.ts.net
   ```

**Expected logs on each validator:**
```
bridge: received message from chain (origin=1, dest=12345)
bridge: signed partial (index=0)
bridge: broadcasted partial to peers
bridge: received partial from peer (index=1)
bridge: received partial from peer (index=2)
bridge: received partial from peer (index=3)
bridge: threshold signature recovered
bridge: submitted attestation (tx_hash=0x...)
```

### Devnet Deployment Options

#### Option A: Helm Chart (Recommended)

The `tempo-node` and `tempo-devnet` charts now support native bridge configuration.

**1. Create a new bridge-enabled devnet:**

```yaml
# devnet-bridge-app.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: devnet-bridge
  namespace: argocd
spec:
  source:
    repoURL: git@github.com:tempoxyz/helm-charts.git
    targetRevision: tempo-devnet-0.2.0  # or feat/native-bridge-support branch
    path: charts/tempo-devnet
    helm:
      valuesObject:
        tempo:
          image:
            tag: sha-c59ae19c1  # Image with bridge feature
          # ... validators config ...
        bridge:
          enabled: true
          epoch: 1
          chains:
            - name: tempo
              chainId: 31319
              wsUrl: "ws://localhost:8546"
              rpcUrl: "http://localhost:8545"
              bridgeAddress: "0x..."  # MessageBridge contract
              finalityBlocks: 1
```

**2. Apply the ArgoCD application:**

```bash
kubectl apply -f devnet-bridge-app.yaml
```

The chart will:
- Generate `bridge.toml` in the init container
- Pass `--bridge.enabled --bridge.config /data/work/bridge.toml` to tempo

**PRs:**
- Helm chart: https://github.com/tempoxyz/helm-charts/pull/197
- Tempo: https://github.com/tempoxyz/tempo/pull/2235

#### Option B: Manual Testing on Existing Devnet

SSH into a validator pod and run with bridge enabled:

```bash
# On a devnet validator
kubectl exec -it validator-0 -n tempo-devnet-nightly -- bash

# Check existing config
cat /config/signing.share

# Create bridge config and run manually
tempo node ... --bridge.enabled --bridge.config /tmp/bridge.toml
```

### What's Implemented

- ✅ **P2P Gossip** - Validators share partial signatures via `BRIDGE_CHANNEL_IDENT` (channel 7)
- ✅ **Threshold Aggregation** - Aggregator collects partials and recovers threshold signature
- ✅ **Multi-Validator Support** - All validators can participate in signing
- ✅ **Helm Chart / Argo Integration** - Automated devnet deployment with bridge

### What's Still TODO

1. **Partial Signature Validation** - Verify incoming partials before aggregation
   - Should check `e(sig, G2) == e(H(m), pk_i)` using the public polynomial
   - Currently trusts authenticated P2P peers send valid partials

2. **Sharing from Chain** - Currently loaded from file
   - Should read from `OnchainDkgOutcome` at epoch boundaries
   - Currently uses `threshold.sharing_file` in bridge config

3. **Duplicate Submission Prevention** - Multiple validators may submit
   - Currently all validators that reach threshold try to submit
   - Should coordinate to avoid wasted gas (or let contract handle idempotently)

---

## Test Infrastructure

### Anvil Configuration

E2E tests start Anvil with Prague hardfork for EIP-2537 BLS precompiles:

```bash
anvil --hardfork prague --block-time 1
```

### Tempo Node

Tests use `TempoNode` from `tempo-node` crate for in-process node without Docker.

### Contract Deployment

Uses real `MessageBridge.bytecode.hex` compiled from Solidity:

```
crates/native-bridge/contracts/out/MessageBridge.sol/MessageBridge.bytecode.hex
```
