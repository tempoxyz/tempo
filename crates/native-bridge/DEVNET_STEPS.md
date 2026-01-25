# Bridge Devnet Setup Guide

Complete step-by-step guide to set up an e2e bridge test environment between Anvil (Ethereum) and Tempo devnet.

## Prerequisites

- `kubectl` configured with access to the Kubernetes cluster
- `helm` installed
- `forge` and `cast` (Foundry) installed
- Access to `tempoxyz/helm-charts` repository
- Access to ArgoCD (or ability to apply manifests directly)

## Overview

The setup creates:
1. **Anvil** - Ethereum node with Prague hardfork (EIP-2537 BLS precompiles)
2. **Tempo Devnet** - 4 validators with consensus and bridge enabled
3. **MessageBridge contracts** - Deployed on both chains with matching DKG public key

---

## Step 1: Create the Namespace and Preallocate Validator IPs

```bash
# Create namespace
kubectl create namespace devnet-bridge

# Create services with static IPs for validators
# These IPs must be used in genesis generation
for i in 1 2 3 4; do
  kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: val$i
  namespace: devnet-bridge
spec:
  clusterIP: 10.96.122.$i
  ports:
  - name: p2p-tcp
    port: 30303
    protocol: TCP
  - name: p2p-udp
    port: 30303
    protocol: UDP
  - name: consensus
    port: 30302
    protocol: TCP
  selector:
    app.tempo.xyz/name: val$i
EOF
done
```

---

## Step 2: Generate Genesis with DKG

Use the `devnet-generate` ClusterWorkflowTemplate to generate genesis:

```bash
kubectl create -f - <<EOF
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: devnet-bridge-generate-
  namespace: argo-workflows
spec:
  workflowTemplateRef:
    name: devnet-generate
    clusterScope: true
  arguments:
    parameters:
      - name: accounts
        value: "100"
      - name: branch
        value: "main"  # or your feature branch
      - name: chain-id
        value: "31319"
      - name: epoch-length
        value: "1000"
      - name: gas-limit
        value: "500000000"
      - name: name
        value: "devnet-bridge"
      - name: validators
        value: "10.96.122.1:30302,10.96.122.2:30302,10.96.122.3:30302,10.96.122.4:30302"
EOF
```

**Wait for workflow completion:**
```bash
kubectl get workflow -n argo-workflows -w
```

**Verify genesis was uploaded:**
```bash
curl -s https://devnet-assets.tempoxyz.dev/devnet-bridge.json | jq '.config.chainId'
# Should return: 31319
```

### Common Errors

**Error: ValidatorConfig precompile missing**
```
Symptoms: Validators spam "nullify" in logs, consensus doesn't progress
Cause: Genesis generated without proper DKG/validator config
Fix: Re-run the devnet-generate workflow, delete PVCs, restart pods
```

**Error: Workflow fails with "branch not found"**
```
Cause: Branch doesn't exist or isn't pushed
Fix: Push your branch to the tempo repository
```

---

## Step 3: Deploy Anvil

Create Anvil deployment with Prague hardfork enabled:

```bash
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: anvil
  namespace: devnet-bridge
spec:
  replicas: 1
  selector:
    matchLabels:
      app: anvil
  template:
    metadata:
      labels:
        app: anvil
    spec:
      containers:
      - name: anvil
        image: ghcr.io/foundry-rs/foundry:latest
        command: ["anvil"]
        args:
          - "--hardfork"
          - "prague"       # Required for EIP-2537 BLS precompiles
          - "--block-time"
          - "2"
          - "--host"
          - "0.0.0.0"
          - "--chain-id"
          - "31337"
        ports:
        - containerPort: 8545
          name: http
        - containerPort: 8546
          name: ws
---
apiVersion: v1
kind: Service
metadata:
  name: anvil
  namespace: devnet-bridge
spec:
  selector:
    app: anvil
  ports:
  - name: http
    port: 8545
    targetPort: 8545
  - name: ws
    port: 8546
    targetPort: 8546
EOF
```

**Verify Anvil is running:**
```bash
kubectl port-forward -n devnet-bridge deploy/anvil 18545:8545 &
cast chain-id --rpc-url http://localhost:18545
# Should return: 31337
```

### Common Errors

**Error: EIP-2537 precompile call fails**
```
Symptoms: BLS verification reverts with no data
Cause: Anvil not started with --hardfork prague
Fix: Ensure args include "--hardfork prague"
```

---

## Step 4: Create ArgoCD Application

Create the ArgoCD application manifest (initially without bridge addresses):

```yaml
# devnet-bridge-app.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: devnet-bridge
  namespace: argocd
spec:
  project: default
  source:
    repoURL: git@github.com:tempoxyz/helm-charts.git
    targetRevision: feat/native-bridge-support  # Your branch with bridge support
    path: charts/tempo-devnet
    helm:
      valuesObject:
        tempo:
          targetRevision: feat/native-bridge-support
          genesisUrl: "https://devnet-assets.tempoxyz.dev/devnet-bridge.json"
          image:
            repository: ghcr.io/tempoxyz/tempo
            tag: sha-XXXXXXX  # Image with bridge feature
          extraArgs:
            - "--builder.state-provider-metrics"
            - "--engine.state-provider-metrics"
            - "--consensus.use-local-p2p-defaults"
          validatorIps:
            - "10.96.122.1"
            - "10.96.122.2"
            - "10.96.122.3"
            - "10.96.122.4"
        bridge:
          enabled: true
          epoch: 1
          chains:
            - name: tempo
              chainId: 31319
              wsUrl: "ws://localhost:8546"
              rpcUrl: "http://localhost:8545"
              bridgeAddress: "0x0000000000000000000000000000000000000000"  # Placeholder
              finalityBlocks: 1
  destination:
    server: https://kubernetes.default.svc
    namespace: argocd
  syncPolicy:
    automated:
      selfHeal: true
    syncOptions:
      - Prune=true
      - CreateNamespace=true
```

```bash
kubectl apply -f devnet-bridge-app.yaml
```

**Wait for validators to be ready:**
```bash
kubectl wait --for=condition=ready pod -l app.tempo.xyz/nodetype=validator \
  -n devnet-bridge --timeout=300s
```

### Common Errors

**Error: CrashLoopBackOff - genesis hash mismatch**
```
Symptoms: Pods crash immediately, logs show "genesis hash mismatch"
Cause: PVC contains old data from different genesis
Fix: Delete PVCs and restart
  kubectl delete pvc -n devnet-bridge --all
  kubectl rollout restart statefulset val1 val2 val3 val4 -n devnet-bridge
```

**Error: Consensus not progressing**
```
Symptoms: Block number stuck, "nullify" spam in logs
Cause: Validators can't reach each other OR ValidatorConfig misconfigured
Fix: 
  1. Verify service IPs match genesis
  2. Verify ValidatorConfig precompile:
     cast call 0xCCCCCCCC00000000000000000000000000000000 "validatorCount()(uint256)" --rpc-url http://localhost:18546
```

---

## Step 5: Extract DKG Public Key

Get the network identity (G2 public key) from genesis:

```bash
# Port forward to a validator
kubectl port-forward -n devnet-bridge svc/val1-rpc 18546:8545 &

# Extract compressed G2 key (96 bytes)
cargo x get-dkg-outcome --rpc-url http://localhost:18546 --block 0
```

Output will show:
```
network_identity: 0x98c6e82fdf8990fa8b78df3788c45d4a...
```

**Convert to EIP-2537 format (256 bytes):**

The compressed G2 (96 bytes) must be converted to EIP-2537 unpadded format (256 bytes).
Use the test in `crates/native-bridge/tests/print_g2.rs` or the `g2_to_eip2537` function.

Example EIP-2537 G2 key:
```
0x0000000000000000000000000000000018c6e82fdf8990fa8b78df3788c45d4a...
```

---

## Step 6: Fund Account on Tempo

Before deploying contracts, fund an account with TIP-20 tokens:

```bash
# Use the tempo_fundAddress RPC method
curl -s -X POST http://localhost:18546 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tempo_fundAddress","params":["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"],"id":1}'
```

This mints tokens to the wrapped native (pathUSD) at `0x20c0000000000000000000000000000000000000`.

**Verify balance:**
```bash
cast call --rpc-url http://localhost:18546 \
  "0x20c0000000000000000000000000000000000000" \
  "balanceOf(address)(uint256)" \
  "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
```

---

## Step 7: Deploy MessageBridge Contracts

### Build contracts first:
```bash
cd crates/native-bridge/contracts
forge build
```

### Deploy to Anvil:
```bash
# Port forward to Anvil
kubectl port-forward -n devnet-bridge deploy/anvil 18545:8545 &

# Deploy
cd crates/native-bridge/contracts
G2_EIP2537="0x<your-256-byte-eip2537-g2-key>"
PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
OWNER="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

BYTECODE=$(cat out/MessageBridge.sol/MessageBridge.bytecode.hex)
ENCODED_ARGS=$(cast abi-encode "constructor(address,uint64,bytes)" "$OWNER" 1 "$G2_EIP2537")
DEPLOY_DATA="${BYTECODE}${ENCODED_ARGS:2}"

ANVIL_BRIDGE=$(cast send --rpc-url http://localhost:18545 \
  --private-key "$PRIVATE_KEY" \
  --json \
  --create "$DEPLOY_DATA" | jq -r '.contractAddress')

echo "Anvil MessageBridge: $ANVIL_BRIDGE"
```

### Deploy to Tempo:
```bash
TEMPO_BRIDGE=$(cast send --rpc-url http://localhost:18546 \
  --private-key "$PRIVATE_KEY" \
  --json \
  --create "$DEPLOY_DATA" | jq -r '.contractAddress')

echo "Tempo MessageBridge: $TEMPO_BRIDGE"
```

### Verify deployments:
```bash
# Anvil
cast call --rpc-url http://localhost:18545 "$ANVIL_BRIDGE" "chainId()(uint64)"
# Should return: 31337

# Tempo
cast call --rpc-url http://localhost:18546 "$TEMPO_BRIDGE" "chainId()(uint64)"
# Should return: 31319
```

### Common Errors

**Error: forge create shows "Dry run enabled" even with --broadcast**
```
Cause: Unknown forge configuration issue
Fix: Use cast send --create instead:
  cast send --rpc-url <url> --private-key <key> --create <bytecode>
```

**Error: Transaction reverts on Tempo with no error data**
```
Cause: Insufficient gas or TIP-20 balance
Fix: Fund account with tempo_fundAddress first
```

---

## Step 8: Update Bridge Configuration

Update the ArgoCD app with deployed contract addresses:

```yaml
bridge:
  enabled: true
  epoch: 1
  chains:
    - name: tempo
      chainId: 31319
      wsUrl: "ws://localhost:8546"
      rpcUrl: "http://localhost:8545"
      bridgeAddress: "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"  # Your Tempo address
      finalityBlocks: 1
    - name: anvil
      chainId: 31337
      wsUrl: "ws://anvil:8545"   # NOTE: Same port as HTTP!
      rpcUrl: "http://anvil:8545"
      bridgeAddress: "0x5FbDB2315678afecb367f032d93F642f64180aa3"  # Your Anvil address
      finalityBlocks: 1
```

```bash
# Apply updated config
kubectl apply -f devnet-bridge-app.yaml

# Restart validators to pick up new config
kubectl rollout restart statefulset val1 val2 val3 val4 -n devnet-bridge

# Wait for ready
kubectl wait --for=condition=ready pod -l app.tempo.xyz/nodetype=validator \
  -n devnet-bridge --timeout=120s
```

### Common Errors

**Error: Bridge watcher fails with "Connection refused" for Anvil**
```
Symptoms: Logs show "ws connect failed: IO error: Connection refused (os error 111)"
Cause: Using ws://anvil:8546 but Anvil serves WebSocket on port 8545
Fix: Change wsUrl to "ws://anvil:8545" (same as HTTP port)
```

**Error: Bridge watcher fails at startup, no retry**
```
Symptoms: Connection error at startup, bridge never reconnects
Cause: Anvil pod wasn't ready when validators started
Fix: Restart validators after Anvil is running:
  kubectl rollout restart statefulset val1 val2 val3 val4 -n devnet-bridge
```

---

## Step 9: Verify Bridge is Running

Check bridge logs:
```bash
kubectl logs -n devnet-bridge val1-0 2>&1 | grep -i "native_bridge" | tail -20
```

**Expected output:**
```
INFO tempo_native_bridge::service: bridge service started
INFO tempo_native_bridge::sidecar::watcher: subscribed to MessageSent events chain=tempo bridge=0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
INFO tempo_native_bridge::sidecar::watcher: subscribed to MessageSent events chain=anvil bridge=0x5FbDB2315678afecb367f032d93F642f64180aa3
```

---

## Step 10: Test Bridge Flow

Send a message from Anvil to Tempo:

```bash
ANVIL_BRIDGE="0x5FbDB2315678afecb367f032d93F642f64180aa3"
PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
MESSAGE_HASH="0x$(openssl rand -hex 32)"
DEST_CHAIN_ID=31319

cast send --rpc-url http://localhost:18545 \
  --private-key "$PRIVATE_KEY" \
  "$ANVIL_BRIDGE" \
  "send(bytes32,uint64)" \
  "$MESSAGE_HASH" \
  "$DEST_CHAIN_ID"
```

**Check bridge processed it:**
```bash
kubectl logs -n devnet-bridge val1-0 --since=30s 2>&1 | grep -i "native_bridge"
```

**Expected output:**
```
INFO tempo_native_bridge::service: bridge: received message from chain origin=31337 dest=31319 hash=0x...
DEBUG tempo_native_bridge::service: bridge: signed partial index=0 hash=0x...
DEBUG tempo_native_bridge::service: bridge: received partial from peer index=1 hash=0x...
DEBUG tempo_native_bridge::service: bridge: received partial from peer index=2 hash=0x...
INFO tempo_native_bridge::sidecar::aggregator: threshold signature recovered hash=0x... partial_count=3
DEBUG tempo_native_bridge::sidecar::submitter: simulating attestation call (no signer configured)
DEBUG tempo_native_bridge::sidecar::submitter: simulation successful
INFO tempo_native_bridge::service: bridge: submitted attestation dest=31319 tx_hash=0x0000...
```

**Note:** The `tx_hash=0x0000...` indicates simulation-only mode (no submitter private key configured). The threshold signature was successfully aggregated but not actually submitted on-chain.

---

## Troubleshooting Reference

| Symptom | Cause | Solution |
|---------|-------|----------|
| Validators in CrashLoopBackOff | Genesis hash mismatch | Delete PVCs, restart pods |
| "nullify" spam in logs | Validators can't reach each other | Check service IPs match genesis |
| Bridge shows "Connection refused" | Wrong WebSocket port for Anvil | Use port 8545 for Anvil WS |
| Bridge not reconnecting | Connection failed at startup | Restart validators after Anvil ready |
| BLS verification reverts | Anvil missing Prague hardfork | Add `--hardfork prague` to Anvil |
| Contract deploy fails on Tempo | No TIP-20 balance | Call `tempo_fundAddress` RPC first |
| forge create dry-run mode | Unknown forge issue | Use `cast send --create` instead |
| "simulation successful" but no tx | Submitter has no private key | Expected in test mode |

---

## Quick Reference: Key Addresses

| Component | Address |
|-----------|---------|
| Wrapped Native (pathUSD) | `0x20c0000000000000000000000000000000000000` |
| TIP20 Factory | `0x20c0000000000000000000000000000000000001` |
| ValidatorConfig Precompile | `0xCCCCCCCC00000000000000000000000000000000` |
| Anvil Default Account | `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` |
| Anvil Default Private Key | `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80` |
