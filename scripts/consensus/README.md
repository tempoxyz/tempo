# Consensus E2E Tests

This directory contains e2e tests for Tempo consensus. Each test spins up 4 peered validators, starts a round-robin transaction generator, and verifies behavior under various failure modes.

### test-partial-network-failure.sh
Single node crash and recovery. This test starts the network and tx generator, verifies block production continues, restarts the validator, and verifies continued production.

### test-network-halt-and-recovery.sh
Majority validator halt (2/4 nodes) and recovery. This test starts the network and tx generator, stops 2 validators to force a chain halt, verifies no block progress, restarts the validators, and verifies the chain resumes from the last finalized state.

### test-full-network-failure-and-recovery.sh
Full network failure and recovery. This test starts the network and tx generator, verifies progress, stops all validators, waits for recovery, and verifies block production resumes.

## Scripts

### start-network.sh
Runs `docker compose up` and waits for block production.

### stop-network.sh
Runs `docker compose down`.

### tx-generator.sh
Uses cast to send 0 value transfers and confirm tx success. This is used to generate network activity during tests.

### test-utils.sh
Shared utilities for monitoring block production, starting/stopping validators, and managing the transaction generator.

## Configuration

### File layout

```
generated/
  genesis.json                      # genesis with DKG outcome in extraData
  validator-{0,1,2,3}/
    signing.key                     # ed25519 signing key
    signing.share                   # BLS signing share
docker-compose.yml
start-network.sh
```

### Regenerating the genesis

If the genesis needs to be regenerated, run from the repo root:

```bash
rm -rf generated
cargo xtask generate-genesis \
  --validators 10.0.0.1:8000,10.0.0.2:8000,10.0.0.3:8000,10.0.0.4:8000 \
  --seed 0 \
  --accounts 100 \
  --no-extra-tokens \
  --no-pairwise-liquidity \
  --output generated

cd generated
for i in 0 1 2 3; do mv "10.0.0.$((i+1)):8000" "validator-$i"; done
```

The validator IPs must match the static IPs assigned in `docker-compose.yml`.

