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
Starts a 4 validator network with Docker.

### stop-network.sh
Stops and cleans up the validator containers and the Docker network.

### tx-generator.sh
Uses cast to send 0 value transfers and confirm tx success. This is used to generate network activity during tests.

### test-utils.sh
Shared utilities for monitoring block production, starting/stopping validators, and managing the transaction generator.

## Configuration

To regenerate the validator configs, run the following command:
```bash
cargo x generate-config --output scripts/consensus/configs --peers 4 --bootstrappers 1 --message-backlog 16384 --mailbox-size 16384 --deque-size 10 --from-port 8000 --fee-recipient 0x0000000000000000000000000000000000000000 --seed 0
```

