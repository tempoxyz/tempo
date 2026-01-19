#!/bin/bash
# Demo: Deposit Attestation Signature Collection Flow
# 
# This script demonstrates how validators collect and aggregate 
# deposit attestation signatures via subblocks.
#
# Layout:
#   ┌─────────────────────┬─────────────────────┐
#   │   Validator 1       │   Validator 2       │
#   │   (proposer)        │                     │
#   ├─────────────────────┼─────────────────────┤
#   │   Validator 3       │   Validator 4       │
#   │                     │                     │
#   ├─────────────────────┴─────────────────────┤
#   │              Test Runner                  │
#   └───────────────────────────────────────────┘

set -e

SESSION="attestation-demo"
TEMPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Deposit Attestation Signature Collection Demo              ║${NC}"
echo -e "${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BLUE}║  This demo shows how validators:                             ║${NC}"
echo -e "${BLUE}║  1. Sign deposit attestations locally                        ║${NC}"
echo -e "${BLUE}║  2. Embed signatures in subblocks                            ║${NC}"
echo -e "${BLUE}║  3. Proposer collects 2/3+ signatures                        ║${NC}"
echo -e "${BLUE}║  4. Inject finalization tx calling precompile                ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Kill existing session if it exists
tmux kill-session -t "$SESSION" 2>/dev/null || true

# Create new tmux session
tmux new-session -d -s "$SESSION" -x 200 -y 50

# Create the layout
tmux split-window -h -t "$SESSION"
tmux split-window -v -t "$SESSION:0.0"
tmux split-window -v -t "$SESSION:0.2"
tmux split-window -v -t "$SESSION:0.0" -l 15

# Name the panes
tmux select-pane -t "$SESSION:0.0" -T "Validator 1 (Proposer)"
tmux select-pane -t "$SESSION:0.1" -T "Test Runner"
tmux select-pane -t "$SESSION:0.2" -T "Validator 3"
tmux select-pane -t "$SESSION:0.3" -T "Validator 2"
tmux select-pane -t "$SESSION:0.4" -T "Validator 4"

# Pane 0: Validator 1 logs (will show proposer collecting signatures)
tmux send-keys -t "$SESSION:0.0" "cd $TEMPO_DIR && echo '${GREEN}═══ Validator 1 (Block Proposer) ═══${NC}'" Enter
tmux send-keys -t "$SESSION:0.0" "echo 'Waiting for test to start...'" Enter
tmux send-keys -t "$SESSION:0.0" "echo ''" Enter
tmux send-keys -t "$SESSION:0.0" "cat << 'EOF'
When proposing a block, this validator will:
1. Collect subblocks from validators 2, 3, 4
2. Extract deposit_attestations from each subblock
3. Track signatures in AttestationTracker
4. When 2/3+ reached, inject finalization tx

Expected logs:
  [INFO] Received subblock from validator 2 with 1 attestation
  [INFO] Received subblock from validator 3 with 1 attestation  
  [INFO] Received subblock from validator 4 with 1 attestation
  [INFO] Threshold reached for request_id=0x1234...
  [INFO] Injecting registerAndFinalizeWithSignatures tx
EOF" Enter

# Pane 1: Test runner
tmux send-keys -t "$SESSION:0.1" "cd $TEMPO_DIR" Enter
tmux send-keys -t "$SESSION:0.1" "echo '${YELLOW}═══ Test Runner ═══${NC}'" Enter
tmux send-keys -t "$SESSION:0.1" "echo ''" Enter
tmux send-keys -t "$SESSION:0.1" "echo 'Running bridge attestation tests...'" Enter
tmux send-keys -t "$SESSION:0.1" "echo ''" Enter

# Pane 2: Validator 3
tmux send-keys -t "$SESSION:0.2" "cd $TEMPO_DIR && echo '${GREEN}═══ Validator 3 ═══${NC}'" Enter
tmux send-keys -t "$SESSION:0.2" "cat << 'EOF'
This validator will:
1. Observe L1 deposit event
2. Wait for L1 finality (64 confirmations)
3. Compute attestation digest with validator_set_hash
4. Sign with ECDSA key
5. Embed signature in SubBlockV2.deposit_attestations
6. Send subblock to proposer every 50ms

Expected logs:
  [INFO] L1 deposit detected: request_id=0x1234...
  [INFO] Waiting for L1 finality (block 19500000)
  [INFO] L1 block finalized, signing attestation
  [INFO] Signed attestation, adding to subblock
EOF" Enter

# Pane 3: Validator 2  
tmux send-keys -t "$SESSION:0.3" "cd $TEMPO_DIR && echo '${GREEN}═══ Validator 2 ═══${NC}'" Enter
tmux send-keys -t "$SESSION:0.3" "cat << 'EOF'
Same flow as Validator 3:
- Observes same L1 deposit
- Signs after finality
- Embeds in subblock
- Sends to proposer
EOF" Enter

# Pane 4: Validator 4
tmux send-keys -t "$SESSION:0.4" "cd $TEMPO_DIR && echo '${GREEN}═══ Validator 4 ═══${NC}'" Enter
tmux send-keys -t "$SESSION:0.4" "cat << 'EOF'
Same flow as Validator 3:
- Observes same L1 deposit
- Signs after finality
- Embeds in subblock
- Sends to proposer
EOF" Enter

# Now run the actual tests in the test runner pane
sleep 1
tmux send-keys -t "$SESSION:0.1" "cargo test -p tempo-e2e --lib bridge -- --test-threads=1 --nocapture 2>&1 | head -100" Enter

# Attach to session
echo -e "${GREEN}Attaching to tmux session...${NC}"
echo -e "Use ${YELLOW}Ctrl+B, D${NC} to detach"
echo ""

tmux attach-session -t "$SESSION"
