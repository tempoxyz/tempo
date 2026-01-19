#!/bin/bash
# Interactive tmux demo showing attestation signature collection implementation
set -e

TEMPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SESSION="attest-demo"

# Kill existing session
tmux kill-session -t "$SESSION" 2>/dev/null || true

# Create new detached session with a named window
tmux new-session -d -s "$SESSION" -n main -c "$TEMPO_DIR"

# Get base index for panes
BASE=$(tmux show-options -gv pane-base-index 2>/dev/null || echo 0)

# Create 2x3 grid layout  
tmux split-window -h -t "$SESSION:main" -c "$TEMPO_DIR"
tmux split-window -h -t "$SESSION:main" -c "$TEMPO_DIR"
tmux select-pane -t "$SESSION:main.$BASE"
tmux split-window -v -t "$SESSION:main" -c "$TEMPO_DIR"
tmux select-pane -t "$SESSION:main.$((BASE+2))"
tmux split-window -v -t "$SESSION:main" -c "$TEMPO_DIR"
tmux select-pane -t "$SESSION:main.$((BASE+4))"
tmux split-window -v -t "$SESSION:main" -c "$TEMPO_DIR"

# Equal sizing
tmux select-layout -t "$SESSION:main" tiled

sleep 0.5

# Get pane IDs dynamically
PANES=($(tmux list-panes -t "$SESSION:main" -F '#{pane_index}'))
P0=${PANES[0]}
P1=${PANES[1]}
P2=${PANES[2]}
P3=${PANES[3]}
P4=${PANES[4]}
P5=${PANES[5]}

# Pane 0: SubBlock structure with deposit_attestations
tmux send-keys -t "$SESSION:main.$P0" "clear && echo -e '\\033[1;36m═══ 1. SubBlock Structure (NEW: deposit_attestations) ═══\\033[0m' && echo '' && grep -B2 -A 18 'pub struct SubBlock {' crates/primitives/src/subblock.rs" Enter

# Pane 1: Payload builder
tmux send-keys -t "$SESSION:main.$P1" "clear && echo -e '\\033[1;36m═══ 2. Payload Builder (system tx injection) ═══\\033[0m' && echo '' && sed -n '113,152p' crates/payload/builder/src/lib.rs" Enter

# Pane 2: ExEx signer
tmux send-keys -t "$SESSION:main.$P2" "clear && echo -e '\\033[1;36m═══ 3. ExEx Signer (attestation digest V2) ═══\\033[0m' && echo '' && sed -n '9,65p' crates/bridge-exex/src/signer.rs" Enter

# Pane 3: Precompile
tmux send-keys -t "$SESSION:main.$P3" "clear && echo -e '\\033[1;36m═══ 4. Precompile (signature verification) ═══\\033[0m' && echo '' && grep -B2 -A 30 'fn register_and_finalize_with_signatures' crates/precompiles/src/bridge/mod.rs | head -35" Enter

# Pane 4: Security fixes
tmux send-keys -t "$SESSION:main.$P4" "clear && echo -e '\\033[1;32m═══ 5. Security Fixes Applied ═══\\033[0m' && cat << 'SECEOF'

✓ DOMAIN V2: validator_set_hash bound
  → Prevents threshold manipulation

✓ L1 FINALITY: beacon finality gate  
  → Prevents reorg-based minting

✓ IDEMPOTENT: no revert if done
  → Prevents griefing proposers

✓ LOW-S: signature normalized
  → Prevents malleability

✓ LIMITS: 64/subblock, 32KB
  → Prevents attestation DoS

✓ PARITY: golden test vectors
  → Catches digest mismatches
SECEOF" Enter

# Pane 5: Run tests
tmux send-keys -t "$SESSION:main.$P5" "clear && echo -e '\\033[1;33m═══ 6. Live Tests ═══\\033[0m' && echo '' && echo 'Running attestation tests...' && cargo test -p tempo-precompiles test_register_and_finalize_with_signatures 2>&1 | grep -E '^(test |running |test result)'" Enter

# Focus on tests pane
tmux select-pane -t "$SESSION:main.$P5"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  Tmux session '$SESSION' created!                         ║"
echo "║                                                           ║"
echo "║  To attach: tmux attach -t $SESSION                       ║"
echo "║  Navigate:  Ctrl+B, Arrow keys                            ║"
echo "║  Detach:    Ctrl+B, D                                     ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Only attach if running interactively
if [ -t 0 ]; then
    tmux attach-session -t "$SESSION"
fi
