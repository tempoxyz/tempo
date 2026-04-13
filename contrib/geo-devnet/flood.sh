#!/usr/bin/env bash
set -euo pipefail

CAST="$HOME/.foundry/bin/cast"
RPC="http://172.20.0.10:8545"
CHAIN_ID=1337
DURATION="${1:-60}"
TARGET_ADDR="0x0000000000000000000000000000000000000001"

# 1KB calldata (1024 bytes = 2048 hex chars)
CALLDATA="0x$(python3 -c "print(\"ab\" * 1024)")"

# Accounts 10-19 private keys (hardhat mnemonic indices 10-19)
KEYS=(
  "0xf214f2b2cd398c806f84e317254e0f0b801d0643303237d97a22a48e01628897"
  "0x701b615bbdfb9de65240bc28bd21bbc0d996645a3dd57e7b12bc2bdf6f192c82"
  "0xa267530f49f8280200edf313ee7af6b827f2a8bce2897751d06a843f644967b1"
  "0x47c99abed3324a2707c28affff1267e45918ec8c3f20b8aa892e8b065d2942dd"
  "0xc526ee95bf44d8fc405a158bb884d9d1238d99f0612e9f33d006bb0789009aaa"
  "0x8166f546bab6da521a8369cab06c5d2b9e46670292d85c875ee9ec20e84ffb61"
  "0xea6c44ac03bff858b476bba40716402b03e41b8e97e276d1baec7c37d42484a0"
  "0x689af8efa8c651a91ad287602527f3af2fe9f6501a7ac4b061667b5a93e037fd"
  "0xde9be858da4a475276426320d5e9262ecfc3ba460bfac56360bfa6c4c28b4ee0"
  "0xdf57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e"
)

NUM_KEYS=${#KEYS[@]}
echo "=== Tempo Geo-Devnet Flood ==="
echo "Duration: ${DURATION}s | Senders: ${NUM_KEYS} | RPC: ${RPC}"
echo "Calldata size: 1024 bytes per tx"

# Get initial nonces for each sender
declare -a NONCES
declare -a ADDRS
for i in "${!KEYS[@]}"; do
  ADDR=$($CAST wallet address --private-key "${KEYS[$i]}" 2>/dev/null)
  ADDRS[$i]="$ADDR"
  NONCE=$($CAST nonce "$ADDR" --rpc-url "$RPC" 2>/dev/null)
  NONCES[$i]=$NONCE
  echo "Sender $i: $ADDR nonce=$NONCE"
done

echo ""
echo "Starting flood at $(date -u +%Y-%m-%dT%H:%M:%SZ)..."

END_TIME=$((SECONDS + DURATION))
TOTAL_SENT=0
TOTAL_ERRORS=0

# Each sender fires txs in its own background loop
sender_loop() {
  local idx=$1
  local key="${KEYS[$idx]}"
  local nonce=${NONCES[$idx]}
  local sent=0
  local errors=0

  while [ $SECONDS -lt $END_TIME ]; do
    # Fire a batch of 5 txs async, then brief pause
    for _ in $(seq 1 5); do
      if [ $SECONDS -ge $END_TIME ]; then break; fi
      $CAST send \
        --private-key "$key" \
        --rpc-url "$RPC" \
        --chain-id "$CHAIN_ID" \
        --nonce "$nonce" \
        --async \
        "$TARGET_ADDR" \
        "$CALLDATA" \
        > /dev/null 2>&1 && {
          sent=$((sent + 1))
          nonce=$((nonce + 1))
        } || {
          errors=$((errors + 1))
          # Re-fetch nonce on error
          nonce=$($CAST nonce "${ADDRS[$idx]}" --rpc-url "$RPC" 2>/dev/null || echo "$nonce")
        }
    done
    # Small delay to pace ~10 tx/s per sender = ~100 tx/s total
    sleep 0.4
  done
  echo "Sender $idx: sent=$sent errors=$errors final_nonce=$nonce"
}

# Launch all sender loops in parallel
for i in "${!KEYS[@]}"; do
  sender_loop "$i" &
done

echo "Flood running... waiting ${DURATION}s"
wait

echo ""
echo "=== Flood complete at $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
