#!/bin/bash

# generate_genesis.sh - Generate genesis configuration for test network

set -e

NUM_NODES=${1:-3}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODES_DIR="$SCRIPT_DIR/../nodes"
GENESIS_FILE="$NODES_DIR/genesis.json"

# Start building genesis JSON
cat > "$GENESIS_FILE" <<EOF
{
  "genesis_time": "$(date -u +"%Y-%m-%dT%H:%M:%S.000000000Z")",
  "chain_id": "tempo-testnet",
  "initial_height": "1",
  "validators": [
EOF

# Add validators
for ((i=0; i<$NUM_NODES; i++)); do
    NODE_DIR="$NODES_DIR/node$i"
    
    # Read validator info from priv_validator_key.json
    if [ ! -f "$NODE_DIR/malachite/config/priv_validator_key.json" ]; then
        echo "Error: Missing priv_validator_key.json for node$i"
        exit 1
    fi
    
    # Extract values using jq or python
    if command -v jq &> /dev/null; then
        ADDRESS=$(jq -r '.address' "$NODE_DIR/malachite/config/priv_validator_key.json")
        PUB_KEY_TYPE=$(jq -r '.pub_key.type' "$NODE_DIR/malachite/config/priv_validator_key.json")
        PUB_KEY_VALUE=$(jq -r '.pub_key.value' "$NODE_DIR/malachite/config/priv_validator_key.json")
    else
        # Fallback to python if jq is not available
        ADDRESS=$(python3 -c "import json; print(json.load(open('$NODE_DIR/malachite/config/priv_validator_key.json'))['address'])")
        PUB_KEY_TYPE=$(python3 -c "import json; print(json.load(open('$NODE_DIR/malachite/config/priv_validator_key.json'))['pub_key']['type'])")
        PUB_KEY_VALUE=$(python3 -c "import json; print(json.load(open('$NODE_DIR/malachite/config/priv_validator_key.json'))['pub_key']['value'])")
    fi
    
    # Add comma for previous entry if not first
    if [ $i -gt 0 ]; then
        echo "," >> "$GENESIS_FILE"
    fi
    
    # Add validator entry
    cat >> "$GENESIS_FILE" <<EOF
    {
      "address": "$ADDRESS",
      "pub_key": {
        "type": "$PUB_KEY_TYPE",
        "value": "$PUB_KEY_VALUE"
      },
      "power": "1",
      "name": "node$i"
    }
EOF
done

# Close the JSON
cat >> "$GENESIS_FILE" <<EOF

  ],
  "app_state": {
    "accounts": [],
    "balances": []
  }
}
EOF

echo "Genesis file created at $GENESIS_FILE"