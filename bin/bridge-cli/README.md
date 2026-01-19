# bridge-cli

CLI for Tempo stablecoin bridge operations.

## Installation

```bash
cargo build --release -p bridge-cli
```

The binary will be available at `target/release/bridge`.

## Configuration

Most commands accept a `--config` flag pointing to a bridge configuration file (JSON format). If not provided, a default test configuration is used.

Key configuration fields:
- `tempo_rpc_url` - Tempo chain RPC endpoint
- `tempo_secondary_rpc_url` - Secondary RPC for quorum verification
- `chains` - Map of origin chains with their RPC URLs and contract addresses
- `validator_key_path` - Path to private key file for signing transactions

## Commands

### status

Show bridge status including pending deposits/burns count and last processed blocks.

```bash
# Basic status
bridge status

# With custom config and state file
bridge status --config bridge-config.json --state /path/to/bridge-state.json

# Override Tempo RPC
bridge status --tempo-rpc http://localhost:8551
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `-c, --config` | Path to bridge config file | test config |
| `-s, --state` | Path to bridge state file | `bridge-state.json` |
| `--tempo-rpc` | Tempo RPC URL (overrides config) | from config or `http://localhost:8551` |

### deposits

List pending deposits awaiting finalization.

```bash
# Show pending deposits in table format
bridge deposits

# Output as JSON
bridge deposits --format json

# Custom state file
bridge deposits --state /path/to/bridge-state.json
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `-s, --state` | Path to bridge state file | `bridge-state.json` |
| `--pending` | Show only pending (non-finalized) deposits | `true` |
| `-f, --format` | Output format (`table`, `json`) | `table` |

### burns

List processed burns and their unlock status.

```bash
# Show burns in table format
bridge burns

# Output as JSON
bridge burns --format json

# Show only pending burns awaiting unlock
bridge burns --pending
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `-s, --state` | Path to bridge state file | `bridge-state.json` |
| `--pending` | Show only burns without unlock tx | `false` |
| `-f, --format` | Output format (`table`, `json`) | `table` |

### retry

Force retry a stuck deposit or burn transaction.

```bash
# Retry a deposit (dry run)
bridge retry 0x1234...abcd --dry-run

# Retry a deposit with signing
bridge retry 0x1234...abcd --key-path /path/to/key.txt

# Retry a burn
bridge retry 0x1234...abcd --type burn --config bridge-config.json
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `<ID>` | Request ID or burn ID to retry (required) | - |
| `-c, --config` | Path to bridge config file | test config |
| `--tempo-rpc` | Tempo RPC URL (overrides config) | from config |
| `--key-path` | Path to private key file for signing | from config |
| `--type` | Retry type: `deposit` or `burn` | `deposit` |
| `--dry-run` | Don't submit transaction | `false` |

### unlock

Manually unlock funds on the origin chain with a proof.

```bash
# Dry run unlock
bridge unlock 0xabc...123 --proof proof.json --chain ethereum --dry-run

# Execute unlock
bridge unlock 0xabc...123 --proof proof.json --chain ethereum --key-path /path/to/key.txt

# Override recipient and amount
bridge unlock 0xabc...123 --proof proof.json --chain ethereum \
  --recipient 0x742d35cc... --amount 1000000
```

**Proof file format (JSON):**
```json
{
  "recipient": "0x742d35cc...",
  "amount": 1000000,
  "proof": "0x...",
  "origin_block_number": 12345678
}
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `<BURN_ID>` | Burn ID to unlock (required) | - |
| `--proof` | Path to proof file in JSON format (required) | - |
| `--chain` | Origin chain name matching config (required) | - |
| `-c, --config` | Path to bridge config file | test config |
| `--key-path` | Path to private key file for signing | from config |
| `--recipient` | Override recipient address | from proof |
| `--amount` | Override amount (in token base units) | from proof |
| `--dry-run` | Don't submit transaction | `false` |

### health

Check RPC connectivity and quorum health across all configured chains.

```bash
# Table output
bridge health

# JSON output for monitoring
bridge health --format json

# With custom config
bridge health --config bridge-config.json
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `-c, --config` | Path to bridge config file | test config |
| `-f, --format` | Output format (`table`, `json`) | `table` |

**Output includes:**
- RPC endpoint status (healthy/failed)
- Current block numbers
- Latency measurements
- Quorum verification (primary vs secondary RPC block agreement)
- Overall health status

## Environment Variables

- `RUST_LOG` - Configure logging level (e.g., `RUST_LOG=debug`)

## Examples

### Monitor bridge health in CI/scripts

```bash
# Exit with error if unhealthy
bridge health --format json | jq -e '.overall_healthy'
```

### Check for stuck deposits

```bash
bridge deposits --format json | jq '.[] | select(.status == "pending")'
```

### Retry all stuck deposits

```bash
for id in $(bridge deposits --format json | jq -r '.[]'); do
  bridge retry "$id" --config bridge-config.json
done
```
