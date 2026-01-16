# storage-stats

CLI tool to analyze storage consumption by address in the Tempo database.

Generates analysis similar to Paradigm's ["Distribution of Ethereum State"](https://www.paradigm.xyz/2024/03/how-to-raise-the-gas-limit-1) visualization.

## Features

- **Iterates over PlainAccountState and PlainStorageState** tables using reth's MDBX database
- **Calculates top consumers by size in MB**
- **Recognizes known contract patterns**:
  - TIP-20 tokens (with symbol resolution from storage)
  - pathUSD, TIP-20 Factory
  - Fee Manager, Stablecoin DEX
  - TIP-403 Registry, Nonce Precompile (2D nonces)
  - Validator Config, Account Keychain
  - Standard utilities (Multicall3, CreateX, Permit2)
- **Parallel symbol resolution** using rayon
- **Multiple output formats**: text, CSV, JSON, treemap

## Installation

```bash
cargo build -p tempo-storage-stats --release
```

## Usage

### Basic Analysis

```bash
# Show top 50 storage consumers
./target/release/storage-stats --db /path/to/tempo/db

# Show top 100 with type breakdown
./target/release/storage-stats --db /path/to/tempo/db -n 100 --group-by-type

# Filter by minimum size
./target/release/storage-stats --db /path/to/tempo/db --min-mb 1.0
```

### Export Formats

```bash
# JSON for further processing
./target/release/storage-stats --db /path/to/tempo/db --format json > state.json

# CSV for spreadsheets
./target/release/storage-stats --db /path/to/tempo/db --format csv > stats.csv

# Treemap JSON with ASCII visualization
./target/release/storage-stats --db /path/to/tempo/db --format treemap
```

### Interactive Treemap Visualization

Generate an interactive HTML treemap (requires Python + plotly):

```bash
# Install Python dependencies
pip install -r scripts/requirements.txt

# Generate JSON and create treemap
./target/release/storage-stats --db /path/to/tempo/db --format json > state.json
python scripts/treemap.py state.json --output state_treemap.html --show

# Or pipe directly
./target/release/storage-stats --db /path/to/tempo/db --format json | \
    python scripts/treemap.py - --output state.html
```

### Parallel Processing

```bash
# Use 16 workers for symbol resolution
./target/release/storage-stats --db /path/to/tempo/db --workers 16
```

## Output Example

### Text Format (default)

```
=== Top 50 Storage Consumers ===

Rank Address                                      Label              Total (MB)      Storage      Slots
--------------------------------------------------------------------------------------------------------
   1 0x20c0000000000000000000000000000000000000   pathUSD                45.320       45.280     710234
   2 0x20c0000000000000000000000000000000000001   USDC                   38.210       38.150     598123
   3 0xdec0000000000000000000000000000000000000   Stablecoin DEX         25.100       25.050     392847
   ...
```

### Treemap Format

```
=== Distribution of Tempo State (245.50 MB total) ===

Tokens                      150.25 MB ( 61.2%) ████████████████████████████████
  └─ pathUSD                 45.32 MB ( 18.5%)
  └─ USDC                    38.21 MB ( 15.6%)
  └─ USDT                    25.10 MB ( 10.2%)
  ...

DEX                          42.30 MB ( 17.2%) █████████
  └─ Stablecoin DEX          42.30 MB ( 17.2%)

Account Abstraction          28.50 MB ( 11.6%) ██████
  └─ Nonce (2D)              28.50 MB ( 11.6%)
```

## Known Contract Categories

| Category | Contracts |
|----------|-----------|
| Tokens | TIP-20 tokens, pathUSD |
| Token Infrastructure | TIP-20 Factory |
| DEX | Stablecoin DEX |
| Fee Infrastructure | Fee Manager |
| Compliance | TIP-403 Registry |
| Account Abstraction | Nonce Precompile, Account Keychain |
| Consensus | Validator Config |
| Utilities | Multicall3, CreateX, Permit2 |

## Data Format

The JSON output contains an array of address statistics:

```json
[
  {
    "address": "0x20c0000000000000000000000000000000000000",
    "kind": "PathUsd",
    "label": "pathUSD",
    "category": "Tokens",
    "total_bytes": 47520358,
    "total_mb": 45.32,
    "storage_bytes": 47478912,
    "storage_mb": 45.28,
    "account_bytes": 41446,
    "storage_slots": 710234,
    "account_entries": 1
  }
]
```

## References

- [How to Raise the Gas Limit, Part 1: State Growth](https://www.paradigm.xyz/2024/03/how-to-raise-the-gas-limit-1)
- [paradigmxyz/how-to-raise-the-gas-limit](https://github.com/paradigmxyz/how-to-raise-the-gas-limit)
