# execution-tests

Differential testing framework for the Tempo execution layer.

Executes test vectors against the EVM, validates transaction outcomes, and generates fingerprints for regression detection. Supports all transaction types (legacy, EIP-1559, Tempo AA), arbitrary prestate setup, and post-execution assertions.

## Quick Start

```bash
# Run all vectors
cargo run -p tempo-execution-tests -- run -d crates/tempo-execution-tests/vectors

# Run a single vector
cargo run -p tempo-execution-tests -- run -f crates/tempo-execution-tests/vectors/tip20_factory/create_token.json

# List available vectors
cargo run -p tempo-execution-tests -- list -d crates/tempo-execution-tests/vectors
```

## Commands

### `run` (alias: `r`)

Execute test vectors and validate outcomes.

```bash
tempo-execution-tests run -d <DIR>           # Run all vectors in directory
tempo-execution-tests run -f <FILE>          # Run a single vector
tempo-execution-tests run -d <DIR> -o out.json  # Save fingerprints to file
```

**Verbosity levels:**

| Flag | Output |
|------|--------|
| (none) | `✓ T1::create_token` per test |
| `-v` | JSON output for failed tests |
| `-vv` | JSON output for all tests |

### `diff` (alias: `d`)

Compare current implementation against a baseline binary to detect regressions.

```bash
# Build baseline from main branch
git stash && cargo build -p tempo-execution-tests --release && git stash pop
cp target/release/tempo-execution-tests /tmp/baseline

# Run diff
tempo-execution-tests diff --baseline-binary /tmp/baseline -d vectors
```

Only vectors with `check_regression: true` are compared against the baseline.

### `compare` (alias: `c`)

Compare two fingerprint files.

```bash
tempo-execution-tests compare baseline.json current.json --strict
```

### `list` (alias: `l`)

List available test vectors.

```bash
tempo-execution-tests list -d vectors
```

## Test Vectors

Vectors are JSON files that define:
- **prestate**: Initial accounts, storage, and precompile state
- **block**: Block context (number, timestamp, basefee, gas_limit)
- **transactions**: Transactions to execute with expected outcomes
- **checks**: Post-execution assertions

### Inheritance

Vectors can extend other vectors using `extends`:

```json
{
  "extends": "setup.json",
  "description": "Test that builds on setup",
  "transactions": [...]
}
```

### Directory Structure

```
vectors/
└── tip20_factory/
    ├── setup.json                           # Base template
    ├── create_token.json                    # Success case
    ├── create_token_fails_already_exists.json
    └── create_token_fails_invalid_quote.json
```

**Naming convention:**
- `<function>.json` — success case
- `<function>_fails_<reason>.json` — failure case

### Example Vector

```json
{
  "extends": "setup.json",
  "description": "Create a TIP20 token via factory",
  "check_regression": true,
  "transactions": [
    {
      "tx_type": "tempo",
      "from": "0x1111111111111111111111111111111111111111",
      "gas_limit": 1000000,
      "max_fee_per_gas": "100",
      "calls": [
        {
          "to": "0x20FC000000000000000000000000000000000000",
          "input": "0x68130445..."
        }
      ],
      "outcome": { "success": true }
    }
  ],
  "checks": {
    "precompiles": [
      {
        "name": "TIP20Token",
        "address": "0x20C0000000000000000000008eec1c9afb183a84",
        "fields": ["name", "symbol", "total_supply"]
      }
    ]
  }
}
```

### Transaction Types

- `legacy` (type 0)
- `eip1559` (type 2, default)
- `tempo` or `aa` (type 118) — Tempo AA transactions with `calls` array

### Outcome Assertions

```json
{ "success": true }

{ "success": false, "error": "TokenAlreadyExists(address)" }

{ "success": false, "revert_contains": "insufficient balance" }

{ "success": false, "error": "0xabcdef12" }
```

### Hardfork-Specific Outcomes

When behavior differs across hardforks:

```json
{
  "outcomes": [
    { "hardforks": ["Genesis", "T0"], "outcome": { "success": true } },
    { "hardforks": ["T1"], "outcome": { "success": false, "error": "NewError()" } }
  ]
}
```

## Fingerprints

Each test produces a fingerprint — a hash of execution results including:
- Transaction success/failure
- Gas used
- Return data
- Emitted logs
- Post-state changes

Fingerprints enable differential testing: if the hash changes between versions, behavior changed.

## CI Integration

```yaml
- name: Run execution tests
  run: cargo run -p tempo-execution-tests -- run -d crates/tempo-execution-tests/vectors

- name: Regression check
  run: |
    cargo build -p tempo-execution-tests --release
    cp target/release/tempo-execution-tests /tmp/current
    git checkout main
    cargo build -p tempo-execution-tests --release
    /tmp/current diff --baseline-binary target/release/tempo-execution-tests -d crates/tempo-execution-tests/vectors
```
