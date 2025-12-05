# Tempo Specs

This directory contains Solidity specifications and fuzz tests for Tempo's precompile contracts. The tests are designed to run against both:

1. **Solidity reference implementations** - Using standard Foundry
2. **Rust precompile implementations** - Using tempo-foundry's custom forge

## How Tests Work

The tests use an `isTempo` flag (defined in `BaseTest.t.sol`) to detect which implementation is being tested:

- **`isTempo = false`**: Tests run against Solidity implementations deployed via `deployCodeTo()`. This is the default when using standard `forge`.
- **`isTempo = true`**: Tests run against Rust precompiles built into tempo-foundry's EVM. The flag is automatically true when native precompile code exists at addresses like `0x20Fc...` (TIP20Factory).

This allows the same test suite to verify both implementations are in sync.

This means running tests with normal foundry, will run them against the solidity implementation.
Using tempo-foundry, will run tests against the rust precompiles.

## Running Tests

**Prerequisite:** Clone the `tempo-foundry` github repo, and update the tempo deps to your branch before running the tests.

### Option 1: Solidity Only (Standard Foundry)

Run tests against the Solidity reference implementations:

```bash
cd docs/specs
forge test
```

With verbose output:

```bash
forge test -vvv
```

Run a specific test:

```bash
forge test --match-test test_mint
```

### Option 2: Rust Precompiles (tempo-foundry)

Run tests against the actual Rust precompile implementations:

```bash
cd docs/specs
./tempo-forge test
```

With verbose output:

```bash
./tempo-forge test -vvv
```

Run a specific test:

```bash
./tempo-forge test --match-test test_mint
```

## Setting Up tempo-foundry

The `tempo-forge` and `tempo-cast` scripts require the [tempo-foundry](https://github.com/tempoxyz/tempo-foundry) repository.

### Option 1: Clone as Sibling Directory (Recommended)

Clone tempo-foundry as a sibling to the tempo repository:

```
Tempo/
├── tempo/              # This repository
└── tempo-foundry/      # tempo-foundry repository
```

```bash
cd ..  # From tempo repo root
git clone git@github.com:tempoxyz/tempo-foundry.git
```

### Option 2: Set Environment Variable

If tempo-foundry is in a different location, set the `TEMPO_FOUNDRY_PATH` environment variable:

```bash
export TEMPO_FOUNDRY_PATH=/path/to/tempo-foundry
./tempo-forge test
```

### Building tempo-foundry

The scripts will automatically build the forge/cast binaries on first run. To build manually:

```bash
cd /path/to/tempo-foundry
cargo build -p forge --profile dev
cargo build -p cast --profile dev
```

If you encounter build errors, try cleaning and rebuilding:

```bash
cargo clean
cargo build -p forge --profile dev
```

## tempo-cast

The `tempo-cast` script runs cast commands using tempo-foundry's custom cast binary:

```bash
# Get function signature
./tempo-cast sig "transfer(address,uint256)"

# Decode function selector
./tempo-cast 4byte 0xa9059cbb

# ABI encode
./tempo-cast abi-encode "transfer(address,uint256)" 0x1234...5678 1000000
```

## CI Integration

The CI runs both test modes:

1. `forge test` - Validates Solidity implementations
2. `tempo-forge test` - Validates Rust precompiles match Solidity specs

This ensures the Rust and Solidity implementations stay in sync.

