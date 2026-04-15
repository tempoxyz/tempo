# Tempo Specs

This directory contains Solidity specifications and fuzz tests for Tempo's precompile contracts. The tests are designed to run against both:

1. **Solidity reference implementations** - Using standard Foundry
2. **Rust precompile implementations** - Using Foundry with the Tempo profile

## How Tests Work

The tests use an `isTempo` flag (defined in `BaseTest.t.sol`) to detect which implementation is being tested:

- **`isTempo = false`**: Tests run against Solidity implementations deployed via `deployCodeTo()`. This is the default `forge` path.
- **`isTempo = true`**: Tests run against Rust precompiles built into upstream Foundry's Tempo EVM. This is the Tempo profile path.

This allows the same test suite to verify both implementations are in sync.

The checked-in `foundry.toml` keeps these two modes separate with profiles:

- `default`: Solidity reference implementations (`isTempo = false`)
- `tempo`: Native Rust precompiles (`isTempo = true`)

## Running Tests

**Prerequisite:** Use an upstream Foundry nightly build.

```bash
foundryup -i nightly
```

### Option 1: Solidity-Only Reference Implementations (Standard Foundry)

Run tests against the Solidity reference implementations:

```bash
cd tips/ref-impls
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

This path is what CI uses for the Solidity-only `forge test` job.

### Option 2: Rust Precompiles (Tempo Profile)

Run tests against the actual Rust precompile implementations:

```bash
cd tips/ref-impls
FOUNDRY_PROFILE=tempo forge test
```

Equivalent wrapper command:

```bash
./tempo-forge test
```

With verbose output:

```bash
FOUNDRY_PROFILE=tempo forge test -vvv
```

Equivalent wrapper command:

```bash
./tempo-forge test -vvv
```

Run a specific test:

```bash
FOUNDRY_PROFILE=tempo forge test --match-test test_mint
```

Equivalent wrapper command:

```bash
./tempo-forge test --match-test test_mint
```

Foundry selects profiles via `FOUNDRY_PROFILE`, so if you run Tempo-mode commands frequently you can also set it in your shell:

```bash
export FOUNDRY_PROFILE=tempo
forge test
```

## CI Integration

The CI runs both test modes:

1. `forge test` - Validates Solidity implementations
2. `FOUNDRY_PROFILE=tempo forge test` - Validates Rust precompiles match Solidity specs

This ensures the Rust and Solidity implementations stay in sync.
