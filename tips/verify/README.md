# Tempo Specs

This directory contains Solidity spec verification tests and fuzz harnesses for Tempo's native precompile contracts.

`TempoTest.t.sol` assumes the Tempo precompiles already exist in the EVM and fails fast if they are missing.

## Profiles

The checked-in `foundry.toml` uses two profiles, which always run against a Tempo-native EVM with enabled Rust precompiles:

- `default`: config for standard Foundry build/fmt/ABI tasks. Lighter optimizer and fuzz/invariant settings, for quicker output.
- `fuzz500`: config for extended invariant runs.

## Running Tests

Tests require a Tempo-capable `forge` binary.

Run the full suite:

```bash
cd tips/verify
forge test
```

Run with verbose output:

```bash
forge test -vvv
```

Run a specific test:

```bash
forge test --match-test test_mint
```

Use the lighter CI profile when you want to match CI settings locally:

```bash
cd tips/verify
FOUNDRY_PROFILE=fuzz500 forge test -vvv
```

If you frequently want the extended invariant profile by default, set it in your shell:

```bash
export FOUNDRY_PROFILE=fuzz500
forge test
```
