# E2E CLI Test Suite

End-to-end tests for the Tempo CLI, designed to catch bugs like incorrect default URLs, missing flags, and RPC issues.

## Quick Start

```bash
# Build from current directory and run tests
./test-cli-e2e.sh --build-local

# Test a specific release via tempoup
./test-cli-e2e.sh --release v1.0.0

# Test a specific commit (builds from source)
./test-cli-e2e.sh --commit abc123def
```

## Tests Included

| Test | Description |
|------|-------------|
| `--version` | Verifies version flag works |
| `--help` | Verifies help output is useful |
| `consensus generate-private-key` | Tests key generation |
| `consensus calculate-public-key` | Tests public key derivation |
| `node --help` | Verifies node subcommand help |
| `default chain URLs` | Checks that default RPC URLs are correct |
| `--follow auto` | Verifies `--follow` uses correct default URL per chain |
| `invalid arguments` | Ensures invalid args produce helpful errors |
| `node dev mode` | Tests node starts in dev mode |
| `RPC methods` | Tests `eth_chainId`, `net_version`, `eth_syncing` |

## Options

```
--commit <SHA>     Test specific commit (builds from source)
--release <TAG>    Test specific release via tempoup
--build-local      Build and test current working directory (default)
--rpc-port <PORT>  RPC port for test node (default: 18545)
```

## Adding New Tests

Add a new test function following this pattern:

```bash
test_my_new_test() {
    local name="my new test"
    info "Testing: $name"
    
    # Your test logic here
    if [[ $condition ]]; then
        test_pass "$name"
    else
        test_fail "$name: reason"
    fi
}
```

Then add it to the test runner section at the bottom.

## Background

This test suite was created to catch bugs like:
- Default RPC URLs pointing to wrong networks
- Missing or broken CLI flags
- RPC endpoint issues after refactoring

## Known Bugs Tested

### PR #2042: TempoCli intercepting --help and --version

**Bug:** The `try_run_tempo_subcommand()` function was calling `TempoCli::try_parse()` before the main reth CLI parser. This caused `tempo --version` to fail and `tempo --help` to only show the limited `consensus` subcommand instead of the full CLI help.

**Symptom:**
- `tempo --version` fails or shows wrong output
- `tempo --help` only shows `consensus` subcommand, not `node`, `init`, `db`, etc.

**Fix:** Added a check to only parse with `TempoCli` if the first positional argument is a known subcommand (like `consensus`).

**Test coverage:**
- `test_version`: Verifies `--version` succeeds and shows version number
- `test_help`: Verifies `--help` shows the full CLI including `node` subcommand
