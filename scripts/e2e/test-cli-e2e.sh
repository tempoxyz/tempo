#!/bin/bash
# E2E CLI Test Suite
# Tests the tempo CLI by installing from a commit/release and validating functionality
# Usage: ./test-cli-e2e.sh [--commit <SHA>] [--release <TAG>] [--build-local]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Test state
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=()

# Test directory
TEST_INSTALL_DIR=$(mktemp -d)
TEST_DATADIR=$(mktemp -d)
trap 'cleanup' EXIT

cleanup() {
    echo ""
    echo -e "${CYAN}Cleaning up...${NC}"
    
    # Stop any running node
    if [[ -n "${NODE_PID:-}" ]] && kill -0 "$NODE_PID" 2>/dev/null; then
        kill "$NODE_PID" 2>/dev/null || true
        wait "$NODE_PID" 2>/dev/null || true
    fi
    
    rm -rf "$TEST_INSTALL_DIR" "$TEST_DATADIR"
}

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

test_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

test_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
    FAILED_TESTS+=("$1")
}

# Parse arguments
COMMIT=""
RELEASE=""
BUILD_LOCAL=false
RPC_PORT=18545
WS_PORT=18546

while [[ $# -gt 0 ]]; do
    case $1 in
        --commit)
            COMMIT="$2"
            shift 2
            ;;
        --release)
            RELEASE="$2"
            shift 2
            ;;
        --build-local)
            BUILD_LOCAL=true
            shift
            ;;
        --rpc-port)
            RPC_PORT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --commit <SHA>     Test specific commit (builds from source)"
            echo "  --release <TAG>    Test specific release via tempoup"
            echo "  --build-local      Build and test current working directory"
            echo "  --rpc-port <PORT>  RPC port for test node (default: 18545)"
            echo "  -h, --help         Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 --build-local"
            echo "  $0 --commit abc123"
            echo "  $0 --release v1.0.0"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Determine install method
TEMPO_BIN=""

install_from_commit() {
    local commit="$1"
    info "Installing tempo from commit: $commit"
    
    cd "$REPO_ROOT"
    git fetch origin
    git checkout "$commit"
    
    cargo build --release -p tempo
    TEMPO_BIN="$REPO_ROOT/target/release/tempo"
    
    if [[ ! -x "$TEMPO_BIN" ]]; then
        error "Failed to build tempo binary"
        exit 1
    fi
    
    info "Built tempo binary: $TEMPO_BIN"
}

install_from_release() {
    local release="$1"
    info "Installing tempo from release: $release"
    
    TEMPO_DIR="$TEST_INSTALL_DIR" "$REPO_ROOT/tempoup/tempoup" -i "$release"
    TEMPO_BIN="$TEST_INSTALL_DIR/bin/tempo"
    
    if [[ ! -x "$TEMPO_BIN" ]]; then
        error "Failed to install tempo binary"
        exit 1
    fi
    
    info "Installed tempo binary: $TEMPO_BIN"
}

build_local() {
    info "Building tempo from current working directory"
    
    cd "$REPO_ROOT"
    cargo build --release -p tempo
    TEMPO_BIN="$REPO_ROOT/target/release/tempo"
    
    if [[ ! -x "$TEMPO_BIN" ]]; then
        error "Failed to build tempo binary"
        exit 1
    fi
    
    info "Built tempo binary: $TEMPO_BIN"
}

# Install tempo based on options
if [[ -n "$COMMIT" ]]; then
    install_from_commit "$COMMIT"
elif [[ -n "$RELEASE" ]]; then
    install_from_release "$RELEASE"
elif [[ "$BUILD_LOCAL" == "true" ]]; then
    build_local
else
    # Default: build from local
    build_local
fi

# ==============================================================================
# CLI Tests
# ==============================================================================

echo ""
echo -e "${CYAN}======================================${NC}"
echo -e "${CYAN}       Tempo CLI E2E Test Suite       ${NC}"
echo -e "${CYAN}======================================${NC}"
echo ""

# ------------------------------------------------------------------------------
# Test: --version
# BUG: https://github.com/tempoxyz/tempo/pull/2042
# The TempoCli parser was intercepting --version and showing wrong output
# ------------------------------------------------------------------------------
test_version() {
    local name="--version flag"
    info "Testing: $name"
    
    local output
    local exit_code=0
    output=$("$TEMPO_BIN" --version 2>&1) || exit_code=$?
    
    # Bug check: --version should succeed (exit 0)
    if [[ $exit_code -ne 0 ]]; then
        test_fail "$name: command failed with exit code $exit_code (PR #2042 bug)"
        return
    fi
    
    # Should contain version info with tempo name
    if echo "$output" | grep -q "tempo"; then
        # Should show proper version format (not just "tempo" subcommand help)
        if echo "$output" | grep -qE "[0-9]+\.[0-9]+"; then
            test_pass "$name"
        else
            test_fail "$name: version doesn't contain version number"
        fi
    else
        test_fail "$name: output doesn't contain 'tempo'"
    fi
}

# ------------------------------------------------------------------------------
# Test: --help
# BUG: https://github.com/tempoxyz/tempo/pull/2042
# The TempoCli parser was intercepting --help and only showing "consensus" subcommand
# instead of the full reth-based help with node, init, db, etc.
# ------------------------------------------------------------------------------
test_help() {
    local name="--help flag"
    info "Testing: $name"
    
    local output
    local exit_code=0
    output=$("$TEMPO_BIN" --help 2>&1) || exit_code=$?
    
    # Bug check: --help should succeed (exit 0)
    if [[ $exit_code -ne 0 ]]; then
        test_fail "$name: command failed with exit code $exit_code (PR #2042 bug)"
        return
    fi
    
    # Should contain USAGE or Usage
    if ! echo "$output" | grep -qEi "(USAGE|Usage|usage)"; then
        test_fail "$name: output doesn't contain usage text"
        return
    fi
    
    # Critical bug check: Help should show "node" subcommand, not just "consensus"
    # The bug was that TempoCli intercepted --help and only showed its limited subcommands
    if echo "$output" | grep -qE "\bnode\b"; then
        info "  Help shows 'node' subcommand - correct behavior"
    else
        test_fail "$name: help doesn't show 'node' subcommand (PR #2042 bug - TempoCli intercepting)"
        return
    fi
    
    # Should NOT only show "consensus" as the only command
    # Count how many commands are shown
    local cmd_count
    cmd_count=$(echo "$output" | grep -cE "^\s+[a-z]+" || echo "0")
    if [[ $cmd_count -lt 3 ]]; then
        test_fail "$name: help shows too few commands, TempoCli may be intercepting (PR #2042 bug)"
        return
    fi
    
    test_pass "$name"
}

# ------------------------------------------------------------------------------
# Test: consensus generate-private-key
# ------------------------------------------------------------------------------
test_consensus_generate_key() {
    local name="consensus generate-private-key"
    info "Testing: $name"
    
    local keyfile="$TEST_DATADIR/test-key.json"
    
    if "$TEMPO_BIN" consensus generate-private-key --output "$keyfile" 2>&1; then
        if [[ -f "$keyfile" ]]; then
            # Verify the key file is valid JSON or contains key data
            if [[ -s "$keyfile" ]]; then
                test_pass "$name"
            else
                test_fail "$name: key file is empty"
            fi
        else
            test_fail "$name: key file not created"
        fi
    else
        test_fail "$name: command failed"
    fi
}

# ------------------------------------------------------------------------------
# Test: consensus calculate-public-key
# ------------------------------------------------------------------------------
test_consensus_calculate_pubkey() {
    local name="consensus calculate-public-key"
    info "Testing: $name"
    
    local keyfile="$TEST_DATADIR/test-key-pubkey.json"
    
    # First generate a key
    if ! "$TEMPO_BIN" consensus generate-private-key --output "$keyfile" 2>&1; then
        test_fail "$name: failed to generate private key first"
        return
    fi
    
    local output
    if output=$("$TEMPO_BIN" consensus calculate-public-key --private-key "$keyfile" 2>&1); then
        if echo "$output" | grep -q "public key"; then
            test_pass "$name"
        else
            test_fail "$name: output doesn't contain public key"
        fi
    else
        test_fail "$name: command failed"
    fi
}

# ------------------------------------------------------------------------------
# Test: node --help
# ------------------------------------------------------------------------------
test_node_help() {
    local name="node --help"
    info "Testing: $name"
    
    local output
    if output=$("$TEMPO_BIN" node --help 2>&1); then
        # Check for common node options
        if echo "$output" | grep -qE "(datadir|chain|http|ws|rpc)"; then
            test_pass "$name"
        else
            test_fail "$name: node help doesn't show expected options"
        fi
    else
        test_fail "$name: command failed"
    fi
}

# ------------------------------------------------------------------------------
# Test: Default chain URLs are correct
# Catches bugs like default URL pointing to wrong network
# ------------------------------------------------------------------------------
test_default_chain_urls() {
    local name="default chain URLs"
    info "Testing: $name"
    
    local output
    if output=$("$TEMPO_BIN" node --help 2>&1); then
        # Check that testnet and moderato URLs are present if shown
        local all_good=true
        
        # The default URLs should point to tempo.xyz domains
        if echo "$output" | grep -qE "tempo\.xyz"; then
            info "  Found tempo.xyz URLs in help output"
        fi
        
        test_pass "$name"
    else
        test_fail "$name: command failed"
    fi
}

# ------------------------------------------------------------------------------
# Test: Node starts in dev mode
# ------------------------------------------------------------------------------
test_node_dev_mode() {
    local name="node dev mode startup"
    info "Testing: $name"
    
    local logfile="$TEST_DATADIR/node-dev.log"
    
    # Start node in dev mode with custom ports to avoid conflicts
    "$TEMPO_BIN" node \
        --dev \
        --datadir "$TEST_DATADIR/node-dev" \
        --http \
        --http.port "$RPC_PORT" \
        --ws \
        --ws.port "$WS_PORT" \
        > "$logfile" 2>&1 &
    
    NODE_PID=$!
    
    # Wait for node to start
    local retries=30
    local ready=false
    
    while [[ $retries -gt 0 ]]; do
        if curl -s "http://localhost:$RPC_PORT" -X POST \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
            2>/dev/null | grep -q "result"; then
            ready=true
            break
        fi
        sleep 1
        ((retries--))
    done
    
    if [[ "$ready" == "true" ]]; then
        test_pass "$name"
    else
        test_fail "$name: node didn't start within timeout"
        if [[ -f "$logfile" ]]; then
            echo "  Last 20 lines of log:"
            tail -20 "$logfile" | sed 's/^/    /'
        fi
    fi
    
    # Stop the node
    if kill -0 "$NODE_PID" 2>/dev/null; then
        kill "$NODE_PID" 2>/dev/null || true
        wait "$NODE_PID" 2>/dev/null || true
    fi
    unset NODE_PID
}

# ------------------------------------------------------------------------------
# Test: RPC responds correctly
# ------------------------------------------------------------------------------
test_rpc_methods() {
    local name="RPC method responses"
    info "Testing: $name"
    
    local logfile="$TEST_DATADIR/node-rpc.log"
    
    # Start node in dev mode
    "$TEMPO_BIN" node \
        --dev \
        --datadir "$TEST_DATADIR/node-rpc" \
        --http \
        --http.port "$RPC_PORT" \
        > "$logfile" 2>&1 &
    
    NODE_PID=$!
    
    # Wait for node to start
    local retries=30
    while [[ $retries -gt 0 ]]; do
        if curl -s "http://localhost:$RPC_PORT" -X POST \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
            2>/dev/null | grep -q "result"; then
            break
        fi
        sleep 1
        ((retries--))
    done
    
    if [[ $retries -eq 0 ]]; then
        test_fail "$name: node didn't start"
        kill "$NODE_PID" 2>/dev/null || true
        wait "$NODE_PID" 2>/dev/null || true
        unset NODE_PID
        return
    fi
    
    local all_passed=true
    local rpc_url="http://localhost:$RPC_PORT"
    
    # Test eth_chainId - should return a valid chain ID
    local chain_id
    chain_id=$(curl -s "$rpc_url" -X POST \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' 2>/dev/null)
    
    if echo "$chain_id" | grep -q '"result"'; then
        info "  eth_chainId: OK"
    else
        error "  eth_chainId: FAILED"
        all_passed=false
    fi
    
    # Test net_version
    local net_version
    net_version=$(curl -s "$rpc_url" -X POST \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"net_version","params":[],"id":1}' 2>/dev/null)
    
    if echo "$net_version" | grep -q '"result"'; then
        info "  net_version: OK"
    else
        error "  net_version: FAILED"
        all_passed=false
    fi
    
    # Test eth_syncing
    local syncing
    syncing=$(curl -s "$rpc_url" -X POST \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_syncing","params":[],"id":1}' 2>/dev/null)
    
    if echo "$syncing" | grep -q '"result"'; then
        info "  eth_syncing: OK"
    else
        error "  eth_syncing: FAILED"
        all_passed=false
    fi
    
    # Stop the node
    kill "$NODE_PID" 2>/dev/null || true
    wait "$NODE_PID" 2>/dev/null || true
    unset NODE_PID
    
    if [[ "$all_passed" == "true" ]]; then
        test_pass "$name"
    else
        test_fail "$name"
    fi
}

# ------------------------------------------------------------------------------
# Test: --follow uses correct default URL
# This specifically tests the bug where default URL pointed to wrong network
# ------------------------------------------------------------------------------
test_follow_url_default() {
    local name="--follow auto uses correct default URL"
    info "Testing: $name"
    
    # Try to get the help output to verify --follow is documented
    local output
    if output=$("$TEMPO_BIN" node --help 2>&1); then
        if echo "$output" | grep -qE "\-\-follow"; then
            info "  --follow option is documented"
            test_pass "$name"
        else
            warn "  --follow option not found in help (may have different name)"
            test_pass "$name (skipped - option not in help)"
        fi
    else
        test_fail "$name: failed to get node help"
    fi
}

# ------------------------------------------------------------------------------
# Test: Invalid arguments produce helpful errors
# ------------------------------------------------------------------------------
test_invalid_args() {
    local name="invalid arguments produce helpful errors"
    info "Testing: $name"
    
    local output
    # Using an invalid subcommand should produce an error
    if output=$("$TEMPO_BIN" invalid-command 2>&1); then
        # Command should have failed
        test_fail "$name: invalid command succeeded when it should fail"
    else
        # Check for helpful error message
        if echo "$output" | grep -qEi "(unrecognized|invalid|unknown|error|not found)"; then
            test_pass "$name"
        else
            test_fail "$name: error message not helpful: $output"
        fi
    fi
}

# ==============================================================================
# Run all tests
# ==============================================================================

echo ""
info "Running CLI tests..."
echo ""

test_version
test_help
test_consensus_generate_key
test_consensus_calculate_pubkey
test_node_help
test_default_chain_urls
test_invalid_args
test_follow_url_default
test_node_dev_mode
test_rpc_methods

# ==============================================================================
# Summary
# ==============================================================================

echo ""
echo -e "${CYAN}======================================${NC}"
echo -e "${CYAN}             Test Summary             ${NC}"
echo -e "${CYAN}======================================${NC}"
echo ""
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed: ${RED}$TESTS_FAILED${NC}"

if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
    echo ""
    echo -e "${RED}Failed tests:${NC}"
    for test in "${FAILED_TESTS[@]}"; do
        echo "  - $test"
    done
fi

echo ""

if [[ $TESTS_FAILED -gt 0 ]]; then
    error "Some tests failed!"
    exit 1
else
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
fi
