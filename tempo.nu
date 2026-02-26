#!/usr/bin/env nu

# Tempo local utilities

const BENCH_DIR = "contrib/bench"
const LOCALNET_DIR = "localnet"
const LOGS_DIR = "contrib/bench/logs"
const RUSTFLAGS = "-C target-cpu=native"
const DEFAULT_PROFILE = "profiling"
const DEFAULT_FEATURES = "jemalloc,asm-keccak"

# Preset weight configurations: [tip20, erc20, swap, order]
const PRESETS = {
    tip20: [1.0, 0.0, 0.0, 0.0],
    erc20: [0.0, 1.0, 0.0, 0.0],
    swap: [0.0, 0.0, 1.0, 0.0],
    order: [0.0, 0.0, 0.0, 1.0],
    "tempo-mix": [0.8, 0, 0.19, 0.01]
}

# ============================================================================
# Helper functions
# ============================================================================

# Convert consensus port to node index (e.g., 8000 -> 0, 8100 -> 1)
def port-to-node-index [port: int] {
    ($port - 8000) / 100 | into int
}

# Build log filter args based on --loud flag
def log-filter-args [loud: bool] {
    if $loud { [] } else { ["--log.stdout.filter" "warn"] }
}

# Wrap command with samply if enabled
def wrap-samply [cmd: list<string>, samply: bool, samply_args: list<string>] {
    if $samply {
        ["samply" "record" ...$samply_args "--" ...$cmd]
    } else {
        $cmd
    }
}

# Validate mode is either "dev" or "consensus"
def validate-mode [mode: string] {
    if $mode != "dev" and $mode != "consensus" {
        print $"Unknown mode: ($mode). Use 'dev' or 'consensus'."
        exit 1
    }
}

# Build tempo binary with cargo
def build-tempo [bins: list<string>, profile: string, features: string] {
    let bin_args = ($bins | each { |bin| ["--bin" $bin] } | flatten)
    let build_cmd = ["cargo" "build" "--profile" $profile "--features" $features] | append $bin_args
    print $"Building ($bins | str join ', '): `($build_cmd | str join ' ')`..."
    with-env { RUSTFLAGS: $RUSTFLAGS } {
        run-external ($build_cmd | first) ...($build_cmd | skip 1)
    }
}

# Find tempo process PIDs (excluding tempo-bench)
def find-tempo-pids [] {
    ps | where name =~ "tempo" | where name !~ "tempo-bench" | get pid
}

# ============================================================================
# Infra commands
# ============================================================================

# Start the observability stack (Grafana + Prometheus)
def "main infra up" [] {
    print "Starting observability stack..."
    docker compose -f $"($BENCH_DIR)/docker-compose.yml" up -d
    print "Grafana available at http://localhost:3000 (admin/admin)"
    print "Prometheus available at http://localhost:9090"
}

# Stop the observability stack
def "main infra down" [] {
    print "Stopping observability stack..."
    docker compose -f $"($BENCH_DIR)/docker-compose.yml" down
}

# ============================================================================
# Kill command
# ============================================================================

# Kill any running tempo processes and cleanup
def "main kill" [
    --prompt    # Prompt before killing (for interactive use)
] {
    let pids = (find-tempo-pids)
    let has_stale_ipc = ("/tmp/reth.ipc" | path exists)

    if ($pids | length) == 0 and not $has_stale_ipc {
        print "No tempo processes or stale IPC socket found."
        return
    }

    if ($pids | length) > 0 {
        print $"Found ($pids | length) running tempo process\(es\)."
    }
    if $has_stale_ipc {
        print "Found stale /tmp/reth.ipc socket."
    }

    let should_kill = if $prompt {
        let answer = (input "Clean up? [Y/n] " | str trim | str downcase)
        $answer == "" or $answer == "y" or $answer == "yes"
    } else {
        true
    }

    if not $should_kill {
        print "Aborting."
        exit 1
    }

    if ($pids | length) > 0 {
        print $"Sending SIGINT to ($pids | length) tempo processes..."
        for pid in $pids {
            kill -s 2 $pid
        }
    }

    # Remove stale IPC socket
    if $has_stale_ipc {
        rm /tmp/reth.ipc
        print "Removed /tmp/reth.ipc"
    }
    print "Done."
}

# ============================================================================
# Localnet command
# ============================================================================

# Run Tempo localnet
def "main localnet" [
    --mode: string = "dev"      # Mode: "dev" or "consensus"
    --nodes: int = 3            # Number of validators (consensus mode)
    --accounts: int = 1000      # Number of genesis accounts
    --genesis: string = ""      # Custom genesis file path (skips generation)
    --samply                    # Enable samply profiling (foreground node only)
    --samply-args: string = ""  # Additional samply arguments (space-separated)
    --reset                     # Wipe and regenerate localnet data
    --profile: string = $DEFAULT_PROFILE # Cargo build profile
    --features: string = $DEFAULT_FEATURES # Cargo features
    --loud                      # Show all node logs (WARN/ERROR shown by default)
    --node-args: string = ""    # Additional node arguments (space-separated)
    --skip-build                # Skip building (assumes binary is already built)
    --force                     # Kill dangling processes without prompting
] {
    validate-mode $mode

    # Check for dangling processes or stale IPC socket
    let pids = (find-tempo-pids)
    let has_stale_ipc = ("/tmp/reth.ipc" | path exists)
    if ($pids | length) > 0 or $has_stale_ipc {
        main kill --prompt=($force | not $in)
    }

    # Parse custom args
    let extra_args = if $node_args == "" { [] } else { $node_args | split row " " }
    let samply_args_list = if $samply_args == "" { [] } else { $samply_args | split row " " }

    # Build first (unless skipped)
    if not $skip_build {
        build-tempo ["tempo"] $profile $features
    }

    if $mode == "dev" {
        if $nodes != 3 {
            print "Error: --nodes is only valid with --mode consensus"
            exit 1
        }
        run-dev-node $accounts $genesis $samply $samply_args_list $reset $profile $loud $extra_args
    } else {
        run-consensus-nodes $nodes $accounts $genesis $samply $samply_args_list $reset $profile $loud $extra_args
    }
}

# ============================================================================
# Dev mode
# ============================================================================

def run-dev-node [accounts: int, genesis: string, samply: bool, samply_args: list<string>, reset: bool, profile: string, loud: bool, extra_args: list<string>] {
    let genesis_path = if $genesis != "" {
        $genesis
    } else {
        let default_genesis = $"($LOCALNET_DIR)/genesis.json"
        let needs_generation = $reset or (not ($default_genesis | path exists))

        if $needs_generation {
            if $reset {
                print "Resetting localnet data..."
            } else {
                print "Genesis not found, generating..."
            }
            rm -rf $LOCALNET_DIR
            mkdir $LOCALNET_DIR
            print $"Generating genesis with ($accounts) accounts..."
            cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $LOCALNET_DIR -a $accounts --no-dkg-in-genesis
        }
        $default_genesis
    }

    let tempo_bin = if $profile == "dev" {
        "./target/debug/tempo"
    } else {
        $"./target/($profile)/tempo"
    }
    let datadir = $"($LOCALNET_DIR)/reth"
    let log_dir = $"($LOCALNET_DIR)/logs"

    let args = (build-base-args $genesis_path $datadir $log_dir 8545 9001)
        | append (build-dev-args)
        | append (log-filter-args $loud)
        | append $extra_args

    let cmd = wrap-samply [$tempo_bin ...$args] $samply $samply_args
    print $"Running dev node: `($cmd | str join ' ')`..."
    run-external ($cmd | first) ...($cmd | skip 1)
}

# Build base node arguments shared between dev and consensus modes
def build-base-args [genesis_path: string, datadir: string, log_dir: string, http_port: int, reth_metrics_port: int] {
    [
        "node"
        "--chain" $genesis_path
        "--datadir" $datadir
        "--http"
        "--http.addr" "0.0.0.0"
        "--http.port" $"($http_port)"
        "--http.api" "all"
        "--metrics" $"0.0.0.0:($reth_metrics_port)"
        "--log.file.directory" $log_dir
        "--faucet.enabled"
        "--faucet.private-key" "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        "--faucet.amount" "1000000000000"
        "--faucet.address" "0x20c0000000000000000000000000000000000000"
        "--faucet.address" "0x20c0000000000000000000000000000000000001"
    ]
}

# Build dev mode specific arguments
def build-dev-args [] {
    [
        "--dev"
        "--dev.block-time" "1sec"
        "--builder.gaslimit" "3000000000"
        "--builder.max-tasks" "8"
        "--builder.deadline" "3"
    ]
}

# ============================================================================
# Consensus mode
# ============================================================================

def run-consensus-nodes [nodes: int, accounts: int, genesis: string, samply: bool, samply_args: list<string>, reset: bool, profile: string, loud: bool, extra_args: list<string>] {
    # Check if we need to generate localnet (only if no custom genesis provided)
    if $genesis == "" {
        let needs_generation = $reset or (not ($LOCALNET_DIR | path exists)) or (
            (ls $LOCALNET_DIR | where type == "dir" | get name | where { |d| ($d | path basename) =~ '^\d+\.\d+\.\d+\.\d+:\d+$' } | length) == 0
        )

        if $needs_generation {
            if $reset {
                print "Resetting localnet data..."
            } else {
                print "Localnet not found, generating..."
            }
            rm -rf $LOCALNET_DIR

            # Generate validator addresses (port 8000, 8100, 8200, ...)
            # Using 100-port gaps to avoid collisions with system services (e.g., Intuit on 8021)
            let validators = (0..<$nodes | each { |i| $"127.0.0.1:($i * 100 + 8000)" } | str join ",")

            print $"Generating localnet with ($accounts) accounts and ($nodes) validators..."
            cargo run -p tempo-xtask --profile $profile -- generate-localnet -o $LOCALNET_DIR --accounts $accounts --validators $validators --force | ignore
        }
    }

    # Parse the generated node configs
    let genesis_path = if $genesis != "" { $genesis } else { $"($LOCALNET_DIR)/genesis.json" }

    # Build trusted peers from enode.identity files
    let validator_dirs = (ls $LOCALNET_DIR | where type == "dir" | get name | where { |d| ($d | path basename) =~ '^\d+\.\d+\.\d+\.\d+:\d+$' })
    let trusted_peers = ($validator_dirs | each { |d|
        let addr = ($d | path basename)
        let port = ($addr | split row ":" | get 1 | into int)
        let identity = (open $"($d)/enode.identity" | str trim)
        $"enode://($identity)@127.0.0.1:($port + 1)"
    } | str join ",")

    print $"Found ($validator_dirs | length) validator configs"

    let tempo_bin = if $profile == "dev" {
        "./target/debug/tempo"
    } else {
        $"./target/($profile)/tempo"
    }

    # Start background nodes first (all except node 0)
    print $"Starting ($validator_dirs | length) nodes..."
    print $"Logs: ($LOGS_DIR)/"
    print "Press Ctrl+C to stop all nodes."

    let foreground_node = $validator_dirs | first
    let background_nodes = $validator_dirs | skip 1

    for node in $background_nodes {
        run-consensus-node $node $genesis_path $trusted_peers $tempo_bin $loud false [] $extra_args true
    }

    # Run node 0 in foreground (receives Ctrl+C directly)
    run-consensus-node $foreground_node $genesis_path $trusted_peers $tempo_bin $loud $samply $samply_args $extra_args false
}

# Run a single consensus node (foreground or background)
def run-consensus-node [
    node_dir: string
    genesis_path: string
    trusted_peers: string
    tempo_bin: string
    loud: bool
    samply: bool
    samply_args: list<string>
    extra_args: list<string>
    background: bool
] {
    let addr = ($node_dir | path basename)
    let port = ($addr | split row ":" | get 1 | into int)
    let node_index = (port-to-node-index $port)
    let http_port = 8545 + $node_index

    let log_dir = $"($LOGS_DIR)/($addr)"
    mkdir $log_dir

    let args = (build-consensus-node-args $node_dir $genesis_path $trusted_peers $port $log_dir)
        | append (log-filter-args $loud)
        | append $extra_args

    let cmd = wrap-samply [$tempo_bin ...$args] $samply $samply_args

    print $"  Node ($addr) -> http://localhost:($http_port)(if $background { '' } else { ' (foreground)' })"

    if $background {
        job spawn { sh -c $"($cmd | str join ' ') 2>&1" | lines | each { |line| print $"[($addr)] ($line)" } }
    } else {
        print $"  Running: ($cmd | str join ' ')"
        run-external ($cmd | first) ...($cmd | skip 1)
    }
}

# Build full node arguments for consensus mode
def build-consensus-node-args [node_dir: string, genesis_path: string, trusted_peers: string, port: int, log_dir: string] {
    let node_index = (port-to-node-index $port)
    let http_port = 8545 + $node_index
    let reth_metrics_port = 9001 + $node_index

    (build-base-args $genesis_path $node_dir $log_dir $http_port $reth_metrics_port)
        | append (build-consensus-args $node_dir $trusted_peers $port)
}

# Build consensus mode specific arguments
def build-consensus-args [node_dir: string, trusted_peers: string, port: int] {
    let signing_key = $"($node_dir)/signing.key"
    let signing_share = $"($node_dir)/signing.share"
    let enode_key = $"($node_dir)/enode.key"

    let execution_p2p_port = $port + 1
    let metrics_port = $port + 2
    let authrpc_port = $port + 3

    [
        "--consensus.signing-key" $signing_key
        "--consensus.signing-share" $signing_share
        "--consensus.listen-address" $"127.0.0.1:($port)"
        "--consensus.metrics-address" $"127.0.0.1:($metrics_port)"
        "--trusted-peers" $trusted_peers
        "--port" $"($execution_p2p_port)"
        "--discovery.port" $"($execution_p2p_port)"
        "--p2p-secret-key" $enode_key
        "--authrpc.port" $"($authrpc_port)"
        "--consensus.fee-recipient" "0x0000000000000000000000000000000000000000"
    ]
}

# ============================================================================
# Bench command
# ============================================================================

# Run a full benchmark: start infra, localnet, and tempo-bench
def "main bench" [
    --mode: string = "consensus"                    # Mode: "dev" or "consensus"
    --preset: string = ""                           # Preset: tip20, erc20, swap, order, tempo-mix
    --tps: int = 10000                              # Target TPS
    --duration: int = 30                            # Duration in seconds
    --accounts: int = 1000                          # Number of accounts
    --max-concurrent-requests: int = 100            # Max concurrent requests
    --nodes: int = 3                                # Number of consensus nodes (consensus mode only)
    --genesis: string = ""                          # Custom genesis file path (skips generation)
    --samply                                        # Profile nodes with samply
    --samply-args: string = ""                      # Additional samply arguments (space-separated)
    --reset                                         # Reset localnet before starting
    --loud                                          # Show node logs (silent by default)
    --profile: string = $DEFAULT_PROFILE            # Cargo build profile
    --features: string = $DEFAULT_FEATURES          # Cargo features
    --node-args: string = ""                        # Additional node arguments (space-separated)
    --bench-args: string = ""                       # Additional tempo-bench arguments (space-separated)
] {
    validate-mode $mode

    # Validate --nodes is only used with consensus mode
    if $mode == "dev" and $nodes != 3 {
        print "Error: --nodes is only valid with --mode consensus"
        exit 1
    }

    # Validate: either preset or bench-args must be provided
    if $preset == "" and $bench_args == "" {
        print "Error: either --preset or --bench-args must be provided"
        print $"  Available presets: ($PRESETS | columns | str join ', ')"
        exit 1
    }

    # Validate preset if provided
    if $preset != "" and not ($preset in $PRESETS) {
        print $"Unknown preset: ($preset). Available: ($PRESETS | columns | str join ', ')"
        exit 1
    }

    let weights = if $preset != "" { $PRESETS | get $preset } else { [0.0, 0.0, 0.0, 0.0] }

    # Start observability stack
    print "Starting observability stack..."
    docker compose -f $"($BENCH_DIR)/docker-compose.yml" up -d

    # Build both binaries first
    build-tempo ["tempo" "tempo-bench"] $profile $features

    # Start nodes in background (skip build since we already compiled)
    let num_nodes = if $mode == "dev" { 1 } else { $nodes }
    print $"Starting ($num_nodes) ($mode) node\(s\)..."

    # Ensure at least as many accounts as validators for genesis generation (+1 for admin account)
    let genesis_accounts = ([$accounts $num_nodes] | math max) + 1

    let node_cmd = [
        "nu" "tempo.nu" "localnet"
        "--mode" $mode
        "--accounts" $"($genesis_accounts)"
        "--skip-build"
        "--force"
        "--profile" $profile
        "--features" $features
    ]
    | append (if $mode == "consensus" { ["--nodes" $"($nodes)"] } else { [] })
    | append (if $genesis != "" { ["--genesis" $genesis] } else { [] })
    | append (if $reset { ["--reset"] } else { [] })
    | append (if $samply { ["--samply"] } else { [] })
    | append (if $samply_args != "" { [$"--samply-args=\"($samply_args)\""] } else { [] })
    | append (if $loud { ["--loud"] } else { [] })
    | append (if $node_args != "" { [$"--node-args=\"($node_args)\""] } else { [] })

    # Spawn nodes as a background job (pipe output to show logs)
    let node_cmd_str = ($node_cmd | str join " ")
    print $"  Command: ($node_cmd_str)"
    job spawn { nu -c $node_cmd_str o+e>| lines | each { |line| print $line } }

    # Wait for nodes to be ready
    sleep 2sec
    print "Waiting for nodes to be ready..."
    let rpc_urls = (0..<$num_nodes | each { |i| $"http://localhost:(8545 + $i)" })
    for url in $rpc_urls {
        wait-for-rpc $url
    }
    print "All nodes ready!"

    # Run tempo-bench
    let tempo_bench_bin = if $profile == "dev" {
        "./target/debug/tempo-bench"
    } else {
        $"./target/($profile)/tempo-bench"
    }
    let bench_cmd = [
        $tempo_bench_bin
        "run-max-tps"
        "--tps" $"($tps)"
        "--duration" $"($duration)"
        "--accounts" $"($accounts)"
        "--max-concurrent-requests" $"($max_concurrent_requests)"
        "--target-urls" ($rpc_urls | str join ",")
        "--faucet"
        "--clear-txpool"
    ]
    | append (if $preset != "" {
        [
            "--tip20-weight" $"($weights | get 0)"
            "--erc20-weight" $"($weights | get 1)"
            "--swap-weight" $"($weights | get 2)"
            "--place-order-weight" $"($weights | get 3)"
        ]
    } else { [] })
    | append (if $bench_args != "" { $bench_args | split row " " } else { [] })

    print $"Running benchmark: ($bench_cmd | str join ' ')"
    try {
        bash -c $"ulimit -Sn unlimited && ($bench_cmd | str join ' ')"
    } catch {
        print "Benchmark interrupted or failed."
    }

    # Cleanup
    print "Cleaning up..."
    main kill

    # Wait for samply to finish saving profiles
    if $samply {
        print "Waiting for samply to finish..."
        loop {
            let samply_running = (ps | where name =~ "samply" | length) > 0
            if not $samply_running {
                break
            }
            sleep 500ms
        }
        print "Samply profiles saved."
    }

    print "Done."
}

# Wait for an RPC endpoint to be ready and chain advancing
def wait-for-rpc [url: string, max_attempts: int = 120] {
    mut attempt = 0
    mut start_block: int = -1

    loop {
        $attempt = $attempt + 1
        if $attempt > $max_attempts {
            print $"  Timeout waiting for ($url)"
            exit 1
        }
        let result = (do { cast block-number --rpc-url $url } | complete)
        if $result.exit_code == 0 {
            let block = ($result.stdout | str trim | into int)
            if $start_block == -1 {
                $start_block = $block
                print $"  ($url) connected \(block ($block)\), waiting for chain to advance..."
            } else if $block > $start_block {
                print $"  ($url) ready \(block ($start_block) -> ($block)\)"
                break
            } else {
                if ($attempt mod 10) == 0 {
                    print $"  ($url) still at block ($block)... \(($attempt)s\)"
                }
            }
        } else {
            if ($attempt mod 10) == 0 {
                print $"  Still waiting for ($url)... \(($attempt)s\)"
            }
        }
        sleep 1sec
    }
}

# ============================================================================
# Coverage commands
# ============================================================================

const COV_DIR = "coverage"
const INVARIANT_DIR = "tips/ref-impls"

# Find tempo-foundry checkout (same search as tempo-forge script)
def find-tempo-foundry [] {
    let env_path = (if "TEMPO_FOUNDRY_PATH" in $env { $env.TEMPO_FOUNDRY_PATH } else { "" })
    if $env_path != "" and ($env_path | path exists) {
        return ($env_path | path expand)
    }
    let sibling = ("../tempo-foundry" | path expand)
    if ($sibling | path exists) and (($sibling | path join "Cargo.toml") | path exists) {
        return $sibling
    }
    let parent = ("../../tempo-foundry" | path expand)
    if ($parent | path exists) and (($parent | path join "Cargo.toml") | path exists) {
        return $parent
    }
    ""
}

# Get LLVM tools bin directory for the active Rust toolchain
def get-llvm-bin-dir [] {
    let sysroot = (rustc --print sysroot | str trim)
    let host = (rustc -vV | lines | where { |l| $l starts-with "host:" } | first | split row " " | get 1)
    $"($sysroot)/lib/rustlib/($host)/bin"
}

# Run coverage: collects from unit tests, integration tests, Solidity invariant
# fuzz tests (with merged Rust precompile coverage), and/or a live localnet.
#
# When --invariants is used, coverage from forge (which exercises Rust precompiles)
# is merged with cargo test coverage via llvm-profdata, matching CI behavior.
#
# Examples:
#   nu tempo.nu coverage --tests                           # unit + integration tests only
#   nu tempo.nu coverage --invariants                      # forge invariant fuzz (Rust precompile coverage)
#   nu tempo.nu coverage --tests --invariants              # merged: cargo tests + forge invariants
#   nu tempo.nu coverage --live --preset tip20             # live node + bench traffic only
#   nu tempo.nu coverage --tests --live --preset tip20     # all combined
#   nu tempo.nu coverage --live --script /path/to/test.sh  # live node + external script
def "main coverage" [
    --tests                                # Include unit + integration test coverage
    --invariants                           # Run Solidity invariant fuzz tests (builds instrumented forge)
    --invariant-profile: string = "ci"     # Foundry profile for invariants (ci, fuzz500, default)
    --invariant-contract: string = ""      # Run only a specific invariant contract (e.g. TempoTransactionInvariantTest)
    --live                                 # Include live node coverage (runs localnet + traffic)
    --preset: string = ""                  # Bench preset for live mode (tip20, erc20, swap, order, tempo-mix)
    --script: string = ""                  # External script to run against live node (instead of bench)
    --tps: int = 1000                      # Target TPS for live bench (ignored with --script)
    --duration: int = 10                   # Bench duration in seconds (ignored with --script)
    --accounts: int = 100                  # Number of accounts
    --format: string = "html"             # Report format: html, lcov, json, text
    --open                                 # Open HTML report in browser
    --reset                                # Wipe localnet data before live run
] {
    if not $tests and not $live and not $invariants {
        print "Error: specify at least one of --tests, --invariants, or --live"
        exit 1
    }

    if $invariants and $live {
        print "Error: --invariants and --live cannot be combined yet"
        print "  Run them separately and merge reports manually"
        exit 1
    }

    if $live and $script == "" and $preset == "" {
        print "Error: --live requires --preset or --script"
        print $"  Available presets: ($PRESETS | columns | str join ', ')"
        exit 1
    }

    if $live and $preset != "" and not ($preset in $PRESETS) {
        print $"Unknown preset: ($preset). Available: ($PRESETS | columns | str join ', ')"
        exit 1
    }

    if $script != "" and not ($script | path exists) {
        print $"Error: script not found: ($script)"
        exit 1
    }

    print "=== Tempo Coverage ==="
    mkdir $COV_DIR

    if $invariants {
        # =================================================================
        # Manual instrumentation path (merges forge + cargo profdata)
        # Matches CI: specs.yml → coverage.yml pipeline
        # =================================================================
        let foundry_dir = (find-tempo-foundry)
        if $foundry_dir == "" {
            print "Error: could not find tempo-foundry repository."
            print ""
            print "Either:"
            print "  1. Clone as sibling: git clone git@github.com:tempoxyz/tempo-foundry.git ../tempo-foundry"
            print "  2. Set TEMPO_FOUNDRY_PATH=/path/to/tempo-foundry"
            exit 1
        }
        print $"Using tempo-foundry at: ($foundry_dir)"

        let profraw_dir = ([$env.PWD $COV_DIR "profraw"] | path join)
        rm -rf $profraw_dir
        mkdir $profraw_dir

        # Step 1: Cargo tests with -C instrument-coverage (if --tests)
        if $tests {
            print ""
            print "--- Running unit + integration tests (instrumented) ---"
            with-env {
                RUSTFLAGS: "-C instrument-coverage"
                LLVM_PROFILE_FILE: $"($profraw_dir)/cargo-%p-%m.profraw"
                RUSTC_WRAPPER: ""
            } {
                cargo test --workspace --exclude tempo-e2e
            }
            print "Tests complete."
        }

        # Step 2: Build tempo-foundry forge with coverage instrumentation
        # Patch tempo-foundry to use local tempo checkout so source paths match
        # in the merged profdata. Uses .cargo/config.toml patch override.
        print ""
        print "--- Building tempo-foundry forge (instrumented) ---"
        print "This may take a while on first run..."
        let tempo_root = ($env.PWD | path expand)
        let foundry_cargo_dir = ($foundry_dir | path join ".cargo")
        let foundry_cargo_config = ($foundry_cargo_dir | path join "config.toml")
        let had_existing_config = ($foundry_cargo_config | path exists)
        let existing_config = (if $had_existing_config { open --raw $foundry_cargo_config } else { "" })
        let foundry_cargo_lock = ($foundry_dir | path join "Cargo.lock")
        let existing_lock = (if ($foundry_cargo_lock | path exists) { open --raw $foundry_cargo_lock } else { "" })

        # Append patch overrides pointing tempo deps at local checkout
        let patch_block = $"

# AUTO-GENERATED by tempo.nu coverage --invariants -- do not commit
[patch.'https://github.com/tempoxyz/tempo']
tempo-alloy = { path = '($tempo_root)/crates/alloy' }
tempo-contracts = { path = '($tempo_root)/crates/contracts' }
tempo-revm = { path = '($tempo_root)/crates/revm' }
tempo-evm = { path = '($tempo_root)/crates/evm' }
tempo-chainspec = { path = '($tempo_root)/crates/chainspec' }
tempo-primitives = { path = '($tempo_root)/crates/primitives' }
tempo-precompiles = { path = '($tempo_root)/crates/precompiles' }
"
        mkdir $foundry_cargo_dir
        $"($existing_config)($patch_block)" | save -f $foundry_cargo_config

        try {
            do {
                cd $foundry_dir
                # Update Cargo.lock to resolve patched crate versions
                cargo update
                with-env { RUSTFLAGS: "-C instrument-coverage", RUSTC_WRAPPER: "" } {
                    cargo build -p forge --profile release
                }
            }
        } catch { |e|
            # Restore original config and lock before propagating error
            if $had_existing_config {
                $existing_config | save -f $foundry_cargo_config
            } else {
                rm -f $foundry_cargo_config
            }
            if $existing_lock != "" {
                $existing_lock | save -f $foundry_cargo_lock
            }
            print $"Error building forge: ($e)"
            exit 1
        }

        # Restore original .cargo/config.toml and Cargo.lock
        if $had_existing_config {
            $existing_config | save -f $foundry_cargo_config
        } else {
            rm -f $foundry_cargo_config
        }
        if $existing_lock != "" {
            $existing_lock | save -f $foundry_cargo_lock
        }

        let forge_bin = $"($foundry_dir)/target/release/forge"
        print $"Forge binary: ($forge_bin)"

        # Step 3: Run invariant tests collecting profraw
        print ""
        print $"--- Running Solidity invariant fuzz tests \(profile: ($invariant_profile)\) ---"
        let forge_args = ["test" "--fail-fast" "--show-progress" "-vv"]
            | append (if $invariant_contract != "" { ["--match-contract" $invariant_contract] } else { [] })

        do {
            cd $"($env.PWD)/($INVARIANT_DIR)"
            with-env {
                LLVM_PROFILE_FILE: $"($profraw_dir)/forge-%p-%m.profraw"
                FOUNDRY_PROFILE: $invariant_profile
            } {
                run-external $forge_bin ...($forge_args)
            }
        }
        print "Invariant tests complete."

        # Step 4: Merge profraw → profdata and generate report
        print ""
        print "--- Merging coverage data ---"
        let llvm_bin = (get-llvm-bin-dir)

        let profraw_files = (glob $"($profraw_dir)/*.profraw")
        if ($profraw_files | length) == 0 {
            print "Error: no profraw files found"
            exit 1
        }
        print $"Found ($profraw_files | length) profraw files"

        let profdata_path = $"($COV_DIR)/merged.profdata"
        run-external $"($llvm_bin)/llvm-profdata" "merge" "-sparse" ...$profraw_files "-o" $profdata_path

        # Collect object files (instrumented binaries)
        mut objects: list<string> = [$forge_bin]
        if $tests {
            let test_bins = (bash -c "find target/debug/deps -type f -executable ! -name '*.d' ! -name '*.rmeta' 2>/dev/null" | lines | where { |l| $l != "" })
            $objects = ($objects | append $test_bins)
        }

        let object_flags = ($objects | each { |o| ["--object" $o] } | flatten)
        let ignore_flags = [
            "--ignore-filename-regex=/rustc/"
            "--ignore-filename-regex=\\.cargo/"
            "--ignore-filename-regex=\\.rustup/"
            "--ignore-filename-regex=tempo-foundry/"
            "--ignore-filename-regex=library/"
        ]

        print $"--- Generating ($format) coverage report ---"

        if $format == "html" or $format == "lcov" {
            let lcov_path = $"($COV_DIR)/coverage.lcov"
            run-external $"($llvm_bin)/llvm-cov" "export" "--format=lcov" $"--instr-profile=($profdata_path)" ...$object_flags ...$ignore_flags o> $lcov_path

            if $format == "html" {
                let html_dir = $"($COV_DIR)/html"
                genhtml $lcov_path --output-directory $html_dir --title "Tempo Precompiles Coverage" --legend
                print $"Report saved to ($html_dir)/index.html"
                if $open {
                    xdg-open $"($html_dir)/index.html"
                }
            } else {
                print $"LCOV report saved to ($lcov_path)"
            }
        } else if $format == "json" {
            let json_path = $"($COV_DIR)/coverage.json"
            run-external $"($llvm_bin)/llvm-cov" "export" $"--instr-profile=($profdata_path)" ...$object_flags ...$ignore_flags o> $json_path
            print $"JSON report saved to ($json_path)"
        } else {
            # text
            run-external $"($llvm_bin)/llvm-cov" "report" $"--instr-profile=($profdata_path)" ...$object_flags ...$ignore_flags
        }

    } else {
        # =================================================================
        # Existing cargo llvm-cov path (--tests and/or --live, no --invariants)
        # =================================================================
        print "Cleaning previous coverage data..."
        cargo llvm-cov clean --workspace

        # Step 1: Unit + integration tests
        if $tests {
            print ""
            print "--- Running unit + integration tests (instrumented) ---"
            cargo llvm-cov --no-report test --workspace
            print "Tests complete."
        }

        # Step 2: Live node coverage
        if $live {
            print ""
            print "--- Running live node coverage ---"

            # Generate genesis if needed
            let genesis_path = $"($LOCALNET_DIR)/genesis.json"
            let needs_genesis = $reset or (not ($genesis_path | path exists))
            if $needs_genesis {
                rm -rf $LOCALNET_DIR
                mkdir $LOCALNET_DIR
                print $"Generating genesis with ($accounts) accounts..."
                cargo run -p tempo-xtask -- generate-genesis --output $LOCALNET_DIR -a $accounts --no-dkg-in-genesis
            }

            # Build node args
            let datadir = $"($LOCALNET_DIR)/reth-cov"
            let log_dir = $"($LOCALNET_DIR)/logs-cov"
            rm -rf $datadir
            let args = (build-base-args $genesis_path $datadir $log_dir 8545 9001)
                | append (build-dev-args)
                | append ["--log.stdout.filter" "warn"]
                | append [
                    "--faucet.address" "0x20c0000000000000000000000000000000000002"
                    "--faucet.address" "0x20c0000000000000000000000000000000000003"
                ]

            # Build + run instrumented binary via cargo llvm-cov run (backgrounds itself)
            print "Building and starting instrumented tempo node..."
            let node_args_str = ($args | str join " ")
            job spawn {
                bash -c $"cargo llvm-cov run --no-report --bin tempo -- ($node_args_str)"
            }

            # Wait for node (generous timeout since cargo llvm-cov run compiles first)
            sleep 5sec
            print "Waiting for node to be ready (this includes compile time)..."
            wait-for-rpc "http://localhost:8545" 600
            print "Node ready!"

            # Run traffic against the node
            if $script != "" {
                print $"Running script: ($script)"
                try {
                    with-env { ETH_RPC_URL: "http://localhost:8545" } {
                        bash $script
                    }
                } catch {
                    print "Script finished (or failed)."
                }
            } else {
                print "Building tempo-bench..."
                cargo build --bin tempo-bench

                let weights = $PRESETS | get $preset
                let bench_bin = "./target/debug/tempo-bench"
                let bench_cmd = [
                    $bench_bin
                    "run-max-tps"
                    "--tps" $"($tps)"
                    "--duration" $"($duration)"
                    "--accounts" $"($accounts)"
                    "--target-urls" "http://localhost:8545"
                    "--faucet"
                    "--clear-txpool"
                    "--tip20-weight" $"($weights | get 0)"
                    "--erc20-weight" $"($weights | get 1)"
                    "--swap-weight" $"($weights | get 2)"
                    "--place-order-weight" $"($weights | get 3)"
                ]

                print $"Running bench: ($bench_cmd | str join ' ')"
                try {
                    run-external ($bench_cmd | first) ...($bench_cmd | skip 1)
                } catch {
                    print "Bench finished (or interrupted)."
                }
            }

            # Graceful shutdown (SIGINT so profraw gets written)
            print "Stopping instrumented node (SIGINT for profraw flush)..."
            let pids = (find-tempo-pids)
            for pid in $pids {
                kill -s 2 $pid
            }
            sleep 3sec
            print "Node stopped."
        }

        # Generate report
        print ""
        print $"--- Generating ($format) coverage report ---"
        let output_flag = if $format == "html" {
            ["--html" "--output-dir" $COV_DIR]
        } else if $format == "lcov" {
            ["--lcov" "--output-path" $"($COV_DIR)/lcov.info"]
        } else if $format == "json" {
            ["--json" "--output-path" $"($COV_DIR)/coverage.json"]
        } else {
            ["--text"]
        }

        let report_cmd = ["cargo" "llvm-cov" "report"] | append $output_flag
        run-external ($report_cmd | first) ...($report_cmd | skip 1)

        if $format == "html" {
            print $"Report saved to ($COV_DIR)/index.html"
            if $open {
                xdg-open $"($COV_DIR)/index.html"
            }
        } else if $format == "lcov" {
            print $"LCOV report saved to ($COV_DIR)/lcov.info"
        } else if $format == "json" {
            print $"JSON report saved to ($COV_DIR)/coverage.json"
        }
    }

    print ""
    print "=== Coverage complete ==="
}

# ============================================================================
# Help
# ============================================================================

# Show help
def main [] {
    print "Tempo local utilities"
    print ""
    print "Usage:"
    print "  nu tempo.nu bench [flags]            Run full benchmark (infra + localnet + bench)"
    print "  nu tempo.nu localnet [flags]         Run Tempo localnet"
    print "  nu tempo.nu coverage [flags]         Run coverage (tests, live node, or both)"
    print "  nu tempo.nu infra up                 Start Grafana + Prometheus"
    print "  nu tempo.nu infra down               Stop the observability stack"
    print "  nu tempo.nu kill                     Kill any running tempo processes"
    print ""
    print "Bench flags (either --preset or --bench-args required):"
    print "  --mode <M>               Mode: dev or consensus (default: consensus)"
    print "  --preset <P>             Preset: tip20, erc20, swap, order, tempo-mix"
    print "  --tps <N>                Target TPS (default: 10000)"
    print "  --duration <N>           Duration in seconds (default: 30)"
    print "  --accounts <N>           Number of accounts (default: 1000)"
    print "  --max-concurrent-requests <N>  Max concurrent requests (default: 100)"
    print "  --nodes <N>              Number of consensus nodes (default: 3, consensus mode only)"
    print "  --samply                 Profile nodes with samply"
    print "  --samply-args <ARGS>     Additional samply arguments (space-separated)"
    print "  --reset                  Reset localnet before starting"
    print "  --loud                   Show all node logs (WARN/ERROR shown by default)"
    print $"  --profile <P>            Cargo profile \(default: ($DEFAULT_PROFILE)\)"
    print $"  --features <F>           Cargo features \(default: ($DEFAULT_FEATURES)\)"
    print "  --node-args <ARGS>       Additional node arguments (space-separated)"
    print "  --bench-args <ARGS>      Additional tempo-bench arguments (space-separated)"
    print ""
    print "Localnet flags:"
    print "  --mode <dev|consensus>   Mode (default: dev)"
    print "  --nodes <N>              Number of validators for consensus (default: 3)"
    print "  --accounts <N>           Genesis accounts (default: 1000)"
    print "  --samply                 Enable samply profiling (foreground node only)"
    print "  --samply-args <ARGS>     Additional samply arguments (space-separated)"
    print "  --loud                   Show all node logs (WARN/ERROR shown by default)"
    print "  --reset                  Wipe and regenerate localnet"
    print $"  --profile <P>            Cargo profile \(default: ($DEFAULT_PROFILE)\)"
    print $"  --features <F>           Cargo features \(default: ($DEFAULT_FEATURES)\)"
    print "  --node-args <ARGS>       Additional node arguments (space-separated)"
    print ""
    print "Coverage flags:"
    print "  --tests                  Include unit + integration test coverage"
    print "  --invariants             Run Solidity invariant fuzz tests (merged Rust precompile coverage)"
    print "  --invariant-profile <P>  Foundry profile for invariants (ci, fuzz500, default; default: ci)"
    print "  --invariant-contract <C> Run only a specific invariant contract"
    print "  --live                   Include live node coverage (runs localnet + traffic)"
    print "  --preset <P>             Bench preset for live mode"
    print "  --script <PATH>          External script to run against live node (instead of bench)"
    print "  --tps <N>                Target TPS for live bench (default: 1000)"
    print "  --duration <N>           Bench duration in seconds (default: 10)"
    print "  --accounts <N>           Number of accounts (default: 100)"
    print "  --format <F>             Report format: html, lcov, json, text (default: html)"
    print "  --open                   Open HTML report in browser"
    print "  --reset                  Wipe localnet data before live run"
    print ""
    print "Examples:"
    print "  nu tempo.nu bench --preset tip20 --tps 20000 --duration 60"
    print "  nu tempo.nu bench --preset tempo-mix --tps 5000 --samply --reset"
    print "  nu tempo.nu coverage --tests                              # unit + integration tests"
    print "  nu tempo.nu coverage --invariants                         # forge invariant fuzz (precompile coverage)"
    print "  nu tempo.nu coverage --tests --invariants                 # merged: cargo + forge coverage"
    print "  nu tempo.nu coverage --invariants --invariant-profile fuzz500  # deeper fuzz run"
    print "  nu tempo.nu coverage --live --preset tip20 --open         # live tx coverage"
    print "  nu tempo.nu coverage --live --script /path/to/test.sh     # live + external script"
    print "  nu tempo.nu coverage --tests --live --preset tempo-mix    # everything merged"
    print "  nu tempo.nu infra up"
    print "  nu tempo.nu localnet --mode dev --samply --accounts 50000 --reset"
    print "  nu tempo.nu localnet --mode consensus --nodes 3"
    print ""
    print "Port assignments (consensus mode, per node N=0,1,2...):"
    print "  Consensus:     8000 + N*100"
    print "  P2P:           8001 + N*100"
    print "  Metrics:       8002 + N*100"
    print "  AuthRPC:       8003 + N*100"
    print "  HTTP RPC:      8545 + N"
    print "  Reth Metrics:  9001 + N"
}
