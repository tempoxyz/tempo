#!/usr/bin/env nu

# Tempo local benchmarking utilities

const BENCH_DIR = "contrib/bench"
const LOCALNET_DIR = "localnet"
const LOGS_DIR = "contrib/bench/logs"
const RUSTFLAGS = "-C target-cpu=native"
const DEFAULT_PROFILE = "profiling"
const DEFAULT_FEATURES = "jemalloc,asm-keccak"

# Start the observability stack (Grafana + Prometheus)
def "main stack up" [] {
    print "Starting observability stack..."
    docker compose -f $"($BENCH_DIR)/docker-compose.yml" up -d
    print "Grafana available at http://localhost:3000 (admin/admin)"
    print "Prometheus available at http://localhost:9090"
}

# Stop the observability stack
def "main stack down" [] {
    print "Stopping observability stack..."
    docker compose -f $"($BENCH_DIR)/docker-compose.yml" down
}

# Kill any running tempo processes and cleanup
def "main kill" [] {
    print "Killing tempo processes..."
    # Kill any nushell jobs
    let jobs = (job list | get id)
    if ($jobs | length) > 0 {
        print $"Killing ($jobs | length) background jobs..."
        for id in $jobs {
            job kill $id
        }
    }
    # Kill any orphaned tempo processes
    let pids = (ps | where name =~ "tempo" | where name !~ "tempo-bench" | get pid)
    if ($pids | length) > 0 {
        print $"Killing ($pids | length) tempo processes..."
        for pid in $pids {
            kill $pid
        }
    }
    print "Done."
}

# Run Tempo node(s) for benchmarking
def "main node" [
    --mode: string = "dev"      # Mode: "dev" or "consensus"
    --nodes: int = 3            # Number of validators (consensus mode)
    --accounts: int = 1000      # Number of genesis accounts
    --samply                    # Enable samply profiling (foreground node only)
    --reset                     # Wipe and regenerate localnet data
    --profile: string = $DEFAULT_PROFILE # Cargo build profile
    --features: string = $DEFAULT_FEATURES # Cargo features
    --logs: string = ""         # Tail logs: "all" or comma-separated node indices (e.g., "0,1,2")
    --silent                    # Suppress WARN/ERROR log output
] {
    # Check for dangling processes
    check-dangling-processes

    if $mode == "dev" {
        run-dev-node $accounts $samply $reset $profile $features
    } else if $mode == "consensus" {
        run-consensus-nodes $nodes $accounts $samply $reset $profile $features $logs $silent
    } else {
        print $"Unknown mode: ($mode). Use 'dev' or 'consensus'."
        exit 1
    }
}

def run-dev-node [accounts: int, samply: bool, reset: bool, profile: string, features: string] {
    let genesis_path = $"($LOCALNET_DIR)/genesis.json"
    let needs_generation = $reset or (not ($genesis_path | path exists))

    if $needs_generation {
        if $reset {
            print "Resetting localnet data..."
        } else {
            print "Genesis not found, generating..."
        }
        rm -rf $LOCALNET_DIR
        mkdir $LOCALNET_DIR
        print $"Generating genesis with ($accounts) accounts..."
        cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $LOCALNET_DIR -a $accounts
    }

    # Build first
    print "Building tempo..."
    with-env { RUSTFLAGS: $RUSTFLAGS } {
        cargo build --bin tempo --profile $profile --features $features
    }

    let tempo_bin = $"./target/($profile)/tempo"
    let datadir = $"($LOCALNET_DIR)/reth"
    let log_dir = $"($LOCALNET_DIR)/logs"

    let base = (build-base-args $genesis_path $datadir $log_dir 8545 9001)
    let dev = (build-dev-args)
    let args = ($base | append $dev)

    if $samply {
        print "Running dev node with samply profiling..."
        samply record -o $"($LOCALNET_DIR)/tempo-dev.samply" -- $tempo_bin ...$args
    } else {
        print "Running dev node..."
        run-external $tempo_bin ...$args
    }
}

def run-consensus-nodes [nodes: int, accounts: int, samply: bool, reset: bool, profile: string, features: string, logs: string, silent: bool] {
    # Check if we need to generate localnet
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

    # Parse the generated node configs
    let genesis_path = $"($LOCALNET_DIR)/genesis.json"

    # Build trusted peers from enode.identity files
    let validator_dirs = (ls $LOCALNET_DIR | where type == "dir" | get name | where { |d| ($d | path basename) =~ '^\d+\.\d+\.\d+\.\d+:\d+$' })
    let trusted_peers = ($validator_dirs | each { |d|
        let addr = ($d | path basename)
        let port = ($addr | split row ":" | get 1 | into int)
        let identity = (open $"($d)/enode.identity" | str trim)
        $"enode://($identity)@127.0.0.1:($port + 1)"
    } | str join ",")

    print $"Found ($validator_dirs | length) validator configs"

    # Parse --logs option: "" = none, "all" = all nodes, "0,1,2" = specific indices
    let log_indices = if $logs == "all" {
        0..<($validator_dirs | length) | each { |i| $i }
    } else if $logs != "" {
        $logs | split row "," | each { |s| $s | str trim | into int }
    } else {
        []
    }

    # Build first
    print "Building tempo..."
    with-env { RUSTFLAGS: $RUSTFLAGS } {
        cargo build --bin tempo --profile $profile --features $features
    }

    let tempo_bin = $"./target/($profile)/tempo"

    # Prepare logs directory
    rm -rf $LOGS_DIR
    mkdir $LOGS_DIR
    print $"Logs will be written to ($LOGS_DIR)/"

    # Start all nodes as background jobs
    print $"Starting ($validator_dirs | length) nodes..."
    for node in ($validator_dirs | enumerate) {
        let tail_logs = ($node.index in $log_indices)
        let show_errors = not $silent
        start-node-job $node.item $genesis_path $trusted_peers $tempo_bin $tail_logs $samply $show_errors
    }

    print "All nodes started. Press Ctrl+C to stop."
    print $"Logs: ($LOGS_DIR)/"

    # Wait for interrupt
    try {
        loop { sleep 1sec }
    } catch {
        print "\nStopping..."
    }
    cleanup-jobs
}

def cleanup-jobs [] {
    let jobs = (job list | get id)
    if ($jobs | length) > 0 {
        print $"Killing ($jobs | length) background jobs..."
        for id in $jobs {
            job kill $id
        }
    }
}

def check-dangling-processes [] {
    let pids = (ps | where name =~ "tempo" | where name !~ "tempo-bench" | get pid)
    if ($pids | length) > 0 {
        print $"Found ($pids | length) running tempo process\(es\)."
        let answer = (input "Kill them? [y/N] " | str trim | str downcase)
        if $answer == "y" or $answer == "yes" {
            for pid in $pids {
                kill $pid
            }
            print "Killed."
        } else {
            print "Aborting."
            exit 1
        }
    }
}

def start-node-job [node_dir: string, genesis_path: string, trusted_peers: string, tempo_bin: string, tail_logs: bool, samply: bool, show_errors: bool] {
    let addr = ($node_dir | path basename)
    let port = ($addr | split row ":" | get 1 | into int)
    let node_index = (($port - 8000) / 100 | into int)
    let http_port = 8545 + $node_index

    let log_dir = $"($LOGS_DIR)/($addr)"
    mkdir $log_dir
    let args = (build-node-args $node_dir $genesis_path $trusted_peers $port $log_dir)

    if $tail_logs {
        # Show all logs for this node
        print $"  Node ($addr) -> http://localhost:($http_port) \(logs to stdout\)"
        if $samply {
            job spawn {
                sh -c $"samply record -o ($LOCALNET_DIR)/tempo-($port).samply -- ($tempo_bin) ($args | str join ' ') 2>&1" | lines | each { |line| print $"[($addr)] ($line)" }
            }
        } else {
            job spawn {
                sh -c $"($tempo_bin) ($args | str join ' ') 2>&1" | lines | each { |line| print $"[($addr)] ($line)" }
            }
        }
    } else if $show_errors {
        # Show only WARN/ERROR logs
        print $"  Node ($addr) -> http://localhost:($http_port)"
        if $samply {
            job spawn {
                sh -c $"samply record -o ($LOCALNET_DIR)/tempo-($port).samply -- ($tempo_bin) ($args | str join ' ') 2>&1" | lines | each { |line| if ($line =~ "WARN|ERROR") { print $"[($addr)] ($line)" } }
            }
        } else {
            job spawn {
                sh -c $"($tempo_bin) ($args | str join ' ') 2>&1" | lines | each { |line| if ($line =~ "WARN|ERROR") { print $"[($addr)] ($line)" } }
            }
        }
    } else {
        # Silent mode - no stdout output
        print $"  Node ($addr) -> http://localhost:($http_port)"
        if $samply {
            job spawn { samply record -o $"($LOCALNET_DIR)/tempo-($port).samply" -- $tempo_bin ...$args }
        } else {
            job spawn { run-external $tempo_bin ...$args }
        }
    }
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
        "--faucet.address" "0x20c0000000000000000000000000000000000001"
    ]
}

# Build dev mode specific arguments
def build-dev-args [] {
    [
        "--dev"
        "--dev.block-time" "1sec"
        "--engine.disable-precompile-cache"
        "--engine.legacy-state-root"
        "--builder.gaslimit" "3000000000"
        "--builder.max-tasks" "8"
        "--builder.deadline" "3"
    ]
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

# Build full node arguments for consensus mode
def build-node-args [node_dir: string, genesis_path: string, trusted_peers: string, port: int, log_dir: string] {
    let node_index = (($port - 8000) / 100 | into int)
    let http_port = 8545 + $node_index
    let reth_metrics_port = 9001 + $node_index

    let base = (build-base-args $genesis_path $node_dir $log_dir $http_port $reth_metrics_port)
    let consensus = (build-consensus-args $node_dir $trusted_peers $port)

    $base | append $consensus
}

# Show help
def main [] {
    print "Tempo local benchmarking utilities"
    print ""
    print "Usage:"
    print "  nu bench.nu stack up              Start Grafana + Prometheus"
    print "  nu bench.nu stack down            Stop the observability stack"
    print "  nu bench.nu kill                  Kill any running tempo processes"
    print "  nu bench.nu node [flags]          Run Tempo node(s)"
    print ""
    print "Node flags:"
    print "  --mode <dev|consensus>   Mode (default: dev)"
    print "  --nodes <N>              Number of validators for consensus (default: 3)"
    print "  --accounts <N>           Genesis accounts (default: 1000)"
    print "  --samply                 Enable samply profiling"
    print "  --logs <spec>            Tail logs: 'all' or comma-separated indices (e.g., '1,2')"
    print "  --silent                 Suppress WARN/ERROR log output"
    print "  --reset                  Wipe and regenerate localnet"
    print $"  --profile <P>            Cargo profile \(default: ($DEFAULT_PROFILE)\)"
    print $"  --features <F>           Cargo features \(default: ($DEFAULT_FEATURES)\)"
    print ""
    print "Examples:"
    print "  nu bench.nu stack up"
    print "  nu bench.nu node --mode dev --samply --accounts 50000 --reset"
    print "  nu bench.nu node --mode consensus --nodes 3"
    print "  nu bench.nu node --mode consensus --nodes 3 --samply"
    print ""
    print "Port assignments (consensus mode, per node N=0,1,2...):"
    print "  Consensus:     8000 + N*100"
    print "  P2P:           8001 + N*100"
    print "  Metrics:       8002 + N*100"
    print "  AuthRPC:       8003 + N*100"
    print "  HTTP RPC:      8545 + N"
    print "  Reth Metrics:  9001 + N"
}
