#!/usr/bin/env nu

# Tempo local benchmarking utilities

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

    # Get samply PIDs first
    let samply_pids = (ps | where name =~ "samply" | get pid)

    # Kill tempo processes with SIGINT (2) for graceful shutdown
    let tempo_pids = (ps | where name =~ "tempo" | where name !~ "tempo-bench" | get pid)
    if ($tempo_pids | length) > 0 {
        print $"Sending SIGINT to ($tempo_pids | length) tempo processes..."
        for pid in $tempo_pids {
            kill -s 2 $pid
        }
    }

    # Remove stale IPC socket
    if ("/tmp/reth.ipc" | path exists) {
        rm /tmp/reth.ipc
        print "Removed /tmp/reth.ipc"
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
    --loud                      # Show all node logs (WARN/ERROR shown by default)
    --node-args: string = ""    # Additional node arguments (space-separated)
    --skip-build                # Skip building (assumes binary is already built)
    --force                     # Kill dangling processes without prompting
] {
    # Check for dangling processes
    check-dangling-processes $force

    # Parse custom node args
    let extra_args = if $node_args == "" { [] } else { $node_args | split row " " }

    # Build first (unless skipped)
    if not $skip_build {
        let build_cmd = ["cargo" "build" "--bin" "tempo" "--profile" $profile "--features" $features]
        print $"Building tempo: `($build_cmd | str join ' ')`..."
        with-env { RUSTFLAGS: $RUSTFLAGS } {
            run-external ($build_cmd | first) ...($build_cmd | skip 1)
        }
    }

    if $mode == "dev" {
        if $nodes != 3 {
            print "Error: --nodes is only valid with --mode consensus"
            exit 1
        }
        run-dev-node $accounts $samply $reset $profile $loud $extra_args
    } else if $mode == "consensus" {
        run-consensus-nodes $nodes $accounts $samply $reset $profile $loud $extra_args
    } else {
        print $"Unknown mode: ($mode). Use 'dev' or 'consensus'."
        exit 1
    }
}

def run-dev-node [accounts: int, samply: bool, reset: bool, profile: string, loud: bool, extra_args: list<string>] {
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

    let tempo_bin = $"./target/($profile)/tempo"
    let datadir = $"($LOCALNET_DIR)/reth"
    let log_dir = $"($LOCALNET_DIR)/logs"

    let base = (build-base-args $genesis_path $datadir $log_dir 8545 9001)
    let dev = (build-dev-args)
    # Apply log filter (WARN by default, all if --loud)
    let log_filter = if $loud { [] } else { ["--log.stdout.filter" "warn"] }
    let args = ($base | append $dev | append $log_filter | append $extra_args)

    mut cmd = [$tempo_bin ...$args];
    if $samply {
        $cmd = ["samply" "record" "--" ...$cmd];
    }
    print $"Running dev node: `($cmd | str join ' ')`..."
    run-external ($cmd | first) ...($cmd | skip 1)
}

def run-consensus-nodes [nodes: int, accounts: int, samply: bool, reset: bool, profile: string, loud: bool, extra_args: list<string>] {
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

    let tempo_bin = $"./target/($profile)/tempo"

    # Start background nodes first (all except node 0)
    print $"Starting ($validator_dirs | length) nodes..."
    print $"Logs: ($LOGS_DIR)/"
    print "Press Ctrl+C to stop all nodes."

    let foreground_node = $validator_dirs | first
    let background_nodes = $validator_dirs | skip 1

    for node in ($background_nodes | enumerate) {
        start-node-job $node.item $genesis_path $trusted_peers $tempo_bin $loud false $extra_args
    }

    # Run node 0 in foreground (show logs only if --loud)
    run-node-foreground $foreground_node $genesis_path $trusted_peers $tempo_bin $loud $samply $extra_args
}

def check-dangling-processes [force: bool] {
    let pids = (ps | where name =~ "tempo" | where name !~ "tempo-bench" | get pid)
    if ($pids | length) > 0 {
        print $"Found ($pids | length) running tempo process\(es\)."
        let should_kill = if $force {
            true
        } else {
            let answer = (input "Kill them? [Y/n] " | str trim | str downcase)
            $answer == "" or $answer == "y" or $answer == "yes"
        }
        if $should_kill {
            for pid in $pids {
                kill -s 2 $pid
            }
            print "Sent SIGINT."
        } else {
            print "Aborting."
            exit 1
        }
    }
}

def start-node-job [node_dir: string, genesis_path: string, trusted_peers: string, tempo_bin: string, loud: bool, samply: bool, extra_args: list<string>] {
    let addr = ($node_dir | path basename)
    let port = ($addr | split row ":" | get 1 | into int)
    let node_index = (($port - 8000) / 100 | into int)
    let http_port = 8545 + $node_index

    let log_dir = $"($LOGS_DIR)/($addr)"
    mkdir $log_dir

    # Build args with appropriate log filter (WARN by default, all if --loud)
    let args = (build-node-args $node_dir $genesis_path $trusted_peers $port $log_dir) | append (
        if $loud { [] } else { ["--log.stdout.filter" "warn"] }
    ) | append $extra_args

    # Build command (with or without samply)
    let cmd = if $samply {
        ["samply" "record" "--" $tempo_bin] | append $args
    } else {
        [$tempo_bin] | append $args
    }

    print $"  Node ($addr) -> http://localhost:($http_port)"
    # Always prefix output with node address
    job spawn { sh -c $"($cmd | str join ' ') 2>&1" | lines | each { |line| print $"[($addr)] ($line)" } }
}

# Run a node in the foreground (receives Ctrl+C directly)
def run-node-foreground [node_dir: string, genesis_path: string, trusted_peers: string, tempo_bin: string, loud: bool, samply: bool, extra_args: list<string>] {
    let addr = ($node_dir | path basename)
    let port = ($addr | split row ":" | get 1 | into int)
    let node_index = (($port - 8000) / 100 | into int)
    let http_port = 8545 + $node_index

    let log_dir = $"($LOGS_DIR)/($addr)"
    mkdir $log_dir

    # Build args with appropriate log filter (WARN by default, all if --loud)
    let args = (build-node-args $node_dir $genesis_path $trusted_peers $port $log_dir) | append (
        if $loud { [] } else { ["--log.stdout.filter" "warn"] }
    ) | append $extra_args

    # Build command (with or without samply)
    let cmd = if $samply {
        ["samply" "record" "--" $tempo_bin] | append $args
    } else {
        [$tempo_bin] | append $args
    }

    if $loud {
        print $"  Node ($addr) -> http://localhost:($http_port) \(foreground, logs to stdout\)"
    } else {
        print $"  Node ($addr) -> http://localhost:($http_port) \(foreground\)"
    }
    print $"  Running foreground consensus node: ($cmd | str join ' ')"

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

# Run a full benchmark: start stack, nodes, and tempo-bench
def "main bench" [
    --mode: string = "consensus"                    # Mode: "dev" or "consensus"
    --preset: string = ""                           # Preset: tip20, erc20, swap, order, tempo-mix
    --tps: int = 10000                              # Target TPS
    --duration: int = 30                            # Duration in seconds
    --accounts: int = 1000                          # Number of accounts
    --nodes: int = 3                                # Number of consensus nodes (consensus mode only)
    --samply                                        # Profile nodes with samply
    --reset                                         # Reset localnet before starting
    --loud                                          # Show node logs (silent by default)
    --profile: string = $DEFAULT_PROFILE            # Cargo build profile
    --features: string = $DEFAULT_FEATURES          # Cargo features
    --node-args: string = ""                        # Additional node arguments (space-separated)
    --bench-args: string = ""                       # Additional tempo-bench arguments (space-separated)
] {
    # Validate mode
    if $mode != "dev" and $mode != "consensus" {
        print $"Unknown mode: ($mode). Use 'dev' or 'consensus'."
        exit 1
    }

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
    print "Building tempo and tempo-bench..."
    let build_cmd = ["cargo" "build" "--bin" "tempo" "--bin" "tempo-bench" "--profile" $profile "--features" $features]
    with-env { RUSTFLAGS: $RUSTFLAGS } {
        run-external ($build_cmd | first) ...($build_cmd | skip 1)
    }

    # Start nodes in background (skip build since we already compiled)
    let num_nodes = if $mode == "dev" { 1 } else { $nodes }
    print $"Starting ($num_nodes) ($mode) node\(s\)..."
    # Ensure at least as many accounts as validators for genesis generation (+1 for admin account)
    let genesis_accounts = ([$accounts $num_nodes] | math max) + 1
    let node_cmd = [
        "nu" "bench.nu" "node"
        "--mode" $mode
        "--accounts" $"($genesis_accounts)"
        "--skip-build"
        "--force"
        "--profile" $profile
        "--features" $features
    ]
    | append (if $mode == "consensus" { ["--nodes" $"($nodes)"] } else { [] })
    | append (if $reset { ["--reset"] } else { [] })
    | append (if $samply { ["--samply"] } else { [] })
    | append (if $loud { ["--loud"] } else { [] })
    | append (if $node_args != "" { ["--node-args" $node_args] } else { [] })

    # Spawn nodes as a background job (pipe output to show logs)
    let node_cmd_str = ($node_cmd | str join " ")
    print $"  Command: ($node_cmd_str)"
    job spawn { nu -c $node_cmd_str o+e>| lines | each { |line| print $line } }

    # Wait for nodes to be ready (give them a moment to start)
    sleep 2sec
    print "Waiting for nodes to be ready..."
    let rpc_urls = (0..<$num_nodes | each { |i| $"http://localhost:(8545 + $i)" })
    for url in $rpc_urls {
        wait-for-rpc $url
    }
    print "All nodes ready!"

    # Build target URLs
    let target_urls = ($rpc_urls | str join ",")

    # Run tempo-bench
    let tempo_bench_bin = $"./target/($profile)/tempo-bench"
    let bench_cmd = [
        $tempo_bench_bin
        "run-max-tps"
        "--tps" $"($tps)"
        "--duration" $"($duration)"
        "--accounts" $"($accounts)"
        "--target-urls" $target_urls
        "--faucet"
        "--clear-txpool"
    ] | append (if $preset != "" {
        [
            "--tip20-weight" $"($weights | get 0)"
            "--erc20-weight" $"($weights | get 1)"
            "--swap-weight" $"($weights | get 2)"
            "--place-order-weight" $"($weights | get 3)"
        ]
    } else { [] }) | append (if $bench_args != "" { $bench_args | split row " " } else { [] })

    print $"Running benchmark: ($bench_cmd | str join ' ')"
    try {
        # Set file descriptor limit and run benchmark
        sh -c $"ulimit -Sn unlimited && ($bench_cmd | str join ' ')"
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

# Show help
def main [] {
    print "Tempo local benchmarking utilities"
    print ""
    print "Usage:"
    print "  nu bench.nu bench [flags]           Run full benchmark (stack + nodes + bench)"
    print "  nu bench.nu stack up                Start Grafana + Prometheus"
    print "  nu bench.nu stack down              Stop the observability stack"
    print "  nu bench.nu kill                    Kill any running tempo processes"
    print "  nu bench.nu node [flags]            Run Tempo node(s)"
    print ""
    print "Bench flags (either --preset or --bench-args required):"
    print "  --mode <M>               Mode: dev or consensus (default: consensus)"
    print "  --preset <P>             Preset: tip20, erc20, swap, order, tempo-mix"
    print "  --tps <N>                Target TPS (default: 10000)"
    print "  --duration <N>           Duration in seconds (default: 30)"
    print "  --accounts <N>           Number of accounts (default: 1000)"
    print "  --nodes <N>              Number of consensus nodes (default: 3, consensus mode only)"
    print "  --samply                 Profile nodes with samply"
    print "  --reset                  Reset localnet before starting"
    print "  --loud                   Show all node logs (WARN/ERROR shown by default)"
    print $"  --profile <P>            Cargo profile \(default: ($DEFAULT_PROFILE)\)"
    print $"  --features <F>           Cargo features \(default: ($DEFAULT_FEATURES)\)"
    print "  --node-args <ARGS>       Additional node arguments (space-separated)"
    print "  --bench-args <ARGS>      Additional tempo-bench arguments (space-separated)"
    print ""
    print "Node flags:"
    print "  --mode <dev|consensus>   Mode (default: dev)"
    print "  --nodes <N>              Number of validators for consensus (default: 3)"
    print "  --accounts <N>           Genesis accounts (default: 1000)"
    print "  --samply                 Enable samply profiling (foreground node only)"
    print "  --loud                   Show all node logs (WARN/ERROR shown by default)"
    print "  --reset                  Wipe and regenerate localnet"
    print $"  --profile <P>            Cargo profile \(default: ($DEFAULT_PROFILE)\)"
    print $"  --features <F>           Cargo features \(default: ($DEFAULT_FEATURES)\)"
    print "  --node-args <ARGS>       Additional node arguments (space-separated)"
    print ""
    print "Examples:"
    print "  nu bench.nu bench --preset tip20 --tps 20000 --duration 60"
    print "  nu bench.nu bench --preset tempo-mix --tps 5000 --samply --reset"
    print "  nu bench.nu stack up"
    print "  nu bench.nu node --mode dev --samply --accounts 50000 --reset"
    print "  nu bench.nu node --mode consensus --nodes 3"
    print ""
    print "Port assignments (consensus mode, per node N=0,1,2...):"
    print "  Consensus:     8000 + N*100"
    print "  P2P:           8001 + N*100"
    print "  Metrics:       8002 + N*100"
    print "  AuthRPC:       8003 + N*100"
    print "  HTTP RPC:      8545 + N"
    print "  Reth Metrics:  9001 + N"
}
