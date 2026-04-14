#!/usr/bin/env nu

# Tempo local utilities

const BENCH_DIR = "contrib/bench"
const LOCALNET_DIR = "localnet"
const LOGS_DIR = "contrib/bench/logs"
const RUSTFLAGS = "-C target-cpu=native"
const DEFAULT_PROFILE = "profiling"
const DEFAULT_FEATURES = "jemalloc,asm-keccak"
const BENCH_WORKTREES_DIR = ".bench-worktrees"
const BENCH_RESULTS_DIR = "bench-results"
const BLOAT_MNEMONIC = "test test test test test test test test test test test junk"
const METRICS_PROXY_SCRIPT = "contrib/bench/bench-metrics-proxy.py"
const METRICS_LABELS_FILE = "/tmp/bench-metrics-labels.json"
const MINIO_BUCKET = "minio/tempo-binaries"
const BENCH_META_SUBDIR = ".bench-meta"

# Preset weight configurations: [tip20, erc20, swap, order]
const PRESETS = {
    tip20: [1.0, 0.0, 0.0, 0.0],
    erc20: [0.0, 1.0, 0.0, 0.0],
    swap: [0.0, 0.0, 1.0, 0.0],
    order: [0.0, 0.0, 0.0, 1.0],
    "tempo-mix": [0.8, 0, 0.19, 0.01]
}

# TIP20 token IDs created by localnet genesis (pathUSD, AlphaUSD, BetaUSD, ThetaUSD)
const TIP20_TOKEN_IDS = [0, 1, 2, 3]

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

# Compute effective features and RUSTFLAGS for tracy builds.
# The "tracy" cargo feature on bin/tempo already includes tracy-client/ondemand,
# so we only need to append "tracy" here. tempo-bench doesn't have a tracy feature,
# so it must be built separately with the base features.
def tracy-build-config [features: string, tracy: string] {
    if $tracy == "off" {
        { features: $features, extra_rustflags: "" }
    } else {
        let tracy_features = if $features == "" { "tracy" } else { $"($features),tracy" }
        { features: $tracy_features, extra_rustflags: " -C force-frame-pointers=yes" }
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
def build-tempo [bins: list<string>, profile: string, features: string, --extra-rustflags: string = ""] {
    let bin_args = ($bins | each { |bin| ["--bin" $bin] } | flatten)
    let build_cmd = ["cargo" "build" "--profile" $profile "--features" $features]
        | append $bin_args
    let rustflags = $"($RUSTFLAGS)($extra_rustflags)"
    print $"Building ($bins | str join ', '): `($build_cmd | str join ' ')`..."
    with-env { RUSTFLAGS: $rustflags } {
        run-external ($build_cmd | first) ...($build_cmd | skip 1)
    }
}

# Find tempo process PIDs (excluding tempo-bench)
def find-tempo-pids [] {
    ps | where name =~ "tempo" | where name !~ "tempo-bench" | get pid
}

# Initialize node with state bloat
# 1. Run `tempo init` to create the database
# 2. Generate state bloat binary file
# 3. Run `tempo init-from-binary-dump` to load the bloat
# Generate the bloat binary file once (skips if already exists)
def generate-bloat-file [bloat_size: int, profile: string] {
    let bloat_file = $"($LOCALNET_DIR)/state_bloat.bin"
    if ($bloat_file | path exists) {
        print $"State bloat file already exists \(($bloat_size) MiB\)"
        return
    }
    print $"Generating state bloat \(($bloat_size) MiB\)..."
    let token_args = ($TIP20_TOKEN_IDS | each { |id| ["--token" $"($id)"] } | flatten)
    cargo run -p tempo-xtask --profile $profile -- generate-state-bloat --size $bloat_size --out $bloat_file ...$token_args
}

# Load the bloat file into a single node's database
def load-bloat-into-node [tempo_bin: string, genesis_path: string, datadir: string] {
    let bloat_file = $"($LOCALNET_DIR)/state_bloat.bin"
    let db_path = $"($datadir)/db"

    # Skip if this node already has a database with bloat loaded
    if ($db_path | path exists) {
        print $"State bloat already loaded into ($datadir | path basename)"
        return
    }

    # Remove existing reth database files while preserving key files (signing.key, signing.share, etc.)
    if ($datadir | path exists) {
        for subdir in [db static_files rocksdb consensus invalid_block_hooks] {
            let path = $"($datadir)/($subdir)"
            if ($path | path exists) { rm -rf $path }
        }
        for file in [reth.toml jwt.hex] {
            let path = $"($datadir)/($file)"
            if ($path | path exists) { rm $path }
        }
    }

    print $"Initializing ($datadir | path basename) database..."
    run-external $tempo_bin "init" "--chain" $genesis_path "--datadir" $datadir

    print $"Loading state bloat into ($datadir | path basename)..."
    run-external $tempo_bin "init-from-binary-dump" "--chain" $genesis_path "--datadir" $datadir $bloat_file
}

# ============================================================================
# Schelk / snapshot helpers
# ============================================================================

# Check if schelk is available
def has-schelk [] {
    (which schelk | length) > 0
}

# Check if MinIO client (mc) is available
def has-mc [] {
    (which mc | length) > 0
}

# Force-clear schelk's "is_mounted" state after a crash where dm-era is gone
def schelk-force-unmount-state [] {
    let state_path = "/var/lib/schelk/state.json"
    print $"  Clearing stale is_mounted flag in ($state_path)..."
    let state = (sudo cat $state_path | from json | update is_mounted false)
    $state | to json | sudo tee $state_path | ignore
}

# Clean database files from a datadir (db, static_files, rocksdb, etc.)
def bench-clean-datadir [datadir: string] {
    for subdir in [db static_files rocksdb consensus invalid_block_hooks] {
        let path = $"($datadir)/($subdir)"
        if ($path | path exists) { rm -rf $path }
    }
    for file in [reth.toml jwt.hex] {
        let path = $"($datadir)/($file)"
        if ($path | path exists) { rm $path }
    }
}

# Initialize a database: run `tempo init`, optionally load state bloat
def bench-init-db [tempo_bin: string, genesis: string, datadir: string, bloat: int, bloat_file: string] {
    print $"Initializing database at ($datadir)..."
    run-external $tempo_bin "init" "--chain" $genesis "--datadir" $datadir

    if $bloat > 0 {
        print $"Loading state bloat into ($datadir)..."
        run-external $tempo_bin "init-from-binary-dump" "--chain" $genesis "--datadir" $datadir $bloat_file | complete
    }
}

# Save genesis files, bloat, and marker to meta dir, then promote and remount.
# Everything is written before promote so it's part of the virgin snapshot.
def bench-save-and-promote [datadir: string, meta_dir: string, marker: record, genesis_files: list, bloat: int, bloat_file: string] {
    mkdir $meta_dir
    for pair in $genesis_files {
        cp ($pair | first) $"($meta_dir)/($pair | last)"
    }
    if $bloat > 0 and ($bloat_file | path exists) {
        cp $bloat_file $"($meta_dir)/state_bloat.bin"
    }
    let marker_path = $"($meta_dir)/marker.json"
    $marker | insert initialized_at (date now | format date "%Y-%m-%dT%H:%M:%SZ") | to json | save -f $marker_path
    print $"Bench marker written to ($marker_path)"

    bench-promote $datadir
    bench-mount
}

# Recover snapshot to virgin state and remount
def bench-recover [datadir: string] {
    if (has-schelk) {
        print "Recovering schelk snapshot..."
        if (mountpoint -q /reth-bench | complete).exit_code == 0 {
            sudo umount -l /reth-bench | ignore
        }
        try {
            sudo schelk recover -y
        } catch {
            print "Surgical recover failed, falling back to full-recover..."
            schelk-force-unmount-state
            sudo schelk full-recover -y
        }
        sudo schelk mount
        sudo chown -R (whoami | str trim) /reth-bench
    } else {
        print $"Restoring snapshot from ($datadir).virgin..."
        rm -rf $datadir
        ^cp -a $"($datadir).virgin" $datadir
    }
}

# Promote current state as the new virgin baseline
def bench-promote [datadir: string] {
    if (has-schelk) {
        print "Promoting schelk scratch to virgin..."
        sudo schelk promote -y
    } else {
        print $"Saving snapshot to ($datadir).virgin..."
        rm -rf $"($datadir).virgin"
        ^cp -a $datadir $"($datadir).virgin"
    }
}

# Mount schelk scratch volume (no-op without schelk)
def bench-mount [] {
    if (has-schelk) {
        # If volume is already mounted, recover first (unmounts + resets scratch)
        if (mountpoint -q /reth-bench | complete).exit_code == 0 {
            print "Schelk volume already mounted, recovering first..."
            sudo umount -l /reth-bench | ignore
            try { sudo schelk recover -y } catch {
                print "Surgical recover failed, falling back to full-recover..."
                schelk-force-unmount-state
                sudo schelk full-recover -y
            }
        }
        print "Mounting schelk scratch volume..."
        try { sudo schelk mount } catch {
            # Mount failed — state may be inconsistent after a crash
            print "Mount failed, forcing recover..."
            try { sudo schelk recover -y } catch {
                print "Surgical recover failed, falling back to full-recover..."
                schelk-force-unmount-state
                sudo schelk full-recover -y
            }
            sudo schelk mount
        }
        sudo chown -R (whoami | str trim) /reth-bench
    }
}

# ============================================================================
# Bench metadata marker (persists across workspace wipes)
# ============================================================================

# Read bench metadata marker from the datadir's meta directory. Returns record or null.
def read-bench-marker [datadir: string] {
    let path = $"($datadir)/($BENCH_META_SUBDIR)/marker.json"
    if ($path | path exists) {
        open $path
    } else {
        null
    }
}

# ============================================================================
# Comparison mode helpers
# ============================================================================

# Ordered list of all Tempo hardforks (must match TempoHardfork enum in crates/chainspec)
const TEMPO_HARDFORKS = ["T0" "T1" "T1A" "T1B" "T1C" "T2" "T3" "T4"]

# Map a hardfork name to generate-genesis CLI args.
# Forks up to and including the given fork are active at genesis (time=0).
# Forks after are disabled (time=max u64).
# Returns a list of CLI flag strings, e.g. ["--t0-time" "0" "--t1-time" "0" "--t1a-time" "9223372036854775807" ...]
def hardfork-to-genesis-args [fork: string] {
    let fork_upper = ($fork | str upcase)
    let idx = ($TEMPO_HARDFORKS | enumerate | where item == $fork_upper)
    if ($idx | length) == 0 {
        print $"Error: unknown hardfork '($fork)'. Valid: ($TEMPO_HARDFORKS | str join ', ')"
        exit 1
    }
    let cutoff = ($idx | get 0.index)
    $TEMPO_HARDFORKS | enumerate | each { |it|
        let flag = $"--($it.item | str downcase)-time"
        let time = if $it.index <= $cutoff { "0" } else { "9223372036854775807" }
        [$flag $time]
    } | flatten
}

# Resolve a git ref to a full commit SHA
def resolve-git-ref [ref: string] {
    git rev-parse $ref | str trim
}

# Try to download cached binaries from MinIO for a given commit SHA.
# Returns true on cache hit, false on miss or any failure.
def try-cache-download [worktree_dir: string, profile: string, commit_sha: string] {
    if not (has-mc) { return false }

    let bins = ["tempo" "tempo-bench"]
    # Check that all binaries exist in the cache
    for bin in $bins {
        let remote = $"($MINIO_BUCKET)/($commit_sha)/($bin)"
        try {
            mc stat $remote | ignore
        } catch {
            print $"Cache miss: ($remote)"
            return false
        }
    }

    # All binaries exist – download them
    let target_dir = if $profile == "dev" {
        $"($worktree_dir)/target/debug"
    } else {
        $"($worktree_dir)/target/($profile)"
    }
    mkdir $target_dir

    for bin in $bins {
        let remote = $"($MINIO_BUCKET)/($commit_sha)/($bin)"
        let local = $"($target_dir)/($bin)"
        print $"Downloading cached ($bin) for ($commit_sha | str substring 0..8)..."
        try {
            mc cp $remote $local
            chmod +x $local
        } catch {
            print $"Cache download failed for ($bin), falling back to build"
            return false
        }
    }

    # Verify binaries work
    for bin in $bins {
        let local = $"($target_dir)/($bin)"
        try {
            run-external $local "--version"
        } catch {
            print $"Cached ($bin) failed --version check, falling back to build"
            return false
        }
    }

    print $"Cache hit: using cached binaries for ($commit_sha | str substring 0..8)"
    return true
}

# Upload built binaries to MinIO cache. Failures are non-fatal.
def cache-upload [worktree_dir: string, profile: string, commit_sha: string] {
    if not (has-mc) { return }

    let target_dir = if $profile == "dev" {
        $"($worktree_dir)/target/debug"
    } else {
        $"($worktree_dir)/target/($profile)"
    }

    for bin in ["tempo" "tempo-bench"] {
        let local = $"($target_dir)/($bin)"
        let remote = $"($MINIO_BUCKET)/($commit_sha)/($bin)"
        print $"Uploading ($bin) to cache for ($commit_sha | str substring 0..8)..."
        try {
            mc cp $local $remote
        } catch {
            print $"Warning: failed to upload ($bin) to cache"
        }
    }
}

# Build tempo binaries in a git worktree (with optional MinIO cache)
def build-in-worktree [worktree_dir: string, ref: string, profile: string, features: string, commit_sha: string, --no-cache, --extra-rustflags: string = "", --bench-features: string = ""] {
    # Try cache first
    if not $no_cache and (try-cache-download $worktree_dir $profile $commit_sha) {
        return
    }

    # Build from source — when tracy is enabled, tempo and tempo-bench need different features
    print $"Building binaries for ($ref) in ($worktree_dir)..."
    let rustflags = $"($RUSTFLAGS)($extra_rustflags)"
    if $bench_features != "" and $bench_features != $features {
        # Build tempo (with tracy features) and tempo-bench (without) separately
        let tempo_cmd = ["cargo" "build" "--profile" $profile "--features" $features "--bin" "tempo"]
        let bench_cmd = ["cargo" "build" "--profile" $profile "--features" $bench_features "--bin" "tempo-bench"]
        with-env { RUSTFLAGS: $rustflags } {
            do { cd $worktree_dir; run-external ($tempo_cmd | first) ...($tempo_cmd | skip 1) }
            do { cd $worktree_dir; run-external ($bench_cmd | first) ...($bench_cmd | skip 1) }
        }
    } else {
        let bin_args = ["--bin" "tempo" "--bin" "tempo-bench"]
        let build_cmd = ["cargo" "build" "--profile" $profile "--features" $features]
            | append $bin_args
        with-env { RUSTFLAGS: $rustflags } {
            do { cd $worktree_dir; run-external ($build_cmd | first) ...($build_cmd | skip 1) }
        }
    }

    # Upload to cache
    cache-upload $worktree_dir $profile $commit_sha
}

# Get the path to a built binary in a worktree
def worktree-bin [worktree_dir: string, profile: string, bin_name: string] {
    if $profile == "dev" {
        $"($worktree_dir)/target/debug/($bin_name)"
    } else {
        $"($worktree_dir)/target/($profile)/($bin_name)"
    }
}

# Dedup CLI args: if extra_args provides a flag already present in base_args,
# the default (in base_args) is dropped so clap doesn't see it twice.
# Handles both `--flag value` and `--flag=value` forms.
def dedup-args [base_args: list<string>, extra_args: list<string>] {
    if ($extra_args | is-empty) { return $base_args }

    # Collect flag keys the user wants to override
    let override_keys = ($extra_args | where { |a| $a starts-with "--" }
        | each { |a| $a | split row "=" | first })

    # Walk base_args, skip any flag (and its value) whose key is overridden
    mut result = []
    mut skip_next = false
    for arg in $base_args {
        if $skip_next {
            $skip_next = false
            continue
        }
        if ($arg starts-with "--") {
            let key = ($arg | split row "=" | first)
            if ($key in $override_keys) {
                # Skip this flag; if it's `--flag value` form (no =), skip next token too
                if not ($arg | str contains "=") {
                    $skip_next = true
                }
                continue
            }
        }
        $result = ($result | append $arg)
    }
    $result | append $extra_args
}

# Run a single benchmark run (start node, run bench, stop node, collect report)
def run-bench-single [
    --tempo-bin: string
    --bench-bin: string
    --genesis-path: string
    --datadir: string
    --run-label: string
    --results-dir: string
    --tps: int
    --duration: int
    --accounts: int
    --max-concurrent-requests: int
    --weights: list<float>
    --preset: string = ""
    --bench-args: string = ""
    --loud
    --node-args: string = ""
    --bloat: int = 0
    --git-ref: string = ""
    --build-profile: string = ""
    --benchmark-mode: string = ""
    --benchmark-id: string = ""
    --reference-epoch: int = 0
    --samply
    --samply-args: list<string> = []
    --tracy: string = "off"
    --tracy-filter: string = "debug"
    --tracy-seconds: int = 0
    --tracy-offset: int = 0
    --tracing-otlp: string = ""
] {
    print $"=== Starting run: ($run_label) ==="

    let log_dir = $"($LOCALNET_DIR)/logs-($run_label)"
    mkdir $log_dir

    # Start metrics proxy with labels for this run
    let run_type = if ($run_label | str starts-with "baseline") { "baseline" } else { "feature" }
    let run_start_epoch = (date now | into int) / 1_000_000_000
    let labels = {
        benchmark_run: $run_label
        run_type: $run_type
        git_ref: $git_ref
        benchmark_id: $benchmark_id
        run_start_epoch: $"($run_start_epoch)"
        reference_epoch: $"($reference_epoch)"
    }
    $labels | to json | save -f $METRICS_LABELS_FILE

    let proxy_pid = if ($METRICS_PROXY_SCRIPT | path exists) {
        let proxy_job = (job spawn {
            python3 $METRICS_PROXY_SCRIPT --upstream "http://127.0.0.1:9001/" --port 9090
        })
        sleep 500ms
        $proxy_job
    } else {
        null
    }

    # Parse extra node args
    let extra_args = if $node_args == "" { [] } else { $node_args | split row " " }

    # Build node arguments, then dedup so user-provided args override defaults
    let base_args = (build-base-args $genesis_path $datadir $log_dir "0.0.0.0" 8545 9001)
        | append (build-dev-args)
        | append (log-filter-args $loud)
        | append (if $tracy != "off" { ["--log.tracy" "--log.tracy.filter" $tracy_filter] } else { [] })
        | append (if $tracing_otlp != "" { [$"--tracing-otlp=($tracing_otlp)"] } else { [] })
    let args = (dedup-args $base_args $extra_args)

    # Tracy environment variables
    let tracy_env_prefix = if $tracy == "on" {
        "TRACY_NO_SYS_TRACE=1 "
    } else if $tracy == "full" {
        "TRACY_SAMPLING_HZ=1 "
    } else { "" }

    # OTEL resource attributes for benchmark identification in logs/traces
    let otel_attrs = $"OTEL_RESOURCE_ATTRIBUTES=benchmark_id=($benchmark_id),benchmark_run=($run_label),run_type=($run_type),git_ref=($git_ref) "

    # Start tempo node in background (optionally wrapped with samply)
    let full_samply_args = if $samply {
        $samply_args | append ["--save-only" "--presymbolicate" "--output" $"($results_dir)/profile-($run_label).json.gz"]
    } else { [] }
    let node_cmd = wrap-samply [$tempo_bin ...$args] $samply $full_samply_args
    let node_cmd_str = ($node_cmd | str join " ")
    let profiling_label = if $samply { " (samply)" } else if $tracy != "off" { $" \(tracy=($tracy)\)" } else { "" }
    print $"  Starting node: ($tempo_bin | path basename)($profiling_label)"
    job spawn { sh -c $"($otel_attrs)($tracy_env_prefix)($node_cmd_str) 2>&1" | lines | each { |line| print $"[($run_label)] ($line)" } }

    # Wait for RPC
    sleep 2sec
    let rpc_timeout = if $bloat > 0 { 600 } else { 120 }
    wait-for-rpc "http://localhost:8545" $rpc_timeout

    # Start tracy-capture after RPC is ready (node must be running for connection)
    # If tracy-offset > 0, delay the capture start in a background job so tempo-bench isn't blocked
    let tracy_output = $"($results_dir)/tracy-profile-($run_label).tracy"
    let tracy_capture_started = if $tracy != "off" {
        let seconds_flag = if $tracy_seconds > 0 { $"-s ($tracy_seconds)" } else { "" }
        let limit_msg = if $tracy_seconds > 0 { $" \(($tracy_seconds)s limit\)" } else { "" }
        if $tracy_offset > 0 {
            print $"  Tracy-capture will start in ($tracy_offset)s($limit_msg)..."
            job spawn { sleep ($"($tracy_offset)sec" | into duration); sh -c $"tracy-capture -f -o ($tracy_output) ($seconds_flag)" }
        } else {
            print $"  Starting tracy-capture($limit_msg)..."
            job spawn { sh -c $"tracy-capture -f -o ($tracy_output) ($seconds_flag)" }
            sleep 500ms
        }
        true
    } else { false }

    # Run tempo-bench
    let bench_cmd = [
        $bench_bin
        "run-max-tps"
        "--tps" $"($tps)"
        "--duration" $"($duration)"
        "--accounts" $"($accounts)"
        "--max-concurrent-requests" $"($max_concurrent_requests)"
        "--target-urls" "http://localhost:8545"
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
    | append (if $bloat > 0 {
        [
            "--mnemonic" $"'($BLOAT_MNEMONIC)'"
            "--existing-recipients"
        ]
    } else { [] })
    | append (if $bench_args != "" { $bench_args | split row " " } else { [] })
    | append (if $git_ref != "" { ["--node-commit-sha" $git_ref] } else { [] })
    | append (if $build_profile != "" { ["--build-profile" $build_profile] } else { [] })
    | append (if $benchmark_mode != "" { ["--benchmark-mode" $benchmark_mode] } else { [] })

    print $"  Running benchmark..."
    try {
        bash -c $"ulimit -Sn unlimited && ($bench_cmd | str join ' ')"
    } catch { |e|
        print $"  Benchmark run ($run_label) failed: ($e.msg)"
    }

    # Collect report
    if ("report.json" | path exists) {
        cp report.json $"($results_dir)/report-($run_label).json"
        rm report.json
        print $"  Report saved: report-($run_label).json"
    } else {
        print $"  ERROR: no report.json found for ($run_label)"
        error make { msg: $"Benchmark run ($run_label) produced no report.json" }
    }

    # Stop tracy-capture FIRST (it needs the node alive to flush data)
    if $tracy_capture_started {
        print "  Stopping tracy-capture..."
        let capture_pids = (ps | where name =~ "tracy-capture" | get pid)
        for pid in $capture_pids {
            kill -s 2 $pid  # SIGINT for graceful flush
        }
        mut wait_tracy = 0
        while $wait_tracy < 30 {
            if (ps | where name =~ "tracy-capture" | length) == 0 { break }
            sleep 1sec
            $wait_tracy = $wait_tracy + 1
        }
        if $wait_tracy >= 30 {
            print "  Warning: tracy-capture did not exit, sending SIGKILL"
            for pid in (ps | where name =~ "tracy-capture" | get pid) {
                kill -s 9 $pid
            }
        }
    }

    # Stop node
    print "  Stopping node..."
    let pids = (find-tempo-pids)
    for pid in $pids {
        kill -s 2 $pid
    }
    # Wait for tempo processes to fully exit
    for pid in $pids {
        mut wait = 0
        while $wait < 30 {
            if (ps | where pid == $pid | length) == 0 { break }
            sleep 1sec
            $wait = $wait + 1
        }
        if $wait >= 30 {
            print $"  Warning: PID ($pid) did not exit, sending SIGKILL"
            kill -s 9 $pid
            sleep 1sec
        }
    }

    # Wait for samply to finish saving profile
    if $samply {
        print "  Waiting for samply to finish saving profile..."
        mut wait = 0
        while $wait < 120 {
            if (ps | where name =~ "samply" | length) == 0 { break }
            sleep 500ms
            $wait = $wait + 1
        }
        if $wait >= 120 {
            print "  Warning: samply did not exit in time"
        }
    }

    # Stop metrics proxy
    if $proxy_pid != null {
        let proxy_pids = (ps | where name =~ "bench-metrics-proxy" | get pid)
        for pid in $proxy_pids {
            kill -s 2 $pid
        }
    }

    # Remove stale IPC socket
    if ("/tmp/reth.ipc" | path exists) {
        rm --force /tmp/reth.ipc
    }

    print $"=== Run ($run_label) complete ==="
}

# Upload a samply profile (.json.gz) to Firefox Profiler and return the short URL.
# Returns null on failure. Uses the same approach as reth-bench.
def upload-samply-profile [profile_path: string] {
    if not ($profile_path | path exists) {
        print $"  Warning: profile not found: ($profile_path)"
        return null
    }

    let profile_size = (ls $profile_path | get size | first)
    print $"  Uploading ($profile_path | path basename) \(($profile_size)\) to Firefox Profiler..."

    let script = $"($BENCH_DIR)/upload-samply-profile.sh"
    let result = (bash $script $profile_path | complete)

    if $result.exit_code != 0 {
        print $"  Warning: failed to upload profile"
        return null
    }

    let url = ($result.stdout | str trim)
    print $"  Profile URL: ($url)"
    $url
}

# Upload a tracy profile (.tracy) to R2 via mc and return the viewer URL.
# Returns null on failure or if mc is not available.
# Deletes the large .tracy file after successful upload to save disk.
def upload-tracy-profile [profile_path: string, label: string, commit_sha: string] {
    if not ($profile_path | path exists) {
        print $"  Warning: tracy profile not found: ($profile_path)"
        return null
    }
    if not (has-mc) {
        print "  Warning: mc not available, skipping tracy upload"
        return null
    }

    let profile_size = (ls $profile_path | get size | first)
    print $"  Uploading ($profile_path | path basename) \(($profile_size)\) to R2..."

    let timestamp = (date now | format date "%Y%m%d-%H%M%S")
    let short_sha = ($commit_sha | str substring 0..7)
    let remote_name = $"($label)-($short_sha)-($timestamp).tracy"
    let mc_alias = "r2"
    let viewer_base = "https://tracy.tempoxyz.dev"

    try {
        mc cp $profile_path $"($mc_alias)/tracy/profiles/($remote_name)"
        let viewer_url = $"($viewer_base)?profile_url=/profiles/($remote_name)"
        print $"  ($label): ($viewer_url)"
        # Delete large .tracy file after upload to free disk
        rm $profile_path
        $viewer_url
    } catch {
        print "  Warning: failed to upload tracy profile"
        null
    }
}

# Generate summary.md from multiple report files
# Compute percentile from a sorted list (0-100)
def percentile [sorted_vals: list<any>, pct: int] {
    if ($sorted_vals | length) == 0 { return 0.0 }
    let idx = (($sorted_vals | length) * $pct / 100 | into int)
    let clamped = [($idx) (($sorted_vals | length) - 1)] | math min
    $sorted_vals | get $clamped
}


def generate-summary [results_dir: string, baseline_ref: string, feature_ref: string, bloat: int, preset: string, tps: int, duration: int, --benchmark-id: string = "", --reference-epoch: int = 0] {
    let run_labels = ["baseline-1" "feature-1" "feature-2" "baseline-2"]
    mut run_data = []
    mut baseline_blocks = []
    mut feature_blocks = []
    mut baseline_intervals = []
    mut feature_intervals = []
    mut baseline_tps_samples = []
    mut feature_tps_samples = []

    let compute_tps_stats = { |samples: list<any>|
        let sorted_samples = ($samples | sort)
        {
            p50: (percentile $sorted_samples 50 | math round --precision 1)
            p90: (percentile $sorted_samples 90 | math round --precision 1)
            p99: (percentile $sorted_samples 99 | math round --precision 1)
        }
    }

    let compute_block_time_stats = { |intervals: list<any>|
        let sorted_intervals = ($intervals | sort)
        {
            p50: (percentile $sorted_intervals 50 | math round --precision 1)
            p90: (percentile $sorted_intervals 90 | math round --precision 1)
            p99: (percentile $sorted_intervals 99 | math round --precision 1)
        }
    }

    for label in $run_labels {
        let report_path = $"($results_dir)/report-($label).json"
        if not ($report_path | path exists) {
            print $"Warning: ($report_path) not found, skipping"
            continue
        }
        let report = (open $report_path)
        let blocks = ($report | get blocks)
        if ($blocks | length) == 0 {
            print $"Warning: ($label) report has no blocks, skipping"
            continue
        }

        let sorted_blocks = ($blocks | sort-by timestamp)
        let timestamps = ($sorted_blocks | get timestamp)
        let block_intervals = if ($timestamps | length) > 1 {
            $timestamps | window 2 | each { |w| ($w | last) - ($w | first) }
        } else { [] }

        # Attribute each interval's throughput to the later block so TPS quantiles stay
        # within a single run and avoid the inter-run gaps that skew merged samples.
        let block_tps_samples = if ($sorted_blocks | length) > 1 {
            $sorted_blocks | window 2 | each { |pair|
                let earlier = ($pair | first)
                let later = ($pair | last)
                let interval_ms = [((($later | get timestamp) - ($earlier | get timestamp))) 1] | math max
                (($later | get tx_count) / ($interval_ms / 1000.0))
            }
        } else { [] }
        let run_tps = do $compute_tps_stats $block_tps_samples
        let run_bt = do $compute_block_time_stats $block_intervals

        # Collect blocks into baseline/feature groups
        if ($label | str starts-with "baseline") {
            $baseline_blocks = ($baseline_blocks | append $blocks)
            $baseline_intervals = ($baseline_intervals | append $block_intervals)
            $baseline_tps_samples = ($baseline_tps_samples | append $block_tps_samples)
        } else {
            $feature_blocks = ($feature_blocks | append $blocks)
            $feature_intervals = ($feature_intervals | append $block_intervals)
            $feature_tps_samples = ($feature_tps_samples | append $block_tps_samples)
        }

        let total_tx = ($blocks | get tx_count | math sum)
        let total_ok = ($blocks | get ok_count | math sum)
        let total_err = ($blocks | get err_count | math sum)
        let total_gas = ($blocks | get gas_used | math sum)
        let latencies = ($blocks | where latency_ms != null | get latency_ms | sort)
        let p50_latency = (percentile $latencies 50 | math round --precision 1)
        let num_blocks = ($blocks | length)

        # Compute TPS from block timestamps (timestamps are in milliseconds)
        let time_span_ms = if ($timestamps | length) > 1 {
            let first = ($timestamps | first)
            let last = ($timestamps | last)
            [($last - $first) 1] | math max
        } else { 1 }
        let time_span_s = $time_span_ms / 1000.0
        let actual_tps = ($total_tx / $time_span_s) | math round --precision 0

        let gas_per_sec = ($total_gas / $time_span_s)
        let mgas_per_sec = ($gas_per_sec / 1_000_000) | math round --precision 1

        let success_rate = if $total_tx > 0 {
            (($total_ok / $total_tx) * 100) | math round --precision 1
        } else { 0 }

        $run_data = ($run_data | append [{
            label: $label
            blocks: $num_blocks
            total_tx: $total_tx
            ok: $total_ok
            err: $total_err
            total_gas: $total_gas
            p50_latency: $p50_latency
            tps: $actual_tps
            tps_p50: $run_tps.p50
            tps_p90: $run_tps.p90
            tps_p99: $run_tps.p99
            mgas_s: $mgas_per_sec
            block_time_p50: $run_bt.p50
            block_time_p90: $run_bt.p90
            block_time_p99: $run_bt.p99
            success_rate: $success_rate
        }])
    }

    if ($run_data | length) == 0 {
        print "No reports found, skipping summary generation"
        return
    }

    # Compute per-block latency percentiles for each group
    let compute_latency_stats = { |blocks: list<any>|
        let latencies = ($blocks | where latency_ms != null | get latency_ms | sort)
        {
            n: ($blocks | length)
            mean: (if ($latencies | length) > 0 { $latencies | math avg | math round --precision 1 } else { 0 })
            stddev: (if ($latencies | length) > 1 { $latencies | math stddev | math round --precision 1 } else { 0 })
            p50: (percentile $latencies 50 | math round --precision 1)
            p90: (percentile $latencies 90 | math round --precision 1)
            p99: (percentile $latencies 99 | math round --precision 1)
        }
    }

    let b_lat = do $compute_latency_stats $baseline_blocks
    let f_lat = do $compute_latency_stats $feature_blocks

    let b_bt = do $compute_block_time_stats $baseline_intervals
    let f_bt = do $compute_block_time_stats $feature_intervals
    let b_tps_stats = do $compute_tps_stats $baseline_tps_samples
    let f_tps_stats = do $compute_tps_stats $feature_tps_samples

    # Aggregate TPS and Mgas/s from per-run totals (total_tx / total_time)
    let baseline_runs = ($run_data | where { |r| $r.label | str starts-with "baseline" })
    let feature_runs = ($run_data | where { |r| $r.label | str starts-with "feature" })

    let b_tps = if ($baseline_runs | length) > 0 { $baseline_runs | get tps | math avg | math round --precision 0 } else { 0 }
    let f_tps = if ($feature_runs | length) > 0 { $feature_runs | get tps | math avg | math round --precision 0 } else { 0 }
    let b_mgas = if ($baseline_runs | length) > 0 { $baseline_runs | get mgas_s | math avg | math round --precision 1 } else { 0 }
    let f_mgas = if ($feature_runs | length) > 0 { $feature_runs | get mgas_s | math avg | math round --precision 1 } else { 0 }

    # Compute deltas (feature vs baseline)
    let delta = { |base: float, feat: float| if $base != 0 { ((($feat - $base) / $base) * 100) | math round --precision 1 } else { 0 } }

    # Build summary markdown
    let summary = ([
        $"# Bench Comparison: ($baseline_ref) vs ($feature_ref)"
        ""
        "## Configuration"
        $"- Bloat: ($bloat) MiB"
        $"- Preset: ($preset)"
        $"- Target TPS: ($tps)"
        $"- Duration: ($duration)s"
        $"- Snapshot: (if (has-schelk) { 'schelk' } else { 'cp fallback' })"
        $"- Baseline blocks: ($b_lat.n)"
        $"- Feature blocks: ($f_lat.n)"
        ""
        "## Tempo Metrics"
        ""
        "| Metric | Baseline | Feature | Delta |"
        "|--------|----------|---------|-------|"
        $"| Avg TPS | ($b_tps) | ($f_tps) | (do $delta $b_tps $f_tps)% |"
        $"| TPS P50 | ($b_tps_stats.p50) | ($f_tps_stats.p50) | (do $delta $b_tps_stats.p50 $f_tps_stats.p50)% |"
        $"| TPS P90 | ($b_tps_stats.p90) | ($f_tps_stats.p90) | (do $delta $b_tps_stats.p90 $f_tps_stats.p90)% |"
        $"| TPS P99 | ($b_tps_stats.p99) | ($f_tps_stats.p99) | (do $delta $b_tps_stats.p99 $f_tps_stats.p99)% |"
        $"| Gas Throughput [Mgas/s] | ($b_mgas) | ($f_mgas) | (do $delta $b_mgas $f_mgas)% |"
        $"| Block Time P50 [ms] | ($b_bt.p50) | ($f_bt.p50) | (do $delta $b_bt.p50 $f_bt.p50)% |"
        $"| Block Time P90 [ms] | ($b_bt.p90) | ($f_bt.p90) | (do $delta $b_bt.p90 $f_bt.p90)% |"
        $"| Block Time P99 [ms] | ($b_bt.p99) | ($f_bt.p99) | (do $delta $b_bt.p99 $f_bt.p99)% |"
        ""
        "## Latency (Secondary)"
        ""
        "| Metric | Baseline | Feature | Delta |"
        "|--------|----------|---------|-------|"
        $"| Latency Mean [ms] | ($b_lat.mean) | ($f_lat.mean) | (do $delta $b_lat.mean $f_lat.mean)% |"
        $"| Latency Std Dev [ms] | ($b_lat.stddev) | ($f_lat.stddev) | (do $delta $b_lat.stddev $f_lat.stddev)% |"
        $"| Latency P50 [ms] | ($b_lat.p50) | ($f_lat.p50) | (do $delta $b_lat.p50 $f_lat.p50)% |"
        $"| Latency P90 [ms] | ($b_lat.p90) | ($f_lat.p90) | (do $delta $b_lat.p90 $f_lat.p90)% |"
        $"| Latency P99 [ms] | ($b_lat.p99) | ($f_lat.p99) | (do $delta $b_lat.p99 $f_lat.p99)% |"
        ""
        "## Per-Run Details"
        ""
        "| Run | Blocks | Total Tx | Success | Failed | Avg TPS | Block P50 | Mgas/s |"
        "|-----|--------|----------|---------|--------|---------|-----------|--------|"
    ] | str join "\n")

    mut per_run_rows = ""
    for row in $run_data {
        $per_run_rows = $"($per_run_rows)| ($row.label) | ($row.blocks) | ($row.total_tx) | ($row.ok) | ($row.err) | ($row.tps) | ($row.block_time_p50) | ($row.mgas_s) |\n"
    }

    let full_summary = $"($summary)\n($per_run_rows)"
    $full_summary | save -f $"($results_dir)/summary.md"
    print $"Summary saved: ($results_dir)/summary.md"
    print $full_summary

    # Write machine-readable summary.json for CI
    let summary_json = {
        benchmark_id: $benchmark_id
        reference_epoch: $reference_epoch
        baseline_ref: $baseline_ref
        feature_ref: $feature_ref
        config: {
            bloat: $bloat
            preset: $preset
            tps: $tps
            duration: $duration
        }
        results: {
            baseline: {
                latency_mean: $b_lat.mean
                latency_stddev: $b_lat.stddev
                latency_p50: $b_lat.p50
                latency_p90: $b_lat.p90
                latency_p99: $b_lat.p99
                tps: $b_tps
                tps_p50: $b_tps_stats.p50
                tps_p90: $b_tps_stats.p90
                tps_p99: $b_tps_stats.p99
                mgas_s: $b_mgas
                block_time_p50: $b_bt.p50
                block_time_p90: $b_bt.p90
                block_time_p99: $b_bt.p99
                blocks: $b_lat.n
            }
            feature: {
                latency_mean: $f_lat.mean
                latency_stddev: $f_lat.stddev
                latency_p50: $f_lat.p50
                latency_p90: $f_lat.p90
                latency_p99: $f_lat.p99
                tps: $f_tps
                tps_p50: $f_tps_stats.p50
                tps_p90: $f_tps_stats.p90
                tps_p99: $f_tps_stats.p99
                mgas_s: $f_mgas
                block_time_p50: $f_bt.p50
                block_time_p90: $f_bt.p90
                block_time_p99: $f_bt.p99
                blocks: $f_lat.n
            }
            deltas: {
                latency_mean: (do $delta $b_lat.mean $f_lat.mean)
                latency_stddev: (do $delta $b_lat.stddev $f_lat.stddev)
                latency_p50: (do $delta $b_lat.p50 $f_lat.p50)
                latency_p90: (do $delta $b_lat.p90 $f_lat.p90)
                latency_p99: (do $delta $b_lat.p99 $f_lat.p99)
                tps: (do $delta $b_tps $f_tps)
                tps_p50: (do $delta $b_tps_stats.p50 $f_tps_stats.p50)
                tps_p90: (do $delta $b_tps_stats.p90 $f_tps_stats.p90)
                tps_p99: (do $delta $b_tps_stats.p99 $f_tps_stats.p99)
                mgas_s: (do $delta $b_mgas $f_mgas)
                block_time_p50: (do $delta $b_bt.p50 $f_bt.p50)
                block_time_p90: (do $delta $b_bt.p90 $f_bt.p90)
                block_time_p99: (do $delta $b_bt.p99 $f_bt.p99)
            }
        }
        per_run: $run_data
    }
    $summary_json | to json | save -f $"($results_dir)/summary.json"
    print $"Summary JSON saved: ($results_dir)/summary.json"
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
        rm --force /tmp/reth.ipc
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
    --bloat: int = 0            # Generate state bloat (size in MiB) for TIP20 tokens
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
        run-dev-node $accounts $genesis $samply $samply_args_list $reset $profile $loud $extra_args $bloat
    } else {
        run-consensus-nodes $nodes $accounts $genesis $samply $samply_args_list $reset $profile $loud $extra_args $bloat
    }
}

# ============================================================================
# Dev mode
# ============================================================================

def run-dev-node [accounts: int, genesis: string, samply: bool, samply_args: list<string>, reset: bool, profile: string, loud: bool, extra_args: list<string>, bloat: int] {
    let tempo_bin = if $profile == "dev" {
        "./target/debug/tempo"
    } else {
        $"./target/($profile)/tempo"
    }
    let datadir = $"($LOCALNET_DIR)/reth"
    let log_dir = $"($LOCALNET_DIR)/logs"

    let genesis_path = if $genesis != "" {
        # Custom genesis provided - check if bloat requires init
        if $bloat > 0 {
            generate-bloat-file $bloat $profile
            load-bloat-into-node $tempo_bin $genesis $datadir
        }
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

        # Apply state bloat if requested (requires fresh init)
        if $bloat > 0 {
            generate-bloat-file $bloat $profile
            load-bloat-into-node $tempo_bin $default_genesis $datadir
        }

        $default_genesis
    }

    let args = (build-base-args $genesis_path $datadir $log_dir "0.0.0.0" 8545 9001)
        | append (build-dev-args)
        | append (log-filter-args $loud)
        | append $extra_args

    let cmd = wrap-samply [$tempo_bin ...$args] $samply $samply_args
    print $"Running dev node: `($cmd | str join ' ')`..."
    run-external ($cmd | first) ...($cmd | skip 1)
}

# Build base node arguments shared between dev and consensus modes
def build-base-args [genesis_path: string, datadir: string, log_dir: string, bind_ip: string, http_port: int, reth_metrics_port: int] {
    [
        "node"
        "--chain" $genesis_path
        "--datadir" $datadir
        "--http"
        "--http.addr" $bind_ip
        "--http.port" $"($http_port)"
        "--http.api" "all"
        "--metrics" $"($bind_ip):($reth_metrics_port)"
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
        "--builder.deadline" "3"
    ]
}

# ============================================================================
# Consensus mode
# ============================================================================

def run-consensus-nodes [nodes: int, accounts: int, genesis: string, samply: bool, samply_args: list<string>, reset: bool, profile: string, loud: bool, extra_args: list<string>, bloat: int] {
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

            # Generate validator addresses with distinct loopback IPs (required by ValidatorConfigV2
            # ingress uniqueness check which is per-IP, not per-socket-address)
            let validators = (0..<$nodes | each { |i| $"127.0.0.($i + 1):($i * 100 + 8000)" } | str join ",")

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
        let ip = ($addr | split row ":" | get 0)
        let port = ($addr | split row ":" | get 1 | into int)
        let identity = (open $"($d)/enode.identity" | str trim)
        $"enode://($identity)@($ip):($port + 1)"
    } | str join ",")

    print $"Found ($validator_dirs | length) validator configs"

    let tempo_bin = if $profile == "dev" {
        "./target/debug/tempo"
    } else {
        $"./target/($profile)/tempo"
    }

    # Ensure loopback aliases exist for distinct validator IPs (macOS only has 127.0.0.1 by default)
    if (sys host | get name) == "Darwin" {
        let extra_ips = ($validator_dirs | each { |d| $d | path basename | split row ":" | get 0 } | where { |ip| $ip != "127.0.0.1" })
        if ($extra_ips | length) > 0 {
            print $"Adding macOS loopback aliases for validator IPs: ($extra_ips | str join ', ') \(sudo required\)..."
        }
        for dir in $validator_dirs {
            let ip = ($dir | path basename | split row ":" | get 0)
            if $ip != "127.0.0.1" {
                try { sudo ifconfig lo0 alias $ip up } catch { |e|
                    print $"(ansi red)Failed to add loopback alias ($ip): ($e.msg)(ansi reset)"
                    print "Run: sudo ifconfig lo0 alias $ip up"
                    exit 1
                }
            }
        }
    }

    # Apply state bloat to each node's datadir if requested
    if $bloat > 0 {
        generate-bloat-file $bloat $profile
        for node_dir in $validator_dirs {
            load-bloat-into-node $tempo_bin $genesis_path $node_dir
        }
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

    (build-base-args $genesis_path $node_dir $log_dir "0.0.0.0" $http_port $reth_metrics_port)
        | append (build-consensus-args $node_dir $trusted_peers $port)
}

# Build consensus mode specific arguments
def build-consensus-args [node_dir: string, trusted_peers: string, port: int] {
    let addr = ($node_dir | path basename)
    let ip = ($addr | split row ":" | get 0)
    let signing_key = $"($node_dir)/signing.key"
    let signing_share = $"($node_dir)/signing.share"
    let enode_key = $"($node_dir)/enode.key"

    let execution_p2p_port = $port + 1
    let metrics_port = $port + 2
    let authrpc_port = $port + 3
    let discv5_port = $port + 4

    [
        "--consensus.signing-key" $signing_key
        "--consensus.signing-share" $signing_share
        "--consensus.listen-address" $"($ip):($port)"
        "--consensus.metrics-address" $"($ip):($metrics_port)"
        "--trusted-peers" $trusted_peers
        "--port" $"($execution_p2p_port)"
        "--discovery.port" $"($execution_p2p_port)"
        "--discovery.v5.port" $"($discv5_port)"
        "--p2p-secret-key" $enode_key
        "--authrpc.port" $"($authrpc_port)"
        "--consensus.fee-recipient" "0x0000000000000000000000000000000000000000"
        "--consensus.use-local-defaults"
        "--consensus.bypass-ip-check"
    ]
}

# ============================================================================
# System tuning for benchmarks
# ============================================================================

# Apply system tuning for reproducible benchmarks on dedicated runners (Linux only).
# Focuses on the essentials: TCP tuning (port exhaustion fix), THP, and noisy services.
def apply-system-tuning [] {
    if (^uname | str trim) != "Linux" {
        print "Warning: --tune is only supported on Linux, skipping system tuning"
        return { tuned: false }
    }

    print "Applying system tuning for benchmarks..."

    # TCP tuning (fixes ephemeral port exhaustion at high TPS)
    print "  TCP: enabling tw_reuse, expanding port range"
    sudo sysctl -w net.ipv4.tcp_tw_reuse=1 | ignore
    sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535" | ignore

    # CPU governor → performance (ignore offline CPUs)
    print "  CPU: setting governor to performance"
    bash -c 'for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance | sudo tee "$g" 2>/dev/null || true; done' | ignore

    # Disable turbo boost (Intel)
    let intel_turbo = "/sys/devices/system/cpu/intel_pstate/no_turbo"
    if ($intel_turbo | path exists) {
        print "  Disabling Intel turbo boost"
        "1" | sudo tee $intel_turbo | ignore
    }

    # Disable turbo boost (AMD)
    let amd_turbo = "/sys/devices/system/cpu/cpufreq/boost"
    if ($amd_turbo | path exists) {
        print "  Disabling AMD turbo boost"
        "0" | sudo tee $amd_turbo | ignore
    }

    # Disable swap
    print "  Disabling swap"
    sudo swapoff -a | ignore

    # Disable THP (transparent huge pages + defrag)
    for thp_dir in ["/sys/kernel/mm/transparent_hugepage" "/sys/kernel/mm/transparent_hugepages"] {
        if ($thp_dir | path exists) {
            print "  Disabling transparent huge pages"
            "never" | sudo tee $"($thp_dir)/enabled" | ignore
            "never" | sudo tee $"($thp_dir)/defrag" | ignore
            break
        }
    }

    # Stop noisy services (ignore failures for services that aren't installed)
    let noisy_services = ["cron" "unattended-upgrades"]
    print $"  Stopping services: ($noisy_services | str join ', ')"
    for svc in $noisy_services {
        try { sudo systemctl stop $svc } catch { }
    }

    # Print environment info for reproducibility
    print $"  Kernel: (^uname -r | str trim)"
    print $"  CPU: (open /proc/cpuinfo | lines | find 'model name' | first | split row ':' | last | str trim)"
    print $"  Port range: (sysctl -n net.ipv4.ip_local_port_range | str trim)"
    print ""

    { tuned: true }
}

# Restore system tuning after benchmarks complete.
def restore-system-tuning [tuning_state: record] {
    if not $tuning_state.tuned {
        return
    }

    print "Restoring system tuning..."
    for svc in ["cron"] {
        try { sudo systemctl start $svc } catch { }
    }
    print "System tuning restored."
}

# ============================================================================
# Bench init command
# ============================================================================

# Initialize the schelk virgin snapshot with genesis + state bloat.
# Run once (or when changing bloat size). Subsequent `bench` calls skip init
# if the marker at $HOME/.tempo-bench-meta.json matches the requested config.
def "main bench-init" [
    --bloat: int = 1024                                 # State bloat size in MiB
    --accounts: int = 1000                              # Number of genesis accounts
    --profile: string = $DEFAULT_PROFILE                # Cargo build profile
    --features: string = $DEFAULT_FEATURES              # Cargo features
    --bench-datadir: string = ""                        # Node database directory (default: /reth-bench for schelk)
    --force                                             # Re-initialize even if marker matches
] {
    let datadir = if $bench_datadir != "" {
        $bench_datadir
    } else if (has-schelk) {
        $"/reth-bench/tempo_($bloat)mb"
    } else {
        $"($LOCALNET_DIR | path expand)/reth"
    }
    let meta_dir = $"($datadir)/($BENCH_META_SUBDIR)"
    let genesis_accounts = ([$accounts 3] | math max) + 1

    # Mount schelk first so we can read the marker from the datadir
    bench-mount

    # Check marker (unless --force)
    if not $force {
        let marker = (read-bench-marker $datadir)
        if $marker != null {
            if ($marker.bloat_mib | into int) == $bloat and ($marker.accounts | into int) == $genesis_accounts {
                if ($"($datadir)/db" | path exists) and ($"($meta_dir)/genesis.json" | path exists) {
                    print $"Virgin snapshot already initialized \(bloat=($bloat) MiB, accounts=($genesis_accounts)\). Use --force to re-initialize."
                    return
                }
            }
        }
    }

    # Build tempo + xtask
    build-tempo ["tempo"] $profile $features
    let tempo_bin = if $profile == "dev" { "./target/debug/tempo" } else { $"./target/($profile)/tempo" }

    # Generate genesis
    let abs_localnet = ($LOCALNET_DIR | path expand)
    if not ($abs_localnet | path exists) { mkdir $abs_localnet }
    let genesis_path = $"($abs_localnet)/genesis.json"
    print $"Generating genesis with ($genesis_accounts) accounts..."
    cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $abs_localnet -a $genesis_accounts --no-dkg-in-genesis

    # Generate bloat file
    let bloat_file = $"($abs_localnet)/state_bloat.bin"
    if $bloat > 0 {
        print $"Generating state bloat \(($bloat) MiB\)..."
        let token_args = ($TIP20_TOKEN_IDS | each { |id| ["--token" $"($id)"] } | flatten)
        cargo run -p tempo-xtask --profile $profile -- generate-state-bloat --size $bloat --out $bloat_file ...$token_args
    }

    bench-clean-datadir $datadir
    bench-init-db $tempo_bin $genesis_path $datadir $bloat $bloat_file

    bench-save-and-promote $datadir $meta_dir {
        bloat_mib: $bloat,
        accounts: $genesis_accounts,
        bench_datadir: $datadir
    } [[$genesis_path "genesis.json"]] $bloat $bloat_file

    print $"Virgin snapshot initialized and promoted."
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
    --loud                                          # Show node logs (silent by default)
    --profile: string = $DEFAULT_PROFILE            # Cargo build profile
    --features: string = $DEFAULT_FEATURES          # Cargo features
    --node-args: string = ""                        # Additional node arguments (space-separated, applied to all runs)
    --baseline-node-args: string = ""               # Additional node arguments for baseline runs only (space-separated)
    --feature-node-args: string = ""                # Additional node arguments for feature runs only (space-separated)
    --bench-args: string = ""                       # Additional tempo-bench arguments (space-separated)
    --bloat: int = 0                                # Generate state bloat (size in MiB) for TIP20 tokens
    --no-infra                                      # Skip starting observability stack (Grafana + Prometheus)
    --baseline: string = ""                         # Git ref for baseline (comparison mode)
    --feature: string = ""                          # Git ref for feature (comparison mode)
    --force                                         # Force re-initialize snapshot (regenerate genesis, bloat, db)
    --bench-datadir: string = ""                    # Node database directory (default: LOCALNET_DIR/reth, /reth-bench for schelk)
    --tune                                          # Apply system tuning for dedicated benchmark runners (Linux only)
    --no-cache                                      # Skip binary cache (force build from source)
    --tracy: string = "off"                         # Tracy profiling: off, on, full
    --tracy-filter: string = "debug"                # Tracy tracing filter level
    --tracy-seconds: int = 30                       # Tracy capture duration limit in seconds (0 = unlimited)
    --tracy-offset: int = 120                       # Seconds to wait before starting tracy capture (default: 120)
    --tracing-otlp: string = ""                     # OTLP endpoint for tracing (auto-derived from TEMPO_TELEMETRY_URL if not set)
    --baseline-hardfork: string = ""                # Latest active hardfork for baseline (e.g. T1, T1C, T2)
    --feature-hardfork: string = ""                 # Latest active hardfork for feature (e.g. T1, T1C, T2)
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

    # Auto-derive tracing OTLP URL: prefer GRAFANA_TEMPO, fall back to TEMPO_TELEMETRY_URL
    let tracing_otlp = if $tracing_otlp == "" and ($env.GRAFANA_TEMPO? | default "" | str length) > 0 {
        let base = ($env.GRAFANA_TEMPO | str trim --right --char '/')
        $"($base)/v1/traces"
    } else if $tracing_otlp == "" and ($env.TEMPO_TELEMETRY_URL? | default "" | str length) > 0 {
        let base = ($env.TEMPO_TELEMETRY_URL | str trim --right --char '/')
        $"($base)/opentelemetry/v1/traces"
    } else {
        $tracing_otlp
    }

    # Handle --force: delete existing localnet data to force full re-init
    if $force {
        if ($LOCALNET_DIR | path exists) {
            print "Removing existing localnet data (--force)..."
            rm -rf $LOCALNET_DIR
        }
    }

    # Pre-flight cleanup: kill leftover tempo processes from failed runs
    main kill

    # Apply system tuning if requested (before any benchmark work)
    let tuning_state = if $tune { apply-system-tuning } else { { tuned: false } }

    # Validate tracy flag
    if $tracy not-in ["off" "on" "full"] {
        print $"Error: --tracy must be one of: off, on, full \(got '($tracy)'\)"
        exit 1
    }
    if $samply and $tracy != "off" {
        print "Error: --samply and --tracy are mutually exclusive. Choose one."
        exit 1
    }
    if $tracy != "off" {
        let has_tracy_capture = (which tracy-capture | length) > 0
        if not $has_tracy_capture {
            print "Error: tracy-capture not found. Install tracy (https://github.com/wolfpld/tracy) and ensure tracy-capture is in PATH."
            exit 1
        }
    }

    # Validate comparison mode flags
    if ($baseline != "" and $feature == "") or ($baseline == "" and $feature != "") {
        print "Error: --baseline and --feature must both be provided for comparison mode"
        exit 1
    }

    # Reject --genesis in comparison mode (it's ambiguous — use --baseline-hardfork/--feature-hardfork instead)
    if $genesis != "" and ($baseline != "" or $feature != "") {
        print "Error: --genesis is not supported in comparison mode"
        exit 1
    }

    # Validate hardfork flags (only valid in comparison mode)
    if ($baseline_hardfork != "" or $feature_hardfork != "") and ($baseline == "" or $feature == "") {
        print "Error: --baseline-hardfork and --feature-hardfork require comparison mode (--baseline + --feature)"
        exit 1
    }
    if ($baseline_hardfork != "" or $feature_hardfork != "") and ($baseline_hardfork == "" or $feature_hardfork == "") {
        print "Error: --baseline-hardfork and --feature-hardfork must both be provided"
        exit 1
    }
    # Validate hardfork names
    if $baseline_hardfork != "" {
        let valid = ($TEMPO_HARDFORKS | any { |f| $f == ($baseline_hardfork | str upcase) })
        if not $valid {
            print $"Error: unknown baseline hardfork '($baseline_hardfork)'. Valid: ($TEMPO_HARDFORKS | str join ', ')"
            exit 1
        }
    }
    if $feature_hardfork != "" {
        let valid = ($TEMPO_HARDFORKS | any { |f| $f == ($feature_hardfork | str upcase) })
        if not $valid {
            print $"Error: unknown feature hardfork '($feature_hardfork)'. Valid: ($TEMPO_HARDFORKS | str join ', ')"
            exit 1
        }
    }
    let dual_hardfork = $baseline_hardfork != "" and $feature_hardfork != ""

    if $baseline != "" and $feature != "" {
        # ================================================================
        # Comparison mode: B-F-F-B interleaved benchmarking
        # ================================================================
        if $mode != "dev" {
            print "Error: comparison mode only supports --mode dev"
            exit 1
        }

        # Resolve git refs to commit SHAs ("local" = current working tree)
        let baseline_sha = if $baseline == "local" { "local" } else { resolve-git-ref $baseline }
        let feature_sha = if $feature == "local" { "local" } else { resolve-git-ref $feature }
        let baseline_label = if $baseline == "local" { "local (working tree)" } else { $"($baseline) → ($baseline_sha)" }
        let feature_label = if $feature == "local" { "local (working tree)" } else { $"($feature) → ($feature_sha)" }
        print $"Baseline: ($baseline_label)"
        print $"Feature: ($feature_label)"

        # Create results directory
        let timestamp = (date now | format date "%Y%m%d-%H%M%S")
        let results_dir = $"($BENCH_RESULTS_DIR)/($timestamp)"
        mkdir $results_dir
        print $"BENCH_RESULTS_DIR=($results_dir)"

        # Setup worktrees (skip for "local" refs)
        let baseline_wt = $"($BENCH_WORKTREES_DIR)/baseline"
        let feature_wt = $"($BENCH_WORKTREES_DIR)/feature"

        let worktrees_to_create = (
            (if $baseline != "local" { [$baseline_wt] } else { [] })
            | append (if $feature != "local" { [$feature_wt] } else { [] })
        )

        # Prune worktree registrations where the directory no longer exists
        git worktree prune

        for wt in [$baseline_wt $feature_wt] {
            if ($wt | path exists) {
                print $"Removing stale worktree: ($wt)"
                try { git worktree remove --force $wt } catch { rm -rf $wt }
            }
        }

        if ($worktrees_to_create | length) > 0 {
            print "Creating worktrees..."
        }
        if $baseline != "local" {
            git worktree add $baseline_wt $baseline_sha
        }
        if $feature != "local" {
            git worktree add $feature_wt $feature_sha
        }

        # Build binaries (apply tracy build config if needed)
        let tbc = (tracy-build-config $features $tracy)
        let effective_features = $tbc.features
        let effective_extra_rustflags = $tbc.extra_rustflags
        # Force --no-cache when tracy is enabled (cached binaries lack tracy features)
        let effective_no_cache = $no_cache or ($tracy != "off")

        if $baseline == "local" or $feature == "local" {
            print "Building local binaries..."
            if $tracy != "off" {
                # Build tempo (with tracy) and tempo-bench (without) separately
                build-tempo --extra-rustflags $effective_extra_rustflags ["tempo"] $profile $effective_features
                build-tempo ["tempo-bench"] $profile $features
            } else {
                build-tempo ["tempo" "tempo-bench"] $profile $effective_features
            }
        }
        if $baseline != "local" {
            if $effective_no_cache {
                build-in-worktree --no-cache --extra-rustflags $effective_extra_rustflags --bench-features $features $baseline_wt $baseline $profile $effective_features $baseline_sha
            } else {
                build-in-worktree $baseline_wt $baseline $profile $effective_features $baseline_sha
            }
        }
        if $feature != "local" {
            if $effective_no_cache {
                build-in-worktree --no-cache --extra-rustflags $effective_extra_rustflags --bench-features $features $feature_wt $feature $profile $effective_features $feature_sha
            } else {
                build-in-worktree $feature_wt $feature $profile $effective_features $feature_sha
            }
        }

        let local_bin = { |name: string| if $profile == "dev" { $"./target/debug/($name)" } else { $"./target/($profile)/($name)" } }

        let baseline_tempo = if $baseline == "local" { do $local_bin "tempo" } else { worktree-bin $baseline_wt $profile "tempo" }
        let baseline_bench_bin = if $baseline == "local" { do $local_bin "tempo-bench" } else { worktree-bin $baseline_wt $profile "tempo-bench" }
        let feature_tempo = if $feature == "local" { do $local_bin "tempo" } else { worktree-bin $feature_wt $profile "tempo" }

        # Determine paths (absolute for use inside worktree cd blocks)
        let abs_localnet = ($LOCALNET_DIR | path expand)
        let bloat_file = $"($abs_localnet)/state_bloat.bin"
        let datadir = if $bench_datadir != "" {
            $bench_datadir
        } else if (has-schelk) {
            $"/reth-bench/tempo_($bloat)mb"
        } else {
            $"($abs_localnet)/reth"
        }
        let meta_dir = $"($datadir)/($BENCH_META_SUBDIR)"
        let genesis_accounts = ([$accounts 3] | math max) + 1

        # Mount schelk (or prepare for cp fallback)
        bench-mount

        if $dual_hardfork {
            # ============================================================
            # Dual-hardfork mode: separate genesis + datadir per branch
            # ============================================================
            # Each branch gets its own genesis (with different fork activation
            # times) and its own database subdirectory within the main datadir.
            # Both subdirs are initialized and promoted as virgin snapshots
            # inside the schelk volume, so `bench-recover` restores both at once.
            if not ($abs_localnet | path exists) { mkdir $abs_localnet }

            let baseline_genesis_args = (hardfork-to-genesis-args $baseline_hardfork)
            let feature_genesis_args = (hardfork-to-genesis-args $feature_hardfork)

            let baseline_genesis_path = $"($abs_localnet)/genesis-baseline.json"
            let feature_genesis_path = $"($abs_localnet)/genesis-feature.json"
            let baseline_datadir = $"($datadir)/baseline-db"
            let feature_datadir = $"($datadir)/feature-db"

            # Check if dual-hardfork snapshot is cached
            let marker = (read-bench-marker $datadir)
            let snapshot_ready = (
                not $force
                and $marker != null
                and ($marker.bloat_mib | into int) == $bloat
                and ($marker.accounts | into int) == $genesis_accounts
                and ($marker | get -o baseline_hardfork | default "") == ($baseline_hardfork | str upcase)
                and ($marker | get -o feature_hardfork | default "") == ($feature_hardfork | str upcase)
                and ($"($baseline_datadir)/db" | path exists)
                and ($"($feature_datadir)/db" | path exists)
                and ($"($meta_dir)/genesis-baseline.json" | path exists)
                and ($"($meta_dir)/genesis-feature.json" | path exists)
            )

            if $snapshot_ready {
                cp $"($meta_dir)/genesis-baseline.json" $baseline_genesis_path
                cp $"($meta_dir)/genesis-feature.json" $feature_genesis_path
                print $"Using cached dual-hardfork snapshot \(initialized ($marker.initialized_at)\)"
            } else {
                # Generate two genesis files with different hardfork schedules
                print $"Generating baseline genesis \(latest fork: ($baseline_hardfork)\)..."
                let baseline_genesis_dir = $"($abs_localnet)/genesis-baseline-dir"
                if ($baseline_genesis_dir | path exists) { rm -rf $baseline_genesis_dir }
                mkdir $baseline_genesis_dir
                if $baseline == "local" {
                    cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $baseline_genesis_dir -a $genesis_accounts --no-dkg-in-genesis ...$baseline_genesis_args
                } else {
                    do {
                        cd $baseline_wt
                        cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $baseline_genesis_dir -a $genesis_accounts --no-dkg-in-genesis ...$baseline_genesis_args
                    }
                }
                cp $"($baseline_genesis_dir)/genesis.json" $baseline_genesis_path
                rm -rf $baseline_genesis_dir

                print $"Generating feature genesis \(latest fork: ($feature_hardfork)\)..."
                let feature_genesis_dir = $"($abs_localnet)/genesis-feature-dir"
                if ($feature_genesis_dir | path exists) { rm -rf $feature_genesis_dir }
                mkdir $feature_genesis_dir
                if $feature == "local" {
                    cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $feature_genesis_dir -a $genesis_accounts --no-dkg-in-genesis ...$feature_genesis_args
                } else {
                    # Use feature worktree for feature genesis so it picks up any
                    # new hardfork-related genesis changes from the feature branch
                    do {
                        cd $feature_wt
                        cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $feature_genesis_dir -a $genesis_accounts --no-dkg-in-genesis ...$feature_genesis_args
                    }
                }
                cp $"($feature_genesis_dir)/genesis.json" $feature_genesis_path
                rm -rf $feature_genesis_dir

                # Generate bloat file (shared, fork-agnostic)
                if $bloat > 0 and not ($bloat_file | path exists) {
                    print $"Generating state bloat \(($bloat) MiB\)..."
                    let token_args = ($TIP20_TOKEN_IDS | each { |id| ["--token" $"($id)"] } | flatten)
                    if $baseline == "local" {
                        cargo run -p tempo-xtask --profile $profile -- generate-state-bloat --size $bloat --out $bloat_file ...$token_args
                    } else {
                        do {
                            cd $baseline_wt
                            cargo run -p tempo-xtask --profile $profile -- generate-state-bloat --size $bloat --out $bloat_file ...$token_args
                        }
                    }
                }

                # Initialize both datadirs
                for side in [
                    { name: "baseline", genesis: $baseline_genesis_path, dd: $baseline_datadir, tempo: $baseline_tempo }
                    { name: "feature", genesis: $feature_genesis_path, dd: $feature_datadir, tempo: $feature_tempo }
                ] {
                    bench-clean-datadir $side.dd
                    mkdir $side.dd
                    bench-init-db $side.tempo $side.genesis $side.dd $bloat $bloat_file
                }

                bench-save-and-promote $datadir $meta_dir {
                    bloat_mib: $bloat
                    accounts: $genesis_accounts
                    bench_datadir: $datadir
                    baseline_hardfork: ($baseline_hardfork | str upcase)
                    feature_hardfork: ($feature_hardfork | str upcase)
                } [[$baseline_genesis_path "genesis-baseline.json"] [$feature_genesis_path "genesis-feature.json"]] $bloat $bloat_file

                print "Dual-hardfork databases initialized and promoted."
            }
        } else {
            # ============================================================
            # Standard mode: single genesis + single datadir
            # ============================================================
            let genesis_path_std = $"($abs_localnet)/genesis.json"

            let marker = (read-bench-marker $datadir)
            let snapshot_ready = (
                not $force
                and $marker != null
                and ($marker.bloat_mib | into int) == $bloat
                and ($marker.accounts | into int) == $genesis_accounts
                and ($"($datadir)/db" | path exists)
                and ($"($meta_dir)/genesis.json" | path exists)
            )

            if $snapshot_ready {
                if not ($abs_localnet | path exists) { mkdir $abs_localnet }
                cp $"($meta_dir)/genesis.json" $genesis_path_std
                print $"Using cached virgin snapshot \(initialized ($marker.initialized_at)\)"
            } else {
                # Full init: generate genesis + bloat, init db, promote
                if not ($genesis_path_std | path exists) {
                    if not ($abs_localnet | path exists) { mkdir $abs_localnet }
                    print $"Generating genesis with ($genesis_accounts) accounts from baseline..."
                    if $baseline == "local" {
                        cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $abs_localnet -a $genesis_accounts --no-dkg-in-genesis
                    } else {
                        do {
                            cd $baseline_wt
                            cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $abs_localnet -a $genesis_accounts --no-dkg-in-genesis
                        }
                    }
                }

                if $bloat > 0 and not ($bloat_file | path exists) {
                    print $"Generating state bloat \(($bloat) MiB\) from baseline..."
                    let token_args = ($TIP20_TOKEN_IDS | each { |id| ["--token" $"($id)"] } | flatten)
                    if $baseline == "local" {
                        cargo run -p tempo-xtask --profile $profile -- generate-state-bloat --size $bloat --out $bloat_file ...$token_args
                    } else {
                        do {
                            cd $baseline_wt
                            cargo run -p tempo-xtask --profile $profile -- generate-state-bloat --size $bloat --out $bloat_file ...$token_args
                        }
                    }
                }

                bench-clean-datadir $datadir
                bench-init-db $baseline_tempo $genesis_path_std $datadir $bloat $bloat_file

                bench-save-and-promote $datadir $meta_dir {
                    bloat_mib: $bloat,
                    accounts: $genesis_accounts,
                    bench_datadir: $datadir
                } [[$genesis_path_std "genesis.json"]] $bloat $bloat_file

                print "Database initialized and promoted to virgin baseline."
            }
        }

        # Resolve per-run genesis/datadir based on mode
        let genesis_path = if $dual_hardfork { "" } else { $"($abs_localnet)/genesis.json" }

        # Start observability stack
        if not $no_infra {
            print "Starting observability stack..."
            docker compose -f $"($BENCH_DIR)/docker-compose.yml" up -d
        }

        # Setup kernel permissions for tracy full mode (CPU sampling)
        if $tracy == "full" and (^uname | str trim) == "Linux" {
            print "Configuring system for tracy CPU sampling..."
            # Allow non-root perf event access (required for CPU sampling)
            try { sudo sysctl -w kernel.perf_event_paranoid=-1 } catch { }
            # Mount tracefs with world-readable permissions
            try { sudo mount -t tracefs tracefs /sys/kernel/tracing -o remount,mode=755 } catch { }
            try { sudo chmod -R a+r /sys/kernel/tracing } catch { }
        }

        # B-F-F-B interleaved runs
        let benchmark_id = $"bench-($timestamp)"
        let reference_epoch = ((date now | into int) / 1_000_000_000 | into int)
        let samply_args_list = if $samply_args == "" { [] } else { $samply_args | split row " " }

        let runs = if $dual_hardfork {
            [
                { label: "baseline-1", tempo: $baseline_tempo, git_ref: $baseline_sha, genesis: $"($abs_localnet)/genesis-baseline.json", datadir: $"($datadir)/baseline-db" }
                { label: "feature-1", tempo: $feature_tempo, git_ref: $feature_sha, genesis: $"($abs_localnet)/genesis-feature.json", datadir: $"($datadir)/feature-db" }
                { label: "feature-2", tempo: $feature_tempo, git_ref: $feature_sha, genesis: $"($abs_localnet)/genesis-feature.json", datadir: $"($datadir)/feature-db" }
                { label: "baseline-2", tempo: $baseline_tempo, git_ref: $baseline_sha, genesis: $"($abs_localnet)/genesis-baseline.json", datadir: $"($datadir)/baseline-db" }
            ]
        } else {
            [
                { label: "baseline-1", tempo: $baseline_tempo, git_ref: $baseline_sha, genesis: $genesis_path, datadir: $datadir }
                { label: "feature-1", tempo: $feature_tempo, git_ref: $feature_sha, genesis: $genesis_path, datadir: $datadir }
                { label: "feature-2", tempo: $feature_tempo, git_ref: $feature_sha, genesis: $genesis_path, datadir: $datadir }
                { label: "baseline-2", tempo: $baseline_tempo, git_ref: $baseline_sha, genesis: $genesis_path, datadir: $datadir }
            ]
        }

        for run in $runs {
            # bench-recover restores the entire schelk volume to the promoted
            # virgin state. In dual-hardfork mode this resets both baseline-db
            # and feature-db subdirs at once.
            bench-recover $datadir

            # Merge common node-args with per-side args (baseline-node-args / feature-node-args)
            let run_type = if ($run.label | str starts-with "baseline") { "baseline" } else { "feature" }
            let side_args = if $run_type == "baseline" { $baseline_node_args } else { $feature_node_args }
            let effective_node_args = ([$node_args $side_args] | where { |a| $a != "" } | str join " ")

            (run-bench-single
                --tempo-bin $run.tempo --bench-bin $baseline_bench_bin
                --genesis-path $run.genesis --datadir $run.datadir
                --run-label $run.label --results-dir $results_dir
                --tps $tps --duration $duration --accounts $accounts
                --max-concurrent-requests $max_concurrent_requests
                --weights $weights --preset $preset --bench-args $bench_args
                --loud=$loud --node-args $effective_node_args --bloat $bloat
                --git-ref $run.git_ref --build-profile $profile --benchmark-mode $mode
                --benchmark-id $benchmark_id --reference-epoch $reference_epoch
                --samply=$samply --samply-args $samply_args_list
                --tracy $tracy --tracy-filter $tracy_filter
                --tracy-seconds $tracy_seconds --tracy-offset $tracy_offset
                --tracing-otlp $tracing_otlp)
        }

        # Generate summary report
        let baseline_label = if $dual_hardfork { $"($baseline) \(($baseline_hardfork | str upcase)\)" } else { $baseline }
        let feature_label = if $dual_hardfork { $"($feature) \(($feature_hardfork | str upcase)\)" } else { $feature }
        generate-summary $results_dir $baseline_label $feature_label $bloat $preset $tps $duration --benchmark-id $benchmark_id --reference-epoch $reference_epoch

        # Cleanup worktrees (only those we created)
        if $baseline != "local" or $feature != "local" {
            print "Cleaning up worktrees..."
        }
        if $baseline != "local" { try { git worktree remove --force $baseline_wt } catch { } }
        if $feature != "local" { try { git worktree remove --force $feature_wt } catch { } }

        if not $no_infra {
            docker compose -f $"($BENCH_DIR)/docker-compose.yml" down
        }

        # Upload samply profiles to Firefox Profiler
        if $samply {
            print "\nUploading samply profiles to Firefox Profiler..."
            for run in $runs {
                let profile = $"($results_dir)/profile-($run.label).json.gz"
                let url = (upload-samply-profile $profile)
                if $url != null {
                    $url | save -f $"($results_dir)/profile-($run.label)-url.txt"
                }
            }
        }

        # Upload tracy profiles to R2
        if $tracy != "off" {
            print "\nUploading tracy profiles to R2..."
            for run in $runs {
                let profile = $"($results_dir)/tracy-profile-($run.label).tracy"
                let viewer_url = (upload-tracy-profile $profile $run.label $run.git_ref)
                if $viewer_url != null {
                    $viewer_url | save -f $"($results_dir)/tracy-($run.label)-url.txt"
                }
            }
        }

        restore-system-tuning $tuning_state
        print $"\nComparison complete! Results: ($results_dir)/"
        return
    }

    # ================================================================
    # Single-run mode (existing behavior)
    # ================================================================

    # Start observability stack
    if not $no_infra {
        print "Starting observability stack..."
        docker compose -f $"($BENCH_DIR)/docker-compose.yml" up -d
    }

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
    | append (if $force { ["--reset"] } else { [] })
    | append (if $samply { ["--samply"] } else { [] })
    | append (if $samply_args != "" { [$"--samply-args=\"($samply_args)\""] } else { [] })
    | append (if $loud { ["--loud"] } else { [] })
    | append (if $node_args != "" { [$"--node-args=\"($node_args)\""] } else { [] })
    | append (if $bloat > 0 { ["--bloat" $"($bloat)"] } else { [] })

    # Spawn nodes as a background job (pipe output to show logs)
    let node_cmd_str = ($node_cmd | str join " ")
    print $"  Command: ($node_cmd_str)"
    job spawn { nu -c $node_cmd_str o+e>| lines | each { |line| print $line } }

    # Wait for nodes to be ready
    sleep 2sec
    print "Waiting for nodes to be ready..."
    let rpc_urls = (0..<$num_nodes | each { |i| $"http://localhost:(8545 + $i)" })
    let rpc_timeout = if $bloat > 0 { 600 } else { 120 }
    for url in $rpc_urls {
        wait-for-rpc $url $rpc_timeout
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
    | append (if $bloat > 0 {
        [
            "--mnemonic" "'test test test test test test test test test test test junk'"
            "--existing-recipients"
        ]
    } else { [] })
    | append (if $bench_args != "" { $bench_args | split row " " } else { [] })
    | append ["--node-commit-sha" (git rev-parse HEAD | str trim) "--build-profile" $profile "--benchmark-mode" $mode]

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

    restore-system-tuning $tuning_state
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
        let result = (do { curl -sf $url -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' } | complete)
        if $result.exit_code == 0 {
            let hex = ($result.stdout | from json | get result)
            let block = ($hex | str replace "0x" "" | into int --radix 16)
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
            let args = (build-base-args $genesis_path $datadir $log_dir "0.0.0.0" 8545 9001)
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
    print "  --tracy <MODE>           Tracy profiling: off (default), on, full"
    print "  --tracy-filter <FILTER>  Tracy tracing filter level (default: debug)"
    print "  --tracy-seconds <N>      Tracy capture duration limit in seconds (default: 30, 0 = unlimited)"
    print "  --tracy-offset <N>       Seconds to wait before starting tracy capture (default: 120)"
    print "  --tracing-otlp <URL>     OTLP endpoint for tracing (auto-derived from TEMPO_TELEMETRY_URL if not set)"
    print "  --reset                  Reset localnet before starting"
    print "  --loud                   Show all node logs (WARN/ERROR shown by default)"
    print $"  --profile <P>            Cargo profile \(default: ($DEFAULT_PROFILE)\)"
    print $"  --features <F>           Cargo features \(default: ($DEFAULT_FEATURES)\)"
    print "  --node-args <ARGS>       Additional node arguments (space-separated, all runs)"
    print "  --baseline-node-args <ARGS>  Additional node arguments for baseline runs only"
    print "  --feature-node-args <ARGS>   Additional node arguments for feature runs only"
    print "  --bench-args <ARGS>      Additional tempo-bench arguments (space-separated)"
    print "  --bloat <N>              Generate TIP20 state bloat (size in MiB)"
    print ""
    print "Localnet flags:"
    print "  --mode <dev|consensus>   Mode (default: dev)"
    print "  --nodes <N>              Number of validators for consensus (default: 3)"
    print "  --accounts <N>           Genesis accounts (default: 1000)"
    print "  --bloat <N>              Generate TIP20 state bloat (size in MiB)"
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
    print "  nu tempo.nu localnet --mode dev --bloat 1024 --reset"
    print "  nu tempo.nu localnet --mode consensus --nodes 3"
    print ""
    print "Port assignments (consensus mode, per node N=0,1,2...):"
    print "  Consensus:     8000 + N*100"
    print "  P2P:           8001 + N*100"
    print "  Metrics:       8002 + N*100"
    print "  AuthRPC:       8003 + N*100"
    print "  Discv5:        8004 + N*100"
    print "  HTTP RPC:      8545 + N"
    print "  Reth Metrics:  9001 + N"
}
