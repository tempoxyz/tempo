#!/usr/bin/env nu

# Tempo local utilities

source contrib/bench/txgen/helpers.nu

const BENCH_DIR = "contrib/bench"
const LOCALNET_DIR = "localnet"
const LOGS_DIR = "contrib/bench/logs"
const RUSTFLAGS = "-C target-cpu=native"
const DEFAULT_PROFILE = "profiling"
const DEFAULT_FEATURES = "jemalloc,asm-keccak"
const BENCH_WORKTREES_DIR = ".bench-worktrees"
const BENCH_RESULTS_DIR = "bench-results"
const MINIO_BUCKET = "minio/tempo-binaries"
const BENCH_META_SUBDIR = ".bench-meta"
const LOCALNET_SIGNING_KEY_SECRET = "tempo-localnet-signing-key-secret"

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
    if $loud { [] } else { ["--log.stdout.filter" "info"] }
}

def prepare-localnet-consensus-secret-fifo [node_dir: string] {
    let secret_path = $"($node_dir)/consensus-secret.fifo"
    rm -f $secret_path
    mkfifo $secret_path
    chmod 600 $secret_path
    $secret_path
}

def start-localnet-consensus-secret-writer [secret_path: string] {
    job spawn { $"($LOCALNET_SIGNING_KEY_SECRET)\n" | save -f $secret_path } | ignore
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
# so we only need to append "tracy" here.
def tracy-build-config [features: string, tracy: string] {
    if $tracy == "off" {
        { features: $features, extra_rustflags: "" }
    } else {
        let tracy_features = if $features == "" { "tracy" } else { $"($features),tracy" }
        { features: $tracy_features, extra_rustflags: " -C force-frame-pointers=yes" }
    }
}

def cargo-feature-args [features: string, no_default_features: bool] {
    let no_default_args = if $no_default_features { ["--no-default-features"] } else { [] }
    let feature_args = if $features == "" { [] } else { ["--features" $features] }
    $no_default_args | append $feature_args
}

# Validate mode is either "dev" or "consensus"
def validate-mode [mode: string] {
    if $mode != "dev" and $mode != "consensus" {
        print $"Unknown mode: ($mode). Use 'dev' or 'consensus'."
        exit 1
    }
}

# Build tempo binary with cargo
def build-tempo [bins: list<string>, profile: string, features: string, --no-default-features, --extra-rustflags: string = ""] {
    let bin_args = ($bins | each { |bin| ["--bin" $bin] } | flatten)
    let feature_args = (cargo-feature-args $features $no_default_features)
    let build_cmd = ["cargo" "build" "--profile" $profile]
        | append $feature_args
        | append $bin_args
    let rustflags = $"($RUSTFLAGS)($extra_rustflags)"
    print $"Building ($bins | str join ', '): `($build_cmd | str join ' ')`..."
    with-env { RUSTFLAGS: $rustflags } {
        run-external ($build_cmd | first) ...($build_cmd | skip 1)
    }
}

def tempo-xtask-bin [profile: string] {
    if $profile == "dev" {
        "./target/debug/tempo-xtask"
    } else {
        $"./target/($profile)/tempo-xtask"
    }
}

def build-tempo-xtask [profile: string] {
    let build_cmd = ["cargo" "build" "-p" "tempo-xtask" "--profile" $profile]
    print $"Building tempo-xtask: `($build_cmd | str join ' ')`..."
    run-external ($build_cmd | first) ...($build_cmd | skip 1)
}

def run-tempo-xtask [profile: string, skip_build: bool, args: list<string>] {
    if $skip_build {
        let xtask_bin = (tempo-xtask-bin $profile)
        if not ($xtask_bin | path exists) {
            print $"Error: --skip-build requires ($xtask_bin). Build it first with `cargo build -p tempo-xtask --profile ($profile)`."
            exit 1
        }
        run-external $xtask_bin ...$args
    } else {
        let run_cmd = ["cargo" "run" "-p" "tempo-xtask" "--profile" $profile "--"]
            | append $args
        run-external ($run_cmd | first) ...($run_cmd | skip 1)
    }
}

# Find tempo node process PIDs.
def find-tempo-pids [] {
    ps | where name =~ '(^|/)tempo$' | get pid
}

# Initialize node with state bloat
# 1. Run `tempo init` to create the database
# 2. Generate state bloat binary file
# 3. Run `tempo init-from-binary-dump` to load the bloat
# Generate the bloat binary file once (skips if already exists)
def generate-bloat-file [bloat_size: int, profile: string, skip_build: bool] {
    let bloat_file = $"($LOCALNET_DIR)/state_bloat.bin"
    if ($bloat_file | path exists) {
        print $"State bloat file already exists \(($bloat_size) MiB\)"
        return
    }
    print $"Generating state bloat \(($bloat_size) MiB\)..."
    let token_args = ($TIP20_TOKEN_IDS | each { |id| ["--token" $"($id)"] } | flatten)
    run-tempo-xtask $profile $skip_build ["generate-state-bloat" "--size" $"($bloat_size)" "--out" $bloat_file ...$token_args]
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

const TEMPO_DISABLED_HARDFORK_TIME = 9223372036854775807

def tempo-hardforks [] {
    let forks = (
        open crates/node/tests/assets/test-genesis.json
        | get config
        | columns
        | where { |key| $key =~ '^t[0-9]+[a-z]?Time$' }
        | each { |key| $key | str replace "Time" "" | str upcase }
    )
    if ($forks | is-empty) {
        print "Error: failed to read Tempo hardforks from crates/node/tests/assets/test-genesis.json"
        exit 1
    }
    $forks
}

def normalize-hardfork [fork: string] {
    let hardforks = (tempo-hardforks)
    let fork_upper = ($fork | str upcase)
    let idx = ($hardforks | enumerate | where item == $fork_upper)
    if ($idx | length) == 0 {
        print $"Error: unknown hardfork '($fork)'. Valid: ($hardforks | str join ', ')"
        exit 1
    }
    $fork_upper
}

def hardfork-index [fork: string] {
    let fork_upper = (normalize-hardfork $fork)
    (tempo-hardforks | enumerate | where item == $fork_upper | get 0.index)
}

def latest-tempo-hardfork [] {
    tempo-hardforks | last
}

def highest-hardfork [forks: list<string>] {
    if ($forks | length) == 0 {
        return (latest-tempo-hardfork)
    }
    mut highest = (normalize-hardfork ($forks | first))
    for fork in ($forks | skip 1) {
        let current = (normalize-hardfork $fork)
        if (hardfork-index $current) > (hardfork-index $highest) {
            $highest = $current
        }
    }
    $highest
}

def hardfork-genesis-config-fields [fork: string] {
    let cutoff = (hardfork-index $fork)
    tempo-hardforks | enumerate | each { |it|
        {
            fork: $it.item
            name: $"($it.item | str downcase)Time"
            value: (if $it.index <= $cutoff { 0 } else { $TEMPO_DISABLED_HARDFORK_TIME })
        }
    }
}

# Map a hardfork name to generate-genesis CLI args.
# Forks up to and including the given fork are active at genesis (time=0).
# Forks after are disabled (time=max u64).
# Returns a list of CLI flag strings, e.g. ["--t0-time" "0" "--t1-time" "0" "--t1a-time" "9223372036854775807" ...]
def hardfork-to-genesis-args [fork: string] {
    hardfork-genesis-config-fields $fork | each { |it|
        let flag = $"--($it.fork | str downcase)-time"
        let time = ($it.value | into string)
        [$flag $time]
    } | flatten
}

# Resolve a git ref to a full commit SHA
def resolve-git-ref [ref: string] {
    git rev-parse $ref | str trim
}

# Resolve a SHA to a human-readable label: tag > branch > fallback.
def resolve-git-ref-label [sha: string, fallback: string] {
    let tag = (git tag --points-at $sha | lines | first | default "")
    if $tag != "" {
        return $tag
    }
    let branch = (git branch -r --points-at $sha | lines | first | default "" | str replace -r '^\s*origin/' '')
    if $branch != "" {
        return $branch
    }
    $fallback
}

def bench-cache-key [commit_sha: string, features: string, no_default_features: bool] {
    if (not $no_default_features) and $features == $DEFAULT_FEATURES {
        return $commit_sha
    }

    let feature_key = if $features == "" {
        "none"
    } else {
        $features
        | str replace -a "," "_"
        | str replace -a "/" "_"
        | str replace -a " " "_"
    }

    let mode_key = if $no_default_features { "no-default" } else { "features" }
    $"($commit_sha)-($mode_key)-($feature_key)"
}

# Try to download cached binaries from MinIO for a given commit SHA.
# Returns true on cache hit, false on miss or any failure.
def try-cache-download [worktree_dir: string, profile: string, commit_sha: string, cache_key: string] {
    if not (has-mc) { return false }

    let bins = ["tempo"]
    # Check that all binaries exist in the cache
    for bin in $bins {
        let remote = $"($MINIO_BUCKET)/($cache_key)/($bin)"
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
        let remote = $"($MINIO_BUCKET)/($cache_key)/($bin)"
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
def cache-upload [worktree_dir: string, profile: string, commit_sha: string, cache_key: string] {
    if not (has-mc) { return }

    let target_dir = if $profile == "dev" {
        $"($worktree_dir)/target/debug"
    } else {
        $"($worktree_dir)/target/($profile)"
    }

    for bin in ["tempo"] {
        let local = $"($target_dir)/($bin)"
        let remote = $"($MINIO_BUCKET)/($cache_key)/($bin)"
        print $"Uploading ($bin) to cache for ($commit_sha | str substring 0..8)..."
        try {
            mc cp $local $remote
        } catch {
            print $"Warning: failed to upload ($bin) to cache"
        }
    }
}

# Build tempo binary in a git worktree (with optional MinIO cache)
def build-in-worktree [worktree_dir: string, ref: string, profile: string, features: string, commit_sha: string, --no-cache, --no-default-features, --extra-rustflags: string = "", --bench-features: string = ""] {
    let cache_key = (bench-cache-key $commit_sha $features $no_default_features)

    # Try cache first
    if not $no_cache and (try-cache-download $worktree_dir $profile $commit_sha $cache_key) {
        return
    }

    print $"Building tempo for ($ref) in ($worktree_dir)..."
    let rustflags = $"($RUSTFLAGS)($extra_rustflags)"
    let feature_args = (cargo-feature-args $features $no_default_features)
    let build_cmd = ["cargo" "build" "--profile" $profile]
        | append $feature_args
        | append ["--bin" "tempo"]
    with-env { RUSTFLAGS: $rustflags } {
        do { cd $worktree_dir; run-external ($build_cmd | first) ...($build_cmd | skip 1) }
    }

    # Upload to cache
    cache-upload $worktree_dir $profile $commit_sha $cache_key
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

def parse-cli-args [args: string] {
    mut result = []
    mut current = ""
    mut quote = ""
    mut escaped = false
    mut token_started = false

    for ch in ($args | split chars) {
        if $escaped {
            $current = $"($current)($ch)"
            $escaped = false
            $token_started = true
            continue
        }
        if $ch == "\\" {
            $escaped = true
            $token_started = true
            continue
        }
        if $quote != "" {
            if $ch == $quote {
                $quote = ""
            } else {
                $current = $"($current)($ch)"
            }
            $token_started = true
            continue
        }
        if $ch == "'" or $ch == '"' {
            $quote = $ch
            $token_started = true
            continue
        }
        if $ch in [" " "\t" "\n" "\r"] {
            if $token_started {
                $result = ($result | append $current)
                $current = ""
                $token_started = false
            }
            continue
        }
        $current = $"($current)($ch)"
        $token_started = true
    }

    if $escaped {
        $current = $"($current)('\')"
    }
    if $quote != "" {
        print $"Error: unterminated quote in args: ($args)"
        exit 1
    }
    if $token_started {
        $result = ($result | append $current)
    }
    $result
}

# Run a single benchmark run (start node, run bench, stop node, collect report)
def run-bench-single [
    --tempo-bin: string
    --txgen-tempo-bin: string
    --txgen-bench-bin: string
    --rpc-urls: string
    --metrics-url: list<string>
    --genesis-path: string
    --datadir: string
    --run-label: string
    --results-dir: string
    --tps: int
    --duration: int
    --accounts: int
    --max-concurrent-requests: int
    --preset-path: string
    --bench-args: string = ""
    --loud
    --node-args: string = ""
    --extra-env: string = ""
    --bench-env: string = ""
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

    let run_type = if ($run_label | str starts-with "baseline") { "baseline" } else { "feature" }

    # Parse extra node args
    let extra_args = (parse-cli-args $node_args)

    # Build node arguments, then dedup so user-provided args override defaults
    let base_args = (build-base-args $genesis_path $datadir $log_dir "0.0.0.0" 8545 9001)
        | append (build-dev-args)
        | append (log-filter-args $loud)
        | append (if $tracy != "off" { ["--log.tracy" "--log.tracy.filter" $tracy_filter] } else { [] })
        | append (if $tracing_otlp != "" { [$"--tracing-otlp=($tracing_otlp)"] } else { [] })
    let args = (dedup-args $base_args $extra_args)

    # Tracy environment variables
    let tracy_env_prefix = if $tracy == "tracy" {
        "TRACY_SAMPLING_HZ=18999 "
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
    let env_prefix = if $extra_env != "" { $"($extra_env) " } else { "" }
    print $"  Starting node: ($tempo_bin | path basename)($profiling_label)"
    job spawn { sh -c $"($env_prefix)($otel_attrs)($tracy_env_prefix)($node_cmd_str) 2>&1" | lines | each { |line| print $"[($run_label)] ($line)" } }

    # Wait for RPC
    sleep 2sec
    let rpc_timeout = if $bloat > 0 { 600 } else { 120 }
    wait-for-rpc "http://localhost:8545" $rpc_timeout

    # Start tracy-capture after RPC is ready (node must be running for connection)
    # If tracy-offset > 0, delay the capture start in a background job so txgen isn't blocked
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

    print $"  Running txgen benchmark..."
    let report_path = $"($results_dir)/report-($run_label).json"
    let bench_result = (try {
        let result = (txgen-run-preset-pipeline
            --txgen-tempo-bin $txgen_tempo_bin
            --txgen-bench-bin $txgen_bench_bin
            --preset-path $preset_path
            --generate-rpc-url "http://localhost:8545"
            --submit-rpc-url $rpc_urls
            --metrics-url $metrics_url
            --report-path $report_path
            --tps $tps
            --duration $duration
            --accounts $accounts
            --max-concurrent-requests $max_concurrent_requests
            --bench-args $bench_args
            --bench-env $bench_env
            --git-ref $git_ref
            --build-profile $build_profile
            --benchmark-mode $benchmark_mode
            --bloat-mib $bloat
            --bloat-token-count ($TIP20_TOKEN_IDS | length)
            --skip-funding=($bloat > 0))
        if not $result.ok {
            print $"  Benchmark run ($run_label) failed with exit code ($result.exit_code)"
        }
        $result
    } catch { |e|
        print $"  Benchmark run ($run_label) failed: ($e.msg)"
        { ok: false, exit_code: 1, report_path: $report_path }
    })
    let bench_failed = not $bench_result.ok

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

    print $"=== Run ($run_label) complete ==="
    if $bench_failed {
        error make { msg: $"Benchmark run ($run_label) failed" }
    }
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

# Upload a tracy profile (.tracy) to R2 via mc and return the viewer and raw profile URLs.
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
    let remote_profile_path = $"/profiles/($remote_name)"

    try {
        mc cp $profile_path $"($mc_alias)/tracy/profiles/($remote_name)"
        let viewer_url = $"($viewer_base)?profile_url=($remote_profile_path)"
        let profile_url = $"($viewer_base)($remote_profile_path)"
        print $"  ($label): ($viewer_url)"
        # Delete large .tracy file after upload to free disk
        rm $profile_path
        { viewer_url: $viewer_url, profile_url: $profile_url }
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

def iso-from-epoch-ms [epoch_ms: int] {
    let seconds = ($epoch_ms / 1000 | into int)
    let millis = ($epoch_ms mod 1000 | into int)
    let base = (^date -u -d $"@($seconds)" "+%Y-%m-%dT%H:%M:%S")
    $"($base).($millis | into string | fill --alignment right --character '0' --width 3)Z"
}

def grafana-performance-url [benchmark_id: string, from_ms: int, to_ms: int] {
    if $benchmark_id == "" or $from_ms <= 0 or $to_ms <= 0 {
        return ""
    }

    let from = (iso-from-epoch-ms $from_ms)
    let to = (iso-from-epoch-ms $to_ms)
    $"https://tempoxyz.grafana.net/d/performance/performance?orgId=1&from=($from)&to=($to)&timezone=browser&var-datasource=efk1hcn87dnnkd&var-filter_label=benchmark_id&var-filter_value=($benchmark_id)&var-group_by=benchmark_run"
}

def internal-perf-url [clickhouse_run_id: string] {
    if $clickhouse_run_id == "" {
        return ""
    }

    $"http://go/dev/tempo-internal-perf/benchmark/($clickhouse_run_id)"
}


def generate-summary [
    results_dir: string,
    baseline_ref: string,
    feature_ref: string,
    bloat: int,
    preset: string,
    tps: int,
    duration: int,
    --benchmark-id: string = "",
    --reference-epoch: int = 0,
    --baseline-hardfork: string = "",
    --feature-hardfork: string = "",
    --summary-warmup-blocks: int = 0,
] {
    if $summary_warmup_blocks < 0 {
        error make { msg: "--summary-warmup-blocks must be non-negative" }
    }

    let run_order_path = $"($results_dir)/run-order.txt"
    let candidate_run_labels = if ($run_order_path | path exists) {
        open $run_order_path | lines | where { |label| $label != "" }
    } else {
        ["baseline-1" "feature-1" "feature-2" "baseline-2"]
    }
    let run_labels = ($candidate_run_labels | where { |label| ($"($results_dir)/report-($label).json" | path exists) })
    mut run_data = []
    mut baseline_blocks = []
    mut feature_blocks = []
    mut baseline_intervals = []
    mut feature_intervals = []
    mut baseline_builder_latency_values = []
    mut feature_builder_latency_values = []
    mut baseline_builder_finish_samples = []
    mut feature_builder_finish_samples = []
    mut baseline_builder_pool_fetch_samples = []
    mut feature_builder_pool_fetch_samples = []
    mut baseline_builder_invalid_tx_execution_attempts_samples = []
    mut feature_builder_invalid_tx_execution_attempts_samples = []
    mut baseline_builder_invalid_tx_skips = []
    mut feature_builder_invalid_tx_skips = []
    mut baseline_builder_nonce_too_low_skips = []
    mut feature_builder_nonce_too_low_skips = []
    mut baseline_builder_fill_idle_samples = []
    mut feature_builder_fill_idle_samples = []
    mut baseline_validation_latency_values = []
    mut feature_validation_latency_values = []
    mut baseline_builder_gas_values = []
    mut feature_builder_gas_values = []
    mut baseline_validation_gas_values = []
    mut feature_validation_gas_values = []
    mut baseline_serialized_block_size_values = []
    mut feature_serialized_block_size_values = []
    mut baseline_serialized_block_size_per_tx_values = []
    mut feature_serialized_block_size_per_tx_values = []

    let compute_block_time_stats = { |intervals: list<any>|
        let sorted_intervals = ($intervals | sort)
        {
            p50: (percentile $sorted_intervals 50 | math round --precision 1)
            p90: (percentile $sorted_intervals 90 | math round --precision 1)
            p99: (percentile $sorted_intervals 99 | math round --precision 1)
        }
    }

    let compute_value_stats = { |values: list<any>|
        let sorted_values = ($values | where { |value| $value != null } | sort)
        {
            n: ($sorted_values | length)
            p50: (percentile $sorted_values 50 | math round --precision 1)
            p90: (percentile $sorted_values 90 | math round --precision 1)
            p99: (percentile $sorted_values 99 | math round --precision 1)
        }
    }

    let compute_value_mean = { |values: list<any>|
        let clean_values = ($values | where { |value| $value != null })
        if ($clean_values | length) > 0 { $clean_values | math avg | math round --precision 0 } else { 0.0 }
    }

    let paired_ratio_values = { |numerators: list<any>, denominators: list<any>, label: string|
        let numerator_len = ($numerators | length)
        let denominator_len = ($denominators | length)
        if $numerator_len != $denominator_len {
            print $"Warning: mismatched serialized block size and transaction count samples in ($label): ($numerator_len) sizes, ($denominator_len) counts"
        }
        let len = [$numerator_len $denominator_len] | math min
        if $len <= 0 {
            []
        } else {
            0..<$len | each { |idx|
                let denominator = ($denominators | get $idx)
                if $denominator > 0 {
                    ($numerators | get $idx) / $denominator
                } else { null }
            } | where { |value| $value != null }
        }
    }

    let counter_delta_values = { |samples: list<any>, metric: string, scale: float|
        let sum_name = $"($metric)_sum"
        let count_name = $"($metric)_count"
        let counter_samples = ($samples | where { |sample| $sample.name in [$sum_name $count_name] })
        $counter_samples
            | group-by { |sample| $sample.labels | to json --raw }
            | transpose labels samples
            | each { |series|
                let points = (
                    $series.samples
                        | group-by unix_ms
                        | transpose unix_ms samples
                        | each { |point|
                            let sum_values = ($point.samples | where name == $sum_name | get value)
                            let count_values = ($point.samples | where name == $count_name | get value)
                            if (($sum_values | length) > 0) and (($count_values | length) > 0) {
                                {
                                    unix_ms: ($point.unix_ms | into int)
                                    sum: ($sum_values | first)
                                    count: ($count_values | first)
                                }
                            } else { null }
                        }
                        | where { |point| $point != null }
                        | sort-by unix_ms
                )
                if ($points | length) > 1 {
                    $points
                        | window 2
                        | each { |pair|
                            let prev = ($pair | first)
                            let curr = ($pair | last)
                            let delta_count = (($curr.count - $prev.count) | into int)
                            let delta_sum = ($curr.sum - $prev.sum)
                            if $delta_count > 0 and $delta_sum >= 0 {
                                let value = (($delta_sum / $delta_count) * $scale)
                                0..<$delta_count | each { $value }
                            } else { [] }
                        }
                        | flatten
                } else { [] }
            }
            | flatten
    }

    let optional_counter_values = { |values: list<any>, label: string, metric: string|
        if ($values | length) == 0 {
            print $"Warning: no counter delta samples for optional metric ($metric) in ($label)"
        }
        $values
    }

    let counter_delta_total = { |samples: list<any>, metric: string|
        let counter_samples = ($samples | where name == $metric)
        if ($counter_samples | length) == 0 {
            0.0
        } else {
            let deltas = (
                $counter_samples
                    | group-by { |sample| $sample.labels | to json --raw }
                    | transpose labels samples
                    | each { |series|
                        let points = (
                            $series.samples
                                | where { |sample| ($sample | get -o value | default null) != null }
                                | sort-by unix_ms
                        )
                        if ($points | length) > 1 {
                            let first = ($points | first)
                            let last = ($points | last)
                            let delta = ($last.value - $first.value)
                            if $delta >= 0 { $delta } else { $last.value }
                        } else { 0.0 }
                    }
            )
            if ($deltas | length) > 0 { $deltas | math sum | math round --precision 0 } else { 0.0 }
        }
    }

    let metric_sample_names = [
        "reth_tempo_payload_builder_payload_finalization_duration_seconds_sum"
        "reth_tempo_payload_builder_payload_finalization_duration_seconds_count"
        "reth_tempo_payload_builder_pool_fetch_duration_seconds_sum"
        "reth_tempo_payload_builder_pool_fetch_duration_seconds_count"
        "reth_tempo_payload_builder_invalid_pool_transaction_execution_attempts_sum"
        "reth_tempo_payload_builder_invalid_pool_transaction_execution_attempts_count"
        "reth_tempo_payload_builder_pool_transactions_skipped_total"
        "reth_tempo_payload_builder_normal_transaction_fill_idle_duration_seconds_sum"
        "reth_tempo_payload_builder_normal_transaction_fill_idle_duration_seconds_count"
        "reth_tempo_payload_builder_payload_build_duration_seconds_sum"
        "reth_tempo_payload_builder_payload_build_duration_seconds_count"
        "reth_consensus_engine_beacon_new_payload_latency_sum"
        "reth_consensus_engine_beacon_new_payload_latency_count"
        "reth_tempo_payload_builder_gas_per_second_sum"
        "reth_tempo_payload_builder_gas_per_second_count"
        "reth_consensus_engine_beacon_new_payload_gas_per_second_sum"
        "reth_consensus_engine_beacon_new_payload_gas_per_second_count"
        "reth_tempo_payload_builder_total_transactions_sum"
        "reth_tempo_payload_builder_total_transactions_count"
        "reth_tempo_payload_builder_rlp_block_size_bytes_sum"
        "reth_tempo_payload_builder_rlp_block_size_bytes_count"
    ]
    let metric_sample_match_args = ($metric_sample_names | each { |name| ["-e" $name] } | flatten)
    let has_rg = ((which rg | length) > 0)

    let load_metric_samples = { |samples_path: string, samples_gz_path: string|
        let filter_result = if ($samples_path | path exists) {
            if $has_rg {
                rg --fixed-strings --no-heading --no-filename --color never ...$metric_sample_match_args $samples_path | complete
            } else {
                grep -F ...$metric_sample_match_args $samples_path | complete
            }
        } else if ($samples_gz_path | path exists) {
            if $has_rg {
                gzip -dc $samples_gz_path | rg --fixed-strings --no-heading --no-filename --color never ...$metric_sample_match_args | complete
            } else {
                gzip -dc $samples_gz_path | grep -F ...$metric_sample_match_args | complete
            }
        } else {
            { stdout: "", stderr: "", exit_code: 0 }
        }

        if $filter_result.exit_code not-in [0 1] {
            error make { msg: $"Failed to filter metric samples from ($samples_path): ($filter_result.stderr)" }
        }

        if $filter_result.stdout != "" {
            $filter_result.stdout
                | lines
                | where { |line| ($line | str trim) != "" }
                | each { |line| $line | from json }
                | where { |sample| $sample.name in $metric_sample_names }
                | where { |sample|
                    let quantile = ($sample.labels | get -o quantile | default "")
                    ($quantile in ["0.5" "0.9" "0.99"]) or ($quantile == "")
                }
        } else { [] }
    }

    for label in $run_labels {
        let report_path = $"($results_dir)/report-($label).json"
        if not ($report_path | path exists) {
            print $"Warning: ($report_path) not found, skipping"
            continue
        }
        let report = (open $report_path)
        let report_blocks = ($report | get blocks | each { |b|
            let tx_count = ($b | get tx_count)
            let timestamp = if (($b | get -o timestamp | default null) != null) {
                $b | get timestamp
            } else {
                $b | get timestamp_ms
            }
            {
                number: ($b | get number)
                timestamp: $timestamp
                tx_count: $tx_count
                ok_count: ($b | get -o ok_count | default $tx_count)
                err_count: ($b | get -o err_count | default 0)
                gas_used: ($b | get gas_used)
                block_time_ms: ($b | get -o block_time_ms | default null)
            }
        })
        if ($report_blocks | length) == 0 {
            print $"Warning: ($label) report has no blocks, skipping"
            continue
        }

        let sorted_blocks = ($report_blocks | sort-by timestamp)
        let warmup_blocks = ([$summary_warmup_blocks ($sorted_blocks | length)] | math min)
        let blocks = ($sorted_blocks | skip $warmup_blocks)
        if ($blocks | length) == 0 {
            print $"Warning: ($label) report has no summary blocks after excluding ($warmup_blocks) warmup blocks, skipping"
            continue
        }

        let first_report_block_ms = ($sorted_blocks | first | get timestamp)
        let timestamps = ($blocks | get timestamp)
        let summary_from_ms = ($timestamps | first)
        let summary_from_offset_ms = $summary_from_ms - $first_report_block_ms
        let block_interval_blocks = if $warmup_blocks > 0 { $blocks | skip 1 } else { $blocks }
        let block_intervals = ($block_interval_blocks | where block_time_ms != null | get block_time_ms)

        let samples_path = $"($results_dir)/report-($label).samples.ndjson"
        let samples_gz_path = $"($samples_path).gz"
        let raw_metric_samples = (do $load_metric_samples $samples_path $samples_gz_path)
        let metric_samples = if $warmup_blocks > 0 {
            $raw_metric_samples | where { |sample|
                let offset_ms = ($sample | get -o offset_ms | default null)
                if $offset_ms != null {
                    ($offset_ms | into int) >= $summary_from_offset_ms
                } else {
                    let unix_ms = ($sample | get -o unix_ms | default 0 | into int)
                    $unix_ms >= $summary_from_ms
                }
            }
        } else {
            $raw_metric_samples
        }
        let optional_counter_metric_values = { |metric: string, scale: float|
            do $optional_counter_values (do $counter_delta_values $metric_samples $metric $scale) $label $metric
        }
        let builder_latency_values = (do $optional_counter_metric_values "reth_tempo_payload_builder_payload_build_duration_seconds" 1000.0)
        let builder_finish_samples = (do $optional_counter_metric_values "reth_tempo_payload_builder_payload_finalization_duration_seconds" 1000.0)
        let builder_pool_fetch_samples = (do $optional_counter_metric_values "reth_tempo_payload_builder_pool_fetch_duration_seconds" 1000.0)
        let builder_invalid_tx_execution_attempts_samples = (do $optional_counter_metric_values "reth_tempo_payload_builder_invalid_pool_transaction_execution_attempts" 1.0)
        let builder_pool_tx_skip_samples = ($metric_samples | where name == "reth_tempo_payload_builder_pool_transactions_skipped_total")
        let builder_pool_tx_skips_for_reason = { |reason: string|
            let samples = (
                $builder_pool_tx_skip_samples
                    | where { |sample| ($sample.labels | get -o reason | default "") == $reason }
            )
            do $counter_delta_total $samples "reth_tempo_payload_builder_pool_transactions_skipped_total"
        }
        let builder_invalid_tx_skips = do $builder_pool_tx_skips_for_reason "invalid_tx"
        let builder_nonce_too_low_skips = do $builder_pool_tx_skips_for_reason "nonce_too_low"
        let builder_fill_idle_samples = (do $optional_counter_metric_values "reth_tempo_payload_builder_normal_transaction_fill_idle_duration_seconds" 1000.0)
        let validation_latency_values = (do $optional_counter_metric_values "reth_consensus_engine_beacon_new_payload_latency" 1000.0)
        let builder_gas_values = (do $optional_counter_metric_values "reth_tempo_payload_builder_gas_per_second" 1.0)
        let validation_gas_values = (do $optional_counter_metric_values "reth_consensus_engine_beacon_new_payload_gas_per_second" 1.0)
        let serialized_block_size_values = (do $optional_counter_metric_values "reth_tempo_payload_builder_rlp_block_size_bytes" 1.0)
        let serialized_block_tx_count_values = (do $optional_counter_metric_values "reth_tempo_payload_builder_total_transactions" 1.0)
        let serialized_block_size_per_tx_values = do $paired_ratio_values $serialized_block_size_values $serialized_block_tx_count_values $label

        let run_bt = do $compute_block_time_stats $block_intervals

        # Collect blocks into baseline/feature groups
        if ($label | str starts-with "baseline") {
            $baseline_blocks = ($baseline_blocks | append $blocks)
            $baseline_intervals = ($baseline_intervals | append $block_intervals)
            $baseline_builder_latency_values = ($baseline_builder_latency_values | append $builder_latency_values)
            $baseline_builder_finish_samples = ($baseline_builder_finish_samples | append $builder_finish_samples)
            $baseline_builder_pool_fetch_samples = ($baseline_builder_pool_fetch_samples | append $builder_pool_fetch_samples)
            $baseline_builder_invalid_tx_execution_attempts_samples = ($baseline_builder_invalid_tx_execution_attempts_samples | append $builder_invalid_tx_execution_attempts_samples)
            $baseline_builder_invalid_tx_skips = ($baseline_builder_invalid_tx_skips | append $builder_invalid_tx_skips)
            $baseline_builder_nonce_too_low_skips = ($baseline_builder_nonce_too_low_skips | append $builder_nonce_too_low_skips)
            $baseline_builder_fill_idle_samples = ($baseline_builder_fill_idle_samples | append $builder_fill_idle_samples)
            $baseline_validation_latency_values = ($baseline_validation_latency_values | append $validation_latency_values)
            $baseline_builder_gas_values = ($baseline_builder_gas_values | append $builder_gas_values)
            $baseline_validation_gas_values = ($baseline_validation_gas_values | append $validation_gas_values)
            $baseline_serialized_block_size_values = ($baseline_serialized_block_size_values | append $serialized_block_size_values)
            $baseline_serialized_block_size_per_tx_values = ($baseline_serialized_block_size_per_tx_values | append $serialized_block_size_per_tx_values)
        } else {
            $feature_blocks = ($feature_blocks | append $blocks)
            $feature_intervals = ($feature_intervals | append $block_intervals)
            $feature_builder_latency_values = ($feature_builder_latency_values | append $builder_latency_values)
            $feature_builder_finish_samples = ($feature_builder_finish_samples | append $builder_finish_samples)
            $feature_builder_pool_fetch_samples = ($feature_builder_pool_fetch_samples | append $builder_pool_fetch_samples)
            $feature_builder_invalid_tx_execution_attempts_samples = ($feature_builder_invalid_tx_execution_attempts_samples | append $builder_invalid_tx_execution_attempts_samples)
            $feature_builder_invalid_tx_skips = ($feature_builder_invalid_tx_skips | append $builder_invalid_tx_skips)
            $feature_builder_nonce_too_low_skips = ($feature_builder_nonce_too_low_skips | append $builder_nonce_too_low_skips)
            $feature_builder_fill_idle_samples = ($feature_builder_fill_idle_samples | append $builder_fill_idle_samples)
            $feature_validation_latency_values = ($feature_validation_latency_values | append $validation_latency_values)
            $feature_builder_gas_values = ($feature_builder_gas_values | append $builder_gas_values)
            $feature_validation_gas_values = ($feature_validation_gas_values | append $validation_gas_values)
            $feature_serialized_block_size_values = ($feature_serialized_block_size_values | append $serialized_block_size_values)
            $feature_serialized_block_size_per_tx_values = ($feature_serialized_block_size_per_tx_values | append $serialized_block_size_per_tx_values)
        }

        let total_tx = ($blocks | get tx_count | math sum)
        let total_ok = ($blocks | get ok_count | math sum)
        let total_err = ($blocks | get err_count | math sum)
        let total_gas = ($blocks | get gas_used | math sum)
        let block_time_mean = if ($block_intervals | length) > 0 { $block_intervals | math avg | math round --precision 1 } else { 0.0 }
        let num_blocks = ($blocks | length)
        let run_builder = do $compute_value_stats $builder_latency_values
        let run_validation = do $compute_value_stats $validation_latency_values
        let run_builder_gas = do $compute_value_mean $builder_gas_values
        let run_validation_gas = do $compute_value_mean $validation_gas_values
        let run_serialized_block_size = do $compute_value_stats $serialized_block_size_values
        let run_serialized_block_size_per_tx = do $compute_value_stats $serialized_block_size_per_tx_values

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
            summary_warmup_blocks: $warmup_blocks
            blocks: $num_blocks
            total_tx: $total_tx
            ok: $total_ok
            err: $total_err
            total_gas: $total_gas
            block_time_mean: $block_time_mean
            builder_latency_p50: $run_builder.p50
            builder_latency_p90: $run_builder.p90
            builder_latency_p99: $run_builder.p99
            builder_gas_s: $run_builder_gas
            tps: $actual_tps
            mgas_s: $mgas_per_sec
            block_time_p50: $run_bt.p50
            block_time_p90: $run_bt.p90
            block_time_p99: $run_bt.p99
            serialized_block_size_p50: $run_serialized_block_size.p50
            serialized_block_size_p90: $run_serialized_block_size.p90
            serialized_block_size_p99: $run_serialized_block_size.p99
            serialized_block_size_per_tx_p50: $run_serialized_block_size_per_tx.p50
            serialized_block_size_per_tx_p90: $run_serialized_block_size_per_tx.p90
            serialized_block_size_per_tx_p99: $run_serialized_block_size_per_tx.p99
            validation_latency_p50: $run_validation.p50
            validation_latency_p90: $run_validation.p90
            validation_latency_p99: $run_validation.p99
            validation_gas_s: $run_validation_gas
            success_rate: $success_rate
        }])
    }

    if ($run_data | length) == 0 {
        print "No reports found, skipping summary generation"
        return
    }

    # Compute per-block-time statistics for each group
    let compute_block_time_summary = { |blocks: list<any>|
        let block_times = ($blocks | where block_time_ms != null | get block_time_ms | sort)
        {
            n: ($blocks | length)
            mean: (if ($block_times | length) > 0 { $block_times | math avg | math round --precision 1 } else { 0.0 })
            p50: (percentile $block_times 50 | math round --precision 1)
            p90: (percentile $block_times 90 | math round --precision 1)
            p99: (percentile $block_times 99 | math round --precision 1)
        }
    }

    let b_block_time = do $compute_block_time_summary $baseline_blocks
    let f_block_time = do $compute_block_time_summary $feature_blocks

    let b_builder = do $compute_value_stats $baseline_builder_latency_values
    let f_builder = do $compute_value_stats $feature_builder_latency_values
    let b_builder_finish = do $compute_value_stats $baseline_builder_finish_samples
    let f_builder_finish = do $compute_value_stats $feature_builder_finish_samples
    let b_builder_pool_fetch = do $compute_value_stats $baseline_builder_pool_fetch_samples
    let f_builder_pool_fetch = do $compute_value_stats $feature_builder_pool_fetch_samples
    let b_builder_invalid_tx_execution_attempts = do $compute_value_stats $baseline_builder_invalid_tx_execution_attempts_samples
    let f_builder_invalid_tx_execution_attempts = do $compute_value_stats $feature_builder_invalid_tx_execution_attempts_samples
    let b_builder_invalid_tx_skips = if ($baseline_builder_invalid_tx_skips | length) > 0 { $baseline_builder_invalid_tx_skips | math sum | math round --precision 0 } else { 0.0 }
    let f_builder_invalid_tx_skips = if ($feature_builder_invalid_tx_skips | length) > 0 { $feature_builder_invalid_tx_skips | math sum | math round --precision 0 } else { 0.0 }
    let b_builder_nonce_too_low_skips = if ($baseline_builder_nonce_too_low_skips | length) > 0 { $baseline_builder_nonce_too_low_skips | math sum | math round --precision 0 } else { 0.0 }
    let f_builder_nonce_too_low_skips = if ($feature_builder_nonce_too_low_skips | length) > 0 { $feature_builder_nonce_too_low_skips | math sum | math round --precision 0 } else { 0.0 }
    let b_builder_fill_idle = do $compute_value_stats $baseline_builder_fill_idle_samples
    let f_builder_fill_idle = do $compute_value_stats $feature_builder_fill_idle_samples
    let b_validation = do $compute_value_stats $baseline_validation_latency_values
    let f_validation = do $compute_value_stats $feature_validation_latency_values
    let b_builder_gas = do $compute_value_mean $baseline_builder_gas_values
    let f_builder_gas = do $compute_value_mean $feature_builder_gas_values
    let b_validation_gas = do $compute_value_mean $baseline_validation_gas_values
    let f_validation_gas = do $compute_value_mean $feature_validation_gas_values
    let b_serialized_block_size = do $compute_value_stats $baseline_serialized_block_size_values
    let f_serialized_block_size = do $compute_value_stats $feature_serialized_block_size_values
    let b_serialized_block_size_per_tx = do $compute_value_stats $baseline_serialized_block_size_per_tx_values
    let f_serialized_block_size_per_tx = do $compute_value_stats $feature_serialized_block_size_per_tx_values

    let b_bt = do $compute_block_time_stats $baseline_intervals
    let f_bt = do $compute_block_time_stats $feature_intervals
    # Aggregate TPS and Mgas/s from per-run totals (total_tx / total_time)
    let baseline_runs = ($run_data | where { |r| $r.label | str starts-with "baseline" })
    let feature_runs = ($run_data | where { |r| $r.label | str starts-with "feature" })
    let run_pairs = ([($baseline_runs | length) ($feature_runs | length)] | math max)

    let b_tps = if ($baseline_runs | length) > 0 { $baseline_runs | get tps | math avg | math round --precision 0 } else { 0.0 }
    let f_tps = if ($feature_runs | length) > 0 { $feature_runs | get tps | math avg | math round --precision 0 } else { 0.0 }
    let b_mgas = if ($baseline_runs | length) > 0 { $baseline_runs | get mgas_s | math avg | math round --precision 1 } else { 0.0 }
    let f_mgas = if ($feature_runs | length) > 0 { $feature_runs | get mgas_s | math avg | math round --precision 1 } else { 0.0 }

    # Compute deltas (feature vs baseline)
    let delta = { |base: float, feat: float| if $base != 0.0 { ((($feat - $base) / $base) * 100) | math round --precision 1 } else { 0.0 } }
    let has_samples = { |stats: record| ($stats.n | default 0) > 0 }
    let fmt_stat = { |stats: record, field: string|
        if (do $has_samples $stats) {
            let value = ($stats | get $field)
            $"($value)"
        } else { "n/a" }
    }
    let fmt_stat_delta = { |base_stats: record, feature_stats: record, field: string|
        let base_has_samples = (do $has_samples $base_stats)
        let feature_has_samples = (do $has_samples $feature_stats)
        if $base_has_samples and $feature_has_samples {
            let base = ($base_stats | get $field)
            let feature = ($feature_stats | get $field)
            $"(do $delta $base $feature)%"
        } else { "n/a" }
    }
    let stat_row = { |label: string, base_stats: record, feature_stats: record, field: string|
        let base_has_samples = (do $has_samples $base_stats)
        let feature_has_samples = (do $has_samples $feature_stats)
        let base_value = if $base_has_samples { $base_stats | get $field } else { 0.0 }
        let feature_value = if $feature_has_samples { $feature_stats | get $field } else { 0.0 }

        if (not $base_has_samples) or (not $feature_has_samples) or $base_value > 0.0 or $feature_value > 0.0 {
            $"| ($label) | (do $fmt_stat $base_stats $field) | (do $fmt_stat $feature_stats $field) | (do $fmt_stat_delta $base_stats $feature_stats $field) |"
        } else { null }
    }
    let nonzero_stat_row = { |label: string, base_stats: record, feature_stats: record, field: string|
        let base_has_samples = (do $has_samples $base_stats)
        let feature_has_samples = (do $has_samples $feature_stats)
        let base_value = if $base_has_samples { $base_stats | get $field } else { 0.0 }
        let feature_value = if $feature_has_samples { $feature_stats | get $field } else { 0.0 }

        if $base_value > 0.0 or $feature_value > 0.0 {
            $"| ($label) | (do $fmt_stat $base_stats $field) | (do $fmt_stat $feature_stats $field) | (do $fmt_stat_delta $base_stats $feature_stats $field) |"
        } else { null }
    }
    let nonzero_count_row = { |label: string, base: float, feature: float|
        if $base > 0.0 or $feature > 0.0 {
            $"| ($label) | ($base) | ($feature) | (do $delta $base $feature)% |"
        } else { null }
    }
    let to_mgas_s = { |value: float| ($value / 1_000_000.0) | math round --precision 1 }
    let b_builder_mgas = do $to_mgas_s $b_builder_gas
    let f_builder_mgas = do $to_mgas_s $f_builder_gas
    let b_validation_mgas = do $to_mgas_s $b_validation_gas
    let f_validation_mgas = do $to_mgas_s $f_validation_gas

    let observability_padding_ms = 5000
    let observability_duration_ms = $duration * ($run_labels | length) * 1000
    let observability_from_ms = if $reference_epoch > 0 {
        (($reference_epoch * 1000) - $observability_padding_ms)
    } else { 0 }
    let observability_to_ms = if $reference_epoch > 0 {
        (($reference_epoch * 1000) + $observability_duration_ms - $observability_padding_ms)
    } else { 0 }
    let phase_ranges = ($run_labels | each { |label|
        let range_path = $"($results_dir)/phase-range-($label).json"
        if ($range_path | path exists) { open $range_path } else { null }
    } | where { |range| $range != null })
    let phase_start_ms = ($phase_ranges | where started_ms != null | get started_ms | sort)
    let phase_finish_ms = ($phase_ranges | where finished_ms != null | get finished_ms | sort)
    let actual_observability_from_ms = if ($phase_start_ms | length) > 0 {
        $phase_start_ms | first
    } else { $observability_from_ms }
    let actual_observability_to_ms = if ($phase_finish_ms | length) > 0 {
        $phase_finish_ms | last
    } else { $observability_to_ms }

    # Build summary markdown
    let grafana_url = (grafana-performance-url $benchmark_id $observability_from_ms $observability_to_ms)
    let clickhouse_run_id_path = $"($results_dir)/clickhouse-run-id.txt"
    let clickhouse_run_id = if ($clickhouse_run_id_path | path exists) {
        open --raw $clickhouse_run_id_path | str trim
    } else {
        ""
    }
    let internal_perf_url = (internal-perf-url $clickhouse_run_id)
    mut config_lines = [
        $"# Bench Comparison: ($baseline_ref) vs ($feature_ref)"
        ""
        "## Configuration"
    ]
    let derek_bench_command = ($env.DEREK_BENCH_COMMAND? | default "")
    if $derek_bench_command != "" {
        $config_lines = ($config_lines | append $"- Derek command: `($derek_bench_command)`")
    }
    $config_lines = ($config_lines | append [
        $"- Bloat: ($bloat) MiB"
        $"- Preset: ($preset)"
        $"- Target TPS: ($tps)"
        $"- Duration: ($duration)s"
        $"- Run pairs: ($run_pairs)"
        $"- Snapshot: (if (has-schelk) { 'schelk' } else { 'cp fallback' })"
        $"- Baseline blocks: ($b_block_time.n)"
        $"- Feature blocks: ($f_block_time.n)"
    ])
    if $summary_warmup_blocks > 0 {
        $config_lines = ($config_lines | append $"- Summary warmup blocks: ($summary_warmup_blocks)")
    }
    if $baseline_hardfork != "" {
        $config_lines = ($config_lines | append $"- Baseline hardfork: ($baseline_hardfork)")
    }
    if $feature_hardfork != "" {
        $config_lines = ($config_lines | append $"- Feature hardfork: ($feature_hardfork)")
    }

    let summary_lines = ($config_lines | append [
        ""
        "## Tempo Metrics"
        ""
        "| Metric | Baseline | Feature | Delta |"
        "|--------|----------|---------|-------|"
        $"| TPS Mean | ($b_tps) | ($f_tps) | (do $delta $b_tps $f_tps)% |"
        $"| Gas Throughput [Mgas/s] | ($b_mgas) | ($f_mgas) | (do $delta $b_mgas $f_mgas)% |"
        $"| Block Time Mean [ms] | ($b_block_time.mean) | ($f_block_time.mean) | (do $delta $b_block_time.mean $f_block_time.mean)% |"
        $"| Block Time P50 [ms] | ($b_bt.p50) | ($f_bt.p50) | (do $delta $b_bt.p50 $f_bt.p50)% |"
        $"| Block Time P90 [ms] | ($b_bt.p90) | ($f_bt.p90) | (do $delta $b_bt.p90 $f_bt.p90)% |"
        $"| Block Time P99 [ms] | ($b_bt.p99) | ($f_bt.p99) | (do $delta $b_bt.p99 $f_bt.p99)% |"
        $"| Serialized Block Size / Tx P50 [B/tx] | ($b_serialized_block_size_per_tx.p50) | ($f_serialized_block_size_per_tx.p50) | (do $delta $b_serialized_block_size_per_tx.p50 $f_serialized_block_size_per_tx.p50)% |"
        $"| Serialized Block Size / Tx P90 [B/tx] | ($b_serialized_block_size_per_tx.p90) | ($f_serialized_block_size_per_tx.p90) | (do $delta $b_serialized_block_size_per_tx.p90 $f_serialized_block_size_per_tx.p90)% |"
        $"| Serialized Block Size / Tx P99 [B/tx] | ($b_serialized_block_size_per_tx.p99) | ($f_serialized_block_size_per_tx.p99) | (do $delta $b_serialized_block_size_per_tx.p99 $f_serialized_block_size_per_tx.p99)% |"
        ""
        "## Builder"
        ""
        "| Metric | Baseline | Feature | Delta |"
        "|--------|----------|---------|-------|"
        $"| Gas Throughput [Mgas/s] | ($b_builder_mgas) | ($f_builder_mgas) | (do $delta $b_builder_gas $f_builder_gas)% |"
        $"| Latency P50 [ms] | ($b_builder.p50) | ($f_builder.p50) | (do $delta $b_builder.p50 $f_builder.p50)% |"
        $"| Latency P90 [ms] | ($b_builder.p90) | ($f_builder.p90) | (do $delta $b_builder.p90 $f_builder.p90)% |"
        $"| Latency P99 [ms] | ($b_builder.p99) | ($f_builder.p99) | (do $delta $b_builder.p99 $f_builder.p99)% |"
        (do $stat_row "Finish P50 [ms]" $b_builder_finish $f_builder_finish p50)
        (do $stat_row "Finish P99 [ms]" $b_builder_finish $f_builder_finish p99)
        $"| Pool Fetch P50 [ms] | (do $fmt_stat $b_builder_pool_fetch p50) | (do $fmt_stat $f_builder_pool_fetch p50) | (do $fmt_stat_delta $b_builder_pool_fetch $f_builder_pool_fetch p50) |"
        $"| Pool Fetch P90 [ms] | (do $fmt_stat $b_builder_pool_fetch p90) | (do $fmt_stat $f_builder_pool_fetch p90) | (do $fmt_stat_delta $b_builder_pool_fetch $f_builder_pool_fetch p90) |"
        $"| Pool Fetch P99 [ms] | (do $fmt_stat $b_builder_pool_fetch p99) | (do $fmt_stat $f_builder_pool_fetch p99) | (do $fmt_stat_delta $b_builder_pool_fetch $f_builder_pool_fetch p99) |"
        (do $nonzero_stat_row "Invalid Tx Attempts P50" $b_builder_invalid_tx_execution_attempts $f_builder_invalid_tx_execution_attempts p50)
        (do $nonzero_stat_row "Invalid Tx Attempts P99" $b_builder_invalid_tx_execution_attempts $f_builder_invalid_tx_execution_attempts p99)
        (do $nonzero_count_row "Invalid Tx Skips" $b_builder_invalid_tx_skips $f_builder_invalid_tx_skips)
        (do $nonzero_count_row "Nonce Too Low Skips" $b_builder_nonce_too_low_skips $f_builder_nonce_too_low_skips)
        (do $nonzero_stat_row "Fill Idle P50 [ms]" $b_builder_fill_idle $f_builder_fill_idle p50)
        (do $nonzero_stat_row "Fill Idle P99 [ms]" $b_builder_fill_idle $f_builder_fill_idle p99)
        ""
        "## Validator"
        ""
        "| Metric | Baseline | Feature | Delta |"
        "|--------|----------|---------|-------|"
        $"| Gas Throughput [Mgas/s] | ($b_validation_mgas) | ($f_validation_mgas) | (do $delta $b_validation_gas $f_validation_gas)% |"
        $"| P50 [ms] | ($b_validation.p50) | ($f_validation.p50) | (do $delta $b_validation.p50 $f_validation.p50)% |"
        $"| P90 [ms] | ($b_validation.p90) | ($f_validation.p90) | (do $delta $b_validation.p90 $f_validation.p90)% |"
        $"| P99 [ms] | ($b_validation.p99) | ($f_validation.p99) | (do $delta $b_validation.p99 $f_validation.p99)% |"
        ""
    ] | where { |line| $line != null })
    let full_summary = ($summary_lines | str join "\n")
    $full_summary | save -f $"($results_dir)/summary.md"
    print $"Summary saved: ($results_dir)/summary.md"
    print $full_summary

    # Write machine-readable summary.json for CI
    let summary_json = {
        benchmark_id: $benchmark_id
        reference_epoch: $reference_epoch
        observability_range: {
            from_ms: $observability_from_ms
            to_ms: $observability_to_ms
            from: (if $observability_from_ms > 0 { iso-from-epoch-ms $observability_from_ms } else { "" })
            to: (if $observability_to_ms > 0 { iso-from-epoch-ms $observability_to_ms } else { "" })
        }
        actual_observability_range: {
            from_ms: $actual_observability_from_ms
            to_ms: $actual_observability_to_ms
            from: (if $actual_observability_from_ms > 0 { iso-from-epoch-ms $actual_observability_from_ms } else { "" })
            to: (if $actual_observability_to_ms > 0 { iso-from-epoch-ms $actual_observability_to_ms } else { "" })
        }
        grafana_url: $grafana_url
        clickhouse_run_id: $clickhouse_run_id
        internal_perf_url: $internal_perf_url
        baseline_ref: $baseline_ref
        feature_ref: $feature_ref
        config: {
            bloat: $bloat
            preset: $preset
            tps: $tps
            duration: $duration
            run_pairs: $run_pairs
            summary_warmup_blocks: $summary_warmup_blocks
            derek_command: $derek_bench_command
            baseline_hardfork: $baseline_hardfork
            feature_hardfork: $feature_hardfork
        }
        results: {
            baseline: {
                block_time_mean: $b_block_time.mean
                builder_latency_p50: $b_builder.p50
                builder_latency_p90: $b_builder.p90
                builder_latency_p99: $b_builder.p99
                builder_finish_p50: $b_builder_finish.p50
                builder_finish_p90: $b_builder_finish.p90
                builder_finish_p99: $b_builder_finish.p99
                builder_pool_fetch_p50: $b_builder_pool_fetch.p50
                builder_pool_fetch_p90: $b_builder_pool_fetch.p90
                builder_pool_fetch_p99: $b_builder_pool_fetch.p99
                builder_invalid_tx_execution_attempts_p50: $b_builder_invalid_tx_execution_attempts.p50
                builder_invalid_tx_execution_attempts_p90: $b_builder_invalid_tx_execution_attempts.p90
                builder_invalid_tx_execution_attempts_p99: $b_builder_invalid_tx_execution_attempts.p99
                builder_invalid_tx_skips: $b_builder_invalid_tx_skips
                builder_nonce_too_low_skips: $b_builder_nonce_too_low_skips
                builder_fill_idle_p50: $b_builder_fill_idle.p50
                builder_fill_idle_p90: $b_builder_fill_idle.p90
                builder_fill_idle_p99: $b_builder_fill_idle.p99
                builder_gas_s: $b_builder_gas
                tps: $b_tps
                mgas_s: $b_mgas
                block_time_p50: $b_bt.p50
                block_time_p90: $b_bt.p90
                block_time_p99: $b_bt.p99
                serialized_block_size_p50: $b_serialized_block_size.p50
                serialized_block_size_p90: $b_serialized_block_size.p90
                serialized_block_size_p99: $b_serialized_block_size.p99
                serialized_block_size_per_tx_p50: $b_serialized_block_size_per_tx.p50
                serialized_block_size_per_tx_p90: $b_serialized_block_size_per_tx.p90
                serialized_block_size_per_tx_p99: $b_serialized_block_size_per_tx.p99
                validation_latency_p50: $b_validation.p50
                validation_latency_p90: $b_validation.p90
                validation_latency_p99: $b_validation.p99
                validation_gas_s: $b_validation_gas
                blocks: $b_block_time.n
            }
            feature: {
                block_time_mean: $f_block_time.mean
                builder_latency_p50: $f_builder.p50
                builder_latency_p90: $f_builder.p90
                builder_latency_p99: $f_builder.p99
                builder_finish_p50: $f_builder_finish.p50
                builder_finish_p90: $f_builder_finish.p90
                builder_finish_p99: $f_builder_finish.p99
                builder_pool_fetch_p50: $f_builder_pool_fetch.p50
                builder_pool_fetch_p90: $f_builder_pool_fetch.p90
                builder_pool_fetch_p99: $f_builder_pool_fetch.p99
                builder_invalid_tx_execution_attempts_p50: $f_builder_invalid_tx_execution_attempts.p50
                builder_invalid_tx_execution_attempts_p90: $f_builder_invalid_tx_execution_attempts.p90
                builder_invalid_tx_execution_attempts_p99: $f_builder_invalid_tx_execution_attempts.p99
                builder_invalid_tx_skips: $f_builder_invalid_tx_skips
                builder_nonce_too_low_skips: $f_builder_nonce_too_low_skips
                builder_fill_idle_p50: $f_builder_fill_idle.p50
                builder_fill_idle_p90: $f_builder_fill_idle.p90
                builder_fill_idle_p99: $f_builder_fill_idle.p99
                builder_gas_s: $f_builder_gas
                tps: $f_tps
                mgas_s: $f_mgas
                block_time_p50: $f_bt.p50
                block_time_p90: $f_bt.p90
                block_time_p99: $f_bt.p99
                serialized_block_size_p50: $f_serialized_block_size.p50
                serialized_block_size_p90: $f_serialized_block_size.p90
                serialized_block_size_p99: $f_serialized_block_size.p99
                serialized_block_size_per_tx_p50: $f_serialized_block_size_per_tx.p50
                serialized_block_size_per_tx_p90: $f_serialized_block_size_per_tx.p90
                serialized_block_size_per_tx_p99: $f_serialized_block_size_per_tx.p99
                validation_latency_p50: $f_validation.p50
                validation_latency_p90: $f_validation.p90
                validation_latency_p99: $f_validation.p99
                validation_gas_s: $f_validation_gas
                blocks: $f_block_time.n
            }
            deltas: {
                block_time_mean: (do $delta $b_block_time.mean $f_block_time.mean)
                builder_latency_p50: (do $delta $b_builder.p50 $f_builder.p50)
                builder_latency_p90: (do $delta $b_builder.p90 $f_builder.p90)
                builder_latency_p99: (do $delta $b_builder.p99 $f_builder.p99)
                builder_finish_p50: (do $delta $b_builder_finish.p50 $f_builder_finish.p50)
                builder_finish_p90: (do $delta $b_builder_finish.p90 $f_builder_finish.p90)
                builder_finish_p99: (do $delta $b_builder_finish.p99 $f_builder_finish.p99)
                builder_pool_fetch_p50: (do $delta $b_builder_pool_fetch.p50 $f_builder_pool_fetch.p50)
                builder_pool_fetch_p90: (do $delta $b_builder_pool_fetch.p90 $f_builder_pool_fetch.p90)
                builder_pool_fetch_p99: (do $delta $b_builder_pool_fetch.p99 $f_builder_pool_fetch.p99)
                builder_invalid_tx_execution_attempts_p50: (do $delta $b_builder_invalid_tx_execution_attempts.p50 $f_builder_invalid_tx_execution_attempts.p50)
                builder_invalid_tx_execution_attempts_p90: (do $delta $b_builder_invalid_tx_execution_attempts.p90 $f_builder_invalid_tx_execution_attempts.p90)
                builder_invalid_tx_execution_attempts_p99: (do $delta $b_builder_invalid_tx_execution_attempts.p99 $f_builder_invalid_tx_execution_attempts.p99)
                builder_invalid_tx_skips: (do $delta $b_builder_invalid_tx_skips $f_builder_invalid_tx_skips)
                builder_nonce_too_low_skips: (do $delta $b_builder_nonce_too_low_skips $f_builder_nonce_too_low_skips)
                builder_fill_idle_p50: (do $delta $b_builder_fill_idle.p50 $f_builder_fill_idle.p50)
                builder_fill_idle_p90: (do $delta $b_builder_fill_idle.p90 $f_builder_fill_idle.p90)
                builder_fill_idle_p99: (do $delta $b_builder_fill_idle.p99 $f_builder_fill_idle.p99)
                builder_gas_s: (do $delta $b_builder_gas $f_builder_gas)
                tps: (do $delta $b_tps $f_tps)
                mgas_s: (do $delta $b_mgas $f_mgas)
                block_time_p50: (do $delta $b_bt.p50 $f_bt.p50)
                block_time_p90: (do $delta $b_bt.p90 $f_bt.p90)
                block_time_p99: (do $delta $b_bt.p99 $f_bt.p99)
                serialized_block_size_p50: (do $delta $b_serialized_block_size.p50 $f_serialized_block_size.p50)
                serialized_block_size_p90: (do $delta $b_serialized_block_size.p90 $f_serialized_block_size.p90)
                serialized_block_size_p99: (do $delta $b_serialized_block_size.p99 $f_serialized_block_size.p99)
                serialized_block_size_per_tx_p50: (do $delta $b_serialized_block_size_per_tx.p50 $f_serialized_block_size_per_tx.p50)
                serialized_block_size_per_tx_p90: (do $delta $b_serialized_block_size_per_tx.p90 $f_serialized_block_size_per_tx.p90)
                serialized_block_size_per_tx_p99: (do $delta $b_serialized_block_size_per_tx.p99 $f_serialized_block_size_per_tx.p99)
                validation_latency_p50: (do $delta $b_validation.p50 $f_validation.p50)
                validation_latency_p90: (do $delta $b_validation.p90 $f_validation.p90)
                validation_latency_p99: (do $delta $b_validation.p99 $f_validation.p99)
                validation_gas_s: (do $delta $b_validation_gas $f_validation_gas)
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

    if ($pids | length) == 0 {
        print "No tempo processes found."
        return
    }

    print $"Found ($pids | length) running tempo process\(es\)."

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

    print "Done."
}

# ============================================================================
# Localnet command
# ============================================================================

# Run Tempo localnet
def "main localnet" [
    --mode: string = "dev"                 # Mode: "dev" or "consensus"
    --nodes: int = 3                       # Number of validators (consensus mode)
    --accounts: int = 1000                 # Number of genesis accounts
    --epoch-length: int = 302400           # Epoch length in blocks for generated genesis/localnet
    --genesis: string = ""                 # Custom genesis file path (skips generation)
    --samply                               # Enable samply profiling (foreground node only)
    --samply-args: string = ""             # Additional samply arguments (space-separated)
    --reset                                # Wipe and regenerate localnet data
    --profile: string = $DEFAULT_PROFILE   # Cargo build profile
    --features: string = $DEFAULT_FEATURES # Cargo features
    --loud                                 # Show all node logs (WARN/ERROR shown by default)
    --node-args: string = ""               # Additional node arguments (space-separated)
    --skip-build                           # Skip building tempo and tempo-xtask (assumes binaries are already built)
    --force                                # Kill dangling processes without prompting
    --bloat: int = 0                       # Generate state bloat (size in MiB) for TIP20 tokens
] {
    validate-mode $mode
    if $epoch_length <= 0 {
        print "Error: --epoch-length must be greater than 0"
        exit 1
    }

    # Check for dangling processes
    let pids = (find-tempo-pids)
    if ($pids | length) > 0 {
        main kill --prompt=($force | not $in)
    }

    # Parse custom args
    let extra_args = (parse-cli-args $node_args)
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
        run-dev-node $accounts $epoch_length $genesis $samply $samply_args_list $reset $profile $skip_build $loud $extra_args $bloat
    } else {
        run-consensus-nodes $nodes $accounts $epoch_length $genesis $samply $samply_args_list $reset $profile $skip_build $loud $extra_args $bloat
    }
}

# ============================================================================
# Dev mode
# ============================================================================

def run-dev-node [accounts: int, epoch_length: int, genesis: string, samply: bool, samply_args: list<string>, reset: bool, profile: string, skip_build: bool, loud: bool, extra_args: list<string>, bloat: int] {
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
            generate-bloat-file $bloat $profile $skip_build
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
            run-tempo-xtask $profile $skip_build ["generate-genesis" "--output" $LOCALNET_DIR "-a" $"($accounts)" "--epoch-length" $"($epoch_length)" "--no-dkg-in-genesis"]
        }

        # Apply state bloat if requested (requires fresh init)
        if $bloat > 0 {
            generate-bloat-file $bloat $profile $skip_build
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
    let ipc_path = $"($datadir)/reth.ipc"

    [
        "node"
        "--chain" $genesis_path
        "--datadir" $datadir
        "--http"
        "--http.addr" $bind_ip
        "--http.port" $"($http_port)"
        "--http.api" "all"
        "--ws"
        "--ws.addr" $bind_ip
        "--ws.port" $"($http_port)"
        "--ws.api" "all"
        "--metrics" $"($bind_ip):($reth_metrics_port)"
        "--ipcpath" $ipc_path
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

def run-consensus-nodes [nodes: int, accounts: int, epoch_length: int, genesis: string, samply: bool, samply_args: list<string>, reset: bool, profile: string, skip_build: bool, loud: bool, extra_args: list<string>, bloat: int] {
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
            run-tempo-xtask $profile $skip_build ["generate-localnet" "-o" $LOCALNET_DIR "--accounts" $"($accounts)" "--epoch-length" $"($epoch_length)" "--validators" $validators "--force"] | ignore
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
        generate-bloat-file $bloat $profile $skip_build
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
    let consensus_secret = (prepare-localnet-consensus-secret-fifo $node_dir)

    let log_dir = $"($LOGS_DIR)/($addr)"
    mkdir $log_dir

    let args = (build-consensus-node-args $node_dir $genesis_path $trusted_peers $port $log_dir $consensus_secret)
        | append (log-filter-args $loud)
        | append $extra_args

    let cmd = wrap-samply [$tempo_bin ...$args] $samply $samply_args

    print $"  Node ($addr) -> http://localhost:($http_port)(if $background { '' } else { ' (foreground)' })"

    if $background {
        start-localnet-consensus-secret-writer $consensus_secret
        job spawn { sh -c $"($cmd | str join ' ') 2>&1" | lines | each { |line| print $"[($addr)] ($line)" } }
    } else {
        print $"  Running: ($cmd | str join ' ')"
        start-localnet-consensus-secret-writer $consensus_secret
        run-external ($cmd | first) ...($cmd | skip 1)
    }
}

# Build full node arguments for consensus mode
def build-consensus-node-args [node_dir: string, genesis_path: string, trusted_peers: string, port: int, log_dir: string, consensus_secret: string] {
    let node_index = (port-to-node-index $port)
    let http_port = 8545 + $node_index
    let reth_metrics_port = 9001 + $node_index

    (build-base-args $genesis_path $node_dir $log_dir "0.0.0.0" $http_port $reth_metrics_port)
        | append (build-consensus-args $node_dir $trusted_peers $port $consensus_secret)
}

# Build consensus mode specific arguments
def build-consensus-args [node_dir: string, trusted_peers: string, port: int, consensus_secret: string] {
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
        "--consensus.secret" $consensus_secret
        "--consensus.signing-share" $signing_share
        "--consensus.listen-address" $"($ip):($port)"
        "--consensus.metrics-address" $"0.0.0.0:($metrics_port)"
        "--trusted-peers" $trusted_peers
        "--port" $"($execution_p2p_port)"
        "--discovery.port" $"($execution_p2p_port)"
        "--discovery.v5.port" $"($discv5_port)"
        "--p2p-secret-key" $enode_key
        "--authrpc.port" $"($authrpc_port)"
        "--consensus.use-local-defaults"
        "--consensus.bypass-ip-check"
    ]
}

# ============================================================================
# Follower command
# ============================================================================

# Start a follower node (requires a running localnet)
def "main follower" [
    --profile: string = $DEFAULT_PROFILE # Cargo build profile
    --features: string = $DEFAULT_FEATURES # Cargo features
    --loud                      # Show all node logs (WARN/ERROR shown by default)
    --node-args: string = ""    # Additional node arguments (space-separated)
    --skip-build                # Skip building (assumes binary is already built)
    --reset                     # Wipe follower data before starting
] {
    # Validate localnet exists
    if not ($LOCALNET_DIR | path exists) {
        print "Error: localnet not found. Run `nu tempo.nu localnet --mode consensus` first."
        exit 1
    }

    let genesis_path = $"($LOCALNET_DIR)/genesis.json"
    if not ($genesis_path | path exists) {
        print $"Error: genesis file not found at ($genesis_path)"
        exit 1
    }

    let extra_args = (parse-cli-args $node_args)
    if not $skip_build {
        build-tempo ["tempo"] $profile $features
    }

    let tempo_bin = if $profile == "dev" {
        "./target/debug/tempo"
    } else {
        $"./target/($profile)/tempo"
    }

    # Auto-detect validators from localnet directory structure
    let validator_dirs = (ls $LOCALNET_DIR | where type == "dir" | get name | where { |d| ($d | path basename) =~ '^\d+\.\d+\.\d+\.\d+:\d+$' })
    if ($validator_dirs | length) == 0 {
        print "Error: no validator configs found. Run `nu tempo.nu localnet --mode consensus --reset` first."
        exit 1
    }

    let trusted_peers = ($validator_dirs | each { |d|
        let addr = ($d | path basename)
        let ip = ($addr | split row ":" | get 0)
        let port = ($addr | split row ":" | get 1 | into int)
        let identity = (open $"($d)/enode.identity" | str trim)
        $"enode://($identity)@($ip):($port + 1)"
    } | str join ",")

    let node_dir = $"($LOCALNET_DIR)/follower"
    if $reset and ($node_dir | path exists) {
        print "Resetting follower data..."
        rm -rf $node_dir
    }

    mkdir $node_dir

    let log_dir = $"($LOGS_DIR)/follower"
    mkdir $log_dir

    # Use the slot after the last validator and mirror consensus node port formulas.
    let node_index = (($validator_dirs | each { |d|
        let addr = ($d | path basename)
        let port = ($addr | split row ":" | get 1 | into int)
        port-to-node-index $port
    } | math max) + 1)

    let consensus_port = ($node_index * 100) + 8000

    let http_port = 8545 + $node_index
    let reth_metrics_port = 9001 + $node_index
    let execution_p2p_port = $consensus_port + 1
    let consensus_metrics_port = $consensus_port + 2
    let authrpc_port = $consensus_port + 3
    let discv5_port = $consensus_port + 4

    let args = (build-base-args $genesis_path $node_dir $log_dir "0.0.0.0" $http_port $reth_metrics_port)
        | append [
            "--follow" $"ws://127.0.0.1:8545"
            "--consensus.metrics-address" $"0.0.0.0:($consensus_metrics_port)"
            "--trusted-peers" $trusted_peers
            "--port" $"($execution_p2p_port)"
            "--discovery.port" $"($execution_p2p_port)"
            "--discovery.v5.port" $"($discv5_port)"
            "--authrpc.port" $"($authrpc_port)"
            "--consensus.use-local-defaults"
            "--consensus.bypass-ip-check"
        ]
        | append (log-filter-args $loud)
        | append $extra_args

    let cmd = [$tempo_bin ...$args]
    print $"Follower -> http://localhost:($http_port)"
    print "Press Ctrl+C to stop."
    run-external ($cmd | first) ...($cmd | skip 1)
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
# if the marker in the benchmark datadir matches the requested config.
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
            if ($marker.bloat_mib | into int) == $bloat and ($marker.accounts | into int) == $genesis_accounts and ($marker | get -o txgen_mnemonic | default "") == (txgen-account-mnemonic) {
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
    let txgen_genesis_args = ["--mnemonic" (txgen-account-mnemonic)]
    print $"Generating genesis with ($genesis_accounts) accounts..."
    cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $abs_localnet -a $genesis_accounts ...$txgen_genesis_args --no-dkg-in-genesis

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
        bench_datadir: $datadir,
        txgen_mnemonic: (txgen-account-mnemonic)
    } [[$genesis_path "genesis.json"]] $bloat $bloat_file

    print $"Virgin snapshot initialized and promoted."
}

# ============================================================================
# Bench command
# ============================================================================

# Run a full benchmark: start infra, localnet, and txgen traffic
def "main bench" [
    --mode: string = "consensus"                    # Mode: "dev" or "consensus"
    --preset: string = ""                           # Txgen preset name
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
    --baseline-args: string = ""                    # Additional node arguments for baseline runs only (space-separated)
    --feature-args: string = ""                     # Additional node arguments for feature runs only (space-separated)
    --bench-args: string = ""                       # Additional txgen generate arguments
    --baseline-env: string = ""                     # Environment variables for baseline node runs (KEY=VAL KEY2=VAL2)
    --feature-env: string = ""                      # Environment variables for feature node runs (KEY=VAL KEY2=VAL2)
    --bench-env: string = ""                        # Environment variables for txgen/bench (KEY=VAL KEY2=VAL2)
    --bloat: int = 0                                # Generate state bloat (size in MiB) for TIP20 tokens
    --no-infra                                      # Skip starting observability stack (Grafana + Prometheus)
    --baseline: string = ""                         # Git ref for baseline (comparison mode)
    --feature: string = ""                          # Git ref for feature (comparison mode)
    --force                                         # Force re-initialize snapshot (regenerate genesis, bloat, db)
    --bench-datadir: string = ""                    # Node database directory (default: LOCALNET_DIR/reth, /reth-bench for schelk)
    --tune                                          # Apply system tuning for dedicated benchmark runners (Linux only)
    --no-cache                                      # Skip binary cache (force build from source)
    --tracy: string = "off"                         # Tracy profiling: off, tracy
    --tracy-filter: string = "debug"                # Tracy tracing filter level
    --tracy-seconds: int = 30                       # Tracy capture duration limit in seconds (0 = unlimited)
    --tracy-offset: int = 120                       # Seconds to wait before starting tracy capture (default: 120)
    --tracing-otlp: string = ""                     # OTLP endpoint for tracing (auto-derived from TEMPO_TELEMETRY_URL if not set)
    --baseline-hardfork: string = ""                # Latest active hardfork for baseline (e.g. T1, T1C, T2)
    --feature-hardfork: string = ""                 # Latest active hardfork for feature (e.g. T1, T1C, T2)
    --gas-limit: string = ""                        # Block gas limit for genesis (raw number, e.g. 1000000000)
] {
    validate-mode $mode

    # Validate --nodes is only used with consensus mode
    if $mode == "dev" and $nodes != 3 {
        print "Error: --nodes is only valid with --mode consensus"
        exit 1
    }

    let preset_path = (txgen-preset-path $preset)
    let txgen = (txgen-resolve-binaries)

    let gas_limit_args = if $gas_limit != "" { ["--gas-limit" $gas_limit] } else { [] }
    let txgen_genesis_args = ["--mnemonic" (txgen-account-mnemonic)]

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
    if $tracy not-in ["off" "tracy"] {
        print $"Error: --tracy must be one of: off, tracy \(got '($tracy)'\)"
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
    let tempo_hardforks = (tempo-hardforks)
    if $baseline_hardfork != "" {
        let valid = ($tempo_hardforks | any { |f| $f == ($baseline_hardfork | str upcase) })
        if not $valid {
            print $"Error: unknown baseline hardfork '($baseline_hardfork)'. Valid: ($tempo_hardforks | str join ', ')"
            exit 1
        }
    }
    if $feature_hardfork != "" {
        let valid = ($tempo_hardforks | any { |f| $f == ($feature_hardfork | str upcase) })
        if not $valid {
            print $"Error: unknown feature hardfork '($feature_hardfork)'. Valid: ($tempo_hardforks | str join ', ')"
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
            build-tempo --extra-rustflags $effective_extra_rustflags ["tempo"] $profile $effective_features
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
                and ($marker | get -o gas_limit | default "") == $gas_limit
                and ($marker | get -o txgen_mnemonic | default "") == (txgen-account-mnemonic)
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
                    cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $baseline_genesis_dir -a $genesis_accounts ...$txgen_genesis_args --no-dkg-in-genesis ...$baseline_genesis_args ...$gas_limit_args
                } else {
                    do {
                        cd $baseline_wt
                        cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $baseline_genesis_dir -a $genesis_accounts ...$txgen_genesis_args --no-dkg-in-genesis ...$baseline_genesis_args ...$gas_limit_args
                    }
                }
                cp $"($baseline_genesis_dir)/genesis.json" $baseline_genesis_path
                rm -rf $baseline_genesis_dir

                print $"Generating feature genesis \(latest fork: ($feature_hardfork)\)..."
                let feature_genesis_dir = $"($abs_localnet)/genesis-feature-dir"
                if ($feature_genesis_dir | path exists) { rm -rf $feature_genesis_dir }
                mkdir $feature_genesis_dir
                if $feature == "local" {
                    cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $feature_genesis_dir -a $genesis_accounts ...$txgen_genesis_args --no-dkg-in-genesis ...$feature_genesis_args ...$gas_limit_args
                } else {
                    # Use feature worktree for feature genesis so it picks up any
                    # new hardfork-related genesis changes from the feature branch
                    do {
                        cd $feature_wt
                        cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $feature_genesis_dir -a $genesis_accounts ...$txgen_genesis_args --no-dkg-in-genesis ...$feature_genesis_args ...$gas_limit_args
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
                    gas_limit: $gas_limit
                    txgen_mnemonic: (txgen-account-mnemonic)
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
                and ($marker | get -o gas_limit | default "") == $gas_limit
                and ($marker | get -o txgen_mnemonic | default "") == (txgen-account-mnemonic)
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
                        cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $abs_localnet -a $genesis_accounts ...$txgen_genesis_args --no-dkg-in-genesis ...$gas_limit_args
                    } else {
                        do {
                            cd $baseline_wt
                            cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $abs_localnet -a $genesis_accounts ...$txgen_genesis_args --no-dkg-in-genesis ...$gas_limit_args
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
                    bench_datadir: $datadir,
                    gas_limit: $gas_limit,
                    txgen_mnemonic: (txgen-account-mnemonic)
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

        # Setup kernel permissions for tracy CPU sampling.
        if $tracy == "tracy" and (^uname | str trim) == "Linux" {
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

            # Merge common node-args with per-side args (baseline-args / feature-args)
            let run_type = if ($run.label | str starts-with "baseline") { "baseline" } else { "feature" }
            let side_args = if $run_type == "baseline" { $baseline_args } else { $feature_args }
            let side_env = if $run_type == "baseline" { $baseline_env } else { $feature_env }
            let effective_node_args = ([$node_args $side_args] | where { |a| $a != "" } | str join " ")

            (run-bench-single
                --tempo-bin $run.tempo
                --txgen-tempo-bin $txgen.txgen_tempo_bin
                --txgen-bench-bin $txgen.txgen_bench_bin
                --rpc-urls "http://localhost:8545"
                --metrics-url ["http://127.0.0.1:9001/metrics"]
                --genesis-path $run.genesis --datadir $run.datadir
                --run-label $run.label --results-dir $results_dir
                --tps $tps --duration $duration --accounts $accounts
                --max-concurrent-requests $max_concurrent_requests
                --preset-path $preset_path --bench-args $bench_args
                --loud=$loud --node-args $effective_node_args --bloat $bloat
                --extra-env $side_env --bench-env $bench_env
                --git-ref $run.git_ref --build-profile $profile --benchmark-mode $mode
                --benchmark-id $benchmark_id --reference-epoch $reference_epoch
                --samply=$samply --samply-args $samply_args_list
                --tracy $tracy --tracy-filter $tracy_filter
                --tracy-seconds $tracy_seconds --tracy-offset $tracy_offset
                --tracing-otlp $tracing_otlp)
        }

        # Generate summary report
        let baseline_hardfork_label = if $dual_hardfork { $baseline_hardfork | str upcase } else { "" }
        let feature_hardfork_label = if $dual_hardfork { $feature_hardfork | str upcase } else { "" }
        generate-summary $results_dir $baseline $feature $bloat $preset $tps $duration --benchmark-id $benchmark_id --reference-epoch $reference_epoch --baseline-hardfork $baseline_hardfork_label --feature-hardfork $feature_hardfork_label

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
                let tracy_urls = (upload-tracy-profile $profile $run.label $run.git_ref)
                if $tracy_urls != null {
                    $tracy_urls.viewer_url | save -f $"($results_dir)/tracy-($run.label)-url.txt"
                    $tracy_urls.profile_url | save -f $"($results_dir)/tracy-($run.label)-profile-url.txt"
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

    # Build tempo and xtask first
    build-tempo ["tempo"] $profile $features
    build-tempo-xtask $profile

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

    print "Running txgen benchmark..."
    let submit_rpc_url = ($rpc_urls | str join ",")
    let primary_rpc_url = ($rpc_urls | first)
    let current_sha = (git rev-parse HEAD | str trim)
    let bench_result = (try {
        let result = (txgen-run-preset-pipeline
            --txgen-tempo-bin $txgen.txgen_tempo_bin
            --txgen-bench-bin $txgen.txgen_bench_bin
            --preset-path $preset_path
            --generate-rpc-url $primary_rpc_url
            --submit-rpc-url $submit_rpc_url
            --metrics-url ["http://127.0.0.1:9001/metrics"]
            --report-path "report.json"
            --tps $tps
            --duration $duration
            --accounts $accounts
            --max-concurrent-requests $max_concurrent_requests
            --bench-args $bench_args
            --bench-env $bench_env
            --git-ref $current_sha
            --build-profile $profile
            --benchmark-mode $mode
            --bloat-mib $bloat
            --bloat-token-count ($TIP20_TOKEN_IDS | length)
            --skip-funding=($bloat > 0))
        $result
    } catch { |e|
        print $"Benchmark interrupted or failed: ($e.msg)"
        { ok: false, exit_code: 1, report_path: "report.json" }
    })
    let single_bench_failed = not $bench_result.ok

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
    if $single_bench_failed {
        error make { msg: "Benchmark interrupted or failed" }
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
const INVARIANT_DIR = "tips/verify"

# Find a local tempo-foundry checkout for coverage runs.
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
    --preset: string = ""                  # Txgen preset name for live mode
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
        print $"  Available txgen presets: (txgen-available-presets-message)"
        exit 1
    }

    let live_preset_path = if $live and $script == "" {
        txgen-preset-path $preset
    } else {
        ""
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
                    cargo build --bin forge --profile release
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
                let txgen = (txgen-resolve-binaries)
                print "Running txgen bench..."
                try {
                    let bench_result = (txgen-run-preset-pipeline
                        --txgen-tempo-bin $txgen.txgen_tempo_bin
                        --txgen-bench-bin $txgen.txgen_bench_bin
                        --preset-path $live_preset_path
                        --generate-rpc-url "http://localhost:8545"
                        --submit-rpc-url "http://localhost:8545"
                        --metrics-url ["http://127.0.0.1:9001/metrics"]
                        --report-path "report.json"
                        --tps $tps
                        --duration $duration
                        --accounts $accounts
                        --max-concurrent-requests 100
                        --build-profile "coverage"
                        --benchmark-mode "coverage"
                        --bloat-mib $bloat
                        --bloat-token-count ($TIP20_TOKEN_IDS | length))
                    if not $bench_result.ok {
                        print "Bench finished (or interrupted)."
                    }
                } catch { |e|
                    print $"Bench finished (or interrupted): ($e.msg)"
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
    print "  nu tempo.nu follower [flags]         Start a follower node (requires running localnet)"
    print "  nu tempo.nu infra up                 Start Grafana + Prometheus"
    print "  nu tempo.nu infra down               Stop the observability stack"
    print "  nu tempo.nu kill                     Kill any running tempo processes"
    print ""
    print "Bench flags (--preset resolves under contrib/bench/txgen/presets):"
    print "  --mode <M>               Mode: dev or consensus (default: consensus)"
    print "  --preset <P>             Txgen preset name (e.g. tip20)"
    print "  --tps <N>                Target TPS (default: 10000)"
    print "  --duration <N>           Duration in seconds (default: 30)"
    print "  --accounts <N>           Number of accounts (default: 1000)"
    print "  --max-concurrent-requests <N>  Max concurrent requests (default: 100)"
    print "  --nodes <N>              Number of consensus nodes (default: 3, consensus mode only)"
    print "  --samply                 Profile nodes with samply"
    print "  --samply-args <ARGS>     Additional samply arguments (space-separated)"
    print "  --tracy <MODE>           Tracy profiling: off (default), tracy"
    print "  --tracy-filter <FILTER>  Tracy tracing filter level (default: debug)"
    print "  --tracy-seconds <N>      Tracy capture duration limit in seconds (default: 30, 0 = unlimited)"
    print "  --tracy-offset <N>       Seconds to wait before starting tracy capture (default: 120)"
    print "  --tracing-otlp <URL>     OTLP endpoint for tracing (auto-derived from TEMPO_TELEMETRY_URL if not set)"
    print "  --reset                  Reset localnet before starting"
    print "  --loud                   Show all node logs (WARN/ERROR shown by default)"
    print $"  --profile <P>            Cargo profile \(default: ($DEFAULT_PROFILE)\)"
    print $"  --features <F>           Cargo features \(default: ($DEFAULT_FEATURES)\)"
    print "  --node-args <ARGS>       Additional node arguments (space-separated, all runs)"
    print "  --baseline-args <ARGS>       Additional node arguments for baseline runs only"
    print "  --feature-args <ARGS>        Additional node arguments for feature runs only"
    print "  --bench-args <ARGS>      Additional txgen generate arguments"
    print "  --bloat <N>              Generate TIP20 state bloat (size in MiB)"
    print "  --gas-limit <N>          Block gas limit for genesis (raw number, default: 1000000000000)"
    print ""
    print "Localnet flags:"
    print "  --mode <dev|consensus>   Mode (default: dev)"
    print "  --nodes <N>              Number of validators for consensus (default: 3)"
    print "  --accounts <N>           Genesis accounts (default: 1000)"
    print "  --epoch-length <N>       Epoch length in blocks for generated genesis/localnet (default: 302400)"
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
    print "  --preset <P>             Txgen preset name for live mode"
    print "  --script <PATH>          External script to run against live node (instead of bench)"
    print "  --tps <N>                Target TPS for live bench (default: 1000)"
    print "  --duration <N>           Bench duration in seconds (default: 10)"
    print "  --accounts <N>           Number of accounts (default: 100)"
    print "  --format <F>             Report format: html, lcov, json, text (default: html)"
    print "  --open                   Open HTML report in browser"
    print "  --reset                  Wipe localnet data before live run"
    print ""
    print "Follower flags:"
    print "  --loud                   Show all node logs (WARN/ERROR shown by default)"
    print "  --reset                  Wipe follower data before starting"
    print $"  --profile <P>            Cargo profile \(default: ($DEFAULT_PROFILE)\)"
    print $"  --features <F>           Cargo features \(default: ($DEFAULT_FEATURES)\)"
    print "  --node-args <ARGS>       Additional node arguments (space-separated)"
    print ""
    print "Examples:"
    print "  nu tempo.nu bench --preset tip20 --tps 20000 --duration 60"
    print "  nu tempo.nu bench --preset tip20 --tps 5000 --samply --reset"
    print "  nu tempo.nu coverage --tests                              # unit + integration tests"
    print "  nu tempo.nu coverage --invariants                         # forge invariant fuzz (precompile coverage)"
    print "  nu tempo.nu coverage --tests --invariants                 # merged: cargo + forge coverage"
    print "  nu tempo.nu coverage --invariants --invariant-profile fuzz500  # deeper fuzz run"
    print "  nu tempo.nu coverage --live --preset tip20 --open         # live tx coverage"
    print "  nu tempo.nu coverage --live --script /path/to/test.sh     # live + external script"
    print "  nu tempo.nu coverage --tests --live --preset tip20        # everything merged"
    print "  nu tempo.nu infra up"
    print "  nu tempo.nu localnet --mode dev --samply --accounts 50000 --reset"
    print "  nu tempo.nu localnet --mode dev --bloat 1024 --reset"
    print "  nu tempo.nu localnet --mode consensus --nodes 3"
    print "  nu tempo.nu follower --reset --loud     # start follower after localnet is running"
    print ""
    print "Port assignments (consensus mode, per node N=0,1,2...):"
    print "  Consensus:     8000 + N*100"
    print "  P2P:           8001 + N*100"
    print "  Metrics:       8002 + N*100"
    print "  AuthRPC:       8003 + N*100"
    print "  Discv5:        8004 + N*100"
    print "  HTTP RPC:      8545 + N"
    print "  Reth Metrics:  9001 + N"
    print "  Follower:      uses N = validator count"
}
