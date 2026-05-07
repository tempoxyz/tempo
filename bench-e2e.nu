#!/usr/bin/env nu

# Single-runner e2e benchmark harness.
# Shared build/cache/report helpers are sourced from tempo.nu; the replacement
# e2e topology stays isolated here.
source tempo.nu

const E2E_A_STATE_PATH = "/var/lib/schelk/a.json"
const E2E_B_STATE_PATH = "/var/lib/schelk/b.json"
const E2E_A_MOUNT = "/reth-bench-a"
const E2E_B_MOUNT = "/reth-bench-b"
const E2E_VALIDATORS = "127.0.0.2:8000,127.0.0.3:8100"
const E2E_SEED = 42
const E2E_A_CPUS = "0-7,16-23"
const E2E_B_CPUS = "8-15,24-31"
const E2E_A_MEMORY = ""
const E2E_B_MEMORY = ""
const E2E_GAS_LIMIT = "1000000000000"
const E2E_BLOAT_TMP_DIR = "/reth-bench-a/.bench-tmp/e2e-local-init"
const E2E_BLOAT_FREE_MARGIN_MIB = 51200
const E2E_LOCAL_RETH_ARGS = [
    "--ipcdisable"
    "--disable-discovery"
    "--trusted-only"
    "--tempo.bootnodes-endpoint" "none"
]

def schelk [state_path: string, subcommand: string, ...args: string] {
    sudo schelk --state-path $state_path $subcommand ...$args
}

def schelk-state [state_path: string] {
    sudo cat $state_path | from json
}

def validate-schelk-state [a_state_path: string, b_state_path: string] {
    if (has-schelk) {
        for state_path in [$a_state_path $b_state_path] {
            if not ($state_path | path exists) {
                print $"Error: schelk state file does not exist: ($state_path)"
                exit 1
            }
        }
        let a_state = (schelk-state $a_state_path)
        let b_state = (schelk-state $b_state_path)
        let a_dm_era = ($a_state | get --optional dm_era_name)
        let b_dm_era = ($b_state | get --optional dm_era_name)
        if $a_dm_era == null or $b_dm_era == null {
            print "Error: schelk state files must include dm_era_name for parallel a/b instances."
            print "Reinitialize schelk a and b with unique --dm-era-name values."
            exit 1
        }
        if $a_dm_era == $b_dm_era {
            print $"Error: schelk a/b state files use the same dm_era_name: ($a_dm_era)"
            print "Reinitialize one side with a unique --dm-era-name before running e2e."
            exit 1
        }
        let a_mount = ($a_state | get --optional mount_point)
        let b_mount = ($b_state | get --optional mount_point)
        if $a_mount != $E2E_A_MOUNT {
            print $"Error: schelk a state mount_point is ($a_mount), expected ($E2E_A_MOUNT)"
            exit 1
        }
        if $b_mount != $E2E_B_MOUNT {
            print $"Error: schelk b state mount_point is ($b_mount), expected ($E2E_B_MOUNT)"
            exit 1
        }
        if $a_mount == $b_mount {
            print $"Error: schelk a/b state files use the same mount_point: ($a_mount)"
            exit 1
        }
    }
}

def bench-restore-at [state_path: string, mount_point: string, datadir: string] {
    if (has-schelk) {
        print $"Restoring schelk snapshot ($mount_point)..."
        let state = (schelk-state $state_path)
        let state_mounted = ($state | get --optional is_mounted) == true
        let actual_mounted = (mountpoint -q $mount_point | complete).exit_code == 0
        try {
            if $state_mounted or $actual_mounted {
                schelk $state_path recover "-y" "--kill"
            }
            schelk $state_path mount
        } catch {
            print $"Schelk restore failed for ($mount_point), falling back to full-recover..."
            schelk $state_path full-recover "-y"
            schelk $state_path mount
        }
        sudo chown -R (whoami | str trim) $mount_point
    } else {
        print $"Restoring snapshot from ($datadir).virgin..."
        rm -rf $datadir
        ^cp -a $"($datadir).virgin" $datadir
    }
}

# Promote a specific schelk scratch volume as the new virgin baseline.
def bench-promote-at [state_path: string, datadir: string] {
    if (has-schelk) {
        print $"Promoting schelk scratch to virgin ($state_path)..."
        schelk $state_path promote "-y" "--kill"
    } else {
        print $"Saving snapshot to ($datadir).virgin..."
        rm -rf $"($datadir).virgin"
        ^cp -a $datadir $"($datadir).virgin"
    }
}

def df-available-mib [path: string] {
    let row = (^df -Pm $path | lines | skip 1 | first | split row --regex '\s+')
    $row | get 3 | into int
}

def ensure-bloat-space [bloat: int] {
    if $bloat <= 0 {
        return
    }
    let required_mib = $bloat + $E2E_BLOAT_FREE_MARGIN_MIB
    for mount in [$E2E_A_MOUNT $E2E_B_MOUNT] {
        let available_mib = (df-available-mib $mount)
        if $available_mib < $required_mib {
            print $"Error: ($mount) has ($available_mib) MiB free, needs at least ($required_mib) MiB for ($bloat) MiB bloat plus margin"
            exit 1
        }
    }
}

def bench-save-e2e-meta [datadir: string, meta_dir: string, marker: record, genesis_files: list] {
    mkdir $meta_dir
    for pair in $genesis_files {
        cp ($pair | first) $"($meta_dir)/($pair | last)"
    }
    let marker_path = $"($meta_dir)/marker.json"
    $marker | insert initialized_at (date now | format date "%Y-%m-%dT%H:%M:%SZ") | to json | save -f $marker_path
    print $"Bench marker written to ($marker_path)"
}

def systemd-scope-command [unit: string, cpus: string, memory: string, script: string] {
    let can_scope = (^uname | str trim) == "Linux" and ((which systemd-run | length) > 0) and ($cpus != "" or $memory != "")
    if not $can_scope {
        return ["bash" "-lc" $script]
    }

    let cpu_args = if $cpus != "" { ["-p" $"AllowedCPUs=($cpus)"] } else { [] }
    let memory_args = if $memory != "" { ["-p" $"MemoryMax=($memory)"] } else { [] }
    let uid = (id -u | str trim)
    let gid = (id -g | str trim)
    [
        "sudo"
        "systemd-run"
        "--scope"
        "--quiet"
        "--collect"
        "--same-dir"
        "--unit" $unit
        "--uid" $uid
        "--gid" $gid
        "-p" "CPUWeight=100"
        ...$cpu_args
        ...$memory_args
        "bash"
        "-lc"
        $script
    ]
}

def start-e2e-local-node [
    role: string,
    phase: string,
    tempo_bin: string,
    args: list<string>,
    env_prefix: string,
    otel_attrs: string,
    tracy_env_prefix: string,
    samply: bool,
    samply_args: list<string>,
    results_dir: string,
    cpus: string,
    memory: string,
] {
    let profile_label = $"($phase)-($role)"
    let full_samply_args = if $samply {
        $samply_args | append ["--save-only" "--presymbolicate" "--output" $"($results_dir)/profile-($profile_label).json.gz"]
    } else { [] }
    let node_cmd = wrap-samply [$tempo_bin ...$args] $samply $full_samply_args
    let node_cmd_str = ($node_cmd | str join " ")
    let script = $"($env_prefix)($otel_attrs)($tracy_env_prefix)($node_cmd_str) 2>&1"
    let unit_phase = ($phase | str replace -a "_" "-" | str replace -a "." "-")
    let runner = (systemd-scope-command $"tempo-e2e-($role)-($unit_phase)" $cpus $memory $script)
    print $"Starting local e2e validator ($role) for ($phase): ($runner | str join ' ')"
    job spawn {
        run-external ($runner | first) ...($runner | skip 1)
        | lines
        | each { |line| print $"[e2e-($phase)-($role)] ($line)" }
    }
}

def stop-e2e-processes-gracefully [] {
    let pids = (find-tempo-pids)
    if ($pids | length) > 0 {
        print $"Stopping tempo processes: ($pids | str join ', ')"
    }
    for pid in $pids {
        kill -s 2 $pid
    }
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
    if ("/tmp/reth.ipc" | path exists) {
        rm --force /tmp/reth.ipc
    }
}

def stop-local-e2e-systemd-scopes [] {
    if (^uname | str trim) != "Linux" or ((which systemctl | length) == 0) {
        return
    }

    let units = (
        bash -lc "systemctl list-units 'tempo-e2e-*.scope' --all --plain --no-legend 2>/dev/null | awk '{print $1}'"
        | lines
        | where { |unit| $unit != "" }
    )
    for unit in $units {
        print $"Stopping stale local e2e scope: ($unit)"
        sudo systemctl kill --kill-whom=all $unit | ignore
        sudo systemctl reset-failed $unit | ignore
    }
}

def cleanup-local-e2e-processes [] {
    stop-local-e2e-systemd-scopes
    stop-e2e-processes-gracefully
    stop-tracy-capture
}

def e2e-wait-for-rpc-online [url: string, max_attempts: int] {
    mut attempt = 0

    loop {
        $attempt = $attempt + 1
        if $attempt > $max_attempts {
            print $"  Timeout waiting for ($url)"
            return false
        }
        let block = (rpc-block-number $url)
        if $block != null {
            print $"  ($url) online \(block ($block)\)"
            return true
        }
        if ($attempt mod 10) == 0 {
            print $"  Still waiting for ($url)... \(($attempt)s\)"
        }
        sleep 1sec
    }
}

def e2e-wait-for-peers [url: string, min_peers: int, max_attempts: int] {
    mut attempt = 0

    loop {
        $attempt = $attempt + 1
        if $attempt > $max_attempts {
            print $"  Timeout waiting for ($url) to reach ($min_peers) peer\(s\)"
            return false
        }
        let peers = (rpc-peer-count $url)
        if $peers != null and $peers >= $min_peers {
            print $"  ($url) has ($peers) peer\(s\)"
            return true
        }
        if ($attempt mod 10) == 0 {
            let current = if $peers == null { "unknown" } else { $"($peers)" }
            print $"  ($url) peers: ($current)/($min_peers)... \(($attempt)s\)"
        }
        sleep 1sec
    }
}

def e2e-wait-for-chain-advance [url: string, max_attempts: int] {
    mut attempt = 0
    mut start_block: int = -1

    loop {
        $attempt = $attempt + 1
        if $attempt > $max_attempts {
            print $"  Timeout waiting for ($url) chain to advance"
            return false
        }
        let block = (rpc-block-number $url)
        if $block != null {
            if $start_block == -1 {
                $start_block = $block
                print $"  ($url) connected \(block ($block)\), waiting for chain to advance..."
            } else if $block > $start_block {
                print $"  ($url) ready \(block ($start_block) -> ($block)\)"
                return true
            } else if ($attempt mod 10) == 0 {
                print $"  ($url) still at block ($block)... \(($attempt)s\)"
            }
        } else if ($attempt mod 10) == 0 {
            print $"  ($url) unavailable while waiting for chain advance... \(($attempt)s\)"
        }
        sleep 1sec
    }
}

def init-local-e2e-side [
    role: string,
    state_path: string,
    mount_point: string,
    datadir: string,
    node_dir: string,
    generated_node_dir: string,
    generated_genesis: string,
    trusted_peers: string,
    bloat: int,
    bloat_file: string,
    tempo_bin: string,
    marker: record,
] {
    let meta_dir = $"($datadir)/($BENCH_META_SUBDIR)"
    let generated_trusted_peers = $"($LOCALNET_DIR)/e2e-local-init/trusted-peers.txt"

    bench-clean-datadir $datadir
    mkdir $datadir
    mkdir $node_dir

    bench-init-db $tempo_bin $generated_genesis $datadir $bloat $bloat_file
    for file in ["signing.key" "signing.share" "enode.key" "enode.identity"] {
        cp $"($generated_node_dir)/($file)" $"($node_dir)/($file)"
    }
    $trusted_peers | save -f $generated_trusted_peers

    bench-save-e2e-meta $datadir $meta_dir ($marker | insert validator_role $role) [[$generated_genesis "genesis.json"] [$generated_trusted_peers "trusted-peers.txt"]]
}

def run-local-e2e-phase [run: record, ctx: record] {
    let phase = $run.phase
    print $"=== Starting local e2e phase: ($phase) ==="
    let run_type = if ($phase | str starts-with "baseline") { "baseline" } else { "feature" }
    let side_args = if $run_type == "baseline" { $ctx.baseline_args } else { $ctx.feature_args }
    let side_env = if $run_type == "baseline" { $ctx.baseline_env } else { $ctx.feature_env }
    let effective_node_args = ([$ctx.node_args $side_args] | where { |a| $a != "" } | str join " ")
    let extra_args = if $effective_node_args == "" { [] } else { $effective_node_args | split row " " }
    let weights = if $ctx.preset != "" { $PRESETS | get $ctx.preset } else { [0.0, 0.0, 0.0, 0.0] }

    cleanup-local-e2e-processes
    bench-restore-at $ctx.a.state_path $ctx.a.mount $ctx.a.datadir
    bench-restore-at $ctx.b.state_path $ctx.b.mount $ctx.b.datadir

    for path in [$ctx.genesis $ctx.a.node_dir $ctx.b.node_dir] {
        if not ($path | path exists) {
            print $"Error: required e2e path does not exist after snapshot recovery: ($path)"
            exit 1
        }
    }
    for role_info in [
        { role: "a", node_dir: $ctx.a.node_dir }
        { role: "b", node_dir: $ctx.b.node_dir }
    ] {
        for required_file in ["signing.key" "signing.share" "enode.key"] {
            let path = $"($role_info.node_dir)/($required_file)"
            if not ($path | path exists) {
                print $"Error: missing ($role_info.role) validator file after snapshot recovery: ($path)"
                exit 1
            }
        }
    }

    let a_log_dir = $"($LOCALNET_DIR)/logs-e2e-local-($phase)-a"
    let b_log_dir = $"($LOCALNET_DIR)/logs-e2e-local-($phase)-b"
    for dir in [$a_log_dir $b_log_dir] {
        if ($dir | path exists) { rm -rf $dir }
        mkdir $dir
    }

    for stale in [
        $"($ctx.results_dir)/report-($phase).json"
        $"($ctx.results_dir)/profile-($phase)-a.json.gz"
        $"($ctx.results_dir)/profile-($phase)-b.json.gz"
        $"($ctx.results_dir)/tracy-profile-($phase).tracy"
        $"($ctx.results_dir)/logs-($phase)-a"
        $"($ctx.results_dir)/logs-($phase)-b"
    ] {
        if ($stale | path exists) { rm -rf $stale }
    }
    if ("report.json" | path exists) { rm report.json }
    let tuning_state = if $ctx.tune { apply-system-tuning } else { { tuned: false } }

    let a_rpc = "http://127.0.0.1:8545"
    let b_rpc = "http://127.0.0.1:8645"
    let a_base_args = (build-base-args $ctx.genesis $ctx.a.datadir $a_log_dir "0.0.0.0" 8545 9001)
        | append (build-e2e-consensus-args $ctx.a.node_dir $ctx.trusted_peers $ctx.a.consensus_port $ctx.a.ip)
        | append $E2E_LOCAL_RETH_ARGS
        | append (log-filter-args $ctx.loud)
        | append (if $ctx.gas_limit != "" { ["--builder.gaslimit" $ctx.gas_limit] } else { [] })
        | append (if $ctx.tracy != "off" { ["--log.tracy" "--log.tracy.filter" $ctx.tracy_filter] } else { [] })
    let b_base_args = (build-base-args $ctx.genesis $ctx.b.datadir $b_log_dir "0.0.0.0" 8645 9101)
        | append (build-e2e-consensus-args $ctx.b.node_dir $ctx.trusted_peers $ctx.b.consensus_port $ctx.b.ip)
        | append $E2E_LOCAL_RETH_ARGS
        | append (log-filter-args $ctx.loud)
        | append (if $ctx.gas_limit != "" { ["--builder.gaslimit" $ctx.gas_limit] } else { [] })
        | append (if $ctx.tracy != "off" { ["--log.tracy" "--log.tracy.filter" $ctx.tracy_filter] } else { [] })
    let a_args = (dedup-args $a_base_args $extra_args)
    let b_args = (dedup-args $b_base_args $extra_args)

    let tracy_env_prefix = if $ctx.tracy == "on" {
        "TRACY_NO_SYS_TRACE=1 "
    } else if $ctx.tracy == "full" {
        "TRACY_SAMPLING_HZ=1 "
    } else { "" }
    let env_prefix = if $side_env != "" { $"($side_env) " } else { "" }
    let a_otel = $"OTEL_RESOURCE_ATTRIBUTES=benchmark_id=($ctx.benchmark_id),benchmark_run=($phase),runner_role=a,run_type=($run_type),git_ref=($run.ref),reference_epoch=($ctx.reference_epoch) "
    let b_otel = $"OTEL_RESOURCE_ATTRIBUTES=benchmark_id=($ctx.benchmark_id),benchmark_run=($phase),runner_role=b,run_type=($run_type),git_ref=($run.ref),reference_epoch=($ctx.reference_epoch) "

    start-e2e-local-node a $phase $run.tempo $a_args $env_prefix $a_otel $tracy_env_prefix $ctx.samply $ctx.samply_args $ctx.results_dir $ctx.a.cpus $ctx.a.memory
    start-e2e-local-node b $phase $run.tempo $b_args $env_prefix $b_otel $tracy_env_prefix $ctx.samply $ctx.samply_args $ctx.results_dir $ctx.b.cpus $ctx.b.memory

    sleep 2sec
    let rpc_timeout = if $ctx.bloat > 0 { 600 } else { 300 }
    mut phase_exit = 0
    if ((find-tempo-pids) | length) < 2 {
        print $"Error: local e2e validators exited before readiness checks completed for ($phase)"
        $phase_exit = 1
    }
    if $phase_exit == 0 and not (e2e-wait-for-rpc-online $a_rpc $rpc_timeout) { $phase_exit = 1 }
    if $phase_exit == 0 and not (e2e-wait-for-rpc-online $b_rpc $rpc_timeout) { $phase_exit = 1 }
    if $phase_exit == 0 and not (e2e-wait-for-peers $a_rpc 1 300) { $phase_exit = 1 }
    if $phase_exit == 0 and not (e2e-wait-for-peers $b_rpc 1 300) { $phase_exit = 1 }
    if $phase_exit == 0 and not (e2e-wait-for-chain-advance $a_rpc 300) { $phase_exit = 1 }
    if $phase_exit == 0 and not (e2e-wait-for-chain-advance $b_rpc 300) { $phase_exit = 1 }

    let tracy_output = $"($ctx.results_dir)/tracy-profile-($phase).tracy"
    mut tracy_capture_started = false
    if $phase_exit == 0 and $ctx.tracy != "off" {
        let seconds_flag = if $ctx.tracy_seconds > 0 { $"-s ($ctx.tracy_seconds)" } else { "" }
        let limit_msg = if $ctx.tracy_seconds > 0 { $" \(($ctx.tracy_seconds)s limit\)" } else { "" }
        if $ctx.tracy_offset > 0 {
            print $"  Tracy-capture will start in ($ctx.tracy_offset)s($limit_msg)..."
            job spawn { sleep ($"($ctx.tracy_offset)sec" | into duration); sh -c $"tracy-capture -f -o ($tracy_output) ($seconds_flag)" }
        } else {
            print $"  Starting tracy-capture($limit_msg)..."
            job spawn { sh -c $"tracy-capture -f -o ($tracy_output) ($seconds_flag)" }
            sleep 500ms
        }
        $tracy_capture_started = true
    }

    let bench_cmd = [
        $run.bench
        "run-max-tps"
        "--tps" $"($ctx.tps)"
        "--duration" $"($ctx.duration)"
        "--accounts" $"($ctx.accounts)"
        "--max-concurrent-requests" $"($ctx.max_concurrent_requests)"
        "--target-urls" $"($a_rpc),($b_rpc)"
        "--faucet"
        "--clear-txpool"
    ]
    | append (if $ctx.preset != "" {
        [
            "--tip20-weight" $"($weights | get 0)"
            "--erc20-weight" $"($weights | get 1)"
            "--swap-weight" $"($weights | get 2)"
            "--place-order-weight" $"($weights | get 3)"
        ]
    } else { [] })
    | append (if $ctx.bloat > 0 { ["--mnemonic" $"'($BLOAT_MNEMONIC)'"] } else { [] })
    | append (if $ctx.bench_args != "" { $ctx.bench_args | split row " " } else { [] })
    | append ["--node-commit-sha" $run.ref "--build-profile" $ctx.profile "--benchmark-mode" "e2e"]

    if $phase_exit == 0 {
        let bench_env_export = if $ctx.bench_env != "" { $"export ($ctx.bench_env) && " } else { "" }
        print $"Running local e2e sender: ($bench_cmd | str join ' ')"
        let bench_result = (bash -c $"($bench_env_export)ulimit -Sn unlimited && ($bench_cmd | str join ' ')" | complete)
        if $bench_result.stdout != "" { print $bench_result.stdout }
        if $bench_result.stderr != "" { print $bench_result.stderr }
        $phase_exit = $bench_result.exit_code

        if ("report.json" | path exists) {
            cp report.json $"($ctx.results_dir)/report-($phase).json"
            rm report.json
        } else {
            print $"ERROR: sender for ($phase) produced no report.json"
            $phase_exit = 1
        }
    } else {
        print $"Skipping local e2e sender for ($phase) because readiness checks failed"
    }

    if $tracy_capture_started {
        stop-tracy-capture
    }
    stop-e2e-processes-gracefully
    if $ctx.samply { wait-for-samply-profile }
    if ($a_log_dir | path exists) { cp -r $a_log_dir $"($ctx.results_dir)/logs-($phase)-a" }
    if ($b_log_dir | path exists) { cp -r $b_log_dir $"($ctx.results_dir)/logs-($phase)-b" }
    restore-system-tuning $tuning_state

    if $phase_exit != 0 {
        return $phase_exit
    }
    print $"=== Local e2e phase complete: ($phase) ==="
    return 0
}

# Run the baseline-feature-feature-baseline e2e sequence on one runner.
def "main e2e" [
    --baseline: string                                  # Baseline git SHA/ref
    --feature: string                                   # Feature git SHA/ref
    --preset: string = ""                               # Preset: tip20, erc20, swap, order, tempo-mix
    --tps: int = 10000                                  # Target TPS
    --duration: int = 300                               # Duration in seconds
    --accounts: int = 1000                              # Number of accounts
    --max-concurrent-requests: int = 100                # Max concurrent requests
    --bloat: int = 0                                    # State bloat size in MiB
    --force-bloat                                      # Regenerate and promote both local e2e snapshots
    --init-only                                         # Refresh snapshots and exit without running benchmark phases
    --profile: string = $DEFAULT_PROFILE                # Cargo build profile
    --features: string = $DEFAULT_FEATURES              # Cargo features
    --samply                                            # Profile validators with samply
    --samply-args: string = ""                          # Additional samply arguments
    --tracy: string = "off"                             # Tracy profiling: off, on, full
    --tracy-filter: string = "debug"                    # Tracy tracing filter level
    --tracy-seconds: int = 30                           # Tracy capture duration limit in seconds
    --tracy-offset: int = 120                           # Seconds to wait before starting tracy capture
    --node-args: string = ""                            # Additional node args for all phases
    --baseline-args: string = ""                        # Additional node args for baseline phases
    --feature-args: string = ""                         # Additional node args for feature phases
    --bench-args: string = ""                           # Additional tempo-bench args
    --baseline-env: string = ""                         # Environment vars for baseline node phases
    --feature-env: string = ""                          # Environment vars for feature node phases
    --bench-env: string = ""                            # Environment vars for the sender process
    --baseline-name: string = ""                         # Baseline display name for summary
    --feature-name: string = ""                          # Feature display name for summary
    --tune                                              # Apply system tuning
    --loud                                              # Show node debug logs
    --no-cache                                           # Skip binary cache
] {
    if $preset == "" and $bench_args == "" {
        print "Error: either --preset or --bench-args must be provided"
        print $"  Available presets: ($PRESETS | columns | str join ', ')"
        exit 1
    }
    if $preset != "" and not ($preset in $PRESETS) {
        print $"Unknown preset: ($preset). Available: ($PRESETS | columns | str join ', ')"
        exit 1
    }
    if $tracy not-in ["off" "on" "full"] {
        print $"Error: --tracy must be one of: off, on, full \(got '($tracy)'\)"
        exit 1
    }
    if $samply and $tracy != "off" {
        print "Error: --samply and --tracy are mutually exclusive. Choose one."
        exit 1
    }
    if $init_only and not $force_bloat {
        print "Error: --init-only requires --force-bloat"
        exit 1
    }
    if $tracy != "off" and ((which tracy-capture | length) == 0) {
        print "Error: tracy-capture not found. Install tracy and ensure tracy-capture is in PATH."
        exit 1
    }

    let validator_list = (
        $E2E_VALIDATORS
        | split row ","
        | each { |v| $v | str trim }
        | where { |v| $v != "" }
    )
    if ($validator_list | length) != 2 {
        print "Error: E2E_VALIDATORS must contain exactly two comma-separated consensus addresses ordered as a,b"
        exit 1
    }
    let a_validator = ($validator_list | get 0)
    let b_validator = ($validator_list | get 1)
    let a_ip = ($a_validator | split row ":" | get 0)
    let a_consensus_port = ($a_validator | split row ":" | get 1 | into int)
    let b_ip = ($b_validator | split row ":" | get 0)
    let b_consensus_port = ($b_validator | split row ":" | get 1 | into int)
    let a_db = $"($E2E_A_MOUNT)/tempo_e2e_($bloat)mb"
    let b_db = $"($E2E_B_MOUNT)/tempo_e2e_($bloat)mb"
    let a_identity = $a_db
    let b_identity = $b_db
    let genesis_path = $"($a_db)/($BENCH_META_SUBDIR)/genesis.json"
    let a_trusted_peers_path = $"($a_db)/($BENCH_META_SUBDIR)/trusted-peers.txt"
    let run_started_at = (date now)
    let timestamp = ($run_started_at | format date "%Y%m%d-%H%M%S-%3f")
    let benchmark_id = $"bench-e2e-local-($timestamp)"
    let reference_epoch = (($run_started_at | into int) / 1_000_000_000 | into int)
    let gas_limit_args = if $E2E_GAS_LIMIT != "" { ["--gas-limit" $E2E_GAS_LIMIT] } else { [] }

    validate-schelk-state $E2E_A_STATE_PATH $E2E_B_STATE_PATH
    cleanup-local-e2e-processes

    if $force_bloat {
        let init_dir = $"($LOCALNET_DIR)/e2e-local-init"
        let generated_genesis = $"($init_dir)/genesis.json"
        let bloat_file = $"($E2E_BLOAT_TMP_DIR)/state_bloat.bin"
        if ($init_dir | path exists) { rm -rf $init_dir }
        mkdir $init_dir
        bench-restore-at $E2E_A_STATE_PATH $E2E_A_MOUNT $a_db
        bench-restore-at $E2E_B_STATE_PATH $E2E_B_MOUNT $b_db
        if ($E2E_BLOAT_TMP_DIR | path exists) { rm -rf $E2E_BLOAT_TMP_DIR }
        mkdir $E2E_BLOAT_TMP_DIR

        build-tempo ["tempo"] $profile $features
        let tempo_bin = if $profile == "dev" { "./target/debug/tempo" } else { $"./target/($profile)/tempo" }
        let genesis_accounts = ([$accounts 3] | math max) + 1
        print $"Generating local e2e localnet config for validators: ($E2E_VALIDATORS)"
        cargo run -p tempo-xtask --profile $profile -- generate-localnet -o $init_dir --accounts $genesis_accounts --validators $E2E_VALIDATORS --seed $E2E_SEED --force ...$gas_limit_args

        let trusted_peers = (trusted-peers-from-localnet $init_dir)
        if $trusted_peers == "" {
            print "Error: generated localnet did not produce trusted peers"
            exit 1
        }
        if $bloat > 0 {
            ensure-bloat-space $bloat
            print $"Generating local e2e state bloat \(($bloat) MiB\)..."
            let token_args = ($TIP20_TOKEN_IDS | each { |id| ["--token" $"($id)"] } | flatten)
            cargo run -p tempo-xtask --profile $profile -- generate-state-bloat --size $bloat --out $bloat_file ...$token_args
        }

        let marker = {
            bloat_mib: $bloat
            accounts: $genesis_accounts
            validators: $E2E_VALIDATORS
            seed: $E2E_SEED
            gas_limit: $E2E_GAS_LIMIT
            dkg_in_genesis: true
            topology: "single-runner"
        }
        init-local-e2e-side a $E2E_A_STATE_PATH $E2E_A_MOUNT $a_db $a_identity $"($init_dir)/($a_validator)" $generated_genesis $trusted_peers $bloat $bloat_file $tempo_bin ($marker | insert bench_datadir $a_db | insert node_dir $a_identity | insert validator_addr $a_validator)
        init-local-e2e-side b $E2E_B_STATE_PATH $E2E_B_MOUNT $b_db $b_identity $"($init_dir)/($b_validator)" $generated_genesis $trusted_peers $bloat $bloat_file $tempo_bin ($marker | insert bench_datadir $b_db | insert node_dir $b_identity | insert validator_addr $b_validator)
        if ($E2E_BLOAT_TMP_DIR | path exists) {
            rm -rf $E2E_BLOAT_TMP_DIR
        }
        bench-promote-at $E2E_A_STATE_PATH $a_db
        bench-promote-at $E2E_B_STATE_PATH $b_db
    }

    bench-restore-at $E2E_A_STATE_PATH $E2E_A_MOUNT $a_db
    bench-restore-at $E2E_B_STATE_PATH $E2E_B_MOUNT $b_db
    if $init_only {
        cleanup-local-e2e-processes
        return
    }
    let trusted_peers = if ($a_trusted_peers_path | path exists) {
        open $a_trusted_peers_path | str trim
    } else {
        let b_trusted_peers_path = $"($b_db)/($BENCH_META_SUBDIR)/trusted-peers.txt"
        if ($b_trusted_peers_path | path exists) {
            open $b_trusted_peers_path | str trim
        } else {
            print $"Error: trusted peers file not found in ($a_trusted_peers_path) or ($b_trusted_peers_path)"
            exit 1
        }
    }

    let results_dir = $"($BENCH_RESULTS_DIR)/($timestamp)"
    mkdir $results_dir
    print $"BENCH_RESULTS_DIR=($results_dir)"

    git worktree prune
    mkdir $BENCH_WORKTREES_DIR
    let baseline_wt = $"($BENCH_WORKTREES_DIR)/e2e-local-baseline"
    let feature_wt = $"($BENCH_WORKTREES_DIR)/e2e-local-feature"
    for wt in [$baseline_wt $feature_wt] {
        if ($wt | path exists) {
            print $"Removing stale local e2e worktree: ($wt)"
            try { git worktree remove --force $wt } catch { rm -rf $wt }
        }
    }
    git worktree add $baseline_wt $baseline
    git worktree add $feature_wt $feature

    let tbc = (tracy-build-config $features $tracy)
    let effective_features = $tbc.features
    let effective_extra_rustflags = $tbc.extra_rustflags
    let effective_no_cache = $no_cache or ($tracy != "off")
    if $effective_no_cache {
        build-in-worktree --no-cache --extra-rustflags $effective_extra_rustflags --bench-features $features $baseline_wt $baseline $profile $effective_features $baseline
        build-in-worktree --no-cache --extra-rustflags $effective_extra_rustflags --bench-features $features $feature_wt $feature $profile $effective_features $feature
    } else {
        build-in-worktree $baseline_wt $baseline $profile $effective_features $baseline
        build-in-worktree $feature_wt $feature $profile $effective_features $feature
    }
    let baseline_tempo = (worktree-bin $baseline_wt $profile "tempo")
    let baseline_bench = (worktree-bin $baseline_wt $profile "tempo-bench")
    let feature_tempo = (worktree-bin $feature_wt $profile "tempo")
    let feature_bench = (worktree-bin $feature_wt $profile "tempo-bench")
    let samply_args_list = if $samply_args == "" { [] } else { $samply_args | split row " " }
    let ctx = {
        genesis: $genesis_path
        trusted_peers: $trusted_peers
        a: {
            state_path: $E2E_A_STATE_PATH
            mount: $E2E_A_MOUNT
            datadir: $a_db
            node_dir: $a_identity
            ip: $a_ip
            consensus_port: $a_consensus_port
            cpus: $E2E_A_CPUS
            memory: $E2E_A_MEMORY
        }
        b: {
            state_path: $E2E_B_STATE_PATH
            mount: $E2E_B_MOUNT
            datadir: $b_db
            node_dir: $b_identity
            ip: $b_ip
            consensus_port: $b_consensus_port
            cpus: $E2E_B_CPUS
            memory: $E2E_B_MEMORY
        }
        preset: $preset
        tps: $tps
        duration: $duration
        accounts: $accounts
        max_concurrent_requests: $max_concurrent_requests
        bloat: $bloat
        results_dir: $results_dir
        profile: $profile
        samply: $samply
        samply_args: $samply_args_list
        tracy: $tracy
        tracy_filter: $tracy_filter
        tracy_seconds: $tracy_seconds
        tracy_offset: $tracy_offset
        node_args: $node_args
        baseline_args: $baseline_args
        feature_args: $feature_args
        bench_args: $bench_args
        baseline_env: $baseline_env
        feature_env: $feature_env
        bench_env: $bench_env
        benchmark_id: $benchmark_id
        reference_epoch: $reference_epoch
        tune: $tune
        loud: $loud
        gas_limit: $E2E_GAS_LIMIT
    }

    let runs = [
        { phase: "baseline-1", ref: $baseline, tempo: $baseline_tempo, bench: $baseline_bench }
        { phase: "feature-1", ref: $feature, tempo: $feature_tempo, bench: $feature_bench }
        { phase: "feature-2", ref: $feature, tempo: $feature_tempo, bench: $feature_bench }
        { phase: "baseline-2", ref: $baseline, tempo: $baseline_tempo, bench: $baseline_bench }
    ]
    mut e2e_exit = 0
    for run in $runs {
        let phase_exit = (run-local-e2e-phase $run $ctx)
        if $phase_exit != 0 {
            $e2e_exit = $phase_exit
            break
        }
    }

    if $e2e_exit == 0 and $samply {
        print "\nUploading local e2e samply profiles to Firefox Profiler..."
        for run in $runs {
            for role in ["a" "b"] {
                let profile_label = $"($run.phase)-($role)"
                let profile = $"($results_dir)/profile-($profile_label).json.gz"
                let url = (upload-samply-profile $profile)
                if $url != null {
                    $url | save -f $"($results_dir)/profile-($profile_label)-url.txt"
                }
            }
        }
    }
    if $e2e_exit == 0 and $tracy != "off" {
        print "\nUploading local e2e tracy profiles to R2..."
        for run in $runs {
            let profile = $"($results_dir)/tracy-profile-($run.phase).tracy"
            let viewer_url = (upload-tracy-profile $profile $run.phase $run.ref)
            if $viewer_url != null {
                $viewer_url | save -f $"($results_dir)/tracy-($run.phase)-url.txt"
            }
        }
    }

    let baseline_label = if $baseline_name != "" { $baseline_name } else { $baseline }
    let feature_label = if $feature_name != "" { $feature_name } else { $feature }
    if $e2e_exit == 0 {
        generate-summary $results_dir $baseline_label $feature_label $bloat $preset $tps $duration --benchmark-id $benchmark_id --reference-epoch $reference_epoch
    }

    try { git worktree remove --force $baseline_wt } catch { }
    try { git worktree remove --force $feature_wt } catch { }
    cleanup-local-e2e-processes
    bench-restore-at $E2E_A_STATE_PATH $E2E_A_MOUNT $a_db
    bench-restore-at $E2E_B_STATE_PATH $E2E_B_MOUNT $b_db
    if $e2e_exit != 0 {
        exit $e2e_exit
    }
}
