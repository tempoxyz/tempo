#!/usr/bin/env nu

# CodSpeed pre-bench fixture collection.
#
# Restores one existing large benchmark snapshot, starts a single dev-mode Tempo
# node, runs txgen + bench for the TIP20 profile, and writes the block artifacts
# that Criterion benchmarks consume later in the CodSpeed job.

source tempo.nu

const PREBENCH_STATE_PATH = "/var/lib/schelk/a.json"
const PREBENCH_MOUNT = "/reth-bench-a"
const PREBENCH_SCHELK_SCRIPT = "bench-schelk.nu"
const PREBENCH_FREE_MARGIN_MIB = 51200

def run-prebench-schelk [...args: string] {
    let result = (nu $PREBENCH_SCHELK_SCRIPT ...$args | complete)
    if $result.stdout != "" { print $result.stdout }
    if $result.stderr != "" { print $result.stderr }
    if $result.exit_code != 0 {
        error make { msg: $"bench-schelk failed: ($args | str join ' ')" }
    }
}

def has-prebench-schelk [] {
    (has-schelk) and ($PREBENCH_STATE_PATH | path exists)
}

def prebench-bloat-gib-to-mib [bloat: int] {
    if $bloat in [1 10 100] {
        return ($bloat * 1000)
    }

    print "Error: --bloat must be one of: 1, 10, 100"
    exit 1
}

def prebench-datadir [bloat_mib: int, configured: string] {
    if $configured != "" {
        return ($configured | path expand)
    }

    if (has-prebench-schelk) {
        return $"($PREBENCH_MOUNT)/tempo_e2e_($bloat_mib)mb"
    }

    $"($LOCALNET_DIR | path expand)/codspeed-prebench-reth"
}

def prebench-generated-datadir [bloat_mib: int] {
    if (has-prebench-schelk) {
        return $"($PREBENCH_MOUNT)/tempo_codspeed_($bloat_mib)mb"
    }

    $"($LOCALNET_DIR | path expand)/codspeed-prebench-reth"
}

def restore-prebench-snapshot [datadir: string] {
    if (has-prebench-schelk) {
        print $"Restoring pre-bench snapshot at ($PREBENCH_MOUNT)..."
        run-prebench-schelk "restore" $PREBENCH_STATE_PATH $PREBENCH_MOUNT
        return
    }

    if ($"($datadir).virgin" | path exists) {
        print $"Restoring snapshot from ($datadir).virgin..."
        rm -rf $datadir
        ^cp -a $"($datadir).virgin" $datadir
    }
}

def promote-prebench-snapshot [datadir: string] {
    if (has-prebench-schelk) {
        print $"Promoting pre-bench snapshot at ($PREBENCH_MOUNT)..."
        run-prebench-schelk "promote" $PREBENCH_STATE_PATH
        return
    }

    print $"Saving snapshot to ($datadir).virgin..."
    rm -rf $"($datadir).virgin"
    ^cp -a $datadir $"($datadir).virgin"
}

def df-available-mib [path: string] {
    let row = (^df -Pm $path | lines | skip 1 | first | split row --regex '\s+')
    $row | get 3 | into int
}

def ensure-prebench-space [mount: string, bloat_mib: int] {
    if $bloat_mib <= 0 or not ($mount | path exists) {
        return
    }

    let required_mib = $bloat_mib + $PREBENCH_FREE_MARGIN_MIB
    let available_mib = (df-available-mib $mount)
    if $available_mib < $required_mib {
        print $"Error: ($mount) has ($available_mib) MiB free, needs at least ($required_mib) MiB for ($bloat_mib) MiB bloat plus margin"
        exit 1
    }
}

def prebench-meta-dir [datadir: string] {
    $"($datadir)/($BENCH_META_SUBDIR)"
}

def prebench-genesis-path [datadir: string] {
    $"(prebench-meta-dir $datadir)/genesis.json"
}

def prebench-snapshot-required-files [datadir: string] {
    [
        (prebench-genesis-path $datadir)
        $"(prebench-meta-dir $datadir)/marker.json"
        $"($datadir)/db"
        $"($datadir)/static_files"
    ]
}

def prebench-snapshot-ready [datadir: string] {
    (prebench-snapshot-required-files $datadir | where { |path| not ($path | path exists) } | length) == 0
}

def save-prebench-meta [datadir: string, genesis_path: string, marker: record] {
    let meta_dir = (prebench-meta-dir $datadir)
    mkdir $meta_dir
    cp $genesis_path $"($meta_dir)/genesis.json"
    $marker | insert initialized_at (date now | format date "%Y-%m-%dT%H:%M:%SZ") | to json | save -f $"($meta_dir)/marker.json"
}

def init-prebench-snapshot [
    tempo_bin: string,
    datadir: string,
    bloat_mib: int,
    accounts: int,
    gas_limit: string,
    profile: string,
] {
    let init_dir = $"($LOCALNET_DIR)/codspeed-prebench-init"
    let bloat_file = $"($init_dir)/state_bloat.bin"
    let genesis_accounts = ([$accounts 3] | math max) + 1
    let gas_limit_args = if $gas_limit != "" { ["--gas-limit" $gas_limit] } else { [] }

    if ($init_dir | path exists) { rm -rf $init_dir }
    mkdir $init_dir

    ensure-prebench-space (if (has-prebench-schelk) { $PREBENCH_MOUNT } else { "." }) $bloat_mib

    print $"Generating CodSpeed pre-bench genesis with ($genesis_accounts) accounts..."
    cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $init_dir -a $genesis_accounts --mnemonic (txgen-account-mnemonic) --no-dkg-in-genesis ...$gas_limit_args

    if $bloat_mib > 0 {
        print $"Generating CodSpeed pre-bench state bloat \(($bloat_mib) MiB\)..."
        let token_args = ($TIP20_TOKEN_IDS | each { |id| ["--token" $"($id)"] } | flatten)
        cargo run -p tempo-xtask --profile $profile -- generate-state-bloat --size $bloat_mib --out $bloat_file ...$token_args
    }

    bench-clean-datadir $datadir
    mkdir $datadir
    bench-init-db $tempo_bin $"($init_dir)/genesis.json" $datadir $bloat_mib $bloat_file
    save-prebench-meta $datadir $"($init_dir)/genesis.json" {
        bloat_mib: $bloat_mib
        accounts: $genesis_accounts
        gas_limit: $gas_limit
        topology: "single-node"
        txgen_mnemonic: (txgen-account-mnemonic)
    }
    promote-prebench-snapshot $datadir
    restore-prebench-snapshot $datadir
}

def stop-prebench-node [] {
    let pids = (find-tempo-pids)
    if ($pids | length) > 0 {
        print $"Stopping tempo process\(es): ($pids | str join ', ')"
    }
    for pid in $pids {
        kill -s 2 $pid
    }
    for pid in $pids {
        mut waited = 0
        while $waited < 30 {
            if (ps | where pid == $pid | length) == 0 { break }
            sleep 1sec
            $waited = $waited + 1
        }
        if $waited >= 30 {
            print $"  Warning: PID ($pid) did not exit, sending SIGKILL"
            kill -s 9 $pid
            sleep 1sec
        }
    }
}

def start-prebench-node [
    tempo_bin: string,
    genesis_path: string,
    datadir: string,
    output_dir: string,
    node_args: string,
    node_env: string,
    bloat_mib: int,
    loud: bool,
] {
    let log_dir = $"($output_dir)/logs-node"
    if ($log_dir | path exists) { rm -rf $log_dir }
    mkdir $log_dir

    let extra_args = if $node_args == "" { [] } else { $node_args | split row " " }
    let base_args = (build-base-args $genesis_path $datadir $log_dir "0.0.0.0" 8545 9001)
        | append (build-dev-args)
        | append [
            "--disable-discovery"
            "--builder.max-tasks" "1"
            "--engine.share-sparse-trie-with-payload-builder"
        ]
        | append (log-filter-args $loud)
    let args = (dedup-args $base_args $extra_args)
    let node_cmd = (txgen-shell-join [$tempo_bin ...$args])
    let env_prefix = if $node_env != "" { $"($node_env) " } else { "" }

    print $"Starting single-node CodSpeed pre-bench node: ($tempo_bin | path basename)"
    job spawn {
        bash -lc $"set -euo pipefail; ($env_prefix)($node_cmd) 2>&1"
        | lines
        | each { |line| print $"[codspeed-prebench-node] ($line)" }
    }

    sleep 2sec
    let rpc_timeout = if $bloat_mib > 0 { 600 } else { 120 }
    wait-for-rpc "http://localhost:8545" $rpc_timeout
}

def "main collect" [
    --preset: string = "tip20"                         # Txgen preset name
    --tps: int = 20000                                  # Target TPS
    --duration: int = 300                               # Duration in seconds
    --accounts: int = 1000                              # Number of accounts
    --max-concurrent-requests: int = 100                # Max concurrent requests
    --bloat: int = 100                                  # State bloat snapshot size in GiB: 1, 10, or 100
    --gas-limit: string = "1000000000"                  # Builder gas limit
    --profile: string = $DEFAULT_PROFILE                # Cargo build profile
    --features: string = $DEFAULT_FEATURES              # Cargo features
    --no-default-features                               # Disable Cargo default features
    --force-bloat                                       # Regenerate and promote the local snapshot
    --bench-args: string = ""                           # Additional txgen generate arguments
    --bench-env: string = ""                            # Environment vars for the sender process
    --node-args: string = ""                            # Additional node args
    --node-env: string = ""                             # Environment vars for the node process
    --bench-datadir: string = ""                        # Node database directory
    --output-dir: string = "codspeed-prebench"          # Directory for fixture artifacts
    --tune                                              # Apply system tuning
    --loud                                              # Show node debug logs
] {
    let preset_path = (txgen-preset-path $preset)
    let txgen = (txgen-resolve-binaries)
    let bloat_mib = (prebench-bloat-gib-to-mib $bloat)
    let restore_datadir = (prebench-datadir $bloat_mib $bench_datadir)
    let artifact_dir = ($output_dir | path expand)
    let current_sha = (git rev-parse HEAD | str trim)
    let timestamp = (date now | format date "%Y%m%d-%H%M%S-%3f")
    let benchmark_id = if (($env | get --optional GITHUB_RUN_ID) != null) {
        $"codspeed-prebench-($env.GITHUB_RUN_ID)"
    } else {
        $"codspeed-prebench-($timestamp)"
    }
    let block_access_list_output = $"($artifact_dir)/block-access-lists.ndjson.gz"
    let trie_witness_output = $"($artifact_dir)/trie-witnesses.ndjson.gz"
    let report_path = $"($artifact_dir)/report-codspeed-prebench.json"

    if ($artifact_dir | path exists) { rm -rf $artifact_dir }
    mkdir $artifact_dir

    stop-prebench-node
    build-tempo --no-default-features=$no_default_features ["tempo"] $profile $features
    let tempo_bin = if $profile == "dev" { "./target/debug/tempo" } else { $"./target/($profile)/tempo" }

    restore-prebench-snapshot $restore_datadir

    let e2e_datadir = $"($PREBENCH_MOUNT)/tempo_e2e_($bloat_mib)mb"
    let datadir = if $bench_datadir != "" {
        $restore_datadir
    } else if (has-prebench-schelk) and (not $force_bloat) and (prebench-snapshot-ready $e2e_datadir) {
        print $"Using existing large e2e snapshot: ($e2e_datadir)"
        $e2e_datadir
    } else {
        prebench-generated-datadir $bloat_mib
    }

    if $force_bloat or not (prebench-snapshot-ready $datadir) {
        if not $force_bloat {
            print $"CodSpeed pre-bench snapshot is missing required files; initializing ($datadir)."
        }
        init-prebench-snapshot $tempo_bin $datadir $bloat_mib $accounts $gas_limit $profile
    }

    let genesis_path = (prebench-genesis-path $datadir)
    if not ($genesis_path | path exists) {
        print $"Error: genesis file not found: ($genesis_path)"
        exit 1
    }

    let tuning_state = if $tune { apply-system-tuning } else { { tuned: false } }
    start-prebench-node $tempo_bin $genesis_path $datadir $artifact_dir $node_args $node_env $bloat_mib $loud

    let run_result = (try {
        let result = (txgen-run-preset-pipeline
            --txgen-tempo-bin ($txgen.txgen_tempo_bin)
            --txgen-bench-bin ($txgen.txgen_bench_bin)
            --preset-path $preset_path
            --generate-rpc-url "http://localhost:8545"
            --submit-rpc-url "http://localhost:8545"
            --metrics-url ["http://127.0.0.1:9001/metrics"]
            --report-path $report_path
            --tps $tps
            --duration $duration
            --accounts $accounts
            --max-concurrent-requests $max_concurrent_requests
            --bench-args $bench_args
            --bench-env $bench_env
            --git-ref $current_sha
            --git-ref-label "codspeed-prebench"
            --build-profile $profile
            --benchmark-mode "codspeed-prebench"
            --benchmark-id $benchmark_id
            --benchmark-run "codspeed-prebench"
            --run-type "codspeed-prebench"
            --platform "tempo"
            --scenario $"($preset)-($tps // 1000)k"
            --block-access-list-output $block_access_list_output
            --trie-witness-output $trie_witness_output
            --skip-funding=($bloat_mib > 0))
        $result
    } catch { |e|
        print $"Error: CodSpeed pre-bench txgen run failed: ($e.msg)"
        { ok: false, exit_code: 1, report_path: $report_path }
    })

    stop-prebench-node
    restore-system-tuning $tuning_state
    restore-prebench-snapshot $datadir

    if not $run_result.ok {
        exit $run_result.exit_code
    }

    for required in [$block_access_list_output $trie_witness_output $report_path] {
        if not ($required | path exists) {
            print $"Error: expected CodSpeed fixture artifact was not written: ($required)"
            exit 1
        }
    }

    {
        preset: $preset
        duration_secs: $duration
        tps: $tps
        accounts: $accounts
        max_concurrent_requests: $max_concurrent_requests
        bloat_gib: $bloat
        bloat_mib: $bloat_mib
        datadir: $datadir
        gas_limit: $gas_limit
        git_ref: $current_sha
        benchmark_id: $benchmark_id
        block_access_lists: "block-access-lists.ndjson.gz"
        trie_witnesses: "trie-witnesses.ndjson.gz"
        report: "report-codspeed-prebench.json"
        format: "gzip_ndjson"
    } | to json | save -f $"($artifact_dir)/manifest.json"

    print $"CodSpeed pre-bench fixtures written to ($artifact_dir)"
}
