#!/usr/bin/env nu

source ../../tempo.nu

const TXGEN_ACCOUNT_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
const TXGEN_DEFAULT_SEED = 99
const TXGEN_SCRAPE_INTERVAL_MS = 500
const TXGEN_DRAIN_TIMEOUT_SECS = 300
const TXGEN_FUND_DRAIN_TIMEOUT_SECS = 120
const TXGEN_EXPIRING_VALID_FOR_SECS = 30
const TXGEN_TIP20_TOKEN = "0x20c0000000000000000000000000000000000000"
const TXGEN_DEFAULT_RECIPIENT = "0x000000000000000000000000000000000000dEaD"

def shell-quote [value: any] {
    let s = ($value | into string)
    let escaped = ($s | str replace -a "'" "'\"'\"'")
    $"'($escaped)'"
}

def shell-join [args: list<any>] {
    $args | each { |arg| shell-quote $arg } | str join " "
}

def resolved-runtime-mode [mode: string] {
    if $mode == "e2e" {
        "dev"
    } else {
        $mode
    }
}

def sanitize-bench-args [bench_args: string] {
    if $bench_args == "" {
        return ""
    }

    $bench_args
        | str replace --all --regex '--existing-recipients=(true|false)' ''
        | str trim
}

def resolve-bench-binary [repo_dir: string] {
    let candidates = [
        $"($repo_dir)/target/release/bench"
        $"($repo_dir)/target/release/bench-cli"
    ]

    for candidate in $candidates {
        if ($candidate | path exists) {
            return $candidate
        }
    }

    error make { msg: $"txgen bench binary not found under ($repo_dir)/target/release/" }
}

def resolve-txgen-paths [repo_dir: string, txgen_tempo_bin: string, txgen_bench_bin: string] {
    let repo = if $repo_dir != "" {
        $repo_dir | path expand
    } else if ($env.TXGEN_REPO_DIR? | default "") != "" {
        $env.TXGEN_REPO_DIR | path expand
    } else {
        "../txgen" | path expand
    }

    if not ($repo | path exists) {
        error make { msg: $"txgen repo not found: ($repo)" }
    }

    let generator = if $txgen_tempo_bin != "" {
        $txgen_tempo_bin | path expand
    } else if ($env.TXGEN_TEMPO_BIN? | default "") != "" {
        $env.TXGEN_TEMPO_BIN | path expand
    } else {
        $"($repo)/target/release/txgen-tempo"
    }

    let bench = if $txgen_bench_bin != "" {
        $txgen_bench_bin | path expand
    } else if ($env.TXGEN_BENCH_BIN? | default "") != "" {
        $env.TXGEN_BENCH_BIN | path expand
    } else {
        resolve-bench-binary $repo
    }

    if not ($generator | path exists) {
        error make { msg: $"txgen-tempo binary not found: ($generator)" }
    }
    if not ($bench | path exists) {
        error make { msg: $"txgen bench binary not found: ($bench)" }
    }

    {
        repo_dir: $repo
        txgen_tempo_bin: $generator
        txgen_bench_bin: $bench
    }
}

def normalize-tracy-mode [value: any] {
    let mode = ($value | into string | str trim | str downcase)

    if $mode in ["" "off" "false"] {
        "off"
    } else if $mode in ["on" "true"] {
        "on"
    } else if $mode == "full" {
        "full"
    } else {
        error make { msg: $"--tracy must be one of: off, on, full \(got ($value)\)" }
    }
}

def rpc-call [rpc_url: string, payload: string] {
    let result = (^curl -sf -X POST -H "Content-Type: application/json" -d $payload $rpc_url | complete)
    if $result.exit_code != 0 {
        error make { msg: $"RPC call failed: ($payload)" }
    }
    $result.stdout | from json
}

def fetch-chain-id [rpc_url: string] {
    let response = (rpc-call $rpc_url '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}')
    $response.result | into int
}

def wait-for-txpool-drain [rpc_url: string, timeout_secs: int] {
    mut zero_count = 0
    mut waited = 0

    while $waited < $timeout_secs {
        let response = (rpc-call $rpc_url '{"jsonrpc":"2.0","method":"txpool_status","params":[],"id":1}')
        let pending = ($response.result.pending | into int)

        if $pending == 0 {
            $zero_count = $zero_count + 1
            if $zero_count >= 3 {
                return
            }
        } else {
            $zero_count = 0
        }

        sleep 1sec
        $waited = $waited + 1
    }

    print $"  Warning: txpool drain timeout reached after ($timeout_secs)s"
}

def write-tip20-spec [spec_path: string, txgen_repo_dir: string, chain_id: int, accounts: int] {
    let abi_path = $"($txgen_repo_dir)/examples/erc20.abi.json"
    let spec = [
        $"chain_id: ($chain_id)"
        ""
        "gas:"
        "  max_fee_per_gas: 100000000000"
        "  max_priority_fee_per_gas: 100000000000"
        ""
        "accounts:"
        "  users:"
        $"    mnemonic: \"($TXGEN_ACCOUNT_MNEMONIC)\""
        $"    range: [0, ($accounts)]"
        ""
        "artifacts:"
        $"  ERC20: \"($abi_path)\""
        ""
        "templates:"
        "  tip20_transfer:"
        "    type: tempo"
        "    from:"
        "      pool: users"
        "      select: random"
        "    gas_limit: 300000"
        "    max_fee_per_gas: 100000000000"
        "    max_priority_fee_per_gas: 100000000000"
        "    expiring_nonce: true"
        $"    valid_for_secs: ($TXGEN_EXPIRING_VALID_FOR_SECS)"
        "    call:"
        $"      to: \"($TXGEN_TIP20_TOKEN)\""
        "      abi: ERC20"
        "      function: transfer"
        "      args:"
        $"        - \"($TXGEN_DEFAULT_RECIPIENT)\""
        "        - 1"
        ""
        "mix:"
        "  - template: tip20_transfer"
        "    weight: 100"
    ] | str join "\n"

    $spec | save -f $spec_path
}

def fund-txgen-accounts [txgen_bin: string, spec_path: string, rpc_url: string] {
    let result = (^$txgen_bin addresses -s $spec_path -f shell | complete)
    if $result.exit_code != 0 {
        error make { msg: $"failed to list txgen addresses for ($spec_path)" }
    }

    let addresses = ($result.stdout | str trim | split row " " | where { |addr| $addr != "" })
    if ($addresses | is-empty) {
        error make { msg: $"txgen spec produced no addresses: ($spec_path)" }
    }

    print $"  Funding (($addresses | length)) txgen account\(s\)..."
    $addresses | par-each { |address|
        ^curl -sf -X POST -H "Content-Type: application/json" -d $"{\"jsonrpc\":\"2.0\",\"method\":\"tempo_fundAddress\",\"params\":[\"($address)\"],\"id\":1}" $rpc_url | ignore
    } | ignore

    print "  Waiting for faucet transactions to drain..."
    wait-for-txpool-drain $rpc_url $TXGEN_FUND_DRAIN_TIMEOUT_SECS
}

def adapt-txgen-report [raw_report: string, adapted_report: string] {
    ^python3 contrib/bench/txgen-report-adapter.py $raw_report $adapted_report
}

def run-txgen-bench-single [
    --tempo-bin: string
    --txgen-tempo-bin: string
    --txgen-bench-bin: string
    --txgen-repo-dir: string
    --genesis-path: string
    --datadir: string
    --run-label: string
    --results-dir: string
    --tps: int
    --duration: int
    --accounts: int
    --max-concurrent-requests: int
    --preset: string = ""
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
    --tracy: any = "off"
    --tracy-filter: string = "debug"
    --tracy-seconds: int = 0
    --tracy-offset: int = 0
    --tracing-otlp: string = ""
] {
    if $preset != "tip20" {
        error make { msg: $"txgen benchmark path currently supports only preset=tip20 \(got ($preset)\)" }
    }

    let ignored_bench_args = (sanitize-bench-args $bench_args)
    if $ignored_bench_args != "" {
        print $"  Warning: txgen path is ignoring unsupported bench args: ($ignored_bench_args)"
    }

    print $"=== Starting txgen run: ($run_label) ==="

    let log_dir = $"($LOCALNET_DIR)/logs-($run_label)"
    if ($log_dir | path exists) {
        rm -rf $log_dir
    }
    mkdir $log_dir

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

    let extra_args = if $node_args == "" { [] } else { $node_args | split row " " }
    let base_args = (build-base-args $genesis_path $datadir $log_dir "0.0.0.0" 8545 9001)
        | append (build-dev-args)
        | append (log-filter-args $loud)
        | append (if $tracy != "off" { ["--log.tracy" "--log.tracy.filter" $tracy_filter] } else { [] })
        | append (if $tracing_otlp != "" { [$"--tracing-otlp=($tracing_otlp)"] } else { [] })
    let args = (dedup-args $base_args $extra_args)

    let tracy_env_prefix = if $tracy == "on" {
        "TRACY_NO_SYS_TRACE=1 "
    } else if $tracy == "full" {
        "TRACY_SAMPLING_HZ=1 "
    } else { "" }

    let otel_attrs = $"OTEL_RESOURCE_ATTRIBUTES=benchmark_id=($benchmark_id),benchmark_run=($run_label),run_type=($run_type),git_ref=($git_ref) "
    let full_samply_args = if $samply {
        $samply_args | append ["--save-only" "--presymbolicate" "--output" $"($results_dir)/profile-($run_label).json.gz"]
    } else { [] }
    let node_cmd = wrap-samply [$tempo_bin ...$args] $samply $full_samply_args
    let node_cmd_str = ($node_cmd | str join " ")
    let profiling_label = if $samply { " (samply)" } else if $tracy != "off" { $" \(tracy=($tracy)\)" } else { "" }
    let env_prefix = if $extra_env != "" { $"($extra_env) " } else { "" }
    print $"  Starting node: ($tempo_bin | path basename)($profiling_label)"
    job spawn { sh -c $"($env_prefix)($otel_attrs)($tracy_env_prefix)($node_cmd_str) 2>&1" | lines | each { |line| print $"[($run_label)] ($line)" } }

    sleep 2sec
    let rpc_timeout = if $bloat > 0 { 600 } else { 120 }
    wait-for-rpc "http://localhost:8545" $rpc_timeout

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

    let chain_id = (fetch-chain-id "http://localhost:8545")
    let spec_path = $"($results_dir)/txgen-spec-($run_label).yaml"
    write-tip20-spec $spec_path $txgen_repo_dir $chain_id $accounts
    fund-txgen-accounts $txgen_tempo_bin $spec_path "http://localhost:8545"

    let raw_report_path = $"($results_dir)/txgen-report-($run_label).json"
    let tx_count = [($tps * $duration) 1] | math max
    let txgen_cmd = [
        $txgen_tempo_bin
        "generate"
        "-s" $spec_path
        "-n" $tx_count
        "--seed" $TXGEN_DEFAULT_SEED
        "--rpc" "http://localhost:8545"
    ]
    let bench_cmd = [
        $txgen_bench_bin
        "send"
        "--rpc-url" "http://localhost:8545"
        "--tps" $tps
        "--max-concurrent" $max_concurrent_requests
        "--metrics-url" "http://127.0.0.1:9090/metrics"
        "--scrape-interval-ms" $TXGEN_SCRAPE_INTERVAL_MS
        "--drain-timeout" $TXGEN_DRAIN_TIMEOUT_SECS
        "--report" $"json:($raw_report_path)"
        "-m" $"chain_id=($chain_id)"
        "-m" $"target_tps=($tps)"
        "-m" $"run_duration_secs=($duration)"
        "-m" $"accounts=($accounts)"
        "-m" $"total_connections=($max_concurrent_requests)"
        "-m" "tip20_weight=1.0"
        "-m" "place_order_weight=0.0"
        "-m" "swap_weight=0.0"
        "-m" "erc20_weight=0.0"
        "-m" $"node_commit_sha=($git_ref)"
        "-m" $"build_profile=($build_profile)"
        "-m" $"mode=($benchmark_mode)"
    ]
    let bench_env_export = if $bench_env != "" { $"export ($bench_env) && " } else { "" }
    let txgen_cmd_str = (shell-join $txgen_cmd)
    let bench_cmd_str = (shell-join $bench_cmd)

    print $"  Streaming ($tx_count) txgen transaction\(s\) into bench send..."
    let pipeline = $"set -euo pipefail; ($bench_env_export)($txgen_cmd_str) | ($bench_cmd_str)"
    try {
        bash -lc $pipeline
    } catch { |e|
        print $"  txgen benchmark run ($run_label) failed: ($e.msg)"
        error make { msg: $"txgen benchmark run ($run_label) failed" }
    }

    adapt-txgen-report $raw_report_path $"($results_dir)/report-($run_label).json"
    print $"  Report saved: report-($run_label).json"

    if $tracy_capture_started {
        print "  Stopping tracy-capture..."
        let capture_pids = (ps | where name =~ "tracy-capture" | get pid)
        for pid in $capture_pids {
            kill -s 2 $pid
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

    print "  Stopping node..."
    let pids = (find-tempo-pids)
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

    if $proxy_pid != null {
        let proxy_pids = (ps | where name =~ "bench-metrics-proxy" | get pid)
        for pid in $proxy_pids {
            kill -s 2 $pid
        }
    }

    if ("/tmp/reth.ipc" | path exists) {
        rm --force /tmp/reth.ipc
    }

    print $"=== Run ($run_label) complete ==="
}

def "main run" [
    --mode: string = "e2e"
    --preset: string = ""
    --tps: int = 10000
    --duration: int = 30
    --accounts: int = 1000
    --max-concurrent-requests: int = 100
    --samply
    --samply-args: string = ""
    --loud
    --profile: string = $DEFAULT_PROFILE
    --features: string = $DEFAULT_FEATURES
    --node-args: string = ""
    --baseline-args: string = ""
    --feature-args: string = ""
    --bench-args: string = ""
    --baseline-env: string = ""
    --feature-env: string = ""
    --bench-env: string = ""
    --bloat: int = 0
    --no-infra
    --baseline: string = ""
    --feature: string = ""
    --force
    --bench-datadir: string = ""
    --tune
    --no-cache
    --tracy: string = "off"
    --tracy-filter: string = "debug"
    --tracy-seconds: int = 30
    --tracy-offset: int = 120
    --tracing-otlp: string = ""
    --baseline-hardfork: string = ""
    --feature-hardfork: string = ""
    --gas-limit: string = ""
    --txgen-repo-dir: string = ""
    --txgen-tempo-bin: string = ""
    --txgen-bench-bin: string = ""
] {
    let runtime_mode = (resolved-runtime-mode $mode)
    if $runtime_mode != "dev" {
        error make { msg: $"txgen benchmark path currently supports only dev/e2e mode \(got ($mode)\)" }
    }
    if $preset != "tip20" {
        error make { msg: $"txgen benchmark path currently supports only preset=tip20 \(got ($preset)\)" }
    }
    if ($baseline != "" and $feature == "") or ($baseline == "" and $feature != "") {
        error make { msg: "--baseline and --feature must both be provided for txgen comparison mode" }
    }
    if $baseline == "" or $feature == "" {
        error make { msg: "txgen benchmark path currently supports comparison mode only" }
    }

    let txgen = (resolve-txgen-paths $txgen_repo_dir $txgen_tempo_bin $txgen_bench_bin)

    if $force and ($LOCALNET_DIR | path exists) {
        print "Removing existing localnet data (--force)..."
        rm -rf $LOCALNET_DIR
    }

    main kill
    let tuning_state = if $tune { apply-system-tuning } else { { tuned: false } }

    let tracy = (normalize-tracy-mode $tracy)
    if $samply and $tracy != "off" {
        error make { msg: "--samply and --tracy are mutually exclusive" }
    }
    if $tracy != "off" and ((which tracy-capture | length) == 0) {
        error make { msg: "tracy-capture not found in PATH" }
    }

    if ($baseline_hardfork != "" or $feature_hardfork != "") and ($baseline_hardfork == "" or $feature_hardfork == "") {
        error make { msg: "--baseline-hardfork and --feature-hardfork must both be provided" }
    }
    let dual_hardfork = $baseline_hardfork != "" and $feature_hardfork != ""

    let baseline_sha = if $baseline == "local" { "local" } else { resolve-git-ref $baseline }
    let feature_sha = if $feature == "local" { "local" } else { resolve-git-ref $feature }
    let baseline_label = if $baseline == "local" { "local (working tree)" } else { $"($baseline) → ($baseline_sha)" }
    let feature_label = if $feature == "local" { "local (working tree)" } else { $"($feature) → ($feature_sha)" }
    print $"Baseline: ($baseline_label)"
    print $"Feature: ($feature_label)"

    let timestamp = (date now | format date "%Y%m%d-%H%M%S")
    let results_dir = $"($BENCH_RESULTS_DIR)/($timestamp)"
    mkdir $results_dir
    print $"BENCH_RESULTS_DIR=($results_dir)"

    let baseline_wt = $"($BENCH_WORKTREES_DIR)/baseline"
    let feature_wt = $"($BENCH_WORKTREES_DIR)/feature"
    git worktree prune
    for wt in [$baseline_wt $feature_wt] {
        if ($wt | path exists) {
            print $"Removing stale worktree: ($wt)"
            try { git worktree remove --force $wt } catch { rm -rf $wt }
        }
    }

    if $baseline != "local" {
        git worktree add $baseline_wt $baseline_sha
    }
    if $feature != "local" {
        git worktree add $feature_wt $feature_sha
    }

    let tbc = (tracy-build-config $features $tracy)
    let effective_features = $tbc.features
    let effective_extra_rustflags = $tbc.extra_rustflags
    let effective_no_cache = $no_cache or ($tracy != "off")

    if $baseline == "local" or $feature == "local" {
        print "Building local tempo binaries..."
        build-tempo --extra-rustflags $effective_extra_rustflags ["tempo"] $profile $effective_features
    }
    if $baseline != "local" {
        if $effective_no_cache {
            build-in-worktree --no-cache --extra-rustflags $effective_extra_rustflags $baseline_wt $baseline $profile $effective_features $baseline_sha
        } else {
            build-in-worktree $baseline_wt $baseline $profile $effective_features $baseline_sha
        }
    }
    if $feature != "local" {
        if $effective_no_cache {
            build-in-worktree --no-cache --extra-rustflags $effective_extra_rustflags $feature_wt $feature $profile $effective_features $feature_sha
        } else {
            build-in-worktree $feature_wt $feature $profile $effective_features $feature_sha
        }
    }

    let local_bin = { |name: string| if $profile == "dev" { $"./target/debug/($name)" } else { $"./target/($profile)/($name)" } }
    let baseline_tempo = if $baseline == "local" { do $local_bin "tempo" } else { worktree-bin $baseline_wt $profile "tempo" }
    let feature_tempo = if $feature == "local" { do $local_bin "tempo" } else { worktree-bin $feature_wt $profile "tempo" }

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
    let gas_limit_args = if $gas_limit != "" { ["--gas-limit" $gas_limit] } else { [] }

    bench-mount

    if $dual_hardfork {
        if not ($abs_localnet | path exists) { mkdir $abs_localnet }

        let baseline_genesis_args = (hardfork-to-genesis-args $baseline_hardfork)
        let feature_genesis_args = (hardfork-to-genesis-args $feature_hardfork)
        let baseline_genesis_path = $"($abs_localnet)/genesis-baseline.json"
        let feature_genesis_path = $"($abs_localnet)/genesis-feature.json"
        let baseline_datadir = $"($datadir)/baseline-db"
        let feature_datadir = $"($datadir)/feature-db"

        let marker = (read-bench-marker $datadir)
        let snapshot_ready = (
            not $force
            and $marker != null
            and ($marker.bloat_mib | into int) == $bloat
            and ($marker.accounts | into int) == $genesis_accounts
            and ($marker | get -o baseline_hardfork | default "") == ($baseline_hardfork | str upcase)
            and ($marker | get -o feature_hardfork | default "") == ($feature_hardfork | str upcase)
            and ($marker | get -o gas_limit | default "") == $gas_limit
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
            let baseline_genesis_dir = $"($abs_localnet)/genesis-baseline-dir"
            if ($baseline_genesis_dir | path exists) { rm -rf $baseline_genesis_dir }
            mkdir $baseline_genesis_dir
            if $baseline == "local" {
                cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $baseline_genesis_dir -a $genesis_accounts --no-dkg-in-genesis ...$baseline_genesis_args ...$gas_limit_args
            } else {
                do {
                    cd $baseline_wt
                    cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $baseline_genesis_dir -a $genesis_accounts --no-dkg-in-genesis ...$baseline_genesis_args ...$gas_limit_args
                }
            }
            cp $"($baseline_genesis_dir)/genesis.json" $baseline_genesis_path
            rm -rf $baseline_genesis_dir

            let feature_genesis_dir = $"($abs_localnet)/genesis-feature-dir"
            if ($feature_genesis_dir | path exists) { rm -rf $feature_genesis_dir }
            mkdir $feature_genesis_dir
            if $feature == "local" {
                cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $feature_genesis_dir -a $genesis_accounts --no-dkg-in-genesis ...$feature_genesis_args ...$gas_limit_args
            } else {
                do {
                    cd $feature_wt
                    cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $feature_genesis_dir -a $genesis_accounts --no-dkg-in-genesis ...$feature_genesis_args ...$gas_limit_args
                }
            }
            cp $"($feature_genesis_dir)/genesis.json" $feature_genesis_path
            rm -rf $feature_genesis_dir

            if $bloat > 0 and not ($bloat_file | path exists) {
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

            for side in [
                { genesis: $baseline_genesis_path, dd: $baseline_datadir, tempo: $baseline_tempo }
                { genesis: $feature_genesis_path, dd: $feature_datadir, tempo: $feature_tempo }
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
            } [[$baseline_genesis_path "genesis-baseline.json"] [$feature_genesis_path "genesis-feature.json"]] $bloat $bloat_file
        }
    } else {
        let genesis_path_std = $"($abs_localnet)/genesis.json"
        let marker = (read-bench-marker $datadir)
        let snapshot_ready = (
            not $force
            and $marker != null
            and ($marker.bloat_mib | into int) == $bloat
            and ($marker.accounts | into int) == $genesis_accounts
            and ($marker | get -o gas_limit | default "") == $gas_limit
            and ($"($datadir)/db" | path exists)
            and ($"($meta_dir)/genesis.json" | path exists)
        )

        if $snapshot_ready {
            if not ($abs_localnet | path exists) { mkdir $abs_localnet }
            cp $"($meta_dir)/genesis.json" $genesis_path_std
            print $"Using cached virgin snapshot \(initialized ($marker.initialized_at)\)"
        } else {
            if not ($genesis_path_std | path exists) {
                if not ($abs_localnet | path exists) { mkdir $abs_localnet }
                if $baseline == "local" {
                    cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $abs_localnet -a $genesis_accounts --no-dkg-in-genesis ...$gas_limit_args
                } else {
                    do {
                        cd $baseline_wt
                        cargo run -p tempo-xtask --profile $profile -- generate-genesis --output $abs_localnet -a $genesis_accounts --no-dkg-in-genesis ...$gas_limit_args
                    }
                }
            }

            if $bloat > 0 and not ($bloat_file | path exists) {
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
                bloat_mib: $bloat
                accounts: $genesis_accounts
                bench_datadir: $datadir
                gas_limit: $gas_limit
            } [[$genesis_path_std "genesis.json"]] $bloat $bloat_file
        }
    }

    let genesis_path = if $dual_hardfork { "" } else { $"($abs_localnet)/genesis.json" }

    if not $no_infra {
        docker compose -f $"($BENCH_DIR)/docker-compose.yml" up -d
    }

    if $tracy == "full" and (^uname | str trim) == "Linux" {
        try { sudo sysctl -w kernel.perf_event_paranoid=-1 } catch { }
        try { sudo mount -t tracefs tracefs /sys/kernel/tracing -o remount,mode=755 } catch { }
        try { sudo chmod -R a+r /sys/kernel/tracing } catch { }
    }

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
        bench-recover $datadir
        let run_type = if ($run.label | str starts-with "baseline") { "baseline" } else { "feature" }
        let side_args = if $run_type == "baseline" { $baseline_args } else { $feature_args }
        let side_env = if $run_type == "baseline" { $baseline_env } else { $feature_env }
        let effective_node_args = ([$node_args $side_args] | where { |a| $a != "" } | str join " ")

        (run-txgen-bench-single
            --tempo-bin $run.tempo
            --txgen-tempo-bin $txgen.txgen_tempo_bin
            --txgen-bench-bin $txgen.txgen_bench_bin
            --txgen-repo-dir $txgen.repo_dir
            --genesis-path $run.genesis
            --datadir $run.datadir
            --run-label $run.label
            --results-dir $results_dir
            --tps $tps
            --duration $duration
            --accounts $accounts
            --max-concurrent-requests $max_concurrent_requests
            --preset $preset
            --bench-args $bench_args
            --loud=$loud
            --node-args $effective_node_args
            --bloat $bloat
            --extra-env $side_env
            --bench-env $bench_env
            --git-ref $run.git_ref
            --build-profile $profile
            --benchmark-mode $mode
            --benchmark-id $benchmark_id
            --reference-epoch $reference_epoch
            --samply=$samply
            --samply-args $samply_args_list
            --tracy $tracy
            --tracy-filter $tracy_filter
            --tracy-seconds $tracy_seconds
            --tracy-offset $tracy_offset
            --tracing-otlp $tracing_otlp)
    }

    let summary_baseline = if $dual_hardfork { $"($baseline) \(($baseline_hardfork | str upcase)\)" } else { $baseline }
    let summary_feature = if $dual_hardfork { $"($feature) \(($feature_hardfork | str upcase)\)" } else { $feature }
    generate-summary $results_dir $summary_baseline $summary_feature $bloat $preset $tps $duration --benchmark-id $benchmark_id --reference-epoch $reference_epoch

    if $baseline != "local" { try { git worktree remove --force $baseline_wt } catch { } }
    if $feature != "local" { try { git worktree remove --force $feature_wt } catch { } }

    if not $no_infra {
        docker compose -f $"($BENCH_DIR)/docker-compose.yml" down
    }

    if $samply {
        for run in $runs {
            let profile = $"($results_dir)/profile-($run.label).json.gz"
            let url = (upload-samply-profile $profile)
            if $url != null {
                $url | save -f $"($results_dir)/profile-($run.label)-url.txt"
            }
        }
    }

    if $tracy != "off" {
        for run in $runs {
            let profile = $"($results_dir)/tracy-profile-($run.label).tracy"
            let viewer_url = (upload-tracy-profile $profile $run.label $run.git_ref)
            if $viewer_url != null {
                $viewer_url | save -f $"($results_dir)/tracy-($run.label)-url.txt"
            }
        }
    }

    restore-system-tuning $tuning_state
    print $"Comparison complete! Results: ($results_dir)/"
}
