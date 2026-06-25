const TXGEN_HELPER_ACCOUNT_MNEMONIC = "test test test test test test test test test test test junk"
const TXGEN_HELPER_DEFAULT_SEED = 99
const TXGEN_HELPER_SCRAPE_INTERVAL_MS = 200
const TXGEN_HELPER_DRAIN_TIMEOUT_SECS = 300
const TXGEN_HELPER_FUND_DRAIN_TIMEOUT_SECS = 120
const TXGEN_HELPER_PRESETS_DIR = "contrib/bench/txgen/presets"
const TXGEN_HELPER_EXISTING_RECIPIENTS_PRESETS = ["tip20_existing_recipients" "tip20_2d_nonces" "tip20_protocol_nonces"]
const TXGEN_HELPER_EXISTING_RECIPIENTS_START = 10000

def txgen-tip20-token-address [token_id: int] {
    ^printf "0x20c000000000000000000000%016x" $token_id
}

def txgen-tip20-token-choices [token_count: int] {
    if $token_count <= 0 {
        error make { msg: "TIP20 token count must be greater than zero" }
    }

    0..<$token_count | each { |id| txgen-tip20-token-address $id } | to json -r
}

def --env txgen-configure-tip20-token-env [token_count: int] {
    $env.TXGEN_TIP20_TOKENS = (txgen-tip20-token-choices $token_count)
}

def txgen-shell-quote [value: any] {
    let s = ($value | into string)
    let escaped = ($s | str replace -a "'" "'\"'\"'")
    $"'($escaped)'"
}

def txgen-shell-join [args: list<any>] {
    $args | each { |arg| txgen-shell-quote $arg } | str join " "
}

def txgen-command-path [name: string] {
    let path = (which $name | get -o 0.path | default "")
    if $path == "" {
        error make { msg: $"($name) not found in PATH" }
    }
    $path
}

def txgen-resolve-configured-bin [configured: string, fallback: string] {
    if $configured == "" {
        return (txgen-command-path $fallback)
    }

    if ($configured | path exists) {
        return ($configured | path expand)
    }

    txgen-command-path $configured
}

def txgen-resolve-binaries [] {
    let generator = (txgen-resolve-configured-bin ($env.TXGEN_TEMPO_BIN? | default "") "txgen-tempo")
    let bench = (txgen-resolve-configured-bin ($env.TXGEN_BENCH_BIN? | default "") "bench")

    {
        txgen_tempo_bin: $generator
        txgen_bench_bin: $bench
    }
}

def txgen-repo-root [] {
    let result = (git rev-parse --show-toplevel | complete)
    if $result.exit_code == 0 {
        return ($result.stdout | str trim)
    }

    "." | path expand
}

def txgen-presets-dir [] {
    [ (txgen-repo-root) $TXGEN_HELPER_PRESETS_DIR ] | path join
}

def txgen-available-presets [] {
    let presets_dir = (txgen-presets-dir)
    if not ($presets_dir | path exists) {
        return []
    }

    glob ([ $presets_dir "*.yml" ] | path join)
        | each { |preset_path| $preset_path | path basename | str replace --regex '\.yml$' '' }
        | sort
}

def txgen-available-presets-message [] {
    let presets = (txgen-available-presets)
    if ($presets | is-empty) {
        "none"
    } else {
        $presets | str join ", "
    }
}

def txgen-preset-path [preset: string] {
    let preset_name = ($preset | str trim)
    if $preset_name == "" {
        error make { msg: $"--preset is required; available txgen presets: (txgen-available-presets-message)" }
    }

    if not ($preset_name =~ '^[A-Za-z0-9][A-Za-z0-9_-]*$') {
        error make { msg: $"invalid txgen preset name '($preset_name)'; use a preset basename like 'tip20'" }
    }

    let spec_path = ([ (txgen-presets-dir) $"($preset_name).yml" ] | path join)
    if not ($spec_path | path exists) {
        error make { msg: $"txgen preset not found: ($preset_name); available txgen presets: (txgen-available-presets-message)" }
    }

    $spec_path
}

def txgen-account-mnemonic [] {
    $TXGEN_HELPER_ACCOUNT_MNEMONIC
}

def txgen-parse-bench-args [bench_args: string] {
    let trimmed = ($bench_args | str trim)
    if $trimmed == "" {
        return []
    }

    let args = ($trimmed | split row " " | where { |arg| $arg != "" })
    for arg in $args {
        if not ($arg =~ '^[A-Za-z0-9._/:=@,+-]+$') {
            error make { msg: $"invalid --bench-args token: ($arg)" }
        }
    }

    $args
}

def txgen-validate-bench-args [bench_args: string] {
    txgen-parse-bench-args $bench_args | ignore
}

def txgen-bloat-accounts-per-token [bloat_mib: int, token_count: int] {
    if $bloat_mib <= 0 {
        error make { msg: "bloat size must be greater than zero" }
    }
    if $token_count <= 0 {
        error make { msg: "bloat token count must be greater than zero" }
    }

    let target_bytes = $bloat_mib * 1024 * 1024
    let overhead_per_token = 40 + 64
    let available_for_balances = $target_bytes - ($token_count * $overhead_per_token)
    if $available_for_balances <= 0 {
        error make { msg: $"bloat size ($bloat_mib) MiB is too small for ($token_count) token\(s\)" }
    }

    (($available_for_balances / 64) / $token_count) | into int
}

def --env txgen-configure-existing-recipients-env [preset_path: string, bloat_mib: int, token_count: int] {
    let preset_name = ($preset_path | path basename | str replace --regex '\.yml$' '')
    if $preset_name not-in $TXGEN_HELPER_EXISTING_RECIPIENTS_PRESETS {
        return
    }

    if $bloat_mib <= 0 {
        error make { msg: $"preset ($preset_name) requires state bloat" }
    }

    let recipient_end = (txgen-bloat-accounts-per-token $bloat_mib $token_count)
    if $recipient_end <= $TXGEN_HELPER_EXISTING_RECIPIENTS_START {
        error make { msg: $"preset ($preset_name) requires state bloat with more than ($TXGEN_HELPER_EXISTING_RECIPIENTS_START) accounts per token" }
    }

    $env.TXGEN_EXISTING_RECIPIENTS_START = ($TXGEN_HELPER_EXISTING_RECIPIENTS_START | into string)
    $env.TXGEN_EXISTING_RECIPIENTS_END = ($recipient_end | into string)
    print $"  Using existing recipient range ($TXGEN_HELPER_EXISTING_RECIPIENTS_START)..($recipient_end) from ($bloat_mib) MiB state bloat"
}

def txgen-rpc-call [rpc_url: string, payload: string] {
    let result = (^curl -sf -X POST -H "Content-Type: application/json" -d $payload $rpc_url | complete)
    if $result.exit_code != 0 {
        error make { msg: $"RPC call failed: ($payload)" }
    }
    let response = ($result.stdout | from json)
    if (($response | get -o error) != null) {
        let rpc_error = ($response | get error)
        error make { msg: $"RPC error: ($rpc_error | to json -r)" }
    }
    $response
}

def txgen-fetch-chain-id [rpc_url: string] {
    let response = (txgen-rpc-call $rpc_url '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}')
    $response.result | into int
}

def txgen-wait-for-txpool-drain [rpc_url: string, timeout_secs: int = $TXGEN_HELPER_FUND_DRAIN_TIMEOUT_SECS] {
    mut zero_count = 0
    mut waited = 0

    while $waited < $timeout_secs {
        let response = (txgen-rpc-call $rpc_url '{"jsonrpc":"2.0","method":"txpool_status","params":[],"id":1}')
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

def txgen-fund-accounts [txgen_bin: string, spec_path: string, rpc_url: string] {
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
        txgen-rpc-call $rpc_url $"{\"jsonrpc\":\"2.0\",\"method\":\"tempo_fundAddress\",\"params\":[\"($address)\"],\"id\":1}" | ignore
    } | ignore

    print "  Waiting for faucet transactions to drain..."
    txgen-wait-for-txpool-drain $rpc_url $TXGEN_HELPER_FUND_DRAIN_TIMEOUT_SECS
}

def txgen-run-preset-pipeline [
    --txgen-tempo-bin: string
    --txgen-bench-bin: string
    --preset-path: string
    --generate-rpc-url: string
    --submit-rpc-url: string
    --metrics-url: list<string>
    --report-path: string
    --tps: int
    --duration: int
    --accounts: int
    --max-concurrent-requests: int
    --bench-args: string = ""
    --bench-env: string = ""
    --git-ref: string = ""
    --git-ref-label: string = ""
    --build-profile: string = ""
    --benchmark-mode: string = ""
    --benchmark-id: string = ""
    --benchmark-run: string = ""
    --run-type: string = ""
    --benchmark-start: int = 0
    --platform: string = ""
    --scenario: string = ""
    --victoriametrics-url: string = ""
    --clickhouse-url: string = ""
    --bloat-mib: int = 0
    --tip20-token-count: int = 0
    --bloat-token-count: int = 4
    --initial-db-size-bytes: int = 0
    --skip-funding                                   # Skip faucet funding (accounts already funded at genesis via state bloat)
] {
    let chain_id = (txgen-fetch-chain-id $generate_rpc_url)
    $env.TXGEN_ACCOUNTS = ($accounts | into string)
    let spec_path = ($preset_path | path expand)
    if not ($spec_path | path exists) {
        error make { msg: $"txgen preset file not found: ($spec_path)" }
    }
    let tx_token_count = if $tip20_token_count > 0 { $tip20_token_count } else { $bloat_token_count }
    txgen-configure-tip20-token-env $tx_token_count
    txgen-configure-existing-recipients-env $spec_path $bloat_mib $bloat_token_count
    let existing_recipient_start = ($env | get --optional TXGEN_EXISTING_RECIPIENTS_START | default "0" | into int)
    let existing_recipient_end = ($env | get --optional TXGEN_EXISTING_RECIPIENTS_END | default "0" | into int)
    let recipient_accounts = if $existing_recipient_end > $existing_recipient_start {
        $existing_recipient_end - $existing_recipient_start
    } else {
        0
    }
    let total_accounts = $accounts + $recipient_accounts
    if not $skip_funding {
        txgen-fund-accounts $txgen_tempo_bin $spec_path $generate_rpc_url
    }

    let tx_count = [($tps * $duration) 1] | math max
    let txgen_duration = $"($duration)s"
    let txgen_cmd = [
        $txgen_tempo_bin
        "generate"
        "-s" $spec_path
        "-n" $tx_count
        "--duration" $txgen_duration
        "--seed" $TXGEN_HELPER_DEFAULT_SEED
        "--rpc" $generate_rpc_url
    ]
    let metrics_url_args = ($metrics_url | each { |url| ["--metrics-url" $url] } | flatten)
    let bench_base_cmd = [
        $txgen_bench_bin
        "send"
        "--rpc-url" $submit_rpc_url
        "--tps" $tps
        "--max-concurrent" $max_concurrent_requests
        "--retries" 0
        ...$metrics_url_args
        "--scrape-interval-ms" $TXGEN_HELPER_SCRAPE_INTERVAL_MS
        "--drain-timeout" $TXGEN_HELPER_DRAIN_TIMEOUT_SECS
    ]
        | append (if $victoriametrics_url != "" and $benchmark_start > 0 { ["--metrics-align" $"($benchmark_start)"] } else { [] })
    let report_args = ["--report" $"json:($report_path)"]
        | append (if $victoriametrics_url != "" { ["--report" $"victoriametrics:($victoriametrics_url)"] } else { [] })
        | append (if $clickhouse_url != "" { ["--report" $"clickhouse:($clickhouse_url)"] } else { [] })
    let pr_number = ($env | get --optional BENCH_PR | default "")
    let metadata_args = [
        "-m" "job=github-tempo-bench-e2e"
        "-m" $"chain_id=($chain_id)"
        "-m" $"target_tps=($tps)"
        "-m" $"run_duration_secs=($duration)"
        "-m" $"accounts=($total_accounts)"
        "-m" $"total_connections=($max_concurrent_requests)"
        "-m" $"bloat_mib=($bloat_mib)"
        "-m" $"tip20_token_count=($tx_token_count)"
        "-m" $"bloat_token_count=($bloat_token_count)"
        "-m" "tip20_weight=1.0"
        "-m" "place_order_weight=0.0"
        "-m" "swap_weight=0.0"
        "-m" "erc20_weight=0.0"
        "-m" $"node_commit_sha=($git_ref)"
        "-m" $"git-sha=($git_ref)"
        "-m" $"git-ref=($git_ref_label)"
        "-m" $"build_profile=($build_profile)"
        "-m" $"mode=($benchmark_mode)"
    ]
        | append (if $benchmark_id != "" { ["-m" $"benchmark_id=($benchmark_id)"] } else { [] })
        | append (if $benchmark_run != "" { ["-m" $"benchmark_run=($benchmark_run)"] } else { [] })
        | append (if $run_type != "" { ["-m" $"run_type=($run_type)"] } else { [] })
        | append (if $platform != "" { ["-m" $"platform=($platform)"] } else { [] })
        | append (if $scenario != "" { ["-m" $"scenario=($scenario)"] } else { [] })
        | append (if $pr_number != "" { ["-m" $"pr_number=($pr_number)"] } else { [] })
        | append (if $initial_db_size_bytes > 0 { ["-m" $"initial_db_size_bytes=($initial_db_size_bytes)"] } else { [] })
    let bench_cmd = $bench_base_cmd | append $report_args | append $metadata_args

    let bench_env_export = if $bench_env != "" { $"export ($bench_env) && " } else { "" }
    let txgen_extra_args = (txgen-parse-bench-args $bench_args)
    let txgen_cmd_str = (txgen-shell-join ($txgen_cmd | append $txgen_extra_args))
    let bench_cmd_str = (txgen-shell-join $bench_cmd)
    let pipeline = $"set -euo pipefail; ($bench_env_export)ulimit -Sn unlimited && ($txgen_cmd_str) | ($bench_cmd_str)"

    print $"  Streaming up to ($tx_count) txgen transaction\(s\) over ($txgen_duration) into bench send..."
    let result = (bash -lc $pipeline | complete)
    if $result.stdout != "" { print $result.stdout }
    if $result.stderr != "" { print $result.stderr }

    if $result.exit_code != 0 {
        return { ok: false, exit_code: $result.exit_code, report_path: $report_path }
    }
    if not ($report_path | path exists) {
        print $"ERROR: txgen sender produced no ($report_path)"
        return { ok: false, exit_code: 1, report_path: $report_path }
    }

    print $"  Report saved: ($report_path)"
    { ok: true, exit_code: 0, report_path: $report_path }
}
