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
const E2E_A_MEMORY = "60G"
const E2E_B_MEMORY = "60G"
const E2E_GAS_LIMIT = "1000000000000"
const E2E_BLOAT_TMP_DIR = "/reth-bench-a/.bench-tmp/e2e-local-init"
const E2E_BLOAT_FREE_MARGIN_MIB = 51200
const E2E_DEFAULT_BLOAT = 100
const TXGEN_DEFAULT_SEED = 99
const TXGEN_SCRAPE_INTERVAL_MS = 500
const TXGEN_DRAIN_TIMEOUT_SECS = 300
const TXGEN_FUND_DRAIN_TIMEOUT_SECS = 120
const TXGEN_TIP20_TEMPLATE = "contrib/bench/txgen/tip20-template.yaml"
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

def e2e-bloat-gib-to-mib [bloat: int] {
    if $bloat in [1 10 100] {
        return ($bloat * 1000)
    }

    print "Error: --bloat must be one of: 1, 10, 100"
    exit 1
}

def shell-quote [value: any] {
    let s = ($value | into string)
    let escaped = ($s | str replace -a "'" "'\"'\"'")
    $"'($escaped)'"
}

def shell-join [args: list<any>] {
    $args | each { |arg| shell-quote $arg } | str join " "
}

def resolve-command-path [name: string] {
    let path = (which $name | get -o 0.path | default "")
    if $path == "" {
        error make { msg: $"($name) not found in PATH" }
    }
    $path
}

def resolve-bench-binary [repo_dir: string] {
    for candidate in [$"($repo_dir)/target/release/bench" $"($repo_dir)/target/release/bench-cli"] {
        if ($candidate | path exists) {
            return $candidate
        }
    }
    error make { msg: $"txgen bench binary not found under ($repo_dir)/target/release/" }
}

def resolve-txgen-paths [] {
    let repo_dir = ($env.TXGEN_REPO_DIR? | default "")
    let repo = if $repo_dir != "" { $repo_dir | path expand } else { "" }
    let generator = if ($env.TXGEN_TEMPO_BIN? | default "") != "" {
        $env.TXGEN_TEMPO_BIN | path expand
    } else if $repo != "" and ($"($repo)/target/release/txgen-tempo" | path exists) {
        $"($repo)/target/release/txgen-tempo"
    } else {
        resolve-command-path "txgen-tempo"
    }
    let bench = if ($env.TXGEN_BENCH_BIN? | default "") != "" {
        $env.TXGEN_BENCH_BIN | path expand
    } else if $repo != "" {
        resolve-bench-binary $repo
    } else {
        resolve-command-path "bench"
    }
    if not ($generator | path exists) {
        error make { msg: $"txgen-tempo binary not found: ($generator)" }
    }
    if not ($bench | path exists) {
        error make { msg: $"txgen bench binary not found: ($bench)" }
    }
    { txgen_tempo_bin: $generator, txgen_bench_bin: $bench }
}

def rpc-call [rpc_url: string, payload: string] {
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
            if $zero_count >= 3 { return }
        } else {
            $zero_count = 0
        }
        sleep 1sec
        $waited = $waited + 1
    }
    print $"  Warning: txpool drain timeout reached after ($timeout_secs)s"
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
        rpc-call $rpc_url $"{\"jsonrpc\":\"2.0\",\"method\":\"tempo_fundAddress\",\"params\":[\"($address)\"],\"id\":1}" | ignore
    } | ignore

    print "  Waiting for faucet transactions to drain..."
    wait-for-txpool-drain $rpc_url $TXGEN_FUND_DRAIN_TIMEOUT_SECS
}

def sanitize-txgen-bench-args [bench_args: string] {
    if $bench_args == "" {
        return ""
    }
    $bench_args
        | str replace --all --regex '--existing-recipients=(true|false)' ''
        | str trim
}

def validator-dirs-in-localnet [localnet_dir: string] {
    ls $localnet_dir
    | where type == "dir"
    | get name
    | where { |d| ($d | path basename) =~ '^\d+\.\d+\.\d+\.\d+:\d+$' }
}

def trusted-peers-from-localnet [localnet_dir: string] {
    validator-dirs-in-localnet $localnet_dir | each { |d|
        let addr = ($d | path basename)
        let ip = ($addr | split row ":" | get 0)
        let port = ($addr | split row ":" | get 1 | into int)
        let identity = (open $"($d)/enode.identity" | str trim)
        $"enode://($identity)@($ip):($port + 1)"
    } | str join ","
}

def init-e2e-db [tempo_bin: string, genesis: string, datadir: string, bloat: int, bloat_file: string] {
    print $"Initializing database at ($datadir)..."
    let init_result = (run-external $tempo_bin "init" "--chain" $genesis "--datadir" $datadir | complete)
    if $init_result.stdout != "" { print $init_result.stdout }
    if $init_result.stderr != "" { print $init_result.stderr }
    if $init_result.exit_code != 0 {
        print $"Error: tempo init failed for ($datadir) with exit code ($init_result.exit_code)"
        exit $init_result.exit_code
    }

    if $bloat > 0 {
        print $"Loading state bloat into ($datadir)..."
        let bloat_result = (run-external $tempo_bin "init-from-binary-dump" "--chain" $genesis "--datadir" $datadir $bloat_file | complete)
        if $bloat_result.stdout != "" { print $bloat_result.stdout }
        if $bloat_result.stderr != "" { print $bloat_result.stderr }
        if $bloat_result.exit_code != 0 {
            print $"Error: state bloat load failed for ($datadir) with exit code ($bloat_result.exit_code)"
            exit $bloat_result.exit_code
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

def e2e-snapshot-required-files [datadir: string] {
    let meta_dir = $"($datadir)/($BENCH_META_SUBDIR)"
    [
        $"($meta_dir)/genesis.json"
        $"($meta_dir)/trusted-peers.txt"
        $"($meta_dir)/marker.json"
        $"($datadir)/signing.key"
        $"($datadir)/signing.share"
        $"($datadir)/enode.key"
        $"($datadir)/enode.identity"
        $"($datadir)/db"
        $"($datadir)/static_files"
    ]
}

def e2e-snapshot-missing-files [datadir: string] {
    e2e-snapshot-required-files $datadir | where { |path| not ($path | path exists) }
}

def e2e-snapshot-ready [datadir: string] {
    (e2e-snapshot-missing-files $datadir | length) == 0
}

def e2e-snapshots-ready [a_db: string, b_db: string] {
    (e2e-snapshot-ready $a_db) and (e2e-snapshot-ready $b_db)
}

def derive-tracing-otlp [tracing_otlp: string] {
    if $tracing_otlp == "" and ($env.GRAFANA_TEMPO? | default "" | str length) > 0 {
        let base = ($env.GRAFANA_TEMPO | str trim --right --char '/')
        return $"($base)/v1/traces"
    }
    if $tracing_otlp == "" and ($env.TEMPO_TELEMETRY_URL? | default "" | str length) > 0 {
        let base = ($env.TEMPO_TELEMETRY_URL | str trim --right --char '/')
        return $"($base)/opentelemetry/v1/traces"
    }
    $tracing_otlp
}

def systemd-scope-command [unit: string, cpus: string, memory: string, script: string] {
    let can_scope = (^uname | str trim) == "Linux" and ((which systemd-run | length) > 0) and ($cpus != "" or $memory != "")
    if not $can_scope {
        return ["bash" "-lc" $script]
    }

    let memory_args = if $memory != "" { ["-p" $"MemoryMax=($memory)"] } else { [] }
    mut telemetry_env_names = []
    if ($env.TEMPO_TELEMETRY_URL? | default "" | str length) > 0 {
        $telemetry_env_names = ($telemetry_env_names | append "TEMPO_TELEMETRY_URL")
    }
    if ($env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT? | default "" | str length) > 0 {
        $telemetry_env_names = ($telemetry_env_names | append "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
    }
    let preserve_env_args = if ($telemetry_env_names | length) > 0 {
        [$"--preserve-env=($telemetry_env_names | str join ',')"]
    } else { [] }
    let telemetry_env = ($telemetry_env_names | each { |name| $"--setenv=($name)" })
    let uid = (id -u | str trim)
    let gid = (id -g | str trim)
    [
        "sudo"
        ...$preserve_env_args
        "systemd-run"
        "--scope"
        "--quiet"
        "--collect"
        "--same-dir"
        "--unit" $unit
        "--uid" $uid
        "--gid" $gid
        ...$telemetry_env
        "-p" "CPUWeight=100"
        ...$memory_args
        "bash"
        "-lc"
        $script
    ]
}

def taskset-command [cmd: list<string>, cpus: string] {
    if $cpus != "" {
        ["taskset" "-c" $cpus ...$cmd]
    } else {
        $cmd
    }
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
    let pinned_cmd = taskset-command [$tempo_bin ...$args] $cpus
    let node_cmd = wrap-samply $pinned_cmd $samply $full_samply_args
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

def build-e2e-consensus-args [node_dir: string, trusted_peers: string, port: int, consensus_ip: string] {
    let addr = ($node_dir | path basename)
    let inferred_ip = if ($addr | str contains ":") {
        $addr | split row ":" | get 0
    } else {
        "0.0.0.0"
    }
    let ip = if $consensus_ip != "" { $consensus_ip } else { $inferred_ip }
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
        "--consensus.use-local-defaults"
        "--consensus.bypass-ip-check"
    ]
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

def stop-tracy-capture [] {
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

def wait-for-samply-profile [] {
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

def rpc-block-number [url: string] {
    let result = (do { curl -sf $url -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' } | complete)
    if $result.exit_code != 0 {
        return null
    }
    let parsed = (try { $result.stdout | from json } catch { null })
    if $parsed == null {
        return null
    }
    let hex = ($parsed | get -o result | default "")
    if $hex == "" {
        return null
    }
    try { $hex | str replace "0x" "" | into int --radix 16 } catch { null }
}

def rpc-peer-count [url: string] {
    let result = (do { curl -sf $url -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}' } | complete)
    if $result.exit_code != 0 {
        return null
    }
    let parsed = (try { $result.stdout | from json } catch { null })
    if $parsed == null {
        return null
    }
    let hex = ($parsed | get -o result | default "")
    if $hex == "" {
        return null
    }
    try { $hex | str replace "0x" "" | into int --radix 16 } catch { null }
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

    init-e2e-db $tempo_bin $generated_genesis $datadir $bloat $bloat_file
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
    let extra_args = if $side_args == "" { [] } else { $side_args | split row " " }

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

    if $phase_exit == 0 {
        let bench_env_export = if $ctx.bench_env != "" { $"export ($ctx.bench_env) && " } else { "" }
        if $ctx.preset != "tip20" {
            print $"Error: txgen e2e currently supports only preset=tip20 \(got ($ctx.preset)\)"
            $phase_exit = 1
        } else {
            let ignored_bench_args = (sanitize-txgen-bench-args $ctx.bench_args)
            if $ignored_bench_args != "" {
                print $"  Warning: txgen path is ignoring unsupported bench args: ($ignored_bench_args)"
            }
            let chain_id = (fetch-chain-id $a_rpc)
            $env.TXGEN_ACCOUNTS = ($ctx.accounts | into string)
            let spec_path = ($TXGEN_TIP20_TEMPLATE | path expand)
            fund-txgen-accounts $ctx.txgen.txgen_tempo_bin $spec_path $a_rpc

            let report_path = $"($ctx.results_dir)/report-($phase).json"
            let tx_count = [($ctx.tps * $ctx.duration) 1] | math max
            let txgen_cmd = [
                $ctx.txgen.txgen_tempo_bin
                "generate"
                "-s" $spec_path
                "-n" $tx_count
                "--seed" $TXGEN_DEFAULT_SEED
                "--rpc" $a_rpc
            ]
            let bench_cmd = [
                $ctx.txgen.txgen_bench_bin
                "send"
                "--rpc-url" $a_rpc
                "--tps" $ctx.tps
                "--max-concurrent" $ctx.max_concurrent_requests
                "--metrics-url" "http://127.0.0.1:9001/metrics"
                "--scrape-interval-ms" $TXGEN_SCRAPE_INTERVAL_MS
                "--drain-timeout" $TXGEN_DRAIN_TIMEOUT_SECS
                "--report" $"json:($report_path)"
                "-m" $"chain_id=($chain_id)"
                "-m" $"target_tps=($ctx.tps)"
                "-m" $"run_duration_secs=($ctx.duration)"
                "-m" $"accounts=($ctx.accounts)"
                "-m" $"total_connections=($ctx.max_concurrent_requests)"
                "-m" "tip20_weight=1.0"
                "-m" "place_order_weight=0.0"
                "-m" "swap_weight=0.0"
                "-m" "erc20_weight=0.0"
                "-m" $"node_commit_sha=($run.ref)"
                "-m" $"build_profile=($ctx.profile)"
                "-m" "mode=e2e"
            ]
            print $"Running local e2e txgen sender: ($txgen_cmd | str join ' ') | ($bench_cmd | str join ' ')"
            let txgen_cmd_str = (shell-join $txgen_cmd)
            let bench_cmd_str = (shell-join $bench_cmd)
            let pipeline = $"set -euo pipefail; ($bench_env_export)ulimit -Sn unlimited && ($txgen_cmd_str) | ($bench_cmd_str)"
            let bench_result = (bash -lc $pipeline | complete)
            if $bench_result.stdout != "" { print $bench_result.stdout }
            if $bench_result.stderr != "" { print $bench_result.stderr }
            $phase_exit = $bench_result.exit_code

            if not ($report_path | path exists) {
                print $"ERROR: txgen sender for ($phase) produced no ($report_path)"
                $phase_exit = 1
            }
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
    --bloat: int = $E2E_DEFAULT_BLOAT                   # State bloat snapshot size in GiB: 1, 10, or 100
    --gas-limit: string = $E2E_GAS_LIMIT                # Builder gas limit
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
    --tracing-otlp: string = ""                         # OTLP endpoint for tracing (auto-derived from GRAFANA_TEMPO/TEMPO_TELEMETRY_URL)
    --baseline-args: string = ""                        # Additional node args for baseline phases
    --feature-args: string = ""                         # Additional node args for feature phases
    --bench-args: string = ""                           # Additional txgen bench args
    --baseline-env: string = ""                         # Environment vars for baseline node phases
    --feature-env: string = ""                          # Environment vars for feature node phases
    --bench-env: string = ""                            # Environment vars for the sender process
    --baseline-name: string = ""                         # Baseline display name for summary
    --feature-name: string = ""                          # Feature display name for summary
    --tune                                              # Apply system tuning
    --loud                                              # Show node debug logs
    --no-cache                                           # Skip binary cache
] {
    if $preset == "" {
        print "Error: --preset tip20 is required for e2e txgen"
        exit 1
    }
    if not ($preset in $PRESETS) {
        print $"Unknown preset: ($preset). Available: ($PRESETS | columns | str join ', ')"
        exit 1
    }
    if $preset != "tip20" {
        print $"Error: e2e txgen currently supports only --preset tip20 \(got '($preset)'\)"
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
    let bloat_mib = (e2e-bloat-gib-to-mib $bloat)
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
    let a_db = $"($E2E_A_MOUNT)/tempo_e2e_($bloat_mib)mb"
    let b_db = $"($E2E_B_MOUNT)/tempo_e2e_($bloat_mib)mb"
    let a_identity = $a_db
    let b_identity = $b_db
    let genesis_path = $"($a_db)/($BENCH_META_SUBDIR)/genesis.json"
    let a_trusted_peers_path = $"($a_db)/($BENCH_META_SUBDIR)/trusted-peers.txt"
    let run_started_at = (date now)
    let timestamp = ($run_started_at | format date "%Y%m%d-%H%M%S-%3f")
    let benchmark_id = $"bench-e2e-local-($timestamp)"
    let reference_epoch = (($run_started_at | into int) / 1_000_000_000 | into int)
    let gas_limit_args = if $gas_limit != "" { ["--gas-limit" $gas_limit] } else { [] }
    let tracing_otlp = (derive-tracing-otlp $tracing_otlp)
    if $tracing_otlp != "" {
        $env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT = $tracing_otlp
    }

    validate-schelk-state $E2E_A_STATE_PATH $E2E_B_STATE_PATH
    cleanup-local-e2e-processes

    bench-restore-at $E2E_A_STATE_PATH $E2E_A_MOUNT $a_db
    bench-restore-at $E2E_B_STATE_PATH $E2E_B_MOUNT $b_db

    let snapshots_ready = (e2e-snapshots-ready $a_db $b_db)
    let should_init_snapshots = $force_bloat or (not $snapshots_ready)
    if (not $snapshots_ready) and (not $force_bloat) {
        print $"Local e2e snapshot ($bloat) is missing required files; initializing it once."
        let missing_a = (e2e-snapshot-missing-files $a_db)
        let missing_b = (e2e-snapshot-missing-files $b_db)
        if ($missing_a | length) > 0 {
            print $"  Missing from a: ($missing_a | str join ', ')"
        }
        if ($missing_b | length) > 0 {
            print $"  Missing from b: ($missing_b | str join ', ')"
        }
    }

    if $should_init_snapshots {
        let init_dir = $"($LOCALNET_DIR)/e2e-local-init"
        let generated_genesis = $"($init_dir)/genesis.json"
        let bloat_file = $"($E2E_BLOAT_TMP_DIR)/state_bloat.bin"
        if ($init_dir | path exists) { rm -rf $init_dir }
        mkdir $init_dir
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
        if $bloat_mib > 0 {
            ensure-bloat-space $bloat_mib
            print $"Generating local e2e state bloat \(($bloat_mib) MiB\)..."
            let token_args = ($TIP20_TOKEN_IDS | each { |id| ["--token" $"($id)"] } | flatten)
            cargo run -p tempo-xtask --profile $profile -- generate-state-bloat --size $bloat_mib --out $bloat_file ...$token_args
        }

        let marker = {
            bloat_mib: $bloat_mib
            bloat: $bloat
            accounts: $genesis_accounts
            validators: $E2E_VALIDATORS
            seed: $E2E_SEED
            gas_limit: $gas_limit
            dkg_in_genesis: true
            topology: "single-runner"
        }
        init-local-e2e-side a $E2E_A_STATE_PATH $E2E_A_MOUNT $a_db $a_identity $"($init_dir)/($a_validator)" $generated_genesis $trusted_peers $bloat_mib $bloat_file $tempo_bin ($marker | insert bench_datadir $a_db | insert node_dir $a_identity | insert validator_addr $a_validator)
        init-local-e2e-side b $E2E_B_STATE_PATH $E2E_B_MOUNT $b_db $b_identity $"($init_dir)/($b_validator)" $generated_genesis $trusted_peers $bloat_mib $bloat_file $tempo_bin ($marker | insert bench_datadir $b_db | insert node_dir $b_identity | insert validator_addr $b_validator)
        if ($E2E_BLOAT_TMP_DIR | path exists) {
            rm -rf $E2E_BLOAT_TMP_DIR
        }
        bench-promote-at $E2E_A_STATE_PATH $a_db
        bench-promote-at $E2E_B_STATE_PATH $b_db
        bench-restore-at $E2E_A_STATE_PATH $E2E_A_MOUNT $a_db
        bench-restore-at $E2E_B_STATE_PATH $E2E_B_MOUNT $b_db
    }

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
    let feature_tempo = (worktree-bin $feature_wt $profile "tempo")
    let txgen = resolve-txgen-paths
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
        bloat: $bloat_mib
        txgen: $txgen
        results_dir: $results_dir
        profile: $profile
        samply: $samply
        samply_args: $samply_args_list
        tracy: $tracy
        tracy_filter: $tracy_filter
        tracy_seconds: $tracy_seconds
        tracy_offset: $tracy_offset
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
        gas_limit: $gas_limit
    }

    let runs = [
        { phase: "baseline-1", ref: $baseline, tempo: $baseline_tempo }
        { phase: "feature-1", ref: $feature, tempo: $feature_tempo }
        { phase: "feature-2", ref: $feature, tempo: $feature_tempo }
        { phase: "baseline-2", ref: $baseline, tempo: $baseline_tempo }
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
        generate-summary $results_dir $baseline_label $feature_label $bloat_mib $preset $tps $duration --benchmark-id $benchmark_id --reference-epoch $reference_epoch
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
