#!/usr/bin/env nu

# Single-runner e2e benchmark harness.
# Shared build/cache/report helpers are sourced from tempo.nu; the replacement
# e2e topology stays isolated here.
source tempo.nu
source contrib/bench/lifecycle/prebuilt.nu
source contrib/bench/lifecycle/run-plan.nu
source contrib/bench/lifecycle/owned-worktrees.nu

const E2E_A_STATE_PATH = "/var/lib/schelk/a.json"
const E2E_B_STATE_PATH = "/var/lib/schelk/b.json"
const E2E_A_MOUNT = "/reth-bench-a"
const E2E_B_MOUNT = "/reth-bench-b"
const BENCH_SCHELK_SCRIPT = "bench-schelk.nu"
const E2E_VALIDATORS = "127.0.0.2:8000,127.0.0.3:8100"
const E2E_SEED = 42
const E2E_A_CPUS = "0-7,16-23"
const E2E_B_CPUS = "8-15,24-31"
const E2E_A_MEMORY = "60G"
const E2E_B_MEMORY = "60G"
const E2E_GAS_LIMIT = "1000000000000"
const E2E_RUNNER_METRICS_URL = "http://127.0.0.1:9100/metrics"
const E2E_BLOAT_TMP_DIR = "/reth-bench-a/.bench-tmp/e2e-local-init"
const TRACY_SAMPLING_HZ = 18999
const E2E_BLOAT_FREE_MARGIN_MIB = 51200
const E2E_BLOAT_IMPORT_WORKING_SET_MULTIPLIER = 7
const E2E_DEFAULT_BLOAT = 100
const E2E_LOCAL_RETH_ARGS = [
    "--ipcdisable"
    "--disable-discovery"
    "--trusted-only"
    "--tempo.bootnodes-endpoint" "none"
    "--consensus.no-legacy-archive"
    "--engine.share-execution-cache-with-payload-builder"
    "--builder.enable-prewarming"
    "--rpc.max-connections" "10000"
    "--txpool.pending-max-count" "200000"
    "--txpool.basefee-max-count" "200000"
    "--txpool.queued-max-count" "200000"
    "--txpool.max-pending-txns" "200000"
    "--txpool.max-new-txns" "200000"
    "--txpool.max-batch-size" "200000"
]

def merge-e2e-features [...features: string] {
    $features
    | each { |f| $f | split row "," }
    | flatten
    | each { |f| $f | str trim }
    | where { |f| $f != "" }
    | uniq
    | str join ","
}

def tempo-node-help [tempo_bin: string] {
    let result = (run-external $tempo_bin "node" "--help" | complete)
    if $result.exit_code != 0 {
        print $"Error: failed to inspect supported tempo node args for ($tempo_bin)"
        if $result.stdout != "" { print $result.stdout }
        if $result.stderr != "" { print $result.stderr }
        exit $result.exit_code
    }
    [$result.stdout $result.stderr] | str join "\n"
}

def supported-node-arg-filter [tempo_bin: string, args: list<string>] {
    let help = (tempo-node-help $tempo_bin)
    mut supported = []
    mut removed = []
    mut skip_next_value = false
    for arg in $args {
        if $skip_next_value {
            if not ($arg starts-with "--") {
                $removed = ($removed | append $arg)
                $skip_next_value = false
                continue
            }
            $skip_next_value = false
        }
        if not ($arg starts-with "--") {
            $supported = ($supported | append $arg)
            continue
        }

        let key = ($arg | split row "=" | first)
        if ($help | str contains $key) {
            $supported = ($supported | append $arg)
        } else {
            print $"Skipping unsupported tempo node arg for ($tempo_bin): ($key)"
            $removed = ($removed | append $arg)
            if not ($arg | str contains "=") {
                $skip_next_value = true
            }
        }
    }
    { supported: $supported, removed: $removed }
}

def format-removed-node-arg-config [label: string, removed: list<string>] {
    if ($removed | is-empty) {
        ""
    } else {
        $", ($label)-removed-args: `($removed | str join ' ')`"
    }
}

def removed-node-args-label [removed: list<string>] {
    if ($removed | is-empty) {
        ""
    } else {
        $removed | str join " "
    }
}

def run-bench-schelk [...args: string] {
    let result = (nu $BENCH_SCHELK_SCRIPT ...$args | complete)
    if $result.stdout != "" { print $result.stdout }
    if $result.stderr != "" { print $result.stderr }
    if $result.exit_code != 0 {
        error make { msg: $"bench-schelk failed: ($args | str join ' ')" }
    }
}

def schelk-state [state_path: string] {
    sudo cat $state_path | from json
}

def mark-schelk-dirty-at [state_path: string] {
    if (has-schelk) {
        run-bench-schelk "mark-dirty" $state_path
    }
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

# Mount only existing, validated scratch volumes before checking their metadata.
# Never recover, copy, initialize, or promote a snapshot in this preflight.
def prebuilt-mount-existing-snapshots [force: bool, init_only: bool] {
    prebuilt-require-snapshot true true $force $init_only
    if not (has-schelk) { return }
    mut pending = []
    for pair in [
        {state: $E2E_A_STATE_PATH, mount: $E2E_A_MOUNT}
        {state: $E2E_B_STATE_PATH, mount: $E2E_B_MOUNT}
    ] {
        let state = (try { schelk-state $pair.state } catch {
            error make {msg: "Prebuilt snapshot state admission failed"}
        })
        let mounted = ($state | get --optional is_mounted)
        if ($mounted | describe) != "bool" or ($state | get --optional mount_point) != $pair.mount {
            error make {msg: "Prebuilt snapshot state admission failed"}
        }
        let actual = (^mountpoint -q $pair.mount | complete)
        if $actual.exit_code not-in [0 32] or $mounted != ($actual.exit_code == 0) {
            error make {msg: "Prebuilt snapshot mount state disagrees"}
        }
        if not $mounted { $pending = ($pending | append $pair.state) }
    }
    # Validate both sides before any mutation, and cover partial mount failures.
    if not ($pending | is-empty) { touch .bench-snapshot-dirty }
    for state_path in $pending {
        let result = (sudo schelk --state-path $state_path mount | complete)
        if $result.exit_code != 0 {
            error make {msg: "Prebuilt existing snapshot mount failed"}
        }
    }
}

def bench-restore-at [state_path: string, mount_point: string, datadir: string] {
    if (has-schelk) {
        run-bench-schelk "restore" $state_path $mount_point
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
        run-bench-schelk "promote" $state_path
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

def e2e-db-size-bytes [datadir: string] {
    let paths = [
        $"($datadir)/db"
        $"($datadir)/static_files"
    ] | where { |path| $path | path exists }
    if ($paths | is-empty) {
        return 0
    }

    let result = (^du -sb ...$paths | complete)
    if $result.exit_code != 0 {
        if $result.stderr != "" { print $result.stderr }
        return 0
    }

    $result.stdout
        | lines
        | each { |line| $line | split row --regex '\s+' | first | into int }
        | math sum
}

def ensure-bloat-space [bloat: int] {
    if $bloat <= 0 {
        return
    }

    let import_working_set_mib = $bloat * $E2E_BLOAT_IMPORT_WORKING_SET_MULTIPLIER
    let a_required_mib = $bloat + $import_working_set_mib + $E2E_BLOAT_FREE_MARGIN_MIB
    let b_required_mib = $import_working_set_mib + $E2E_BLOAT_FREE_MARGIN_MIB
    let requirements = [
        {
            mount: $E2E_A_MOUNT
            required_mib: $a_required_mib
            components: $"dump=($bloat) MiB, import-working-set=($import_working_set_mib) MiB, margin=($E2E_BLOAT_FREE_MARGIN_MIB) MiB"
        }
        {
            mount: $E2E_B_MOUNT
            required_mib: $b_required_mib
            components: $"import-working-set=($import_working_set_mib) MiB, margin=($E2E_BLOAT_FREE_MARGIN_MIB) MiB"
        }
    ]

    print "Checking e2e bloat rebuild free space..."
    print $"  Bloat dump: ($bloat) MiB on ($E2E_A_MOUNT)"
    print $"  Import working set: ($import_working_set_mib) MiB per side; multiplier=($E2E_BLOAT_IMPORT_WORKING_SET_MULTIPLIER)x bloat for DB, ETL, static file, and trie writes"
    print $"  Free-space margin: ($E2E_BLOAT_FREE_MARGIN_MIB) MiB per side"

    mut failed = false
    for requirement in $requirements {
        let available_mib = (df-available-mib $requirement.mount)
        print $"  ($requirement.mount): available=($available_mib) MiB required=($requirement.required_mib) MiB \(($requirement.components)\)"
        if $available_mib < $requirement.required_mib {
            $failed = true
        }
    }

    if $failed {
        print "Error: insufficient free space for e2e bloat snapshot rebuild"
        for requirement in $requirements {
            let available_mib = (df-available-mib $requirement.mount)
            if $available_mib < $requirement.required_mib {
                print $"  ($requirement.mount) needs at least ($requirement.required_mib) MiB, has ($available_mib) MiB"
            }
        }
        exit 1
    }
}

def e2e-bloat-gib-to-mib [bloat: int] {
    if $bloat == 0 {
        return 0
    }
    if $bloat in [1 10 100] {
        return ($bloat * 1000)
    }

    print "Error: --bloat must be one of: 0, 1, 10, 100"
    exit 1
}

def e2e-validate-token-count [token_count: int] {
    let available_token_count = ($TIP20_TOKEN_IDS | length)
    if $token_count <= 0 {
        print "Error: --token-count must be a positive integer"
        exit 1
    }
    if $token_count > $available_token_count {
        print $"Error: --token-count ($token_count) exceeds ($available_token_count) TIP20 token\(s\) available in state bloat"
        exit 1
    }
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

def e2e-snapshot-state-hardfork [datadir: string] {
    let marker = (read-bench-marker $datadir)
    if $marker == null {
        return ""
    }
    let state_hardfork = ($marker | get -o state_hardfork | default "")
    if $state_hardfork == "" {
        return ""
    }
    normalize-hardfork $state_hardfork
}

def normalize-gas-limit [gas_limit: string] {
    if $gas_limit == "" {
        return ""
    }
    $gas_limit | into int | into string
}

def gas-limit-quantity [gas_limit: string] {
    let normalized = (normalize-gas-limit $gas_limit)
    if $normalized == "" {
        return ""
    }
    $normalized | into int | format number | get lowerhex
}

def e2e-snapshot-state-gas-limit [datadir: string] {
    let marker = (read-bench-marker $datadir)
    if $marker != null {
        let marker_gas_limit = ($marker | get -o gas_limit | default "")
        if $marker_gas_limit != "" {
            return (normalize-gas-limit $marker_gas_limit)
        }
    }

    let genesis_path = $"($datadir)/($BENCH_META_SUBDIR)/genesis.json"
    if ($genesis_path | path exists) {
        let genesis_gas_limit = (open $genesis_path | get -o gasLimit | default "")
        if $genesis_gas_limit != "" {
            return (normalize-gas-limit $genesis_gas_limit)
        }
    }

    ""
}

def e2e-snapshot-state-general-gas-limit [datadir: string] {
    let marker = (read-bench-marker $datadir)
    if $marker != null {
        let marker_general_gas_limit = ($marker | get -o general_gas_limit | default "")
        if $marker_general_gas_limit != "" {
            return (normalize-gas-limit $marker_general_gas_limit)
        }
    }

    let genesis_path = $"($datadir)/($BENCH_META_SUBDIR)/genesis.json"
    if ($genesis_path | path exists) {
        let genesis_general_gas_limit = (open $genesis_path | get -o config.generalGasLimit | default "")
        if $genesis_general_gas_limit != "" {
            return (normalize-gas-limit $genesis_general_gas_limit)
        }
    }

    ""
}

def e2e-update-snapshot-genesis-marker [
    datadir: string,
    hardfork: string,
    gas_limit: string,
    general_gas_limit: string,
] {
    let marker_path = $"($datadir)/($BENCH_META_SUBDIR)/marker.json"
    mut marker = (open $marker_path)
    if $hardfork != "" {
        let fork = (normalize-hardfork $hardfork)
        $marker = ($marker | upsert state_hardfork $fork)
    }
    if $gas_limit != "" {
        $marker = ($marker | upsert gas_limit (normalize-gas-limit $gas_limit))
    }
    if $general_gas_limit != "" {
        $marker = ($marker | upsert general_gas_limit (normalize-gas-limit $general_gas_limit))
    } else {
        $marker = ($marker | reject -o general_gas_limit)
    }
    $marker | to json | save -f $marker_path
}

def e2e-synthesize-genesis [
    source_genesis: string,
    target_genesis: string,
    hardfork: string,
    gas_limit: string,
    general_gas_limit: string,
] {
    let source = (open $source_genesis)
    mut config = ($source | get config)
    mut patch_labels = []
    if $hardfork != "" {
        let fork = (normalize-hardfork $hardfork)
        for field in (hardfork-genesis-config-fields $fork) {
            $config = ($config | upsert $field.name $field.value)
        }
        $patch_labels = ($patch_labels | append $"hardfork=($fork)")
    }
    if $general_gas_limit != "" {
        let normalized_general_gas_limit = (normalize-gas-limit $general_gas_limit)
        $config = ($config | upsert generalGasLimit ($normalized_general_gas_limit | into int))
        $patch_labels = ($patch_labels | append $"general_gas_limit=($normalized_general_gas_limit)")
    } else {
        $config = ($config | reject -o generalGasLimit)
    }
    mut genesis = ($source | upsert config $config)
    if $gas_limit != "" {
        let normalized_gas_limit = (normalize-gas-limit $gas_limit)
        $genesis = ($genesis | upsert gasLimit (gas-limit-quantity $normalized_gas_limit))
        $patch_labels = ($patch_labels | append $"gas_limit=($normalized_gas_limit)")
    }
    let target_dir = ($target_genesis | path dirname)
    mkdir $target_dir
    $genesis | to json | save -f $target_genesis
    let patch_label = if ($patch_labels | length) > 0 {
        $patch_labels | str join ", "
    } else {
        "unchanged"
    }
    print $"Synthesized genesis \(($patch_label)\) at ($target_genesis)"
}

def e2e-regenesis [
    tempo_bin: string,
    genesis: string,
    datadir: string,
    hardfork: string,
    gas_limit: string,
    general_gas_limit: string,
] {
    let target_hardfork = if $hardfork != "" { normalize-hardfork $hardfork } else { latest-tempo-hardfork }
    let target_gas_limit = if $gas_limit != "" { normalize-gas-limit $gas_limit } else { "" }
    let target_general_gas_limit = if $general_gas_limit != "" { normalize-gas-limit $general_gas_limit } else { "" }
    let current_hardfork = (e2e-snapshot-state-hardfork $datadir)
    let current_gas_limit = (e2e-snapshot-state-gas-limit $datadir)
    let current_general_gas_limit = (e2e-snapshot-state-general-gas-limit $datadir)
    let hardfork_matches = $current_hardfork == $target_hardfork
    let gas_limit_matches = $target_gas_limit == "" or $current_gas_limit == $target_gas_limit
    let general_gas_limit_matches = $current_general_gas_limit == $target_general_gas_limit
    if $hardfork_matches and $gas_limit_matches and $general_gas_limit_matches {
        mut matches = []
        if $target_hardfork != "" {
            $matches = ($matches | append $"state_hardfork=($target_hardfork)")
        }
        if $target_gas_limit != "" {
            $matches = ($matches | append $"gas_limit=($target_gas_limit)")
        }
        if $target_general_gas_limit != "" {
            $matches = ($matches | append $"general_gas_limit=($target_general_gas_limit)")
        }
        print $"Skipping tempo regenesis for ($datadir); marker already matches (($matches | str join ', '))"
        return
    }

    let target_genesis = $"($datadir)/($BENCH_META_SUBDIR)/regenesis-target.json"
    e2e-synthesize-genesis $genesis $target_genesis $target_hardfork $target_gas_limit $target_general_gas_limit

    mut changes = []
    if not $hardfork_matches {
        $changes = ($changes | append $"state_hardfork=($current_hardfork) -> ($target_hardfork)")
    }
    if not $gas_limit_matches {
        $changes = ($changes | append $"gas_limit=($current_gas_limit) -> ($target_gas_limit)")
    }
    if not $general_gas_limit_matches {
        $changes = ($changes | append $"general_gas_limit=($current_general_gas_limit) -> ($target_general_gas_limit)")
    }
    print $"Running tempo regenesis for ($datadir): ($changes | str join ', ') with ($target_genesis)..."
    let result = (run-external $tempo_bin "regenesis" "--chain" $target_genesis "--datadir" $datadir | complete)
    if $result.stdout != "" { print $result.stdout }
    if $result.stderr != "" { print $result.stderr }
    if $result.exit_code != 0 {
        print $"Error: tempo regenesis failed for ($datadir) with exit code ($result.exit_code)"
        exit $result.exit_code
    }
    e2e-synthesize-genesis $"($datadir)/($BENCH_META_SUBDIR)/genesis.json" $"($datadir)/($BENCH_META_SUBDIR)/genesis.json" $target_hardfork $target_gas_limit $target_general_gas_limit
    e2e-update-snapshot-genesis-marker $datadir $target_hardfork $target_gas_limit $target_general_gas_limit
    rm $target_genesis
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
    if ($env.BENCH_RUN_CLEANUP? | default "") == "true" {
        $telemetry_env_names = ($telemetry_env_names | append "TMPDIR")
    }
    if ($env.TEMPO_TELEMETRY_URL? | default "" | str length) > 0 {
        $telemetry_env_names = ($telemetry_env_names | append "TEMPO_TELEMETRY_URL")
    }
    if ($env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT? | default "" | str length) > 0 {
        $telemetry_env_names = ($telemetry_env_names | append "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
    }
    let preserve_env_args = if ($telemetry_env_names | length) > 0 {
        [$"--preserve-env=($telemetry_env_names | str join ',')"]
    } else { [] }
    let telemetry_env = ($telemetry_env_names | each { |name|
        if $name == "TMPDIR" {
            $"--setenv=TMPDIR=($env.TMPDIR)"
        } else {
            $"--setenv=($name)"
        }
    })
    [
        "sudo"
        ...$preserve_env_args
        "systemd-run"
        "--scope"
        "--quiet"
        "--collect"
        "--same-dir"
        "--unit" $unit
        ...$telemetry_env
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
    quiet: bool,
    scheduler: bool,
] {
    let profile_label = $"($phase)-($role)"
    let full_samply_args = if $samply {
        $samply_args | append ["--save-only" "--presymbolicate" "--output" $"($results_dir)/profile-($profile_label).json.gz"]
    } else { [] }
    let pinned_cmd = taskset-command [$tempo_bin ...$args] $cpus
    let node_cmd = wrap-samply $pinned_cmd $samply $full_samply_args
    let plain_node_cmd = ($node_cmd | str join " ")
    let node_cmd_str = if $scheduler {
        let encoded = ($plain_node_cmd | encode base64)
        let directory = ($"($results_dir)/lifecycle-raw/($phase)" | path expand)
        $"/usr/bin/python3 contrib/bench/lifecycle/scheduler/runtime.py --binary ($tempo_bin) --role ($role) --directory ($directory) --command-base64 ($encoded)"
    } else { $plain_node_cmd }
    let script = $"($env_prefix)($otel_attrs)($tracy_env_prefix)($node_cmd_str) 2>&1"
    let unit_phase = ($phase | str replace -a "_" "-" | str replace -a "." "-")
    let runner = (systemd-scope-command $"tempo-e2e-($role)-($unit_phase)" $cpus $memory $script)
    if not $quiet { print $"Starting local e2e validator ($role) for ($phase): ($runner | str join ' ')" }
    job spawn {
        run-external ($runner | first) ...($runner | skip 1)
        | lines
        | each { |line| if not $quiet { print $"[e2e-($phase)-($role)] ($line)" } }
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
    let signing_key_contents = (open --raw $signing_key | into binary)
    let signing_key_is_encrypted = ($signing_key_contents | bytes starts-with 0x[61 67 65 2d 65 6e 63 72 79 70 74 69 6f 6e 2e 6f 72 67 2f])
    let signing_secret_args = if $signing_key_is_encrypted {
        ["--consensus.secret" "<(printf '%s\\n' 'tempo-localnet-signing-key-secret')"]
    } else {
        []
    }

    let execution_p2p_port = $port + 1
    let metrics_port = $port + 2
    let authrpc_port = $port + 3
    let discv5_port = $port + 4

    [
        "--consensus.signing-key" $signing_key
        ...$signing_secret_args
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
        sudo kill -s 2 $pid
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
            sudo kill -s 9 $pid
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
        sudo kill -s 2 $pid
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
            sudo kill -s 9 $pid
        }
    }
}

def wait-for-tracy-capture-exit [job_id: int, phase: string] {
    print "  Waiting for tracy-capture to exit and close trace..."
    let result = (try {
        job recv --tag 18999 --timeout 45sec
    } catch {
        null
    })
    if $result == null {
        print $"  Warning: tracy-capture job did not report completion for ($phase); killing job ($job_id)"
        try { job kill $job_id } catch {}
        return
    }
    let exit_code = ($result | get --optional exit_code | default 0)
    if $exit_code != 0 {
        print $"  Warning: tracy-capture exited with code ($exit_code) for ($phase)"
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

def chown-to-current-user [path: string] {
    if (^uname | str trim) != "Linux" or not ($path | path exists) {
        return
    }
    let uid = (id -u | str trim)
    let gid = (id -g | str trim)
    sudo chown -R $"($uid):($gid)" $path | ignore
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

# Update the PR comment with current benchmark phase status.
# Requires BENCH_GH_TOKEN, BENCH_COMMENT_ID, BENCH_ACTOR, BENCH_JOB_URL,
# BENCH_CONFIG, and GITHUB_REPOSITORY environment variables.
def bench-update-pr-status [status: string] {
    let comment_id = ($env | get -o BENCH_COMMENT_ID | default "")
    let token = ($env | get -o BENCH_GH_TOKEN | default "")
    if $comment_id == "" or $token == "" { return }
    let repo = $env.GITHUB_REPOSITORY
    let actor = ($env | get -o BENCH_ACTOR | default "")
    let job_url = ($env | get -o BENCH_JOB_URL | default "")
    let config = ($env | get -o BENCH_CONFIG | default "")
    let body = $"cc @($actor)\n\n🚀 Benchmark started! [View job]\(($job_url)\)\n\n⏳ **Status:** ($status)\n\n($config)"
    let payload = { body: $body } | to json
    try {
        ^curl -sS -X PATCH $"https://api.github.com/repos/($repo)/issues/comments/($comment_id)" -H $"Authorization: token ($token)" -H "Accept: application/vnd.github+json" -d $payload | ignore
    } catch {
        print $"Warning: failed to update PR comment status"
    }
}

def build-valscope-static-reports [
    results_dir: string,
    benchmark_id: string,
    valscope_dir: string,
] {
    let manifest = $"($valscope_dir)/apps/api/Cargo.toml"
    if not ($manifest | path exists) {
        print $"Error: ValScope API Cargo manifest not found at ($manifest)"
        exit 1
    }

    let vm_url = ($env | get -o VICTORIAMETRICS_URL | default "")
    let vlogs_url = ($env | get -o VICTORIALOGS_URL | default "")
    if $vm_url == "" {
        print "Error: VICTORIAMETRICS_URL is required to generate ValScope static reports"
        exit 1
    }
    if $vlogs_url == "" {
        print "Error: VICTORIALOGS_URL is required to generate ValScope static reports"
        exit 1
    }

    print "Generating ValScope static reports with configured VM/VLogs datasources"
    let out_dir = $"($results_dir)/valscope-static"
    let web_dir = $"($valscope_dir)/apps/web"
    let web_dist = $"($web_dir)/dist"
    let npm_ci = (run-external "npm" "--prefix" $web_dir "ci" | complete)
    if $npm_ci.stdout != "" { print $npm_ci.stdout }
    if $npm_ci.stderr != "" { print $npm_ci.stderr }
    if $npm_ci.exit_code != 0 {
        print $"Error: ValScope web dependency install failed with exit code ($npm_ci.exit_code)"
        exit $npm_ci.exit_code
    }
    let web_build = (run-external "npm" "--prefix" $web_dir "run" "build:static-report-app" | complete)
    if $web_build.stdout != "" { print $web_build.stdout }
    if $web_build.stderr != "" { print $web_build.stderr }
    if $web_build.exit_code != 0 {
        print $"Error: ValScope static web build failed with exit code ($web_build.exit_code)"
        exit $web_build.exit_code
    }
    let result = (with-env { VICTORIAMETRICS_URL: $vm_url, VICTORIALOGS_URL: $vlogs_url } {
        run-external "cargo" "run" "--manifest-path" $manifest "--bin" "valscope-bench-report" "--" "--results-dir" $results_dir "--out-dir" $out_dir "--web-dist" $web_dist "--benchmark-id" $benchmark_id | complete
    })
    if $result.stdout != "" { print $result.stdout }
    if $result.stderr != "" { print $result.stderr }
    if $result.exit_code != 0 {
        if ($out_dir | path exists) { rm -rf $out_dir }
        print $"Error: ValScope static report generation failed with exit code ($result.exit_code)"
        exit $result.exit_code
    }
}

def lifecycle-finalize-phase-receipt [window_path: string, receipt_path: string] {
    let stop_reason = (open $window_path | get -o stop_reason | default "")
    if $stop_reason not-in ["load_finished" "backpressure"] {
        error make {msg: "Invalid sanitized lifecycle stop reason"}
    }
    let receipt = (open $receipt_path)
    if ($receipt | columns | sort) != ["finished_ms" "phase" "schema" "started_ms" "stop_reason"] or $receipt.schema != 1 {
        error make {msg: "Invalid private lifecycle phase receipt"}
    }
    $receipt | upsert stop_reason $stop_reason | to json | save -f $receipt_path
    $stop_reason
}

def run-local-e2e-phase [run: record, ctx: record] {
    let phase = $run.phase
    if ($ctx.prebuilt_directory? | default "") != "" {
        let features = if $run.side == "baseline" { $ctx.baseline_build_features } else { $ctx.feature_build_features }
        let selected = (prebuilt-select $ctx.prebuilt_directory $run.side $run.ref $features $ctx.profile $ctx.a.cpus $ctx.b.cpus)
        if $selected.tempo != $run.tempo or $selected.txgen_tempo != $ctx.txgen.txgen_tempo_bin or $selected.bench != $ctx.txgen.txgen_bench_bin {
            error make {msg: "Prebuilt phase binary identity changed"}
        }
    }
    print $"=== Starting local e2e phase: ($phase) ==="
    let run_type = $run.side
    let genesis = ($run | get -o genesis | default $ctx.genesis)
    let hardfork = ($run | get -o hardfork | default "")
    let side_args = if $run_type == "baseline" { $ctx.baseline_args } else { $ctx.feature_args }
    let side_env = if $run_type == "baseline" { $ctx.baseline_env } else { $ctx.feature_env }
    let extra_args = (parse-cli-args $side_args)
    let local_reth_args = if $run_type == "baseline" { $ctx.baseline_local_reth_args } else { $ctx.feature_local_reth_args }

    cleanup-local-e2e-processes
    bench-restore-at $ctx.a.state_path $ctx.a.mount $ctx.a.datadir
    bench-restore-at $ctx.b.state_path $ctx.b.mount $ctx.b.datadir

    for path in [$genesis $ctx.a.node_dir $ctx.b.node_dir] {
        if not ($path | path exists) {
            print $"Error: required e2e path does not exist after snapshot recovery: ($path)"
            exit 1
        }
    }
    if $hardfork != "" or $ctx.gas_limit != "" or $ctx.general_gas_limit != "" {
        e2e-regenesis $ctx.regenesis_tempo $genesis $ctx.a.datadir $hardfork $ctx.gas_limit $ctx.general_gas_limit
        e2e-regenesis $ctx.regenesis_tempo $genesis $ctx.b.datadir $hardfork $ctx.gas_limit $ctx.general_gas_limit
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
        $"($ctx.results_dir)/tracy-capture-($phase).log"
        $"($ctx.results_dir)/logs-($phase)-a"
        $"($ctx.results_dir)/logs-($phase)-b"
    ] {
        if ($stale | path exists) { rm -rf $stale }
    }
    if ("report.json" | path exists) { rm report.json }

    let a_rpc = "http://127.0.0.1:8545"
    let b_rpc = "http://127.0.0.1:8645"
    let a_base_args = (build-base-args $genesis $ctx.a.datadir $a_log_dir "0.0.0.0" 8545 9001)
        | append ["--log.file.format" "json"]
        | append (build-e2e-consensus-args $ctx.a.node_dir $ctx.trusted_peers $ctx.a.consensus_port $ctx.a.ip)
        | append $local_reth_args
        | append (log-filter-args $ctx.loud)
        | append (if $ctx.gas_limit != "" { ["--builder.gaslimit" $ctx.gas_limit] } else { [] })
        | append (if $ctx.samply { ["--log.samply"] } else { [] })
        | append (if $ctx.tracy != "off" { ["--log.tracy" "--log.tracy.filter" $ctx.tracy_filter] } else { [] })
        | append (benchmark-otlp-args $ctx.tracing_otlp)
    let b_base_args = (build-base-args $genesis $ctx.b.datadir $b_log_dir "0.0.0.0" 8645 9101)
        | append ["--log.file.format" "json"]
        | append (build-e2e-consensus-args $ctx.b.node_dir $ctx.trusted_peers $ctx.b.consensus_port $ctx.b.ip)
        | append $local_reth_args
        | append (log-filter-args $ctx.loud)
        | append (if $ctx.gas_limit != "" { ["--builder.gaslimit" $ctx.gas_limit] } else { [] })
        | append (if $ctx.samply { ["--log.samply"] } else { [] })
        | append (benchmark-otlp-args $ctx.tracing_otlp)
    let privacy_args = if $ctx.lifecycle { ["--log.stdout.filter" "off" "--log.file.filter" "off"] } else { [] }
    let a_args = (dedup-args $a_base_args ($extra_args | append $privacy_args))
    let b_args = (dedup-args $b_base_args ($extra_args | append $privacy_args))

    if $ctx.tracy != "off" {
        print $"  Tracy mode: ($ctx.tracy), sampling hz: ($TRACY_SAMPLING_HZ)"
    }
    let tracy_env_prefix = if $ctx.tracy != "off" { $"TRACY_SAMPLING_HZ=($TRACY_SAMPLING_HZ) " } else { "" }
    let env_prefix = if $side_env != "" { $"($side_env) " } else { "" }
    let a_otel = $"OTEL_RESOURCE_ATTRIBUTES=benchmark_id=($ctx.benchmark_id),benchmark_run=($phase),runner_role=a,run_type=($run_type),git_ref=($run.ref),reference_epoch=($ctx.reference_epoch) "
    let b_otel = $"OTEL_RESOURCE_ATTRIBUTES=benchmark_id=($ctx.benchmark_id),benchmark_run=($phase),runner_role=b,run_type=($run_type),git_ref=($run.ref),reference_epoch=($ctx.reference_epoch) "

    let lifecycle_dir = ($"($ctx.results_dir)/lifecycle-raw/($phase)" | path expand)
    let lifecycle_report_dir = ($"($ctx.results_dir)/lifecycle/($phase)" | path expand)
    let lifecycle_key = ($"($LOCALNET_DIR)/lifecycle-key-($phase)" | path expand)
    if $ctx.lifecycle {
        # Only pre-start disk admission is recoverable here. Return through the
        # phase loop so its existing owned-worktree cleanup and restore run.
        let admitted = try {
            lifecycle-require-disk "before capture, results filesystem" $ctx.results_dir 49152
            lifecycle-require-disk "before capture, runner root" "/" 49152
            true
        } catch { false }
        if not $admitted {
            print "Lifecycle phase admission failed: capture disk guard"
            return 1
        }
    }
    let lifecycle_epoch = if $ctx.lifecycle {
        mkdir $lifecycle_dir
        ^python3 -c 'import os,sys,time; f=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(f,os.urandom(32)); os.close(f); print(time.monotonic_ns())' $lifecycle_key | str trim
    } else { "" }
    let capture_detail = ($run.lifecycle_detail? | default $ctx.lifecycle_detail)
    let readiness_env = if ($env.BENCH_READ_READINESS? | default "false") == "true" {
        let trial_baseline = ($env.BENCH_SELECTIVE_RETRY_TRIAL? | default "") == "true" and $run_type == "baseline"
        if not $ctx.lifecycle or $capture_detail != "milestones" or ($run_type != "feature" and not $trial_baseline) {
            error make {msg: "Read-readiness capture requires an admitted milestone phase"}
        }
        "TEMPO_READ_READINESS=1 "
    } else { "env -u TEMPO_READ_READINESS " }
    let scheduler_env = if $ctx.lifecycle_scheduler { "TEMPO_LIFECYCLE_SCHEDULER=registered_threads_v1 TEMPO_LIFECYCLE_KERNEL_WAITS=2 TEMPO_LIFECYCLE_PREWARM_CPU=disabled TEMPO_LIFECYCLE_PROCESS_CPU=disabled " } else { "" }
    let prewarm_config = (lifecycle-prewarm-config $ctx.lifecycle_prewarm_cpu $run.side)
    let a_capture = if $ctx.lifecycle { $"($prewarm_config.env)($scheduler_env)($readiness_env)RETH_LIFECYCLE_FILE=($lifecycle_dir)/a.jsonl TEMPO_LIFECYCLE_DETAIL=($capture_detail) RETH_LIFECYCLE_KEY_FILE=($lifecycle_key) RETH_LIFECYCLE_EPOCH_NS=($lifecycle_epoch) " } else { "" }
    let b_capture = if $ctx.lifecycle { $"($prewarm_config.env)($scheduler_env)($readiness_env)RETH_LIFECYCLE_FILE=($lifecycle_dir)/b.jsonl TEMPO_LIFECYCLE_DETAIL=($capture_detail) RETH_LIFECYCLE_KEY_FILE=($lifecycle_key) RETH_LIFECYCLE_EPOCH_NS=($lifecycle_epoch) " } else { "" }

    mark-schelk-dirty-at $ctx.a.state_path
    mark-schelk-dirty-at $ctx.b.state_path

    # Admission can reject the phase; change host tuning only after it succeeds.
    let tuning_state = if $ctx.tune { apply-system-tuning } else { { tuned: false } }

    start-e2e-local-node a $phase $run.tempo $a_args $"($env_prefix)($a_capture)" $a_otel $tracy_env_prefix $ctx.samply $ctx.samply_args $ctx.results_dir $ctx.a.cpus $ctx.a.memory $ctx.lifecycle $ctx.lifecycle_scheduler
    start-e2e-local-node b $phase $run.tempo $b_args $"($env_prefix)($b_capture)" $b_otel "" $ctx.samply $ctx.samply_args $ctx.results_dir $ctx.b.cpus $ctx.b.memory $ctx.lifecycle $ctx.lifecycle_scheduler

    if $ctx.lifecycle_scheduler {
        # The diagnostic checks the final binary and attaches before exec.
        mut startup_wait = 0
        while ((find-tempo-pids) | length) < 2 and $startup_wait < 150 {
            if ($"($lifecycle_dir)/scheduler-a.failed" | path exists) or ($"($lifecycle_dir)/scheduler-b.failed" | path exists) { break }
            sleep 1sec
            $startup_wait = $startup_wait + 1
        }
    } else { sleep 2sec }
    let rpc_timeout = if $ctx.bloat > 0 { 600 } else { 300 }
    mut phase_exit = 0
    if ((find-tempo-pids) | length) < 2 {
        print $"Error: local e2e validators exited before readiness checks completed for ($phase)"
        if $ctx.lifecycle_scheduler {
            ^python3 contrib/bench/lifecycle/scheduler/runtime.py --failure-summary $lifecycle_dir
        }
        $phase_exit = 1
    }
    if $phase_exit == 0 and not (e2e-wait-for-rpc-online $a_rpc $rpc_timeout) { $phase_exit = 1 }
    if $phase_exit == 0 and not (e2e-wait-for-rpc-online $b_rpc $rpc_timeout) { $phase_exit = 1 }
    if $phase_exit == 0 and not (e2e-wait-for-peers $a_rpc 1 300) { $phase_exit = 1 }
    if $phase_exit == 0 and not (e2e-wait-for-peers $b_rpc 1 300) { $phase_exit = 1 }
    if $phase_exit == 0 and not (e2e-wait-for-chain-advance $a_rpc 300) { $phase_exit = 1 }
    if $phase_exit == 0 and not (e2e-wait-for-chain-advance $b_rpc 300) { $phase_exit = 1 }

    # Validators may run as root and create mode-0600 captures. Hand off this
    # owned phase before either admission or the backpressure watcher reads it.
    if $phase_exit == 0 and $ctx.lifecycle {
        chown-to-current-user $lifecycle_dir
    }

    if $phase_exit == 0 and $ctx.lifecycle_prewarm_cpu == "compare" {
        let admission = (^python3 contrib/bench/lifecycle/prewarm.py --expected $prewarm_config.expected --timeout 10 $"($lifecycle_dir)/a.jsonl" $"($lifecycle_dir)/b.jsonl" | complete)
        if $admission.exit_code != 0 {
            print "prewarm_cpu_admission_failed"
            $phase_exit = 1
        }
    }

    let tracy_output = $"($ctx.results_dir)/tracy-profile-($phase).tracy"
    let tracy_log = $"($ctx.results_dir)/tracy-capture-($phase).log"
    mut tracy_capture_started = false
    mut tracy_capture_job = 0
    if $phase_exit == 0 and $ctx.tracy != "off" {
        let seconds_flag = if $ctx.tracy_seconds > 0 { $"-s ($ctx.tracy_seconds)" } else { "" }
        let limit_msg = if $ctx.tracy_seconds > 0 { $" \(($ctx.tracy_seconds)s limit\)" } else { "" }
        let capture_path = ($env.PATH | str join (char esep))
        let capture_cmd = $"sudo env PATH=($capture_path) TRACY_SAMPLING_HZ=($TRACY_SAMPLING_HZ) tracy-capture -f -o ($tracy_output) ($seconds_flag) >($tracy_log) 2>&1"
        if $ctx.tracy_offset > 0 {
            print $"  Tracy-capture will start after ($ctx.tracy_offset) seconds($limit_msg)..."
            $tracy_capture_job = (job spawn {
                sleep ($"($ctx.tracy_offset)sec" | into duration)
                let result = (sh -c $capture_cmd | complete)
                { phase: $phase, exit_code: $result.exit_code } | job send --tag 18999 0
            })
        } else {
            print $"  Starting tracy-capture($limit_msg)..."
            $tracy_capture_job = (job spawn {
                let result = (sh -c $capture_cmd | complete)
                { phase: $phase, exit_code: $result.exit_code } | job send --tag 18999 0
            })
            sleep 500ms
        }
        $tracy_capture_started = true
    }

    let phase_clickhouse_url = if $ctx.clickhouse_url != "" and ($ctx.clickhouse_run == "" or $ctx.clickhouse_run == $phase) {
        $ctx.clickhouse_url
    } else {
        ""
    }
    let metrics_urls = ["a:http://127.0.0.1:9001/metrics" "b:http://127.0.0.1:9101/metrics"]
        | append (if $ctx.runner_metrics_url != "" { [$"runner:($ctx.runner_metrics_url)"] } else { [] })
    let submit_rpc_url = [$a_rpc $b_rpc] | str join ","

    mut phase_stop_reason = ""
    if $phase_exit == 0 {
        let phase_started_ms = ((date now | into int) / 1_000_000 | into int)
        let initial_db_size_bytes = (e2e-db-size-bytes $ctx.a.datadir)
        let sender_exit = (try {
            let load_config = {ctx: $ctx, run: $run, phase: $phase, a_rpc: $a_rpc,
                submit_rpc_url: $submit_rpc_url, metrics_urls: $metrics_urls,
                initial_db_size_bytes: $initial_db_size_bytes, phase_clickhouse_url: $phase_clickhouse_url}
            if $ctx.lifecycle {
                with-env {TEMPO_LIFECYCLE_LOAD: ($load_config | to json --raw)} {
                    ^python3 contrib/bench/lifecycle/backpressure.py --epoch $lifecycle_epoch --window $"($lifecycle_dir)/window.json" --capture $"($lifecycle_dir)/a.jsonl" --capture $"($lifecycle_dir)/b.jsonl" -- nu bench-e2e.nu lifecycle-load
                    $env.LAST_EXIT_CODE
                }
            } else {
                (e2e-load $load_config).exit_code
            }
        } catch { |e|
            print $"Error: local e2e txgen sender failed for ($phase): ($e.msg)"
            1
        })
        if $sender_exit == 0 and $phase_clickhouse_url != "" {
            let report = (open $"($ctx.results_dir)/report-($phase).json")
            let report_benchmark_id = ($report | get --optional benchmark_id | default "")
            if $report_benchmark_id != "" {
                $report_benchmark_id | save -f $"($ctx.results_dir)/clickhouse-run-id-($phase).txt"
                $report_benchmark_id | save -f $"($ctx.results_dir)/clickhouse-run-id.txt"
            }
        }
        let phase_finished_ms = ((date now | into int) / 1_000_000 | into int)
        $phase_stop_reason = if $ctx.lifecycle and ($"($lifecycle_dir)/window.json" | path exists) {
            open $"($lifecycle_dir)/window.json" | get -o stop_reason | default ""
        } else if not $ctx.lifecycle { "load_finished" } else { "" }
        if $phase_stop_reason not-in ["load_finished" "backpressure"] {
            print $"Error: invalid lifecycle stop reason for ($phase)"
            $phase_exit = 1
        }
        {
            schema: 1
            phase: $phase
            started_ms: $phase_started_ms
            finished_ms: $phase_finished_ms
            stop_reason: $phase_stop_reason
        } | to json | save -f $"($ctx.results_dir)/phase-range-($phase).json"
        if $sender_exit != 0 { $phase_exit = $sender_exit }
    } else {
        print $"Skipping local e2e sender for ($phase) because readiness checks failed"
    }

    if $tracy_capture_started {
        print "  Stopping validators before tracy-capture so Tracy can record graceful node shutdown..."
    }
    stop-e2e-processes-gracefully
    if $tracy_capture_started {
        stop-tracy-capture
        if $tracy_capture_job > 0 {
            wait-for-tracy-capture-exit $tracy_capture_job $phase
        }
        if not ($tracy_output | path exists) {
            print $"  Warning: tracy-capture did not write ($tracy_output)"
            if ($tracy_log | path exists) {
                print $"  tracy-capture log for ($phase):"
                open $tracy_log | lines | each { |line| print $"    ($line)" }
            } else {
                print $"  Warning: tracy-capture log not found: ($tracy_log)"
            }
        }
    }
    if $ctx.samply { wait-for-samply-profile }
    chown-to-current-user $ctx.results_dir
    chown-to-current-user $a_log_dir
    chown-to-current-user $b_log_dir
    if not $ctx.lifecycle and ($a_log_dir | path exists) { cp -r $a_log_dir $"($ctx.results_dir)/logs-($phase)-a" }
    if not $ctx.lifecycle and ($b_log_dir | path exists) { cp -r $b_log_dir $"($ctx.results_dir)/logs-($phase)-b" }
    restore-system-tuning $tuning_state
    if $ctx.lifecycle {
        rm -f $lifecycle_key
        let prewarm_report_args = if $ctx.lifecycle_prewarm_cpu == "compare" { ["--expected-prewarm-cpu" $prewarm_config.expected] } else { [] }
        let scheduler_report_args = if $ctx.lifecycle_scheduler { ["--scheduler-dir" $lifecycle_dir] } else { [] }
        let report = (^python3 contrib/bench/lifecycle/progress.py ...$scheduler_report_args --prune --expected-detail $capture_detail ...$prewarm_report_args --out $lifecycle_report_dir --warmup $ctx.summary_warmup_blocks --workload-report $"($ctx.results_dir)/report-($phase).json" --window $"($lifecycle_dir)/window.json" $"($lifecycle_dir)/a.jsonl" $"($lifecycle_dir)/b.jsonl" err> /dev/stderr | complete)
        if $report.exit_code != 0 { $phase_exit = 1 }
        if $report.exit_code == 0 {
            let final_stop_reason = try {
                lifecycle-finalize-phase-receipt $"($lifecycle_report_dir)/window.json" $"($ctx.results_dir)/phase-range-($phase).json"
            } catch { |error|
                print $"Error: failed to reconcile lifecycle stop reason for ($phase): ($error.msg)"
                ""
            }
            if $final_stop_reason == "" {
                $phase_exit = 1
            } else {
                $phase_stop_reason = $final_stop_reason
            }
        }
        rm -rf $lifecycle_dir
        if $phase_exit == 0 {
            # Workload has returned, validators stopped, tuning restored and the
            # strict pre-cutoff report completed. Compress only this owned phase.
            if (find-tempo-pids | length) != 0 {
                error make {msg: "Cannot retain lifecycle phase while validators remain active"}
            }
            if ($ctx.prebuilt_directory? | default "") != "" {
                cp $"($ctx.prebuilt_directory)/admission.json" $"($lifecycle_report_dir)/prebuilt-admission.json"
            }
            let archive = (^python3 contrib/bench/lifecycle/phase_archive.py pack $lifecycle_report_dir --remove-source | complete)
            print $archive.stdout
            if $archive.stderr != "" { print $archive.stderr }
            if $archive.exit_code != 0 { $phase_exit = 1 }
        }
    }

    if $phase_exit == 0 and $phase_stop_reason == "backpressure" {
        let completed = (glob $"($ctx.results_dir)/phase-range-*.json" | length)
        ^python3 contrib/bench/lifecycle/statistical_trial.py unavailable $ctx.results_dir $completed
        return 75
    }

    if $phase_exit != 0 {
        return $phase_exit
    }
    print $"=== Local e2e phase complete: ($phase) ==="
    return 0
}

# Run in a separate process group so a lifecycle stop interrupts funding, setup,
# generation and submission together, while the parent still drains validators.
def e2e-load [config: record] {
    let ctx = $config.ctx
    let run = $config.run
    let phase = $config.phase
    let a_rpc = $config.a_rpc
    let submit_rpc_url = $config.submit_rpc_url
    let metrics_urls = $config.metrics_urls
    let initial_db_size_bytes = $config.initial_db_size_bytes
    let phase_clickhouse_url = $config.phase_clickhouse_url
    let scenario = $ctx.preset
    (txgen-run-preset-pipeline
        --txgen-tempo-bin $ctx.txgen.txgen_tempo_bin
        --txgen-bench-bin $ctx.txgen.txgen_bench_bin
        --preset-path $ctx.preset_path
        --generate-rpc-url $a_rpc
        --submit-rpc-url $submit_rpc_url
        --metrics-url $metrics_urls
        --report-path $"($ctx.results_dir)/report-($phase).json"
        --tps $ctx.tps
        --duration $ctx.duration
        --accounts $ctx.accounts
        --max-concurrent-requests $ctx.max_concurrent_requests
        --bench-args $ctx.bench_args
        --bench-env $ctx.bench_env
        --git-ref $run.ref
        --git-ref-label ($run | get -o ref_label | default $run.ref)
        --build-profile $ctx.profile
        --benchmark-mode "e2e"
        --benchmark-id $ctx.benchmark_id
        --benchmark-run $phase
        --run-type $ctx.run_type
        --benchmark-start $ctx.reference_epoch
        --platform "tempo"
        --scenario $scenario
        --bloat-mib $ctx.bloat
        --tip20-token-count $ctx.token_count
        --bloat-token-count ($TIP20_TOKEN_IDS | length)
        --initial-db-size-bytes $initial_db_size_bytes
        --victoriametrics-url $ctx.victoriametrics_url
        --clickhouse-url $phase_clickhouse_url
        --skip-funding=($ctx.bloat > 0))
}

def "main lifecycle-load" [] {
    let result = (e2e-load ($env.TEMPO_LIFECYCLE_LOAD | from json))
    exit $result.exit_code
}

def e2e-run-sides [run_pairs: int, run_side: string] {
    if $run_pairs <= 0 {
        print "Error: --run-pairs must be a positive integer"
        exit 1
    }

    if $run_side == "feature" {
        return (0..<$run_pairs | each { "feature" })
    }
    if $run_side == "baseline" {
        return (0..<$run_pairs | each { "baseline" })
    }

    mut sides = []
    if ($run_pairs mod 2) == 0 {
        for _ in 0..<($run_pairs // 2) {
            $sides = ($sides | append ["feature" "baseline" "baseline" "feature"])
        }
    } else {
        for _ in 0..<$run_pairs {
            $sides = ($sides | append ["feature" "baseline"])
        }
    }
    $sides
}

def e2e-write-summary-config [
    results_dir: string
    baseline_label: string
    feature_label: string
    bloat_mib: int
    token_count: int
    preset: string
    tps: int
    duration: int
    benchmark_id: string
    reference_epoch: int
    summary_warmup_blocks: int
    run_side: string
    baseline_hardfork: string
    feature_hardfork: string
    baseline_removed_args: string
    feature_removed_args: string
] {
    {
        baseline_label: $baseline_label
        feature_label: $feature_label
        bloat_mib: $bloat_mib
        token_count: $token_count
        preset: $preset
        tps: $tps
        duration: $duration
        benchmark_id: $benchmark_id
        reference_epoch: $reference_epoch
        summary_warmup_blocks: $summary_warmup_blocks
        run_side: $run_side
        baseline_hardfork: $baseline_hardfork
        feature_hardfork: $feature_hardfork
        baseline_removed_args: $baseline_removed_args
        feature_removed_args: $feature_removed_args
    } | to json | save -f $"($results_dir)/summary-config.json"
}

def e2e-generate-summary [results_dir: string] {
    let config_path = $"($results_dir)/summary-config.json"
    if not ($config_path | path exists) {
        print $"Error: summary config not found: ($config_path)"
        exit 1
    }

    let config = (open $config_path)
    let baseline_hardfork = ($config | get -o baseline_hardfork | default "")
    let feature_hardfork = ($config | get -o feature_hardfork | default "")
    let summary_warmup_blocks = ($config | get -o summary_warmup_blocks | default 0 | into int)
    let run_side = ($config | get -o run_side | default "comparison")
    generate-summary $results_dir $config.baseline_label $config.feature_label ($config.bloat_mib | into int) $config.preset ($config.tps | into int) ($config.duration | into int) --benchmark-id ($config.benchmark_id | default "") --reference-epoch ($config.reference_epoch | default 0 | into int) --baseline-hardfork $baseline_hardfork --feature-hardfork $feature_hardfork --summary-warmup-blocks $summary_warmup_blocks
    let summary_path = $"($results_dir)/summary.json"
    if ($summary_path | path exists) {
        let baseline_removed_args = ($config | get -o baseline_removed_args | default "")
        let feature_removed_args = ($config | get -o feature_removed_args | default "")
        let token_count = ($config | get -o token_count | default 4 | into int)
        let summary = (open $summary_path)
        let summary = ($summary | upsert config ($summary.config | upsert token_count $token_count | upsert run_side $run_side | upsert baseline_removed_args $baseline_removed_args | upsert feature_removed_args $feature_removed_args))
        $summary | to json | save -f $summary_path
    }

    with-env {
        GITHUB_TOKEN: ""
        CLICKHOUSE_URL: ""
        CLICKHOUSE_USER: ""
        CLICKHOUSE_PASSWORD: ""
        BENCH_VICTORIAMETRICS_URL: ""
        SLACK_BENCH_BOT_TOKEN: ""
        SLACK_BENCH_CHANNEL: ""
    } {
        ^node .github/scripts/bench-e2e-classify.js $results_dir
        ^node .github/scripts/bench-log-summary.js $results_dir e2e summary.md
    }
}

def "main summarize" [
    results_dir: string                                # Results directory from an e2e run
] {
    e2e-generate-summary $results_dir
}

def "main render-txgen-spec" [
    --preset: string = ""                              # Txgen preset name or scenario expression
    --out-dir: string = ""                             # Directory for rendered scenario specs
] {
    let spec = (txgen-resolve-bench-spec $preset $out_dir)
    print $spec.spec_path
}

# Run the e2e sequence on one runner.
def "main e2e" [
    --baseline: string                                  # Baseline git SHA/ref
    --feature: string                                   # Feature git SHA/ref
    --preset: string = ""                               # Txgen preset name
    --preset-path: string = ""                          # Pre-rendered txgen preset path
    --tps: int = 50000                                  # Target TPS
    --duration: int = 90                                # Duration in seconds
    --summary-warmup-blocks: int = 5                    # Initial blocks per run excluded from summary metrics
    --accounts: int = 1000                              # Number of accounts
    --max-concurrent-requests: int = 500                # Max concurrent requests
    --bloat: int = $E2E_DEFAULT_BLOAT                   # State bloat snapshot size in GiB: 0, 1, 10, or 100
    --token-count: int = 4                         # Number of TIP20 tokens to use in txgen presets
    --gas-limit: string = $E2E_GAS_LIMIT                # Builder gas limit
    --general-gas-limit: string = $E2E_GAS_LIMIT        # General (non-payment) gas limit override
    --force-bloat                                      # Regenerate and promote both local e2e snapshots
    --init-only                                         # Refresh snapshots and exit without running benchmark phases
    --profile: string = $DEFAULT_PROFILE                # Cargo build profile
    --features: string = ""                             # Additional Cargo features appended to the e2e defaults
    --baseline-features: string = ""                    # Additional Cargo features for baseline build (defaults to --features)
    --feature-features: string = ""                     # Additional Cargo features for feature build (defaults to --features)
    --no-default-features                               # Disable Cargo default features
    --lifecycle                                         # Capture privacy-filtered block lifecycle artifacts on both validators
    --lifecycle-scheduler                               # Opt-in registered-thread kernel fault diagnostic
    --lifecycle-prewarm-cpu: string = "disabled"          # Matched selected-call CPU observer: disabled or compare
    --lifecycle-detail: string = "full"                  # Capture detail: full, milestones, or compare (requires --lifecycle)
    --samply                                            # Profile validators with samply
    --samply-args: string = ""                          # Additional samply arguments
    --tracy: string = "off"                             # Tracy profiling: off, tracy
    --tracy-filter: string = "debug"                    # Tracy tracing filter level
    --tracy-seconds: int = 0                            # Tracy capture duration limit in seconds; 0 captures until stopped
    --tracy-offset: int = 0                             # Seconds to wait before starting tracy capture
    --tracing-otlp: string = ""                         # OTLP endpoint for tracing (auto-derived from GRAFANA_TEMPO/TEMPO_TELEMETRY_URL)
    --victoriametrics-url: string = ""                  # VictoriaMetrics base URL for txgen metric sample import
    --clickhouse-url: string = ""                       # ClickHouse HTTP endpoint for txgen result upload
    --clickhouse-run: string = "feature-1"              # Run label allowed to use the ClickHouse reporter; empty = every run
    --runner-metrics-url: string = $E2E_RUNNER_METRICS_URL # Runner node-exporter metrics URL (empty disables runner metrics)
    --run-pairs: int = 3                                # Number of baseline/feature run pairs
    --run-side: string = "comparison"                   # Phases to run: comparison, feature, or baseline
    --run-type: string = ""                             # Run type label (dispatch, nightly, release)
    --baseline-args: string = ""                        # Additional node args for baseline phases
    --feature-args: string = ""                         # Additional node args for feature phases
    --bench-args: string = ""                           # Additional txgen generate arguments
    --baseline-env: string = ""                         # Environment vars for baseline node phases
    --feature-env: string = ""                          # Environment vars for feature node phases
    --bench-env: string = ""                            # Environment vars for the sender process
    --baseline-name: string = ""                         # Baseline display name for summary
    --feature-name: string = ""                          # Feature display name for summary
    --baseline-hardfork: string = ""                     # Latest active hardfork for baseline phases
    --feature-hardfork: string = ""                      # Latest active hardfork for feature phases
    --tune                                              # Apply system tuning
    --loud                                              # Show node debug logs
    --prebuilt-directory: string = ""                     # Verified job-owned portable bundle; no compilation
    --no-cache                                           # Skip binary cache
    --valscope-static-report                             # Generate static ValScope reports under the results directory
    --valscope-dir: string = "../valscope"               # Path to the ValScope checkout
    --skip-summary                                       # Leave summary generation to a later workflow step
] {
    let prebuilt = $prebuilt_directory != ""
    if $prebuilt != (($env.BENCH_BINARY_MODE? | default "build_v1") == "prebuilt_v1") {
        error make {msg: "Prebuilt workflow and binary route must agree"}
    }
    let selective_retry_mode = ($env.BENCH_SELECTIVE_RETRY_TRIAL? | default "")
    let selective_retry_trial = $selective_retry_mode == "true"
    if $selective_retry_mode not-in ["" "true"] or ($selective_retry_trial and (
        not $prebuilt or ($env.BENCH_READ_READINESS? | default "false") != "false" or
        ($baseline | default "") !~ '^[0-9a-f]{40}$' or $baseline != $feature or
        $baseline_args != "--engine.storage-worker-count 32 --engine.account-worker-count 32 --engine.prewarming-threads 16" or
        $feature_args != $baseline_args or $baseline_hardfork != $feature_hardfork or
        $run_side != "comparison" or $run_pairs != 6 or $duration != 15 or
        $preset != "default" or $bloat != 100 or $tps != 15000 or $accounts != 1000 or
        $max_concurrent_requests != 100 or $token_count != 4 or
        $baseline_env != "" or $feature_env != "RETH_EXPERIMENTAL_SELECTIVE_STORAGE_RETRIES=1"
    )) {
        error make {msg: "Selective storage retry trial requires identical immutable inputs and the exact feature toggle"}
    }
    if $selective_retry_trial {
        hide-env -i RETH_EXPERIMENTAL_SELECTIVE_STORAGE_RETRIES TEMPO_READ_READINESS
    }
    if $prebuilt and (not $lifecycle or $profile != "profiling" or not $no_default_features or $force_bloat or $init_only or $no_cache or $samply or $tracy != "off" or $valscope_static_report or $baseline_env != "" or ($feature_env != "" and not $selective_retry_trial) or $bench_env != "" or $baseline_features != "" or $feature_features != "") {
        error make {msg: "Unsupported prebuilt execution inputs"}
    }
    let readiness_mode = ($env.BENCH_READ_READINESS? | default "false")
    if $readiness_mode not-in ["false" "true"] or ($readiness_mode == "true" and (
        $selective_retry_trial or
        not $prebuilt or not $lifecycle or $lifecycle_detail != "milestones" or
        ($run_side != "feature" and not $selective_retry_trial) or
        ($selective_retry_trial and $run_pairs != 6) or
        ((not $selective_retry_trial) and $run_pairs != 1) or
        ($selective_retry_trial and $duration != 15) or ((not $selective_retry_trial) and $duration != 30) or
        $lifecycle_scheduler or $lifecycle_prewarm_cpu != "disabled"
    )) {
        error make {msg: "Read-readiness requires a 30-second feature diagnostic and is disabled for the selective retry trial"}
    }
    if $lifecycle_scheduler and (not $lifecycle or $lifecycle_detail != "full" or $lifecycle_prewarm_cpu != "disabled" or $samply or $tracy != "off") {
        error make {msg: "Kernel fault diagnostic requires full lifecycle and no other observer"}
    }
    if $lifecycle_prewarm_cpu not-in ["disabled" "compare"] or ($lifecycle_prewarm_cpu == "compare" and (not $lifecycle or $lifecycle_detail != "milestones" or $run_side != "comparison")) {
        error make {msg: "Prewarm CPU comparison requires milestone lifecycle and both sides"}
    }
    if $lifecycle_prewarm_cpu == "compare" and (
        ($baseline | default "") !~ '^[0-9a-f]{40}$' or $baseline != $feature or
        $baseline_args != $feature_args or $baseline_features != $feature_features or
        $baseline_hardfork != $feature_hardfork or
        $bench_env != "" or $baseline_env != "" or $feature_env != ""
    ) {
        error make {msg: "Prewarm CPU comparison requires identical immutable refs and node inputs without environment overrides"}
    }
    if $lifecycle_detail not-in ["full" "milestones" "compare"] or (not $lifecycle and $lifecycle_detail != "full") {
        error make {msg: "Lifecycle detail must be full, milestones or compare; reduced modes require --lifecycle"}
    }
    if $lifecycle_detail == "compare" and $run_side != "comparison" {
        error make {msg: "Comparing lifecycle detail requires baseline/feature comparison"}
    }
    if $lifecycle {
        if $samply or $tracy != "off" or $valscope_static_report {
            error make {msg: "Lifecycle mode requires other profilers and ValScope export to be disabled"}
        }
        hide-env -i TEMPO_TELEMETRY_URL GRAFANA_TEMPO OTEL_EXPORTER_OTLP_TRACES_ENDPOINT OTEL_EXPORTER_OTLP_HEADERS CLICKHOUSE_URL CLICKHOUSE_USER CLICKHOUSE_PASSWORD BENCH_VICTORIAMETRICS_URL
    }
    let preset_spec = if $preset_path == "" {
        txgen-resolve-bench-spec $preset
    } else {
        {
            kind: pre_rendered
            scenario_id: $preset
            spec_path: ($preset_path | path expand)
            rendered: true
        }
    }
    let preset_path = $preset_spec.spec_path
    if not ($preset_path | path exists) {
        print $"Error: txgen preset file not found: ($preset_path)"
        exit 1
    }
    txgen-validate-bench-args $bench_args
    let general_gas_limit = if $general_gas_limit == "" and (txgen-spec-has-keychain-setup $preset_path) {
        $gas_limit
    } else {
        $general_gas_limit
    }
    if $tracy not-in ["off" "tracy"] {
        print $"Error: --tracy must be one of: off, tracy \(got '($tracy)'\)"
        exit 1
    }
    if $run_pairs <= 0 {
        print "Error: --run-pairs must be a positive integer"
        exit 1
    }
    if $run_side not-in ["comparison" "feature" "baseline"] {
        print $"Error: --run-side must be one of: comparison, feature, baseline \(got '($run_side)'\)"
        exit 1
    }
    if $summary_warmup_blocks < 0 {
        print "Error: --summary-warmup-blocks must be non-negative"
        exit 1
    }
    let bloat_mib = (e2e-bloat-gib-to-mib $bloat)
    e2e-validate-token-count $token_count
    if $init_only and not $force_bloat {
        print "Error: --init-only requires --force-bloat"
        exit 1
    }
    if $tracy != "off" and ((which tracy-capture | length) == 0) {
        print "Error: tracy-capture not found. Install tracy and ensure tracy-capture is in PATH."
        exit 1
    }
    let hardfork_mode = $baseline_hardfork != "" or $feature_hardfork != ""
    if $hardfork_mode and ($baseline_hardfork == "" or $feature_hardfork == "") {
        print "Error: --baseline-hardfork and --feature-hardfork must both be provided"
        exit 1
    }
    let baseline_hardfork_name = if $hardfork_mode { normalize-hardfork $baseline_hardfork } else { "" }
    let feature_hardfork_name = if $hardfork_mode { normalize-hardfork $feature_hardfork } else { "" }
    let snapshot_state_hardfork = if $hardfork_mode {
        highest-hardfork [$baseline_hardfork_name $feature_hardfork_name]
    } else {
        latest-tempo-hardfork
    }
    let snapshot_hardfork_args = (hardfork-to-genesis-args $snapshot_state_hardfork)

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
    let benchmark_id = ($env | get --optional BENCHMARK_ID)
    let benchmark_id = if $benchmark_id == null or ($benchmark_id | str trim) == "" {
        let run_id = ($env | get --optional GITHUB_RUN_ID)
        if $run_id == null or ($run_id | str trim) == "" {
            print "Error: BENCHMARK_ID or GITHUB_RUN_ID must be set for e2e benchmarks"
            exit 1
        }
        $"bench-e2e-($run_id)"
    } else {
        $benchmark_id
    }
    let reference_epoch = (($run_started_at | into int) / 1_000_000_000 | into int)
    let gas_limit_args = if $gas_limit != "" { ["--gas-limit" $gas_limit] } else { [] }
    let general_gas_limit_args = if $general_gas_limit != "" { ["--general-gas-limit" $general_gas_limit] } else { [] }
    let tracing_otlp = if $lifecycle { "" } else { derive-tracing-otlp $tracing_otlp }
    if $tracing_otlp != "" {
        $env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT = $tracing_otlp
    }

    validate-schelk-state $E2E_A_STATE_PATH $E2E_B_STATE_PATH
    # Reject missing snapshot metadata before process cleanup or restoration.
    # Recheck after restoration below; neither check may fall back to generation.
    if $prebuilt {
        prebuilt-mount-existing-snapshots $force_bloat $init_only
        prebuilt-require-snapshot true (e2e-snapshots-ready $a_db $b_db) $force_bloat $init_only
    }
    if ($env.BENCH_RUN_CLEANUP? | default "") == "true" {
        if not (has-schelk) { error make {msg: "Runner cleanup requires schelk snapshots"} }
        touch .bench-snapshot-dirty
    }
    cleanup-local-e2e-processes

    bench-restore-at $E2E_A_STATE_PATH $E2E_A_MOUNT $a_db
    bench-restore-at $E2E_B_STATE_PATH $E2E_B_MOUNT $b_db

    let snapshots_ready = (e2e-snapshots-ready $a_db $b_db)
    prebuilt-require-snapshot $prebuilt $snapshots_ready $force_bloat $init_only
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
        mark-schelk-dirty-at $E2E_A_STATE_PATH
        mark-schelk-dirty-at $E2E_B_STATE_PATH
        if ($init_dir | path exists) { rm -rf $init_dir }
        mkdir $init_dir
        if ($E2E_BLOAT_TMP_DIR | path exists) { rm -rf $E2E_BLOAT_TMP_DIR }
        mkdir $E2E_BLOAT_TMP_DIR

        let snapshot_features = (merge-e2e-features $DEFAULT_FEATURES $features)
        if $lifecycle {
            lifecycle-require-disk "before snapshot build, workspace" "." 65536
            lifecycle-require-disk "before snapshot build, runner root" "/" 65536
        }
        build-tempo --no-default-features=$no_default_features ["tempo"] $profile $snapshot_features
        let tempo_bin = if $profile == "dev" { "./target/debug/tempo" } else { $"./target/($profile)/tempo" }
        let genesis_accounts = ([$accounts 3] | math max) + 1
        print $"Generating local e2e localnet config for validators: ($E2E_VALIDATORS)"
        cargo run -p tempo-xtask --profile $profile -- generate-localnet -o $init_dir --accounts $genesis_accounts --validators $E2E_VALIDATORS --seed $E2E_SEED --force ...$gas_limit_args ...$general_gas_limit_args ...$snapshot_hardfork_args

        let trusted_peers = (trusted-peers-from-localnet $init_dir)
        if $trusted_peers == "" {
            print "Error: generated localnet did not produce trusted peers"
            exit 1
        }
        if $bloat_mib > 0 {
            print "Cleaning restored e2e datadirs before bloat snapshot rebuild..."
            bench-clean-datadir $a_db
            bench-clean-datadir $b_db
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
            general_gas_limit: $general_gas_limit
            dkg_in_genesis: true
            topology: "single-runner"
            state_hardfork: $snapshot_state_hardfork
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
    let hardfork_genesis_dir = $"($LOCALNET_DIR)/e2e-hardfork-genesis"
    let baseline_genesis_path = if $hardfork_mode { $"($hardfork_genesis_dir)/genesis-baseline.json" } else { $genesis_path }
    let feature_genesis_path = if $hardfork_mode { $"($hardfork_genesis_dir)/genesis-feature.json" } else { $genesis_path }
    if $hardfork_mode {
        if ($hardfork_genesis_dir | path exists) { rm -rf $hardfork_genesis_dir }
        mkdir $hardfork_genesis_dir
        e2e-synthesize-genesis $genesis_path $baseline_genesis_path $baseline_hardfork_name $gas_limit $general_gas_limit
        e2e-synthesize-genesis $genesis_path $feature_genesis_path $feature_hardfork_name $gas_limit $general_gas_limit
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
    cp $preset_path $"($results_dir)/txgen-spec.yml"

    git worktree prune
    mkdir $BENCH_WORKTREES_DIR
    let baseline_wt = $"($BENCH_WORKTREES_DIR)/e2e-local-baseline"
    let feature_wt = $"($BENCH_WORKTREES_DIR)/e2e-local-feature"
    let regenesis_needed = $hardfork_mode or $gas_limit != "" or $general_gas_limit != ""
    let needs_baseline = $run_side in ["comparison" "baseline"]
    let needs_feature = $run_side in ["comparison" "feature"]
    mut worktrees = []
    if $needs_baseline {
        $worktrees = ($worktrees | append $baseline_wt)
    }
    if $needs_feature {
        $worktrees = ($worktrees | append $feature_wt)
    }
    for wt in $worktrees {
        if ($wt | path exists) {
            print $"Removing stale local e2e worktree: ($wt)"
            try { git worktree remove --force $wt } catch { rm -rf $wt }
        }
    }
    mut created_build_worktrees = []
    if $needs_baseline {
        git worktree add $baseline_wt $baseline
        if $env.LAST_EXIT_CODE != 0 { error make { msg: "Baseline worktree creation failed" } }
        if $lifecycle {
            $created_build_worktrees = ($created_build_worktrees | append (e2e-record-worktree-owner $baseline_wt))
        }
    }
    if $needs_feature {
        git worktree add $feature_wt $feature
        if $env.LAST_EXIT_CODE != 0 { error make { msg: "Feature worktree creation failed" } }
        if $lifecycle {
            $created_build_worktrees = ($created_build_worktrees | append (e2e-record-worktree-owner $feature_wt))
        }
    }

    let owned_build_worktrees = $created_build_worktrees

    let global_build_features = (merge-e2e-features $DEFAULT_FEATURES $features)
    let baseline_build_features = if $baseline_features != "" { merge-e2e-features $global_build_features $baseline_features } else { $global_build_features }
    let feature_build_features = if $feature_features != "" { merge-e2e-features $global_build_features $feature_features } else { $global_build_features }
    let baseline_tbc = (tracy-build-config $baseline_build_features $tracy)
    let feature_tbc = (tracy-build-config $feature_build_features $tracy)
    let effective_no_cache = $no_cache or ($tracy != "off")
    # Independent target directories allow ordinary builds to run in parallel.
    # Lifecycle builds run sequentially and trim each target to bound peak disk use.
    mut builds = []
    if $needs_baseline {
        $builds = ($builds | append { wt: $baseline_wt, ref_name: $baseline, sha: $baseline, label: "baseline", features: $baseline_tbc.features, extra_rustflags: $baseline_tbc.extra_rustflags, bench_features: $baseline_build_features })
    }
    if $needs_feature {
        $builds = ($builds | append { wt: $feature_wt, ref_name: $feature, sha: $feature, label: "feature", features: $feature_tbc.features, extra_rustflags: $feature_tbc.extra_rustflags, bench_features: $feature_build_features })
    }
    let build_binary = { |b|
        if $prebuilt {
            prebuilt-select $prebuilt_directory $b.label $b.sha $b.features $profile $E2E_A_CPUS $E2E_B_CPUS | ignore
        } else if $effective_no_cache {
            build-in-worktree --lifecycle-build=$lifecycle --no-cache --no-default-features=$no_default_features --extra-rustflags $b.extra_rustflags --bench-features $b.bench_features $b.wt $b.ref_name $profile $b.features $b.sha
        } else {
            build-in-worktree --lifecycle-build=$lifecycle --no-default-features=$no_default_features $b.wt $b.ref_name $profile $b.features $b.sha
        }
    }
    let reuse_baseline_binary = (not $prebuilt) and (lifecycle-reuse-build $lifecycle $effective_no_cache $builds)
    let selected_builds = if $reuse_baseline_binary { $builds | take 1 } else { $builds }
    if $lifecycle {
        try {
            for build in $selected_builds {
                do $build_binary $build
                if not $prebuilt { lifecycle-trim-worktree $build.wt $profile }
            }
        } catch { |build_error|
            e2e-cleanup-owned-worktrees $owned_build_worktrees
            error make $build_error.raw
        }
    } else {
        $builds | par-each { |build| do $build_binary $build } | ignore
    }
    let baseline_tempo = if $needs_baseline { if $prebuilt { (prebuilt-select $prebuilt_directory "baseline" $baseline $baseline_tbc.features $profile $E2E_A_CPUS $E2E_B_CPUS).tempo } else { worktree-bin $baseline_wt $profile "tempo" } } else { "" }
    let feature_tempo = if $reuse_baseline_binary { $baseline_tempo } else if $needs_feature { if $prebuilt { (prebuilt-select $prebuilt_directory "feature" $feature $feature_tbc.features $profile $E2E_A_CPUS $E2E_B_CPUS).tempo } else { worktree-bin $feature_wt $profile "tempo" } } else { "" }
    let regenesis_tempo = if $regenesis_needed {
        if $needs_feature { $feature_tempo } else { $baseline_tempo }
    } else { "" }
    let baseline_arg_filter = if $needs_baseline { supported-node-arg-filter $baseline_tempo $E2E_LOCAL_RETH_ARGS } else { { supported: [], removed: [] } }
    let feature_arg_filter = if $needs_feature { supported-node-arg-filter $feature_tempo $E2E_LOCAL_RETH_ARGS } else { { supported: [], removed: [] } }
    let removed_arg_config = $"(format-removed-node-arg-config 'baseline' $baseline_arg_filter.removed)(format-removed-node-arg-config 'feature' $feature_arg_filter.removed)"
    if $removed_arg_config != "" {
        let current_config = ($env | get -o BENCH_CONFIG | default "")
        let updated_config = $"($current_config)($removed_arg_config)"
        $env.BENCH_CONFIG = $updated_config
        let github_env = ($env | get -o GITHUB_ENV | default "")
        if $github_env != "" {
            $"BENCH_CONFIG=($updated_config)\n" | save --append $github_env
        }
    }
    let txgen = txgen-resolve-binaries
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
        preset_path: $preset_path
        tps: $tps
        duration: $duration
        accounts: $accounts
        max_concurrent_requests: $max_concurrent_requests
        bloat: $bloat_mib
        token_count: $token_count
        txgen: $txgen
        results_dir: $results_dir
        profile: $profile
        prebuilt_directory: $prebuilt_directory
        baseline_build_features: $baseline_tbc.features
        feature_build_features: $feature_tbc.features
        samply: $samply
        samply_args: $samply_args_list
        lifecycle: $lifecycle
        lifecycle_detail: $lifecycle_detail
        lifecycle_scheduler: $lifecycle_scheduler
        lifecycle_prewarm_cpu: $lifecycle_prewarm_cpu
        summary_warmup_blocks: $summary_warmup_blocks
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
        victoriametrics_url: (if $lifecycle { "" } else { $victoriametrics_url })
        clickhouse_url: (if $lifecycle { "" } else { $clickhouse_url })
        clickhouse_run: $clickhouse_run
        runner_metrics_url: $runner_metrics_url
        run_type: $run_type
        benchmark_id: $benchmark_id
        reference_epoch: $reference_epoch
        tune: $tune
        loud: $loud
        gas_limit: $gas_limit
        general_gas_limit: $general_gas_limit
        baseline_local_reth_args: $baseline_arg_filter.supported
        feature_local_reth_args: $feature_arg_filter.supported
        regenesis_tempo: $regenesis_tempo
        tracing_otlp: $tracing_otlp
    }

    if $lifecycle_prewarm_cpu == "compare" {
        let equality = (^cmp --silent $baseline_tempo $feature_tempo | complete)
        if $equality.exit_code != 0 {
            error make {msg: "Prewarm CPU comparison requires identical binary bytes"}
        }
    }
    let baseline_base_label = if $baseline_name != "" { $baseline_name } else { $baseline }
    let feature_base_label = if $feature_name != "" { $feature_name } else { $feature }

    mut runs = []
    let run_plan = (lifecycle-run-plan (e2e-run-sides $run_pairs $run_side) $lifecycle_detail)
    for planned in $run_plan {
        if $planned.side == "baseline" {
            $runs = ($runs | append {
                phase: $planned.phase
                side: $planned.side
                lifecycle_detail: $planned.detail
                ref: $baseline
                ref_label: $baseline_base_label
                tempo: $baseline_tempo
                genesis: $baseline_genesis_path
                hardfork: $baseline_hardfork_name
            })
        } else {
            $runs = ($runs | append {
                phase: $planned.phase
                side: $planned.side
                lifecycle_detail: $planned.detail
                ref: $feature
                ref_label: $feature_base_label
                tempo: $feature_tempo
                genesis: $feature_genesis_path
                hardfork: $feature_hardfork_name
            })
        }
    }
    let valid_run_labels = ($runs | get phase)
    if not $lifecycle and $clickhouse_run != "" and $clickhouse_run not-in $valid_run_labels {
        print $"Error: --clickhouse-run must be one of: ($valid_run_labels | str join ', ') \(got '($clickhouse_run)'\)"
        exit 1
    }
    $valid_run_labels | str join "\n" | save -f $"($results_dir)/run-order.txt"
    e2e-write-summary-config $results_dir $baseline_base_label $feature_base_label $bloat_mib $token_count $preset $tps $duration $benchmark_id $reference_epoch $summary_warmup_blocks $run_side $baseline_hardfork_name $feature_hardfork_name (removed-node-args-label $baseline_arg_filter.removed) (removed-node-args-label $feature_arg_filter.removed)
    let num_phases = ($runs | length)
    mut e2e_exit = 0
    for idx in 0..<$num_phases {
        let run = ($runs | get $idx)
        bench-update-pr-status $"Running benchmark phase ($run.phase) \(($idx + 1)/($num_phases)\)..."
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
            let tracy_urls = (upload-tracy-profile $profile $run.phase $run.ref)
            if $tracy_urls != null {
                $tracy_urls.viewer_url | save -f $"($results_dir)/tracy-($run.phase)-url.txt"
                $tracy_urls.profile_url | save -f $"($results_dir)/tracy-($run.phase)-profile-url.txt"
            }
        }
    }

    if $e2e_exit == 0 {
        if not $skip_summary {
            e2e-generate-summary $results_dir
        }
        if $valscope_static_report {
            build-valscope-static-reports $results_dir $benchmark_id $valscope_dir
        }
    }

    if $needs_baseline {
        try { git worktree remove --force $baseline_wt } catch { }
    }
    if $needs_feature {
        try { git worktree remove --force $feature_wt } catch { }
    }
    cleanup-local-e2e-processes
    bench-restore-at $E2E_A_STATE_PATH $E2E_A_MOUNT $a_db
    bench-restore-at $E2E_B_STATE_PATH $E2E_B_MOUNT $b_db
    if $e2e_exit != 0 {
        exit $e2e_exit
    }
}
