const TXGEN_HELPER_ACCOUNT_MNEMONIC = "test test test test test test test test test test test junk"
const TXGEN_HELPER_DEFAULT_SEED = 99
const TXGEN_HELPER_SCRAPE_INTERVAL_MS = 200
const TXGEN_HELPER_FUND_DRAIN_TIMEOUT_SECS = 120
const TXGEN_HELPER_PRESETS_DIR = "contrib/bench/txgen/presets"
const TXGEN_HELPER_TIP20_PIECES_DIR = "contrib/bench/txgen/presets/tip20"
const TXGEN_HELPER_TIP20_SCENARIO_PRESETS = ["default" "tip20"]
const TXGEN_HELPER_ALWAYS_FUND_PRESETS = ["dex"]
const TXGEN_HELPER_EXISTING_RECIPIENTS_START = 10000
const TXGEN_HELPER_KEYCHAIN_ACCESS_KEYS_START = 100000
const TXGEN_HELPER_KEYCHAIN_AUTHORIZE_SETUP_GAS_LIMIT = 20000000
const TXGEN_HELPER_KEY_AUTHORIZATION_MIN_GAS_LIMIT = 3000000
const TXGEN_HELPER_KEY_AUTHORIZATION_BASE_GAS_LIMIT = 2000000
const TXGEN_HELPER_KEY_AUTHORIZATION_PER_TOKEN_GAS_LIMIT = 2000000
const TXGEN_HELPER_KEYCHAIN_LIMIT_AMOUNT = "1000000000000000000000000000000000000"
const TXGEN_HELPER_TIP20_TRANSFER_SELECTOR = "0xa9059cbb"
const TXGEN_HELPER_FEE_AMM_LIQUIDITY_AMOUNT = 10000000000
const TXGEN_HELPER_FEE_AMM_2D_LIQUIDITY_AMOUNT = 10000000000000
const TXGEN_HELPER_DEFAULT_RENDERED_SPECS_DIR = ".bench-tmp/txgen-specs"

def txgen-tip20-default-scenario [] {
    {
        workload: "tip20"
        recipient: "users"
        auth: "direct"
        nonce: "expiring"
        fee_token: "pathusd"
    }
}

def txgen-tip20-scenario-alias [name: string] {
    if $name in ["default" "tip20"] {
        return (txgen-tip20-default-scenario)
    }

    # Legacy preset names remain accepted, but active workflows should use scenario strings.
    if $name == "tip20_random_recipients" {
        return ((txgen-tip20-default-scenario) | merge { recipient: "random", fee_token: "any_tip20" })
    }
    if $name == "tip20_existing_recipients" {
        return ((txgen-tip20-default-scenario) | merge { recipient: "existing", fee_token: "any_tip20" })
    }
    if $name == "tip20_keychain" {
        return ((txgen-tip20-default-scenario) | merge { auth: "keychain", fee_token: "any_tip20" })
    }
    if $name == "tip20_keychain_random_recipients" {
        return ((txgen-tip20-default-scenario) | merge { recipient: "random", auth: "keychain", fee_token: "any_tip20" })
    }
    if $name == "tip20_keychain_existing_recipients" {
        return ((txgen-tip20-default-scenario) | merge { recipient: "existing", auth: "keychain", fee_token: "any_tip20" })
    }
    if $name == "tip20_key_authorization" {
        return ((txgen-tip20-default-scenario) | merge { auth: "key_authorization", fee_token: "any_tip20" })
    }
    if $name == "tip20_protocol_nonces" {
        return ((txgen-tip20-default-scenario) | merge { recipient: "existing", nonce: "protocol", fee_token: "any_tip20" })
    }
    if $name == "tip20_2d_nonces" {
        return ((txgen-tip20-default-scenario) | merge { recipient: "existing", nonce: "2d", fee_token: "any_tip20" })
    }

    null
}

def txgen-scenario-field-name [field: string] {
    $field | str trim | str replace -a "-" "_"
}

def txgen-parse-tip20-scenario [preset: string] {
    let preset_name = ($preset | str trim)
    let alias = (txgen-tip20-scenario-alias $preset_name)
    if $alias != null {
        return $alias
    }

    if not ($preset_name | str starts-with "tip20:") {
        return null
    }

    let body = ($preset_name | str replace --regex '^tip20:' '')
    mut scenario = (txgen-tip20-default-scenario)
    if ($body | str trim) != "" {
        for raw_part in ($body | split row "," | each { |part| $part | str trim } | where { |part| $part != "" }) {
            let kv = ($raw_part | split row "=")
            if ($kv | length) != 2 {
                error make { msg: $"invalid tip20 scenario component '($raw_part)'; expected key=value" }
            }

            let key = (txgen-scenario-field-name ($kv | get 0))
            let value = (($kv | get 1) | str trim)
            if $key not-in ["recipient" "auth" "nonce" "fee_token"] {
                error make { msg: $"unknown tip20 scenario field '($key)'" }
            }
            if $value == "" {
                error make { msg: $"tip20 scenario field '($key)' must not be empty" }
            }

            $scenario = ($scenario | upsert $key $value)
        }
    }

    txgen-validate-tip20-scenario $scenario
    $scenario
}

def txgen-ensure-one-of [field: string, value: string, allowed: list<string>] {
    if $value not-in $allowed {
        error make { msg: $"invalid ($field)=($value); expected one of: ($allowed | str join ', ')" }
    }
}

def txgen-validate-tip20-scenario [scenario: record] {
    txgen-ensure-one-of "recipient" $scenario.recipient ["users" "random" "existing"]
    txgen-ensure-one-of "auth" $scenario.auth ["direct" "keychain" "key_authorization"]
    txgen-ensure-one-of "nonce" $scenario.nonce ["expiring" "protocol" "2d"]
    txgen-ensure-one-of "fee_token" $scenario.fee_token ["pathusd" "any_tip20"]

    if $scenario.auth != "direct" and $scenario.nonce != "expiring" {
        error make { msg: $"auth=($scenario.auth) currently supports only nonce=expiring" }
    }
}

def txgen-tip20-scenario-id [scenario: record] {
    $"tip20:recipient=($scenario.recipient),auth=($scenario.auth),nonce=($scenario.nonce),fee_token=($scenario.fee_token)"
}

def txgen-scenario-file-stem [scenario_id: string] {
    $scenario_id
        | str replace -a ":" "-"
        | str replace -a "," "-"
        | str replace -a "=" "-"
        | str replace -a "/" "-"
}

def txgen-tip20-uses-fee-amm [scenario: record] {
    $scenario.fee_token == "any_tip20"
}

def txgen-tip20-pieces-dir [] {
    [ (txgen-repo-root) $TXGEN_HELPER_TIP20_PIECES_DIR ] | path join
}

def txgen-tip20-piece-path [piece: string] {
    [ (txgen-tip20-pieces-dir) $"($piece).yml" ] | path join
}

def txgen-tip20-piece-path-checked [piece: string] {
    let piece_path = (txgen-tip20-piece-path $piece)
    if not ($piece_path | path exists) {
        error make { msg: $"missing tip20 txgen piece: ($piece)" }
    }

    $piece_path
}

def txgen-tip20-piece-name [dimension: string, value: string] {
    $"($dimension)-($value | str replace -a '_' '-')"
}

def txgen-tip20-scenario-pieces [scenario: record] {
    mut pieces = [
        (txgen-tip20-piece-name "recipient" $scenario.recipient)
        (txgen-tip20-piece-name "fee-token" $scenario.fee_token)
    ]

    if (txgen-tip20-uses-fee-amm $scenario) {
        $pieces = ($pieces | append "fee-amm-liquidity")
    }

    $pieces = ($pieces | append (txgen-tip20-piece-name "auth" $scenario.auth))
    $pieces = ($pieces | append (txgen-tip20-piece-name "nonce" $scenario.nonce))
    $pieces
}

# Write a scenario spec that lists its pieces via txgen's native `include`
# directive; txgen resolves the merge/append sections in each piece itself.
def txgen-render-tip20-spec [scenario: record, out_dir: string] {
    let out_dir = if ($out_dir | str trim) == "" {
        [ (txgen-repo-root) $TXGEN_HELPER_DEFAULT_RENDERED_SPECS_DIR ] | path join
    } else {
        $out_dir | path expand
    }
    mkdir $out_dir

    let uses_fee_amm = (txgen-tip20-uses-fee-amm $scenario)
    let pieces = (["base"] | append (txgen-tip20-scenario-pieces $scenario))
    let piece_paths = ($pieces | each { |piece| txgen-tip20-piece-path-checked $piece })

    let scenario_id = (txgen-tip20-scenario-id $scenario)
    let spec_path = ([ $out_dir $"(txgen-scenario-file-stem $scenario_id).yml" ] | path join)
    [$"# ($scenario_id)" "include:"]
        | append ($piece_paths | each { |piece_path| $"  - ($piece_path)" })
        | append ""
        | str join "\n"
        | save -f $spec_path

    {
        kind: generated
        scenario_id: $scenario_id
        spec_path: ($spec_path | path expand)
        rendered: true
        requires_existing_recipients: ($scenario.recipient == "existing")
        requires_keychain_setup: ($scenario.auth == "keychain")
        uses_fee_amm: $uses_fee_amm
    }
}

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

def txgen-keychain-tip20-limits [token_count: int] {
    if $token_count <= 0 {
        error make { msg: "keychain TIP20 token count must be greater than zero" }
    }

    0..<$token_count
        | each { |id|
            {
                token: (txgen-tip20-token-address $id)
                amount: $TXGEN_HELPER_KEYCHAIN_LIMIT_AMOUNT
                period: 0
            }
        }
        | to json -r
}

def txgen-keychain-tip20-allowed-calls [token_count: int] {
    if $token_count <= 0 {
        error make { msg: "keychain TIP20 token count must be greater than zero" }
    }

    0..<$token_count
        | each { |id|
            {
                target: (txgen-tip20-token-address $id)
                selectors: [
                    {
                        selector: $TXGEN_HELPER_TIP20_TRANSFER_SELECTOR
                        recipients: []
                    }
                ]
            }
        }
        | to json -r
}

def txgen-key-authorization-gas-limit [token_count: int] {
    if $token_count <= 0 {
        error make { msg: "key authorization token count must be greater than zero" }
    }

    if $token_count == 1 {
        return ($TXGEN_HELPER_KEY_AUTHORIZATION_MIN_GAS_LIMIT | into string)
    }

    ($TXGEN_HELPER_KEY_AUTHORIZATION_BASE_GAS_LIMIT + ($token_count * $TXGEN_HELPER_KEY_AUTHORIZATION_PER_TOKEN_GAS_LIMIT)) | into string
}

def --env txgen-configure-keychain-env [accounts: int, token_count: int] {
    if $accounts <= 0 {
        error make { msg: "keychain account count must be greater than zero" }
    }

    let access_keys_end = $TXGEN_HELPER_KEYCHAIN_ACCESS_KEYS_START + $accounts
    $env.TXGEN_KEYCHAIN_ACCESS_KEYS_START = ($TXGEN_HELPER_KEYCHAIN_ACCESS_KEYS_START | into string)
    $env.TXGEN_KEYCHAIN_ACCESS_KEYS_END = ($access_keys_end | into string)
    $env.TXGEN_KEYCHAIN_TIP20_LIMITS = (txgen-keychain-tip20-limits $token_count)
    $env.TXGEN_KEYCHAIN_TIP20_ALLOWED_CALLS = (txgen-keychain-tip20-allowed-calls $token_count)
    $env.TXGEN_KEYCHAIN_AUTHORIZE_SETUP_GAS_LIMIT = ($TXGEN_HELPER_KEYCHAIN_AUTHORIZE_SETUP_GAS_LIMIT | into string)
    $env.TXGEN_KEY_AUTHORIZATION_GAS_LIMIT = (txgen-key-authorization-gas-limit $token_count)
}

# 2D-nonce specs mint deeper FeeAMM liquidity, matching the removed
# tip20_2d_nonces preset. `nonce_key:` only appears in 2D-nonce specs.
def --env txgen-configure-fee-amm-env [spec_path: string] {
    let amount = if (txgen-spec-effective-text $spec_path) =~ '(?m)^\s*nonce_key:\s*$' {
        $TXGEN_HELPER_FEE_AMM_2D_LIQUIDITY_AMOUNT
    } else {
        $TXGEN_HELPER_FEE_AMM_LIQUIDITY_AMOUNT
    }
    $env.TXGEN_FEE_AMM_LIQUIDITY_AMOUNT = ($amount | into string)
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
        return $TXGEN_HELPER_TIP20_SCENARIO_PRESETS
    }

    let static_presets = (glob ([ $presets_dir "*.yml" ] | path join)
        | each { |preset_path| $preset_path | path basename | str replace --regex '\.yml$' '' }
    )

    $static_presets | append $TXGEN_HELPER_TIP20_SCENARIO_PRESETS | uniq | sort
}

def txgen-available-presets-message [] {
    let presets = (txgen-available-presets)
    if ($presets | is-empty) {
        "none"
    } else {
        $"($presets | str join ', '), or tip20:<field>=<value>,..."
    }
}

def txgen-static-preset-path [preset: string] {
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

def txgen-resolve-bench-spec [preset: string, out_dir: string = ""] {
    let preset_name = ($preset | str trim)
    let tip20_scenario = (txgen-parse-tip20-scenario $preset_name)
    if $tip20_scenario != null {
        return (txgen-render-tip20-spec $tip20_scenario $out_dir)
    }

    let spec_path = (txgen-static-preset-path $preset_name)
    {
        kind: static
        scenario_id: $preset_name
        spec_path: $spec_path
        rendered: false
        requires_existing_recipients: false
        requires_keychain_setup: (txgen-spec-has-keychain-setup $spec_path)
        uses_fee_amm: false
    }
}

def txgen-preset-path [preset: string] {
    (txgen-resolve-bench-spec $preset).spec_path
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

# Return the spec text with `include` entries expanded, so content checks see
# included pieces. Pieces do not nest includes, so one level is enough.
def txgen-spec-effective-text [spec_path: string] {
    let path = ($spec_path | path expand)
    let raw = (open --raw $path)
    let doc = (try { $raw | from yaml } catch { null })
    if $doc == null or not (($doc | describe) | str starts-with "record") {
        return $raw
    }

    let include_value = ($doc | get -o include | default ($doc | get -o includes))
    let includes = if $include_value == null {
        []
    } else if (($include_value | describe) == "string") {
        [$include_value]
    } else {
        $include_value
    }

    let base_dir = ($path | path dirname)
    $includes
        | each { |include_path|
            let resolved = if ($include_path | str starts-with "/") {
                $include_path
            } else {
                [ $base_dir $include_path ] | path join
            }
            open --raw $resolved
        }
        | append $raw
        | str join "\n"
}

def txgen-spec-has-keychain-setup [spec_path: string] {
    (txgen-spec-effective-text $spec_path) =~ '(?m)^\s*keychain_authorize_pool:\s*$'
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
    let spec_uses_existing_recipients = if ($preset_path | path exists) {
        (txgen-spec-effective-text $preset_path) =~ '(?m)^\s*existing_recipients:\s*$'
    } else {
        false
    }
    if not $spec_uses_existing_recipients {
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
    txgen-configure-keychain-env $accounts $tx_token_count
    txgen-configure-existing-recipients-env $spec_path $bloat_mib $bloat_token_count
    txgen-configure-fee-amm-env $spec_path
    let preset_name = ($spec_path | path basename | str replace --regex '\.yml$' '')
    let skip_faucet_funding = $skip_funding and ($preset_name not-in $TXGEN_HELPER_ALWAYS_FUND_PRESETS)
    let existing_recipient_start = ($env | get --optional TXGEN_EXISTING_RECIPIENTS_START | default "0" | into int)
    let existing_recipient_end = ($env | get --optional TXGEN_EXISTING_RECIPIENTS_END | default "0" | into int)
    let recipient_accounts = if $existing_recipient_end > $existing_recipient_start {
        $existing_recipient_end - $existing_recipient_start
    } else {
        0
    }
    let total_accounts = $accounts + $recipient_accounts
    if not $skip_faucet_funding {
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
    let txgen_setup_cmd = [
        $txgen_tempo_bin
        "generate"
        "-s" $spec_path
        "-n" 0
        "--seed" $TXGEN_HELPER_DEFAULT_SEED
        "--rpc" $generate_rpc_url
    ]
    let metrics_url_args = ($metrics_url | each { |url| ["--metrics-url" $url] } | flatten)
    let bench_send_base_cmd = [
        $txgen_bench_bin
        "send"
        "--rpc-url" $submit_rpc_url
        "--tps" $tps
        "--max-concurrent" $max_concurrent_requests
        "--retries" 0
        "--scrape-interval-ms" $TXGEN_HELPER_SCRAPE_INTERVAL_MS
    ]
    let bench_base_cmd = [
        ...$bench_send_base_cmd
        ...$metrics_url_args
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
    let use_two_phase_keychain_setup = (txgen-spec-has-keychain-setup $spec_path)
    let txgen_cmd_str = (txgen-shell-join ($txgen_cmd | append $txgen_extra_args))
    let bench_cmd = if $use_two_phase_keychain_setup { $bench_cmd | append "--skip-setup" } else { $bench_cmd }
    let bench_cmd_str = (txgen-shell-join $bench_cmd)
    let pipeline = $"set -euo pipefail; ($bench_env_export)ulimit -Sn unlimited && ($txgen_cmd_str) | ($bench_cmd_str)"

    if $use_two_phase_keychain_setup {
        let txgen_setup_cmd_str = (txgen-shell-join ($txgen_setup_cmd | append $txgen_extra_args))
        let bench_setup_cmd_str = (txgen-shell-join ($bench_send_base_cmd | append ["--drain-timeout" 0]))
        let setup_pipeline = $"set -euo pipefail; ($bench_env_export)ulimit -Sn unlimited && ($txgen_setup_cmd_str) | ($bench_setup_cmd_str)"

        print "  Streaming keychain setup transactions into bench send..."
        let setup_result = (bash -lc $setup_pipeline | complete)
        if $setup_result.stdout != "" { print $setup_result.stdout }
        if $setup_result.stderr != "" { print $setup_result.stderr }

        if $setup_result.exit_code != 0 {
            return { ok: false, exit_code: $setup_result.exit_code, report_path: $report_path }
        }
    }

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
