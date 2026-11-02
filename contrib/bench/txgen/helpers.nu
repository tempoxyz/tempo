const TXGEN_HELPER_ACCOUNT_MNEMONIC = "test test test test test test test test test test test junk"
const TXGEN_HELPER_DEFAULT_SEED = 99
const TXGEN_HELPER_SCRAPE_INTERVAL_MS = 200
const TXGEN_HELPER_FUND_DRAIN_TIMEOUT_SECS = 120
const TXGEN_HELPER_PRESETS_DIR = "contrib/bench/txgen/presets"
const TXGEN_HELPER_TIP20_PIECES_DIR = "contrib/bench/txgen/presets/tip20"
const TXGEN_HELPER_TIP20_SCENARIO_PRESETS = ["default" "public" "tip20"]
const TXGEN_HELPER_ALWAYS_FUND_PRESETS = [
    "zone-earn-mix"
    "zone-earn-hot"
    "zone-earn-serial"
    "zone-portal-hot"
    "card-settlement"
    "neobank-generic"
    "neobank-multi"
    "projected-pipeline"
    "batch-payout"
    "agentic"
    "dex"
    "bridge-mix"
    "bridge-mix-new-accounts"
    "cross-border"
    "neobank-deposit"
    "neobank-swap"
    "neobank-withdraw"
    "public-mix"
    "tip20-policy"
    "institutional"
    "vault-deposit"
    "vault-withdraw"
    "vault-throughput"
    "zone-portal-throughput"
    "zone-to-zone"
    "zone-to-zone-hot"
]
# Presets composed by txgen-prepare-public-mix-preset from the public-mix fixtures.
const TXGEN_HELPER_PUBLIC_MIX_PRESETS = ["public-mix" "vault-throughput" "zone-portal-throughput" "zone-earn-mix" "zone-earn-hot" "zone-earn-serial" "zone-portal-hot" "card-settlement" "neobank-generic" "neobank-multi" "projected-pipeline" "batch-payout"]
# Presets that pin the zone portal count instead of sizing it by TPS (TXGEN_ZONE_COUNT still overrides).
const TXGEN_HELPER_PRESET_ZONE_COUNTS = {"zone-earn-hot": 1, "zone-portal-hot": 1}
# Zone -> zone presets (presets/zone-to-zone.yml); the hot variant pins one source and one target portal.
const TXGEN_HELPER_ZONE_TO_ZONE_PRESETS = ["zone-to-zone" "zone-to-zone-hot"]
const TXGEN_HELPER_ZONE_TO_ZONE_CALLBACK_GAS = 1500000
const TXGEN_HELPER_ZONE_TO_ZONE_GAS_LIMIT = 2500000
# Like the public-mix workloads: expiring nonces let transfers the saturated general lane
# cannot include expire instead of holding the sender's pending window past its timeout.
# A random TIP-1106 nonce keeps a sender's otherwise identical transfers distinct.
const TXGEN_HELPER_ZONE_TO_ZONE_VALID_FOR_SECS = 25
# A route's first transfer creates portal queue state, so setup warms it with more gas.
const TXGEN_HELPER_ZONE_TO_ZONE_WARM_CALLBACK_GAS = 3000000
const TXGEN_HELPER_ZONE_TO_ZONE_WARM_GAS_LIMIT = 10000000
# ZoneToZoneTransfer(address,address) and WithdrawalProcessed(address,bytes32,address,uint128,bool).
const TXGEN_HELPER_ZONE_TO_ZONE_TRANSFER_TOPIC = "0x45310f61ef78f3fcb9ab97ea27304d615534bc583c8ef2b31ecabd38fac9a4b7"
const TXGEN_HELPER_WITHDRAWAL_PROCESSED_TOPIC = "0x65042ea6dad60c26f055e80ec401b3437c854ed586a0704d305bb4e9ea4518cf"
# Presets whose zone settlement and Earn deposits come from one sender with ordered nonces.
const TXGEN_HELPER_SINGLE_SENDER_PRESETS = ["zone-earn-serial"]
# Card settlement: a small pool of shard senders redeem vault shares and forward proceeds.
const TXGEN_HELPER_CARD_SETTLEMENT_PRESETS = ["card-settlement"]
const TXGEN_HELPER_CARD_SETTLEMENT_SENDERS = 18
const TXGEN_HELPER_CARD_SETTLEMENT_ACCOUNT = "0x000000000000000000000000000000000000ca4d"
# Batch payouts: recipients per transaction by preset (TXGEN_BATCH_PAYOUT_RECIPIENTS overrides),
# within the txpool's 32 calls per Tempo transaction and the 30M transaction gas cap.
const TXGEN_HELPER_BATCH_PAYOUT_RECIPIENTS = {"batch-payout": 32, "neobank-generic": 32, "neobank-multi": 32, "projected-pipeline": 32}
const TXGEN_HELPER_BATCH_PAYOUT_BASE_GAS = 500000
const TXGEN_HELPER_BATCH_TREASURY_SIZE = 16
# neobank-generic mix templates by module (TXGEN_NEOBANK_MODULES selects modules).
const TXGEN_HELPER_NEOBANK_MODULES = {
    account: [account_first_receive access_key_create access_key_rotate]
    deposit: [zone_deposit public_transfer payroll_existing payroll_new]
    earn: [vault_deposit vault_withdraw reward_distribution]
    transfer: [public_transfer_memo zone_withdraw dex_swap]
    spend: [card_settlement card_spend card_refund keychain_merchant_pull keychain_agent_spend]
    cashout: [cash_out]
}
# Single-account sinks (card settlement, cash out, merchant); each neobank-multi instance gets its own.
const TXGEN_HELPER_NEOBANK_SINKS = [
    "0x000000000000000000000000000000000000ca4d"
    "0x0000000000000000000000000000000000000ff0"
    "0x0000000000000000000000000000000000005e77"
]
# Deployment-shape pillars (presets/shapes/README.md) and the month length behind peak TPS.
const TXGEN_HELPER_SHAPE_PILLARS = [cross-border institutional embedded-finance agentic]
const TXGEN_HELPER_SECONDS_PER_MONTH = 2592000
# neobank-multi style presets and their default instances or shapes file (TXGEN_NEOBANK_INSTANCES overrides).
const TXGEN_HELPER_NEOBANK_MULTI_PRESETS = {"neobank-multi": "neobank/instances.yml", "projected-pipeline": "shapes/pipeline.yml"}
# neobank-multi mix weights sum to about this, split by instance gas share.
const TXGEN_HELPER_NEOBANK_WEIGHT_SCALE = 1000000000
const TXGEN_HELPER_MAX_AA_CALLS = 32
const TXGEN_HELPER_TX_GAS_LIMIT_CAP = 30000000
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
const TXGEN_HELPER_CLICKHOUSE_METRICS_FILE = "contrib/bench/clickhouse-metrics.txt"
const TXGEN_HELPER_TIP403_REGISTRY = "0x403c000000000000000000000000000000000000"
const TXGEN_HELPER_POLICY_ABI = "contrib/bench/txgen/tip403-policy.abi.json"
const TXGEN_HELPER_POLICY_SETUP_GAS_LIMIT = 10000000
# Presets that run tip20-policy's issuer and receiver policy setup. Only tip20-policy
# itself requires full inclusion: load presets such as institutional saturate the pool.
const TXGEN_HELPER_POLICY_PRESETS = ["tip20-policy" "institutional"]

def txgen-tip20-base-scenario [] {
    {
        workload: "tip20"
        recipient: "users"
        auth: "direct"
        nonce: "expiring"
        fee_token: "pathusd"
    }
}

def txgen-tip20-public-scenario [] {
    {
        workload: "tip20"
        recipient: "users"
        auth: "direct"
        nonce: "expiring"
        fee_token: "pathusd"
    }
}

def txgen-tip20-scenario-alias [name: string] {
    if $name == "public" {
        return (txgen-tip20-public-scenario)
    }

    # Legacy preset names remain accepted, but active workflows should use scenario strings.
    if $name == "tip20" {
        return (txgen-tip20-base-scenario)
    }
    if $name == "tip20_random_recipients" {
        return ((txgen-tip20-base-scenario) | merge { recipient: "random", fee_token: "any_tip20" })
    }
    if $name == "tip20_existing_recipients" {
        return ((txgen-tip20-base-scenario) | merge { recipient: "existing", fee_token: "any_tip20" })
    }
    if $name == "tip20_keychain" {
        return ((txgen-tip20-base-scenario) | merge { auth: "keychain", fee_token: "any_tip20" })
    }
    if $name == "tip20_keychain_random_recipients" {
        return ((txgen-tip20-base-scenario) | merge { recipient: "random", auth: "keychain", fee_token: "any_tip20" })
    }
    if $name == "tip20_keychain_existing_recipients" {
        return ((txgen-tip20-base-scenario) | merge { recipient: "existing", auth: "keychain", fee_token: "any_tip20" })
    }
    if $name == "tip20_key_authorization" {
        return ((txgen-tip20-base-scenario) | merge { auth: "key_authorization", fee_token: "any_tip20" })
    }
    if $name == "tip20_protocol_nonces" {
        return ((txgen-tip20-base-scenario) | merge { recipient: "existing", nonce: "protocol", fee_token: "any_tip20" })
    }
    if $name == "tip20_2d_nonces" {
        return ((txgen-tip20-base-scenario) | merge { recipient: "existing", nonce: "2d", fee_token: "any_tip20" })
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
    mut scenario = (txgen-tip20-base-scenario)
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
    # Shared with the multi-region runner; keep workload selection in the assets.
    let name = ($preset | str trim)
    let aliases = (open ([ (txgen-presets-dir) "aliases.json" ] | path join))
    let preset_name = ($aliases | get -o $name | default $name)
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

# Store concrete workload identities; a moving CLI alias must not relabel history.
def txgen-scenario-metadata-args [scenario: string, spec_path: string] {
    let aliases = (open ([ (txgen-presets-dir) "aliases.json" ] | path join))
    let resolved = ($aliases | get -o $scenario | default $scenario)
    ["-m" $"preset=($spec_path | path basename | str replace --regex '\.yml$' '')"]
        | append (if $resolved != "" { ["-m" $"scenario=($resolved)"] } else { [] })
        | append (if $resolved != $scenario { ["-m" $"requested_preset=($scenario)"] } else { [] })
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
    # Nushell's YAML parser panics on integers above i64::MAX (e.g. nonce bounds).
    # Use the same pinned Python yq as workload metadata and only pass include
    # paths back to Nushell. Keep the original spec text and numeric values intact.
    let result = (^uv run --no-project --with yq==3.4.3 yq -c '
        if type == "object" then (.include // .includes // []) else [] end
    ' $path | complete)
    if $result.exit_code != 0 {
        error make {msg: $"Failed to read txgen spec includes: ($result.stderr)"}
    }

    let include_value = ($result.stdout | from json)
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
            # Rendered specs include presets that include fragments; read the whole tree.
            txgen-spec-effective-text $resolved
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
        error make { msg: $"failed to list txgen addresses for ($spec_path): ($result.stderr | str trim)" }
    }

    # Pools may share accounts (batch-payout treasury); fund each address once.
    let addresses = ($result.stdout | str trim | split row " " | where { |addr| $addr != "" } | uniq)
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

# Portal count: TXGEN_ZONE_COUNT, else the preset's pinned count, else the TPS-sized default.
def txgen-zone-count [preset_name: string, automatic: int] {
    let pinned = ($TXGEN_HELPER_PRESET_ZONE_COUNTS | get -o $preset_name)
    $env.TXGEN_ZONE_COUNT? | default ($pinned | default $automatic) | into int
}

# Sends zone settlement and Earn deposits from users[0] with ordered nonces.
def txgen-single-sender-templates [templates: record] {
    $templates | items { |name, template|
        let serial = ($name =~ '^(zone_withdraw|vault_deposit)_[0-9]+$')
        let value = if $serial {
            $template
                | upsert from {pool: users, select: {index: 0}}
                | upsert expiring_nonce false
                | reject -o valid_for_secs nonce
        } else { $template }
        {name: $name, value: $value}
    } | transpose -r -d
}

# Keeps the first card shard senders' vault redemptions, unsponsored, each followed by
# a transfer of the proceeds to one settlement account. Each gets a random TIP-1106
# nonce discriminator so a sender's otherwise identical redemptions stay distinct.
def txgen-card-settlement-template [template: record, --account: string = $TXGEN_HELPER_CARD_SETTLEMENT_ACCOUNT] {
    let forward = {
        to: "0x20c0000000000000000000000000000000000000"
        abi: ERC20
        function: transfer
        args: [$account 1]
    }
    $template | reject -o sponsor | upsert nonce {uniform: [0 9223372036854775807]} | upsert calls ($template.calls | append $forward)
}

# Repeats each batch-payout template's last call once per recipient, scales its
# approvals to cover every recipient and sizes gas_limit (a per-recipient budget) to
# the batch. A template whose batch would pass the call or gas cap gets the most
# recipients that fit.
def txgen-batch-payout-templates [presets_dir: string, recipients: int] {
    if $recipients < 1 { error make {msg: "TXGEN_BATCH_PAYOUT_RECIPIENTS must be positive"} }
    # Nushell's YAML parser keeps the i64 nonce bound exact; a jq round-trip may not.
    open ($presets_dir | path join batch-payout.yml) | get templates | items { |name, template|
        let gas_fit = (($TXGEN_HELPER_TX_GAS_LIMIT_CAP - $TXGEN_HELPER_BATCH_PAYOUT_BASE_GAS) // $template.gas_limit)
        let call_fit = $TXGEN_HELPER_MAX_AA_CALLS - ($template.calls | length) + 1
        let count = ([$recipients $gas_fit $call_fit] | math min)
        let payout = ($template.calls | last)
        let approvals = ($template.calls | drop 1 | each { |call|
            if $call.function == approve { $call | update args.1 ($call.args.1 * $count) } else { $call }
        })
        {name: $name, value: ($template
            | update gas_limit ($template.gas_limit * $count + $TXGEN_HELPER_BATCH_PAYOUT_BASE_GAS)
            | update calls ($approvals | append (1..$count | each { $payout })))}
    } | transpose -r -d
}

def txgen-card-settlement [templates: record, mix: list<any>] {
    let shard = { |name: string|
        let parsed = ($name | parse --regex '^vault_withdraw_(?<index>[0-9]+)$')
        ($parsed | length) > 0 and (($parsed | first).index | into int) < $TXGEN_HELPER_CARD_SETTLEMENT_SENDERS
    }
    {
        templates: ($templates | items { |name, template|
            let value = if (do $shard $name) {
                txgen-card-settlement-template $template
            } else { $template }
            {name: $name, value: $value}
        } | transpose -r -d)
        mix: ($mix | where { |entry|
            let name = ($entry | get -o template | default "")
            not ($name | str starts-with "vault_withdraw_") or (do $shard $name)
        })
    }
}

# Pairs users with portals. --groups pairs each user range only with its own portal
# range ([{users: [start end], zones: [start end]}]); by default all users with all portals.
def txgen-prepare-zones-preset [spec_path: string, count: int, accounts: int, zones: int, mode: string, --groups: list<any> = []] {
    if $mode not-in [mixed deposit withdraw] { error make {msg: "TXGEN_ZONE_MODE must be mixed, deposit, or withdraw"} }
    let spec = (open $spec_path)
    let token = "0x20c0000000000000000000000000000000000000"
    mut steps = [$spec.setup.steps.0]
    for zone in 0..<$zones {
        $steps = ($steps | append ($spec.setup.steps.1
            | update id $"portal_($zone)"
            | update deploy.constructor_args.0 {var: setup.settlement.sender}))
    }
    for zone in 0..<$zones {
        $steps = ($steps | append ($spec.setup.steps.2 | update id $"fund_($zone)"
            | update tx.calls.0.args [{var: $"setup.portal_($zone).address"} $count]))
    }
    let groups = if ($groups | is-empty) { [{users: [0 $accounts], zones: [0 $zones]}] } else { $groups }
    mut templates = {}
    mut mix = []
    mut pair = 0
    for group in $groups {
        let group_users = $group.users.1 - $group.users.0
        let group_zones = $group.zones.1 - $group.zones.0
        let pairs = ([$group_users $group_zones] | math max)
        let minimum_per_zone = ($pairs // $group_zones)
        for offset in 0..<$pairs {
            let user = $group.users.0 + ($offset mod $group_users)
            let zone_offset = $offset mod $group_zones
            let zone = $group.zones.0 + $zone_offset
            let portal = {var: $"setup.portal_($zone).address"}
            let account = {pool: users, select: {index: $user}}
            let recipient = {pool: $account}
            if $mode != withdraw {
                $steps = ($steps | append ($spec.setup.steps.2 | update id $"approve_($pair)"
                    | update tx.from $account
                    | update tx.calls [{to: $token, abi: ERC20, function: approve,
                        args: [$portal "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"]}]))
            }
            let per_zone = $minimum_per_zone + (if $zone_offset < ($pairs mod $group_zones) { 1 } else { 0 })
            let weight = $minimum_per_zone * ($minimum_per_zone + 1) // $per_zone
            for kind in (if $mode == mixed { [deposit withdraw] } else { [$mode] }) {
                let name = $"zone_($kind)_($pair)"
                mut template = ($spec.templates | get $"zone_($kind)" | update from $account)
                if $kind == deposit {
                    $template = ($template | update calls.0.to $portal | update calls.0.args.4 $recipient)
                }
                let settlement_index = if $kind == deposit { 1 } else { 0 }
                let call = ($template.calls | get $settlement_index | update args [$portal $token $recipient ($kind == withdraw)])
                $template = ($template | update calls ($template.calls | update $settlement_index $call))
                $templates = ($templates | insert $name $template)
                $mix = ($mix | append {template: $name, weight: $weight})
            }
            $pair = $pair + 1
        }
    }
    let output_dir = ([ (txgen-repo-root) $TXGEN_HELPER_DEFAULT_RENDERED_SPECS_DIR (random uuid) ] | path join)
    mkdir $output_dir
    let output = ($output_dir | path join zones.yml)
    {include: $spec_path, accounts: {users: {range: [0 $accounts]}},
        setup: {steps: $steps}, templates: $templates, mix: $mix} | to yaml | save -f $output
    $output
}

# Zone -> zone transfer settings, from TXGEN_ZONE_TO_ZONE_* (see presets/zone-to-zone.yml).
def txgen-zone-to-zone-config [] {
    let access = ($env.TXGEN_ZONE_TO_ZONE_ACCESS? | default "closed")
    if $access not-in [closed open] { error make {msg: "TXGEN_ZONE_TO_ZONE_ACCESS must be closed or open"} }
    let share = ($env.TXGEN_ZONE_TO_ZONE_SHARE? | default "100" | into int)
    if $share < 1 or $share > 100 { error make {msg: "TXGEN_ZONE_TO_ZONE_SHARE must be 1–100"} }
    let callback_gas = ($env.TXGEN_ZONE_TO_ZONE_CALLBACK_GAS? | default $TXGEN_HELPER_ZONE_TO_ZONE_CALLBACK_GAS | into int)
    let gas_limit = ($env.TXGEN_ZONE_TO_ZONE_GAS_LIMIT? | default $TXGEN_HELPER_ZONE_TO_ZONE_GAS_LIMIT | into int)
    if $callback_gas < 1 or $gas_limit > $TXGEN_HELPER_TX_GAS_LIMIT_CAP {
        error make {msg: "TXGEN_ZONE_TO_ZONE_CALLBACK_GAS must be positive and TXGEN_ZONE_TO_ZONE_GAS_LIMIT at most 30M"}
    }
    # A closed source portal only accepts a callback that deposits back into it.
    {access: $access, share: $share, callback_gas: $callback_gas, gas_limit: $gas_limit,
        return_amount: (if $access == closed { 1 } else { 0 })}
}

# Portal i sends to portal i + 1 (a ring of at least two); hot sends everything from 0 to 1.
# Setup warms each route once, so the first transfer's queue-state creation stays out of the run.
def txgen-prepare-zone-to-zone-preset [spec_path: string, count: int, accounts: int, zones: int, --hot, --out-dir: string = ""] {
    let config = (txgen-zone-to-zone-config)
    let base = if $hot { $spec_path | path dirname | path join zone-to-zone.yml } else { $spec_path }
    let spec = (open $base)
    let zones = if $hot { 2 } else { [$zones 2] | math max }
    let token = "0x20c0000000000000000000000000000000000000"
    let closed = $config.access == closed
    let sources = if $hot { [0] } else { 0..<$zones | each { |zone| $zone } }
    let target = { |zone| if $hot { 1 } else { ($zone + 1) mod $zones } }
    let portal = { |zone| {var: $"setup.portal_($zone).address"} }
    let transfer_call = ($spec.templates.zone_to_zone.calls | first)
    let withdraw_call = ($spec.templates.zone_withdraw.calls | first)
    # Closed portals only pay plain withdrawals to their allowlisted account (the deployer).
    let allowlisted = {var: setup.settlement.sender}
    mut steps = ($spec.setup.steps | take 3)
    for zone in 0..<$zones {
        $steps = ($steps | append ($spec.setup.steps.3 | update id $"portal_($zone)" | update deploy.constructor_args.6 $closed))
    }
    let escrow = $count * (1 + $config.return_amount) + $count + 2 * (2 + $config.return_amount)
    for zone in $sources {
        $steps = ($steps | append ($spec.setup.steps.4 | update id $"fund_($zone)"
            | update tx.calls.0.args [(do $portal $zone) $escrow]))
    }
    for zone in $sources {
        let warm = ($spec.setup.steps.4 | update id $"warm_($zone)" | update tx.gas_limit $TXGEN_HELPER_ZONE_TO_ZONE_WARM_GAS_LIMIT)
        mut calls = [($transfer_call | update args [(do $portal $zone) (do $portal (do $target $zone)) $token
            {var: setup.gateway.address} $config.return_amount $TXGEN_HELPER_ZONE_TO_ZONE_WARM_CALLBACK_GAS])]
        if $config.share < 100 {
            $calls = ($calls | append ($withdraw_call | update args [(do $portal $zone) $token $allowlisted true]))
        }
        $steps = ($steps | append ($warm | update tx.calls $calls))
    }
    let pairs = ([$accounts ($sources | length)] | math max)
    let minimum_per_zone = ($pairs // ($sources | length))
    mut templates = {}
    mut mix = []
    for pair in 0..<$pairs {
        let user = $pair mod $accounts
        let slot = $pair mod ($sources | length)
        let zone = ($sources | get $slot)
        let account = {pool: users, select: {index: $user}}
        let per_zone = $minimum_per_zone + (if $slot < ($pairs mod ($sources | length)) { 1 } else { 0 })
        let weight = $minimum_per_zone * ($minimum_per_zone + 1) // $per_zone
        let transfer = ($spec.templates.zone_to_zone | update from $account | update gas_limit $config.gas_limit
            | upsert expiring_nonce true | upsert valid_for_secs $TXGEN_HELPER_ZONE_TO_ZONE_VALID_FOR_SECS | upsert nonce {uniform: [0 9223372036854775807]}
            | update calls [($transfer_call | update args [(do $portal $zone) (do $portal (do $target $zone)) $token
                {var: setup.gateway.address} $config.return_amount $config.callback_gas])])
        $templates = ($templates | insert $"zone_to_zone_($pair)" $transfer)
        $mix = ($mix | append {template: $"zone_to_zone_($pair)", weight: ($weight * $config.share)})
        if $config.share < 100 {
            let recipient = if $closed { $allowlisted } else { {pool: $account} }
            let withdraw = ($spec.templates.zone_withdraw | update from $account
                | upsert expiring_nonce true | upsert valid_for_secs $TXGEN_HELPER_ZONE_TO_ZONE_VALID_FOR_SECS | upsert nonce {uniform: [0 9223372036854775807]}
                | update calls [($withdraw_call | update args [(do $portal $zone) $token $recipient true])])
            $templates = ($templates | insert $"zone_withdraw_($pair)" $withdraw)
            $mix = ($mix | append {template: $"zone_withdraw_($pair)", weight: ($weight * (100 - $config.share))})
        }
    }
    let output_dir = if $out_dir == "" {
        [ (txgen-repo-root) $TXGEN_HELPER_DEFAULT_RENDERED_SPECS_DIR (random uuid) ] | path join
    } else { $out_dir | path expand }
    mkdir $output_dir
    # Keep the preset's file name: reports derive the preset label from it.
    let output = ($output_dir | path join ($spec_path | path basename))
    {include: $base, accounts: {users: {range: [0 $accounts]}},
        setup: {steps: $steps}, templates: $templates, mix: $mix} | to yaml | save -f $output
    $output
}

# Tallies zone -> zone receipts: ZoneToZoneTransfer marks a transfer, and its
# WithdrawalProcessed log's callbackSuccess says delivered or bounced back to zone A.
def txgen-zone-to-zone-tally [receipts: list<any>] {
    let marker = $TXGEN_HELPER_ZONE_TO_ZONE_TRANSFER_TOPIC
    let processed = $TXGEN_HELPER_WITHDRAWAL_PROCESSED_TOPIC
    let rows = ($receipts | each { |receipt|
        let logs = ($receipt.logs? | default [])
        let is_transfer = ($logs | any { |log| ($log.topics | first) == $marker })
        let outcomes = ($logs | where { |log| ($log.topics | first) == $processed }
            | each { |log| ($log.data | str substring (-1..)) == "1" })
        {
            transfer: $is_transfer
            reverted: ($receipt.status == "0x0")
            delivered: ($is_transfer and ($outcomes | any { |ok| $ok }))
            bounced: ($is_transfer and ($outcomes | any { |ok| not $ok }))
            plain: ((not $is_transfer) and ($outcomes | is-not-empty))
            gas: ($receipt.gasUsed | into int)
        }
    })
    let transfers = ($rows | where transfer)
    {
        transfers: ($transfers | length)
        delivered: ($transfers | where delivered | length)
        bounced: ($transfers | where bounced | length)
        plain_withdrawals: ($rows | where plain | length)
        reverted: ($rows | where reverted | length)
        transfer_gas: ($transfers | get gas | math sum)
    }
}

# Empty, distinct blacklists exercise every successful authorization lookup without
# requiring per-member setup. Policy IDs come from the live registry counter.
def txgen-tip20-policy-calls [token_count: int, policy_start: int] {
    let registry_call = {|function, args| {to: $TXGEN_HELPER_TIP403_REGISTRY, abi: TIP403Policy, function: $function, args: $args} }
    let blacklist = {|| do $registry_call createPolicy [{pool: {pool: policy_admin, select: {index: 0}}} 1] }
    let issuer_calls = (0..<$token_count | each { |id|
        let start = $policy_start + 4 * $id
        (0..<3 | each { do $blacklist })
            | append (do $registry_call createCompoundPolicy [$start ($start + 1) ($start + 2)])
            | append {to: (txgen-tip20-token-address $id), abi: TIP403Policy, function: changeTransferPolicyId, args: [($start + 3 | into string)]}
    } | flatten)
    let receive_start = $policy_start + 4 * $token_count
    {
        admin_calls: ($issuer_calls | append (0..<2 | each { do $blacklist }))
        receive_call: (do $registry_call setReceivePolicy [$receive_start ($receive_start + 1) "0x0000000000000000000000000000000000000000"])
    }
}

# All issuer and receiver setup is funded and confirmed before measurement.
def txgen-prepare-tip20-policy [spec_path: string, rpc_url: string, token_count: int, accounts: int] {
    if $token_count < 2 or $accounts < 1 {
        error make { msg: "tip20-policy requires at least two TIP20 tokens and one user account" }
    }
    let counter = (txgen-rpc-call $rpc_url $'{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"($TXGEN_HELPER_TIP403_REGISTRY)","data":"0x3cc32f9c"},"latest"]}')
    let policy = (txgen-tip20-policy-calls $token_count ($counter.result | into int))
    let setup_tx = {
        type: tempo
        from: {pool: policy_admin, select: {index: 0}}
        gas_limit: $TXGEN_HELPER_POLICY_SETUP_GAS_LIMIT
        fee_token: (txgen-tip20-token-address 0)
        calls: $policy.admin_calls
    }
    let steps = [{id: issuer_policies, tx: $setup_tx}] | append (0..<$accounts | each { |index|
        {id: $"receive_policy_($index)", depends_on: [issuer_policies], tx: ($setup_tx | merge {
            from: {pool: policy_receivers, select: {index: $index}}
            calls: [$policy.receive_call]
        })}
    })
    let output_dir = ([ (txgen-repo-root) $TXGEN_HELPER_DEFAULT_RENDERED_SPECS_DIR (random uuid) ] | path join)
    mkdir $output_dir
    let fragment = ($output_dir | path join "policy-setup.yml")
    {
        merge: {
            artifacts: {TIP403Policy: ([ (txgen-repo-root) $TXGEN_HELPER_POLICY_ABI ] | path join)}
            accounts: {
                policy_admin: {mnemonic: $TXGEN_HELPER_ACCOUNT_MNEMONIC, range: [0 1]}
                policy_receivers: {mnemonic: $TXGEN_HELPER_ACCOUNT_MNEMONIC, range: [$accounts ($accounts * 2)]}
            }
        }
        append: {setup: {steps: $steps}}
    } | to json | save -f $fragment
    let output = ($output_dir | path join ($spec_path | path basename))
    {include: [($spec_path | path expand) $fragment]} | to json | save -f $output
    $output
}

def txgen-prepare-vault-preset [spec_path: string, accounts: int, chain_id: int] {
    if $chain_id != 1337 or $accounts <= 0 or $accounts > 100000 {
        error make { msg: "Vault presets require chain ID 1337 and 1..100000 user accounts" }
    }
    let operation = ($spec_path | path basename | str replace "vault-" "" | str replace ".yml" "")
    let template_path = ([ ($spec_path | path dirname) "vault" $"user-($operation).yml" ] | path join)
    let template = (open $template_path).setup.steps.0
    let steps = (0..<$accounts | each { |index|
        $template | update id $"($template.id)_($index)" | update bindings.user.account.select.index $index
    })
    let base = (open ([ ($template_path | path dirname) "base.yml" ] | path join))
    let workload = ($base.templates | get $"vault_($operation)")
    let templates = (0..<$accounts | each { |index|
        { name: $"vault_($operation)_($index)", value: ($workload
            | update from.select {index: $index}
            | update calls.1.args.1 {pool: {pool: users, select: {index: $index}}}) }
    } | transpose -r -d)
    let mix = (0..<$accounts | each { |index| {template: $"vault_($operation)_($index)", weight: 1} })
    let output_dir = ([ (txgen-repo-root) $TXGEN_HELPER_DEFAULT_RENDERED_SPECS_DIR (random uuid) ] | path join)
    mkdir $output_dir
    let output = ($output_dir | path join ($spec_path | path basename))
    { include: $spec_path, templates: $templates, mix: $mix, append: { setup: { steps: $steps } } } | to yaml | save -f $output
    $output
}

# Only public-mix-composed presets need category metadata; all presets use gas weighting.
def txgen-workload-metadata-args [preset_name: string, spec_path: string] {
    if $preset_name not-in $TXGEN_HELPER_PUBLIC_MIX_PRESETS { return ["-m" "workload_mix_weighting=gas"] }

    # Read only the prepared file's mix, not its included setup/template specs.
    # Pin the jq-compatible Python yq, rather than relying on a system yq variant.
    let result = (^uv run --no-project --with yq==3.4.3 yq -ceS '
        .mix | if length > 0 then . else error("public-mix requires a mix") end
        | map({key: ((.template // .sequence)
            | capture("^((?<instance>[a-z][a-z0-9-]*)/)?(?<name>.+)$") as $m
            | ($m.name | sub("^(?<category>(zone|vault)_(deposit|withdraw)|card_settlement)_[0-9]+$"; "\(.category)")) as $family
            # neobank-multi templates are named <instance>/<template>.
            | if $m.instance then "\($m.instance)/\($family)" else $family end), value: .weight})
        | group_by(.key)
        | map({key: .[0].key, value: (map(.value) | add)})
        | from_entries
    ' $spec_path | complete)
    if $result.exit_code != 0 {
        error make {msg: $"Failed to extract public-mix metadata: ($result.stderr)"}
    }
    ["-m" "workload_mix_version=1" "-m" "workload_mix_weighting=gas" "-m" $"workload_mix_weights=($result.stdout | str trim)"]
}

# TXGEN_NEOBANK_MODULES: comma-separated neobank modules (empty: all), in module order.
def txgen-neobank-modules [value: string] {
    let known = ($TXGEN_HELPER_NEOBANK_MODULES | columns)
    let requested = ($value | split row "," | each { |name| $name | str trim } | where { |name| $name != "" })
    let unknown = ($requested | where { |name| $name not-in $known })
    if ($unknown | is-not-empty) {
        error make {msg: $"unknown neobank module\(s\): ($unknown | str join ', '); expected ($known | str join ', ')"}
    }
    if ($requested | is-empty) { $known } else { $known | where { |name| $name in $requested } }
}

# Keeps the mix entries of the given modules. Weights are relative gas shares, so the
# remaining entries renormalise.
def txgen-neobank-filter-mix [mix: list<any>, modules: list<string>] {
    let families = ($modules | each { |module| $TXGEN_HELPER_NEOBANK_MODULES | get $module } | flatten)
    let filtered = ($mix | where { |entry| ($entry | get -o template | default "") in $families })
    if ($filtered | is-empty) {
        error make {msg: $"neobank modules ($modules | str join ',') select no mix templates"}
    }
    $filtered
}

# Splits total items into contiguous [start, end) ranges proportional to shares
# (largest remainder), each holding at least minimum items.
def txgen-split-ranges [total: int, shares: list<number>, minimum: int] {
    let count = ($shares | length)
    if $total < $count * $minimum {
        error make {msg: $"cannot split ($total) into ($count) ranges of at least ($minimum)"}
    }
    let spare = $total - $count * $minimum
    let share_sum = ($shares | math sum)
    let exact = ($shares | each { |share| $spare * $share / $share_sum })
    let floors = ($exact | each { |value| $value | math floor | into int })
    let extra = ($exact | enumerate
        | sort-by -r { |item| $item.item - ($item.item | math floor) }
        | first ($spare - ($floors | math sum)) | get index)
    let sizes = ($floors | enumerate | each { |item| $minimum + $item.item + (if $item.index in $extra { 1 } else { 0 }) })
    $sizes | enumerate | each { |item|
        let start = ($sizes | first $item.index | append 0 | math sum)
        [$start ($start + $item.item)]
    }
}

# Deployment shapes (presets/shapes/README.md) as neobank-multi instances. A flow's
# weight is split evenly over its templates; the shape's modules are those its
# templates belong to, and their other templates get weight 0. Share defaults to the
# peak transaction rate (tx_per_month times peak_factor).
def txgen-deployment-shapes [path: string, --presets-dir: string = ""] {
    let presets_dir = if $presets_dir == "" { txgen-presets-dir } else { $presets_dir }
    let shapes = (open $path | get -o shapes | default [])
    if ($shapes | is-empty) { error make {msg: $"($path) lists no deployment shapes"} }
    let known = ($TXGEN_HELPER_NEOBANK_MODULES | values | flatten)
    $shapes | each { |shape|
        let name = ($shape | get -o name | default "")
        if not ($name =~ '^[a-z][a-z0-9-]*$') {
            error make {msg: $"deployment shape name '($name)' must be lowercase letters, digits and hyphens"}
        }
        let pillar = ($shape | get -o pillar | default "")
        if $pillar not-in $TXGEN_HELPER_SHAPE_PILLARS {
            error make {msg: $"deployment shape ($name) pillar '($pillar)' must be one of ($TXGEN_HELPER_SHAPE_PILLARS | str join ', ')"}
        }
        let volume = ($shape | get -o volume | default {})
        let tx = ($volume | get -o tx_per_month | default 0)
        if ($tx | describe) not-in [int float] or $tx <= 0 {
            error make {msg: $"deployment shape ($name) needs a positive volume.tx_per_month"}
        }
        let peak = ($volume | get -o peak_factor | default 1)
        if ($peak | describe) not-in [int float] or $peak < 1 {
            error make {msg: $"deployment shape ($name) volume.peak_factor must be at least 1"}
        }
        let flows = ($shape | get -o flows | default {})
        if not ($flows | describe | str starts-with "record") or ($flows | is-empty) {
            error make {msg: $"deployment shape ($name) needs flows: a map of flow names to weight and templates"}
        }
        let rows = ($flows | transpose flow spec | each { |row|
            let weight = ($row.spec | get -o weight | default 0)
            if ($weight | describe) not-in [int float] or $weight <= 0 {
                error make {msg: $"deployment shape ($name) flow ($row.flow) needs a positive weight"}
            }
            let templates = ($row.spec | get -o templates | default [])
            if ($templates | describe | str starts-with "list") == false or ($templates | is-empty) {
                error make {msg: $"deployment shape ($name) flow ($row.flow) needs a list of templates"}
            }
            let unknown = ($templates | where { |template| $template not-in $known })
            if ($unknown | is-not-empty) {
                error make {msg: $"deployment shape ($name) flow ($row.flow) names unknown neobank-generic template\(s\) ($unknown | str join ', ')"}
            }
            $templates | each { |template| {template: $template, weight: ($weight / ($templates | length))} }
        } | flatten)
        let used = ($rows | get template | uniq)
        let modules = ($TXGEN_HELPER_NEOBANK_MODULES | transpose module templates
            | where { |module| $module.templates | any { |template| $template in $used } } | get module)
        let weights = ($modules | each { |module| $TXGEN_HELPER_NEOBANK_MODULES | get $module } | flatten
            | reduce --fold {} { |template, acc|
                $acc | insert $template ($rows | where template == $template | get weight | append 0 | math sum)
            })
        for preset in ($shape | get -o presets | default []) {
            if not ($presets_dir | path join $"($preset).yml" | path exists) {
                error make {msg: $"deployment shape ($name) lists unknown preset ($preset)"}
            }
        }
        {
            name: $name
            share: ($shape | get -o share | default ($tx * $peak))
            modules: $modules
            weights: $weights
            peak_tps: ($tx / $TXGEN_HELPER_SECONDS_PER_MONTH * $peak)
        }
    }
}

# neobank-multi instances: name (a traffic shape, never a customer), gas share and
# modules (default all), from TXGEN_NEOBANK_INSTANCES or presets/neobank/instances.yml.
# A deployment-shapes file (a top-level shapes key) is converted to instances.
def txgen-neobank-instances [path: string, --presets-dir: string = ""] {
    let instances = if (open $path | get -o shapes) != null {
        txgen-deployment-shapes $path --presets-dir $presets_dir
    } else {
        open $path | get -o instances | default []
    }
    if ($instances | is-empty) { error make {msg: $"($path) lists no neobank instances"} }
    let parsed = ($instances | each { |instance|
        let name = ($instance | get -o name | default "")
        if not ($name =~ '^[a-z][a-z0-9-]*$') {
            error make {msg: $"neobank instance name '($name)' must be lowercase letters, digits and hyphens"}
        }
        let share = ($instance | get -o share | default 0)
        if ($share | describe) not-in [int float] or $share <= 0 {
            error make {msg: $"neobank instance ($name) needs a positive share"}
        }
        let modules = ($instance | get -o modules | default [])
        let modules = if ($modules | describe) == string { $modules } else { $modules | str join "," }
        let modules = (txgen-neobank-modules $modules)
        let weights = ($instance | get -o weights | default {})
        if ($weights | describe | str starts-with "record") == false {
            error make {msg: $"neobank instance ($name) weights must map template names to weights"}
        }
        let enabled = ($modules | each { |module| $TXGEN_HELPER_NEOBANK_MODULES | get $module } | flatten)
        for item in ($weights | transpose template weight) {
            if $item.template not-in ($TXGEN_HELPER_NEOBANK_MODULES | values | flatten) {
                error make {msg: $"neobank instance ($name) weights name unknown template ($item.template)"}
            }
            if $item.template not-in $enabled {
                error make {msg: $"neobank instance ($name) weights ($item.template), which is outside its modules"}
            }
            if ($item.weight | describe) not-in [int float] or $item.weight < 0 {
                error make {msg: $"neobank instance ($name) weight for ($item.template) must be a non-negative number"}
            }
        }
        {name: $name, id: ($name | str replace --all "-" "_"), share: $share, modules: $modules, weights: $weights,
            peak_tps: ($instance | get -o peak_tps)}
    })
    if ($parsed | get id | uniq | length) != ($parsed | length) {
        error make {msg: "neobank instance names must be unique"}
    }
    $parsed
}

# An instance's mix: neobank-generic's entries for its modules, with its weight
# overrides applied; a zero weight drops the template.
def txgen-neobank-instance-mix [mix: list<any>, instance: record] {
    let weights = ($instance | get -o weights | default {})
    let entries = (txgen-neobank-filter-mix $mix $instance.modules
        | each { |entry| $entry | update weight ($weights | get -o $entry.template | default $entry.weight) }
        | where weight > 0)
    if ($entries | is-empty) { error make {msg: $"neobank instance ($instance.name) has no templates with positive weight"} }
    $entries
}

# Lines under one top-level key of a YAML file, read as text.
def txgen-raw-section-lines [path: string, key: string] {
    let lines = (open --raw $path | lines)
    let start = ($lines | enumerate | where item == $"($key):" | get -o 0.index)
    if $start == null { return [] }
    $lines | skip ($start + 1) | take while { |line| not ($line =~ '^[A-Za-z_]') }
}

# A preset's own templates as raw text blocks keyed by name. Copies made by text
# replacement keep u64 nonce bounds (which Nushell's YAML parser cannot hold) and
# ${TXGEN_*} placeholders exactly as written.
def txgen-raw-template-blocks [path: string] {
    txgen-raw-section-lines $path templates | reduce --fold {current: null, blocks: {}} { |line, acc|
        let header = ($line | parse --regex '^  (?<name>[A-Za-z0-9_]+):\s*$')
        if ($header | is-not-empty) {
            let name = ($header | first | get name)
            {current: $name, blocks: ($acc.blocks | insert $name [$line])}
        } else if $acc.current == null {
            $acc
        } else {
            let block = ($acc.blocks | get $acc.current | append $line)
            {current: $acc.current, blocks: ($acc.blocks | update $acc.current $block)}
        }
    } | get blocks | items { |name, block|
        {name: $name, value: ($block | str join "\n" | str trim --right)}
    } | transpose -r -d
}

# Instance index's copy of a single-account sink: the instance number (1-based) in the
# address's top two bytes.
def txgen-neobank-sink [address: string, index: int] {
    $"0x(($index + 1) | fill --alignment right --character '0' --width 4)($address | str substring 6..)"
}

# Copies a raw template or setup block for one instance: its own sender pool, sinks
# and keychain setup.
def txgen-neobank-instance-text [text: string, instance: record, index: int] {
    let pool = $"users_($instance.id)"
    let text = ($text
        | str replace --all --regex '(?m)pool: users([,}]|$)' ('pool: ' + $pool + '${1}')
        | str replace --all "authorize_keychain_users" $"authorize_keychain_($instance.id)")
    $TXGEN_HELPER_NEOBANK_SINKS | reduce --fold $text { |sink, acc|
        $acc | str replace --all $sink (txgen-neobank-sink $sink $index)
    }
}

# Several neobank setups side by side (see neobank-multi.yml). Each instance gets a
# disjoint user slice with its own random-sender and treasury pools, sinks, keychain
# setup, vault/zone templates and portals (when zones >= instances); its mix is its
# share times its modules' neobank-generic weights renormalised within the instance.
def txgen-prepare-neobank-multi-preset [spec_path: string, count: int, accounts: int, zones: int, chain_id: int, output_dir: string] {
    let presets = ($spec_path | path dirname)
    # A relative TXGEN_NEOBANK_INSTANCES path resolves from the working directory, then the repository root.
    let preset_name = ($spec_path | path basename | str replace --regex '\.yml$' '')
    let config = ($env.TXGEN_NEOBANK_INSTANCES? | default ($presets | path join ($TXGEN_HELPER_NEOBANK_MULTI_PRESETS | get $preset_name)))
    let config = if ($config | path exists) { $config } else { [ (txgen-repo-root) $config ] | path join }
    if not ($config | path exists) { error make {msg: $"neobank instances file not found: ($config)"} }
    let instances = (txgen-neobank-instances $config --presets-dir $presets)
    let targets = ($instances | where peak_tps != null)
    if ($targets | is-not-empty) {
        let summary = ($targets | each { |shape| $"($shape.name) ($shape.peak_tps | math round --precision 1)" } | str join ", ")
        print $"Deployment shapes peak target: ($targets | get peak_tps | math sum | math round --precision 1) TPS \(($summary)\)"
    }
    let base_path = ($presets | path join neobank-generic.yml)
    let result = (^uv run --no-project --with yq==3.4.3 yq -c '.mix' $base_path | complete)
    if $result.exit_code != 0 { error make {msg: $"Failed to read neobank-generic mix: ($result.stderr)"} }
    let base_mix = ($result.stdout | from json)
    let shares = ($instances | get share)
    let share_sum = ($shares | math sum)
    # Two users per instance at least: its refund sender is the slice's second user.
    let user_ranges = (txgen-split-ranges $accounts $shares 2)
    let zone_ranges = if $zones >= ($instances | length) {
        txgen-split-ranges $zones $shares 1
    } else {
        $instances | enumerate | each { |item| let zone = $item.index mod $zones; [$zone ($zone + 1)] }
    }
    let groups = ($user_ranges | zip $zone_ranges | each { |pair| {users: $pair.0, zones: $pair.1} })
    let deposits = (open (txgen-prepare-vault-preset ($presets | path join vault-deposit.yml) $accounts $chain_id))
    let withdrawals = (open (txgen-prepare-vault-preset ($presets | path join vault-withdraw.yml) $accounts $chain_id))
    let zone_spec = (open (txgen-prepare-zones-preset ($presets | path join zones.yml) $count $accounts $zones mixed --groups $groups))
    let vault_setup = (open ($presets | path join vault setup.yml)).setup.steps
    let users = ($withdrawals.append.setup.steps | each { |step|
        $step | update tx.calls.0.args.1 "2000000000000000000000000"
    })
    let recipients = ($env.TXGEN_BATCH_PAYOUT_RECIPIENTS? | default ($TXGEN_HELPER_BATCH_PAYOUT_RECIPIENTS | get neobank-multi) | into int)
    let batch = (txgen-batch-payout-templates $presets $recipients)
    let raw = (txgen-raw-template-blocks ($presets | path join public-mix.yml) | merge (txgen-raw-template-blocks $base_path))
    let keychain_lines = (txgen-raw-section-lines ($presets | path join access-key-mix.yml) setup | skip 1)
    if ($keychain_lines | where { |line| $line =~ '^    - ' } | length) != 1 {
        error make {msg: "access-key-mix.yml setup must hold exactly one keychain step"}
    }
    let keychain_step = ($keychain_lines | str join "\n" | str trim --right)
    let expiring = { |template| $template | upsert expiring_nonce true | upsert valid_for_secs 25 }

    let parts = ($instances | enumerate | each { |item|
        let index = $item.index
        let instance = $item.item
        let range = ($user_ranges | get $index)
        let instance_share = $instance.share / $share_sum
        let families = (txgen-neobank-instance-mix $base_mix $instance)
        let family_total = ($families | get weight | math sum)
        let in_slice = { |template| $template.from.select.index >= $range.0 and $template.from.select.index < $range.1 }
        let entries = ($families | each { |entry|
            let family = $entry.template
            let prefix = $"($instance.name)/"
            let members = if $family in [vault_deposit vault_withdraw] {
                let source = if $family == vault_deposit { $deposits.templates } else { $withdrawals.templates }
                $range.0..<$range.1 | each { |user|
                    {name: $"($prefix)($family)_($user)", rel: 1, template: (do $expiring ($source | get $"($family)_($user)"))}
                }
            } else if $family == card_settlement {
                let card_account = (txgen-neobank-sink $TXGEN_HELPER_CARD_SETTLEMENT_ACCOUNT $index)
                let end = ([$range.1 ($range.0 + $TXGEN_HELPER_CARD_SETTLEMENT_SENDERS)] | math min)
                $range.0..<$end | each { |user|
                    let source = (do $expiring ($withdrawals.templates | get $"vault_withdraw_($user)"))
                    {name: $"($prefix)card_settlement_($user)", rel: 1,
                        template: (txgen-card-settlement-template $source --account $card_account)}
                }
            } else if $family in [zone_deposit zone_withdraw] {
                $zone_spec.mix | where { |zone|
                    ($zone.template | str starts-with $"($family)_") and (do $in_slice ($zone_spec.templates | get $zone.template))
                } | each { |zone|
                    {name: $"($prefix)($zone.template)", rel: $zone.weight, template: (do $expiring ($zone_spec.templates | get $zone.template))}
                }
            } else if $family in ($batch | columns) {
                let template = ($batch | get $family | to json -r
                    | str replace --all '"pool":"treasury"' $'"pool":"treasury_($instance.id)"'
                    | str replace --all '"pool":"users"' $'"pool":"users_($instance.id)"' | from json)
                [{name: $"($prefix)($family)", rel: 1, template: $template}]
            } else if $family in ($raw | columns) {
                let text = (txgen-neobank-instance-text ($raw | get $family) $instance $index
                    | str replace --regex '^  [A-Za-z0-9_]+:' $'  "($prefix)($family)":')
                [{name: $"($prefix)($family)", rel: 1, raw: $text}]
            } else {
                error make {msg: $"neobank-multi has no template for ($family)"}
            }
            let rel_total = ($members | get rel | math sum)
            $members | each { |member|
                let weight = ($instance_share * $entry.weight / $family_total * $member.rel / $rel_total * $TXGEN_HELPER_NEOBANK_WEIGHT_SCALE)
                $member | insert weight ([1 ($weight | math round | into int)] | math max)
            }
        } | flatten)
        let treasury_end = ([$range.1 ($range.0 + $TXGEN_HELPER_BATCH_TREASURY_SIZE)] | math min)
        let keychain = if ($families | any { |entry| $entry.template | str starts-with "keychain_" }) {
            let keys = ($range | each { |user| $TXGEN_HELPER_KEYCHAIN_ACCESS_KEYS_START + $user | into string })
            [(txgen-neobank-instance-text $keychain_step $instance $index
                | str replace '${TXGEN_KEYCHAIN_ACCESS_KEYS_START}' $keys.0
                | str replace '${TXGEN_KEYCHAIN_ACCESS_KEYS_END}' $keys.1)]
        } else { [] }
        {
            accounts: {
                $"users_($instance.id)": {mnemonic: $TXGEN_HELPER_ACCOUNT_MNEMONIC, range: $range}
                $"treasury_($instance.id)": {mnemonic: $TXGEN_HELPER_ACCOUNT_MNEMONIC, range: [$range.0 $treasury_end]}
            }
            entries: $entries
            keychain: $keychain
            dex: ($families | any { |entry| $entry.template == "dex_swap" })
        }
    })
    let entries = ($parts | get entries | flatten)
    let templates = ($entries | where { |entry| ($entry | get -o template) != null }
        | each { |entry| {name: $entry.name, value: $entry.template} } | transpose -r -d)
    let raw_templates = ($entries | where { |entry| ($entry | get -o raw) != null } | get raw)
    let accounts_record = ($parts | get accounts | reduce --fold {users: {range: [0 $accounts]}} { |pools, acc| $acc | merge $pools })
    let dex_setup = if ($parts | any { |part| $part.dex }) {
        let result = (^uv run --no-project --with yq==3.4.3 yq -c '.append.setup.steps' ($presets | path join dex walls.yml) | complete)
        if $result.exit_code != 0 { error make {msg: $"Failed to read dex setup: ($result.stderr)"} }
        $result.stdout | from json
    } else { [] }
    mkdir $output_dir
    # Copied templates stay text: included as a separate file next to the rendered spec.
    let raw_name = "neobank-multi-templates.yml"
    $"# Per-instance copies of neobank-generic templates, rendered by helpers.nu.\ntemplates:\n($raw_templates | str join "\n")\n"
        | save -f ($output_dir | path join $raw_name)
    let body = ({include: [($spec_path | path expand) $raw_name], accounts: $accounts_record,
        setup: {steps: ($vault_setup | append $users | append $zone_spec.setup.steps | append $dex_setup)},
        templates: $templates,
        mix: ($entries | each { |entry| {template: $entry.name, weight: $entry.weight} })} | to yaml)
    # Keychain steps hold ${TXGEN_*} placeholders: appended as text after the setup above.
    let keychain = ($parts | get keychain | flatten)
    let append = if ($keychain | is-empty) { "" } else {
        "append:\n  setup:\n    steps:\n" + ($keychain | str join "\n" | lines | each { |line| $"  ($line)" } | str join "\n") + "\n"
    }
    let output = ($output_dir | path join ($spec_path | path basename))
    $body + $append | save -f $output
    $output
}


# Reuse the standalone renderers, preserving aggregate transaction shares even
# when users and portals have different counts. Keep each fixture nonce lane in
# order; separate vault/zone deployers and explicit dependencies allow overlap.
def txgen-prepare-public-mix-preset [spec_path: string, count: int, accounts: int, zones: int, chain_id: int, --out-dir: string = ""] {
    # Keep u64 nonce bounds out of Nushell's YAML parser; only the mix and setup
    # presence are needed to compose the workload.
    let result = (^uv run --no-project --with yq==3.4.3 yq -c '
        {has_setup: ((.setup.steps // []) | length > 0), mix: .mix}
    ' $spec_path | complete)
    if $result.exit_code != 0 {
        error make {msg: $"Failed to read public-mix spec: ($result.stderr)"}
    }
    let spec = ($result.stdout | from json)
    # The render command has already composed this spec. Consume it unchanged.
    if $spec.has_setup {
        return $spec_path
    }
    if $zones < 1 { error make {msg: "Public mix requires at least one zone"} }
    let preset_name = ($spec_path | path basename | str replace --regex '\.yml$' '')
    if $preset_name in ($TXGEN_HELPER_NEOBANK_MULTI_PRESETS | columns) {
        let output_dir = if $out_dir == "" {
            [ (txgen-repo-root) $TXGEN_HELPER_DEFAULT_RENDERED_SPECS_DIR (random uuid) ] | path join
        } else { $out_dir | path expand }
        return (txgen-prepare-neobank-multi-preset $spec_path $count $accounts $zones $chain_id $output_dir)
    }
    let spec = if $preset_name == "neobank-generic" {
        $spec | update mix (txgen-neobank-filter-mix $spec.mix (txgen-neobank-modules ($env.TXGEN_NEOBANK_MODULES? | default "")))
    } else { $spec }
    let presets = ($spec_path | path dirname)
    let deposits = (open (txgen-prepare-vault-preset ($presets | path join vault-deposit.yml) $accounts $chain_id))
    let withdrawals = (open (txgen-prepare-vault-preset ($presets | path join vault-withdraw.yml) $accounts $chain_id))
    let zone_spec = (open (txgen-prepare-zones-preset ($presets | path join zones.yml) $count $accounts $zones mixed))
    let vault_setup = (open ($presets | path join vault setup.yml)).setup.steps
    # Seed withdrawal shares and retain equally deep pathUSD balances for deposits.
    let users = ($withdrawals.append.setup.steps | each { |step|
        $step | update tx.calls.0.args.1 "2000000000000000000000000"
    })
    let zone_weight = ($zone_spec.mix | where { |entry| $entry.template | str starts-with "zone_deposit_" } | get weight | math sum)
    let scale = $accounts * $zone_weight
    mut mix = []
    for entry in $spec.mix {
        let name = ($entry | get -o template | default "")
        if $name in [vault_deposit vault_withdraw] {
            let entries = if $name == vault_deposit { $deposits.mix } else { $withdrawals.mix }
            $mix = ($mix | append ($entries | each { |item| $item | update weight ($entry.weight * $zone_weight) }))
        } else if $name == card_settlement {
            # Card shards: the first users' vault redemptions forwarded to the settlement account,
            # alongside ordinary withdrawals. Shards split the entry's aggregate weight.
            let shards = ($withdrawals.mix | where { |item|
                ($item.template | str replace "vault_withdraw_" "" | into int) < $TXGEN_HELPER_CARD_SETTLEMENT_SENDERS
            })
            let per_shard = ($entry.weight * $scale // ($shards | length))
            $mix = ($mix | append ($shards | each { |item|
                {template: ($item.template | str replace "vault_withdraw_" "card_settlement_"), weight: $per_shard}
            }))
        } else if $name in [zone_deposit zone_withdraw] {
            let entries = ($zone_spec.mix | where { |item| $item.template | str starts-with $"($name)_" })
            $mix = ($mix | append ($entries | each { |item| $item | update weight ($item.weight * $entry.weight * $accounts) }))
        } else {
            $mix = ($mix | append ($entry | update weight ($entry.weight * $scale)))
        }
    }
    let output_dir = if $out_dir == "" {
        [ (txgen-repo-root) $TXGEN_HELPER_DEFAULT_RENDERED_SPECS_DIR (random uuid) ] | path join
    } else { $out_dir | path expand }
    mkdir $output_dir
    # Keep the preset's file name: reports derive the preset label from it.
    let output = ($output_dir | path join ($spec_path | path basename))
    # Match the other public-mix workloads without account-nonce dependencies.
    # Setup and standalone vault/zone presets retain their ordered nonce lanes.
    let templates = ($deposits.templates | merge $withdrawals.templates | merge $zone_spec.templates
        | items { |name, template|
            {name: $name, value: ($template | upsert expiring_nonce true | upsert valid_for_secs 25)}
        } | transpose -r -d)
    let templates = if $preset_name in $TXGEN_HELPER_SINGLE_SENDER_PRESETS {
        txgen-single-sender-templates $templates
    } else { $templates }
    let batch_recipients = ($TXGEN_HELPER_BATCH_PAYOUT_RECIPIENTS | get -o $preset_name)
    let templates = if $batch_recipients != null {
        let recipients = ($env.TXGEN_BATCH_PAYOUT_RECIPIENTS? | default $batch_recipients | into int)
        $templates | merge (txgen-batch-payout-templates $presets $recipients)
    } else { $templates }
    let templates = ($mix
        | where { |entry| ($entry | get -o template | default "") | str starts-with "card_settlement_" }
        | reduce --fold $templates { |entry, acc|
            let source = ($templates | get ($entry.template | str replace "card_settlement_" "vault_withdraw_"))
            $acc | insert $entry.template (txgen-card-settlement-template $source)
        })
    let card = if $preset_name in $TXGEN_HELPER_CARD_SETTLEMENT_PRESETS {
        txgen-card-settlement $templates $mix
    } else { {templates: $templates, mix: $mix} }
    let templates = $card.templates
    let mix = $card.mix
    # Asset conversion swaps on the stablecoin DEX need dex/walls.yml's liquidity walls.
    let dex_setup = if ($spec.mix | any { |entry| ($entry | get -o template) == "dex_swap" }) {
        let result = (^uv run --no-project --with yq==3.4.3 yq -c '.append.setup.steps' ($presets | path join dex walls.yml) | complete)
        if $result.exit_code != 0 { error make {msg: $"Failed to read dex setup: ($result.stderr)"} }
        $result.stdout | from json
    } else { [] }
    # Delegated-key payments need access-key-mix.yml's per-user keychain setup.
    let keychain_setup = if ($spec.mix | any { |entry| ($entry | get -o template | default "") | str starts-with "keychain_" }) {
        let result = (^uv run --no-project --with yq==3.4.3 yq -c '.setup.steps' ($presets | path join access-key-mix.yml) | complete)
        if $result.exit_code != 0 { error make {msg: $"Failed to read access-key setup: ($result.stderr)"} }
        $result.stdout | from json
    } else { [] }
    {include: $spec_path, accounts: {users: {range: [0 $accounts]}},
        setup: {steps: ($vault_setup | append $users | append $zone_spec.setup.steps | append $dex_setup | append $keychain_setup)},
        templates: $templates,
        mix: $mix} | to yaml | save -f $output
    $output
}

# The TXGEN_* variables bench-env sets, read through bash's export as the sender's
# pipeline does, so quoting and expansion match what the sender sees.
def txgen-bench-env-txgen-vars [bench_env: string] {
    if ($bench_env | str trim) == "" { return {} }
    let result = (with-env {TXGEN_HELPER_BENCH_ENV: $bench_env} {
        ^bash -c 'eval "export $TXGEN_HELPER_BENCH_ENV" && env -0' | complete
    })
    if $result.exit_code != 0 { error make {msg: $"invalid bench-env: ($result.stderr | str trim)"} }
    let names = ($bench_env | parse --regex '(?:^|\s)(?<name>TXGEN_[A-Z0-9_]+)=' | get name)
    $result.stdout | split row (char nul) | where { |line| ($line | split row "=" | first) in $names }
        | parse --regex '^(?<key>[^=]+)=(?<value>[\s\S]*)$'
        | reduce --fold {} { |item, acc| $acc | upsert $item.key $item.value }
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
    # Size zones and label metadata with the same TXGEN_* values the render used.
    load-env (txgen-bench-env-txgen-vars $bench_env)
    let chain_id = (txgen-fetch-chain-id $generate_rpc_url)
    $env.TXGEN_ACCOUNTS = ($accounts | into string)
    mut spec_path = ($preset_path | path expand)
    if not ($spec_path | path exists) {
        error make { msg: $"txgen preset file not found: ($spec_path)" }
    }
    let tx_token_count = if $tip20_token_count > 0 { $tip20_token_count } else { $bloat_token_count }
    txgen-configure-tip20-token-env $tx_token_count
    txgen-configure-keychain-env $accounts $tx_token_count
    txgen-configure-existing-recipients-env $spec_path $bloat_mib $bloat_token_count
    txgen-configure-fee-amm-env $spec_path
    let preset_name = ($spec_path | path basename | str replace --regex '\.yml$' '')
    let is_public_mix = $preset_name in $TXGEN_HELPER_PUBLIC_MIX_PRESETS
    let is_zone_to_zone = $preset_name in $TXGEN_HELPER_ZONE_TO_ZONE_PRESETS
    # Zones and vaults generate the full count: setup must not consume workload duration.
    let full_count = $preset_name in ["zones" "vault-deposit" "vault-withdraw"]
    let tx_count = [($tps * $duration) 1] | math max
    mut zone_metadata = []
    if $preset_name == "zones" or $is_public_mix or $is_zone_to_zone {
        if $chain_id != 1337 or $accounts < 1 or $accounts > 100000 {
            error make { msg: "zones requires local chain 1337 and 1–100000 accounts" }
        }
        let portal_code = (txgen-rpc-call $generate_rpc_url '{"jsonrpc":"2.0","id":1,"method":"eth_getCode","params":["0x5ad1000000000000000000000000000000000000","latest"]}')
        if $portal_code.result == "0x" {
            error make { msg: "zones requires the ZonePortal runtime; activate T10 or later before running the benchmark" }
        }
        let nonce_response = (txgen-rpc-call $generate_rpc_url '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionCount","params":["0xd7932ce865275be97001a0574441d79b143820ec","pending"]}')
        let latest_nonce = (txgen-rpc-call $generate_rpc_url '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionCount","params":["0xd7932ce865275be97001a0574441d79b143820ec","latest"]}')
        if $nonce_response.result != $latest_nonce.result {
            error make { msg: "zone fixture deployer has pending transactions; drain its nonce lane before setup" }
        }
        let mode = ($env.TXGEN_ZONE_MODE? | default "mixed")
        # TIP-1096 allows 230 outstanding deposits, reserving 20 for bounce-backs.
        # This is a configurable sizing window, not a claimed mainnet settlement cadence.
        let window_ms = ($env.TXGEN_ZONE_SETTLEMENT_WINDOW_MS? | default "3000" | into int)
        if $window_ms < 1 { error make { msg: "TXGEN_ZONE_SETTLEMENT_WINDOW_MS must be positive" } }
        let automatic_zones = ([1 (($tps * $window_ms / 210000) | math ceil | into int)] | math max)
        let zones = (txgen-zone-count $preset_name $automatic_zones)
        if $zones < 1 { error make { msg: "TXGEN_ZONE_COUNT must be positive" } }
        # Zone -> zone needs a source and a target portal; the hot variant uses exactly those two.
        let zones = if $preset_name == "zone-to-zone-hot" { 2 } else if $is_zone_to_zone { [$zones 2] | math max } else { $zones }
        $zone_metadata = ["-m" $"zone_count=($zones)" "-m" $"zone_sizing_window_ms=($window_ms)"]
        if $is_zone_to_zone {
            let config = (txgen-zone-to-zone-config)
            $zone_metadata = ($zone_metadata | append [
                "-m" $"zone_to_zone_access=($config.access)" "-m" $"zone_to_zone_share=($config.share)"
                "-m" $"zone_to_zone_callback_gas=($config.callback_gas)" "-m" $"zone_to_zone_gas_limit=($config.gas_limit)"
            ])
        }
        print $"  Zones: ($zones), users: ($accounts), sizing window: ($window_ms)ms, capacity: 210 deposits/portal"
        $spec_path = if $is_public_mix {
            txgen-prepare-public-mix-preset $spec_path $tx_count $accounts $zones $chain_id
        } else if $is_zone_to_zone {
            txgen-prepare-zone-to-zone-preset $spec_path $tx_count $accounts $zones --hot=($preset_name == "zone-to-zone-hot")
        } else {
            txgen-prepare-zones-preset $spec_path $tx_count $accounts $zones $mode
        }
    }
    let skip_faucet_funding = $skip_funding and ($preset_name not-in $TXGEN_HELPER_ALWAYS_FUND_PRESETS)
    let is_vault = $preset_name in ["vault-deposit" "vault-withdraw"]
    if $is_vault {
        $spec_path = (txgen-prepare-vault-preset $spec_path $accounts $chain_id)
    }
    if $is_vault or $is_public_mix {
        # The checked-in deployments use fixed nonces and transfer policy 2.
        # Check before funding or submitting any setup transactions.
        let deployer_nonce = (txgen-rpc-call $generate_rpc_url '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionCount","params":["0xd7932ce865275be97001a0574441d79b143820ec","pending"]}')
        let policy_counter = (txgen-rpc-call $generate_rpc_url '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0x403c000000000000000000000000000000000000","data":"0x3cc32f9c"},"pending"]}')
        if ($deployer_nonce.result | into int) != 0 or ($policy_counter.result | into int) != 2 {
            error make { msg: "Vault presets require a fresh fixture: deployers[0] nonce must be 0 and TIP-403 policyIdCounter must be 2. Restore the benchmark snapshot before rerunning." }
        }
    }
    let existing_recipient_start = ($env | get --optional TXGEN_EXISTING_RECIPIENTS_START | default "0" | into int)
    let existing_recipient_end = ($env | get --optional TXGEN_EXISTING_RECIPIENTS_END | default "0" | into int)
    let uses_existing_recipients = (txgen-spec-effective-text $spec_path) =~ '(?m)^\s*existing_recipients:\s*$'
    let recipient_accounts = if $preset_name in $TXGEN_HELPER_POLICY_PRESETS {
        $accounts
    } else if $uses_existing_recipients and $existing_recipient_end > $existing_recipient_start {
        $existing_recipient_end - $existing_recipient_start
    } else {
        0
    }
    let total_accounts = $accounts + $recipient_accounts
    let workload_metadata = (txgen-workload-metadata-args $preset_name $spec_path)
    if $preset_name in $TXGEN_HELPER_POLICY_PRESETS {
        $spec_path = (txgen-prepare-tip20-policy $spec_path $generate_rpc_url $tx_token_count $accounts)
    }
    if not $skip_faucet_funding {
        txgen-fund-accounts $txgen_tempo_bin $spec_path $generate_rpc_url
    }

    let txgen_duration = $"($duration)s"
    let txgen_cmd = [
        $txgen_tempo_bin
        "generate"
        "-s" $spec_path
        "-n" $tx_count
        "--seed" $TXGEN_HELPER_DEFAULT_SEED
        "--rpc" $generate_rpc_url
    ] | append (if $full_count { [] } else { ["--duration" $txgen_duration] })
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
        | append (if $clickhouse_url != "" {
            ["--report" $"clickhouse:($clickhouse_url)" "--clickhouse-metrics-file" ([ (txgen-repo-root) $TXGEN_HELPER_CLICKHOUSE_METRICS_FILE ] | path join)]
        } else { [] })
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
        | append $workload_metadata
        | append $zone_metadata
        | append (if $recipient_accounts > 0 { ["-m" $"recipient_accounts=($recipient_accounts)"] } else { [] })
        | append (if $benchmark_id != "" { ["-m" $"benchmark_id=($benchmark_id)"] } else { [] })
        | append (if $benchmark_run != "" { ["-m" $"benchmark_run=($benchmark_run)"] } else { [] })
        | append (if $run_type != "" { ["-m" $"run_type=($run_type)"] } else { [] })
        | append (if $platform != "" { ["-m" $"platform=($platform)"] } else { [] })
        | append (txgen-scenario-metadata-args $scenario $spec_path)
        | append (if $pr_number != "" { ["-m" $"pr_number=($pr_number)"] } else { [] })
        | append (if $initial_db_size_bytes > 0 { ["-m" $"initial_db_size_bytes=($initial_db_size_bytes)"] } else { [] })
    let bench_cmd = $bench_base_cmd | append $report_args | append $metadata_args

    let bench_env_export = if $bench_env != "" { $"export ($bench_env) && " } else { "" }
    let txgen_extra_args = (txgen-parse-bench-args $bench_args)
    let setup_state_path = $"($report_path).setup.json"
    let gas_mix_args = ["--gas-weighted-mix" "--setup-state-in" $setup_state_path]
    let workload_extra_args = ($txgen_extra_args | where { |arg| $arg != "--gas-weighted-mix" })
    let txgen_cmd_str = (txgen-shell-join ($txgen_cmd | append $workload_extra_args | append $gas_mix_args))
    let bench_cmd = $bench_cmd | append "--skip-setup"
    let bench_cmd = if $is_vault { $bench_cmd | append ["--drain-timeout" "300"] } else { $bench_cmd }
    let bench_cmd_str = (txgen-shell-join $bench_cmd)
    let pipeline = $"set -euo pipefail; ($bench_env_export)ulimit -Sn unlimited && ($txgen_cmd_str) | ($bench_cmd_str)"

    let setup_state_args = ["--setup-state-out" $setup_state_path]
    let txgen_setup_cmd_str = (txgen-shell-join ($txgen_setup_cmd | append $workload_extra_args | append $setup_state_args))
    let bench_setup_cmd_str = (txgen-shell-join ($bench_send_base_cmd | append ["--drain-timeout" 0]))
    let setup_pipeline = $"set -euo pipefail; ($bench_env_export)ulimit -Sn unlimited && ($txgen_setup_cmd_str) | ($bench_setup_cmd_str)"

    print "  Confirming setup before gas sampling..."
    let setup_result = (bash -lc $setup_pipeline | complete)
    if $setup_result.stdout != "" { print $setup_result.stdout }
    if $setup_result.stderr != "" { print $setup_result.stderr }

    if $setup_result.exit_code != 0 {
        return { ok: false, exit_code: $setup_result.exit_code, report_path: $report_path }
    }

    if $full_count {
        print $"  Streaming ($tx_count) ($preset_name) transactions at target ($tps) TPS into bench send..."
    } else {
        print $"  Streaming up to ($tx_count) txgen transaction\(s\) over ($txgen_duration) into bench send..."
    }
    let check_receipts = $is_vault or $preset_name == "tip20-policy" or $is_zone_to_zone
    let workload_start_block = if $check_receipts {
        (txgen-rpc-call $generate_rpc_url '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}').result | into int
    } else { 0 }
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

    if $preset_name in ["zones" "vault-deposit" "vault-withdraw" "tip20-policy"] and (open $report_path).failed > 0 {
        print $"ERROR: ($preset_name) workload contains sender failures; see ($report_path)"
        return { ok: false, exit_code: 1, report_path: $report_path }
    }
    if $check_receipts {
        # Check block receipts after bench drains the pool, without polling every transaction.
        let report = (open $report_path)
        let expected = if $is_vault { $tx_count } else { $report.sent }
        let deadline = (date now) + 60sec
        mut next_block = $workload_start_block + 1
        mut included = 0
        mut reverted = 0
        mut zone_to_zone = []
        while $included < $expected and (date now) < $deadline {
            let last = (txgen-rpc-call $generate_rpc_url '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}').result | into int
            while $next_block <= $last {
                let block = ($next_block | format number | get lowerhex)
                let payload = ({jsonrpc: "2.0", id: 1, method: eth_getBlockReceipts, params: [$block]} | to json -r)
                let receipts = (txgen-rpc-call $generate_rpc_url $payload).result | where type == "0x76"
                $included = $included + ($receipts | length)
                $reverted = $reverted + ($receipts | where status == "0x0" | length)
                if $is_zone_to_zone and ($receipts | is-not-empty) {
                    $zone_to_zone = ($zone_to_zone | append (txgen-zone-to-zone-tally $receipts))
                }
                $next_block = $next_block + 1
            }
            # An empty pool can precede canonical inclusion of the last built block.
            if $included < $expected { sleep 200ms }
        }
        print $"  ($preset_name) receipts: ($included) included, ($reverted) reverted, ($report.sent) submitted"
        if $is_zone_to_zone {
            # Bounce-backs and saturation are results, not harness failures; report them.
            let transfers = ($zone_to_zone | get -o transfers | default [] | math sum)
            let gas = ($zone_to_zone | get -o transfer_gas | default [] | math sum)
            let summary = {
                included: $included
                reverted: $reverted
                transfers: $transfers
                delivered: ($zone_to_zone | get -o delivered | default [] | math sum)
                bounced: ($zone_to_zone | get -o bounced | default [] | math sum)
                plain_withdrawals: ($zone_to_zone | get -o plain_withdrawals | default [] | math sum)
                gas_per_transfer: (if $transfers > 0 { $gas // $transfers } else { 0 })
                max_transfers_per_block: ($zone_to_zone | get -o transfers | default [0] | math max)
                blocks_with_transfers: ($zone_to_zone | where transfers > 0 | length)
            }
            print $"  zone-to-zone: ($summary.transfers) transfers, ($summary.delivered) delivered, ($summary.bounced) bounced, ($summary.plain_withdrawals) plain withdrawals, ($summary.reverted) reverted; ($summary.gas_per_transfer) gas/transfer; up to ($summary.max_transfers_per_block) transfers/block over ($summary.blocks_with_transfers) blocks"
            $summary | to json | save -f $"($report_path).zone-to-zone.json"
            if $summary.delivered == 0 {
                error make { msg: "zone-to-zone workload delivered no transfers" }
            }
        } else if $expected == 0 or $included != $expected or $reverted != 0 {
            error make { msg: $"($preset_name) workload did not include the full transaction count successfully" }
        }
    }
    print $"  Report saved: ($report_path)"
    { ok: true, exit_code: 0, report_path: $report_path }
}
