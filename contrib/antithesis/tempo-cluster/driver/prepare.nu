source /app/contrib/bench/txgen/helpers.nu

def main [rpc: string] {
    $env.TXGEN_ACCOUNTS = "16"
    txgen-configure-tip20-token-env 4
    txgen-configure-keychain-env 16 4
    # A small, shared genesis supplies existing recipients instead of a state-bloat dump.
    $env.TXGEN_EXISTING_RECIPIENTS_START = "16"
    $env.TXGEN_EXISTING_RECIPIENTS_END = "64"
    let spec = (txgen-prepare-public-mix-preset (txgen-preset-path public-mix) 1000000000 16 2 1337 --out-dir /state)
    $env | columns | where {|name| $name | str starts-with 'TXGEN_'}
        | reduce --fold {} {|name, acc| $acc | insert $name ($env | get $name)}
        | to json | save -f /state/env.json
    txgen-fund-accounts txgen-tempo $spec $rpc
}
