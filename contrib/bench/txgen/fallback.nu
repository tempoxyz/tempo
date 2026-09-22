# Benchmark-only fixtures for successful first-token vs second-token fallback.
# Use only against the two local chain-1337 benchmark nodes.

def fallback-rpc [rpc: string, method: string, params: list] {
    let response = (http post --content-type application/json $rpc ({jsonrpc: "2.0", id: 1, method: $method, params: $params} | to json -r))
    let response = if ($response | describe) == "string" { $response | from json } else { $response }
    if ($response | get -o error) != null { error make {msg: ($response.error | to json -r)} }
    $response.result
}

def fallback-read [rpc: string, to: string, selector: string, address: string] {
    let word = ($address | str substring 2.. | fill -a right -c '0' -w 64)
    fallback-rpc $rpc eth_call [{to: $to, data: $"0x($selector)($word)"} latest]
}

def fallback-skip-counters [metrics_urls: list<string>] {
    $metrics_urls | where {|url| $url =~ '^[ab]:http'} | each {|entry|
        let node = ($entry | str substring 0..0)
        let url = ($entry | str substring 2..)
        let lines = (http get --raw $url | lines | where {|line| $line | str starts-with 'reth_tempo_payload_builder_pool_transactions_skipped_total{'})
        let counters = [invalid_tx invalid_replay nonce_too_low] | each {|reason|
            let matching = ($lines | where {|line| $line | str contains $'reason="($reason)"'})
            let total = if ($matching | is-empty) { 0 } else {
                $matching | each {|line| $line | split row --regex '\s+' | get 1 | into float} | math sum | into int
            }
            {reason: $reason, count: $total}
        }
        {node: $node, counters: $counters}
    }
}

def fallback-send [txgen: string, bench: string, spec: string, rpc: string, count: int] {
    let generate = (txgen-shell-join [$txgen generate -s $spec -n $count --seed 99 --rpc $rpc])
    let send = (txgen-shell-join [$bench send --rpc-url $rpc --tps 1000 --max-concurrent 20 --retries 0 --drain-timeout 0])
    let result = (bash -lc $"set -euo pipefail; ($generate) | ($send)" | complete)
    if $result.exit_code != 0 {
        print $result.stdout
        print $result.stderr
        let last = (fallback-rpc $rpc eth_blockNumber [] | into int)
        for height in ([0 ($last - 3)] | math max)..$last {
            let block = ($height | format number | get lowerhex)
            let failed = (fallback-rpc $rpc eth_getBlockReceipts [$block] | where status == "0x0")
            for receipt in ($failed | first 2) {
                print $"FAILED_FIXTURE_RECEIPT ($receipt | select transactionHash status gasUsed feeToken | to json -r)"
            }
        }
        error make {msg: "Fallback benchmark fixture/probe failed"}
    }
    txgen-wait-for-txpool-drain $rpc
}

def fallback-proof [rpc: string, start: int, expected_token: string] {
    let deadline = (date now) + 30sec
    mut next = $start + 1
    while (date now) < $deadline {
        let last = (fallback-rpc $rpc eth_blockNumber [] | into int)
        while $next <= $last {
            let block = ($next | format number | get lowerhex)
            let receipts = (fallback-rpc $rpc eth_getBlockReceipts [$block] | where type == "0x76")
            for receipt in $receipts {
                let tx = (fallback-rpc $rpc eth_getTransactionByHash [$receipt.transactionHash])
                let input = ($tx | get -o input | default "")
                # Tempo RPC exposes AA call inputs inside calls.
                let call = ($tx | get -o calls.0)
                let input = if $call != null { $call | get -o input | default ($call | get -o data | default $input) } else { $input }
                if ($input | str starts-with "0x095ea7b3") {
                    if ($tx | get -o feeToken) != null { error make {msg: "Probe unexpectedly specifies feeToken"} }
                    if $receipt.status != "0x1" or ($receipt.feeToken | str downcase) != $expected_token {
                        error make {msg: "Probe did not succeed using the expected fallback token"}
                    }
                    let header = (fallback-rpc $rpc eth_getBlockByNumber [$block false])
                    let validator_token = (fallback-read $rpc "0xfeec000000000000000000000000000000000000" "6dc54a7a" $header.miner)
                    let validator_token = $"0x($validator_token | str substring 26.. | str downcase)"
                    if $validator_token != "0x20c0000000000000000000000000000000000000" {
                        error make {msg: "Fallback benchmark validator must prefer pathUSD"}
                    }
                    return {transaction_hash: $receipt.transactionHash, status: $receipt.status, fee_token: $receipt.feeToken, validator: $header.miner, validator_fee_token: $validator_token, explicit_fee_token: false, call_selector: "0x095ea7b3"}
                }
            }
            $next = $next + 1
        }
        sleep 200ms
    }
    error make {msg: "No successful fallback probe receipt found"}
}

def fallback-verify-receipts [rpc: string, start: int, expected_count: int, report_path: string] {
    let last = (fallback-rpc $rpc eth_blockNumber [] | into int)
    mut included = 0
    mut reverted = 0
    mut wrong_fee_token = 0
    for height in ($start + 1)..$last {
        let block = ($height | format number | get lowerhex)
        let receipts = (fallback-rpc $rpc eth_getBlockReceipts [$block] | where type == "0x76")
        $included = $included + ($receipts | length)
        $reverted = $reverted + ($receipts | where status != "0x1" | length)
        $wrong_fee_token = $wrong_fee_token + ($receipts | where {|r| ($r.feeToken | str downcase) != "0x20c0000000000000000000000000000000000001"} | length)
    }
    let evidence = {expected: $expected_count, included: $included, reverted: $reverted, wrong_fee_token: $wrong_fee_token}
    $evidence | to json | save -f $"($report_path).receipt-proof.json"
    print $"RECEIPT_PROOF ($evidence | to json -r)"
    if $included != $expected_count or $reverted != 0 or $wrong_fee_token != 0 {
        error make {msg: "Fallback workload did not include every transaction successfully using alphaUSD"}
    }
}

def txgen-prepare-fallback [spec_path: string, txgen: string, bench: string, rpc: string, accounts: int, phase: string, report_path: string] {
    if (fallback-rpc $rpc eth_chainId [] | into int) != 1337 { error make {msg: "Fallback fixture requires local chain 1337"} }
    let alpha = "0x20c0000000000000000000000000000000000001"
    let pathusd = "0x20c0000000000000000000000000000000000000"
    let fee_manager = "0xfeec000000000000000000000000000000000000"
    let expected = $alpha
    let addresses_result = (^$txgen addresses -s $spec_path -f shell | complete)
    if $addresses_result.exit_code != 0 { error make {msg: "Cannot derive fallback fixture accounts"} }
    let addresses = ($addresses_result.stdout | str trim | split row ' ' | where {|a| $a != ''})
    if ($addresses | length) != $accounts { error make {msg: "Unexpected fallback fixture account count"} }

    # Install FeeAMM liquidity before draining pathUSD; this setup is unmeasured.
    fallback-send $txgen $bench $spec_path $rpc 0
    let base_dir = ($spec_path | path dirname)
    let original = (open $spec_path)
    let includes = ($original.include | where {|p| not ($p | str contains "fee-amm-liquidity") } | each {|p| [$base_dir $p] | path join | path expand })
    let workload = ($original | update include $includes)
    let steps = ($addresses | enumerate | each {|entry|
        let balance = (fallback-read $rpc $pathusd "70a08231" $entry.item)
        let amount = $balance
        {id: $"drain_pathusd_($entry.index)", tx: {
            type: tempo, from: {pool: users, select: {index: $entry.index}}, gas_limit: 1000000,
            max_fee_per_gas: 100000000000, max_priority_fee_per_gas: 100000000000,
            fee_token: $alpha, call: {to: $pathusd, abi: ERC20, function: transfer,
                args: ["0x000000000000000000000000000000000000dead" $amount]}
        }}
    })
    let dir = [$base_dir .. .. .. .. .bench-tmp fallback $phase] | path join | path expand
    mkdir $dir
    # Establish the shared recipient balance with a fixed payer first. Otherwise
    # whichever payer wins pool ordering pays the first-write storage gas.
    for batch in [{name: first, steps: ($steps | first 1)}, {name: remaining, steps: ($steps | skip 1)}] {
        let setup_path = [$dir $"setup-($batch.name).yml"] | path join
        $workload | insert setup {steps: $batch.steps} | to yaml | save -f $setup_path
        fallback-send $txgen $bench $setup_path $rpc 0
    }

    # Both sides must start with identical balances and FeeAMM reserves.
    mut balances = []
    for address in $addresses {
        let preference = (fallback-read $rpc $fee_manager "ed498fa8" $address)
        let path_balance = (fallback-read $rpc $pathusd "70a08231" $address)
        let selected_balance = (fallback-read $rpc $expected "70a08231" $address)
        let significant = ($selected_balance | str replace --regex '^0x0*' '')
        let funded = if ($significant | str length) > 4 { true } else {
            ($selected_balance | into int) >= 30000
        }
        if not ($preference =~ '^0x0+$') or not ($path_balance =~ '^0x0+$') or not $funded {
            error make {msg: $"Fallback preconditions failed for ($address): preference=($preference), pathUSD=($path_balance), selected=($selected_balance)"}
        }
        $balances = ($balances | append {address: $address, alpha: $selected_balance, pathusd: $path_balance, preference: $preference})
    }
    let alpha_word = ($alpha | str substring 2.. | fill -a right -c '0' -w 64)
    let path_word = ($pathusd | str substring 2.. | fill -a right -c '0' -w 64)
    let pool = (fallback-rpc $rpc eth_call [{to: $fee_manager, data: $"0x531aa03e($alpha_word)($path_word)"} latest])
    let initial_state = {payers: $balances, alpha_pathusd_pool: $pool}
    let state_digest = ($initial_state | to json -r | hash sha256)
    $initial_state | to json | save -f $"($report_path).initial-state.json"
    print $"INITIAL_STATE_PROOF ($phase): ($state_digest), pool=($pool)"
    let state_digest_path = ($report_path | path dirname | path join fallback-state.sha256)
    if ($state_digest_path | path exists) {
        if (open --raw $state_digest_path | str trim) != $state_digest { error make {msg: "Fallback payer balances or FeeAMM reserves differ between trials"} }
    } else { $state_digest | save $state_digest_path }
    let workload_path = [$dir workload.yml] | path join
    $workload | to yaml | save -f $workload_path
    let start = (fallback-rpc $rpc eth_blockNumber [] | into int)
    fallback-send $txgen $bench $workload_path $rpc 1
    let proof = (fallback-proof $rpc $start $expected)
    let evidence = {phase: $phase, accounts_checked: $accounts, stored_preferences: 0, all_payer_pathusd_zero: true, initial_state_sha256: $state_digest, alpha_pathusd_pool: $pool, probe: $proof}
    $evidence | to json | save -f $"($report_path).fallback-proof.json"
    print $"FALLBACK_PROOF ($evidence | to json -r)"
    $workload_path
}
