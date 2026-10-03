#!/usr/bin/env nu
# Test-only post-run diagnostics, while the disposable RPC node is still alive.
source helpers.nu

def main [report_path: path, rpc_url: string] {
    let report = (open $report_path)
    let output = ($report_path | path dirname | path join (($report_path | path basename | str replace '.json' '') + '.reverts.json'))
    mut failures = []
    for block in $report.blocks {
        let receipts = (txgen-rpc-call $rpc_url ({jsonrpc: '2.0', id: 1, method: eth_getBlockReceipts,
            params: [($block.number | format number | get lowerhex)]} | to json -r)).result
        for receipt in ($receipts | where status == '0x0') {
            let transaction = (try {
                (txgen-rpc-call $rpc_url ({jsonrpc: '2.0', id: 1, method: eth_getTransactionByHash,
                    params: [$receipt.transactionHash]} | to json -r)).result
            } catch {|error| {diagnostic_error: $error.msg}})
            let trace = (try {
                (txgen-rpc-call $rpc_url ({jsonrpc: '2.0', id: 1, method: debug_traceTransaction,
                    params: [$receipt.transactionHash, {tracer: callTracer, timeout: '10s'}]} | to json -r)).result
            } catch {|error| {diagnostic_error: $error.msg}})
            $failures = ($failures | append {receipt: $receipt, transaction: $transaction, trace: $trace})
            if ($failures | length) >= 5 { break }
        }
        if ($failures | length) >= 5 { break }
    }
    {source_report: ($report_path | path basename), sampled_reverts: ($failures | length), failures: $failures}
        | to json | save -f $output
    print $output
}
