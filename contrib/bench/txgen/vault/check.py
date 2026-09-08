"""Run a vault preset through the benchmark helper and check on-chain receipts.

Requires a fresh disposable local Tempo node with its faucet enabled, Nushell,
txgen-tempo and bench. Use a fresh data directory for each preset.
"""

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc", default="http://127.0.0.1:18545")
    parser.add_argument("--preset", choices=["deposit", "withdraw"], required=True)
    parser.add_argument("--txgen-bin", default="txgen-tempo")
    parser.add_argument("--bench-bin", default="bench")
    args = parser.parse_args()
    if urlparse(args.rpc).hostname not in ("localhost", "127.0.0.1", "::1"):
        parser.error("only a disposable loopback node is supported")

    def rpc(method, *params):
        request = Request(
            args.rpc,
            json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
            ).encode(),
            {"Content-Type": "application/json"},
        )
        with urlopen(request, timeout=30) as response:
            result = json.load(response)
        if "error" in result:
            raise RuntimeError(result["error"])
        return result["result"]

    assert int(rpc("eth_chainId"), 16) == 1337
    first_block = int(rpc("eth_blockNumber"), 16) + 1
    root = Path(__file__).resolve().parents[4]
    with tempfile.TemporaryDirectory(prefix="vault-preset-check-") as directory:
        report_path = Path(directory) / "report.json"
        env = os.environ | {
            "CHECK_RPC": args.rpc,
            "CHECK_PRESET": str(
                root / f"contrib/bench/txgen/presets/vault-{args.preset}.yml"
            ),
            "CHECK_TXGEN": args.txgen_bin,
            "CHECK_BENCH": args.bench_bin,
            "CHECK_REPORT": str(report_path),
        }
        subprocess.run(
            [
                "nu",
                "-c",
                (
                    "source contrib/bench/txgen/helpers.nu; "
                    "let result = (txgen-run-preset-pipeline "
                    "--txgen-tempo-bin $env.CHECK_TXGEN --txgen-bench-bin $env.CHECK_BENCH "
                    "--preset-path $env.CHECK_PRESET "
                    "--generate-rpc-url $env.CHECK_RPC --submit-rpc-url $env.CHECK_RPC "
                    "--metrics-url [] --report-path $env.CHECK_REPORT "
                    "--tps 10 --duration 3 --accounts 3 --max-concurrent-requests 10); "
                    "if not $result.ok { error make {msg: 'vault benchmark failed'} }"
                ),
            ],
            cwd=root,
            env=env,
            check=True,
        )
        report = json.loads(report_path.read_text())
        assert report["sent"] == report["success"] == 30
        assert report["failed"] == 0
        last_block = int(rpc("eth_blockNumber"), 16)
        receipts = [
            receipt
            for number in range(first_block, last_block + 1)
            for receipt in rpc("eth_getBlockReceipts", hex(number))
        ]
        assert receipts and all(receipt["status"] == "0x1" for receipt in receipts)
        workload_blocks = {block["number"] for block in report["blocks"]}
        workload = [r for r in receipts if int(r["blockNumber"], 16) in workload_blocks]
        assert len(workload) == 30
        # Check that the multi-user setup was exercised, not just the fixture owner.
        assert len({receipt["from"].lower() for receipt in workload}) == 3
        assert all(receipt["logs"] for receipt in workload)
        print(
            f"{args.preset}: all {len(receipts)} receipts succeeded; 30 workload transactions across 3 users"
        )


if __name__ == "__main__":
    main()
