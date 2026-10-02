#!/usr/bin/env python3
"""Run isolated local-node load trials; retain data, logs, metrics and reports.

Build tempo and tempo-bench first. Each trial uses fresh genesis state, loopback
RPC, no peers, and the public test mnemonic. No existing node data is modified.
"""

import argparse
import json
import pathlib
import platform
import socket
import subprocess
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
MNEMONIC = "test test test test test test test test test test test junk"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(url, method):
    data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": []}).encode()
    req = urllib.request.Request(url, data, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as response:
        result = json.load(response)
        if "error" in result:
            raise RuntimeError(result["error"])
        return result["result"]


def metrics(url, path):
    with urllib.request.urlopen(url, timeout=10) as response:
        path.write_bytes(response.read())


def trial(args, threads, target):
    directory = args.output / f"workers-{threads}-target-{target}"
    directory.mkdir(parents=True, exist_ok=False)
    rpc_port, auth_port, metrics_port = free_port(), free_port(), free_port()
    rpc = f"http://127.0.0.1:{rpc_port}"
    metrics_url = f"http://127.0.0.1:{metrics_port}/metrics"
    node_cmd = [str(ROOT / "target/release/tempo"), "node",
                "--chain", str(ROOT / "crates/node/tests/assets/test-genesis.json"),
                "--datadir", str(directory / "data"), "--dev", "--dev.block-time", "100ms",
                "--http", "--http.port", str(rpc_port), "--http.api", "eth,net,web3,txpool",
                "--authrpc.port", str(auth_port), "--port", "0", "--disable-discovery",
                "--ipcdisable", "--metrics", f"127.0.0.1:{metrics_port}",
                "--rpc.max-connections", "4096", "--txpool.pending-max-count", "500000",
                "--txpool.pending-max-size", "1024", "--txpool.queued-max-count", "500000",
                "--txpool.queued-max-size", "1024", "--engine.disable-prewarming",
                "--execution.threads", str(threads), "--execution.batch-size", str(args.batch_size),
                "--log.file.directory", str(directory / "logs"), "--log.stdout.filter", "info"]
    bench_cmd = [str(ROOT / "target/release/tempo-bench"), "run-max-tps",
                 "--tps", str(target), "--duration", str(args.duration), "--accounts", "100",
                 "--mnemonic", MNEMONIC, "--target-urls", rpc, "--fd-limit", "65536",
                 "--max-concurrent-requests", "256", "--max-concurrent-transactions", "10000",
                 "--benchmark-mode", f"local-workers-{threads}-{args.nonces}"]
    if args.nonces == "2d":
        bench_cmd.append("--use-2d-nonces")
    (directory / "commands.json").write_text(json.dumps({"node": node_cmd, "bench": bench_cmd}, indent=2) + "\n")
    with (directory / "node.log").open("wb") as log:
        node = subprocess.Popen(node_cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 30
            while True:
                if node.poll() is not None:
                    raise RuntimeError(f"node failed; see {directory / 'node.log'}")
                try:
                    request(rpc, "eth_chainId")
                    break
                except (OSError, RuntimeError):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.1)
            metrics(metrics_url, directory / "metrics-before.prom")
            with (directory / "bench.log").open("wb") as bench_log:
                subprocess.run(bench_cmd, cwd=directory, stdout=bench_log, stderr=subprocess.STDOUT,
                               timeout=args.duration + 180, check=True)
            metrics(metrics_url, directory / "metrics-after.prom")
            report = json.loads((directory / "report.json").read_text())
            sending = report["sending"]
            print(json.dumps({"workers": threads, "target_tps": target, **sending}), flush=True)
        finally:
            node.terminate()
            try:
                node.wait(timeout=30)
            except subprocess.TimeoutExpired:
                node.kill()
                node.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--targets", default="10000,25000,50000,75000")
    parser.add_argument("--workers", default="0,16")
    parser.add_argument("--duration", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--nonces", choices=["2d", "expiring"], default="2d")
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "host.json").write_text(json.dumps({"platform": platform.platform(),
        "processor": platform.processor(), "source": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT))}, indent=2) + "\n")
    for threads in map(int, args.workers.split(",")):
        for target in map(int, args.targets.split(",")):
            trial(args, threads, target)


if __name__ == "__main__":
    main()
