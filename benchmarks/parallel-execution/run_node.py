#!/usr/bin/env python3
"""Run isolated local-node load trials; retain data, logs, metrics and reports.

Build tempo and tempo-bench first. Each trial uses fresh genesis state, loopback
RPC, no peers, and the public test mnemonic. No existing node data is modified.
"""

import argparse
import json
import os
import pathlib
import platform
import shutil
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


def request(url, method, params=None):
    data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
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
    node_cmd = [str(args.node_binary), "node",
                "--chain", str(args.genesis),
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
                 "--max-concurrent-requests", str(args.client_concurrency), "--max-concurrent-transactions", "10000",
                 "--benchmark-mode", f"local-workers-{threads}-{args.nonces}"]
    if args.nonces == "2d":
        bench_cmd.append("--use-2d-nonces")
    node_env = {}
    if args.node_tokio_threads is not None:
        node_env["TOKIO_WORKER_THREADS"] = str(args.node_tokio_threads)
    (directory / "commands.json").write_text(json.dumps({
        "node": node_cmd, "bench": bench_cmd, "node_environment_overrides": node_env,
    }, indent=2) + "\n")
    with (directory / "node.log").open("wb") as log:
        node = subprocess.Popen(node_cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                env={**os.environ, **node_env})
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
            block = request(rpc, "eth_getBlockByNumber", ["latest", False])
            if int(block["gasLimit"], 16) != args.block_gas_limit:
                raise RuntimeError("node block gas limit differs from benchmark genesis")
            metrics(metrics_url, directory / "metrics-before.prom")
            with (directory / "bench.log").open("wb") as bench_log:
                bench = subprocess.Popen(bench_cmd, cwd=directory, stdout=bench_log,
                                         stderr=subprocess.STDOUT)
                profiler = None
                try:
                    (directory / "processes.json").write_text(json.dumps({
                        "node": node.pid, "bench": bench.pid, "start_unix_seconds": time.time(),
                    }, indent=2) + "\n")
                    with (directory / "cpu.log").open("wb") as cpu_log:
                        if args.profile_cpu:
                            profiler = subprocess.Popen([
                                "pidstat", "-u", "-t", "-h", "-H", "-p",
                                f"{node.pid},{bench.pid}", "1",
                            ], stdout=cpu_log, stderr=subprocess.STDOUT)
                        code = bench.wait(timeout=args.duration + 180)
                        if code:
                            raise subprocess.CalledProcessError(code, bench_cmd)
                finally:
                    if bench.poll() is None:
                        bench.kill()
                        bench.wait()
                    if profiler is not None:
                        profiler.terminate()
                        try:
                            profiler.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            profiler.kill()
                            profiler.wait()
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
    parser.add_argument("--node-binary", type=pathlib.Path,
                        default=ROOT / "target/release/tempo")
    parser.add_argument("--client-concurrency", type=int, default=256)
    parser.add_argument("--node-tokio-threads", type=int,
                        help="Override the node's Tokio workers without changing the client's runtime")
    parser.add_argument("--profile-cpu", action="store_true",
                        help="Record per-thread CPU usage for the node and client using pidstat")
    parser.add_argument("--nonces", choices=["2d", "expiring"], default="2d")
    parser.add_argument("--block-gas-limit", type=int,
                        help="Override the gas limit in a fresh benchmark genesis copy")
    args = parser.parse_args()
    if args.client_concurrency <= 0:
        parser.error("--client-concurrency must be positive")
    if args.node_tokio_threads is not None and args.node_tokio_threads <= 0:
        parser.error("--node-tokio-threads must be positive")
    if args.profile_cpu and shutil.which("pidstat") is None:
        parser.error("--profile-cpu requires pidstat")
    if args.block_gas_limit is not None and not 0 < args.block_gas_limit < 2**64:
        parser.error("--block-gas-limit must fit a positive u64")
    args.output = args.output.resolve()
    args.node_binary = args.node_binary.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    args.genesis = ROOT / "crates/node/tests/assets/test-genesis.json"
    genesis = json.loads(args.genesis.read_text())
    if args.block_gas_limit is not None:
        genesis["gasLimit"] = hex(args.block_gas_limit)
        args.genesis = args.output / "genesis.json"
        args.genesis.write_text(json.dumps(genesis, indent=2) + "\n")
    else:
        args.block_gas_limit = int(genesis["gasLimit"], 16)
    (args.output / "host.json").write_text(json.dumps({"platform": platform.platform(),
        "processor": platform.processor(), "block_gas_limit": args.block_gas_limit,
        "tokio_worker_threads": os.environ.get("TOKIO_WORKER_THREADS"),
        "node_tokio_worker_threads": (str(args.node_tokio_threads)
                                      if args.node_tokio_threads is not None
                                      else os.environ.get("TOKIO_WORKER_THREADS")),
        "source": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT))}, indent=2) + "\n")
    for threads in map(int, args.workers.split(",")):
        for target in map(int, args.targets.split(",")):
            trial(args, threads, target)


if __name__ == "__main__":
    main()
