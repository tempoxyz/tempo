#!/usr/bin/env python3
"""Real four-validator light-client smoke test; no mock certificates or proof-success paths.

Requires a freshly built tempo binary, Cargo and Foundry cast. Public development credentials
only. All processes/listeners are local and are stopped on exit. Output contains public evidence,
logs and measurements, not production keys. This is not the complete security/load acceptance suite.
"""
import argparse
import concurrent.futures
import json
import os
import pathlib
import platform
import statistics
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
OWNER = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
HOLDER = "0x000000000000000000000000000000000000cafe"
TOKEN = "0x20c0000000000000000000000000000000000001"
PATH_USD = "0x20c0000000000000000000000000000000000000"
VALIDATORS = "0xcccccccc00000000000000000000000000000001"
EPOCH_LENGTH = 100


def rpc(url, method, params=(), allow_error=False):
    body = json.dumps(dict(jsonrpc="2.0", id=1, method=method, params=params)).encode()
    with urllib.request.urlopen(urllib.request.Request(url, body, {"Content-Type": "application/json"}), timeout=20) as response:
        result = json.load(response)
    if "error" in result:
        if allow_error:
            return result
        raise RuntimeError(f"{method}: {result['error']}")
    return result["result"]


def wait_for(probe, timeout=120):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            result = probe()
            if result:
                return result
        except (OSError, RuntimeError) as error:
            last = error
        time.sleep(0.1)
    raise RuntimeError(f"timed out waiting for devnet condition: {last}")


def cast(*args):
    environment = dict(os.environ, FOUNDRY_DISABLE_NIGHTLY_WARNING="1")
    result = subprocess.run(["cast", *map(str, args)], text=True, capture_output=True, env=environment)
    if result.returncode:
        raise RuntimeError(f"cast {args[0]} failed: {result.stdout} {result.stderr}")
    return result.stdout.strip()


class Proxy(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, address, upstream):
        super().__init__(address, Handler)
        self.upstream = upstream
        self.mode = "honest"
        self.changed = 0
        self.account_only = 0
        self.proof_started = threading.Event()
        self.proof_release = threading.Event()
        self.slow_hash = None
        self.counts = {}
        self.bytes = {}
        self.gate = threading.BoundedSemaphore(8)

    def process_request(self, request, address):
        if not self.gate.acquire(False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.gate.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.gate.release()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 65536:
                self.send_error(413)
                return
            request = json.loads(self.rfile.read(size))
            method = request["method"]
            is_proof = method in ("eth_getProof", "eth_getMultiProof")
            grouped = []
            if is_proof:
                selector = request["params"][-1]
                assert isinstance(selector, dict) and "blockHash" in selector and selector.get("requireCanonical") is True
                grouped = request["params"][0] if method == "eth_getMultiProof" else [(request["params"][0], request["params"][1])]
            has_slots = any(slots for _, slots in grouped)
            account_only = bool(grouped) and not has_slots
            if account_only:
                self.server.account_only += 1
            body = json.dumps(request).encode()
            with urllib.request.urlopen(urllib.request.Request(self.server.upstream, body, {"Content-Type": "application/json"}), timeout=10) as upstream:
                response = json.load(upstream)
            self.server.counts[method] = self.server.counts.get(method, 0) + 1
            if (self.server.mode == "slow" and has_slots
                    and "result" in response
                    and self.server.slow_hash is None):
                # Hold one genuine, already generated, hash-pinned proof while new blocks arrive.
                self.server.slow_hash = selector["blockHash"]
                self.server.proof_started.set()
                self.server.proof_release.wait(timeout=10)
            if self.server.mode == "scalar" and is_proof and "result" in response:
                proofs = response["result"] if isinstance(response["result"], list) else [response["result"]]
                for proof in proofs:
                    if proof["storageProof"]:
                        slot = proof["storageProof"][0]
                        slot["value"] = hex(int(slot["value"], 16) ^ 1)
                        self.server.changed += 1
            encoded = json.dumps(response).encode()
            self.server.bytes[method] = self.server.bytes.get(method, 0) + len(encoded)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        except (OSError, ValueError, AssertionError, KeyError):
            self.send_error(502)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tempo-bin", default="target/debug/tempo")
    parser.add_argument("--workdir", type=pathlib.Path, required=True)
    parser.add_argument("--base-port", type=int, default=13000)
    args = parser.parse_args()
    binary = str(pathlib.Path(args.tempo_bin).resolve())
    work = args.workdir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    genesis_dir = work / "devnet"
    if genesis_dir.exists():
        raise RuntimeError("use a fresh workdir; this test never overwrites an existing devnet")
    ports = [args.base_port + i * 10 for i in range(4)]
    addresses = [f"127.0.0.1:{port}" for port in ports]
    with (work / "genesis.log").open("w") as log:
        subprocess.run(["cargo", "run", "-p", "tempo-xtask", "--", "generate-localnet", "--output", str(genesis_dir), "--accounts", "10", "--seed", "73", "--epoch-length", str(EPOCH_LENGTH), "--validators", ",".join(addresses)], stdout=log, stderr=subprocess.STDOUT, check=True)
    secret = work / "public-devnet-passphrase"
    secret.write_text("tempo-localnet-signing-key-secret\n")
    secret.chmod(0o600)
    peers = ",".join(f"enode://{(genesis_dir / address / 'enode.identity').read_text().strip()}@127.0.0.1:{port + 1}" for address, port in zip(addresses, ports))
    processes = []
    logs = []
    proxy = None
    secondary_proxy = None
    try:
        def spawn(name, options):
            log = (work / f"{name}.log").open("w")
            logs.append(log)
            process = subprocess.Popen([binary, "node", *options], stdout=log, stderr=subprocess.STDOUT)
            processes.append(process)
            return process

        urls = []
        for index, (address, port) in enumerate(zip(addresses, ports)):
            directory = genesis_dir / address
            urls.append(f"http://127.0.0.1:{port + 5}")
            spawn(f"validator-{index}", ["--chain", str(genesis_dir / "genesis.json"), "--datadir", str(directory), "--consensus.signing-key", str(directory / "signing.key"), "--consensus.secret", str(secret), "--consensus.signing-share", str(directory / "signing.share"), "--consensus.listen-address", address, "--consensus.metrics-address", f"127.0.0.1:{port + 2}", "--consensus.use-local-defaults", "--consensus.target-block-time", "200ms", "--trusted-peers", peers, "--port", str(port + 1), "--disable-discovery", "--p2p-secret-key", str(directory / "enode.key"), "--authrpc.port", str(port + 3), "--http", "--http.addr", "127.0.0.1", "--http.port", str(port + 5), "--http.api", "all", "--rpc.eth-proof-window", "128"])
        for url in urls:
            wait_for(lambda url=url: int(rpc(url, "eth_blockNumber"), 16) > 2)
        proxy = Proxy(("127.0.0.1", args.base_port + 50), urls[0])
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        secondary_proxy = Proxy(("127.0.0.1", args.base_port + 52), urls[1])
        threading.Thread(target=secondary_proxy.serve_forever, daemon=True).start()
        api = f"http://127.0.0.1:{args.base_port + 51}"
        light_options = ["--chain", str(genesis_dir / "genesis.json"), "--light", "--light.datadir", str(work / "light"), "--light.listen", f"127.0.0.1:{args.base_port + 51}", "--light.upstream", f"http://127.0.0.1:{args.base_port + 50}", "--light.upstream", f"http://127.0.0.1:{args.base_port + 52}", "--light.poll-interval-ms", "100", "--light.request-timeout-ms", "10000"]
        started = time.monotonic()
        light = spawn("light", light_options)
        wait_for(lambda: rpc(api, "light_status")["durable"])
        startup_seconds = time.monotonic() - started
        requests = [dict(kind="balance", token=TOKEN, holder=OWNER), dict(kind="balance", token=TOKEN, holder=HOLDER), dict(kind="allowance", token=TOKEN, owner=OWNER, spender=HOLDER), dict(kind="totalSupply", token=TOKEN)]

        def compare():
            result = rpc(api, "light_readVerified", [requests])
            selector = dict(blockHash=result["block"]["hash"], requireCanonical=True)
            calls = [("balanceOf(address)", OWNER), ("balanceOf(address)", HOLDER), ("allowance(address,address)", OWNER, HOLDER), ("totalSupply()",)]
            expected = [int(rpc(urls[0], "eth_call", [dict(to=TOKEN, data=cast("calldata", *call)), selector]), 16) for call in calls]
            assert [int(value, 16) for value in result["values"]] == expected
            return result

        def send(address, signature, *arguments, check=True):
            receipt = json.loads(cast("send", address, signature, *arguments, "--private-key", KEY, "--rpc-url", urls[0], "--gas-limit", "1000000", "--json"))
            assert int(receipt["status"], 16) == 1, receipt
            height = int(receipt["blockNumber"], 16)
            wait_for(lambda: (rpc(api, "light_status")["head"] or {}).get("height", -1) >= height)
            return compare() if check else height

        operations = {"initial": compare()}
        # Even when AlphaUSD's storage root is unchanged, a fresh global root requires full
        # proofs for missing reads, without a speculative account-only round trip.
        proofs_before = proxy.counts.get("eth_getMultiProof", 0)
        operations["unchangedTokenRoot"] = send(PATH_USD, "transfer(address,uint256)", HOLDER, 19)
        assert proxy.counts.get("eth_getMultiProof", 0) > proofs_before
        assert proxy.account_only == secondary_proxy.account_only == 0
        send(TOKEN, "grantRole(bytes32,address)", cast("keccak", "ISSUER_ROLE"), OWNER)
        operations["mint"] = send(TOKEN, "mint(address,uint256)", HOLDER, 1000)
        operations["transfer"] = send(TOKEN, "transfer(address,uint256)", HOLDER, 123)
        operations["approve"] = send(TOKEN, "approve(address,uint256)", HOLDER, 456)
        operations["burn"] = send(TOKEN, "burn(uint256)", 17)

        # A held real proof must finish at its original block, even after a real mint changes the
        # token root and head publication advances. The subsequent read must see the new value.
        slow_request = dict(kind="balance", token=TOKEN, holder="0x000000000000000000000000000000000000a010")
        proxy.mode = "slow"
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as reader:
                pending = reader.submit(rpc, api, "light_readVerified", [[slow_request]])
                assert proxy.proof_started.wait(timeout=10), "no real proof reached the hold point"
                try:
                    mint_height = send(TOKEN, "mint(address,uint256)", slow_request["holder"], 999, check=False)
                    assert rpc(api, "light_status")["head"]["hash"] != proxy.slow_hash
                finally:
                    proxy.proof_release.set()
                retained = pending.result(timeout=15)
            assert retained["block"]["hash"] == proxy.slow_hash
            assert int(retained["values"][0], 16) == 0
        finally:
            proxy.proof_release.set()
            proxy.mode = "honest"
        updated = rpc(api, "light_readVerified", [[slow_request]])
        assert int(updated["values"][0], 16) == 999
        assert updated["block"]["height"] >= mint_height
        operations["retainedReadDuringMint"] = retained
        operations["subsequentReadAfterMint"] = updated

        # Stop before a genuine full-DKG key change, then authenticate catch-up from disk.
        head = rpc(api, "light_status")["head"]
        rotation_epoch = head["height"] // EPOCH_LENGTH + 1
        send(VALIDATORS, "setNetworkIdentityRotationEpoch(uint64)", rotation_epoch)
        before = json.loads((work / "light/checkpoint.json").read_text())["checkpoint"]["identity"]
        stop(light)
        wait_for(lambda: int(rpc(urls[0], "eth_blockNumber"), 16) >= (rotation_epoch + 1) * EPOCH_LENGTH + 3, timeout=180)
        resumed = time.monotonic()
        light = spawn("light-restarted", light_options)
        wait_for(lambda: (rpc(api, "light_status")["head"] or {}).get("height", 0) >= (rotation_epoch + 1) * EPOCH_LENGTH + 3)
        catchup_seconds = time.monotonic() - resumed
        checkpoint = json.loads((work / "light/checkpoint.json").read_text())
        assert checkpoint["checkpoint"]["identity"]["identity"] != before["identity"], "full DKG did not rotate the signing key"
        assert checkpoint["checkpoint"]["transition"] is not None
        operations["afterRotation"] = compare()

        # A real proxy corrupts a real proof; independent verification rejects it, then fails over.
        failures = rpc(api, "light_status")["integrityFailures"]
        proxy.mode = "scalar"
        zero = dict(kind="balance", token=TOKEN, holder="0x000000000000000000000000000000000000a001")
        result = rpc(api, "light_readVerified", [[zero]])
        assert int(result["values"][0], 16) == 0
        assert proxy.changed > 0
        assert rpc(api, "light_status")["integrityFailures"] > failures
        # Losing the honest provider must produce an explicit error, never a forged value or zero.
        stop(processes[1])
        # Force another global-root change, leaving AlphaUSD untouched. Corrupt the full proof
        # for a mixed previously-read/new-slot batch: neither a new account mapping nor a partial
        # result may be published.
        send(PATH_USD, "transfer(address,uint256)", HOLDER, 1, check=False)
        entries_before = rpc(api, "light_status")["accountCacheEntries"]
        zero["holder"] = "0x000000000000000000000000000000000000a002"
        failure = rpc(api, "light_readVerified", [[requests[0], zero]], allow_error=True)
        assert "error" in failure and failure["error"]["code"] == -32010, failure
        assert "result" not in failure
        assert proxy.account_only == secondary_proxy.account_only == 0
        assert rpc(api, "light_status")["accountCacheEntries"] == entries_before
        proxy.mode = "honest"
        missing = dict(kind="balance", token="0x20c0999999999999999999999999999999999999", holder=HOLDER)
        assert "error" in rpc(api, "light_readVerified", [[missing]], allow_error=True)
        assert "error" in rpc(api, "eth_sendRawTransaction", ["0x"], allow_error=True)

        latencies = []
        for _ in range(100):
            start = time.monotonic()
            rpc(api, "light_readVerified", [requests])
            latencies.append((time.monotonic() - start) * 1000)
        report = dict(platform=platform.platform(), transport="loopback HTTP", validators=4, targetBlockMillis=200, epochLength=EPOCH_LENGTH, startupSeconds=startup_seconds, restartAcrossRotationSeconds=catchup_seconds, readBatchSize=len(requests), readSamples=100, readLatencyMillis=dict(p50=statistics.median(latencies), p95=sorted(latencies)[94], max=max(latencies)), proxyRequestCounts=proxy.counts, proxyResponseBytes=proxy.bytes, accountOnlyRequests=proxy.account_only, operations=operations, finalStatus=rpc(api, "light_status"))
        (work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        # Public conformance capture pinned to the exact returned block (not a production anchor).
        selected = compare()
        evidence = rpc(urls[0], "consensus_getFinalizedHeader", [dict(height=selected["block"]["height"])])
        assert evidence["digest"] == selected["block"]["hash"]
        slots = []
        for holder in (OWNER, HOLDER):
            slots.append(cast("keccak", "0x" + holder[2:].zfill(64) + hex(9)[2:].zfill(64)))
        owner_slot = cast("keccak", "0x" + OWNER[2:].zfill(64) + hex(10)[2:].zfill(64))
        slots.append(cast("keccak", "0x" + HOLDER[2:].zfill(64) + owner_slot[2:]))
        slots.append("0x" + hex(8)[2:].zfill(64))
        proof = rpc(urls[0], "eth_getProof", [TOKEN, slots, dict(blockHash=selected["block"]["hash"], requireCanonical=True)])
        capture = dict(formatVersion=1, layout="V1", checkpoint=checkpoint, requests=requests, verifiedRead=selected, evidence=evidence, responses=[proof])
        (work / "conformance.json").write_text(json.dumps(capture, indent=2) + "\n")
        stop(light)
        assert {path.name for path in (work / "light").iterdir()} == {"lock", "checkpoint.json"}, "light mode created unexpected execution/archive files"
        print(json.dumps({key: value for key, value in report.items() if key != "operations"}, indent=2))
        print(f"PASS: real operations, direct proofs without account-only probes, retained slow snapshot, atomic failed batch, exact-block reference, key rotation, restart, malicious-proof failover; evidence and logs in {work}")
    finally:
        for process in reversed(processes):
            stop(process)
        for server in (proxy, secondary_proxy):
            if server:
                server.shutdown()
                server.server_close()
        for log in logs:
            log.close()


if __name__ == "__main__":
    main()
