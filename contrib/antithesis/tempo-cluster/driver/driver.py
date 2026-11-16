"""Consensus/public-mix driver. No node-local state is used as a correctness oracle."""
import collections
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

import hegel
from hegel import generators as gs
from antithesis import assertions, lifecycle

URLS = [f"http://validator-{i}:8545" for i in range(4)]
RPC_TIMEOUT = 2
RECOVERY_TIMEOUT = 180
FAULT_CONTROL_TIMEOUT = 10
# A terminal lease, not a permanent pause: even os._exit or a crashed driver
# cannot strand the injector. Leave room for the handshake and the last RPC/
# bounded 64-block receipt scan + 20-second burst to overrun the polling deadline.
RECOVERY_PAUSE_SECONDS = 3600


class FaultControlError(RuntimeError):
    pass


def pause_faults_for_recovery():
    """Return a conservative lease deadline, or None for explicit local output."""
    helper = os.getenv("ANTITHESIS_STOP_FAULTS")
    if helper is None:
        # Compose explicitly selects SDK local output. That variable is also
        # present on-platform, so it is NOT sufficient without excluding every
        # platform marker (including Hegel's unsupported control protocol).
        local = (bool(os.getenv("ANTITHESIS_SDK_LOCAL_OUTPUT"))
                 and not any(name in os.environ for name in (
                     "ANTITHESIS_OUTPUT_DIR", "ANTITHESIS_FAULT_CONTROL"))
                 and not Path("/usr/lib/libvoidstar.so").exists())
        if local:
            print("Local SDK-output mode: no Antithesis fault injector to pause", flush=True)
            return None
        raise FaultControlError("Recovery requires ANTITHESIS_STOP_FAULTS outside local SDK-output mode")
    # Authoritative duration protocol (NOT Hegel 0.4.7's --pause/--unpause):
    # https://antithesis.com/docs/product/writing_tests/controlling_faults/pause_faults/
    # Success means the helper has stopped faults/restored the network and
    # killed containers; their readiness is still checked over RPC below.
    # Clock skips already in progress are not cancelled by this API.
    requested_at = time.monotonic()
    try:
        status = command([helper, str(RECOVERY_PAUSE_SECONDS)], FAULT_CONTROL_TIMEOUT)
    except OSError as error:
        raise FaultControlError("Could not execute ANTITHESIS_STOP_FAULTS") from error
    if status != 0:
        raise FaultControlError(f"ANTITHESIS_STOP_FAULTS handshake failed (status {status})")
    print(f"Fault-pause helper completed for {RECOVERY_PAUSE_SECONDS} seconds", flush=True)
    # Count from BEFORE the handshake, conservatively covering any helper delay.
    return requested_at + RECOVERY_PAUSE_SECONDS


class RpcError(Exception):
    pass


def rpc(url, method, params):
    request = urllib.request.Request(
        url, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        {"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=RPC_TIMEOUT) as response:
            result = json.load(response)
    except (OSError, ValueError, urllib.error.URLError) as error:
        raise RpcError(str(error)) from error
    if "error" in result or "result" not in result:
        raise RpcError(str(result))
    return result["result"]


def block(url, tag):
    value = rpc(url, "eth_getBlockByNumber", [tag, False])
    if value is None:
        raise RpcError(f"block {tag} unavailable")
    # Missing/malformed fields are harness or RPC failures, not agreement evidence.
    try:
        int(value["number"], 16)
        for field in ("hash", "stateRoot", "receiptsRoot", "transactionsRoot"):
            if len(value[field]) != 66:
                raise ValueError(field)
        if not isinstance(value["transactions"], list):
            raise ValueError("transactions")
    except (KeyError, ValueError, TypeError) as error:
        raise RpcError(f"malformed block: {value}") from error
    return value


def fingerprint(value):
    return tuple(value[key] for key in ("hash", "stateRoot", "receiptsRoot", "transactionsRoot"))


def command(args, timeout):
    # Kill the entire generator|sender pipeline on timeout, not just its shell.
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen(args, stdout=log, stderr=log, start_new_session=True)
        try:
            status = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            status = -signal.SIGKILL
        if status != 0:
            log.seek(0, os.SEEK_END)
            log.seek(max(0, log.tell() - 4096))
            print(f"command failed ({status}): {log.read().decode(errors='replace')}", flush=True)
        return status


class Cluster(hegel.StateMachine):
    def __init__(self, urls):
        self.urls = urls
        self.anchors = collections.OrderedDict()
        self.anchor_cursor = 0
        self.highest = [0] * len(urls)
        self.start_height = 0
        self.scanned_height = 0
        self.started = time.monotonic()
        self.successful_receipts = 0
        self.successful_height = 0
        self.seen_receipts = collections.OrderedDict()
        self.bursts = 0
        self.recovery_requested = False
        self.recovery_due = float(os.getenv("EVENTUALLY_AFTER_SECONDS", "0"))

    def observe(self):
        heads = []
        checkpoints = list(self.anchors.items())
        checked = checkpoints[-1:]
        if checkpoints:
            old = checkpoints[self.anchor_cursor % len(checkpoints)]
            if old not in checked:
                checked.append(old)
            self.anchor_cursor += 1
        for node, url in enumerate(self.urls):
            try:
                head = block(url, "finalized")
                height = int(head["number"], 16)
                assertions.always(height >= self.highest[node], "Finalized height never regresses",
                                  {"node": node, "before": self.highest[node], "after": height})
                self.highest[node] = max(self.highest[node], height)
                heads.append((node, height))
                # Check retained checkpoints against every node that has finalized them.
                for checkpoint, expected in checked:
                    if height >= checkpoint:
                        actual = block(url, hex(checkpoint))
                        assertions.always(fingerprint(actual) == expected,
                                          "Finalized checkpoints remain immutable",
                                          {"node": node, "height": checkpoint, "expected": expected,
                                           "actual": fingerprint(actual)})
            except RpcError:
                continue
        if len(heads) < 2:
            return False
        common = min(height for _, height in heads)
        samples = []
        for node, _ in heads:
            try:
                samples.append((node, block(self.urls[node], hex(common))))
            except RpcError:
                pass
        if len(samples) < 2:
            return False
        expected = fingerprint(samples[0][1])
        assertions.always(all(fingerprint(value) == expected for _, value in samples),
                          "Validators agree on finalized block and state roots",
                          {"height": common, "blocks": {str(node): fingerprint(value) for node, value in samples}})
        if common in self.anchors:
            assertions.always(self.anchors[common] == expected, "Repeated finalized reads agree",
                              {"height": common, "expected": self.anchors[common], "actual": expected})
        self.anchors[common] = expected
        while len(self.anchors) > 64:
            self.anchors.popitem(last=False)
        assertions.sometimes(common > self.start_height + 2, "Consensus finalizes new blocks",
                             {"height": common, "setup_height": self.start_height})
        # Scan a bounded prefix of newly finalized blocks, not just the usually-empty tip.
        # Advancing the cursor only after a complete read preserves retries after faults.
        for height in range(max(self.scanned_height, self.start_height) + 1,
                            min(common, max(self.scanned_height, self.start_height) + 64) + 1):
            try:
                finalized = block(self.urls[samples[0][0]], hex(height))
                if finalized["transactions"]:
                    txhash = finalized["transactions"][0]
                    receipt = rpc(self.urls[samples[0][0]], "eth_getTransactionReceipt", [txhash])
                    if receipt is None:
                        break
                    assertions.always(receipt["blockHash"] == finalized["hash"],
                                      "Finalized transaction receipts match their block",
                                      {"tx": txhash, "receipt": receipt})
                    if receipt.get("status") == "0x1" and txhash not in self.seen_receipts:
                        self.successful_receipts += 1
                        self.successful_height = max(self.successful_height, height)
                        self.seen_receipts[txhash] = None
                        while len(self.seen_receipts) > 256:
                            self.seen_receipts.popitem(last=False)
                self.scanned_height = height
            except RpcError:
                break
        assertions.sometimes(self.successful_receipts > 0, "Public mix transactions execute successfully",
                             {"successful_samples": self.successful_receipts, "bursts": self.bursts})
        return len(heads) == len(self.urls) and len(samples) == len(self.urls)

    def wait_ready(self):
        previous = None
        while True:
            try:
                chains = [rpc(url, "eth_chainId", []) for url in self.urls]
                heads = [block(url, "finalized") for url in self.urls]
                if all(chain == "0x539" for chain in chains) and min(int(h["number"], 16) for h in heads) > 1:
                    return
                reason = f"waiting for chain 1337 consensus finality: {chains}, {[h['number'] for h in heads]}"
            except RpcError as error:
                reason = str(error)
            if reason != previous:
                print(reason, flush=True)
                previous = reason
            time.sleep(1)

    @hegel.rule(weight=8)
    def public_mix(self, tc):
        if self.recovery_requested:
            self.recover_with_faults_paused(tc)
        node = tc.draw(gs.integers(min_value=0, max_value=3))
        seed = tc.draw(gs.integers(min_value=0, max_value=2**63 - 1))
        with tempfile.TemporaryDirectory() as directory:
            status = command(["/driver/txgen.sh", "burst", self.urls[node], str(seed), f"{directory}/report.json"], 20)
        self.bursts += 1
        assertions.sometimes(status == 0, "Public mix generator and sender complete a burst", {"node": node})
        # RPC/generation errors while faulting have unknown outcomes, not safety failures.

    @hegel.invariant(always_run=True)
    def finalized_state(self, tc):
        self.observe()
        if self.recovery_due and time.monotonic() - self.started >= self.recovery_due:
            self.recovery_requested = True

    @hegel.rule()
    def eventually(self, tc):
        if self.recovery_requested or (os.getenv("DISABLE_EVENTUALLY", "0") != "1"
                                       and tc.draw(gs.weighted_booleans(0.002))):
            self.recover_with_faults_paused(tc)

    def recover_with_faults_paused(self, tc):
        # Only terminal recovery requests a lease; normal rounds retain faults.
        # Do not rely on Hegel's pause_faults=True: pinned 0.4.7 silently no-ops
        # without ANTITHESIS_FAULT_CONTROL, which this platform does not expose.
        quiet_until = pause_faults_for_recovery()
        recovery = hegel.Machine(tc).steps(1)
        recovery.rule("idle", lambda _: None)
        recovery.invariant("recovery", lambda _: self.recover(quiet_until), always_run=True)
        recovery.run()

    def recover(self, quiet_until):
        target = max(self.highest) + 3
        before = self.successful_receipts
        deadline = time.monotonic() + RECOVERY_TIMEOUT
        print(f"Recovery assertions start: all validators must finalize past {target}", flush=True)
        # Rules run on one worker, so no burst overlaps the recovery window.
        sent = False
        sent_height = None
        recovered = False
        while time.monotonic() < deadline:
            available = self.observe()
            if available and min(self.highest) >= target and not sent:
                sent_height = max(self.highest)
                with tempfile.TemporaryDirectory() as directory:
                    sent = command(["/driver/txgen.sh", "burst", self.urls[0], "99", f"{directory}/report.json"], 20) == 0
            if available and min(self.highest) >= target and sent and self.successful_height > sent_height and self.successful_receipts > before:
                recovered = True
                break
            time.sleep(1)
        if quiet_until is not None and time.monotonic() >= quiet_until:
            raise FaultControlError("Recovery exceeded the fault-pause lease; liveness result is invalid")
        assertions.always(recovered, "Cluster resumes finality and successful transactions after faults stop",
                          {"target": target, "heights": self.highest, "successful_samples": self.successful_receipts - before})
        Path("/state/recovery-result.json").write_text(json.dumps({"recovered": recovered, "heights": self.highest}))
        print("Ending recovered timeline", flush=True)
        os._exit(0 if recovered else 1)


@hegel.main(settings=hegel.Settings.from_profile("workload"), phases=[hegel.Phase.generate])
def workload(tc):
    urls = os.getenv("RPC_URLS", ",".join(URLS)).split(",")
    if len(urls) != 4:
        raise ValueError("RPC_URLS must contain exactly four validator endpoints")
    cluster = Cluster(urls)
    cluster.wait_ready()
    if command(["/driver/txgen.sh", "prepare", urls[0]], 300) != 0:
        raise RuntimeError("Public-mix setup failed; setup_complete was not emitted")
    cluster.wait_ready()
    # bench confirms inclusion; wait for every setup-tail block to finalize before
    # choosing the baseline, so setup receipts cannot satisfy workload progress.
    setup_tail = max(int(block(url, "latest")["number"], 16) for url in urls)
    while min(int(block(url, "finalized")["number"], 16) for url in urls) < setup_tail:
        time.sleep(0.2)
    cluster.start_height = max(int(block(url, "finalized")["number"], 16) for url in urls)
    lifecycle.setup_complete({"validators": 4, "preset": "public-mix", "height": cluster.start_height})
    print("setup_complete: waiting for /workload-active", flush=True)
    while not Path("/workload-active").exists():
        time.sleep(0.1)
    assertions.reachable("The tempo cluster workload starts", {})
    cluster.started = time.monotonic()
    hegel.run_state_machine(tc, cluster, steps=2**63 - 1, min_concurrency=1, max_concurrency=1)


if __name__ == "__main__":
    workload()
