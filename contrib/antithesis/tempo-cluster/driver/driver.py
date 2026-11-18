"""Consensus transfer/mint driver. No node-local state is used as a correctness oracle."""
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
# Ledger workload: transfers and mints of one TIP-20 token between genesis accounts.
# BetaUSD carries no fees: genesis sets AlphaUSD as every account's fee token,
# so a token's balances move only through the transactions this driver sends.
CHAIN_ID = 1337
TOKEN = "0x20c0000000000000000000000000000000000002"
MNEMONIC = "test test test test test test test test test test test junk"
ISSUER = 0  # Genesis grants account 0 the issuer role on every token.
TRACKED = tuple(range(1, 17))
GAS_LIMIT = 500_000
MAX_PENDING = 256
MAX_AMOUNT = 1_000_000
SELECTORS = {"balanceOf": "70a08231", "totalSupply": "18160ddd",
             "transfer": "a9059cbb", "mint": "40c10f19"}
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


def call_data(name, *args):
    words = (format(int(arg, 16) if isinstance(arg, str) else arg, "064x") for arg in args)
    return "0x" + SELECTORS[name] + "".join(words)


class Ledger:
    """Client-side model of the token, settled only from finalized receipts.

    Every signed transaction is tracked from before it is sent, since a failed
    send can still land. At finalized height H the model applies exactly the
    tracked transactions whose receipts sit at or below H; a transaction without
    one either lands later or its nonce is consumed by another tracked one.
    """

    def __init__(self, keys):
        self.keys = keys
        self.addresses = {index: keys[index].address for index in TRACKED}
        self.expected = {}
        self.supply = None
        self.height = None
        self.pending = {}
        self.consumed = {}
        self.applied = 0
        self.failed = 0

    @staticmethod
    def derive():
        from eth_account import Account
        Account.enable_unaudited_hdwallet_features()
        return {index: Account.from_mnemonic(MNEMONIC, account_path=f"m/44'/60'/0'/0/{index}")
                for index in (ISSUER, *TRACKED)}

    def read(self, url, height):
        tag = hex(height)
        balances = {}
        for index, address in self.addresses.items():
            balances[index] = int(rpc(url, "eth_call", [{"to": TOKEN, "data": call_data("balanceOf", address)}, tag]), 16)
        supply = int(rpc(url, "eth_call", [{"to": TOKEN, "data": call_data("totalSupply")}, tag]), 16)
        return balances, supply

    def baseline(self, url, height):
        self.expected, self.supply = self.read(url, height)
        self.height = height

    def submit(self, url, kind, sender, recipient, amount):
        """Sign and send one transaction; False means its outcome is unknown."""
        if len(self.pending) >= MAX_PENDING:
            return False
        account = self.keys[sender]
        try:
            nonce = int(rpc(url, "eth_getTransactionCount", [account.address, "pending"]), 16)
            gas_price = int(rpc(url, "eth_gasPrice", []), 16)
        except RpcError:
            return False
        signed = account.sign_transaction({
            "type": 2, "chainId": CHAIN_ID, "nonce": nonce, "to": TOKEN, "value": 0,
            "gas": GAS_LIMIT, "maxFeePerGas": 2 * gas_price + 1, "maxPriorityFeePerGas": 0,
            "data": call_data(kind, self.addresses[recipient], amount),
        })
        txhash = "0x" + bytes(signed.hash).hex()
        self.pending[txhash] = {"kind": kind, "sender": sender, "nonce": nonce,
                                "recipient": recipient, "amount": amount}
        try:
            rpc(url, "eth_sendRawTransaction", ["0x" + bytes(signed.raw_transaction).hex()])
        except RpcError:
            return False
        return True

    def settle(self, url, height):
        """Apply tracked transactions finalized at or below height. url must have finalized height."""
        if self.height is None or height <= self.height:
            return False
        for txhash, tx in list(self.pending.items()):
            receipt = rpc(url, "eth_getTransactionReceipt", [txhash])
            if receipt is None or int(receipt["blockNumber"], 16) > height:
                continue
            del self.pending[txhash]
            self.consumed[tx["sender"]] = max(self.consumed.get(tx["sender"], -1), tx["nonce"])
            if receipt.get("status") != "0x1":
                self.failed += 1
                continue
            self.applied += 1
            if tx["kind"] == "mint":
                self.supply += tx["amount"]
            else:
                self.expected[tx["sender"]] -= tx["amount"]
            self.expected[tx["recipient"]] += tx["amount"]
        for txhash, tx in list(self.pending.items()):
            if tx["nonce"] <= self.consumed.get(tx["sender"], -1):
                del self.pending[txhash]
        self.height = height
        return True

    def check(self, url, height):
        if not self.settle(url, height):
            return
        balances, supply = self.read(url, height)
        assertions.always(balances == self.expected and supply == self.supply,
                          "Token balances and supply match the finalized ledger",
                          {"height": height, "supply": supply, "expected_supply": self.supply,
                           "diff": {str(index): [balances[index], self.expected[index]]
                                    for index in balances if balances[index] != self.expected[index]}})
        assertions.always(all(balance >= 0 for balance in balances.values()),
                          "No account balance goes negative", {"height": height})
        assertions.sometimes(self.applied > 0, "Finalized transfers and mints settle in the ledger",
                             {"applied": self.applied, "failed": self.failed, "height": height})


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
    def __init__(self, urls, follower_url=None, ledger=None):
        # Transaction injection is validator-only. The follower participates in
        # read-side safety and recovery, never in the four-validator committee.
        self.urls = urls
        self.observed_urls = list(urls) + ([follower_url] if follower_url else [])
        self.anchors = collections.OrderedDict()
        self.anchor_cursor = 0
        self.highest = [0] * len(self.observed_urls)
        self.heights = [None] * len(self.observed_urls)
        self.start_height = 0
        self.scanned_height = 0
        self.started = time.monotonic()
        self.successful_receipts = 0
        self.successful_height = 0
        self.seen_receipts = collections.OrderedDict()
        self.bursts = 0
        self.ledger = ledger
        self.recovery_requested = False
        self.recovery_due = float(os.getenv("EVENTUALLY_AFTER_SECONDS", "0"))

    def observe(self):
        heads = []
        self.heights = [None] * len(self.observed_urls)
        checkpoints = list(self.anchors.items())
        checked = checkpoints[-1:]
        if checkpoints:
            old = checkpoints[self.anchor_cursor % len(checkpoints)]
            if old not in checked:
                checked.append(old)
            self.anchor_cursor += 1
        for node, url in enumerate(self.observed_urls):
            try:
                head = block(url, "finalized")
                height = int(head["number"], 16)
                # A restarted node may serve a lagging persisted finalized marker.
                self.heights[node] = height
                self.highest[node] = max(self.highest[node], height)
                heads.append((node, height))
                # Keep checking blocks this node previously finalized, even if its marker lags.
                for checkpoint, expected in checked:
                    if self.highest[node] >= checkpoint:
                        actual = block(url, hex(checkpoint))
                        assertions.always(fingerprint(actual) == expected,
                                          "Finalized checkpoints remain immutable",
                                          {"node": node, "height": checkpoint, "expected": expected,
                                           "actual": fingerprint(actual)})
            except RpcError:
                continue
        if sum(node < len(self.urls) for node, _ in heads) < 2:
            return False
        common = min(height for _, height in heads)
        samples = []
        for node, _ in heads:
            try:
                samples.append((node, block(self.observed_urls[node], hex(common))))
            except RpcError:
                pass
        if sum(node < len(self.urls) for node, _ in samples) < 2:
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
                finalized = block(self.observed_urls[samples[0][0]], hex(height))
                if finalized["transactions"]:
                    txhash = finalized["transactions"][0]
                    receipts = []
                    for node, _ in samples:
                        receipt = rpc(self.observed_urls[node], "eth_getTransactionReceipt", [txhash])
                        if receipt is not None:
                            assertions.always(receipt["blockHash"] == finalized["hash"],
                                              "Finalized transaction receipts match their block",
                                              {"node": node, "tx": txhash, "receipt": receipt})
                            receipts.append(receipt)
                    if len(receipts) != len(samples):
                        break
                    if receipts[0].get("status") == "0x1" and txhash not in self.seen_receipts:
                        self.successful_receipts += 1
                        self.successful_height = max(self.successful_height, height)
                        self.seen_receipts[txhash] = None
                        while len(self.seen_receipts) > 256:
                            self.seen_receipts.popitem(last=False)
                self.scanned_height = height
            except RpcError:
                break
        assertions.sometimes(self.successful_receipts > 0, "Workload transactions execute successfully",
                             {"successful_samples": self.successful_receipts, "bursts": self.bursts})
        if self.ledger is not None:
            try:
                self.ledger.check(self.observed_urls[samples[0][0]], common)
            except RpcError:
                pass
        return len(heads) == len(self.observed_urls) and len(samples) == len(self.observed_urls)

    def wait_ready(self):
        previous = None
        while True:
            try:
                chains = [rpc(url, "eth_chainId", []) for url in self.observed_urls]
                heads = [block(url, "finalized") for url in self.observed_urls]
                if all(chain == "0x539" for chain in chains) and min(int(h["number"], 16) for h in heads) > 1:
                    return
                reason = f"waiting for chain 1337 consensus finality: {chains}, {[h['number'] for h in heads]}"
            except RpcError as error:
                reason = str(error)
            if reason != previous:
                print(reason, flush=True)
                previous = reason
            time.sleep(1)

    def submit(self, node, kind, sender, recipient, amount):
        """Send one tracked transaction to a validator; False is an unknown outcome."""
        if self.ledger is None:
            return False
        return self.ledger.submit(self.urls[node], kind, sender, recipient, amount)

    def burst(self, tc, kind):
        if self.recovery_requested:
            self.recover_with_faults_paused(tc)
        node = tc.draw(gs.integers(min_value=0, max_value=3))
        count = tc.draw(gs.integers(min_value=1, max_value=8))
        sent = 0
        for _ in range(count):
            recipient = tc.draw(gs.sampled_from(TRACKED))
            amount = tc.draw(gs.integers(min_value=1, max_value=MAX_AMOUNT))
            if kind == "mint":
                sender = ISSUER
            else:
                sender = tc.draw(gs.sampled_from([index for index in TRACKED if index != recipient]))
            sent += self.submit(node, kind, sender, recipient, amount)
        self.bursts += 1
        # RPC errors while faulting have unknown outcomes, not safety failures.
        assertions.sometimes(sent == count, "A validator accepts a burst of transfers and mints",
                             {"node": node, "kind": kind, "sent": sent, "count": count})

    @hegel.rule(weight=6)
    def transfers(self, tc):
        self.burst(tc, "transfer")

    @hegel.rule(weight=2)
    def mints(self, tc):
        self.burst(tc, "mint")

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
        print(f"Recovery assertions start: all observed nodes must finalize past {target}", flush=True)
        # Rules run on one worker, so no burst overlaps the recovery window.
        sent = False
        sent_height = None
        recovered = False
        while time.monotonic() < deadline:
            available = self.observe()
            if available and min(self.heights) >= target and not sent:
                sent_height = max(self.highest)
                sent = self.submit(0, "transfer", TRACKED[0], TRACKED[1], 1)
            if available and min(self.heights) >= target and sent and self.successful_height > sent_height and self.successful_receipts > before:
                recovered = True
                break
            time.sleep(1)
        if quiet_until is not None and time.monotonic() >= quiet_until:
            raise FaultControlError("Recovery exceeded the fault-pause lease; liveness result is invalid")
        assertions.always(recovered, "Cluster resumes finality and successful transactions after faults stop",
                          {"target": target, "heights": self.heights, "highest": self.highest, "successful_samples": self.successful_receipts - before})
        Path("/state/recovery-result.json").write_text(json.dumps({"recovered": recovered, "heights": self.heights}))
        print("Ending recovered timeline", flush=True)
        os._exit(0 if recovered else 1)


@hegel.main(settings=hegel.Settings.from_profile("workload"), phases=[hegel.Phase.generate])
def workload(tc):
    urls = os.getenv("RPC_URLS", ",".join(URLS)).split(",")
    if len(urls) != 4:
        raise ValueError("RPC_URLS must contain exactly four validator endpoints")
    follower_url = os.getenv("FOLLOWER_RPC_URL", "").strip() or None
    ledger = Ledger(Ledger.derive())
    cluster = Cluster(urls, follower_url=follower_url, ledger=ledger)
    cluster.wait_ready()
    # Genesis funds every account, so there is no setup transaction. Wait for
    # every node to finalize the current tip before taking the ledger baseline.
    setup_tail = max(int(block(url, "latest")["number"], 16) for url in cluster.observed_urls)
    while min(int(block(url, "finalized")["number"], 16) for url in cluster.observed_urls) < setup_tail:
        time.sleep(0.2)
    cluster.start_height = max(int(block(url, "finalized")["number"], 16) for url in cluster.observed_urls)
    while True:
        try:
            ledger.baseline(urls[0], cluster.start_height)
            break
        except RpcError as error:
            print(f"waiting for ledger baseline: {error}", flush=True)
            time.sleep(1)
    Path("/state/setup-confirmed").touch()
    lifecycle.setup_complete({"validators": 4, "followers": int(follower_url is not None),
                              "workload": "transfers-mints", "height": cluster.start_height})
    print("setup_complete: waiting for /workload-active", flush=True)
    while not Path("/workload-active").exists():
        time.sleep(0.1)
    assertions.reachable("The tempo cluster workload starts", {})
    cluster.started = time.monotonic()
    hegel.run_state_machine(tc, cluster, steps=2**63 - 1, min_concurrency=1, max_concurrency=1)


if __name__ == "__main__":
    workload()
