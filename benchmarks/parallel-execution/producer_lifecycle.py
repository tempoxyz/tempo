#!/usr/bin/env python3
"""Opt-in benchmark cleanup; no tuning, snapshot restore, or process-name kills.

capture precedes ALL Nu work. quiesce gates each snapshot restore. restore runs
outside the control scope in a separate always-run workflow step. The workflow
must use the predeclared unique scopes and ownership Description verbatim.
"""

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time


COMMAND_SECONDS = 5
COMMAND_OUTPUT_BYTES = 16384
OPERATION_SECONDS = 120
TERM_SECONDS = 10
KILL_SECONDS = 5
CONFIG_BYTES = 16384
STATE_BYTES = 2097152
MAX_GOVERNORS = 512
MAX_EVENTS = 2048
SYSCTLS = {
    "net.ipv4.tcp_tw_reuse": "/proc/sys/net/ipv4/tcp_tw_reuse",
    "net.ipv4.ip_local_port_range": "/proc/sys/net/ipv4/ip_local_port_range",
}
GOVERNORS = "/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor"
TURBO = (
    "/sys/devices/system/cpu/intel_pstate/no_turbo",
    "/sys/devices/system/cpu/cpufreq/boost",
)
THP = (
    "/sys/kernel/mm/transparent_hugepage",
    "/sys/kernel/mm/transparent_hugepages",
)
SERVICES = ("cron.service", "unattended-upgrades.service")
PROPERTIES = (
    "Id", "LoadState", "ActiveState", "SubState", "ControlGroup",
    "Description", "InvocationID",
)


class Refusal(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def bounded_json(path, limit):
    require(not path.is_symlink(), f"refusing symlink: {path}")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, f"oversized JSON: {path}")
    return json.loads(raw)


def atomic_json(path, value, exclusive=False):
    data = encoded(value)
    require(len(data) <= STATE_BYTES, "state size limit")
    require(not path.is_symlink(), "state symlink")
    # A SIGKILL may leave a temporary behind; a unique name keeps the next
    # finalizer able to recover from the previous durable journal/prestate.
    fd, temporary_name = tempfile.mkstemp(prefix=path.name + ".tmp-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if exclusive:
            os.link(temporary, path, follow_symlinks=False)
            temporary.unlink()
        else:
            os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


class System:
    """All machine reads, commands and time are injected in fake tests."""

    def read(self, path, limit=16384):
        with open(path, "rb") as stream:
            raw = stream.read(limit + 1)
        require(len(raw) <= limit, f"oversized machine state: {path}")
        return raw.decode("utf-8", errors="strict")

    def exists(self, path):
        # Permission/I/O failures must not certify that a cgroup is absent.
        try:
            os.stat(path)
            return True
        except FileNotFoundError:
            return False

    def glob(self, pattern):
        # glob.glob suppresses directory enumeration errors, which could omit
        # governors from the prestate. Enumerate this one fixed tree strictly.
        require(pattern == GOVERNORS, "unsupported machine-state glob")
        governors = []
        with os.scandir("/sys/devices/system/cpu") as entries:
            for entry in entries:
                if not re.fullmatch(r"cpu[0-9]+", entry.name):
                    continue
                candidate = "/sys/devices/system/cpu/" + entry.name + "/cpufreq/scaling_governor"
                if self.exists(candidate):
                    governors.append(candidate)
                    require(len(governors) <= MAX_GOVERNORS, "CPU governor count")
        return sorted(governors)

    def now(self):
        return time.monotonic()

    def sleep(self, seconds):
        time.sleep(seconds)

    def command(self, argv, timeout, stdin=None):
        # No shell, no inherited stdin, no unbounded PIPE communicate buffers.
        # Allocate before any launch; selector failure cannot leave a child.
        selector = selectors.DefaultSelector()
        process = None
        signals_open = True
        try:
            chunks = {"stdout": bytearray(), "stderr": bytearray()}
            end = self.now() + timeout
            process = subprocess.Popen(
                argv, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                env={**os.environ, "LC_ALL": "C", "SYSTEMD_PAGER": "", "SYSTEMD_COLORS": "0"},
            )
            if stdin is not None:
                require(len(stdin) <= 1024, "command stdin limit")
                process.stdin.write(stdin)
                process.stdin.close()
            for label, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            while True:
                # Observe without reaping: the leader's reserved PID prevents
                # its numeric process-group ID being recycled before cleanup.
                observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if observed is not None and not selector.get_map():
                    break
                remaining = end - self.now()
                require(remaining > 0, "command timeout")
                for key, _ in selector.select(min(remaining, 0.1)):
                    part = os.read(key.fileobj.fileno(), 4096)
                    if not part:
                        selector.unregister(key.fileobj)
                        continue
                    chunks[key.data].extend(part)
                    require(sum(map(len, chunks.values())) <= COMMAND_OUTPUT_BYTES, "command output limit")
            # From here on, no path may signal this numeric process-group ID.
            # Close authority before the first operation which can reap.
            signals_open = False
            code = process.wait(timeout=max(0.01, end - self.now()))
            return {"code": code, **{k: v.decode("utf-8", errors="replace") for k, v in chunks.items()}}
        except BaseException:
            # A timed-out helper must not survive and mutate after restoration.
            if process is not None and signals_open:
                try:
                    # If another reaper somehow stole ownership, never signal a
                    # potentially recycled ID. This helper has no other reaper.
                    os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                except ChildProcessError as error:
                    signals_open = False
                    raise Refusal("command leader ownership lost; refusing group signal") from error
                try:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                finally:
                    signals_open = False
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired as error:
                    raise Refusal("command did not reap after SIGKILL") from error
            raise
        finally:
            selector.close()
            if process is not None:
                process.stdout.close()
                process.stderr.close()
                if getattr(process, "stdin", None) is not None:
                    process.stdin.close()


def normalize(raw):
    return " ".join(raw.split())


def selected_value(raw):
    values = re.findall(r"\[([a-z_-]+)\]", raw)
    require(len(values) == 1, "THP state requires exactly one selected value")
    return values[0]


def parse_properties(raw):
    values = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        require(separator and key in PROPERTIES and key not in values, "unexpected systemctl property")
        values[key] = value
    require(set(values) == set(PROPERTIES), "incomplete systemctl properties")
    return values


def validate_config(config):
    require(set(config) == {
        "schema_version", "run_token", "state_dir", "control_unit", "node_units", "unit_description",
    }, "config keys")
    require(config["schema_version"] == 1, "config version")
    token = config["run_token"]
    require(isinstance(token, str) and re.fullmatch(r"[0-9a-f]{16,64}", token), "unique lowercase hex run token")
    prefix = f"tempo-producer-{token}"
    require(config["control_unit"] == prefix + "-control.scope", "control unit name")
    require(config["node_units"] == [prefix + "-a.scope", prefix + "-b.scope"], "exact node unit names")
    require(config["unit_description"] == "tempo-producer:" + token, "ownership Description")
    path = Path(config["state_dir"])
    require(path.is_absolute() and str(path.resolve()) == str(path), "absolute canonical state directory")
    require(not str(path).startswith(("/var/lib/schelk/", "/mnt/")), "state must survive snapshot restore")
    return config


class Lifecycle:
    def __init__(self, config, system=None):
        self.config = validate_config(config)
        self.system = system or System()
        self.directory = Path(config["state_dir"])
        self.config_sha = digest(encoded(config))
        self.source_sha = digest(Path(__file__).read_bytes())
        self.deadline = self.system.now() + OPERATION_SECONDS
        self.journal = None
        self.prestate = None

    @contextlib.contextmanager
    def locked(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(not self.directory.is_symlink(), "state directory symlink")
        fd = os.open(self.directory / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    self.remaining()
                    self.system.sleep(0.05)
            yield
        finally:
            os.close(fd)

    def remaining(self):
        remaining = self.deadline - self.system.now()
        require(remaining > 0, "operation deadline")
        return remaining

    def command(self, argv, stdin=None):
        return self.system.command(argv, min(COMMAND_SECONDS, self.remaining()), stdin)

    def save(self):
        self.remaining()
        atomic_json(self.directory / "journal.json", self.journal)

    def event(self, kind, **fields):
        require(len(self.journal["events"]) < MAX_EVENTS, "journal event limit")
        self.journal["events"].append({"kind": kind, "monotonic": self.system.now(), **fields})
        self.save()

    def boot(self):
        return self.system.read("/proc/sys/kernel/random/boot_id").strip()

    def no_swaps(self):
        lines = self.system.read("/proc/swaps").splitlines()
        require(lines and lines[0].split() == ["Filename", "Type", "Size", "Used", "Priority"], "swap header")
        require(not any(line.strip() for line in lines[1:]), "active swap cannot be restored exactly; refusing")
        return []

    def show(self, unit):
        result = self.command(["systemctl", "show", unit, "--no-pager", "--all", "--property=" + ",".join(PROPERTIES)])
        properties = parse_properties(result["stdout"])
        require(properties["Id"] == unit, "systemctl identity mismatch")
        require(result["code"] == 0 or properties["LoadState"] == "not-found", "systemctl show failed")
        return properties

    def service(self, name):
        item = self.show(name)
        if item["LoadState"] == "not-found":
            require(item["ActiveState"] == "inactive", "not-found service state")
            return {"load": "not-found", "active": "inactive", "sub": item["SubState"]}
        require(item["LoadState"] == "loaded", "service is not loaded normally")
        require((item["ActiveState"], item["SubState"]) in (("active", "running"), ("active", "exited"), ("inactive", "dead")), "service failed/transitional/unsupported state")
        return {"load": "loaded", "active": item["ActiveState"], "sub": item["SubState"]}

    def paths(self):
        governors = self.system.glob(GOVERNORS)
        require(len(governors) <= MAX_GOVERNORS and len(governors) == len(set(governors)), "CPU governor count")
        require(all(re.fullmatch(r"/sys/devices/system/cpu/cpu[0-9]+/cpufreq/scaling_governor", p) for p in governors), "governor path")
        files = {path: "governor" for path in governors}
        files.update({path: "turbo" for path in TURBO if self.system.exists(path)})
        for directory in THP:
            if self.system.exists(directory):
                files.update({directory + "/" + name: "thp" for name in ("enabled", "defrag")})
                break
        return files

    def value(self, path, kind):
        raw = self.system.read(path)
        if kind == "thp":
            return selected_value(raw)
        value = normalize(raw)
        if kind == "governor":
            require(re.fullmatch(r"[a-zA-Z0-9_-]+", value), "governor value")
        elif kind == "turbo":
            require(value in ("0", "1"), "turbo value")
        elif kind == "sysctl":
            require(re.fullmatch(r"[0-9]+(?: [0-9]+)?", value), "sysctl value")
        else:
            raise Refusal("unknown setting kind")
        return value

    def settings(self):
        paths = self.paths()
        return {
            "sysctls": {key: self.value(path, "sysctl") for key, path in SYSCTLS.items()},
            "files": {path: {"kind": kind, "value": self.value(path, kind)} for path, kind in paths.items()},
            "services": {name: self.service(name) for name in SERVICES},
            "swaps": self.no_swaps(),
        }

    def cgroup_populated(self, unit):
        directory = "/sys/fs/cgroup/system.slice/" + unit
        if not self.system.exists(directory):
            return False
        raw = self.system.read(directory + "/cgroup.events")
        pairs = [line.split() for line in raw.splitlines()]
        require(all(len(pair) == 2 for pair in pairs), "malformed cgroup.events")
        require(len({pair[0] for pair in pairs}) == len(pairs), "duplicate cgroup event")
        fields = dict(pairs)
        require(fields.get("populated") in ("0", "1"), "missing populated cgroup event")
        return fields["populated"] == "1"

    def inspect_unit(self, unit, capture=False):
        item = self.show(unit)
        populated = self.cgroup_populated(unit)
        if capture:
            require(item["LoadState"] == "not-found", "configured unit already exists")
            require(not self.system.exists("/sys/fs/cgroup/system.slice/" + unit), "configured cgroup already exists")
            return False
        if item["LoadState"] == "not-found":
            require(not populated, "populated cgroup has no owned systemd unit")
            return False
        require(item["LoadState"] == "loaded", "unexpected owned unit load state")
        require(item["Description"] == self.config["unit_description"], "owned unit Description mismatch")
        require(item["ControlGroup"] in ("", "/system.slice/" + unit), "owned unit cgroup mismatch")
        if populated:
            require(item["ControlGroup"] == "/system.slice/" + unit, "populated unit without expected cgroup")
        invocation = item["InvocationID"]
        if invocation:
            require(re.fullmatch(r"[0-9a-f]{32}", invocation), "unit InvocationID")
            previous = self.journal["unit_invocations"].get(unit)
            require(previous is None or previous == invocation, "unit InvocationID changed")
            if previous is None:
                self.journal["unit_invocations"][unit] = invocation
                self.event("unit_identity", unit=unit, invocation_id=invocation)
        else:
            require(not populated, "populated unit lacks InvocationID")
        return populated

    def outside_scopes(self, units):
        own = self.system.read("/proc/self/cgroup")
        require(not any("/" + name in own for name in units), "helper would terminate its own scope")

    def inside_control(self):
        groups = [line.split(":", 2) for line in self.system.read("/proc/self/cgroup").splitlines()]
        unified = [parts[2] for parts in groups if len(parts) == 3 and parts[:2] == ["0", ""]]
        expected = "/system.slice/" + self.config["control_unit"]
        require(len(unified) == 1 and (unified[0] == expected or unified[0].startswith(expected + "/")),
                "quiesce caller must belong to the declared control scope")
        require(self.inspect_unit(self.config["control_unit"]), "caller control scope is not populated")

    def capture(self):
        with self.locked():
            require(not (self.directory / "prestate.json").exists(), "prestate already captured; never overwrite")
            require(not (self.directory / "journal.json").exists(), "journal already exists")
            require(self.system.exists("/sys/fs/cgroup/cgroup.controllers"), "cgroup v2 required")
            for unit in [self.config["control_unit"], *self.config["node_units"]]:
                self.inspect_unit(unit, capture=True)
            original = self.settings()
            self.prestate = {
                "schema_version": 1, "config": self.config, "config_sha256": self.config_sha,
                "helper_sha256": self.source_sha, "boot_id": self.boot(), "settings": original,
                "captured_monotonic": self.system.now(),
            }
            atomic_json(self.directory / "prestate.json", self.prestate, exclusive=True)
            self.journal = {
                "schema_version": 1, "prestate_sha256": digest(encoded(self.prestate)),
                "status": "captured", "unit_invocations": {}, "events": [],
            }
            self.event("capture_persisted_before_mutation")
            return {"status": "captured", "prestate_sha256": self.journal["prestate_sha256"]}

    def load(self):
        self.prestate = bounded_json(self.directory / "prestate.json", STATE_BYTES)
        self.journal = bounded_json(self.directory / "journal.json", STATE_BYTES)
        require(self.prestate["schema_version"] == self.journal["schema_version"] == 1, "state version")
        require(self.prestate["config"] == self.config and self.prestate["config_sha256"] == self.config_sha, "config changed")
        require(self.prestate["helper_sha256"] == self.source_sha, "helper source changed")
        require(self.prestate["boot_id"] == self.boot(), "boot changed")
        require(self.journal["prestate_sha256"] == digest(encoded(self.prestate)), "prestate changed")
        require(self.journal["status"] in ("captured", "closing", "restore_failed", "restored"), "journal status")
        require(len(self.journal["events"]) < MAX_EVENTS, "journal event limit")
        require(set(self.prestate["settings"]["sysctls"]) == set(SYSCTLS), "sysctl set changed")
        require(set(self.prestate["settings"]["services"]) == set(SERVICES), "service set changed")

    def mutate(self, argv, stdin=None):
        self.event("command_intent", argv=argv)
        result = self.command(argv, stdin)
        self.event("command_result", argv=argv, code=result["code"],
                   stdout_sha256=digest(result["stdout"].encode()), stderr_sha256=digest(result["stderr"].encode()),
                   stderr_excerpt=result["stderr"][:1024] if result["code"] else "")
        return result

    def wait_empty(self, units, seconds):
        end = min(self.deadline, self.system.now() + seconds)
        while True:
            pending = [unit for unit in units if self.inspect_unit(unit)]
            if not pending or self.system.now() >= end:
                return pending
            self.system.sleep(min(0.1, max(0, end - self.system.now())))

    def stop(self, units):
        self.outside_scopes(units)
        pending = [unit for unit in units if self.inspect_unit(unit)]
        for sig, seconds in (("TERM", TERM_SECONDS), ("KILL", KILL_SECONDS)):
            for unit in pending:
                result = self.mutate(["sudo", "-n", "--", "systemctl", "kill", "--kill-whom=all", "--signal=" + sig, unit])
                require(result["code"] == 0 or not self.inspect_unit(unit), "owned unit signal failed")
            pending = self.wait_empty(pending, seconds)
            if not pending:
                break
        require(not pending, "owned processes remain after TERM/KILL; no restore permitted")
        # Recheck every declared scope, including scopes that were absent initially.
        require(not any(self.inspect_unit(unit) for unit in units), "owned scope repopulated")
        self.event("scopes_proven_empty", units=units)

    def quiesce(self):
        with self.locked():
            self.load()
            require(self.journal["status"] == "captured", "run is closing/closed; no further Nu mutation permitted")
            self.inside_control()
            self.stop(self.config["node_units"])
            return {"status": "nodes_quiescent", "snapshot_restore_permitted": True,
                    "node_units": self.config["node_units"], "prestate_sha256": self.journal["prestate_sha256"]}

    def restore_settings(self):
        old = self.prestate["settings"]
        # Setting topology must not prevent stopping owned processes first.
        require({p: x["kind"] for p, x in old["files"].items()} == self.paths(), "sysfs path set changed")
        self.no_swaps()
        for key, value in old["sysctls"].items():
            if self.value(SYSCTLS[key], "sysctl") != value:
                result = self.mutate(["sudo", "-n", "--", "sysctl", "-w", key + "=" + value])
                require(result["code"] == 0, "sysctl restore failed")
                require(self.value(SYSCTLS[key], "sysctl") == value, "sysctl verification failed")
        for path, item in old["files"].items():
            if self.value(path, item["kind"]) != item["value"]:
                result = self.mutate(["sudo", "-n", "--", "tee", path], (item["value"] + "\n").encode())
                require(result["code"] == 0, "sysfs restore failed")
                require(self.value(path, item["kind"]) == item["value"], "sysfs verification failed")
        for name, expected in old["services"].items():
            current = self.service(name)
            require(current["load"] == expected["load"], "service load state changed")
            if current != expected:
                action = "start" if expected["active"] == "active" else "stop"
                result = self.mutate(["sudo", "-n", "--", "systemctl", action, name])
                require(result["code"] == 0, "service restore failed")
                require(self.service(name) == expected, "service restoration verification failed")
        require(self.settings() == old, "full prestate restoration verification failed")

    def restore(self):
        with self.locked():
            self.load()
            self.outside_scopes([self.config["control_unit"], *self.config["node_units"]])
            try:
                # Persist before stopping the control scope: a late control launch
                # must call quiesce first and will refuse all subsequent mutations.
                self.journal["status"] = "closing"
                self.event("closing_before_launcher_stop")
                self.stop([self.config["control_unit"]])
                self.stop(self.config["node_units"])
                self.restore_settings()
                require(not any(self.inspect_unit(unit) for unit in [self.config["control_unit"], *self.config["node_units"]]), "scope restarted during restoration")
                self.journal["status"] = "restored"
                self.event("restored_and_verified")
                return {"status": "restored", "prestate_sha256": self.journal["prestate_sha256"],
                        "all_owned_scopes_empty": True, "settings_equal_prestate": True}
            except Exception as error:
                self.journal["status"] = "restore_failed"
                # Persist failure even when the operation deadline was reached.
                self.journal["failure"] = {"type": type(error).__name__, "message": str(error)[:2048]}
                atomic_json(self.directory / "journal.json", self.journal)
                raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("capture", "quiesce", "restore"))
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()
    try:
        # Timeout cleanup must be able to kill every member of privileged
        # command groups, including children whose real UID is root.
        require(os.geteuid() == 0, "invoke this CLI with sudo -n for bounded privileged child cleanup")
        helper = Lifecycle(bounded_json(args.config, CONFIG_BYTES))
        print(json.dumps(getattr(helper, args.action)(), sort_keys=True))
    except Exception as error:
        print(json.dumps({"status": "failed", "error_type": type(error).__name__, "error": str(error)[:2048]}, sort_keys=True), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
