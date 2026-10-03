#!/usr/bin/env python3
"""Verify/recover only one disposable GCP benchmark, without Terraform state.

The audited upstream stack (dba9dd13) owns instances and their boot/local disks,
not networks, service accounts or buckets. Compute delete APIs address names:
we recheck immutable IDs before deletion and require the operation targetId to
match. There is no API atomic ID precondition; the workflow must have stopped
provisioning before this helper runs. No credentials or VM metadata are saved.

Normal workflow use: --snapshot before Terraform destroy, then --recover with
--prior-inventory pointing to that snapshot's cleanup.json. Verification without
--recover never deletes. Recover a lost runner through the existing workflow:
  gh workflow run bench-e2e-multi-region.yml --ref <reviewed-branch> \
    -f cloud=gcp-cleanup -f baseline=bench-e2e-multi-region-<run-id>-<attempt>
The recovery job verifies the target run/attempt is completed before GCP auth.
It does not provision, benchmark, or notify Slack. Both modes retain cleanup.json.
"""
import argparse
import datetime
import hashlib
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

PROJECT = "chain-benchmarking-zygis"
BASE = f"https://compute.googleapis.com/compute/v1/projects/{PROJECT}"
ROLES = {"validator", "load-generator", "state-snapshot-builder"}
RUN_ID = re.compile(r"bench-e2e-multi-region-([1-9][0-9]{0,19})-([1-9][0-9]{0,9})\Z")
FIELDS = {
    "instances": "id,name,zone,labels,disks(boot,type,autoDelete,source)",
    "disks": "id,name,zone,labels,users",
}


class CleanupError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise CleanupError(message)


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class Compute:
    def __init__(self, deadline):
        self.deadline = deadline
        token = subprocess.run(
            ["gcloud", "auth", "print-access-token", "--quiet"],
            capture_output=True, text=True, timeout=20, check=False,
        )
        require(token.returncode == 0 and token.stdout.strip(), "gcloud authentication failed")
        self.token = token.stdout.strip()

    def request(self, method, path, **params):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "cleanup deadline exceeded")
        require(re.fullmatch(r"(?:aggregated/(?:instances|disks)|zones/[a-z0-9-]+/(?:instances|disks|operations)/[a-z0-9-]+)", path), "invalid API path")
        url = BASE + "/" + path + ("?" + urllib.parse.urlencode(params) if params else "")
        request = urllib.request.Request(url, method=method, headers={"Authorization": "Bearer " + self.token})
        try:
            with urllib.request.urlopen(request, timeout=min(20, remaining)) as response:
                raw = response.read(8 * 1024 * 1024 + 1)
            require(len(raw) <= 8 * 1024 * 1024, "API response exceeds bound")
            result = json.loads(raw)
            require(isinstance(result, dict) and not result.get("error"), "malformed/error API response")
            return result
        except urllib.error.HTTPError as error:
            if method == "GET" and error.code == 404 and re.fullmatch(
                r"zones/[a-z0-9-]+/(?:instances|disks)/[a-z0-9-]+", path
            ):
                return None
            raise CleanupError(f"{method} {path}: HTTP {error.code}") from None
        except (urllib.error.URLError, TimeoutError, ValueError) as error:
            raise CleanupError(f"{method} {path}: {type(error).__name__}") from None


def relative_link(link):
    require(isinstance(link, str), "invalid resource link")
    for root in (BASE, BASE.replace("compute.googleapis.com", "www.googleapis.com")):
        if link.startswith(root + "/"):
            return link[len(root) + 1:]
    raise CleanupError("resource link outside project")


def resource_path(kind, item):
    zone = relative_link(item.get("zone", ""))
    require(re.fullmatch(r"zones/[a-z][a-z0-9-]+", zone), "invalid zone")
    name, identity = item.get("name"), item.get("id")
    require(isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,62}", name), "invalid resource name")
    require(isinstance(identity, str) and re.fullmatch(r"[1-9][0-9]*", identity), "missing immutable resource ID")
    return f"{zone}/{kind}/{name}"


class Cleanup:
    def __init__(self, api, benchmark_id, output, deadline, recover=False, sleep=time.sleep):
        require(RUN_ID.fullmatch(benchmark_id), "expected exact bench-e2e-multi-region-<run>-<attempt> ID")
        self.api, self.run, self.output = api, benchmark_id, Path(output)
        self.deadline, self.recover, self.sleep = deadline, recover, sleep
        self.known = {}
        self.report = {"benchmark_id": benchmark_id, "project": PROJECT, "recover": recover,
                       "helper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                       "started_at": timestamp(), "ok": False, "inventories": [], "operations": []}

    def pause(self, seconds):
        require(time.monotonic() + seconds < self.deadline, "cleanup deadline exceeded")
        self.sleep(seconds)

    def save(self):
        self.output.mkdir(parents=True, exist_ok=True)
        temporary = self.output / "cleanup.json.tmp"
        temporary.write_text(json.dumps(self.report, indent=2) + "\n")
        temporary.replace(self.output / "cleanup.json")

    def owned(self, kind, item):
        labels = item.get("labels", {})
        require(isinstance(labels, dict), "invalid labels")
        if labels.get("benchmark-id") != self.run:
            return False
        require(labels.get("managed-by") == "terraform" and
                labels.get("repository") == "tempo-multi-region-benchmark" and
                labels.get("role") in ROLES, "run resource has conflicting ownership labels/role")
        suffix = {"validator": r"validator-[0-9]+", "load-generator": "load-generator-0",
                  "state-snapshot-builder": "snapshot-builder"}[labels["role"]]
        expected = "tempo-e2e-" + self.run[:36] + "-" + suffix
        require(re.fullmatch(expected, item.get("name", "")), "run resource name disagrees with role")
        resource_path(kind, item)
        return True

    def inventory(self):
        selected = {}
        for kind in FIELDS:
            page, seen_pages = "", set()
            while True:
                require(page not in seen_pages and len(seen_pages) < 100, "invalid/excessive inventory pagination")
                seen_pages.add(page)
                response = self.api.request("GET", "aggregated/" + kind,
                    maxResults=500, returnPartialSuccess="false", includeAllScopes="true", pageToken=page,
                    fields=f"kind,items/*/{kind}({FIELDS[kind]}),items/*/warning,nextPageToken,warning,unreachables")
                require(isinstance(response, dict) and response.get("kind") == f"compute#{kind[:-1]}AggregatedList", "invalid inventory response kind")
                require(not response.get("unreachables"), "inventory has unreachable scopes")
                scopes = response.get("items", {})
                require(isinstance(scopes, dict), "invalid inventory scopes")
                for group in [response, *scopes.values()]:
                    require(isinstance(group, dict), "invalid inventory scope")
                    warning = group.get("warning")
                    require(not warning or (isinstance(warning, dict) and warning.get("code") == "NO_RESULTS_ON_PAGE"),
                            "incomplete inventory warning")
                    require(not group.get("error"), "inventory scope error")
                for group in scopes.values():
                    items = group.get(kind, [])
                    require(isinstance(items, list), "invalid inventory resources")
                    for item in items:
                        require(isinstance(item, dict), "invalid inventory resource")
                        if self.owned(kind, item):
                            path = resource_path(kind, item)
                            require(path not in selected, "duplicate inventory resource")
                            selected[path] = item
                page = response.get("nextPageToken", "")
                require(isinstance(page, str), "invalid inventory page token")
                if not page:
                    break
        require(len(selected) <= 256, "run resource count exceeds cleanup bound")
        self.report["inventories"].append({"at": timestamp(), "resources": selected})
        self.save()
        return selected

    def recheck(self, path, expected):
        kind = path.split("/")[2]
        current = self.api.request("GET", path, fields=FIELDS[kind])
        if current is None:
            return None
        require(self.owned(kind, current), "resource lost ownership labels")
        require(resource_path(kind, current) == path and current["id"] == expected["id"], "resource immutable ID changed")
        require(current["labels"] == expected["labels"], "resource labels changed")
        return current

    def check_disks(self, path, instance):
        disks = instance.get("disks")
        require(isinstance(disks, list) and disks, "instance disk attachment evidence missing")
        for disk in disks:
            require(isinstance(disk, dict), "invalid disk attachment")
            if disk.get("type") == "SCRATCH":
                require(not disk.get("source"), "unexpected scratch disk source")
                continue
            require(disk.get("type") == "PERSISTENT" and disk.get("boot") is True and
                    disk.get("autoDelete") is True, "unexpected persistent attachment; refusing VM delete")
            source = disk.get("source", "")
            disk_path = relative_link(source)
            require(disk_path in self.known and "/disks/" in disk_path, "attached disk outside run inventory")
            current = self.recheck(disk_path, self.known[disk_path])
            require(current is not None and current["labels"]["role"] == instance["labels"]["role"], "attached disk ownership changed")
            users = current.get("users")
            require(isinstance(users, list) and [relative_link(user) for user in users] == [path],
                    "attached disk has unexpected users")

    def delete(self, path, expected):
        current = self.recheck(path, expected)
        if current is None:
            self.report["operations"].append({"path": path, "id": expected["id"], "already_absent": True})
            self.save()
            return
        if "/instances/" in path:
            self.check_disks(path, current)
        else:
            require(current.get("users", []) == [], "refusing to delete an attached disk")
        request_id = str(uuid.uuid4())
        operation = self.api.request("DELETE", path, requestId=request_id)
        record = {"path": path, "id": expected["id"], "request_id": request_id, "responses": []}
        self.report["operations"].append(record)
        while True:
            require(isinstance(operation, dict), "missing delete operation")
            record["responses"].append(operation)
            self.save()
            require(operation.get("operationType") == "delete" and operation.get("targetId") == expected["id"] and
                    relative_link(operation.get("targetLink")) == path, "delete operation identity mismatch")
            require(not operation.get("error") and not operation.get("httpErrorStatusCode") and
                    not operation.get("warnings"), "delete operation failed or warned")
            name = operation.get("name", "")
            require(re.fullmatch(r"[a-z0-9-]+", name), "invalid operation name")
            zone = path.split("/")[1]
            require(relative_link(operation.get("zone")) == "zones/" + zone, "operation zone mismatch")
            if operation.get("status") == "DONE":
                break
            require(operation.get("status") in {"PENDING", "RUNNING"}, "invalid operation status")
            self.pause(2)
            operation = self.api.request("GET", f"zones/{zone}/operations/{name}")
        require(self.recheck(path, expected) is None, "resource remains after completed delete")

    def run_cleanup(self, prior=None, snapshot=False):
        try:
            self.report["mode"] = "snapshot" if snapshot else "cleanup"
            initial = self.inventory()
            self.known = dict(initial)
            if prior is not None:
                require(prior.get("project") == PROJECT and prior.get("benchmark_id") == self.run and
                        prior.get("mode") == "snapshot" and prior.get("ok") is True,
                        "invalid prior inventory provenance")
                inventories = prior.get("inventories")
                require(isinstance(inventories, list) and len(inventories) == 1,
                        "invalid prior snapshot")
                resources = inventories[0].get("resources")
                require(isinstance(resources, dict) and len(resources) <= 256, "invalid prior resources")
                for path, item in resources.items():
                    kind = path.split("/")[2]
                    require(kind in FIELDS and self.owned(kind, item) and resource_path(kind, item) == path,
                            "prior resource outside cleanup scope")
                    require(path not in initial or initial[path]["id"] == item["id"],
                            "resource ID changed since pre-destroy snapshot")
                    self.known[path] = item
                self.report["prior_inventory"] = prior
            # Validate every present VM's attachments before any destructive request.
            for path, item in initial.items():
                if "/instances/" in path:
                    self.check_disks(path, item)
            if snapshot:
                self.report["ok"] = True
                return
            require(not initial or self.recover, "run resources remain; recovery was not enabled")
            if self.recover:
                for kind in ("instances", "disks"):
                    for path, item in self.known.items():
                        if path.split("/")[2] == kind:
                            self.delete(path, item)
            for index in range(2):
                if index:
                    self.pause(5)
                require(not self.inventory(), "resources remain or appeared during cleanup")
                # A relabeled or recreated resource must not evade the final label scan.
                for path, item in self.known.items():
                    require(self.recheck(path, item) is None, "known resource still exists")
            self.report["ok"] = True
        except Exception as error:
            self.report["error"] = str(error) if isinstance(error, CleanupError) else type(error).__name__
            raise
        finally:
            self.report["finished_at"] = timestamp()
            self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--recover", action="store_true", help="delete verified leftover run-owned instances and unattached boot disks")
    mode.add_argument("--snapshot", action="store_true", help="save non-deleting pre-destroy resource identity evidence")
    parser.add_argument("--prior-inventory", type=Path, help="successful pre-destroy cleanup.json snapshot")
    args = parser.parse_args()
    # Validate before obtaining credentials; ten minutes bounds all API calls/polls.
    require(RUN_ID.fullmatch(args.benchmark_id), "invalid benchmark ID")
    deadline = time.monotonic() + 600
    cleanup = Cleanup(None, args.benchmark_id, args.output, deadline, args.recover)
    try:
        prior = json.loads(args.prior_inventory.read_text()) if args.prior_inventory else None
        cleanup.api = Compute(deadline)
        cleanup.run_cleanup(prior=prior, snapshot=args.snapshot)
    except Exception as error:
        cleanup.report.update(error=str(error) if isinstance(error, CleanupError) else type(error).__name__, finished_at=timestamp())
        cleanup.save()
        print(f"GCP cleanup failed; inspect {args.output / 'cleanup.json'}", file=sys.stderr)
        return 1
    print(f"{'Captured resource identities' if args.snapshot else 'Verified no remaining resources'} for {args.benchmark_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
