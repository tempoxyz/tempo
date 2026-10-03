#!/usr/bin/env python3
"""No cloud access: ownership, deletion and incomplete-evidence regressions."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import shutil
import subprocess
import textwrap
import time
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("gcp_cleanup", Path(__file__).with_name("gcp_cleanup.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
RUN = "bench-e2e-multi-region-37125841828-1"
WWW = m.BASE.replace("compute.googleapis.com", "www.googleapis.com")
ZONE = "us-central1-a"


def resource(kind, role="validator", identity="123", run=RUN, index=0):
    suffix = {"validator": f"validator-{index}", "load-generator": "load-generator-0",
              "state-snapshot-builder": "snapshot-builder"}[role]
    item = {"name": "tempo-e2e-" + run[:36] + "-" + suffix, "id": identity,
            "zone": WWW + "/zones/" + ZONE,
            "labels": {"benchmark-id": run, "managed-by": "terraform",
                       "repository": "tempo-multi-region-benchmark", "role": role}}
    if kind == "instances":
        item["disks"] = [{"type": "PERSISTENT", "boot": True, "autoDelete": True,
                          "source": WWW + f"/zones/{ZONE}/disks/" + item["name"]}, {"type": "SCRATCH"}]
    else:
        item["users"] = []
    return item


class FakeCompute:
    def __init__(self, resources=()):
        self.resources = {m.resource_path(kind, item): copy.deepcopy(item) for kind, item in resources}
        self.calls, self.operations = [], {}
        self.warning = None
        self.fail = None
        self.operation_change = lambda value: value
        self.get_change = lambda path, value: value
        self.page_size = 500
        self.aggregation_count = 0
        self.inventory_change = lambda api: None
        self.running_once = False

    def request(self, method, path, **params):
        self.calls.append((method, path, params))
        if self.fail:
            raise m.CleanupError(self.fail)
        if path.startswith("aggregated/"):
            self.aggregation_count += 1
            self.inventory_change(self)
            kind = path.split("/")[1]
            items = [copy.deepcopy(value) for key, value in self.resources.items() if key.split("/")[2] == kind]
            offset = int(params.get("pageToken", "") or "0")
            result = {"kind": f"compute#{kind[:-1]}AggregatedList", "items": {
                "zones/" + ZONE: {kind: items[offset:offset + self.page_size]}}}
            if offset + self.page_size < len(items):
                result["nextPageToken"] = str(offset + self.page_size)
            if self.warning:
                result["items"]["zones/" + ZONE]["warning"] = {"code": self.warning}
            return result
        if "/operations/" in path:
            result = copy.deepcopy(self.operations[path])
            result["status"] = "DONE"
            return result
        if method == "GET":
            return self.get_change(path, copy.deepcopy(self.resources.get(path)))
        assert method == "DELETE"
        item = self.resources.pop(path)
        if "/instances/" in path:
            for disk in item["disks"]:
                if disk.get("source"):
                    self.resources[m.relative_link(disk["source"])]["users"] = []
        operation_path = f"zones/{ZONE}/operations/op-{item['id']}"
        result = {"name": "op-" + item["id"], "operationType": "delete", "targetId": item["id"],
                  "targetLink": WWW + "/" + path, "zone": WWW + "/zones/" + ZONE,
                  "status": "RUNNING" if self.running_once else "DONE"}
        result = self.operation_change(result)
        self.operations[operation_path] = copy.deepcopy(result)
        return result

    @property
    def deletions(self):
        return [path for method, path, _ in self.calls if method == "DELETE"]


def pair(role="validator", identity=123, index=0):
    instance = resource("instances", role, str(identity), index=index)
    disk = resource("disks", role, str(identity + 1), index=index)
    disk["users"] = [WWW + "/" + m.resource_path("instances", instance)]
    return [("instances", instance), ("disks", disk)]


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def cleanup(self, api, recover=True, deadline=None):
        return m.Cleanup(api, RUN, self.directory.name, deadline or time.monotonic() + 600,
                         recover, sleep=lambda _: None)

    def test_empty_requires_two_fresh_verifications(self):
        api = FakeCompute()
        cleanup = self.cleanup(api)
        cleanup.run_cleanup()
        self.assertTrue(cleanup.report["ok"])
        self.assertEqual(6, api.aggregation_count)
        self.assertEqual([], api.deletions)

    def test_all_roles_paginated_and_immutable_operations(self):
        items = pair() + pair("load-generator", 223) + pair("state-snapshot-builder", 323)
        api = FakeCompute(items)
        api.page_size, api.running_once = 1, True
        cleanup = self.cleanup(api)
        cleanup.run_cleanup()
        self.assertEqual(6, len(api.deletions))
        self.assertTrue(all("/instances/" in path for path in api.deletions[:3]))
        self.assertEqual(set(), set(api.resources))
        self.assertTrue(cleanup.report["ok"])
        self.assertEqual(6, len(cleanup.report["operations"]))
        saved = json.loads((Path(self.directory.name) / "cleanup.json").read_text())
        self.assertEqual(RUN, saved["benchmark_id"])

    def test_other_runs_and_shared_resources_untouched(self):
        other = resource("disks", run="bench-e2e-multi-region-37125841829-1")
        shared = resource("disks", identity="999")
        shared["labels"] = {}
        api = FakeCompute([("disks", other), ("disks", shared)])
        self.cleanup(api).run_cleanup()
        self.assertFalse(api.deletions)
        self.assertEqual(2, len(api.resources))

    def test_bad_ids_rejected_before_api(self):
        for run in ("", RUN + "-extra", "bench-e2e-multi-region-1-0", "../" + RUN, RUN.upper()):
            with self.subTest(run=run), self.assertRaises(m.CleanupError):
                m.Cleanup(None, run, self.directory.name, time.monotonic() + 600)

    def test_conflicting_labels_roles_and_name_fail_before_delete(self):
        for change in ({"repository": "other"}, {"managed-by": "other"}, {"role": "database"}):
            item = resource("disks")
            item["labels"].update(change)
            api = FakeCompute([("disks", item)])
            with self.subTest(change=change), self.assertRaises(m.CleanupError):
                self.cleanup(api).run_cleanup()
            self.assertFalse(api.deletions)
        item = resource("disks")
        item["name"] = "shared-disk"
        api = FakeCompute([("disks", item)])
        with self.assertRaises(m.CleanupError):
            self.cleanup(api).run_cleanup()
        self.assertFalse(api.deletions)

    def test_incomplete_inventory_never_means_empty(self):
        for warning in ("UNREACHABLE", "SCOPE_UNAVAILABLE"):
            api = FakeCompute()
            api.warning = warning
            with self.subTest(warning=warning), self.assertRaises(m.CleanupError):
                self.cleanup(api).run_cleanup()
            self.assertFalse(api.deletions)
        api = FakeCompute()
        api.fail = "permission denied"
        cleanup = self.cleanup(api)
        with self.assertRaises(m.CleanupError):
            cleanup.run_cleanup()
        self.assertFalse(cleanup.report["ok"])
        self.assertTrue((Path(self.directory.name) / "cleanup.json").exists())

    def test_dry_verification_wont_delete_leftovers(self):
        api = FakeCompute([("disks", resource("disks"))])
        with self.assertRaises(m.CleanupError):
            self.cleanup(api, recover=False).run_cleanup()
        self.assertFalse(api.deletions)

    def test_attached_disk_is_never_deleted(self):
        disk = resource("disks")
        disk["users"] = [WWW + "/zones/elsewhere/instances/someone-else"]
        api = FakeCompute([("disks", disk)])
        with self.assertRaises(m.CleanupError):
            self.cleanup(api).run_cleanup()
        self.assertFalse(api.deletions)

    def test_vm_with_shared_or_nonboot_disk_is_never_deleted(self):
        for scenario in ("shared", "nonboot", "other-user", "nonauto"):
            items = pair()
            if scenario == "shared":
                items[1][1]["labels"] = {}
            elif scenario == "nonboot":
                items[0][1]["disks"][0]["boot"] = False
            elif scenario == "nonauto":
                items[0][1]["disks"][0]["autoDelete"] = False
            else:
                items[1][1]["users"].append(WWW + "/zones/us-central1-a/instances/other")
            api = FakeCompute(items)
            with self.subTest(scenario=scenario), self.assertRaises(m.CleanupError):
                self.cleanup(api).run_cleanup()
            self.assertFalse(api.deletions)

    def test_same_name_recreated_or_relabelled_fails_before_delete(self):
        for field, value in (("id", "987"), ("labels", {})):
            api = FakeCompute([("disks", resource("disks"))])
            def changed(path, item):
                if item is not None:
                    item[field] = value
                return item
            api.get_change = changed
            with self.subTest(field=field), self.assertRaises(m.CleanupError):
                self.cleanup(api).run_cleanup()
            self.assertFalse(api.deletions)

    def test_operation_error_and_wrong_target_never_pass(self):
        for change in ({"targetId": "987"}, {"error": {"errors": [{"code": "DENIED"}]}},
                       {"targetLink": WWW + "/zones/elsewhere/disks/wrong"}, {"warnings": [{"code": "UNKNOWN"}]}):
            api = FakeCompute([("disks", resource("disks"))])
            api.operation_change = lambda result: {**result, **change}
            cleanup = self.cleanup(api)
            with self.subTest(change=change), self.assertRaises(m.CleanupError):
                cleanup.run_cleanup()
            self.assertFalse(cleanup.report["ok"])

    def test_resource_appearing_between_empty_scans_fails(self):
        api = FakeCompute()
        def new_resource(fake):
            if fake.aggregation_count == 5:
                item = resource("disks")
                fake.resources[m.resource_path("disks", item)] = item
        api.inventory_change = new_resource
        with self.assertRaises(m.CleanupError):
            self.cleanup(api).run_cleanup()
        self.assertFalse(api.deletions)

    def test_deadline_bounds_operation_poll(self):
        api = FakeCompute([("disks", resource("disks"))])
        api.running_once = True
        with self.assertRaisesRegex(m.CleanupError, "deadline"):
            self.cleanup(api, deadline=time.monotonic() + 1).run_cleanup()

    def test_self_links_cannot_cross_project(self):
        item = resource("disks")
        item["zone"] = WWW.replace(m.PROJECT, "other-project") + "/zones/us-central1-a"
        with self.assertRaises(m.CleanupError):
            m.resource_path("disks", item)

    def test_snapshot_never_deletes_and_tracks_terraform_removed_ids(self):
        api = FakeCompute(pair())
        snapshot = self.cleanup(api)
        snapshot.run_cleanup(snapshot=True)
        self.assertFalse(api.deletions)
        self.assertEqual(2, len(snapshot.report["inventories"][0]["resources"]))
        api.resources.clear()  # Terraform already destroyed both resources.
        final = self.cleanup(api)
        final.run_cleanup(prior=snapshot.report)
        self.assertTrue(final.report["ok"])
        self.assertFalse(api.deletions)
        self.assertEqual(2, len(final.report["operations"]))
        self.assertTrue(all(row["already_absent"] for row in final.report["operations"]))

    def test_verify_only_accepts_prior_resources_already_destroyed(self):
        api = FakeCompute([("disks", resource("disks"))])
        snapshot = self.cleanup(api)
        snapshot.run_cleanup(snapshot=True)
        api.resources.clear()
        final = self.cleanup(api, recover=False)
        final.run_cleanup(prior=snapshot.report)
        self.assertTrue(final.report["ok"])
        self.assertFalse(api.deletions)
        self.assertFalse(final.report["operations"])

    def test_changed_prior_id_or_hidden_relabelled_resource_is_rejected(self):
        for change in ("id", "label"):
            api = FakeCompute([("disks", resource("disks"))])
            snapshot = self.cleanup(api)
            snapshot.run_cleanup(snapshot=True)
            item = next(iter(api.resources.values()))
            if change == "id":
                item["id"] = "987"
            else:
                item["labels"]["benchmark-id"] = "some-other-run"
            with self.subTest(change=change), self.assertRaises(m.CleanupError):
                self.cleanup(api).run_cleanup(prior=snapshot.report)
            self.assertFalse(api.deletions)

    def test_missing_kind_unreachable_scope_and_bad_pagination_fail(self):
        for response in ({}, {"kind": "compute#instanceAggregatedList", "unreachables": ["zone"]},
                         {"kind": "compute#instanceAggregatedList", "nextPageToken": "repeat"}):
            api = FakeCompute()
            with mock.patch.object(api, "request", return_value=response), self.assertRaises(m.CleanupError):
                self.cleanup(api).run_cleanup()
            self.assertFalse(api.deletions)

    def test_http_404_means_absent_only_for_resource_get(self):
        api = m.Compute.__new__(m.Compute)
        api.deadline, api.token = time.monotonic() + 600, "fake-not-a-credential"
        error = m.urllib.error.HTTPError("https://example.invalid", 404, "missing", {}, None)
        with mock.patch.object(m.urllib.request, "urlopen", side_effect=error):
            self.assertIsNone(api.request("GET", "zones/us-central1-a/instances/some-name"))
            self.assertIsNone(api.request("GET", "zones/us-central1-a/disks/some-name"))
            for method, path in (("GET", "aggregated/instances"), ("GET", "zones/us-central1-a/operations/op"),
                                 ("DELETE", "zones/us-central1-a/disks/some-name")):
                with self.subTest(method=method, path=path), self.assertRaises(m.CleanupError):
                    api.request(method, path)
        with mock.patch.object(m.urllib.request, "urlopen", return_value=io.BytesIO(b"not JSON")):
            with self.assertRaises(m.CleanupError):
                api.request("GET", "aggregated/disks")
        forbidden = m.urllib.error.HTTPError("https://example.invalid", 403, "forbidden", {}, None)
        with mock.patch.object(m.urllib.request, "urlopen", side_effect=forbidden), self.assertRaises(m.CleanupError):
            api.request("GET", "zones/us-central1-a/disks/some-name")


@unittest.skipUnless(shutil.which("node"), "Node is needed to execute the actual GitHub-script target guard")
class WorkflowGuardTests(unittest.TestCase):
    def test_actual_recovery_guard_accepts_only_completed_matching_attempt(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/bench-e2e-multi-region.yml").read_text()
        source = workflow.split("- name: Validate completed cleanup target before cloud authentication", 1)[1]
        script = textwrap.dedent(source.split("script: |\n", 1)[1].split("\n      - name:", 1)[0])
        self.assertNotIn("github-token:", source.split("script: |", 1)[0])
        good = {"id": 37125841828, "run_attempt": 1, "repository": {"full_name": "tempoxyz/tempo"},
                "path": ".github/workflows/bench-e2e-multi-region.yml", "status": "completed", "head_sha": "a" * 40}
        cases = [(good, good, RUN, True)]
        for change in ({"status": "in_progress"}, {"repository": {"full_name": "other/repo"}},
                       {"path": ".github/workflows/unrelated.yml"}, {"run_attempt": 2}, {"id": 1}):
            cases.append((good, {**good, **change}, RUN, False))
        cases.extend([({**good, "status": "in_progress"}, good, RUN, False),
                      (good, good, "bench-e2e-multi-region-37125841828-0", False),
                      (good, good, "main", False)])
        for latest, attempt, benchmark_id, accepted in cases:
            with self.subTest(attempt=attempt, benchmark_id=benchmark_id), tempfile.TemporaryDirectory() as directory:
                harness = "const context = {repo:{owner:'tempoxyz',repo:'tempo'},sha:'abc',actor:'test'};\n"
                harness += "const github = {rest:{actions:{getWorkflowRun:async()=>({data:" + json.dumps(latest) + "}),"
                harness += "getWorkflowRunAttempt:async()=>({data:" + json.dumps(attempt) + "})}}};\n"
                harness += "process.env.CLEANUP_BENCHMARK_ID=" + json.dumps(benchmark_id) + ";\n"
                harness += "(async()=>{\n" + script + "\n})().catch(()=>process.exitCode=1);"
                result = subprocess.run(["node", "-e", harness], cwd=directory, capture_output=True, timeout=10)
                self.assertEqual(accepted, result.returncode == 0, result.stderr.decode())
                self.assertEqual(accepted, (Path(directory) / "gcp-cleanup-evidence/target.json").exists())


if __name__ == "__main__":
    unittest.main()
