"""Fail local smoke on a safety counterexample or vacuous workload."""
import json
import sys

with open(sys.argv[1]) as source:
    events = [json.loads(line) for line in source if line.strip()]
checks = [event["antithesis_assert"] for event in events if "antithesis_assert" in event]
failures = [check for check in checks if check.get("hit") and check.get("assert_type") == "always" and not check["condition"]]
required = {
    "The tempo cluster workload starts",
    "Consensus finalizes new blocks",
    "Workload transactions execute successfully",
    "Finalized transfers and mints settle in the ledger",
    "Cluster resumes finality and successful transactions after faults stop",
}
passed = {check["message"] for check in checks if check.get("hit") and check.get("condition")}
if failures or required - passed:
    raise SystemExit(f"Safety failures: {failures}; missing progress: {sorted(required - passed)}")
print("SDK safety and progress checks passed")
