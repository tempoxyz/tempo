#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
docker compose -f "$root/docker-compose.yaml" config --format json | python3 -c '
import json, sys
services = json.load(sys.stdin)["services"]
assert all(not service.get("restart") for service in services.values())
controlled = {name for name, service in services.items()
              if any(volume.get("target") == "/fault-control" for volume in service.get("volumes", []))}
assert controlled == {"zone-0", "zone-1", "zone-2", "workload"}, controlled
for index in range(3):
    service = services[f"zone-{index}"]
    assert service["entrypoint"] == ["/bin/bash", "/opt/zones/zone-supervisor.sh"]
    assert service["command"] == [str(index), "/opt/zones/zone-node.sh", str(index)]
assert services["zone-rpc"]["entrypoint"] == ["/opt/zones/zone-node.sh"]
print("compose fault isolation fixtures passed")
'

for mode in false true; do
    ZONE_HANDOFF_DIRECT_ONLY="$mode" docker compose -f "$root/docker-compose.yaml" config --format json |
        EXPECTED_MODE="$mode" python3 -c '
import json, os, sys
services = json.load(sys.stdin)["services"]
assert services["workload"]["environment"]["ZONE_HANDOFF_DIRECT_ONLY"] == os.environ["EXPECTED_MODE"]
assert all("ZONE_HANDOFF_DIRECT_ONLY" not in service.get("environment", {})
           for name, service in services.items() if name != "workload")
'
done
echo 'focused handoff configuration fixtures passed'
