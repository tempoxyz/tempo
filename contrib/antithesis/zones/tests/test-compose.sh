#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
docker compose -f "$root/docker-compose.yaml" config --format json | python3 -c '
import json, sys
services = json.load(sys.stdin)["services"]
assert all(not service.get("restart") for service in services.values())
controlled = {name for name, service in services.items()
              if any(volume.get("target") == "/fault-control" for volume in service.get("volumes", []))}
assert controlled == {"zone-0", "zone-1", "zone-2", "proxy-0", "proxy-1", "proxy-2", "workload"}, controlled
for index in range(3):
    proxy = services[f"proxy-{index}"]
    assert proxy["image"] == services[f"zone-{index}"]["image"]
    assert proxy["entrypoint"] == ["/usr/local/bin/tempo-zones-antithesis"]
    assert proxy["command"] == ["fault-proxy", "--index", str(index)]
    assert proxy["networks"]["zones"]["ipv4_address"] == f"10.20.0.{41 + index}"
    assert proxy["init"] is True
    assert proxy["hostname"] == proxy["container_name"] == f"proxy-{index}"
    assert {v["target"] for v in proxy["volumes"]} == {"/fault-control"}
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

# Execute zone-node.sh against a stub to prove only quorum L1 URLs are proxied.
python3 - "$root" <<'PYTEST'
import pathlib, subprocess, sys, tempfile
root = pathlib.Path(sys.argv[1])
with tempfile.TemporaryDirectory() as tmp:
    script = pathlib.Path(tmp) / "zone-node.sh"
    script.write_text((root / "scripts/zone-node.sh").read_text().replace(
        "exec /usr/local/bin/tempo-zone node", "printf '%s\\n' node"))
    for node in ["0", "1", "2", "rpc"]:
        args = subprocess.check_output(["sh", str(script), node], text=True).splitlines()
        expected = "ws://10.20.0.10:8546" if node == "rpc" else f"ws://10.20.0.{41+int(node)}:8546"
        assert args[args.index("--l1.rpc-url") + 1] == expected, args
        assert args[args.index("--p2p.listen") + 1] == "0.0.0.0:9200"
        assert "--p2p.bypass-ip-check" in args
provision = (root / "scripts/provision.sh").read_text()
assert "10.20.0.$((41 + i)):9200" in provision
assert "10.20.0.20:9200" in provision
print("proxy routing fixtures passed")
PYTEST
