#!/usr/bin/env python3
"""Choose unused HTTP/metrics/auth ports once for a local e2e comparison."""
import json
import socket


def select_ports():
    # Stay below Linux's default ephemeral range. Consensus/P2P endpoints and
    # validator identities remain unchanged; only local services use this range.
    for base in range(20000, 32000, 1000):
        ports = {side: {"http_port": base + offset + 45,
                        "metrics_port": base + offset + 1,
                        "authrpc_port": base + offset + 3}
                 for side, offset in [("a", 0), ("b", 100)]}
        probes = []
        try:
            for node in ports.values():
                for port in node.values():
                    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    probes.append(probe)
                    probe.bind(("0.0.0.0", port))
            return ports
        except OSError:
            continue
        finally:
            for probe in probes:
                probe.close()
    raise SystemExit("No free e2e listener range between 20000 and 32000")


if __name__ == "__main__":
    print(json.dumps(select_ports()))
