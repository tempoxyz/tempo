#!/usr/bin/env python3
"""Capture the node's built-in Pyroscope profiles to a local loopback server.

Build an unstripped binary first:
  cargo rustc --release -p tempo --bin tempo --features pyroscope -- -C strip=none

Profiling affects throughput; use run_node.py without this wrapper for comparisons.
The output retains the normal trial artifacts plus profiles/*.pb and request metadata.
"""

import argparse
import gzip
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import shlex
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=ROOT / "benchmark-artifacts/parallel-execution" / f"profile-{time.time_ns()}",
                        help="Artifact directory (default: a fresh ignored benchmark-artifacts/parallel-execution/profile-* directory)")
    parser.add_argument("--node-binary", required=True, type=Path)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--target", type=int, default=50000)
    parser.add_argument("--duration", type=int, default=20)
    parser.add_argument("--recipients", choices=["existing", "new"], default="new")
    parser.add_argument("--sample-rate", type=int, default=199)
    args = parser.parse_args()
    if args.duration < 20:
        parser.error("duration must be at least 20 seconds to capture a complete 10-second profile")
    if args.workers < 0 or min(args.target, args.sample_rate) <= 0:
        parser.error("workers must be nonnegative; target and sample rate must be positive")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    profiles = output / "profiles"
    profiles.mkdir()

    class Capture(BaseHTTPRequestHandler):
        def do_POST(self):
            data = self.rfile.read(int(self.headers["Content-Length"]))
            if self.headers.get("Content-Encoding") == "gzip":
                data = gzip.decompress(data)
            name = str(time.time_ns())
            (profiles / f"{name}.pb").write_bytes(data)
            (profiles / f"{name}.json").write_text(json.dumps({
                "url": self.path, "headers": dict(self.headers),
            }, indent=2) + "\n")
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Capture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    wrapper = output / "node-wrapper.sh"
    wrapper.write_text(
        "#!/bin/sh\nexec " + shlex.quote(str(args.node_binary.resolve())) + ' "$@"'
        + f" --pyroscope.enabled --pyroscope.sample-rate {args.sample_rate}"
        + f" --pyroscope.server-url http://127.0.0.1:{server.server_port}\n"
    )
    wrapper.chmod(0o700)
    command = [
        sys.executable, str(Path(__file__).with_name("run_node.py")),
        "--output", str(output / "trial"), "--node-binary", str(wrapper),
        "--workers", str(args.workers), "--targets", str(args.target),
        "--duration", str(args.duration), "--recipients", args.recipients,
        "--nonces", "2d", "--block-gas-limit", "5000000000",
        "--share-sparse-trie", "--builder-max-tasks", "1", "--profile-cpu",
    ]
    (output / "profile-command.json").write_text(json.dumps(command, indent=2) + "\n")
    try:
        subprocess.run(command, check=True)
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


if __name__ == "__main__":
    main()
