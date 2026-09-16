#!/usr/bin/env python3
"""Linux integration check: distinguish direct-I/O files from warmed cached files."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location(
    "snapshot", Path(__file__).with_name("bench-cache-snapshot.py")
)
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)

with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "file"
    subprocess.run(
        ["dd", "if=/dev/zero", f"of={path}", "bs=4096", "count=4", "oflag=direct"],
        check=True, capture_output=True,
    )
    cold = snapshot.file_cache([path])
    assert cold["complete"], cold
    assert cold["size_bytes"] == 16384, cold
    assert cold["resident_bytes"] == 0, cold
    subprocess.run(
        ["dd", f"if={path}", "of=/dev/null", "bs=4096", "iflag=direct"],
        check=True, capture_output=True,
    )
    direct = snapshot.file_cache([path])
    assert direct["complete"] and direct["resident_bytes"] == 0, direct
    assert path.read_bytes() == bytes(16384)
    warm = snapshot.file_cache([path])
    assert warm["complete"] and warm["resident_bytes"] == 16384, warm
    print("Verified cache residency: direct I/O = 0 bytes, buffered I/O = 16384 bytes")
