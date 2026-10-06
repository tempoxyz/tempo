# /// script
# requires-python = ">=3.10"
# dependencies = ["blake3==1.0.10", "zstandard==0.25.0"]
# ///

"""Exercise snapshot installation with synthetic, non-bootable EL and consensus archives."""

import argparse
import functools
import io
import json
import subprocess
import tarfile
import tempfile
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import blake3
import zstandard


def write_archive(directory, name, path, contents):
    archive_buffer = io.BytesIO()
    with tarfile.open(fileobj=archive_buffer, mode="w") as archive:
        entry = tarfile.TarInfo(path)
        entry.size = len(contents)
        archive.addfile(entry, io.BytesIO(contents))
    compressed = zstandard.ZstdCompressor().compress(archive_buffer.getvalue())
    (directory / name).write_bytes(compressed)
    return {
        "file": name,
        "size": len(compressed),
        "decompressed_size": len(contents),
        "blake3": blake3.blake3(compressed).hexdigest(),
        "output_files": [
            {
                "path": path,
                "size": len(contents),
                "blake3": blake3.blake3(contents).hexdigest(),
            }
        ],
    }


def check_download(tempo, directory, manifest_url, chain_args):
    label = "explicit-chain" if chain_args else "default-chain"
    datadir = directory / label
    result = subprocess.run(
        [
            str(tempo),
            "download",
            "--manifest-url",
            manifest_url,
            "--datadir",
            str(datadir),
            "--archive",
            "-y",
            "--log.file.directory",
            str(directory / "logs" / label),
            *chain_args,
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"{label} download exited {result.returncode}\n{result.stdout}\n{result.stderr}"
        )
    for relative_path, expected in (
        ("db/cli-smoke-test.txt", b"execution snapshot fixture\n"),
        ("consensus/partition/cli-smoke-test.txt", b"consensus snapshot fixture\n"),
    ):
        if (datadir / relative_path).read_bytes() != expected:
            raise RuntimeError(f"{label}: unexpected contents in {relative_path}")
    if not (datadir / "reth.toml").is_file():
        raise RuntimeError(f"{label}: missing generated reth.toml")
    print(f"PASS: Moderato snapshot download ({label})")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tempo", type=Path)
    args = parser.parse_args()
    tempo = args.tempo.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="tempo-cli-download-") as temporary:
        directory = Path(temporary)
        snapshot = directory / "snapshot"
        snapshot.mkdir()
        execution_archive = write_archive(
            snapshot, "state.tar.zst", "db/cli-smoke-test.txt", b"execution snapshot fixture\n"
        )
        consensus_archive = write_archive(
            snapshot,
            "consensus.tar.zst",
            "partition/cli-smoke-test.txt",
            b"consensus snapshot fixture\n",
        )
        digest = "0x" + "00" * 32
        manifest = {
            "block": 0,
            "chain_id": 42431,
            "storage_version": 2,
            "timestamp": 0,
            "components": {"state": execution_archive},
            "consensus": {
                "execution_finalized_height": 0,
                "execution_finalized_digest": digest,
                "tip_finalization_height": 0,
                "tip_finalization_digest": digest,
                "anchor_finalization_height": 0,
                "anchor_finalization_digest": digest,
                "consensus_archive": consensus_archive,
            },
        }
        (snapshot / "manifest.json").write_text(json.dumps(manifest))
        handler = functools.partial(SimpleHTTPRequestHandler, directory=str(snapshot))
        with ThreadingHTTPServer(("127.0.0.1", 0), handler) as server:
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            try:
                manifest_url = f"http://127.0.0.1:{server.server_port}/manifest.json"
                check_download(tempo, directory, manifest_url, ["--chain", "moderato"])
                check_download(tempo, directory, manifest_url, [])
            finally:
                server.shutdown()
                server_thread.join()


if __name__ == "__main__":
    main()
