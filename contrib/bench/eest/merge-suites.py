#!/usr/bin/env python3
"""Merge independent Tempo Engine suites into one boundary-aware manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any


FILE_FIELDS = ("rlp_file", "bal_file")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Merge tempo-engine-suite/v1 manifests without copying their block data. "
            "The resulting suite requires Benchmarkoor rollback_strategy=container-recreate."
        )
    )
    parser.add_argument("--out", required=True, type=Path, help="Output manifest path")
    parser.add_argument("--name", default="tempo-complete-benchmark-suite")
    parser.add_argument("manifests", nargs="+", type=Path)
    return parser.parse_args()


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as source:
        manifest = json.load(source)
    if manifest.get("format") != "tempo-engine-suite/v1":
        raise ValueError(f"{path}: unsupported format {manifest.get('format')!r}")
    if not manifest.get("tests"):
        raise ValueError(f"{path}: suite contains no tests")
    return manifest


def resolve_reference(manifest_path: Path, reference: str) -> Path:
    return (manifest_path.parent / reference).resolve()


def relative_reference(output_path: Path, referenced_path: Path) -> str:
    return os.path.relpath(referenced_path, output_path.parent)


def rewrite_call_files(
    call: dict[str, Any], manifest_path: Path, output_path: Path
) -> None:
    for field in FILE_FIELDS:
        reference = call.get(field)
        if reference:
            source_path = resolve_reference(manifest_path, reference)
            if not source_path.is_file():
                raise ValueError(f"{manifest_path}: missing {field} file {source_path}")
            call[field] = relative_reference(output_path, source_path)


def main() -> None:
    args = parse_args()
    output_path = args.out.resolve()
    manifest_paths = [path.resolve() for path in args.manifests]
    loaded = [(path, load_manifest(path)) for path in manifest_paths]

    first_path, first = loaded[0]
    first_chain = first["chain"]
    first_defaults = first.get("defaults", {})
    genesis_path = resolve_reference(first_path, first_chain["genesis"])
    genesis_digest = hashlib.sha256(genesis_path.read_bytes()).hexdigest()

    tests: list[dict[str, Any]] = []
    source_names: list[str] = []
    for segment_index, (manifest_path, manifest) in enumerate(loaded):
        source_name = manifest["name"]
        source_names.append(source_name)
        if manifest["chain"] != first_chain:
            raise ValueError(f"{manifest_path}: chain configuration differs from first suite")
        if manifest.get("defaults", {}) != first_defaults:
            raise ValueError(f"{manifest_path}: defaults differ from first suite")

        candidate_genesis = resolve_reference(manifest_path, manifest["chain"]["genesis"])
        candidate_digest = hashlib.sha256(candidate_genesis.read_bytes()).hexdigest()
        if candidate_digest != genesis_digest:
            raise ValueError(f"{manifest_path}: genesis differs from first suite")

        for test_index, source_test in enumerate(manifest["tests"]):
            test = json.loads(json.dumps(source_test))
            test["name"] = f"{source_name}::{source_test['name']}"
            test["tags"] = list(dict.fromkeys([*test.get("tags", []), "merged-suite"]))
            metadata = dict(test.get("metadata", {}))
            metadata["source_suite"] = source_name
            metadata["suite_segment"] = str(segment_index)
            if test_index == 0:
                metadata["suite_segment_start"] = "true"
            test["metadata"] = metadata
            for phase in ("setup", "test", "cleanup"):
                for call in test.get(phase, []):
                    rewrite_call_files(call, manifest_path, output_path)
            tests.append(test)

    output = {
        "format": "tempo-engine-suite/v1",
        "name": args.name,
        "description": (
            "All verified EEST-derived and Tempo-native benchmark suites, with "
            "fresh Tempo state at each source-suite boundary"
        ),
        "origin": {
            "kind": "suite-bundle",
            "repository": "https://github.com/tempoxyz/tempo",
            "generator": "contrib/bench/eest/merge-suites.py",
        },
        "chain": {
            **first_chain,
            "genesis": relative_reference(output_path, genesis_path),
        },
        "metadata": {
            "measurement": "server_execution_ns",
            "source_suites": ",".join(source_names),
            "segment_count": str(len(loaded)),
            "test_count": str(len(tests)),
            "requires_rollback_strategy": "container-recreate",
            "segment_boundary_metadata": "suite_segment_start",
        },
        "defaults": first_defaults,
        "tests": tests,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "manifest": str(output_path),
                "segments": len(loaded),
                "tests": len(tests),
                "genesis_sha256": genesis_digest,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
