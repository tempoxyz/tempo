#!/usr/bin/env python3
"""Update the current/next hardfork matrix in tempoxyz/workflows."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def replace_parameter(path: Path, value: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if line.strip() != "- name: hardforks":
            continue
        for value_index in range(index + 1, min(index + 12, len(lines))):
            if lines[value_index].strip().startswith("- name:"):
                break
            if lines[value_index].lstrip().startswith("value:"):
                indent = lines[value_index][: len(lines[value_index]) - len(lines[value_index].lstrip())]
                lines[value_index] = f"{indent}value: '{value}'"
                path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                return
    raise ValueError(f"missing hardforks parameter in {path}")


def parse_metadata(raw: str, requested: str) -> tuple[list[dict[str, str]], dict[str, object]]:
    try:
        metadata = json.loads(raw)
        current = metadata["current"]
        next_hardfork = metadata["next"]
        ordered = metadata["ordered"]
        matrix = metadata["hardforks"]
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise ValueError("invalid hardfork metadata") from error

    if (
        not isinstance(current, str)
        or not isinstance(next_hardfork, str)
        or not isinstance(ordered, list)
        or not all(isinstance(hardfork, str) for hardfork in ordered)
        or not isinstance(matrix, list)
        or len(matrix) != 2
        or not all(isinstance(lane, dict) for lane in matrix)
        or not all(
            isinstance(lane.get("hardfork"), str) and isinstance(lane.get("genesisArgs"), str)
            for lane in matrix
        )
    ):
        raise ValueError("invalid hardfork metadata shape")
    if len(ordered) < 2 or ordered[-2:] != [current, next_hardfork]:
        raise ValueError("hardfork metadata must end with current and next hardforks")
    if next_hardfork != requested:
        raise ValueError(
            f"generated next profile is {next_hardfork}, expected requested hardfork {requested}"
        )
    if [lane["hardfork"] for lane in matrix] != [current, next_hardfork]:
        raise ValueError("hardfork metadata lanes must match current and next hardforks")
    return matrix, metadata


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflows-root", type=Path, required=True)
    parser.add_argument("--hardfork", required=True)
    parser.add_argument("--metadata", required=True)
    args = parser.parse_args()

    matrix, metadata = parse_metadata(args.metadata, args.hardfork)
    replace_parameter(
        args.workflows_root / "manifests/tempo-tests.yaml",
        json.dumps(matrix, separators=(",", ":")),
    )
    replace_parameter(
        args.workflows_root / "manifests/invariant-tests.yaml",
        json.dumps([{"hardfork": lane["hardfork"]} for lane in matrix], separators=(",", ":")),
    )
    print(json.dumps(metadata, separators=(",", ":")))


if __name__ == "__main__":
    main()
