"""Emit advisory GitHub warnings for nextest tests that passed after retrying."""

import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def warning(title, message):
    # Escape workflow-command data, including newlines in XML attributes.
    message = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::warning title={title}::{message}")


def report_flakes(path):
    try:
        root = ET.parse(path).getroot()
    except FileNotFoundError:
        # A build failure or interrupted test run may not produce a report.
        print("No E2E JUnit report found; skipping flaky-test warnings.")
        return
    except (ET.ParseError, OSError) as error:
        warning("E2E report unavailable", f"Could not read JUnit report: {error}")
        return

    for case in root.iter("testcase"):
        # Only direct child elements describe this test's result. Captured output
        # (including CDATA containing XML-like text) must never count as a flake.
        if any(child.tag in {"failure", "error", "skipped"} for child in case):
            continue
        retries = sum(child.tag in {"flakyFailure", "flakyError"} for child in case)
        if retries:
            name = f"{case.get('classname', '')}::{case.get('name', '(unnamed)')}"
            warning(
                "Flaky E2E test",
                f"{name} passed after {retries} failed attempt(s). "
                "See the nextest output and JUnit artifact for details.",
            )


if __name__ == "__main__":
    report_flakes(Path(sys.argv[1]))
