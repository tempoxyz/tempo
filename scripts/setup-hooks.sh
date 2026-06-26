#!/usr/bin/env bash
set -euo pipefail

git config core.hooksPath .githooks
echo "Configured git hooks from .githooks"
