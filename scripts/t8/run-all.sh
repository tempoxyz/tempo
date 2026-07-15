#!/usr/bin/env bash

set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd)

"$dir/test-tip-1042.sh"
"$dir/test-tip-1062-1087.sh" "${DEX_MODE:-post-only}"
"$dir/test-tip-1070.sh"
"$dir/test-tip-1075.sh"

echo "PASS: all requested T8 network checks completed"
