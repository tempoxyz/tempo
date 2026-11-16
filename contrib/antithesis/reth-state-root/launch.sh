#!/usr/bin/env bash
set -euo pipefail

if (( $# < 2 )); then
    echo "Usage: $0 CONFIG_IMAGE MAX_COMPUTE_HOURS [snouty launch options...]" >&2
    exit 2
fi

config_image=$1
compute_hours=$2
shift 2
exec snouty launch --launcher basic_test --config-image "$config_image" --max-compute-hours "$compute_hours" \
    --fault-tolerance high_availability "$@"
