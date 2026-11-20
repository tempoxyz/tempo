#!/usr/bin/env bash
# Prints a zone-only termination launch; --launch explicitly submits the paid run.
set -euo pipefail

if (( $# < 3 || $# > 4 )); then
    echo "usage: bash $0 CONFIG_IMAGE@sha256:DIGEST DURATION_MINUTES COMPUTE_HOURS [--launch]" >&2
    exit 2
fi
image=$1
minutes=$2
hours=$3
if [[ ! "$image" =~ ^[^[:space:]]+@sha256:[[:xdigit:]]{64}$ ]] ||
   [[ ! "$minutes" =~ ^[1-9][0-9]{0,3}$ ]] ||
   [[ ! "$hours" =~ ^[1-9][0-9]{0,3}$ ]] ||
   (( hours < 12 || hours > 1000 || minutes * 48 > hours * 60 )); then
    echo "use a digest-pinned config, positive minutes, and 12..1000 standard-tier compute-hours covering the duration" >&2
    exit 2
fi
if (( $# == 4 )) && [[ "$4" != --launch ]]; then
    echo "the only optional argument is --launch" >&2
    exit 2
fi

# custom_faults uses legacy internally. Do not send antithesis.fault_tolerance:
# the custom parameters below, not a built-in level, select the disruptions.
args=(
    launch --launcher custom_faults --config-image "$image"
    --test-name zones-single-sequencer-outage --performance-tier standard
    --max-compute-hours "$hours" --param "antithesis.duration=$minutes"
    --fault-exclusions '^(l1|provision|workload|zone-rpc)$'
    --param 'custom.exclude_from_network_faults=^(l1|provision|workload|zone-rpc)$'
    --param custom.disable_network_faults=true
    --param custom.include_for_node_throttle=
    --param custom.include_all_for_node_throttle=false
    --param custom.include_for_node_hang=
    --param custom.include_all_for_node_hang=false
    --param 'custom.include_for_node_termination=^zone-[0-2]$'
    --param custom.include_all_for_node_termination=false
    --param custom.cpu_modulation=false
    --param custom.clock_jitter=false
    --param custom.disable_faults=false
    --param custom.smoke_test_seconds=100
)
if (( $# == 4 )); then
    exec snouty "${args[@]}"
fi
printf 'snouty'
printf ' %q' "${args[@]}"
printf '\n'
