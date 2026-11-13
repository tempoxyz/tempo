#!/usr/bin/env bash
# Prints a zone-only fault launch; --launch explicitly submits the paid run.
set -euo pipefail

if (( $# < 2 || $# > 4 )); then
    echo "usage: bash $0 CONFIG_IMAGE@sha256:DIGEST COMPUTE_HOURS [--network-faults] [--launch]" >&2
    exit 2
fi
image=$1
hours=$2
shift 2
if [[ ! "$image" =~ ^[^[:space:]]+@sha256:[[:xdigit:]]{64}$ ]] ||
   [[ ! "$hours" =~ ^[1-9][0-9]{0,3}$ ]] || (( hours < 12 || hours > 1000 )); then
    echo "use a digest-pinned config and 12..1000 standard-tier compute-hours" >&2
    exit 2
fi
launch=false
network=false
for option in "$@"; do
    case "$option" in
        --launch) [[ "$launch" == false ]] || exit 2; launch=true ;;
        --network-faults) [[ "$network" == false ]] || exit 2; network=true ;;
        *) echo "unknown option: $option" >&2; exit 2 ;;
    esac
done
# Duration and compute budget are alternatives. A raw duration parameter bypasses snouty's
# typed conflict check; do not send both. Confirm custom launcher budget support before use.
disable_network=true
name=zones-single-sequencer-outage
if [[ "$network" == true ]]; then
    disable_network=false
    name=zones-leader-quorum
fi

# custom_faults uses legacy internally. Do not send antithesis.fault_tolerance:
# the custom parameters below, not a built-in level, select the disruptions.
args=(
    launch --launcher custom_faults --config-image "$image"
    --test-name "$name" --performance-tier standard
    --max-compute-hours "$hours" --setup-timeout 5m
    --fault-exclusions '^(l1|provision|workload|zone-rpc|proxy-[0-2])$'
    --param 'custom.exclude_from_network_faults=^(l1|provision|workload|zone-rpc|proxy-[0-2])$'
    --param "custom.disable_network_faults=$disable_network"
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
if [[ "$launch" == true ]]; then
    exec snouty "${args[@]}"
fi
printf 'snouty'
printf ' %q' "${args[@]}"
printf '\n'
