#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/snouty" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$ARGS_FILE"
STUB
chmod +x "$tmp/snouty"
export PATH="$tmp:$PATH" ARGS_FILE="$tmp/args"
image="example.invalid/config@sha256:$(printf '%064d' 0)"
bash "$root/launch.sh" "$image" 24 > "$tmp/printed"
[[ ! -e "$ARGS_FILE" ]]
for network in false true; do
    set -- "$image" 24
    if [[ "$network" == true ]]; then set -- "$@" --network-faults; fi
    bash "$root/launch.sh" "$@" --launch
    grep -qx 'custom_faults' "$ARGS_FILE"
    grep -Fqx 'custom.include_for_node_termination=^zone-[0-2]$' "$ARGS_FILE"
    grep -qx -- '--max-compute-hours' "$ARGS_FILE"
    grep -qx '24' "$ARGS_FILE"
    grep -qx -- '--setup-timeout' "$ARGS_FILE"
    grep -qx '5m' "$ARGS_FILE"
    if [[ "$network" == true ]]; then
        grep -qx 'custom.disable_network_faults=false' "$ARGS_FILE"
        grep -qx 'zones-leader-quorum' "$ARGS_FILE"
    else
        grep -qx 'custom.disable_network_faults=true' "$ARGS_FILE"
    fi
    grep -Fqx '^(l1|provision|workload|zone-rpc|proxy-[0-2])$' "$ARGS_FILE"
    grep -Fqx 'custom.exclude_from_network_faults=^(l1|provision|workload|zone-rpc|proxy-[0-2])$' "$ARGS_FILE"
    if grep -Eq 'antithesis.duration|--duration|fault.tolerance' "$ARGS_FILE"; then
        echo 'unexpected duration or fault_tolerance parameter' >&2
        exit 1
    fi
done
for args in 'latest 24' "$image 0" "$image 11" "$image 1001" "$image 24 --other" "$image 30 24" "$image 24 --launch --launch" "$image 24 --network-faults --network-faults"; do
    rm -f "$ARGS_FILE"
    # Inputs are fixture literals, deliberately split into argv (never evaluated as code).
    # shellcheck disable=SC2086
    if bash "$root/launch.sh" $args > /dev/null 2>&1; then
        echo "accepted invalid launch: $args" >&2
        exit 1
    fi
    [[ ! -e "$ARGS_FILE" ]]
done
echo 'launch fixtures passed (no service contacted)'
