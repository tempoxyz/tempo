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
bash "$root/launch.sh" "$image" 30 24 > "$tmp/printed"
[[ ! -e "$ARGS_FILE" ]]
bash "$root/launch.sh" "$image" 30 24 --launch
grep -qx 'custom_faults' "$ARGS_FILE"
grep -Fqx 'custom.include_for_node_termination=^zone-[0-2]$' "$ARGS_FILE"
grep -qx 'antithesis.duration=30' "$ARGS_FILE"
grep -qx 'custom.disable_network_faults=true' "$ARGS_FILE"
grep -Fqx '^(l1|provision|workload|zone-rpc)$' "$ARGS_FILE"
! grep -q 'fault.tolerance' "$ARGS_FILE"
for args in 'latest 30 24' "$image 31 24" "$image 0 24" "$image 30 1001" "$image 30 24 --other"; do
    rm "$ARGS_FILE"
    # Inputs are fixture literals, deliberately split into argv (never evaluated as code).
    # shellcheck disable=SC2086
    if bash "$root/launch.sh" $args > /dev/null 2>&1; then
        echo "accepted invalid launch: $args" >&2
        exit 1
    fi
    [[ ! -e "$ARGS_FILE" ]]
    touch "$ARGS_FILE"
done
echo 'launch fixtures passed (no service contacted)'
