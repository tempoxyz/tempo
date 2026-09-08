#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-utils.sh"

tmp_dir=$(mktemp -d)
tx_gen_pid=""
export TX_GEN_READY_FILE="$tmp_dir/ready"
cleanup() {
  if [[ "$tx_gen_pid" =~ ^[0-9]+$ ]] && kill -0 "$tx_gen_pid" 2>/dev/null; then
    kill "$tx_gen_pid" 2>/dev/null || true
    wait "$tx_gen_pid" 2>/dev/null || true
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

cat >"$tmp_dir/tx-generator.sh" <<'EOF'
#!/usr/bin/env bash
if [[ "${2:-}" == "fail" ]]; then
  exit 7
fi
trap 'exit 0' TERM
: >"$TX_GEN_READY_FILE"
while :; do
  read -r -t 1 || true
done
EOF
chmod +x "$tmp_dir/tx-generator.sh"

start_tx_generator tx_gen_pid 999999 "$tmp_dir"
[[ "$tx_gen_pid" =~ ^[0-9]+$ ]]
kill -0 "$tx_gen_pid"
for _ in {1..100}; do
  [[ -e "$TX_GEN_READY_FILE" ]] && break
  kill -0 "$tx_gen_pid"
  sleep 0.01
done
[[ -e "$TX_GEN_READY_FILE" ]]
stop_tx_generator "$tx_gen_pid"
! kill -0 "$tx_gen_pid" 2>/dev/null

if stop_tx_generator "not-a-pid"; then
  echo "stop_tx_generator accepted an invalid PID" >&2
  exit 1
fi

start_tx_generator tx_gen_pid fail "$tmp_dir"
sleep 0.1
if stop_tx_generator "$tx_gen_pid"; then
  echo "stop_tx_generator ignored a failed generator" >&2
  exit 1
fi
