#!/usr/bin/env bash
# Local process fixtures; no Docker daemon, Antithesis run, or network required.
set -euo pipefail
set -m
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
supervisor=$root/scripts/zone-supervisor.sh
tmp=$(mktemp -d)
sup=
cleanup() {
    if [[ -n $sup ]]; then
        kill -TERM "$sup" 2>/dev/null || true
        wait "$sup" 2>/dev/null || true
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; cat "$case_dir/supervisor.log" >&2; exit 1; }

cat > "$tmp/child" <<'CHILD'
#!/usr/bin/env bash
set -eu
dir=$1
trap 'echo TERM >> "$dir/signals"; exit 0' TERM
trap 'echo INT >> "$dir/signals"; exit 0' INT
# Publish readiness only after both handlers exist, avoiding a fixture signal race.
printf '%s\n' "$$" >> "$dir/spawns"
while :; do
    if [[ -f $dir/exit ]]; then exit "$(<"$dir/exit")"; fi
    sleep 0.05
done
CHILD
chmod +x "$tmp/child"

new_case() {
    case_dir=$tmp/$1
    mkdir -p "$case_dir"
    status=$case_dir/zone-0.status
    request=$case_dir/zone-0.request
}
launch() {
    # Some noninteractive launchers inherit SIGINT ignored. Bash cannot trap a
    # signal ignored at entry, even with job control; normalize the fixture's
    # child environment like the container init does, before starting Bash.
    ZONE_FAULT_CONTROL_DIR=$case_dir ZONE_FAULT_HOLD_SECONDS=${1:-30} \
        env --default-signal=INT,TERM bash "$supervisor" 0 "$tmp/child" "$case_dir" \
        >> "$case_dir/supervisor.log" 2>&1 &
    sup=$!
}
send() {
    printf '{"id":%s,"action":"%s"}\n' "$1" "$2" > "$request.tmp"
    mv "$request.tmp" "$request"
}
await_status() {
    local expected=''
    printf -v expected '{"id":%s,"state":"%s","generation":%s}' "$1" "$2" "$3"
    for ((i = 0; i < 200; i++)); do
        if [[ -f $status && $(<"$status") == "$expected" ]]; then return; fi
        kill -0 "$sup" 2>/dev/null || fail "supervisor exited waiting for $expected"
        sleep 0.025
    done
    fail "timed out waiting for $expected; got $(cat "$status" 2>/dev/null || true)"
}
assert_status() {
    local expected
    printf -v expected '{"id":%s,"state":"%s","generation":%s}' "$1" "$2" "$3"
    [[ $(<"$status") == "$expected" ]] || fail "expected $expected; got $(<"$status")"
}
await_spawns() {
    for ((i = 0; i < 200; i++)); do
        if [[ -f $case_dir/spawns && $(wc -l < "$case_dir/spawns") -eq $1 ]]; then
            pid=$(tail -1 "$case_dir/spawns")
            return
        fi
        sleep 0.025
    done
    fail "expected $1 child spawns"
}
await_exit() {
    local expected=$1 code=0
    for ((i = 0; i < 400; i++)); do
        kill -0 "$sup" 2>/dev/null || break
        sleep 0.025
    done
    kill -0 "$sup" 2>/dev/null && fail "supervisor did not exit"
    wait "$sup" || code=$?
    sup=
    [[ $code -eq $expected ]] || fail "expected exit $expected, got $code"
}
assert_dead() { ! kill -0 "$1" 2>/dev/null || fail "child $1 is still alive"; }
stop() { kill -TERM "$sup"; await_exit 143; }

new_case lifecycle
launch
await_status 0 running 1
await_spawns 1
send 1 start
await_status 1 running 1
send 2 kill
await_status 2 down 1
assert_dead "$pid"
sleep 0.25
assert_status 2 down 1
send 1 start
sleep 0.2
assert_status 2 down 1
send 2 start
sleep 0.2
assert_status 2 down 1
send 3 start
await_status 3 running 2
await_spawns 2
send 4 kill
await_status 4 down 2
stop
# A prior DOWN request/status must not kill the replacement process.
launch
await_status 4 running 3
await_spawns 3
sleep 0.2
assert_status 4 running 3
stop
# Even a request interrupted before acknowledgement is stale on startup.
send 5 kill
launch
await_status 5 running 4
await_spawns 4
stop
assert_dead "$pid"
echo 'PASS: SIGKILL/reap, hold, release, idempotent start, stale IDs and container restart'

new_case expiry
launch 1
await_status 0 running 1
await_spawns 1
send 1 kill
await_status 1 down 1
assert_dead "$pid"
await_status 1 running 2
await_spawns 2
sleep 0.2
assert_status 1 running 2
stop
echo 'PASS: watchdog expiry changes state and generation without replaying kill'

new_case unexpected
launch
await_status 0 running 1
await_spawns 1
printf '23\n' > "$case_dir/exit"
await_exit 23
assert_dead "$pid"
[[ $(wc -l < "$case_dir/spawns") -eq 1 ]] || fail 'unexpected exit restarted child'
echo 'PASS: unexpected child exit is propagated, not restarted'

for signal in TERM INT; do
    new_case "signal-$signal"
    launch
    await_status 0 running 1
    await_spawns 1
    kill -s "$signal" "$sup"
    if [[ $signal == TERM ]]; then await_exit 143; else await_exit 130; fi
    assert_dead "$pid"
    grep -qx "$signal" "$case_dir/signals" || fail "$signal was not forwarded"
done
echo 'PASS: SIGTERM/SIGINT propagate and clean up the child'

new_case malformed
launch
await_status 0 running 1
await_spawns 1
printf '{"id":1,"action":"touch %s/injected"}\n' "$tmp" > "$request.tmp"
mv "$request.tmp" "$request"
await_exit 64
assert_dead "$pid"
[[ ! -e $tmp/injected ]] || fail 'request executed an arbitrary command'
echo 'PASS: malformed action fails safely and cannot execute a command'

new_case u64
# Exercise counters beyond IEEE-754 and signed-integer precision.
printf '18446744073709551613\n' > "$case_dir/zone-0.generation"
launch
await_status 0 running 18446744073709551614
send 18446744073709551614 kill
await_status 18446744073709551614 down 18446744073709551614
send 18446744073709551615 start
await_status 18446744073709551615 running 18446744073709551615
await_spawns 2
stop
echo 'PASS: full-u64 IDs and generations retain exact decimal values'

new_case invalid_id
launch
await_status 0 running 1
send 18446744073709551616 kill
await_exit 64
echo 'PASS: ID overflow is rejected'

echo 'All zone-supervisor fixtures passed.'
