#!/usr/bin/env bash
# Test-only process fault control. The container stays alive during an intentional
# SIGKILL; genuine process exits are NOT restarted here. Requests are atomically
# renamed into place by the workload. Only the startup argv can be executed.
set -euo pipefail
export LC_ALL=C

if [[ $# -lt 2 || ! $1 =~ ^[0-2]$ ]]; then
    echo "usage: zone-supervisor.sh <0|1|2> <command...>" >&2
    exit 64
fi
node=$1
shift
control=${ZONE_FAULT_CONTROL_DIR:-/fault-control}
hold=${ZONE_FAULT_HOLD_SECONDS:-180}
if [[ ! $hold =~ ^[1-9][0-9]{0,5}$ ]]; then
    echo "zone-supervisor: invalid hold duration" >&2
    exit 64
fi
mkdir -p "$control"
request=$control/zone-$node.request
status=$control/zone-$node.status
counter=$control/zone-$node.generation
child=
last_id=0
generation=0
state=down
hold_started=0

# Separate process groups let shutdown reach the child's descendants and preserve
# SIGINT handling (ordinary asynchronous shell children inherit ignored SIGINT).
set -m

cleanup() {
    local signal=${1:-TERM}
    trap '' TERM INT
    if [[ -n $child ]]; then
        kill -s "$signal" -- "-$child" 2>/dev/null || true
        # Bound shutdown even if the child ignores the forwarded signal.
        for ((attempt = 0; attempt < 50; attempt++)); do
            kill -0 "$child" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL -- "-$child" 2>/dev/null || true
        wait "$child" 2>/dev/null || true
        child=
    fi
    rm -f "$status.tmp.$$" "$counter.tmp.$$"
}
trap cleanup EXIT
trap 'cleanup TERM; exit 143' TERM
trap 'cleanup INT; exit 130' INT

fail() {
    echo "zone-supervisor[$node]: $*" >&2
    exit 64
}

# Bash arithmetic is signed and jq numbers may round large integers. Validate and
# compare decimal tokens directly so every u64 request ID survives unchanged.
valid_u64() {
    [[ $1 =~ ^(0|[1-9][0-9]*)$ ]] &&
        { [[ ${#1} -lt 20 ]] || [[ ${#1} -eq 20 && ! $1 > 18446744073709551615 ]]; }
}
greater() {
    [[ ${#1} -gt ${#2} || ( ${#1} -eq ${#2} && $1 > $2 ) ]]
}
increment_generation() {
    [[ $generation != 18446744073709551615 ]] || fail "generation exhausted"
    local prefix=$generation suffix= digit
    while [[ -n $prefix ]]; do
        digit=${prefix: -1}
        prefix=${prefix:0:${#prefix}-1}
        if [[ $digit != 9 ]]; then
            generation=$prefix$((digit + 1))$suffix
            return
        fi
        suffix=0$suffix
    done
    generation=1$suffix
}

# Accept the two field orders produced by JSON serializers, with whitespace, but
# reject extra/duplicate fields, non-integer IDs, and arbitrary action strings.
ws='[[:space:]]*'
number='(0|[1-9][0-9]*)'
request_id_first="^${ws}\\{${ws}\"id\"${ws}:${ws}${number}${ws},${ws}\"action\"${ws}:${ws}\"(kill|start)\"${ws}\\}${ws}$"
request_action_first="^${ws}\\{${ws}\"action\"${ws}:${ws}\"(kill|start)\"${ws},${ws}\"id\"${ws}:${ws}${number}${ws}\\}${ws}$"
read_request() {
    local body
    body=$(<"$request")
    if [[ $body =~ $request_id_first ]]; then
        request_id=${BASH_REMATCH[1]}
        action=${BASH_REMATCH[2]}
    elif [[ $body =~ $request_action_first ]]; then
        action=${BASH_REMATCH[1]}
        request_id=${BASH_REMATCH[2]}
    else
        fail "invalid request JSON"
    fi
    valid_u64 "$request_id" || fail "request ID outside u64"
}

# Status is our own canonical JSON. A corrupt durable record must not reset the
# generation/ID guards and accidentally replay an old fault.
if [[ -e $status ]]; then
    body=$(<"$status")
    status_pattern='^\{"id":(0|[1-9][0-9]*),"state":"(running|down)","generation":(0|[1-9][0-9]*)\}$'
    [[ $body =~ $status_pattern ]] || fail "invalid persisted status"
    last_id=${BASH_REMATCH[1]}
    generation=${BASH_REMATCH[3]}
    valid_u64 "$last_id" && valid_u64 "$generation" || fail "invalid persisted counters"
fi
if [[ -e $counter ]]; then
    reserved=$(<"$counter")
    valid_u64 "$reserved" || fail "invalid persisted generation"
    if greater "$reserved" "$generation"; then generation=$reserved; fi
fi
# Also consume a request interrupted before its acknowledgement. No request that
# predates this supervisor instance may kill the newly started process.
if [[ -e $request ]]; then
    read_request
    if greater "$request_id" "$last_id"; then last_id=$request_id; fi
fi

write_status() {
    printf '{"id":%s,"state":"%s","generation":%s}\n' \
        "$last_id" "$state" "$generation" > "$status.tmp.$$"
    mv -f "$status.tmp.$$" "$status"
}
spawn() {
    increment_generation
    # Reserve before spawning so a container kill between spawn and status cannot
    # reuse a generation. A skipped generation is harmless.
    printf '%s\n' "$generation" > "$counter.tmp.$$"
    mv -f "$counter.tmp.$$" "$counter"
    "$@" &
    child=$!
    state=running
    write_status
}
child_exited() {
    local code=0
    wait "$child" 2>/dev/null || code=$?
    # Preserve genuine exits; the EXIT trap also cleans up surviving descendants.
    echo "zone-supervisor[$node]: unexpected child exit $code" >&2
    exit "$code"
}

# Invalidate a stale DOWN acknowledgement before startup can run a replacement.
# This is not an acknowledgement of a new START request; those publish after spawn.
state=running
write_status
spawn "$@"
while :; do
    if [[ -n $child ]] && ! kill -0 "$child" 2>/dev/null; then
        child_exited
    fi
    if [[ -e $request ]]; then
        read_request
        if greater "$request_id" "$last_id"; then
            case $action in
                kill)
                    if [[ $state == running ]]; then
                        kill -KILL -- "-$child" 2>/dev/null || child_exited
                        code=0
                        wait "$child" 2>/dev/null || code=$?
                        [[ $code -eq 137 ]] || child_exited
                        child=
                        state=down
                        hold_started=$SECONDS
                    fi
                    # Another kill while down acknowledges but does not extend
                    # the original watchdog deadline.
                    last_id=$request_id
                    write_status
                    ;;
                start)
                    last_id=$request_id
                    if [[ $state == down ]]; then
                        spawn "$@"
                    else
                        write_status
                    fi
                    ;;
            esac
        fi
    fi
    if [[ $state == down ]] && ((SECONDS - hold_started >= hold)); then
        echo "zone-supervisor[$node]: hold expired for request $last_id" >&2
        # Revoke DOWN before the replacement can do work. This same-ID transition
        # is NOT a new START acknowledgement. spawn then publishes its generation.
        state=running
        write_status
        spawn "$@"
    fi
    sleep 0.1
done
