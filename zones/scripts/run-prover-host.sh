#!/usr/bin/env bash

# Supervises the Nitro enclave and its TCP-to-vsock proxy.
set -Eeuo pipefail

EIF_PATH="${PROVER_EIF_PATH:-/opt/tempo-zone-prover/tempo-zone-prover.eif}"
ENCLAVE_NAME="${ENCLAVE_NAME:-tempo-zone-prover}"
ENCLAVE_CPU_COUNT="${ENCLAVE_CPU_COUNT:-2}"
ENCLAVE_MEMORY_MIB="${ENCLAVE_MEMORY_MIB:-10240}"
ENCLAVE_CID="${ENCLAVE_CID:-16}"
TCP_PORT="${PROVER_TCP_PORT:-5000}"
VSOCK_PORT="${PROVER_VSOCK_PORT:-5000}"
MONITOR_INTERVAL_SECONDS="${MONITOR_INTERVAL_SECONDS:-30}"

enclave_id=""
proxy_pid=""

# Invoked by the EXIT trap below.
# shellcheck disable=SC2329
cleanup() {
    local status=$?

    trap - EXIT INT TERM

    if [[ -n "${proxy_pid}" ]] && kill -0 "${proxy_pid}" 2>/dev/null; then
        kill "${proxy_pid}" 2>/dev/null || true
        wait "${proxy_pid}" 2>/dev/null || true
    fi

    if [[ -n "${enclave_id}" ]]; then
        printf 'Terminating enclave %s\n' "${enclave_id}"
        nitro-cli terminate-enclave --enclave-id "${enclave_id}" >/dev/null 2>&1 || true
    fi

    exit "${status}"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ ! -f "${EIF_PATH}" ]]; then
    printf 'Prover EIF not found: %s\n' "${EIF_PATH}" >&2
    exit 1
fi

if [[ ! "${MONITOR_INTERVAL_SECONDS}" =~ ^[1-9][0-9]*$ ]]; then
    printf 'MONITOR_INTERVAL_SECONDS must be a positive integer\n' >&2
    exit 1
fi

printf 'Launching the Tempo Zone prover as a non-debug Nitro Enclave\n'
set +e
run_output="$(nitro-cli run-enclave \
    --enclave-name "${ENCLAVE_NAME}" \
    --cpu-count "${ENCLAVE_CPU_COUNT}" \
    --memory "${ENCLAVE_MEMORY_MIB}" \
    --eif-path "${EIF_PATH}" \
    --enclave-cid "${ENCLAVE_CID}" 2>&1)"
nitro_status=$?
set -e

printf '%s\n' "${run_output}"
if [[ "${nitro_status}" -ne 0 ]]; then
    printf 'nitro-cli run-enclave failed\n' >&2
    exit "${nitro_status}"
fi

if ! enclave_id="$(jq -Rser \
    'capture("(?s)(?<json>\\{.*\\})").json | fromjson | .EnclaveID' \
    <<<"${run_output}")"; then
    printf 'nitro-cli returned no parseable EnclaveID\n' >&2
    exit 1
fi

printf 'Tempo Zone prover enclave %s is running at CID %s on vsock port %s\n' \
    "${enclave_id}" "${ENCLAVE_CID}" "${VSOCK_PORT}"

/usr/local/bin/tempo-vsock-proxy "${TCP_PORT}" "${ENCLAVE_CID}" "${VSOCK_PORT}" &
proxy_pid=$!
printf 'Forwarding TCP port %s to enclave CID %s, vsock port %s with VMADDR_FLAG_TO_HOST\n' \
    "${TCP_PORT}" "${ENCLAVE_CID}" "${VSOCK_PORT}"

while kill -0 "${proxy_pid}" 2>/dev/null; do
    if ! descriptions="$(nitro-cli describe-enclaves 2>&1)"; then
        printf 'nitro-cli describe-enclaves failed:\n%s\n' "${descriptions}" >&2
        exit 1
    fi

    if ! jq -e --arg enclave_id "${enclave_id}" \
        'any(.[]; .EnclaveID == $enclave_id)' <<<"${descriptions}" >/dev/null; then
        printf 'Enclave %s stopped unexpectedly\n' "${enclave_id}" >&2
        exit 1
    fi

    sleep "${MONITOR_INTERVAL_SECONDS}"
done

wait "${proxy_pid}" || true
printf 'TCP-to-vsock proxy exited unexpectedly\n' >&2
exit 1
