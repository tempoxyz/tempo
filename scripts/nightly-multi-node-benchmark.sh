#!/bin/bash

export ETH_RPC_URL=http://lento-node-1-1:8545
export ANSIBLE_HOST_KEY_CHECKING=False

set -euo pipefail
cd infrastructure/ansible

echo "[$(date)] setting up testnet with Ansible"

ansible-playbook --vault-password-file ./vault.key --extra-vars "tempo_download_url='https://api.github.com/repos/tempoxyz/tempo/actions/artifacts/$TEMPO_DOWNLOAD_ID/zip' tempo_sidecar_download_url='https://api.github.com/repos/tempoxyz/tempo/actions/artifacts/$TEMPO_SIDECAR_DOWNLOAD_ID/zip' tempo_force_reset=True tempo_relative_path='../../'" -i benchmark-1 --limit benchmark-1 --tags devnet devnet.yml

echo "[$(date)] running benchmark"

ansible-playbook --vault-password-file ./vault.key \
    --extra-vars "{\"tempo_bench_download_url\": \"https://api.github.com/repos/tempoxyz/tempo/actions/artifacts/$TEMPO_BENCH_DOWNLOAD_ID/zip\", \"tempo_bench_node_sha\": \"$TEMPO_BENCH_NODE_SHA\", \"tempo_bench_build_profile\": \"$TEMPO_BENCH_BUILD_PROFILE\", \"tempo_bench_benchmark_mode\": \"$TEMPO_BENCH_BENCHMARK_MODE\"}" \
    -i benchmark-1 --limit benchmark-1-bench --tags benchmark benchmark.yml

echo "[$(date)] benchmark done"

echo "[$(date)] copying logs"

mkdir report/

scp ubuntu@lento-node-1-1:/home/ubuntu/.cache/reth/logs/4246/reth.log report/node-1.log
scp ubuntu@lento-node-2:/home/ubuntu/.cache/reth/logs/4246/reth.log report/node-2.log
scp ubuntu@lento-node-3-1:/home/ubuntu/.cache/reth/logs/4246/reth.log report/node-3.log

cp benchmark.json report/benchmark.json

cat report/node-1.log | ../../scripts/parse_reth_timing_logs.sh > report/node-1-timings.csv
cat report/node-2.log | ../../scripts/parse_reth_timing_logs.sh > report/node-2-timings.csv
cat report/node-3.log | ../../scripts/parse_reth_timing_logs.sh > report/node-3-timings.csv

rm report/*.log
