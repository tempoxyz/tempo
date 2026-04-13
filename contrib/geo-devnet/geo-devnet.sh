#!/usr/bin/env bash
# geo-devnet.sh — One-command multi-validator Tempo devnet with EU↔US network conditions
#
# Usage:
#   ./geo-devnet.sh              # 4 validators (2 EU, 2 US), default settings
#   ./geo-devnet.sh 6            # 6 validators (3 EU, 3 US)
#   ./geo-devnet.sh 4 120        # 4 validators, 120ms RTT between EU↔US
#   ./geo-devnet.sh 4 90 1.5     # 4 validators, 90ms RTT, 1.5% packet loss
#   ./geo-devnet.sh down         # tear down the devnet
#
# Requirements: docker, docker compose
#
# Network topology:
#   EU validators: 172.20.0.10, .11, ... (low intra-EU latency)
#   US validators: 172.20.0.20, .21, ... (low intra-US latency)
#   EU ↔ US: configurable RTT (default 90ms), 0.5% packet loss, 1Gbps bandwidth
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORK_DIR="$SCRIPT_DIR/.geodevnet"

# ── Config ──────────────────────────────────────────────────────────────────
NUM_VALS="${1:-4}"
RTT_MS="${2:-90}"                         # round-trip time EU↔US in ms
ONE_WAY_MS=$((RTT_MS / 2))               # netem delay is one-way
JITTER_MS=$((ONE_WAY_MS / 9 + 1))        # ~10% jitter
LOSS_PCT="${3:-0}"                         # packet loss %
BW="1gbit"                                # bandwidth cap
SEED=42                                   # deterministic key generation
CHAIN_ID=1337
GAS_LIMIT=500000000
EU_SUBNET_BASE=10                         # 172.20.0.10, .11, ...
US_SUBNET_BASE=20                         # 172.20.0.20, .21, ...
DOCKER_SUBNET="172.20.0.0/24"
COMPOSE_PROJECT="geodevnet"

# ── Handle teardown ─────────────────────────────────────────────────────────
if [[ "${1:-}" == "down" ]]; then
    echo "==> Tearing down geo-devnet..."
    docker compose -p "$COMPOSE_PROJECT" -f "$WORK_DIR/docker-compose.yml" down -v 2>/dev/null || true
    rm -rf "$WORK_DIR"
    echo "==> Done."
    exit 0
fi

if ! [[ "$NUM_VALS" =~ ^[0-9]+$ ]] || [ "$NUM_VALS" -lt 2 ]; then
    echo "Error: need at least 2 validators (got: $NUM_VALS)"
    exit 1
fi

HALF=$((NUM_VALS / 2))
if [ $((NUM_VALS % 2)) -ne 0 ]; then
    HALF=$((HALF + 1))  # EU gets the extra validator if odd
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Tempo Geo-Devnet: ${NUM_VALS} validators (${HALF} EU + $((NUM_VALS - HALF)) US)           "
echo "║  EU ↔ US: ${RTT_MS}ms RTT, ${LOSS_PCT}% loss, ${BW} bandwidth          "
echo "╚══════════════════════════════════════════════════════════════╝"

# ── Prepare workspace ───────────────────────────────────────────────────────
mkdir -p "$WORK_DIR"

# ── Build validator IP list ─────────────────────────────────────────────────
VALIDATOR_ADDRS=""
declare -a VAL_IPS=()
declare -a VAL_REGIONS=()

for i in $(seq 0 $((NUM_VALS - 1))); do
    if [ "$i" -lt "$HALF" ]; then
        IP="172.20.0.$((EU_SUBNET_BASE + i))"
        VAL_REGIONS+=("eu")
    else
        IP="172.20.0.$((US_SUBNET_BASE + i - HALF))"
        VAL_REGIONS+=("us")
    fi
    VAL_IPS+=("$IP")
    PORT=9000
    VALIDATOR_ADDRS="${VALIDATOR_ADDRS:+$VALIDATOR_ADDRS,}${IP}:${PORT}"
done

echo "==> Validators: $VALIDATOR_ADDRS"

# ── Build Docker images ────────────────────────────────────────────────────
echo "==> Building tempo Docker image (this may take a while on first run)..."

# Build the chef image first (has cargo-chef + deps)
docker build \
    -f "$REPO_ROOT/Dockerfile.chef" \
    -t tempo-chef \
    --target builder \
    "$REPO_ROOT"

# Build tempo + xtask binaries
docker build \
    -f "$REPO_ROOT/Dockerfile" \
    --build-arg CHEF_IMAGE=tempo-chef \
    --build-arg RUST_PROFILE=release \
    --build-arg RUST_FEATURES="asm-keccak,jemalloc" \
    -t tempo-node:geodevnet \
    --target tempo \
    "$REPO_ROOT"

docker build \
    -f "$REPO_ROOT/Dockerfile" \
    --build-arg CHEF_IMAGE=tempo-chef \
    --build-arg RUST_PROFILE=release \
    --build-arg RUST_FEATURES="asm-keccak,jemalloc" \
    -t tempo-xtask:geodevnet \
    --target tempo-xtask \
    "$REPO_ROOT"

# Build the runtime image with iproute2 bash for tc/netem
cat > "$WORK_DIR/Dockerfile.runtime" <<'DOCKERFILE'
ARG BASE_IMAGE=tempo-node:geodevnet
FROM ${BASE_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 bash && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
DOCKERFILE

# ── Generate localnet configs via xtask ─────────────────────────────────────
CONFIGS_DIR="$WORK_DIR/configs"
rm -rf "$CONFIGS_DIR"
mkdir -p "$CONFIGS_DIR"

echo "==> Generating localnet configs for $NUM_VALS validators..."
docker run --rm \
    -v "$CONFIGS_DIR:/output" \
    tempo-xtask:geodevnet \
    generate-localnet \
    --output /output \
     \
    --validators "$VALIDATOR_ADDRS" \
    --seed "$SEED" \
    --chain-id "$CHAIN_ID" \
    --gas-limit "$GAS_LIMIT"

echo "==> Generated configs:"
# Rename colon-containing dirs (Docker volume mount incompatible)
for d in "$CONFIGS_DIR"/*:*; do [ -d "$d" ] && mv "$d" "${d//:/_}"; done
find "$CONFIGS_DIR" -type f | sort | head -30

# ── Read enode identities to build trusted-peers ────────────────────────────
declare -a ENODE_IDS=()
for i in $(seq 0 $((NUM_VALS - 1))); do
    IP="${VAL_IPS[$i]}"
    IDENTITY_FILE="$CONFIGS_DIR/${IP}_9000/enode.identity"
    ENODE_ID=$(cat "$IDENTITY_FILE")
    ENODE_IDS+=("$ENODE_ID")
done

# Build trusted-peers string (all enodes)
TRUSTED_PEERS=""
for i in $(seq 0 $((NUM_VALS - 1))); do
    ENODE="enode://${ENODE_IDS[$i]}@${VAL_IPS[$i]}:9001"
    TRUSTED_PEERS="${TRUSTED_PEERS:+$TRUSTED_PEERS,}${ENODE}"
done

# ── Create entrypoint script ───────────────────────────────────────────────
cat > "$WORK_DIR/entrypoint.sh" <<'ENTRYPOINT'
#!/bin/bash
set -e

# Apply network shaping if NETEM_TARGETS is set (comma-separated CIDRs to delay)
if [ -n "${NETEM_TARGETS:-}" ]; then
    NETEM_LIMIT_PKTS="${NETEM_LIMIT_PKTS:-20000}"
    echo "[netem] Applying network shaping: delay=${NETEM_DELAY}ms jitter=${NETEM_JITTER}ms loss=${NETEM_LOSS}% rate=${NETEM_RATE} limit=${NETEM_LIMIT_PKTS}pkts"

    # Default all traffic to the unshaped band. We add explicit filters below
    # for cross-region destinations that should pass through netem.
    tc qdisc add dev eth0 root handle 1: prio bands 3 \
        priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1

    # Band 1:1 = shaped (cross-region traffic)
    tc qdisc add dev eth0 parent 1:1 handle 10: netem \
        limit "${NETEM_LIMIT_PKTS}" \
        delay "${NETEM_DELAY}ms" "${NETEM_JITTER}ms" distribution normal \
        loss "${NETEM_LOSS}%" \
        rate "${NETEM_RATE}"

    # Band 1:2 = unshaped (intra-region + everything else)
    tc qdisc add dev eth0 parent 1:2 handle 20: pfifo_fast

    # Route cross-region IPs to the shaped band
    IFS=',' read -ra TARGETS <<< "$NETEM_TARGETS"
    for target in "${TARGETS[@]}"; do
        echo "[netem] Shaping traffic to $target"
        tc filter add dev eth0 parent 1:0 protocol ip prio 1 u32 \
            match ip dst "$target" flowid 1:1
    done

    # Keep all other traffic, including same-region validator traffic, on the
    # unshaped band.
    tc filter add dev eth0 parent 1:0 protocol ip prio 100 u32 \
        match u32 0 0 flowid 1:2

    echo "[netem] Network shaping active:"
    tc qdisc show dev eth0
    echo ""
fi

echo "[tempo] Starting validator..."
# Set a larger initial congestion window on every existing route. This must be
# done line-by-line so the validator subnet route (172.20.0.0/24), not just the
# default route, picks up the override for new peer connections.
ip -4 route show | while IFS= read -r route; do
  [ -n "$route" ] || continue
  ip route replace $route initcwnd 363 initrwnd 363 2>/dev/null && \
    echo "[tcp] Set initcwnd=363 initrwnd=363 on: $route"
done

exec /usr/local/bin/tempo "$@"
ENTRYPOINT

# Build the runtime image
docker build -f "$WORK_DIR/Dockerfile.runtime" -t tempo-geodevnet:latest "$WORK_DIR"

# ── Compute netem targets per region ────────────────────────────────────────
# EU nodes need to shape traffic to all US IPs, and vice versa
EU_TARGETS=""
US_TARGETS=""
for i in $(seq 0 $((NUM_VALS - 1))); do
    IP="${VAL_IPS[$i]}"
    if [ "$i" -lt "$HALF" ]; then
        EU_TARGETS="${EU_TARGETS:+$EU_TARGETS,}${IP}/32"  # used BY US nodes
    else
        US_TARGETS="${US_TARGETS:+$US_TARGETS,}${IP}/32"  # used BY EU nodes
    fi
done

# ── Generate docker-compose.yml ────────────────────────────────────────────
echo "==> Generating docker-compose.yml..."

COMPOSE_FILE="$WORK_DIR/docker-compose.yml"

cat > "$COMPOSE_FILE" <<HEADER
# Auto-generated by geo-devnet.sh — do not edit manually
# ${NUM_VALS} validators: ${HALF} EU + $((NUM_VALS - HALF)) US
# EU ↔ US: ${RTT_MS}ms RTT, ${LOSS_PCT}% loss, ${BW} bandwidth

services:
HEADER

for i in $(seq 0 $((NUM_VALS - 1))); do
    IP="${VAL_IPS[$i]}"
    REGION="${VAL_REGIONS[$i]}"
    VAL_DIR="${IP}_9000"

    CONSENSUS_P2P_PORT=9000
    EXEC_P2P_PORT=9001
    METRICS_PORT=9002
    AUTHRPC_PORT=9003
    HTTP_PORT=8545
    WS_PORT=8546

    # Determine netem targets: EU nodes shape traffic to US nodes and vice versa
    if [ "$REGION" = "eu" ]; then
        TARGETS="$US_TARGETS"
    else
        TARGETS="$EU_TARGETS"
    fi

    SERVICE_NAME="${REGION}-val-${i}"

    cat >> "$COMPOSE_FILE" <<SERVICE
  ${SERVICE_NAME}:
    image: tempo-geodevnet:latest
    container_name: ${SERVICE_NAME}
    hostname: ${SERVICE_NAME}
    cap_add:
      - NET_ADMIN
    environment:
      - NETEM_TARGETS=${TARGETS}
      - NETEM_DELAY=${ONE_WAY_MS}
      - NETEM_JITTER=${JITTER_MS}
      - NETEM_LOSS=${LOSS_PCT}
      - NETEM_RATE=${BW}
    volumes:
      - ${CONFIGS_DIR}/${VAL_DIR}/signing.key:/data/signing.key:ro
      - ${CONFIGS_DIR}/${VAL_DIR}/signing.share:/data/signing.share:ro
      - ${CONFIGS_DIR}/${VAL_DIR}/enode.key:/data/enode.key:ro
      - ${CONFIGS_DIR}/genesis.json:/data/genesis.json:ro
    command:
      - node
      - --consensus.signing-key=/data/signing.key
      - --consensus.signing-share=/data/signing.share
      - --consensus.listen-address=0.0.0.0:${CONSENSUS_P2P_PORT}
      - --consensus.metrics-address=0.0.0.0:${METRICS_PORT}
      - --consensus.use-local-defaults
      - --consensus.allow-private-ips
      - --consensus.bypass-ip-check
      - --consensus.fee-recipient=0x0000000000000000000000000000000000000000
      - --chain=/data/genesis.json
      - --datadir=/data/db
      - --trusted-peers=${TRUSTED_PEERS}
      - --port=${EXEC_P2P_PORT}
      - --discovery.port=${EXEC_P2P_PORT}
      - --p2p-secret-key=/data/enode.key
      - --authrpc.port=${AUTHRPC_PORT}
      - --authrpc.addr=0.0.0.0
      - --http
      - --http.addr=0.0.0.0
      - --http.port=${HTTP_PORT}
      - --http.api=eth,net,web3,txpool,debug,trace
      - --ws
      - --ws.addr=0.0.0.0
      - --ws.port=${WS_PORT}
      - --log.stdout.format=terminal
    networks:
      geodevnet:
        ipv4_address: ${IP}
    labels:
      - "geodevnet.region=${REGION}"
      - "geodevnet.validator=${i}"

SERVICE
done

cat >> "$COMPOSE_FILE" <<FOOTER
networks:
  geodevnet:
    driver: bridge
    ipam:
      config:
        - subnet: ${DOCKER_SUBNET}
FOOTER

echo "==> docker-compose.yml written to $COMPOSE_FILE"

# ── Print summary ──────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Geo-Devnet Ready                                          ║"
echo "╠══════════════════════════════════════════════════════════════╣"

for i in $(seq 0 $((NUM_VALS - 1))); do
    IP="${VAL_IPS[$i]}"
    REGION="${VAL_REGIONS[$i]}"
    REGION_UPPER=$(echo "$REGION" | tr '[:lower:]' '[:upper:]')
    printf "║  val-%d [%s]  %-15s  RPC: http://%s:8545  ║\n" "$i" "$REGION_UPPER" "$IP" "$IP"
done

echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Network shaping:                                          ║"
printf "║    EU ↔ US: %dms RTT, %s%% loss, %s bandwidth          ║\n" "$RTT_MS" "$LOSS_PCT" "$BW"
echo "║    Intra-region: unthrottled (Docker bridge speed)         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Launch ──────────────────────────────────────────────────────────────────
echo "==> Starting geo-devnet..."
docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" up -d

echo ""
echo "==> All validators are starting. Watch logs with:"
echo "    docker compose -p $COMPOSE_PROJECT -f $COMPOSE_FILE logs -f"
echo ""
echo "==> Test cross-region latency:"
echo "    docker exec eu-val-0 ping -c 5 ${VAL_IPS[$((NUM_VALS - 1))]}"
echo ""
echo "==> Tear down with:"
echo "    $0 down"
