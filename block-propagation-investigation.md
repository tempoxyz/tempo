# Block Propagation Investigation

**Date:** 2026-04-13
**Status:** In progress — on the fixed geo-devnet, a three-scenario `1800 TPS / 60s / 400 account` matrix now shows `default` at roughly `~492ms`, `initcwnd=363 initrwnd=363` at roughly `~62ms`, and container-local `bbr` at roughly `~407ms` for the cross-region body path; testnet still needs to be reconciled against that result

---

## Problem Statement

Block body propagation from same-region proposers to cross-region validators is 10–20× slower than expected on testnet. The proposal certificate (40-byte digest on channel 0) arrives in ~50ms, but the block body (480KB on channel 3) takes 460–500ms.

### Testnet Observations (Block 12165208)

- **Proposer:** cross-region investigation proposer
- **Block:** 2,105 txs, 101.8M gas, 480,422 bytes
- **Build time:** 358ms

| Validator | Region | Cert Arrival | Body Arrival (inferred) | Gap (cert→body) | verify_ms |
|-----------|--------|-------------|------------------------|-----------------|-----------|
| same-region peer A | same-region | T+473ms | T+487ms | **14ms** | 104ms |
| same-region peer B | same-region | T+474ms | T+489ms | **15ms** | 290ms |
| cross-region peer A | cross-region | T+519ms | T+982ms | **463ms** | 476ms |
| cross-region peer B | cross-region | T+519ms | T+1020ms | **501ms** | 416ms |
| cross-region peer C | cross-region | T+521ms | T+1003ms | **482ms** | 413ms |

The gap scales with block size:

| Block | Txs | Size | Avg gap (cross-region validators) |
|-------|-----|------|------------------------|
| 12165100 | 123 | ~5KB | 1.2ms |
| 12165164 | 379 | ~20KB | 168ms |
| 12165186 | 2289 | ~400KB | 382ms |
| 12165208 | 2105 | ~480KB | 411ms |

---

## Measurement Methodology

### Valscope Definitions (from `valscope/apps/api/src/store.rs`)

The correct metrics and their log sources:

| Metric | Definition | Log message |
|--------|-----------|-------------|
| **T0** (proposal constructed) | When the proposer finished building the block | `"constructed proposal"` — extract `view=N` |
| **receive_delay_ms** | Network propagation: T0 → `BlockReceived` | `constructed proposal` ts → `BlockReceived` ts |
| **process_ms** | Body received → reth canonical added | `"requested proposal verification"` ts → `"Block added to canonical chain"` ts |
| **verify_ms** | Pure reth execution time | `elapsed=` field on `"Block added to canonical chain"` (same as `RethCanonicalAdded.duration_ms`) |

Source: `valscope/apps/api/src/parser.rs` lines 65-101:
```
"constructed proposal" → EventType::ProposeConstructed
"requested proposal verification" → EventType::BlockReceived  
"Block added to canonical chain" → EventType::RethCanonicalAdded
```

And from `valscope/apps/api/src/store.rs` lines 2538-2570:
```rust
// process_ms = RethCanonicalAdded.timestamp - BlockReceived.timestamp
let p_ms = match (received_ts, canonical_ts) {
    (Some(r), Some(c)) if c > r => Some((c as f64 - r as f64) / 1_000_000.0),
    _ => None,
};

// verify_ms = RethCanonicalAdded.duration_ms (reth's own execution time)
let v_ms = tenant_events.iter()
    .find(|e| e.event_type == EventType::RethCanonicalAdded)
    .and_then(|e| e.duration_ms);

// receive_delay_ms = BlockReceived.timestamp - ProposeConstructed.timestamp
let r_delay = received_ts.map(|r| (r - record.constructed_ns) / 1_000_000.0);
```

### ⚠️ What NOT to use

**Do NOT compare `"Block added to canonical chain"` timestamps between validators.** This event fires after both propagation AND execution. The `elapsed` field in that log is only reth's execution time, NOT the total processing time. Subtracting `elapsed` from the timestamp does not give you the body arrival time — there are actor hops and queuing between body arrival and reth execution start.

### Geo-Devnet Measurement Used In This Investigation

For the current geo-devnet investigation, the working receiver-side marker is:

- `"sending block to execution layer for verification"`

This log is emitted by Tempo immediately before calling `verify_block(...)` in `crates/commonware-node/src/consensus/application/actor.rs`.

This is **not** a pure wire-level body-arrival timestamp. It means:

- the block digest has already been resolved via `marshal.subscribe_by_digest(...)`
- the parent is available
- local pre-EL steps like `verify_header_extra_data(...)` and `canonicalize_head(parent...)` have completed

That makes it a later marker than raw body arrival, but it is acceptable for the current investigation because we only need a consistent receiver-side proxy that is close to the handoff into the execution layer.

### Correct measurement for current geo-devnet runs

Parse docker logs for:
1. `"constructed proposal"` with `view=N` → T0 per view (from the proposer container)
2. First `"sending block to execution layer for verification"` with `view=N` per non-proposer container → receiver-side handoff timestamp
3. `receive_delay = el_verify_ts - constructed_ts`
4. Join the view to the proposer's `"Built payload"` log using the proposal digest to recover `payment_transactions`, `total_transactions`, and `gas_used`

For older runs that do not have the new Tempo log, `contrib/geo-devnet/analyze_propagation.py --receiver-marker requested_verify` can still use `"requested proposal verification"` as a fallback marker.

Example grep:
```bash
docker logs <proposer-container> 2>&1 | grep "constructed proposal" | head -5
docker logs <receiver-container> 2>&1 | grep "sending block to execution layer for verification" | head -5
```

---

## How Blocks Propagate Through Commonware

### Architecture: Single TCP Connection Per Peer

All channels (0–6) are multiplexed over a **single TCP connection per peer**. Confirmed in `commonware-p2p` `peer/actor.rs`: one `Sender`/`Receiver` pair per peer, one sender task per peer.

| Channel | Purpose | Typical size |
|---------|---------|-------------|
| 0 (VOTES) | Propose/notarize votes | ~120 bytes |
| 1 (CERTIFICATES) | Notarization/finalization certs | ~160 bytes |
| 2 (RESOLVER) | Block backfill requests | varies |
| 3 (BROADCASTER) | Block bodies | 5KB–500KB+ |
| 4 (MARSHAL) | Marshal/backfill | varies |
| 5 (DKG) | DKG messages | varies |
| 6 (SUBBLOCKS) | Subblock data | varies |

### Send Path (Proposer → Validators)

```
voter/actor.rs: self.state.proposed(proposal)  →  vote broadcast (ch 0, ~120B)
                self.relay.broadcast(block)     →  body broadcast (ch 3, ~480KB)
  ↓
marshal/actor.rs: buffer.send(round, block, Recipients::All)
  ↓
broadcast/engine.rs: handle_broadcast() → WrappedSender::send(Recipients::All, block)
  ↓
p2p/limited.rs: KeyedRateLimiter per-peer check (8/sec per peer) ← NOT a bottleneck
  ↓
p2p/router/actor.rs: for each peer → relay.try_send(encoded.clone())  ← non-blocking
  ↓
p2p/peer/actor.rs: sender task dequeues → encrypted::Sender::send(payload)
  ↓
stream/encrypted.rs: pool.alloc() → copy plaintext → ChaCha20-Poly1305 encrypt → sink.send(frame)
  ↓
runtime/network/tokio.rs: OwnedWriteHalf::write_all_buf()  ← TCP write
```

### Key Code Locations

| Component | File | What it does |
|-----------|------|-------------|
| Channel config | `crates/commonware-node/src/config.rs:18-24` | Channel IDs and rate limits |
| Network setup | `crates/commonware-node/src/lib.rs:68-86` | Channel registration |
| Consensus args | `crates/commonware-node/src/args.rs` | Timing defaults (450ms propose wait, etc.) |
| Runtime config | `bin/tempo/src/main.rs:350-354` | `tcp_nodelay=true`, worker threads=3 |
| Broadcast engine | `commonware-broadcast-2026.3.0/src/buffered/engine.rs:227-246` | `handle_broadcast` |
| Router fanout | `commonware-p2p-2026.3.0/src/authenticated/lookup/actors/router/actor.rs:138-150` | Iterates peers, `try_send` |
| Per-peer sender | `commonware-p2p-2026.3.0/src/authenticated/lookup/actors/peer/actor.rs:130-187` | `select_loop` draining high/low channels |
| Encrypted send | `commonware-stream-2026.3.0/src/encrypted.rs:308-340` | Encrypt + TCP write |
| Tokio TCP sink | `commonware-runtime-2026.2.0/src/network/tokio.rs:20-27` | `write_all_buf` on `OwnedWriteHalf` |
| Buffer pool | `commonware-runtime-2026.2.0/src/iobuf/pool.rs:143-152` | `max_size: 64KB`, oversized → heap fallback |
| Rate limiter | `commonware-p2p-2026.3.0/src/utils/limited.rs:70-148` | `KeyedRateLimiter` (per-peer, not global) |

### Notable Design Properties

1. **Rate limit is per-peer**: `BROADCASTER_LIMIT = 8/sec` uses `KeyedRateLimiter` — each peer gets its own 8/sec bucket. Broadcasting to 17 peers is fine.
2. **Router fanout is non-blocking**: `relay.try_send()` — all peers get queued instantly.
3. **Each peer has its own sender task**: No cross-peer HOL blocking.
4. **Buffer pool max 64KB**: A 480KB message bypasses the pool entirely, allocating fresh heap memory (17 × 480KB = 8.1MB per block broadcast). Not a latency issue but worth noting.
5. **HOL blocking within a connection**: While a 480KB body is being written via `write_all_buf`, no other messages (including votes) can be sent to that peer. The sender task is blocked.
6. **No `SO_SNDBUF`/`SO_RCVBUF` tuning**: All socket buffer sizes are kernel defaults.
7. **`TCP_NODELAY` is enabled**: Nagle's algorithm is disabled.

---

## Theories Tested

### ✅ Theory 1: Initial cwnd on the validator subnet route materially changes the body path

**Hypothesis:** cwnd resets between blocks because connections are application-limited, causing 480KB to need ~5 slow-start RTTs × 80ms = ~400ms.

**What was wrong with the earlier tests:**

- The first attempt changed the **wrong route** (`default` instead of the validator subnet route)
- Later, the generated geo-devnet entrypoint turned out to be iterating routes incorrectly, so only the `default` route reliably got `initcwnd=363`; the validator subnet route still stayed at kernel defaults
- `initcwnd` only matters for **new** TCP connections, so changing it on long-lived connections without forcing reconnects is not enough

**Corrected re-test on the fixed Docker/netem setup:**

- Recreated the geo-devnet with the traffic-shaping fix in place so same-region stayed sane again
- Ran a baseline `900 TPS` bench with kernel-default TCP init windows on the validator subnet route
- Confirmed on the live containers that the body path was bad while the digest/cert path was sane:
  - `constructed_proposal -> marshal_wait`: median same-region `1.1ms`, cross-region `54.2ms`
  - `buffer_sent -> broadcast_received`: median same-region `0.3ms`, cross-region `376.2ms`
  - `buffer_sent -> buffer_resolved`: median same-region `0.6ms`, cross-region `376.5ms`
  - `buffer_sent -> execution_layer`: median same-region `0.7ms`, cross-region `376.3ms`
- Then reapplied `initcwnd=363 initrwnd=363` to the validator subnet route on all validators, killed the existing `:9001` peer sessions so new connections would inherit it, and reran the same `900 TPS` bench

**Result with `initcwnd=363 initrwnd=363` on the validator subnet route:** Large improvement.

- `constructed_proposal -> marshal_wait`: median same-region `1.1ms`, cross-region `52.2ms`
- `buffer_sent -> broadcast_received`: median same-region `0.3ms`, cross-region `59.8ms`
- `buffer_sent -> buffer_resolved`: median same-region `0.5ms`, cross-region `60.1ms`
- `buffer_sent -> execution_layer`: median same-region `0.6ms`, cross-region `60.2ms`
- `constructed_proposal -> broadcast_received`: median same-region `1.5ms`, cross-region `61.0ms`
- `constructed_proposal -> execution_layer`: median same-region `1.8ms`, cross-region `61.3ms`

These were not empty-block artifacts. The `363/363` rerun still included blocks up to roughly `1143` transactions and `40.8M` gas, plus many blocks in the `~520–680` transaction range.

Live `ss -tin` snapshots after the forced reconnect showed cross-region validator sockets at `cwnd:363 ssthresh:363`, confirming the rerun was actually using the enlarged startup window on the peer-to-peer links.

**Current conclusion:** On geo-devnet, once same-region behavior is sane and `initcwnd=363` is applied to the correct route for new validator connections, the cross-region block-body delay drops from roughly `~376ms` to `~60ms`. That makes TCP startup window behavior a live explanation for the geo-devnet symptom, even though testnet still needs its own confirmation.

### ✅ Three-scenario matrix at higher load

To compare the competing explanations under a load that gives `default` and `bbr` time to ramp, we ran a three-scenario matrix on the remote benchmark host with:

- `1800 TPS`
- `60s` duration
- `400` funded accounts
- `400` max concurrent requests
- scenario artifacts stored under `contrib/geo-devnet/.geodevnet/scenario-runs/<timestamp>`

For each scenario, the runner captured:

- timestamped `ss -tinm` snapshots per validator in `tcp/*.ss-tinm.log`
- route, qdisc, class, and congestion-control state in `state/*`
- scenario-bounded propagation summaries in `analysis/*`

The three scenarios tested were:

| Scenario | Container TCP config | Body-path median (`buffer_sent -> broadcast_received`) | Digest-path median (`constructed_proposal -> marshal_wait`) |
|----------|----------------------|--------------------------------------------------------|------------------------------------------------------------|
| `default` | `cubic`, no `initcwnd` override on the validator subnet route | `492.4ms` | `54.7ms` |
| `initcwnd363` | `cubic`, `initcwnd=363 initrwnd=363` on the validator subnet route | `61.9ms` | `52.6ms` |
| `bbr` | container-local `tcp_congestion_control=bbr`, no `initcwnd` override | `407.0ms` | `54.7ms` |

Same-region behavior stayed sane in all three cases:

- `default`: same-region `buffer_sent -> broadcast_received` median `0.7ms`
- `initcwnd363`: same-region `buffer_sent -> broadcast_received` median `0.5ms`
- `bbr`: same-region `buffer_sent -> broadcast_received` median `0.7ms`

Representative large blocks from the matrix:

- `default`: up to `~10.8k` transactions / `~386M` gas, with cross-region body-path delays still around `~808–833ms` on the largest blocks
- `initcwnd363`: up to `~11.1k` transactions / `~396M` gas, with many large-block body-path delays in the `~62–177ms` range and a few larger outliers
- `bbr`: up to `~6.8k` transactions / `~243M` gas, with large-block body-path delays still often in the `~315–675ms` range

**Current conclusion:** at this higher sustained load, `initcwnd=363 initrwnd=363` on the validator subnet route is still the only scenario that meaningfully collapses the cross-region body-path delay. Container-local `bbr` helps somewhat relative to raw default cubic, but it does not come close to the `initcwnd` result.

### ⚠️ Theory 2: Container-local BBR alone is not enough

We tested `bbr` by setting `net.ipv4.tcp_congestion_control=bbr` inside each validator network namespace and then forcing the `:9001` peer sessions to reconnect.

Important caveat:

- `net.core.default_qdisc` is not exposed in these validator netns
- the validator `eth0` already carries the custom netem/prio root qdisc, so the closest container-only version of the requested test is `bbr` with the existing root qdisc unchanged

**Result:** container-local `bbr` kept the digest/cert path healthy but still left a large cross-region body-path penalty.

- `constructed_proposal -> marshal_wait`: same-region `1.2ms`, cross-region `54.7ms`
- `buffer_sent -> broadcast_received`: same-region `0.7ms`, cross-region `407.0ms`
- `buffer_sent -> execution_layer`: same-region `1.5ms`, cross-region `390.5ms`

**Current conclusion:** `bbr` is better than the raw default scenario but still much worse than the subnet-route `initcwnd=363` case.

### ❌ Theory 3: TCP Slow Start After Idle (sysctl)

**Not yet tested** via `net.ipv4.tcp_slow_start_after_idle=0`.

After the new three-scenario matrix, this remains interesting but lower priority than the already-demonstrated subnet-route `initcwnd` effect.

### ⚠️ Theory 4: Application-Layer Delay / Measurement Artifact

**Observation:** With netem completely removed (all 4 validators on same Docker bridge, sub-ms latency), the `"Block added to canonical chain"` timestamps still showed ~253ms deltas between validators. However, this measurement was **wrong** — it used the incorrect methodology (comparing "Block added" timestamps and subtracting `elapsed`).

**Important clarification:** `"requested proposal verification"` is also too early to mean “body definitely arrived”. It is logged by the consensus voter when verification is requested, before the application finishes waiting on `marshal.subscribe_by_digest(...)`. For this investigation we therefore switched to the later Tempo log `"sending block to execution layer for verification"`.

**Current conclusion:** The earlier “geo-devnet does not reproduce the delay” conclusion was confounded first by a Docker/netem misconfiguration and later by the broken route-update loop in the generated runtime. On the fixed setup, the correct receiver-side markers do reproduce a large cross-region body-path gap in the `default` and `bbr` scenarios, while the digest/cert-side wait markers remain near the expected `~50ms` cross-region baseline.

---

## Geo-Devnet Test Infrastructure

### Setup

The geo-devnet (`contrib/geo-devnet/geo-devnet.sh`) creates a Docker-based local devnet simulating a two-region topology:

```
./contrib/geo-devnet/geo-devnet.sh 4 90   # 4 validators, 90ms RTT
./contrib/geo-devnet/geo-devnet.sh down    # tear down
```

- **4 validators**: two same-region validators and two cross-region validators
- **Network shaping**: `tc netem` adds 45ms one-way delay (90ms RTT) + ~6ms jitter between the two regions. Intra-region traffic is unthrottled.
- **`NET_ADMIN` capability**: Containers have cap_add NET_ADMIN for tc/ip route commands.
- **Startup TCP override**: the generated runtime now applies `initcwnd=363 initrwnd=363` to every existing route line-by-line, including the validator subnet route, not just the default route.
- **Chain ID**: 1337, gas limit 500M
- **Accounts**: Hardhat mnemonic (`test test test ... junk`), 50K accounts funded with pathUSD

### Current scenario runner

`contrib/geo-devnet/run_scenario_matrix.sh` runs the current comparison matrix across:

- `default`
- `initcwnd363`
- `bbr`

It reconfigures the validator TCP settings inside the container namespaces, forces the validator `:9001` sessions to reconnect, runs the bench, and writes scenario-bounded TCP and propagation artifacts under `.geodevnet/scenario-runs/<timestamp>/`.

### Remote workflow used for this investigation

The working environment for these reruns is a remote benchmark host in a dedicated tmux session.

- Apply source changes in the remote repo checkout
- If the Tempo binary changed, rebuild `tempo-node:geodevnet`
- Rebuild the runtime image from `contrib/geo-devnet/.geodevnet/Dockerfile.runtime`
- Recreate the stack with `docker compose -p geodevnet -f contrib/geo-devnet/.geodevnet/docker-compose.yml up -d --force-recreate`
- If testing a new `initcwnd` value on an already-running stack, update the validator subnet route inside each validator and kill the existing `:9001` sessions so the peer TCP connections reconnect under the new route settings
- For a three-scenario comparison run, use `contrib/geo-devnet/run_scenario_matrix.sh` so the bench, TCP snapshots, and propagation analyses are captured together

### Known Issues with the Script

1. **Colon in directory names**: xtask generates dirs like `<validator-address>:9000/` which break Docker volume mounts. The script renames them to `<validator-address>_9000/`.
2. **`--force` flag**: Removed because Docker volume mounts prevent clearing the output dir inside the container.
3. **Entrypoint shebang**: Must be `#!/bin/bash` (not `/bin/sh`) because the script uses `<<<` here-strings. The Dockerfile installs `bash`.
4. **Faucet/admin RPC**: `tempo_fundAddress` and `admin_clearTxpool` are not available. Accounts are funded from genesis.
5. **Startup `initcwnd` hook**: The generated entrypoint now updates routes line-by-line so the validator subnet route really picks up `initcwnd=363 initrwnd=363`. Any baseline test that intends to compare “with vs without initcwnd” must disable that hook first.
6. **New connections only**: changing `initcwnd` on a running container does not retroactively change established validator TCP sessions. Force reconnects on `:9001` or recreate the containers before trusting the next run.

### Running the Bench

```bash
# From the repo root:
./target/release/tempo-bench run-max-tps \
  --tps 3000 --duration 30 --accounts 200 \
  --from-mnemonic-index 200 \
  -m "test test test test test test test test test test test junk" \
  --target-urls http://<validator-rpc-host>:8545 \
  --max-concurrent-requests 200 \
  --use-standard-nonces \
  --tip20-weight 1.0 \
  --existing-recipients \
  --fd-limit 65536
```

**Important**: Use `--from-mnemonic-index N` with a fresh value each run to avoid nonce conflicts with prior runs. Accounts 0-9 are validators/admin.

For the medium-block reruns in this document, `--tps 900` was the stable setting used to keep same-region behavior sane while still producing useful `~500–1100 tx` blocks.

For the higher-load three-scenario matrix, the current settings are:

- `1800 TPS`
- `60s` duration
- `400` accounts
- `400` max concurrent requests

Example:

```bash
TPS=1800 DURATION=60 ACCOUNTS=400 MAX_CONCURRENT_REQUESTS=400 \
  FROM_MNEMONIC_INDEX_BASE=12000 \
  ./contrib/geo-devnet/run_scenario_matrix.sh
```

### Applying/Removing Netem Manually

```bash
# Apply netem (region-A → region-B shaping on the region-A nodes)
for c in <region-a-validator-containers>; do
  docker exec $c bash -c "
    tc qdisc add dev eth0 root handle 1: prio bands 3 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    tc qdisc add dev eth0 parent 1:1 handle 10: netem delay 45ms 6ms distribution normal rate 1gbit
    tc qdisc add dev eth0 parent 1:2 handle 20: pfifo_fast
    tc filter add dev eth0 parent 1:0 protocol ip prio 1 u32 match ip dst <region-b-validator-ip>/32 flowid 1:1
  "
done
# Same for the region-B nodes but targeting the region-A validator IPs

# Remove netem
for c in <all-validator-containers>; do
  docker exec $c tc qdisc del dev eth0 root 2>/dev/null
done

# Set initcwnd on subnet route (NOT default route — inter-container traffic uses subnet route)
for c in <all-validator-containers>; do
  docker exec $c bash -c "
    SUBNET=\$(ip -4 route show | grep -v default | head -1)
    ip route replace \$SUBNET initcwnd 363 initrwnd 363
  "
done

# Force validator p2p sessions to reconnect so the new initcwnd value applies
for c in <all-validator-containers>; do
  docker exec $c sh -lc "ss -K dport = 9001 || true; ss -K sport = 9001 || true"
done
```

### Analysis Script

`contrib/geo-devnet/analyze_propagation.py` — parses docker logs and computes receive delays. Usage:

```bash
python3 contrib/geo-devnet/analyze_propagation.py --min-view 300 --min-total-transactions 100
```

Current script behavior:

- supports `--sender-marker constructed_proposal|marshal_request|marshal_accepted|buffer_handoff|buffer_sent` to shift the proposer-side baseline later into the send path
- defaults to the Tempo INFO log `"sending block to execution layer for verification"`
- supports `--receiver-marker requested_verify` for older DEBUG-only runs
- also supports `--receiver-marker marshal_wait|buffer_wait|buffer_resolved|marshal_resolved` for the newer upstream body-resolution instrumentation
- supports `--max-view` so scenario-bounded reruns can exclude later experiments from the same long-lived container logs
- correlates views to `Built payload` by proposal digest
- extracts `payment_transactions`, `total_transactions`, and `gas_used`

Useful filters for the next smaller-block reruns:

```bash
python3 contrib/geo-devnet/analyze_propagation.py \
  --receiver-marker buffer_resolved \
  --min-total-transactions 1500 \
  --max-total-transactions 3000 \
  --min-gas-used 80000000 \
  --max-gas-used 160000000

python3 contrib/geo-devnet/analyze_propagation.py \
  --receiver-marker marshal_resolved \
  --min-total-transactions 1500 \
  --max-total-transactions 3000 \
  --min-gas-used 80000000 \
  --max-gas-used 160000000
```

Important bug fixed during this investigation:

- the script originally failed to parse proposer `constructed proposal` lines because `view=` appears in the tracing span prefix before the message text

---

## What Still Needs to Be Done

### 1. Reconcile testnet vs geo-devnet

Geo-devnet now shows three clear regimes on the fixed setup:

- `default`: body path about `~492ms` cross-region while same-region stays sub-millisecond
- `initcwnd363`: body path about `~62ms` cross-region with same-region still sub-millisecond
- `bbr`: body path about `~407ms` cross-region with same-region still sub-millisecond

The next task is to understand whether the testnet symptom is the same phenomenon and, if so, what effective startup-window or path differences exist there. Candidates still include:

- different proposer/validator hardware
- different network fanout / peer counts
- different logging assumptions used to infer testnet body arrival
- different commonware / runtime / deployment config

### 2. Deploy the new Tempo receiver-side log where the issue reproduces

The new log `"sending block to execution layer for verification"` is the current investigation marker. It should be deployed in whichever environment actually reproduces the issue so the same analysis can be run there.

### 3. Push the matrix deeper into the `~1.5k–2.5k tx` band

The new `1800 TPS / 60s / 400 account` matrix already reaches well beyond that on some views, but the body-path medians are still influenced by a wide mix of block sizes. The next reruns should tighten the load and filters so each scenario has a clean concentration in the earlier suspicious range, roughly `~1.5k–2.5k` transactions or `~80–160M` gas.

### 4. If needed, instrument an earlier body-availability point

If execution-layer handoff turns out to be too late, the next deeper marker should be around the block resolving path itself:

- immediately after `marshal.subscribe_by_digest(...)` resolves, or
- inside the buffered broadcast cache when a waiter is notified for the block digest

The key distinctions to measure are:

- when the proposer asks marshal to broadcast the body
- when marshal accepts that request
- when buffered broadcast finishes handing the body to the network sender

- when verification starts waiting on marshal for the block digest
- when the buffered broadcast cache subscription itself resolves
- when the application actor finally gets the block back from marshal

If the proposer-side `buffer_sent` marker is already late, the delay is before or inside the sender-side fanout path. If `buffer_sent` is early but receiver-side `broadcast_received` is late, the remaining gap is below the broadcast engine boundary. If the buffered-cache resolution is already late, the bottleneck is still upstream of marshal local notification. If the buffered-cache resolution is fast but marshal/application receipt is late, the delay is in the local wakeup path after the body is already cached.

### 5. Test `tcp_slow_start_after_idle=0` only on a reproducing environment

```bash
for c in <all-validator-containers>; do
  docker exec $c sysctl -w net.ipv4.tcp_slow_start_after_idle=0
done
```

This is still reasonable to try, but it is lower priority than validating whether the `363/363` result holds in the `~1.5k–2.5k tx` range and in a testnet-like environment.

### 6. Capture TCP_INFO during large block sends on a reproducing run

```bash
# On proposer container during bench:
while true; do ss -tin | grep -v State; sleep 0.01; done > /tmp/tcp_info.log
```

Look for `cwnd`, `unacked`, `app_limited`, `snd_wnd`, and receive-window behavior at the moment of large sends.

Recent geo-devnet snapshots now exist for all three scenarios under `.geodevnet/scenario-runs/<timestamp>/`. A side-by-side TCP_INFO capture under `default`, `initcwnd363`, and `bbr` would help quantify whether the remaining outliers are still congestion-window related or whether a second bottleneck appears once the initial window is no longer dominant.

### 7. Test separate connections for control vs bulk

The most architecturally sound fix would be separating votes/certs (channel 0-1) onto a different TCP connection than block bodies (channel 3). This eliminates:
- HOL blocking where a 480KB body write blocks subsequent votes
- Shared cwnd between tiny control messages and large bulk data

---

## Potential Solutions (Ordered by Impact)

### OS-Level (No Code Changes)

1. **Moderate `initcwnd` increase on the validator subnet route** — current geo-devnet evidence says this has by far the clearest impact, but it only matters for new peer connections
2. **Container or host `bbr` tuning** — tested container-local `bbr` helps somewhat but does not come close to the `initcwnd363` result on its own
3. **`tcp_slow_start_after_idle=0`** on all validators — prevents cwnd reset during idle gaps
4. **Larger TCP buffer sizes** — `tcp_wmem`/`tcp_rmem` tuning

### Code Changes (Commonware/Tempo)

4. **Separate control and bulk TCP connections per peer** — one for votes/certs, one for block bodies. Eliminates HOL blocking and allows independent cwnd management.
5. **Active fetch on body miss** — `subscribe_by_digest(None, payload)` uses `round: None`, meaning no resolver fetch is triggered. Adding a round hint could trigger parallel fetch.
6. **Increase buffer pool `max_size`** beyond 64KB — reduces heap allocation churn for large messages.

### Architectural

7. **Erasure coding / multi-peer body retrieval** — download block body from multiple peers in parallel.

### What Will NOT Fix This

- **`SO_SNDBUF`/`SO_RCVBUF` alone** — larger buffers let the app enqueue faster but don't bypass congestion control on the wire.
- **QUIC alone** — QUIC still has congestion control and slow start. Helps with multiplexing (no HOL across streams) but doesn't avoid cwnd growth on a fresh stream.

---

## Files Referenced

| File | Purpose |
|------|---------|
| `crates/commonware-node/src/config.rs` | Channel IDs (`BROADCASTER_CHANNEL_IDENT=3`) and rate limits (`BROADCASTER_LIMIT=8/sec`) |
| `crates/commonware-node/src/lib.rs` | Network instantiation, channel registration |
| `crates/commonware-node/src/args.rs` | CLI args: `max_message_size_bytes`, `minimum_time_before_propose=450ms`, `worker_threads=3` |
| `bin/tempo/src/main.rs:350-354` | Runtime config: `tcp_nodelay=true`, worker threads |
| `commonware-broadcast/buffered/engine.rs` | Broadcast engine: `handle_broadcast()`, cache, waiters |
| `commonware-p2p/lookup/actors/router/actor.rs` | Router: fans out to per-peer relays via `try_send` |
| `commonware-p2p/lookup/actors/peer/actor.rs` | Per-peer sender/receiver tasks, `select_loop` |
| `commonware-p2p/utils/limited.rs` | `KeyedRateLimiter` (per-peer rate limiting) |
| `commonware-stream/encrypted.rs` | Encrypt + TCP write per peer |
| `commonware-runtime/network/tokio.rs` | `write_all_buf` on `OwnedWriteHalf` — the actual TCP send |
| `commonware-runtime/iobuf/pool.rs` | Buffer pool: 64KB max, oversized → heap fallback |
| `crates/commonware-node/src/consensus/application/actor.rs` | New investigation log: `"sending block to execution layer for verification"` right before `verify_block(...)` |
| `valscope/apps/api/src/parser.rs` | Log message → event type mapping |
| `valscope/apps/api/src/store.rs:2538-2570` | `process_ms`, `verify_ms`, `receive_delay_ms` computation |
| `contrib/geo-devnet/geo-devnet.sh` | Docker-based geo-devnet with netem shaping |
| `contrib/geo-devnet/analyze_propagation.py` | Propagation delay analysis script, now keyed by proposal digest and `Built payload` metadata |
