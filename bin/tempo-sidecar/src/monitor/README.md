# StablecoinDEX Monitor

Orderbook monitoring for Tempo's StablecoinDEX. Exposes Prometheus metrics and includes a Grafana dashboard.

## Quick Start

```bash
# Demo mode (simulated data — no RPC needed)
cd contrib/bench && docker compose up -d
RUST_LOG=info cargo run --bin tempo-sidecar -- dex-monitor \
  --demo --chain-id demo --port 8001
open http://localhost:3000/d/tempo-dex-monitoring
# Login: admin/admin. Select Chain: "demo".

# Live mode (real data from a Tempo node)
RUST_LOG=info cargo run --bin tempo-sidecar -- dex-monitor \
  --rpc-url https://rpc.moderato.tempo.xyz \
  --chain-id 42431 \
  --port 8001
```

## How It Works

```
Tempo Node (or --demo)
  |
  | 1. Scan PairCreated events → discover trading pairs
  | 2. Fetch token metadata (name) via ITIP20
  |
  v
DexMonitor::worker() — polls every 5 seconds
  |
  |-- discover_new_pairs()
  |     Incremental: only scans blocks since last_processed_block
  |
  |-- update_orderbook_metrics()
  |     Per pair:
  |       books(book_key)          → bestBidTick, bestAskTick → spread
  |       getTickLevel(best_bid)   → bid liquidity
  |       getTickLevel(best_ask)   → ask liquidity
  |       quoteSwapExactAmountIn() → slippage estimation
  |     Global:
  |       nextOrderId()            → total orders
  |
  v
Prometheus gauges (localhost:8001/metrics)
  |
  | Prometheus scrapes every 1s (contrib/bench/prometheus.yml)
  v
Grafana dashboard (localhost:3000)
  6 panels: Spread, Total Orders, Errors, Bid Depth, Ask Depth, Slippage
```

## Metrics

| Metric | Type | Labels | What it measures |
|--------|------|--------|------------------|
| `tempo_dex_spread_ticks` | gauge | `chain_id`, `base_name`, `quote_name` | Bid-ask spread in ticks. Lower = tighter market |
| `tempo_dex_best_bid_liquidity` | gauge | `chain_id`, `base_name`, `quote_name` | Volume at best buy price |
| `tempo_dex_best_ask_liquidity` | gauge | `chain_id`, `base_name`, `quote_name` | Volume at best sell price |
| `tempo_dex_slippage_bps` | gauge | `chain_id`, `base_name`, `quote_name` | Price impact of a $1000 swap (1 bps = 0.01%) |
| `tempo_dex_total_orders` | gauge | `chain_id` | Total orders ever created (global) |
| `tempo_dex_monitor_errors` | counter | `chain_id`, `request` | RPC errors by call type |

## CLI Options

```
--rpc-url <URL>      Tempo node RPC endpoint (required in live mode)
--chain-id <ID>      Chain identifier for metric labels (default: "1")
--port <PORT>        HTTP port for /metrics endpoint (required)
--poll-interval <N>  Seconds between polls (default: 5)
--demo               Run with simulated data (no RPC needed)
```

## Demo Mode

`--demo` generates simulated metrics without connecting to a node. Useful for:
- Dashboard development and testing
- Demonstrating the monitoring stack

Simulates 5 pairs with different risk profiles:

| Pair | Spread | Liquidity | Slippage | Risk level |
|------|--------|-----------|----------|------------|
| USDC/PathUSD | ~5 ticks | ~500M | ~3 bps | Low |
| USDT/PathUSD | ~8 ticks | ~300M | ~8 bps | Low |
| DAI/PathUSD | ~15 ticks | ~100M | ~25 bps | Low |
| EURC/PathUSD | ~25 ticks | ~50M | ~65 bps | Medium |
| wBTC/PathUSD | ~40 ticks | ~20M | ~150 bps | High |

Values fluctuate ±15% each cycle to simulate market activity.

## Grafana Dashboard

Auto-imported via provisioner at `contrib/bench/grafana/dashboards/dex-monitoring.json`.

**Panels:**
- **Spread — Price Efficiency**: bid-ask spread per pair with threshold zones
- **Total Orders**: cumulative order count with sparkline
- **Monitor Errors**: RPC error rate by call type (green/yellow/red)
- **Bid Depth — Buy Side**: liquidity at best bid per pair
- **Ask Depth — Sell Side**: liquidity at best ask per pair
- **Slippage — Swap Cost Estimation**: estimated swap cost with threshold zones

**Threshold zones (background colors):**
- Spread: Green (<10) | Yellow (10-30) | Red (>30 ticks)
- Slippage: Green (<50) | Yellow (50-150) | Red (>150 bps)

**Variables (dropdowns at top):**
- **Chain**: filter by network (e.g., "demo", "42431")
- **Pair**: multi-select to focus on specific pairs

## Architecture

```
bin/tempo-sidecar/src/
  cmd/dex_monitor.rs          CLI args + setup (tracing, Prometheus, poem HTTP)
  monitor/dex.rs              DexMonitor: discovery, polling, metrics, demo mode

contrib/bench/
  docker-compose.yml          Prometheus + Grafana containers
  prometheus.yml              Scrape targets (includes tempo-dex-monitor on :8001)
  grafana/
    dashboards/
      dex-monitoring.json     Dashboard with 6 panels + header + variables
    provisioning/
      datasources/prometheus.yml   Auto-configures Prometheus datasource
      dashboards/default.yml       Auto-imports dashboards from /dashboards/
```

## For Mainnet Deployment

To deploy against a live network:

1. Point `--rpc-url` to a mainnet Tempo node
2. Set `--chain-id` to the mainnet chain ID
3. Configure Prometheus scrape target in your monitoring infrastructure
4. Import `dex-monitoring.json` into your Grafana instance

The monitor auto-discovers all pairs via PairCreated events.
