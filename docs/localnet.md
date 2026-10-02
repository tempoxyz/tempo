# Tempo localnet container

`tempo-localnet` is a batteries-included Tempo network for application development and CI. It starts a deterministic development node, waits for RPC, and prepares the payment features commonly needed by SDK and backend tests.

```bash
docker run --rm -p 127.0.0.1:8545:8545 ghcr.io/tempoxyz/tempo-localnet:latest
```

The RPC is available at `http://127.0.0.1:8545` with chain ID `1337`. The container reports healthy only after setup completes.

Use a version or digest instead of `latest` in CI so protocol upgrades do not change a test run unexpectedly.

## Included setup

The default container starts with:

- The standard development mnemonic and 10 prefunded accounts.
- `tempo_fundAddress` configured for the four canonical TIP-20 tokens.
- Fee AMM liquidity between AlphaUSD, BetaUSD, ThetaUSD, and pathUSD.
- Stablecoin DEX bid and ask liquidity at a 1:1 price for the same pairs.

Bootstrap is idempotent. When `/data` is reused, existing pools and orders are preserved instead of duplicated.

| Token | Address |
| --- | --- |
| pathUSD | `0x20c0000000000000000000000000000000000000` |
| AlphaUSD | `0x20c0000000000000000000000000000000000001` |
| BetaUSD | `0x20c0000000000000000000000000000000000002` |
| ThetaUSD | `0x20c0000000000000000000000000000000000003` |

The deterministic mnemonic is:

```text
test test test test test test test test test test test junk
```

Its first account is `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`. These public development credentials are not safe for hosted networks or real funds.

## Options

The default is the fully bootstrapped network. Only two runtime options are exposed:

| Option | Effect |
| --- | --- |
| `--bare` | Start the node without the faucet or liquidity setup. |
| `--block-time <duration>` | Set the block interval, up to `5s`. Default: `1s`. Examples: `200ms`, `2s`. |

Examples:

```bash
# Faster blocks
docker run --rm -p 127.0.0.1:8545:8545 \
  ghcr.io/tempoxyz/tempo-localnet:latest --block-time 200ms

# Node only
docker run --rm -p 127.0.0.1:8545:8545 \
  ghcr.io/tempoxyz/tempo-localnet:latest --bare

# Publish the RPC on a different host port
docker run --rm -p 127.0.0.1:9545:8545 \
  ghcr.io/tempoxyz/tempo-localnet:latest
```

The RPC binds to all interfaces inside the container so Docker can forward it. The examples bind
the published port to host loopback. Do not remove `127.0.0.1` on an untrusted network: every RPC
module, permissive CORS, and the development faucet are enabled.

## Protocol semantics

The image uses Tempo's `dev` chainspec, whose development hardfork schedule activates at genesis.
It can therefore include protocol changes that are not active on Presto, Moderato, or another live
network. Use it for deterministic application tests, not live-network fork compatibility tests.
Point compatibility tests at the intended network or a forked environment with its chainspec.

## Fund a test account

The default mode exposes the same faucet method used by Tempo test networks:

```bash
cast rpc tempo_fundAddress 0xYOUR_ADDRESS \
  --rpc-url http://127.0.0.1:8545
```

The call funds the address with each canonical TIP-20 token.

## Persist chain state

Mount `/data` to preserve state between runs:

```bash
docker volume create tempo-localnet-data

docker run --rm -p 127.0.0.1:8545:8545 \
  -v tempo-localnet-data:/data \
  ghcr.io/tempoxyz/tempo-localnet:latest
```

Remove the volume when a test needs a fresh genesis:

```bash
docker volume rm tempo-localnet-data
```

See [`examples/localnet/compose.yaml`](../examples/localnet/compose.yaml) for the equivalent Docker Compose configuration.

## Configure an SDK

Point the client at the local RPC and use chain ID `1337`. For example, with viem:

```ts
import { createPublicClient, defineChain, http } from 'viem'

const tempoLocalnet = defineChain({
  id: 1337,
  name: 'Tempo Localnet',
  nativeCurrency: { name: 'USD', symbol: 'USD', decimals: 18 },
  rpcUrls: { default: { http: ['http://127.0.0.1:8545'] } },
})

const client = createPublicClient({
  chain: tempoLocalnet,
  transport: http(),
})
```

Tempo Go and MPP services use the same endpoint through `TEMPO_RPC_URL`:

```bash
TEMPO_RPC_URL=http://127.0.0.1:8545 go test ./...
```

## CI

The image has a built-in health check. A shell job can wait for it before running tests:

```bash
container_id=$(docker run -d -p 127.0.0.1:8545:8545 \
  ghcr.io/tempoxyz/tempo-localnet:latest)
cleanup() {
  docker stop --time 10 "$container_id" >/dev/null 2>&1 || true
  docker rm "$container_id" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ready=false
for _ in $(seq 1 150); do
  running=$(docker inspect --format '{{.State.Running}}' "$container_id")
  health=$(docker inspect --format '{{.State.Health.Status}}' "$container_id")
  if [ "$running" != true ] || [ "$health" = unhealthy ]; then
    docker logs "$container_id"
    exit 1
  fi
  if [ "$health" = healthy ]; then
    ready=true
    break
  fi
  sleep 1
done
if [ "$ready" != true ]; then
  docker logs "$container_id"
  exit 1
fi

TEMPO_RPC_URL=http://127.0.0.1:8545 npm test
```

See [`examples/localnet/github-actions.yml`](../examples/localnet/github-actions.yml) for a GitHub Actions service-container example.
