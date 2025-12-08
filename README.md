<br>
<br>

<p align="center">
  <a href="https://tempo.xyz">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/tempoxyz/.github/refs/heads/main/assets/combomark-dark.svg">
      <img alt="tempo combomark" src="https://raw.githubusercontent.com/tempoxyz/.github/refs/heads/main/assets/combomark-bright.svg" width="auto" height="120">
    </picture>
  </a>
</p>

<br>
<br>

# Tempo

The blockchain for payments at scale.

[Tempo](https://docs.tempo.xyz/) is a blockchain designed specifically for stablecoin payments. Its architecture focuses on high throughput, low cost, and features that financial institutions, payment service providers, and fintech platforms expect from modern payment infrastructure.

## Overview

Tempo is fully compatible with the Ethereum Virtual Machine (EVM), targeting the Osaka EVM hard fork. So, everything you'd expect to work with Ethereum works on Tempo, with only a few exceptions which we detail in the [EVM Differences](https://docs.tempo.xyz/quickstart/evm-compatibility#handling-eth-balance-checks) section of the documentation.

Key characteristics:

- Payments‑first policy and execution
  - 500ms block interval engineered for low perceived latency in payment flows
  - Deterministic, low‑variance fee behavior
  - Mempool prioritization for transfer‑shaped transactions, fairness windows, and nonce continuity
- Stablecoin‑native UX
  - Pay gas in supported stablecoins via protocol‑level conversion
  - Dedicated payments lane, memos, and access lists to streamline payer/merchant flows
  - Opt‑in privacy modes with reconcilable indexing
- EVM compatibility
  - Standard JSON‑RPC and EVM semantics
  - Built on the Rust‑based Reth SDK with high‑performance execution

## Specification

## Getting Started

### As a user

You can connect to Tempo Testnet using the following details:

| Property           | Value                           |
| ------------------ | ------------------------------- |
| **Network Name**   | Tempo Testnet (Andantino)       |
| **Currency**       | `USD`                           |
| **Chain ID**       | `42429`                         |
| **HTTP URL**       | `https://rpc.testnet.tempo.xyz` |
| **WebSocket URL**  | `wss://rpc.testnet.tempo.xyz`   |
| **Block Explorer** | `https://explore.tempo.xyz`     |

Next, grab some stablecoins to test with on from Tempo's [Faucet](https://docs.tempo.xyz/quickstart/faucet#faucet).

Alternatively, use [`cast`](https://github.com/tempoxyz/tempo-foundry):

```bash
cast rpc tempo_fundAddress <ADDRESS> --rpc-url https://rpc.testnet.tempo.xyz
```

### As an operator

See the [Tempo documentation](https://docs.tempo.xyz/guide/node) for instructions on how to install and run Tempo.

### As a developer

We provide three different installation paths - installing a pre-built binary, building from source or using our provided Docker image.

- [Pre-built Binary](https://docs.tempo.xyz/guide/node/installation#pre-built-binary)
- [Build from Source](https://docs.tempo.xyz/guide/node/installation#build-from-source)
- [Docker](https://docs.tempo.xyz/guide/node/installation#docker)

Tempo has several SDKs to help you get started building on Tempo:

- [TypeScript](https://docs.tempo.xyz/sdk/typescript)
- [Rust](https://docs.tempo.xyz/sdk/rust)
- [Go](https://docs.tempo.xyz/sdk/go)
- [Foundry](https://docs.tempo.xyz/sdk/foundry)

## Contributing

Our contributor guidelines can be found in [`CONTRIBUTING.md`](https://github.com/tempoxyz/tempo?tab=contributing-ov-file).

Prerequisites: [`just`](https://github.com/casey/just?tab=readme-ov-file#packages)

```bash
just
just build-all
just localnet
```

## Security

See [`SECURITY.md`](https://github.com/tempoxyz/tempo?tab=security-ov-file). Note: Tempo is still undergoing audit and does not have an active bug bounty. Submissions will not be eligible for a bounty until audits have concluded.

## License

Licensed under either of [Apache License](./LICENSE-APACHE), Version
2.0 or [MIT License](./LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in these crates by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
