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

You can get started today by integrating with the Tempo testnet, building on Tempo, running a Tempo node, reading the Tempo protocol specs or by building with Tempo SDKs.

- [Integrate Tempo Testnet](https://docs.tempo.xyz/quickstart/integrate-tempo)
- [Start Building on Tempo](https://docs.tempo.xyz/guide/use-accounts)
- [Run a Tempo Node](https://docs.tempo.xyz/guide/node)
- [Read Tempo Protocol Specs](https://docs.tempo.xyz/documentation/protocol)
- [Build on Tempo SDKs](https://docs.tempo.xyz/sdk)

## What makes Tempo different

- [TIP‑20 token standard](https://docs.tempo.xyz/documentation/protocol/tip20/overview) (enshrined ERC‑20 extensions)

  - Predictable payment throughput via dedicated payment lanes reserved for TIP‑20 transfers—eliminates noisy‑neighbor contention.
  - Native reconciliation with on‑transfer memos and commitment patterns (hash/locator) for off‑chain PII and large data.
  - Built‑in compliance through [TIP‑403 Policy Registry](https://docs.tempo.xyz/documentation/protocol/tip403/overview): single policy shared across multiple tokens, updated once and enforced everywhere.

- Low, predictable fees in [stablecoins](https://docs.tempo.xyz/learn/stablecoins)

  - Users pay gas directly in USD-stablecoins at launch; the [Fee AMM](https://docs.tempo.xyz/documentation/protocol/fees/fee-amm#fee-amm-overview) automatically converts to the validator’s preferred stablecoin.
  - TIP‑20 transfers target sub‑millidollar costs (<$0.001).

- [Tempo Transactions](https://docs.tempo.xyz/guide/tempo-transaction) (native `smart account` features)

  - Batched payments: atomic multi‑operation payouts (payroll, settlements, refunds).
  - Fee sponsorship: apps can pay users' gas to streamline onboarding and flows.
  - Scheduled payments: protocol‑level time windows for recurring and timed disbursements.
  - Modern authentication: passkeys via WebAuthn/P256 (biometric sign‑in, secure enclave, cross‑device sync).

- Performance and finality

  - Built on the [Reth SDK](https://github.com/paradigmxyz/reth), a highly performant EVM execution client.
  - Simplex Consensus (via [Commonware](https://commonware.xyz/)): fast, sub‑second finality in normal conditions; graceful degradation under adverse networks.

- Coming soon

  - On‑chain FX and non‑USD stablecoin support for direct on‑chain liquidity; pay fees in more currencies.
  - Native private token standard: opt‑in privacy for balances/transfers coexisting with issuer compliance and auditability.

## What makes Tempo familiar

- Fully compatible with the Ethereum Virtual Machine (EVM), targeting the Osaka EVM hard fork.
- Deploy and interact with smart contracts using the same tools, languages, and frameworks they use on Ethereum, such as Solidity, Foundry, and Hardhat.
- All Ethereum JSON-RPC methods work out of the box.

While the execution environment mirrors Ethereum's, Tempo introduces some differences optimized for payments, described [here](https://docs.tempo.xyz/quickstart/evm-compatibility).

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

We provide three different installation paths: installing a pre-built binary, building from source or using our provided Docker image.

- [Pre-built Binary](https://docs.tempo.xyz/guide/node/installation#pre-built-binary)
- [Build from Source](https://docs.tempo.xyz/guide/node/installation#build-from-source)
- [Docker](https://docs.tempo.xyz/guide/node/installation#docker)

See the [Tempo documentation](https://docs.tempo.xyz/guide/node) for instructions on how to install and run Tempo.

### As a developer

Tempo has several SDKs to help you get started building on Tempo:

- [TypeScript](https://docs.tempo.xyz/sdk/typescript)
- [Rust](https://docs.tempo.xyz/sdk/rust)
- [Go](https://docs.tempo.xyz/sdk/go)
- [Foundry](https://docs.tempo.xyz/sdk/foundry)

Want to contribute?

First, clone the repository:

```
git clone https://github.com/tempoxyz/tempo
cd tempo
```

Next, install [`just`](https://github.com/casey/just?tab=readme-ov-file#packages).

Install the dependencies:

```bash
just
```

Build Tempo:

```bash
just build-all
```

Run the tests:

```bash
cargo nextest run
```

Start a `localnet`:

```bash
just localnet
```

## Contributing

Our contributor guidelines can be found in [`CONTRIBUTING.md`](https://github.com/tempoxyz/tempo?tab=contributing-ov-file).

## Security

See [`SECURITY.md`](https://github.com/tempoxyz/tempo?tab=security-ov-file). Note: Tempo is still undergoing audit and does not have an active bug bounty. Submissions will not be eligible for a bounty until audits have concluded.

## License

Licensed under either of [Apache License](./LICENSE-APACHE), Version
2.0 or [MIT License](./LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in these crates by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
