<br>
<br>

<p align="center">
  <a href="https://tempo.xyz">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset=".github/assets/tempo-wordmark-white.svg">
      <img alt="Tempo wordmark" src=".github/assets/tempo-wordmark-black.svg" width="360">
    </picture>
  </a>
</p>

<br>
<br>

# Tempo

[![CodSpeed](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://app.codspeed.io/tempoxyz/tempo)

The blockchain for payments at scale.

Stablecoin payments on general-purpose blockchains are slow, expensive, and unpredictable — networks built for trading weren't designed for payment volume and reliability. Tempo exists to fix that: it's built for fintechs, payment processors, and enterprises who need payment infrastructure that behaves predictably at scale.

[Tempo](https://tempo.xyz/), incubated by [Stripe](https://stripe.com) and [Paradigm](https://www.paradigm.xyz), is a blockchain designed specifically for stablecoin payments. Its architecture focuses on high throughput, low cost, and features that financial institutions, payment service providers, and fintech platforms expect from modern payment infrastructure.

You can get started today by integrating with the [Tempo testnet](https://tempo.xyz/developers/docs/quickstart/integrate-tempo), [running a Tempo node](https://tempo.xyz/developers/docs/guide/node), reading the [Tempo protocol specs](https://tempo.xyz/developers/docs/protocol), or [building with Tempo SDKs](https://tempo.xyz/developers/docs/sdk).

## What makes Tempo different

- [TIP‑20 token standard](https://tempo.xyz/developers/docs/protocol/tip20/overview) (enshrined ERC‑20 extensions)

  - Predictable payment throughput via dedicated payment lanes reserved for TIP‑20 transfers (eliminates noisy‑neighbor contention).
  - Native reconciliation with on‑transfer memos and commitment patterns (hash/locator) for off‑chain PII and large data.
  - Built‑in compliance through [TIP‑403 Policy Registry](https://tempo.xyz/developers/docs/protocol/tip403/overview): single policy shared across multiple tokens, updated once and enforced everywhere.

- Low, predictable fees in [stablecoins](https://tempo.xyz/learn/what-are-stablecoins/)

  - Users pay gas directly in USD-stablecoins at launch; the [Fee AMM](https://tempo.xyz/developers/docs/protocol/fees/fee-amm#fee-amm-overview) automatically converts to the validator’s preferred stablecoin.
  - TIP‑20 transfers target sub-cent fees.

- [Tempo Transactions](https://tempo.xyz/developers/docs/guide/tempo-transaction) (native “smart accounts”)

  - Batched payments: atomic multi‑operation payouts (payroll, settlements, refunds).
  - Fee sponsorship: apps can pay users' gas to streamline onboarding and flows.
  - Scheduled payments: protocol‑level time windows for recurring and timed disbursements.
  - Modern authentication: passkeys via WebAuthn/P256 (biometric sign‑in, secure enclave, cross‑device sync).

- Performance and finality

  - Built on the [Reth SDK](https://github.com/paradigmxyz/reth), the most performant and flexible EVM (Ethereum Virtual Machine) execution client.
  - Simplex Consensus (via [Commonware](https://commonware.xyz/)): fast, sub‑second finality in normal conditions; graceful degradation under adverse networks.

- Tempo also powers the [Machine Payments Protocol (MPP)](https://mpp.dev), an open standard for machine-to-machine payments co-developed by Tempo and Stripe, enabling AI agents and apps to pay for resources inline with a request — no API keys required.

- Coming soon

  - On‑chain FX and non‑USD stablecoin support for direct on‑chain liquidity; pay fees in more currencies.
  - Native private token standard: opt‑in privacy for balances/transfers coexisting with issuer compliance and auditability.

## What makes Tempo familiar

- Fully compatible with the Ethereum Virtual Machine (EVM), targeting the Osaka hardfork.
- Deploy and interact with smart contracts using the same tools, languages, and frameworks used on Ethereum, such as Solidity, Foundry, and Hardhat.
- All Ethereum JSON-RPC methods work out of the box.

While the execution environment mirrors Ethereum's, Tempo introduces some differences optimized for payments, described [here](https://tempo.xyz/developers/docs/quickstart/evm-compatibility).

## Getting Started

### As a user

You can connect to Tempo's public testnet using the following details:

| Property           | Value                              |
| ------------------ | ---------------------------------- |
| **Network Name**   | Tempo Testnet (Moderato)           |
| **Currency**       | `USD`                              |
| **Chain ID**       | `42431`                            |
| **HTTP URL**       | `https://rpc.moderato.tempo.xyz`   |
| **WebSocket URL**  | `wss://rpc.moderato.tempo.xyz`     |
| **Block Explorer** | `https://explore.tempo.xyz`        |

Next, grab some stablecoins to test with from Tempo's [Faucet](https://tempo.xyz/developers/docs/quickstart/faucet#faucet).

Alternatively, use [`cast`](https://github.com/foundry-rs/foundry):

```bash
cast rpc tempo_fundAddress <ADDRESS> --rpc-url https://rpc.moderato.tempo.xyz
```

### As an operator

We provide three different installation paths: installing a pre-built binary, building from source or using our provided Docker image.

- [Pre-built Binary](https://tempo.xyz/developers/docs/guide/node/installation#pre-built-binary)
- [Build from Source](https://tempo.xyz/developers/docs/guide/node/installation#build-from-source)
- [Docker](https://tempo.xyz/developers/docs/guide/node/installation#docker)

See the [Tempo documentation](https://tempo.xyz/developers/docs/guide/node) for instructions on how to install and run Tempo.

### As a developer

Tempo has several SDKs to help you get started building on Tempo:

- [TypeScript](https://tempo.xyz/developers/docs/sdk/typescript)
- [Rust](https://tempo.xyz/developers/docs/sdk/rust)
- [Go](https://tempo.xyz/developers/docs/sdk/go)
- [Foundry](https://tempo.xyz/developers/docs/sdk/foundry)

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

Configure Git to run the repository hooks:

```bash
./scripts/setup-hooks.sh
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

## Related projects

- [`tempoxyz/tempo-apps`](https://github.com/tempoxyz/tempo-apps): Developer applications and hosted services for Tempo, including the explorer and network tooling.
- [`tempoxyz/tidx`](https://github.com/tempoxyz/tidx): Chain indexer for querying Tempo blocks, transactions, and logs.
- [`tempoxyz/wallet-cli`](https://github.com/tempoxyz/wallet-cli): Command-line wallet and HTTP client for Tempo and MPP-enabled services.
- [`tempoxyz/mpp`](https://github.com/tempoxyz/mpp): Documentation, protocol explainers, and service directory for MPP.
- [`tempoxyz/mpp-specs`](https://github.com/tempoxyz/mpp-specs): Specifications for the Machine Payments Protocol.
- [`tempoxyz/mpp-rs`](https://github.com/tempoxyz/mpp-rs): Rust SDK for the Machine Payments Protocol.

## Contributing

Our contributor guidelines can be found in [`CONTRIBUTING.md`](https://github.com/tempoxyz/tempo?tab=contributing-ov-file).

## Security

See [`SECURITY.md`](https://github.com/tempoxyz/tempo?tab=security-ov-file). Note: Tempo is still undergoing audit and does not have an active bug bounty. Submissions will not be eligible for a bounty until audits have concluded.

### Verifying release binaries

Each release ships `<binary>-<version>-<target>.tar.gz` plus `.sha256` (archive checksum) and `.asc` (GPG signature), and is also covered by Sigstore-signed SLSA build provenance.

The [`tempoup`](./tempoup) installer performs these checks automatically on every install. To verify manually, pick **one** of the two paths below. Both prove the archive came from the tagged commit, signed by tempoxyz.

**Path A: offline / no GitHub auth required (checksum + GPG):**

```bash
TAG=v1.6.0
ARCHIVE=tempo-${TAG}-x86_64-unknown-linux-gnu.tar.gz

gh release download "$TAG" --repo tempoxyz/tempo \
  -p "$ARCHIVE" -p "$ARCHIVE.sha256" -p "$ARCHIVE.asc"

sha256sum -c "$ARCHIVE.sha256"

# Public key + fingerprint:
# https://tempo.xyz/developers/docs/guide/node/installation#verifying-releases
gpg --verify "$ARCHIVE.asc" "$ARCHIVE"
```

**Path B: Sigstore (requires `gh` installed and authenticated):**

```bash
TAG=v1.6.0
ARCHIVE=tempo-${TAG}-x86_64-unknown-linux-gnu.tar.gz

gh release download "$TAG" --repo tempoxyz/tempo -p "$ARCHIVE"
gh attestation verify "$ARCHIVE" --repo tempoxyz/tempo \
  --predicate-type https://slsa.dev/provenance/v1
```

## License

Licensed under either of [Apache License](./LICENSE-APACHE), Version
2.0 or [MIT License](./LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in these crates by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
