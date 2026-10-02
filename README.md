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

[![CodSpeed](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://codspeed.io/tempoxyz/tempo?utm_source=badge)

The blockchain for payments at scale.

Tempo nodes use published [network identities](#network-identities) to verify consensus finalisation and authenticate snapshots.

[Tempo](https://docs.tempo.xyz/) is a blockchain designed specifically for stablecoin payments. Its architecture focuses on high throughput, low cost, and features that financial institutions, payment service providers, and fintech platforms expect from modern payment infrastructure.

You can get started today by integrating with the [Tempo testnet](https://docs.tempo.xyz/quickstart/integrate-tempo), [building on Tempo](https://docs.tempo.xyz/guide/use-accounts), [running a Tempo node](https://docs.tempo.xyz/guide/node), reading the [Tempo protocol specs](https://docs.tempo.xyz/protocol) or by [building with Tempo SDKs](https://docs.tempo.xyz/sdk).

## What makes Tempo different

- [TIP‑20 token standard](https://docs.tempo.xyz/protocol/tip20/overview) (enshrined ERC‑20 extensions)

  - Predictable payment throughput via dedicated payment lanes reserved for TIP‑20 transfers (eliminates noisy‑neighbor contention).
  - Native reconciliation with on‑transfer memos and commitment patterns (hash/locator) for off‑chain PII and large data.
  - Built‑in compliance through [TIP‑403 Policy Registry](https://docs.tempo.xyz/protocol/tip403/overview): single policy shared across multiple tokens, updated once and enforced everywhere.

- Low, predictable fees in [stablecoins](https://docs.tempo.xyz/learn/stablecoins)

  - Users pay gas directly in USD-stablecoins at launch; the [Fee AMM](https://docs.tempo.xyz/protocol/fees/fee-amm#fee-amm-overview) automatically converts to the validator’s preferred stablecoin.
  - TIP‑20 transfers target sub‑millidollar costs (<$0.001).

- [Tempo Transactions](https://docs.tempo.xyz/guide/tempo-transaction) (native “smart accounts”)

  - Batched payments: atomic multi‑operation payouts (payroll, settlements, refunds).
  - Fee sponsorship: apps can pay users' gas to streamline onboarding and flows.
  - Scheduled payments: protocol‑level time windows for recurring and timed disbursements.
  - Modern authentication: passkeys via WebAuthn/P256 (biometric sign‑in, secure enclave, cross‑device sync).

- Performance and finality

  - Built on the [Reth SDK](https://github.com/paradigmxyz/reth), the most performant and flexible EVM (Ethereum Virtual Machine) execution client.
  - Simplex Consensus (via [Commonware](https://commonware.xyz/)): fast, sub‑second finality in normal conditions; graceful degradation under adverse networks.

- Coming soon

  - On‑chain FX and non‑USD stablecoin support for direct on‑chain liquidity; pay fees in more currencies.
  - Native private token standard: opt‑in privacy for balances/transfers coexisting with issuer compliance and auditability.

## What makes Tempo familiar

- Fully compatible with the Ethereum Virtual Machine (EVM), targeting the Osaka hardfork.
- Deploy and interact with smart contracts using the same tools, languages, and frameworks used on Ethereum, such as Solidity, Foundry, and Hardhat.
- All Ethereum JSON-RPC methods work out of the box.

While the execution environment mirrors Ethereum's, Tempo introduces some differences optimized for payments, described [here](https://docs.tempo.xyz/quickstart/evm-compatibility).

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

Next, grab some stablecoins to test with from Tempo's [Faucet](https://docs.tempo.xyz/quickstart/faucet#faucet).

Alternatively, use [`cast`](https://github.com/foundry-rs/foundry):

```bash
cast rpc tempo_fundAddress <ADDRESS> --rpc-url https://rpc.moderato.tempo.xyz
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

For local development and CI, run the [bootstrapped localnet container](./docs/localnet.md):

```bash
docker run --rm -p 127.0.0.1:8545:8545 ghcr.io/tempoxyz/tempo-localnet:latest
```

For prover E2E devnets, `ghcr.io/tempoxyz/tempo-devnet` (also on Docker Hub)
contains the Tempo L1 binary built with `custom-pcrs`. It is published alongside
the regular images with matching tags, including `sha-<short-sha>` and `nightly`.
Pass the prover measurements using `--zone-verifier.custom-pcrs` or
`TEMPO_ZONE_VERIFIER_CUSTOM_PCRS`; this variant refuses to start on mainnet and
Moderato. The regular images keep the compiled-in PCR policy.

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

## Contributing

Our contributor guidelines can be found in [`CONTRIBUTING.md`](https://github.com/tempoxyz/tempo?tab=contributing-ov-file).

## Network identities

These BLS threshold public keys are built into Tempo nodes and used by both follow/RPC nodes and validators to verify consensus finalisation certificates, including those used to authenticate snapshots.

**Mainnet — from epoch 0**

```text
0xa217bb85001d4dcf8e5c50136f77af88cb2cab1857279b91c6240f41cca95c4f43f6dcab3e0dfb87dafb3ecbeb6251e90a5df2e6c47432482821cd8b84665ee4642589d2d9628a92b03e2bbfb00e006d038cd98def76d2a41b7c228c05f5a193
```

**Testnet (Moderato) — from epoch 1747**

```text
0x967ae1a6d3ddbe5cb0fe5e6fc58e74249787b4a277619b549fed6609d04660540dd2449cd7174def35e40f544e5ad72d15d064191a205ed6e0c49619c68f975108b614d0d51def9a8416a10a07c4193bea0cbbc4252ec1b33f21095a5d7aa590
```

See the [compiled network identities](./crates/chainspec/src/network_identity.rs) for the built-in values. To override them, see [How do I override the network identity?](https://tempo.xyz/developers/docs/guide/node/validator-troubleshooting#my-node-fails-to-start-finalized-tip-certificate-failed-verification-against-the-trusted-network-identity).

## Security

See [`SECURITY.md`](https://github.com/tempoxyz/tempo?tab=security-ov-file). Note: Tempo is still undergoing audit and does not have an active bug bounty. Submissions will not be eligible for a bounty until audits have concluded.

### Verifying release binaries

Each release ships `<binary>-<version>-<target>.tar.gz` plus `.sha256` (archive checksum) and `.asc` (GPG signature), and is also covered by Sigstore-signed SLSA build provenance.

The [`tempoup`](./tempoup) installer performs these checks automatically on every install. To verify manually, pick **one** of the two paths below — both prove the archive came from the tagged commit, signed by tempoxyz.

**Path A — offline / no GitHub auth required (checksum + GPG):**

```bash
TAG=v1.6.0
ARCHIVE=tempo-${TAG}-x86_64-unknown-linux-gnu.tar.gz

gh release download "$TAG" --repo tempoxyz/tempo \
  -p "$ARCHIVE" -p "$ARCHIVE.sha256" -p "$ARCHIVE.asc"

sha256sum -c "$ARCHIVE.sha256"

# Public key + fingerprint:
# https://docs.tempo.xyz/guide/node/installation#verifying-releases
gpg --verify "$ARCHIVE.asc" "$ARCHIVE"
```

**Path B — Sigstore (requires `gh` installed and authenticated):**

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
