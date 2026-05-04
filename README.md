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

### Verifying release binaries

Each release ships `<binary>-<version>-<target>.tar.gz` plus `.sha256` (archive checksum), `.asc` (GPG signature), and `.spdx.json` (SBOM), as well as a separate `<binary>-<version>-<target>.sha256` for the bare unpacked binary (the durable hash an independent rebuilder will compare against). Releases also carry Sigstore-signed SLSA provenance and SBOM attestations. To verify a download:

```bash
TAG=v1.6.0
BIN=tempo-${TAG}-x86_64-unknown-linux-gnu
ARCHIVE=${BIN}.tar.gz

# 1. Download the archive and its sidecars from the release.
gh release download "$TAG" --repo tempoxyz/tempo \
  -p "$ARCHIVE" -p "$ARCHIVE.sha256" -p "$ARCHIVE.asc" \
  -p "$ARCHIVE.spdx.json" -p "$BIN.sha256"

# 2. Checksum the archive (and, after extraction, the bare binary).
sha256sum -c "$ARCHIVE.sha256"
tar xzf "$ARCHIVE" && sha256sum -c "$BIN.sha256"

# 3. GPG signature. See https://docs.tempo.xyz/guide/node/installation#verifying-releases
#    for the public key, fingerprint, and `gpg --recv-keys` command.
gpg --verify "$ARCHIVE.asc" "$ARCHIVE"

# 4. GitHub release attestation (tag + asset digests, signed by GitHub).
gh release verify "$TAG" --repo tempoxyz/tempo

# 5. SLSA build provenance (proves the workflow + commit that built it).
#    Both the archive and the bare binary are listed as subjects of the
#    same attestation, so either path verifies.
gh attestation verify "$ARCHIVE" --repo tempoxyz/tempo \
  --predicate-type https://slsa.dev/provenance/v1
gh attestation verify "$BIN"     --repo tempoxyz/tempo \
  --predicate-type https://slsa.dev/provenance/v1

# 6. SBOM attestation (binds $ARCHIVE.spdx.json to the artifact digest).
gh attestation verify "$ARCHIVE" --repo tempoxyz/tempo \
  --predicate-type https://spdx.dev/Document
gh attestation verify "$BIN"     --repo tempoxyz/tempo \
  --predicate-type https://spdx.dev/Document
```

## License

Licensed under either of [Apache License](./LICENSE-APACHE), Version
2.0 or [MIT License](./LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in these crates by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
