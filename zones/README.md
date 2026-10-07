
<br>

<p align="center">
  <a href="https://tempo.xyz/blog/introducing-tempo-zones">
    <img src="assets/header.png" alt="Tempo Zones" width="100%">
  </a>
</p>

# Zones

> [!NOTE]
> This repository is actively under development and subject to rapid iteration.
> APIs, interfaces, and behavior may change without notice. Not recommended for production use yet.

Zones are private blockchains anchored to [Tempo](https://github.com/tempoxyz/tempo) *(currently available in testnet only),* with native support for confidential balances and transactions. Zones inherit compliance via TIP403 policies from Tempo and support interoperability with Tempo for moving assets in and out of Zones.

You can get started today by [deploying a Zone](#getting-started) on Tempo testnet, reading the [Zones documentation](https://docs.tempo.xyz/guide/private-zones), or exploring the [Zone spec](specs/spec.md).

<br>

## What Makes Zones Interesting

- **Private balances and transactions.** State access requires account authentication at the RPC layer. This ensures that only the authorized account holder can access balances and transaction history. The Zone operator maintains full visibility into state for compliance.

- **Encrypted deposits and withdrawals.** When depositing into a Zone, users can encrypt the recipient to not reveal who receives funds inside the Zone. Encrypted withdrawals are also possible, allowing the sender to be replaced with a commitment, preserving recipient verifiability without exposing the sender when withdrawing to Tempo mainnet.

- **Zone to Zone transfers.** Zones interoperate with Tempo via withdrawals with optional calldata. Withdrawal calldata can execute on Tempo and deposit into another Zone, enabling flows like Zone to Zone transfers or executing a swap between sending amounts to another Zone.

- **Compliance inherited from Tempo.** [TIP-403](https://docs.tempo.xyz/protocol/tip403/overview) policies (whitelist, blacklist) are mirrored from Tempo and enforced on Zones. Issuers set the policy once on Tempo and the Zone picks it up automatically. If an issuer freezes an address or updates a blacklist on Tempo, the Zone inherits the change in the next block in the Zone.

- **Fast withdrawals.** The Zone processes transactions every 250ms and submits batches of withdrawals to Tempo, where blocks are produced every ~500ms. Once batches are accepted and the attached proof is validated, withdrawals are processed and funds are released from escrow.

<br>

## Workspace layout

Run all commands below from the **Tempo repository root**. Zones shares the root
Cargo workspace and lockfile; Rust sources are in `crates/zones/`,
`bin/tempo-zone/`, and `bin/prover/`. Zone binary versions remain `0.3.5`.
Use `cargo xtask zones --help` for tooling and `just --list zones` for recipes.
Support files, specs, deployment scripts, and genesis fixtures live in `zones/`.

```bash
cargo build --locked --bin tempo-zone
just zones::contracts-build
docker buildx bake -f zones/docker/docker-bake.hcl --print
# Full image builds require Docker/BuildKit and checked-out contract submodules:
docker buildx bake -f zones/docker/docker-bake.hcl
# Reproducible verification build (Linux amd64):
OUT_DIR=target/zones-reproducible zones/scripts/reproducible-build.sh
```

See [migration notes](MIGRATION.md) for layout changes, release tags, benchmark
setup, and external operational cutover requirements.

## Getting Started

Prerequisites: [Rust](https://rustup.rs/), [Foundry](https://book.getfoundry.sh/getting-started/installation), [`just`](https://github.com/casey/just#packages), [`jq`](https://jqlang.github.io/jq/download/)

### Local Development with Anvil

Use Foundry 1.8 or newer, or a nightly build from July 11, 2026 or later,
then run Anvil in Tempo mode:

```bash
anvil --network tempo --block-time 1
```

Provision and run a fresh zone against its WebSocket endpoint:

```bash
cargo run --release --bin tempo-zone -- dev \
  --l1.rpc-url ws://127.0.0.1:8545
```

The default Anvil dev key is used automatically. The zone HTTP RPC listens on
`http://127.0.0.1:9545`; generated metadata and node data are written under
`/tmp/tempo-zone-dev`.

Older Anvil builds only add Tempo fields to Ethereum headers at the RPC layer.
The dev command rejects those builds because Zones require canonical Tempo block
hashes and parent links.


### Deploying a Zone

```bash
# Deploy and start a zone on Moderato testnet
export L1_RPC_URL="wss://rpc.moderato.tempo.xyz"
just zones::deploy-zone my-zone
```

The `deploy-zone` command generates admin and sequencer keypairs, funds them on L1, deploys the portal via `ZoneFactory`, generates genesis, and starts the node.

```bash
# Start/restart a zone after initial deployment
just zones::zone-up my-zone
```

### Custom L1 fork schedules

For custom L1 chain IDs, `node` and `re-execute` use the fork schedule in the
supplied Zone genesis without inheriting the binary's DEV defaults. Include the
intended Ethereum and Tempo fork activations when generating genesis; omitted
Tempo forks remain inactive. `ZONE_L1_DEV_CHAIN_IDS` is ignored and can be removed
after upgrading to a binary with this behavior. Mainnet, Moderato, and local
development chain IDs 1337/31337 retain their existing parent-schedule inheritance.

### Depositing into a Zone

```bash
export L1_PORTAL_ADDRESS=$(jq -r '.portal' zones/generated/my-zone/zone.json)
export PRIVATE_KEY=$(jq -r '.sequencerKey' zones/generated/my-zone/zone.json)
just zones::max-approve-portal

# Deposits are encrypted; the command fetches the portal's active encryption key.
just zones::send-deposit 1000000                       # to your own address
just zones::send-deposit 1000000 <recipient-address>   # to a specific address
```

### Withdrawing from Zone to Tempo

```bash

# withdraw from the zone
just zones::max-approve-outbox
just zones::send-withdrawal 1000000 <recipient-address>  # withdraw to a specific address
```

The sequencer includes the withdrawal in the next batch submission to L1 and processes it automatically.


### Querying the Redacted RPC

Zone balances are private by default. Every RPC request must include a signed authorization token that proves you control the querying account.

`just zones::zone-auth-token` reads `zones/generated/<name>/zone.json` and signs a short-lived auth token:

```bash

# generate an auth token
export PRIVATE_KEY=<zone-wallet-private-key>
export TOKEN=$(just zones::zone-auth-token my-zone)

# query your TIP-20 balance
just zones::check-balance-redacted my-zone <token-address>
```


See [docs/ZONES.md](docs/ZONES.md) for the full guide on deposits, withdrawals, redacted RPC, router demos, TIP-403 policy flows, and command references.

<br>

## License

Licensed under either of [Apache License](../LICENSE-APACHE), Version
2.0 or [MIT License](../LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in these crates by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
