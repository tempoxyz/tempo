# Threat model

## What this project does and where untrusted input enters

Tempo is a payments blockchain: an EVM execution client built on the Reth SDK, with Commonware Simplex consensus and
enshrined precompiles for stablecoins (TIP-20 tokens, the Fee AMM, a stablecoin DEX, the TIP-403 policy registry,
account keychains). Mainnet holds real funds, so treat every byte from the network as hostile.

Untrusted input enters through:
- **Transactions**: any account can submit Tempo transactions (`crates/primitives/src/transaction`): batched calls,
  fee sponsorship, 2D nonces, validity windows, P256/WebAuthn signatures and key authorizations. They reach the
  transaction pool, then execution and the precompiles.
- **Public JSON-RPC** (`crates/node/src/rpc`), including Tempo-specific methods such as `tempo_simulateV1`.
- **P2P**: execution-layer devp2p from Reth, and consensus gossip between validators (`crates/consensus`). Validators
  are permissioned, but a minority of them may be Byzantine.
- **Blocks and certificates** from peers and snapshots, verified against the network identities in
  `crates/chainspec/src/network_identity.rs`.

## Components that matter most / least

Most important:
- `crates/precompiles`: TIP-20 balances, mint/burn, allowances, rewards; the Fee AMM and fee manager; the stablecoin
  DEX; TIP-403 policy enforcement; account keychain and nonce precompiles; validator config. Any way to create,
  steal, freeze or misaccount tokens lives here.
- `crates/primitives`, `crates/revm`, `crates/evm`: transaction encoding, signature verification and execution. Every
  node must reach the same state root from the same block; any non-determinism is consensus-breaking.
- `crates/transaction-pool`: validation and admission, payment lanes, the 2D nonce pool, fee-token liquidity checks.
- `crates/consensus`, `crates/payload`, `crates/node`: block building, finalization, DKG and epochs, subblocks.
- `crates/nitro-attestation`, `crates/precompiles/src/zone_verifier`: consensus-critical attestation checks.

In scope but lower priority: `crates/zones` and `bin/tempo-zone` (Tempo Zones L2), `bin/tempo-sidecar`.

Out of scope: `xtask`, `crates/state-bloat`, `crates/faucet` (testnets only), `scripts/`, `contrib/`, benchmark
tooling, and bugs in upstream Reth, Revm, Alloy or Commonware that do not depend on Tempo's code (report those
upstream).

## How to exercise it

- All test binaries are prebuilt. Select tests with `cargo nextest run --workspace -E 'package(<name>)' [filter]`,
  never `-p <name>`: `-p` changes feature unification and rebuilds hundreds of crates, and the container has 2 CPUs.
  Precompile tests in `crates/precompiles` run against an in-memory EVM and are the fastest way to prove a token or
  DEX bug.
- Full-node tests: `crates/node/tests/it` and `crates/e2e` start real nodes in-process. They are heavy; run one test
  at a time (`cargo nextest run --workspace -E 'package(tempo-e2e)' <name>`).
- A dev chain: `target/debug/tempo node --dev` serves RPC on `127.0.0.1:8545`; `target/debug/tempo-localnet` also
  funds the dev accounts and seeds Fee AMM and DEX liquidity (see `docs/localnet.md`). Rebuild them with
  `cargo build --workspace --bins --features tempo/localnet`.
- Behaviour is gated by hardfork (`crates/hardfork`, `crates/chainspec`). Report against the fork active on mainnet
  unless the bug is in an unreleased fork's code path, and say which.
- Zones tests that load Solidity artifacts from `crates/zones/contracts/out` fail here: building them needs a private
  repository. That is expected.

## How you rate severity

- **Critical**: theft, minting or permanent freezing of funds; bypass of TIP-403 policies or keychain spending
  limits; a chain split or state-root divergence reachable by an unprivileged transaction, block or message; a
  remote crash or halt of the network (not just one node); forging finalization.
- **High**: crashing or wedging any node remotely without validator privileges (malformed transaction, RPC call or
  P2P message); temporary freezing of funds; fee or AMM accounting errors that lose value; a minority of Byzantine
  validators stalling consensus.
- **Medium**: remote resource exhaustion that degrades a node without stopping it; pool admission bugs that let
  spam bypass fees or payment-lane limits; incorrect RPC results that could mislead wallets.
- **Low**: issues that need operator access, a malicious local config, or a majority of validators; panics only
  reachable from trusted admin RPC or the CLI.

A report should include a reproducer (a test in the affected crate is ideal) and the hardfork it applies to.

## Anything to leave alone

- Gas-cost or performance differences from Ethereum that are documented in a TIP (`tips/`).
- Admin and debug RPC namespaces, which operators must not expose publicly.
- Development keys and the `test test ... junk` mnemonic in tests and localnet.
