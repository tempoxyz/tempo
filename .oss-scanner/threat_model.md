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

Out of scope: `xtask`, `crates/state-bloat`, `crates/faucet` (testnets only), `contrib/`, benchmark tooling,
development scripts in `scripts/` (but not `publish-crates.sh` and the `sanitize_*.py` it runs, which handle the
crates.io token in release CI), and bugs in upstream Reth, Revm, Alloy or Commonware that do not depend on Tempo's code (report those
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
- Fuzzing: `cd crates/nitro-attestation && cargo +nightly fuzz run parse_attestation -- -max_len=24577` (prebuilt;
  see its README).
- Behaviour is gated by hardfork (`crates/hardfork`, `crates/chainspec`). Report against the fork active on mainnet
  unless the bug is in an unreleased fork's code path, and say which.
- Zones tests that load Solidity artifacts from `crates/zones/contracts/out` fail here: building them needs a private
  repository. That is expected.

## How you rate severity

| Impact | Severity |
| --- | --- |
| Execution, transfer or replay under another account, key or sponsor on a live path | Critical |
| Unbounded value drain, e.g. a profitable AMM round trip | Critical |
| Consensus split reachable by ordinary transactions | Critical |
| One small request crashes any node, or a permissionless trigger wipes the mempool | Critical |
| Theft or replay needing an uncommon precondition, such as a shared access key | High |
| Spending-limit bypass, or paused or blacklisted value escaping through a side path | High |
| Missing charge for account creation or other state growth | High |
| Liveness failure that needs intervention, or proposer-forced heavy work before rejection | High |
| Whole class of valid transactions rejected, or expired keys admitted | High |
| Bounded accounting drift, pool or RPC resource leaks, mispriced gas constants | Medium |
| Validator-reachable corruption of the validator set | Medium |
| Narrow edge cases, misclassified transactions, restart-recoverable liveness, wrong error semantics | Low |
| Spec or documentation divergence, hardening, efficiency, latent defects with no caller | Informational |

The table wins: the adjustments below move a finding within what its row intends, never out of it.

Adjust for:
- The same defect rates higher when the vulnerable path is live on mainnet, and lower when it sits only behind an
  inactive fork or in pre-fork history.
- An ungated consensus-visible change is a chain split; severity tracks how easily an ordinary transaction triggers it.
- Misconfiguration reachable only by the config owner or a validator is Medium or Low, unless it crashes or splits
  honest nodes.
- A Byzantine proposer is in scope; forcing every validator to do large work before rejecting a block is High.
- Free, permissionless and repeatable attacks rate one level higher than equivalent paid attacks.
- A per-node slowdown needing sustained traffic is Medium or Low; network-wide mempool unavailability is High.
- A fault that clears on restart and cannot simply be triggered again is Low (a crash any remote caller can repeat
  is the table's Critical row); one that leaves a stale peer set for an epoch or needs manual repair is High.
- Latent storage, packing and encoding defects take the severity of their first reachable use.

A report should include a reproducer (a test in the affected crate is ideal) and the hardfork it applies to.

## Anything to leave alone

- Gas-cost or performance differences from Ethereum that are documented in a TIP (`tips/`).
- Admin and debug RPC namespaces, which operators must not expose publicly.
- Development keys and the `test test ... junk` mnemonic in tests and localnet.
