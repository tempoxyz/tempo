# Tempo protocol specification (T13)

This folder specifies the Tempo protocol precisely enough to build a Tempo client from scratch that follows and validates Tempo mainnet from genesis through the T13 network upgrade.

## Scope

- **In scope:** everything that decides whether a block is valid and what state it produces, plus what a validator needs to propose, vote and run the DKG, and what a follower needs to sync and verify finality.
- **Networks:** Tempo mainnet (chain ID 4217) from genesis, with every rule from T0 through T13. Moderato testnet (chain ID 42431) shares these rules from its T0 activation onward. Its earlier pre-T0 "Genesis" era is not specified.
- **Out of scope:** JSON-RPC, transaction pool policy (except where it affects block validity), node operations, T14 and later.

## Normative references

- Ethereum execution layer as of Osaka: [ethereum/execution-specs](https://github.com/ethereum/execution-specs) and the EIPs cited in each chapter. Tempo runs the EVM at the Osaka spec in every fork, so an EIP up to Osaka applies unless a chapter says otherwise.
- [commonware](https://github.com/commonwarexyz/monorepo) **2026.9.0**: the Simplex consensus, threshold BLS12-381, the Feldman-Desmedt DKG, the authenticated p2p transport and the codec. This spec refers to their wire formats and does not restate them.
- Tempo Improvement Proposals in [`tips/`](../tips). Where a chapter and a TIP disagree, the chapter wins.

## Conventions

- MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.
- "From Tn" means the rule applies to a block whose header timestamp is at or after Tn's activation, and "Before Tn" means it applies before that. [01-chain-and-forks.md](01-chain-and-forks.md) defines this precisely.
- Every "Reference implementation" line points to the Rust implementation in this repository at commit `37dc7833023927f49fd0aa81ae84dbd43790f70c`, so readers can trace the rule. Those lines are informative, not normative.
- An **Open conflict** marker shows where Tempo's docs or TIPs disagree with what the implementation does and that disagreement has not been decided yet. [conflicts.md](conflicts.md) lists each one.

## Chapters

| Chapter | Covers |
|---|---|
| [01-chain-and-forks.md](01-chain-and-forks.md) | Chain IDs, genesis configuration, the fork model and schedule, and the per-fork change ledger |
| [02-encoding.md](02-encoding.md) | Header, block, transaction, key authorization, system transaction and receipt encodings |
| [03-signatures.md](03-signatures.md) | secp256k1, P256, WebAuthn and Keychain signatures, and sender recovery |
| [04-state-and-genesis.md](04-state-and-genesis.md) | State model, address namespaces and genesis construction |
| [05-block-execution.md](05-block-execution.md) | EVM changes, header checks, the block pipeline, system calls, gas lanes and post-execution checks |
| [06-transactions-and-fees.md](06-transactions-and-fees.md) | Transaction validation and processing, nonces, intrinsic gas and fee payment |
| [precompiles/00-framework.md](precompiles/00-framework.md) | Precompile registry, dispatch, storage model, gas and errors |
| [precompiles/tip20.md](precompiles/tip20.md) | TIP-20 tokens, the factory and the channel reserve |
| [precompiles/tip403.md](precompiles/tip403.md) | The TIP-403 policy registry, receive policies and the address registry |
| [precompiles/fee-manager.md](precompiles/fee-manager.md) | Fee manager and the fee AMM |
| [precompiles/stablecoin-dex.md](precompiles/stablecoin-dex.md) | Stablecoin DEX |
| [precompiles/account-keychain.md](precompiles/account-keychain.md) | Account keychain, nonce manager, signature verifier and storage credits |
| [precompiles/validator-config-and-zones.md](precompiles/validator-config-and-zones.md) | Validator config, current committee, zone factory and zone runtimes |
| [07-consensus.md](07-consensus.md) | Epochs, Simplex parameters, leader election, DKG, on-chain artifacts and how validators propose and verify |
| [08-p2p-and-sync.md](08-p2p-and-sync.md) | Validator p2p, the tempo/1 subprotocol, backfill, follower mode and persistence |
| [conflicts.md](conflicts.md) | Open conflicts between docs, TIPs and the implementation |
