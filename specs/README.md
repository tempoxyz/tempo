# Tempo protocol specification (T13)

This folder specifies the Tempo protocol precisely enough to build a Tempo client from scratch that follows and validates Tempo mainnet from genesis through the T13 network upgrade.

## Scope

- **In scope:** everything that decides whether a block is valid and what state it produces, plus what a validator needs to propose, vote and run the DKG, and what a follower needs to sync and verify finality.
- **Networks:** Tempo mainnet (chain ID 4217) from genesis, with every rule from T0 through T13. Moderato testnet (chain ID 42431) shares these rules from its T0 activation onward. Its earlier pre-T0 "Genesis" era is not specified.
- **Out of scope:** JSON-RPC, transaction pool policy (except where it affects block validity), node operations, T14 and later.

## Normative references

- Ethereum execution layer as of Osaka: [ethereum/execution-specs](https://github.com/ethereum/execution-specs) and the EIPs cited in each chapter. Tempo runs the EVM at the Osaka spec in every fork, so an EIP up to Osaka applies unless a chapter says otherwise.
- Cryptographic and transport standards used by the consensus chapters: Ed25519 ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)) with [ZIP-215](https://zips.z.cash/zip-0215) verification, BLS12-381 ([draft-irtf-cfrg-pairing-friendly-curves](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-11)) with hashing to curves per [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380), X25519 ([RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)), ChaCha20-Poly1305 ([RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)), SHA-256 ([FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)) and [BLAKE3](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf).
- Wire and interface standards: the [Solidity ABI specification](https://docs.soliditylang.org/en/latest/abi-spec.html), RLP and the [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf), the [devp2p specifications](https://github.com/ethereum/devp2p) (RLPx, discv4, eth/68, eth/69) and the [Engine API](https://github.com/ethereum/execution-apis).
- Tempo Improvement Proposals in [`tips/`](../tips). Where a chapter and a TIP disagree, the chapter wins.

The Simplex consensus, threshold BLS12-381, the Feldman–Desmedt DKG, the validator network and their codec are specified in the five commonware chapters of this spec (listed under Chapters), which are self-contained.

## Conventions

- MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.
- "From Tn" means the rule applies to a block whose header timestamp is at or after Tn's activation, and "Before Tn" means it applies before that. [01-chain-and-forks.md](01-chain-and-forks.md) defines this precisely.
- These chapters, the TIPs and the external specifications listed under Normative references are the only sources a client needs. The chapters do not refer to any implementation's code.
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
| [commonware/codec.md](commonware/codec.md) | The consensus codec, ordered sets, namespaced messages, the N3f1 fault model and fixed-length epochs |
| [commonware/cryptography.md](commonware/cryptography.md) | Ed25519, BLS12-381 MinSig, threshold BLS, the threshold VRF scheme and the BLAKE3 transcript |
| [commonware/dkg.md](commonware/dkg.md) | The Feldman–Desmedt DKG and resharing: round information, messages, dealer logs, output and share derivation |
| [commonware/simplex.md](commonware/simplex.md) | Simplex consensus as Tempo runs it: types, signing, leader election, the protocol and the marshal wrapper |
| [commonware/p2p.md](commonware/p2p.md) | The validator network: framing, handshake, encrypted transport, lookup network, multiplexer, resolver and broadcast |
| [conflicts.md](conflicts.md) | Open conflicts between docs, TIPs and the implementation |
