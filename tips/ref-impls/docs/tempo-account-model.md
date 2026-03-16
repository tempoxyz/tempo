# The Tempo Account Model

*Draft, March 2026*

Tempo extends Ethereum's account model to support multiple signing key schemes at the protocol level. This document lays out the problem space, the decisions we've already made, the ones we haven't, and where the model is headed.

## The Problem

Ethereum's account model assumes a single key type and signature scheme. EOAs use secp256k1 ECDSA exclusively. Smart contracts verify identity through two mechanisms, both locked to secp256k1:

1. **`msg.sender`**: on-chain identity for transfers, deposits, votes, and any call-based interaction. The caller's address is implicitly trusted.
2. **`ecrecover`**: off-chain signature verification. Contracts pass a `(v, r, s)` tuple to recover the signer's address. Permits, gasless approvals, off-chain order signing, and governance voting by signature all rely on this path.

The `msg.sender` half is solvable — Tempo grants every key type its own address space, so on-chain interactions work across account types. The `ecrecover` half is the harder problem: any account using a non-secp256k1 key scheme is a second-class citizen for signature-based workflows. In practice, this affects Uniswap Permit2 approvals, Seaport order signing, Aave/Compound governance (`castVoteBySig`), DAI permit, CoW Protocol intent signing, ERC-2612 gasless permits, any ERC-2771/GSN meta-transaction relayer, and more.

This is a structural limitation. As passkey-based wallets (P256/WebAuthn), multisig schemes, and post-quantum cryptography become necessary, Ethereum's single-scheme assumption forces the ecosystem into increasingly complex workarounds.

## Why Existing Solutions Fall Short

The AA debate on Ethereum splits into two camps: enshrine specific features into the protocol, or provide generic primitives and let developers build. Ethereum's proposals have gravitated toward the latter, and the resulting complexity is the cost.

**[ERC-4337](https://eips.ethereum.org/EIPS/eip-4337)** builds a second transaction pipeline at the application layer: separate message type (UserOperations), separate relay network (bundlers), and a singleton `EntryPoint` contract mediating every execution. This adds gas overhead per `UserOp`, depends on a thin bundler market with no protocol-level liveness guarantee, and forces every block explorer, indexer, and wallet to handle a second class of transaction.

**[EIP-7702](https://eips.ethereum.org/EIPS/eip-7702)** lets an EOA delegate execution to a contract for one transaction — enabling batching, gas sponsorship, and custom validation. But the delegating account is still a secp256k1 EOA. A passkey holder or multisig cannot initiate a 7702 delegation on its own. Existing EOAs gain new capabilities, but remain secp256k1 accounts underneath.

**[EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) (Frame Transactions)** a fully generic account model: authorization, gas payment, and execution are all arbitrary EVM code. This can express any AA use case, but there are no sane defaults — every integrator independently solves key management, gas abstraction, and replay protection:

- Clients must execute arbitrary code to validate transactions before inclusion, which makes mempool DoS protection more complex.
- Developer tooling (block explorers, debuggers, simulators) must handle transactions with no well-defined structure, where authorization and payment can happen at any point during execution.
- Wallets must integrate and audit smart account implementations on every chain — whether their own or third-party.

## Tempo's Account Model

Tempo solves this at the protocol level. Multiple key schemes authenticate in the execution layer, outside the EVM, before a transaction ever touches a contract — without bundlers, wrapper contracts, or alternative mempools.

All account types share the same transaction format, mempool, and gas semantics.

| Key Type | Scheme | Status |
|---|---|---|
| secp256k1 | ECDSA | Live |
| P256 / WebAuthn | secp256r1 | Live |
| Multisig | M-of-N or weighted M-of-N quorum | In progress |
| Post-Quantum | TBD | Future |

All key types receive their own address space at the protocol level, so `msg.sender`-based interactions work identically across account types.

## The Verification Precompile (TIP-1020)

Protocol-level authentication solves the `msg.sender` half of the problem. But contracts that verify off-chain signatures — the `ecrecover` half — still can't work with non-secp256k1 accounts.

The solution is a unified verification precompile: a single address that accepts `(address signer, bytes32 hash, bytes signature)` and returns whether the signature is valid, regardless of what key type backs the account.

```solidity
// Instead of:
address signer = ecrecover(hash, v, r, s);

// Tempo-native contracts call:
bool valid = TEMPO_VERIFY.verify(signer, hash, signature);
```

Contracts call this precompile instead of `ecrecover`. They don't need to know what key type the signer uses, and they don't need to be redeployed when new key types are added.

Three properties matter:

1. **Forward-compatible.** As key types are activated or deprecated through hardforks, their verification logic is added or removed from the precompile. Contracts don't change; the chain's answer to "is this signature valid?" evolves over time.

2. **Preserves immutability.** Without the precompile, contracts would need upgradeability mechanisms just to keep up with new key types. The precompile lets contracts remain immutable while supporting all Tempo EOAs.

3. **Single policy enforcement point.** The precompile is the authoritative boundary between the account model (which changes) and the contract layer (which doesn't). It governs which cryptographic schemes the chain considers valid at any given block height, letting the model evolve without breaking deployed contracts.

For Tempo-native contracts — TIP-20 tokens, the stablecoin DEX, governance — this is the standard verification path. Ethereum-origin contracts deployed on Tempo that use `ecrecover` will continue to work, but only for secp256k1 accounts.

## Address Derivation and Cryptographic Isolation

Supporting multiple key schemes introduces a security consideration: the chain's address space is only as strong as its weakest active scheme. If a scheme is broken, an attacker could derive a key whose address collides with an existing account under a different scheme. One compromised scheme poisons the entire address space.

There are two approaches to contain this blast radius:

### Option A: Partition the address space

Reserve a prefix byte per key type. Each scheme can only derive addresses within its partition:

```
No prefix   → secp256k1
0x01_______ → P256 / WebAuthn
0x02_______ → Multisig
0x03_______ → Post-Quantum
```

A compromised scheme can only collide with addresses in its own partition — a broken PQ derivation cannot take over a P256 account.

**Tradeoffs:** secp256k1 addresses already exist without prefix restrictions, so this partition can't be enforced retroactively (affected users would need to migrate). Non-secp256k1 key generation becomes slightly slower as devices mine for valid prefixes. Effective address space per partition drops from 160 to 152 bits.

### Option B: Register key type on first use

Keep address derivation uniform. The first transaction from an account records its key type at the protocol level. Subsequent signatures from a different key type are rejected unless the account explicitly rotates via a migration operation.

This preserves address format compatibility and requires the fewest changes. It also opens a clean path to key rotation. The tradeoff is that the blast radius remains broad: a broken scheme still has access to the full address space for counterfactual (never-activated) addresses, including burn addresses like `0x00..00` and `0x00..dead`.

## Open Problems

Two problems remain open. First, the account model changes but smart contracts do not. The verification precompile is the seam between these two worlds — it must remain a stable interface while everything behind it evolves with each hardfork. Getting this boundary right is what lets the model evolve without breaking what's already deployed.

Second, the chain's security is bounded by its weakest active key scheme. Whether we partition the address space or register key types on first use, we need to resolve which isolation strategy to adopt.
