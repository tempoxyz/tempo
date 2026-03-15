# The Tempo Account Model

*Draft, March 2026*

Tempo extends Ethereum's account model to support multiple signing key schemes at the protocol level. This document lays out the problem space, the decisions we've already made, the ones we haven't, and where the model is headed.

## Ethereum's Account Model and Contract Design

Ethereum has one EOA type: secp256k1 ECDSA. An EOA's address is the hash of it's public key. Because of this, all contracts today determine the identity of EOAs in 2 ways:

1. **`msg.sender`**: Transfer tokens, vote, deposit into a vault. In Tempo, all key types are granted an address space and would work with `msg.sender` based interactions.

2. **`ecrecover`**: contracts use it to verify off-chain signatures. These take a `(v, r, s)` tuple and call `ecrecover` to recover the signer's address, and only works for secp256k1 EOAs.

## The Tempo account model today

Tempo has introduced new account types and will keep introducing more:

| Key Type | Scheme | Status |
|---|---|---|
| secp256k1 | ECDSA | Live |
| P256 / WebAuthn | secp256r1 | Live |
| Multisig | M-of-N or weighted M-of-N quorum | In progress |
| Post-Quantum | TBD | Future |

All of these authenticate in the execution layer outside the EVM. 

## The `ecrecover` gap

P256 accounts, multisig or post-quantum keys cannot produce a valid `(v, r, s)` tuple that validates within the ecrecover precompile. Thus, these accounts cannot use any contracts that verifies signatures via `ecrecover`. This includes permits, gasless approvals, off-chain order signing, and governance voting by signature.

Protocols that would reject signatures from non-secp256k1 Tempo accounts today include Uniswap (Permit2 approvals), OpenSea/Seaport (order signing), Aave and Compound (governance `castVoteBySig`), MakerDAO (DAI permit), CoW Protocol (intent signing), OpenZeppelin Governor (vote by signature), ERC-2612 tokens broadly (gasless `permit`), and any ERC-2771/GSN meta-transaction relayer.

For Tempo-native contracts (TIP-20 tokens, the stablecoin DEX, governance) we control the code and can use a different verification path. Ethereum contracts that use `ecrecover` on Tempo can only serve secp256k1 EOAs.

## The TIP-1020 Verification Precompile

The solution for Tempo-native contracts is a unified signature verification precompile: a single address that accepts `(address signer, bytes32 hash, bytes signature)` and returns whether the signature is valid, regardless of what key type backs the account.

Contracts call this precompile instead of `ecrecover`. They don't need to know what key type the signer uses, and they don't need to be redeployed when new key types are added.

Critically, this precompile serves as the gateway to Tempo's evolving account model. As key types are activated or deprecated through hardforks, their corresponding verification logic is added or removed accordingly. This makes the precompile the single policy enforcement point governing which cryptographic schemes the chain considers valid at any given block height.

Without the precompile, these contracts will be forced to implement upgradeability on Tempo just to maintain compatibility with the Tempo account model. The precompile allows smart contracts to remain immutable and support the entire suite of Tempo EOAs while the Tempo account model changes. They delegate the "is this signature valid" question to the chain, and the chain's answer changes over time.

## Address derivation

Today, all Tempo key types derive addresses that maps to the entire full key space, a `bytes20`. This works fine as long as every active key scheme is cryptographically strong. If a weak scheme is introduced, or an existing scheme is broken, an attacker could find a key under that scheme whose derived address collides with an existing account. One broken scheme poisons the entire address space.

There are two approaches to contain this blast radius:

### Option A: Partition the address space

Reserve a prefix byte per key type. Each scheme can only derive addresses within its partition:

```
No prefix   → secp256k1
0x01_______ → P256 / WebAuthn
0x02_______ → Multisig
0x03_______ → Post-Quantum
```

A broken scheme can then only collide with addresses in its own partition. A compromised PQ derivation can't take over a P256 account because the addresses live in different spaces.

The catch is that secp256k1 addresses already exist everywhere with no prefix restriction, so the secp256k1 partition can't be enforced retroactively. Users whose secp256k1 address happens to fall in another scheme's range would be encouraged to migrate. Non-secp256k1 key generation also gets slightly slower, since devices need to mine for addresses with valid prefixes. Effective address space per partition drops from 160 to 152 bits with a 1-byte prefix.

### Option B: Register key type on first use

Keep address derivation uniform. The first transaction from an account records its key type at the protocol level. From that point on, the protocol rejects signatures from a different key type unless the account explicitly rotates via a migration operation.

This preserves address format compatibility and requires the fewest changes. It also opens a clean path to key rotation. The tradeoff is that blast radius remains broad: a broken scheme still has access to the full address space for counterfactual addresses and unactivated accounts such as burn addresses `0x00..00` and `0x00..dead`.

### Bottom line

This model gives Tempo a clean form of account abstraction without the complexity that
comes with existing solutions. Every account — regardless of key type — submits transactions the same way, lands in the same mempool, and executes with the same gas semantics.

Two problems remain open. First, the account model changes but smart contracts do not. The verification precompile is the seam between these two worlds — it must remain a stable interface while everything behind it evolves with each hardfork. Getting this boundary right is what lets the model evolve without breaking what's already deployed.

Second, the chain's security is bounded by its weakest active key scheme. Whether we
partition the address space or register key types on first use, we should find a resolution here.
