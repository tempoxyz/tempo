---
id: TIP-XXXX
title: TIP-20 Address Prefix Protection for Contract Creation
description: Prevents contracts from being deployed at addresses with the reserved TIP-20 address prefix via CREATE, CREATE2, or EIP-7702 delegation.
authors: howydev
status: Draft
related: TIP-20
protocolVersion: TBD
---

# TIP-XXXX: TIP-20 Address Prefix Protection for Contract Creation

## Abstract

This TIP introduces protocol-level protection to prevent contracts from being deployed at addresses with the reserved TIP-20 address prefix (`0x20C0...`) via `CREATE`, `CREATE2`, or EIP-7702 delegation. This enforces that all addresses recognized as TIP-20 tokens were deployed exclusively through the TIP-20 factory.

## Motivation

TIP-20 tokens are identified by their **address prefix**. The `isTIP20` check verifies whether an address is a valid TIP-20 token by checking:

1. The address starts with the 12-byte prefix `0x20C000000000000000000000`
2. The address has code deployed (`codesize > 0`)

```solidity
function isTIP20(address token) internal view returns (bool) {
    return bytes12(bytes20(token)) == bytes12(0x20c000000000000000000000) 
        && token.code.length > 0;
}
```

Currently, there is no explicit protection preventing a contract from being deployed at an address that happens to have this prefix. With sufficient computing power, an attacker could find a `CREATE2` salt that produces an address with the TIP-20 prefix, allowing arbitrary code to be deployed at an address that passes `isTIP20` checks.

One of the core invariants relied on by the Tempo precompiles is that `isTIP20` reliably identifies tokens deployed through the official factory. This proposal enforces that invariant at the protocol level.

---

# Specification

## Reserved Address Prefix

The TIP-20 address prefix is defined as:

```
TIP20_ADDRESS_PREFIX = 0x20C000000000000000000000 (12 bytes)
```

Addresses starting with this prefix are reserved exclusively for TIP-20 tokens deployed through the TIP-20 factory.

## Contract Creation Check

For all contract creation operations (`CREATE`, `CREATE2`, and EIP-7702 delegation), before deploying code to the target address:

1. Check if the target address starts with `TIP20_ADDRESS_PREFIX`
2. If yes, the creation MUST revert
3. Otherwise, proceed with normal contract deployment

### Pseudocode

```solidity
function validateContractCreationAddress(address target) internal pure {
    if (bytes12(bytes20(target)) == bytes12(0x20c000000000000000000000)) {
        revert("TIP20AddressReserved");
    }
}
```

## Affected Operations

| Operation | Check Applied |
|-----------|---------------|
| `CREATE` | Before deploying to computed address |
| `CREATE2` | Before deploying to computed address |
| EIP-7702 delegation | When setting delegation target |

## EIP-7702 Delegation

For EIP-7702 account delegation, the check applies when an EOA sets a delegation target:

- If the EOA's address starts with `0x20C0...`, the delegation MUST revert
- This prevents EOAs at TIP-20 addresses from being used as smart accounts

## TIP-20 Factory Exemption

The TIP-20 factory precompile (`0x20Fc...`) is exempt from this check. The factory is the sole authorized mechanism for deploying code at TIP-20 addresses.

---

# Invariants

| ID | Invariant | Description |
|----|-----------|-------------|
| **P1** | Address prefix exclusivity | No contract deployed via CREATE/CREATE2/7702 can be at an address starting with `0x20C0...` |
| **P2** | TIP-20 authenticity | All addresses where `isTIP20` returns true were deployed through the TIP-20 factory |
| **P3** | Backwards compatible | Existing contracts are unaffected; only new deployments are checked |

## Test Considerations

Testing requires addresses with the TIP-20 prefix, which is computationally infeasible to find. Test approaches include:

- Mocking the address prefix check in unit tests
- Verifying the check exists in the CREATE/CREATE2/7702 code paths

---

# Backwards Compatibility

This is an execution layer upgrade requiring a hard fork.

Existing contracts are unaffected. The check only applies to new contract deployments after the fork activation block.

---

# Security Considerations

The `isTIP20` invariant is already practically protected by the computational infeasibility of finding a CREATE2 salt that produces an address with the 12-byte TIP-20 prefix. This proposal elevates that protection from infeasible to impossible, ensuring the invariant holds regardless of future advances in computing power.
