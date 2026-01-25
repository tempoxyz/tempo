# Message Format Specification

This document defines the canonical message format used for BLS threshold attestations.

## Overview

Validators sign an **attestation** that binds the message hash to its cross-chain context. This document specifies:
- The attestation structure validators sign
- Domain separation for replay protection
- BLS signing conventions
- Implementation in Rust and Solidity

## Attestation Structure

### What Validators Sign

When a `MessageSent` event is observed, validators sign an attestation containing:

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `domain` | bytes | 15 | Fixed: `"TEMPO_BRIDGE_V1"` |
| `sender` | address | 20 | Original sender on source chain |
| `messageHash` | bytes32 | 32 | The 32-byte payload hash |
| `originChainId` | uint64 | 8 | Source chain ID |
| `destinationChainId` | uint64 | 8 | Destination chain ID |

**Total encoded length**: 83 bytes (before hashing)

### Attestation Hash Computation

```
attestationHash = keccak256(abi.encodePacked(
    "TEMPO_BRIDGE_V1",    // 15 bytes - domain separator
    sender,               // 20 bytes (address)
    messageHash,          // 32 bytes
    originChainId,        // 8 bytes (uint64)
    destinationChainId    // 8 bytes (uint64)
))
```

## Replay Protection

The attestation structure prevents various replay attacks:

| Attack Vector | Prevention |
|---------------|------------|
| Cross-chain replay | `originChainId` and `destinationChainId` bound in signature |
| Sender spoofing | `sender` bound in signature |
| Protocol confusion | Domain prefix `"TEMPO_BRIDGE_V1"` |
| Duplicate send | Origin chain checks `sent[sender][hash]` |
| Duplicate write | Destination checks `received[origin][sender][hash]` |

## BLS Threshold Signatures

### Signing Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           BLS Threshold Signing                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   MessageSent(sender, messageHash, destChainId) observed on origin chain    │
│                                                                              │
│   attestationHash = keccak256(domain || sender || hash || origin || dest)   │
│                                                                              │
│   H(m) = hash_to_curve(attestationHash, DST)  →  point in G2                │
│                                                                              │
│   Validator i:  σᵢ = skᵢ · H(m)     (partial signature)                     │
│                                                                              │
│   Aggregator:   σ = Σ λᵢ · σᵢ      (Lagrange interpolation, t-of-n)         │
│                     i∈S                                                      │
│                                                                              │
│   On-chain:     e(PK, H(m)) == e(G1, σ)  (BLS verification)                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### BLS Domain Separation Tag

```
DST = "TEMPO_BRIDGE_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_"
```

### Signature Format

| Format | Size | Use |
|--------|------|-----|
| Compressed G1 (public key) | 48 bytes | Off-chain transmission |
| Uncompressed G1 (public key) | 128 bytes | On-chain storage (EIP-2537 format) |
| Compressed G2 (signature) | 96 bytes | Off-chain transmission |
| Uncompressed G2 (signature) | 256 bytes | On-chain verification (EIP-2537 format) |

## Rust Implementation

```rust
use alloy_primitives::{keccak256, Address, B256};

pub const BRIDGE_DOMAIN: &[u8] = b"TEMPO_BRIDGE_V1";
pub const BLS_DST: &[u8] = b"TEMPO_BRIDGE_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_";

/// Message data extracted from MessageSent event
#[derive(Debug, Clone)]
pub struct Message {
    pub sender: Address,
    pub message_hash: B256,
    pub origin_chain_id: u64,
    pub destination_chain_id: u64,
}

impl Message {
    /// Compute the attestation hash that validators sign
    pub fn attestation_hash(&self) -> B256 {
        let mut data = Vec::with_capacity(83);
        
        // Domain separator (15 bytes)
        data.extend_from_slice(BRIDGE_DOMAIN);
        
        // Sender (20 bytes)
        data.extend_from_slice(self.sender.as_slice());
        
        // Message hash (32 bytes)
        data.extend_from_slice(self.message_hash.as_slice());
        
        // Chain IDs (8 bytes each)
        data.extend_from_slice(&self.origin_chain_id.to_be_bytes());
        data.extend_from_slice(&self.destination_chain_id.to_be_bytes());
        
        keccak256(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_attestation_hash_deterministic() {
        let msg = Message {
            sender: Address::repeat_byte(0xAA),
            message_hash: B256::repeat_byte(0x11),
            origin_chain_id: 1,
            destination_chain_id: 12345,
        };
        
        let hash1 = msg.attestation_hash();
        let hash2 = msg.attestation_hash();
        assert_eq!(hash1, hash2);
    }
    
    #[test]
    fn test_different_sender_different_hash() {
        let msg1 = Message {
            sender: Address::repeat_byte(0xAA),
            message_hash: B256::repeat_byte(0x11),
            origin_chain_id: 1,
            destination_chain_id: 12345,
        };
        let msg2 = Message {
            sender: Address::repeat_byte(0xBB),
            ..msg1.clone()
        };
        
        assert_ne!(msg1.attestation_hash(), msg2.attestation_hash());
    }
    
    #[test]
    fn test_different_direction_different_hash() {
        let msg1 = Message {
            sender: Address::repeat_byte(0xAA),
            message_hash: B256::repeat_byte(0x11),
            origin_chain_id: 1,
            destination_chain_id: 12345,
        };
        let msg2 = Message {
            origin_chain_id: 12345,
            destination_chain_id: 1,
            ..msg1.clone()
        };
        
        assert_ne!(msg1.attestation_hash(), msg2.attestation_hash());
    }
}
```

## Solidity Implementation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library MessageFormat {
    bytes constant DOMAIN = "TEMPO_BRIDGE_V1";
    
    /// @notice Compute the attestation hash that validators sign
    /// @param sender The original sender on source chain
    /// @param messageHash The message hash
    /// @param originChainId The source chain ID
    /// @param destinationChainId The destination chain ID
    function computeAttestationHash(
        address sender,
        bytes32 messageHash,
        uint64 originChainId,
        uint64 destinationChainId
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            DOMAIN,
            sender,
            messageHash,
            originChainId,
            destinationChainId
        ));
    }
}
```

## Test Vectors

### Test Vector 1: Ethereum to Tempo

**Input:**
```
sender:             0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
messageHash:        0x1111111111111111111111111111111111111111111111111111111111111111
originChainId:      1
destinationChainId: 12345
```

**Expected attestationHash:**
```
keccak256(
    "TEMPO_BRIDGE_V1" ||
    0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ||
    0x1111111111111111111111111111111111111111111111111111111111111111 ||
    0x0000000000000001 ||
    0x0000000000003039
)
```

### Test Vector 2: Tempo to Ethereum

**Input:**
```
sender:             0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
messageHash:        0x2222222222222222222222222222222222222222222222222222222222222222
originChainId:      12345
destinationChainId: 1
```

## Invariants

1. **Determinism**: Same inputs always produce same attestation hash
2. **Uniqueness**: Different inputs produce different attestation hashes
3. **Parity**: Rust and Solidity implementations produce identical results
4. **Domain Isolation**: Attestation hashes are unique to this protocol

## References

- [EIP-2537: BLS12-381 Precompiles](https://eips.ethereum.org/EIPS/eip-2537)
- [RFC 9380: Hashing to Elliptic Curves](https://www.rfc-editor.org/rfc/rfc9380)
