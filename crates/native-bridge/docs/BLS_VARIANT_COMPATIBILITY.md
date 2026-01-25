# BLS12-381 Variant: MinSig (Consensus-Compatible)

## Summary

The Tempo native bridge uses the **MinSig** BLS12-381 variant, which is the same variant used by the consensus system. This allows validators to **reuse their existing DKG shares** for bridge signing without requiring a separate DKG ceremony.

| Component | Group | Size (Compressed) | Size (EIP-2537) |
|-----------|-------|-------------------|-----------------|
| **Public Keys** | G2 | 96 bytes | 256 bytes |
| **Signatures** | G1 | 48 bytes | 128 bytes |
| **Hash-to-Curve** | G1 | - | - |

---

## Why MinSig?

### Consensus Compatibility

The Tempo consensus system uses MinSig:
- DKG produces `Sharing<MinSig>` with polynomial coefficients on G2
- Group public key: G2 point (96 bytes compressed)
- Validator partial public keys: G2 points
- Signatures: G1 points (48 bytes compressed)

By using MinSig for the bridge, validators can sign bridge messages using the **same private key share** they use for consensus, without any conversion or separate key management.

### Trade-offs

| Aspect | MinSig (Our Choice) | MinPk (Alternative) |
|--------|---------------------|---------------------|
| Public key size | 256 bytes (EIP-2537) | 128 bytes (EIP-2537) |
| Signature size | 128 bytes (EIP-2537) | 256 bytes (EIP-2537) |
| Share reuse | ✅ Same as consensus | ❌ Requires separate DKG |
| On-chain storage | Larger pubkey | Larger signature |

We chose MinSig because **share reuse** eliminates operational complexity and security risks of managing multiple key sets.

---

## Implementation Details

### Domain Separation Tag (DST)

The bridge uses a DST that indicates G1 hash-to-curve:

```
TEMPO_BRIDGE_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_
```

This follows RFC 9380 conventions where:
- `G1` indicates the target curve for hash-to-curve
- `XMD:SHA-256` indicates expand_message_xmd with SHA-256
- `SSWU_RO_` indicates Simplified SWU map with random oracle security

### Rust Implementation

```rust
// crates/native-bridge/src/signer.rs
use commonware_cryptography::bls12381::primitives::variant::MinSig;

pub fn sign_partial(&self, attestation_hash: B256) -> Result<PartialSignature> {
    let signature: G1 = sign::<MinSig>(&self.share.private, BLS_DST, attestation_hash.as_slice());
    // Returns G1 signature (48 bytes compressed)
}

pub fn public_key(&self) -> G2 {
    self.share.public::<MinSig>()  // G2 point
}
```

### Solidity Implementation

The bridge contract uses [randa-mu/bls-solidity](https://github.com/randa-mu/bls-solidity) for signature verification:

```solidity
// BLS12381.sol wraps the bls-solidity library
import {BLS2} from "bls-solidity/src/libraries/BLS2.sol";

function verify(
    bytes memory publicKey,    // G2, 256 bytes EIP-2537
    bytes memory message,
    bytes memory dst,
    bytes memory signature     // G1, 128 bytes EIP-2537
) internal view returns (bool) {
    // Convert from EIP-2537 padded format to BLS2 compact format
    bytes memory sig96 = _g1FromEip2537(signature);
    bytes memory pk192 = _g2FromEip2537(publicKey);
    
    // Use BLS2 library for verification
    BLS2.PointG1 memory sig = BLS2.g1Unmarshal(sig96);
    BLS2.PointG2 memory pk = BLS2.g2Unmarshal(pk192);
    BLS2.PointG1 memory hm = BLS2.hashToPoint(dst, message);
    
    (bool pairingSuccess, bool callSuccess) = BLS2.verifySingle(sig, pk, hm);
    return callSuccess && pairingSuccess;
}
```

### Format Conversion

EIP-2537 uses padded field elements (64 bytes each with 16-byte zero padding), while the bls-solidity library uses compact format (48-byte field elements):

| Format | G1 | G2 |
|--------|----|----|
| Compressed | 48 bytes | 96 bytes |
| EIP-2537 (padded) | 128 bytes | 256 bytes |
| bls-solidity (compact) | 96 bytes | 192 bytes |

The BLS12381.sol wrapper handles conversion between EIP-2537 format (used in our Rust code) and bls-solidity format.

---

## Verification Equation

For MinSig variant, the pairing check equation is:

```
e(sig, G2_generator) = e(H(m), pk)
```

Or equivalently (for multi-pairing):

```
e(sig, -G2_generator) × e(H(m), pk) = 1
```

Where:
- `sig` ∈ G1 (the signature)
- `pk` ∈ G2 (the public key)
- `H(m)` ∈ G1 (message hashed to G1)
- `e` is the pairing function

---

## Security Considerations

### Point at Infinity Rejection

Both Rust and Solidity implementations reject the point at infinity for public keys and signatures to prevent trivial forgery attacks.

### DST Uniqueness

The DST `TEMPO_BRIDGE_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_` is unique to the bridge and different from any other Tempo signing context, ensuring domain separation.

---

## References

- [EIP-2537: BLS12-381 Precompiles](https://eips.ethereum.org/EIPS/eip-2537)
- [RFC 9380: Hashing to Elliptic Curves](https://www.rfc-editor.org/rfc/rfc9380)
- [BLS Signatures Draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature)
- [randa-mu/bls-solidity](https://github.com/randa-mu/bls-solidity)
- [Commonware Cryptography Library](https://github.com/commonwarexyz/monorepo)
