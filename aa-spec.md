# Account Abstraction Tx Type

## Abstract

This spec introduces native protocol support for the following account abstraction features, using a new account abstraction tx type - 

* WebAuthn/P256 signature validation - enables passkey accounts
* Parallelizable nonces - allows higher tx throughput for each account
* Gas sponsorship - allows apps to pay for their users's transactions
* Scheduled Txs - allow users to specify a time window in which their tx can be executed

## Motivation

Current accounts are limited to secp256k1 signatures and sequential nonces, creating UX and scalability challenges. Users cannot leverage modern authentication methods like passkeys, applications face throughput limitations due to sequential nonces. This proposal enshrines these features at the protocol level to provide:

- Native support for passkey authentication via P256/WebAuthn signatures
- Parallel transaction execution through 2D nonce system
- Native Gas Sponsorship using fee payers
- Call Batching is supported using the ERC 7821 `execute` interface available in all Default Accounts
- Scheduled Transactions are enabled using the optional `validBefore` and `validAfter` fields in the transaction 

### Transaction Type

A new EIP-2718 transaction type is introduced with the following structure:

```rust
pub struct AATransaction {
    // Standard EIP-1559 fields
    chain_id: U64,
    max_priority_fee_per_gas: U256,
    max_fee_per_gas: U256,
    gas_limit: U64,
    to: Address,             
    value: U256,         
    access_list: Vec<AccessListItem>,

    // AA-specific fields
    data: Bytes,              // ERC-7821 encoded operations for batching
    signature: Bytes,         // Variable length based on type
    nonce_key: U192,          // 192 bit sequence keys
    nonce_sequence: U64       // 64 bit current value of the sequence key

    // Optional features
    fee_payer_signature: Option<Bytes>, // Sponsored transactions
    fee_token: Option<Address>,
    validBefore: Option<U64>,         // Transaction expiration timestamp
    validAfter: Option<U64>          // Transaction can only be included in a block after this timestamp
}
```

### Signature Types

Three signature schemes are supported, identified by length:

#### secp256k1 (65 bytes)
```rust
type K1Sig = { r: bytes32, s: bytes32, v: uint8 }
```

#### P256 (129 bytes)
```rust
type P256Sig = { 
    r: bytes32, 
    s: bytes32, 
    pubKeyX: bytes32, 
    pubKeyY: bytes32, 
    preHash: bool
}
```
Note: Some p256 implementers like Web Crypto, require the digests to be prehashed before verification.
If this bool is set to `true`, then before verification `bytes32 digest = sha256(digest)` needs to be performed.


#### WebAuthn (Variable length, max 2KB)
```rust
type WebAuthnSig = { 
    verificationData: bytes,  // Variable length
    r: bytes32, 
    s: bytes32, 
    pubKeyX: bytes32, 
    pubKeyY: bytes32 
}
```

### Address Derivation

#### secp256k1
```solidity
address(uint160(uint256(keccak256(abi.encode(x, y)))))
```

#### P256 and WebAuthn
```solidity
function deriveAddressFromP256(bytes32 pubKeyX, bytes32 pubKeyY) public pure returns (address) {    
    // Hash 
    bytes32 hash = keccak256(abi.encodePacked(
        pubKeyX,
        pubKeyY
    ));
    
    // Take last 20 bytes as address
    return address(uint160(uint256(hash)));
}
```

### Parallelizable Nonces

The protocol implements 2D nonces without expiry or garbage collection:

- **Protocol nonce (key 0)**: Existing account nonce, incremented for regular txs, 7702 authorization, or `CREATE`
- **User nonces (keys 1-N)**: Enable parallel execution with special gas schedule

#### Account State Changes
- `nonces: mapping(uint192 => uint64)` - 2D nonce tracking
- `num_active_user_keys: uint` - tracks number of user keys for gas calculation

**Implementation Note:** Nonces are stored in the storage of a designated precompile at address `0x4E4F4E4345000000000000000000000000000000` (ASCII hex for "NONCE"), as there is currently no clean way to extend account state in Reth.

**Storage Layout at 0x4E4F4E4345:**
- Storage key: `keccak256(abi.encode(account_address, nonce_key))`
- Storage value: `nonce_sequence` (uint64)
- Active key count for account: stored at `keccak256(abi.encode(account_address, uint192(0)))`

Note: Protocol Nonce key (0), is directly stored in the account state, just like normal transaction types.

#### Gas Schedule

For transactions using nonce keys:

1. If `sequence > 0`: Add 5,000 gas to base cost (21,000)
   - Rationale: Equivalent to a cold SSTORE on a non-zero slot (2,900 base + 2,100 cold access)

2. If `sequence == 0`: Add progressive cost
   ```rust
   let num_active_nonce_keys = count(non_zero_nonce_keys with sequence > 0)
   base_gas_cost = 21_000 + num_active_nonce_keys * 20_000
   ```

This linearly increasing fee compensates for state growth and mitigates DOS vectors from unbounded sequence key creation.
We specify the complete gas schedule in more detail in the [gas costs section](#gas-costs)

### Transaction Validation

#### Signature Validation
1. Determine type from signature length:
   - 65 bytes = secp256k1
   - 129 bytes = P256
   - >129 bytes = WebAuthn
   - Otherwise invalid
2. Apply appropriate verification:
   - K1: Standard `ecrecover`
   - P256: P256 curve verification with provided public key (sha256 pre-hash if flag set)
   - WebAuthn: Parse clientDataJSON, verify challenge and type, then P256 verify

#### Nonce Validation
1. Fetch sequence for given nonce key
2. Verify sequence matches transaction
3. Increment sequence

#### Fee Payer Validation (if present)
1. Verify fee payer signature (K1 only initially)
2. Recover payer address via `ecrecover`
3. Deduct fees from payer instead of sender

### WebAuthn Signature Verification

WebAuthn verification follows the [Daimo P256 verifier approach](https://github.com/daimo-eth/p256-verifier/blob/master/src/WebAuthn.sol).

#### Signature Format

```
signature = authenticatorData || clientDataJSON || r (32) || s (32) || pubKeyX (32) || pubKeyY (32)
```

Parse by working backwards:
- Last 32 bytes: `pubKeyY`
- Previous 32 bytes: `pubKeyX`
- Previous 32 bytes: `s`
- Previous 32 bytes: `r`
- Remaining bytes: `authenticatorData || clientDataJSON` (requires parsing to split)

#### Authenticator Data Structure (minimum 37 bytes)

```
Bytes 0-31:   rpIdHash (32 bytes)
Byte 32:      flags (1 byte)
              - Bit 0 (0x01): User Presence (UP) - must be set
Bytes 33-36:  signCount (4 bytes)
```

#### Verification Steps

```python
def verify_webauthn(tx_hash: bytes32, signature: bytes, require_uv: bool) -> bool:
    # 1. Parse signature
    pubKeyY = signature[-32:]
    pubKeyX = signature[-64:-32]
    s = signature[-96:-64]
    r = signature[-128:-96]
    webauthn_data = signature[:-128]

    # Parse authenticatorData and clientDataJSON
    # Minimum authenticatorData is 37 bytes
    # Simple approach: try to decode clientDataJSON from different split points
    authenticatorData, clientDataJSON = split_webauthn_data(webauthn_data)

    # 2. Validate authenticator data
    if len(authenticatorData) < 37:
        return False

    flags = authenticatorData[32]
    if not (flags & 0x01):  # UP bit must be set
        return False

    # 3. Validate client data JSON
    if not contains(clientDataJSON, '"type":"webauthn.get"'):
        return False

    challenge_b64url = base64url_encode(tx_hash)
    challenge_property = '"challenge":"' + challenge_b64url + '"'
    if not contains(clientDataJSON, challenge_property):
        return False

    # 4. Compute message hash
    clientDataHash = sha256(clientDataJSON)
    messageHash = sha256(authenticatorData || clientDataHash)

    # 5. Verify P256 signature
    return p256_verify(messageHash, r, s, pubKeyX, pubKeyY)
```

#### What We Verify

- Authenticator data minimum length (37 bytes)
- User Presence (UP) flag is set
- `"type":"webauthn.get"` in clientDataJSON
- Challenge matches tx_hash (Base64URL encoded)
- P256 signature validity

#### What We Skip

- Origin verification (not applicable to blockchain)
- RP ID hash validation (no central RP in decentralized context)
- Signature counter (anti-cloning left to application layer)
- Backup flags (account policy decision)

#### Parsing authenticatorData and clientDataJSON

Since authenticatorData has variable length, finding the split point requires:
1. Check if AT flag (bit 6) is set at byte 32
2. If not set, authenticatorData is exactly 37 bytes
3. If set, need to parse CBOR credential data (complex, see implementation)
4. Everything after authenticatorData is clientDataJSON (valid UTF-8 JSON)

**Simplified approach:** For AA transactions, wallets should send minimal authenticatorData (37 bytes, no AT/ED flags) to minimize gas costs and simplify parsing.

## Rationale

### Signature Type Detection by Length
Using signature length for type detection avoids adding explicit type fields while maintaining deterministic parsing. The chosen lengths (65, 129, variable) are naturally distinct.

### Linear Gas Scaling for Nonce Keys
The progressive pricing model prevents state bloat while keeping initial keys affordable. The 20,000 gas increment approximates the long-term state cost of maintaining each additional nonce mapping.

### No Nonce Expiry
Avoiding expiry simplifies the protocol and prevents edge cases where in-flight transactions become invalid. Wallets handle nonce key allocation to prevent conflicts.

## Backwards Compatibility

This spec introduces a new transaction type and does not modify existing transaction processing. Legacy transactions continue to work unchanged. We special case `nonce key = 0` (also referred to as the protocol nonce key) to maintain compatibility with existing nonce behavior.

## Gas Costs

### Signature Verification Gas Schedule

Different signature types incur different base transaction costs to reflect their computational complexity:

| Signature Type | Base Gas Cost | Calculation | Rationale |
|----------------|---------------|-------------|-----------|
| **secp256k1** | 21,000 | Standard | Includes 3,000 gas for ecrecover precompile |
| **P256** | 26,000 | 21,000 + 8,000 - 3,000 | Adds P256 cost (8,000) minus saved ecrecover cost (3,000) |
| **WebAuthn** | 26,000 + variable data cost | 26,000 + (calldata gas for clientDataJSON) | Base P256 cost plus variable cost for clientDataJSON based on size |

**Rationale:**
- The base 21,000 gas for standard transactions already includes the cost of secp256k1 signature verification via ecrecover (3,000 gas)
- [EIP 7951](https://eips.ethereum.org/EIPS/eip-7951) sets P256 verification cost at 6900. We add 1100 gas to this, to account for the additional 65 bytes of signature size as compared to standard ECDSA. 
- WebAuthn signatures require additional computation to parse and validate the clientDataJSON structure. We cap the total signature size at 2kb. The signature is also  charged using the same gas schedule as calldata (16 gas per non-zero byte, 4 gas per zero byte) to prevent the use of this signature space from spam.
- Individual per-signature-type gas costs allow us to add more advanced verification methods in the future like multisigs, which could have dynamic gas pricing.

### Nonce Key Gas Schedule

Transactions using parallelizable nonces incur additional costs based on the nonce key usage pattern:

#### Case 1: Protocol Nonce (Key 0)
- **Additional Cost:** 0 gas
- **Total:** 21,000 gas (base transaction cost)
- **Rationale:** Maintains backward compatibility with existing transaction flow

#### Case 2: Existing User Nonce Key (sequence > 0)
- **Additional Cost:** 5,000 gas
- **Total:** 26,000 gas
- **Rationale:** Equivalent to a cold SSTORE on a non-zero slot (2,900 base + 2,100 cold access)

#### Case 3: New User Nonce Key (sequence == 0)
- **Additional Cost:** Progressive based on active keys
- **Formula:**
  ```
  additional_gas = num_active_nonce_keys * 20,000
  total_base_cost = 21,000 + additional_gas + signature_verification_cost
  ```
- **Examples:**
  - First user key: 21,000 + 0 = 21,000 gas
  - Second user key: 21,000 + 20,000 = 41,000 gas
  - Third user key: 21,000 + 40,000 = 61,000 gas

**Rationale for Progressive Pricing:**
1. **State Growth Compensation:** Each new nonce key adds permanent state that nodes must maintain
2. **DoS Prevention:** Linear cost increase prevents attackers from cheaply creating unbounded nonce keys
3. **Fair Usage:** Users who need higher parallel execution pay proportionally to their state footprint
4. **Storage Pattern Alignment:** Costs mirror actual storage operations (cold vs warm access patterns)

### Reference Pseudocode
```
def calculate_calldata_gas(data: bytes) -> uint256:
    """
    Calculate gas cost for calldata based on zero and non-zero bytes

    Args:
        data: bytes to calculate cost for

    Returns:
        gas_cost: uint256
    """
    CALLDATA_ZERO_BYTE_GAS = 4
    CALLDATA_NONZERO_BYTE_GAS = 16

    gas = 0
    for byte in data:
        if byte == 0:
            gas += CALLDATA_ZERO_BYTE_GAS
        else:
            gas += CALLDATA_NONZERO_BYTE_GAS

    return gas

def calculate_aa_tx_base_gas(tx):
    """
    Calculate the base gas cost for an AA transaction

    Args:
        tx: AA transaction object with fields:
            - signature: bytes (variable length)
            - nonce_key: uint192
            - nonce_sequence: uint64
            - sender_address: address

    Returns:
        total_gas: uint256
    """

    # Constants
    BASE_TX_GAS = 21_000
    P256_VERIFY_GAS = 5_000 
    COLD_SSTORE_GAS = 5_000
    NEW_NONCE_KEY_MULTIPLIER = 20_000

    # Step 1: Determine signature verification cost
    sig_length = len(tx.signature)

    if sig_length == 65:  # secp256k1
        signature_gas = BASE_TX_GAS  # Already includes ecrecover
    elif sig_length == 129:  # P256
        signature_gas = BASE_TX_GAS + P256_VERIFY_GAS
    elif sig_length > 129:  # WebAuthn
        # WebAuthn signature format: webauthn variable data || r (32) || s (32) || pubKeyX (32) || pubKeyY (32)
        # Charge calldata gas for everything except the last 128 bytes (r, s, pubKeyX, pubKeyY)
        webauthn_data = tx.signature[:-128]
        webauthn_data_gas = calculate_calldata_gas(webauthn_data)
        signature_gas = BASE_TX_GAS + P256_VERIFY_GAS + webauthn_data_gas
    else:
        revert("Invalid signature length")

    # Step 2: Calculate nonce key cost
    if tx.nonce_key == 0:
        # Protocol nonce (backward compatible)
        nonce_gas = 0
    else:
        # User nonce key
        current_sequence = get_nonce(tx.sender_address, tx.nonce_key)

        if current_sequence > 0:
            # Existing nonce key
            nonce_gas = COLD_SSTORE_GAS
        else:
            # New nonce key - progressive pricing
            num_active_keys = num_active_user_keys(tx.sender_address)
            nonce_gas = num_active_keys * NEW_NONCE_KEY_MULTIPLIER

    # Step 3: Calculate total base gas
    total_gas = signature_gas + nonce_gas

    return total_gas
```

## Security Considerations


### Mempool DOS Protection

Transaction pools perform pre-execution validation checks before accepting transactions. These checks are performed for free by the nodes, making them potential DOS vectors. The three primary validation checks are:

1. **Signature verification** - Must be valid
2. **Nonce verification** - Must match current account nonce
3. **Balance check** - Account must have sufficient balance to pay for transaction

This transaction type impacts all three areas:

#### Signature Verification Impact
- **P256 signatures**: Fixed computational cost similar to ecrecover.
- **WebAuthn signatures**: Variable cost due to clientDataJSON parsing, but **capped at 2KB total signature size** to prevent abuse
- **Mitigation**: All signature types have bounded computational costs that are in the same ballpark as standard ecrecover.

#### Nonce Verification Impact
- **2D nonce lookup**: Requires additional storage read from nonce precompile
- **Cost**: Equivalent to a cold SLOAD (~2,100 gas worth of free computation)
- **Mitigation**: Cost is bounded to a manageable value.

#### Fee Payer Impact
- **Additional account read**: When fee payer is specified, must fetch fee payer's account to verify balance
- **Cost**: Effectively doubles the free account access work for sponsored transactions
- **Mitigation**: Cost is still bounded to a single additional account read.

#### Comparison to Ethereum

The introduction of 7702 delegated accounts already created complex cross-transaction dependencies in the mempool, which prevents any static pool checks from being useful.
Because a single transaction can invalidate multiple others by spending balances of multiple accounts

**Assessment:** While this transaction type introduces additional pre-execution validation costs, all costs are bounded to reasonable limits. The mempool complexity issues around cross-transaction dependencies already exist in Ethereum due to 7702 and accounts with code, making static validation inherently difficult. So the incremental cost from this transaction type is acceptable given these existing constraints.

### State Growth and Nonce Garbage Collection

The 2D nonce system introduces some state growth concerns, as each account can create a large number of nonce keys. One discussed solution to this has been garbage collection of nonces after transaction expiry. 
Current spec makes an *intentionally excludes garbage collection** for nonces.

#### Rationale for Excluding Garbage Collection

1. **Not Valuable in Isolation**
In the current implementation, each new nonce is stored in a precompile storage. So nonce state, growth is the exact same problem as general state growth.
So it is not valuable to enshrine a partial solution just for nonces, until we solve the broader state growth problem.

2. **Progressive Gas Model Addresses State Growth**
The linearly increasing gas cost model provides economic pressure against state bloat:
     - 1st new sequence key: 20,000 gas
     - 2nd new sequence key: 40,000 gas
     - Nth new sequence key: N × 20,000 gas
This creates a **practical economic limit** on the number of sequence keys per account. We can also introduce a protocol limit of 32 or 64 nonce keys for each account.

3. **Technical Complexity with Nonce Keys**
It is unclear how garbage collection would work safely with sequence-based nonces
Example: If a nonce key is at sequence X and a wallet signs for X+1, but X gets garbage collected before submission, the transaction with X+1 would fail unexpectedly

4. **Future Extensibility**
The specification includes an optional `validBefore` field in the transaction structure
If garbage collection becomes necessary, this field can be made mandatory

#### State Growth Analysis

**Worst Case Scenario:**
- An attacker willing to pay increasing gas costs could create many nonce keys
- However, the linear cost model makes this economically prohibitive at scale
- Example: Creating 100 nonce keys would require cumulative gas costs of ~5,000,000 gas just for the nonce key creation


**Practical Usage:**
- Most users will use 1-5 parallel nonce keys for typical parallel transaction patterns
- Power users requiring higher parallelism will pay proportionally

### RLP Encoding Safety
Care must be taken to ensure unique RLP encoding for all valid transaction configurations, particularly around optional fields. The encoding must be unambiguous to prevent transaction malleability.
