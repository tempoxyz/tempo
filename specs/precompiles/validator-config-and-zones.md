# Validator configuration, current committee and Zones

This chapter specifies the Tempo system precompiles and protocol-managed accounts that hold consensus-validator configuration and Tempo Zones state:

| Component | Address | Kind | Active from |
|---|---|---|---|
| ValidatorConfig (V1) | `0xCCCCCCCC00000000000000000000000000000000` | native precompile | Genesis (mainnet: T0) |
| ValidatorConfigV2 | `0xCCCCCCCC00000000000000000000000000000001` | native precompile | dispatched from Genesis; functional from T2 |
| CurrentCommittee | `0xC077E00000000000000000000000000000000000` | native precompile | T8 |
| ZoneFactory | `0x5AF2000000000000000000000000000000000000` | native precompile | T10 |
| ZonePortal implementation | `0x5AD1000000000000000000000000000000000000` | protocol-installed EVM runtime | T10 (replaced at T13) |
| ZoneMessenger | `0x5A4D000000000000000000000000000000000000` | protocol-installed EVM runtime | T10 (replaced at T13) |
| ZoneVerifier | `0x5A56000000000000000000000000000000000000` | EVM stub T10–T12; native precompile from T13 | T10 / T13 |
| ZonePortal proxies | `0x5AD0000000000000000000` ‖ `uint64(zoneId)` | ERC-1167 proxy written by `createZone` | T10 |

"Fork F active" means `header.timestamp >= activation_time(F)`, as defined in 01-chain-and-forks.md. "From F:" rules apply exactly when F is active; "Before F:" rules apply exactly when it is not. T14 and later forks are out of scope; where the reference implementation already contains T14/T15 code paths this chapter states that they are unreachable at or below T13.

## 0. Conventions

### 0.1 Shared precompile rules

Unless this chapter says otherwise, every native precompile here follows precompiles/00-framework.md:

- the input charge is taken first (`ceil(len(calldata)/32) * 6` gas before T11, `* 30` from T11); running out of gas is an exceptional halt;
- selector routing, `UnknownFunctionSelector(bytes4)` (selector `0xaa4bc69a`) for unknown or not-yet-scheduled selectors, empty revert data for malformed arguments, and the per-fork ABI decoder strictness;
- the gas of every storage read/write (including TIP-1000 pricing and TIP-1016 state gas where active), of account-info reads and of every emitted log;
- static-context rules (a write or log inside a static call fails as the framework specifies), and the `DELEGATECALL`/`CALLCODE` rejection;
- Solidity-ABI revert encoding of the custom errors listed here, and `Panic(uint256)` (selector `0x4e487b71`) with code `0x11` for arithmetic over/underflow and `0x32` for array out-of-bounds.

Errors listed for a function are checked in the order given. Writes listed for a function are performed in the order given; the order is normative because it determines warm/cold and new-slot pricing of later writes to the same slot. A function that reverts leaves no state change but keeps the gas already consumed.

None of these precompiles charges gas for computation (signature checks, parsing, hashing) except where a section states an explicit charge.

### 0.2 Storage notation

Storage layouts follow Solidity's layout rules exactly (precompiles/00-framework.md): fields are assigned slots in declaration order, a value type packs into the current slot when it fits (starting at the least-significant byte), structs, dynamic arrays, mappings and strings start a new slot and the next field starts a new slot after them.

- `p(x)`: `x` left-padded to 32 bytes (addresses, integers, `bytes32` as-is).
- Mapping `m` at slot `s`: `m[k]` lives at `keccak256(p(k) ‖ p(s))`.
- Dynamic array at slot `s`: length at `s`; element `i` at `keccak256(p(s)) + i * slotsPerElement`; elements of at most 16 bytes pack `floor(32/size)` per slot (element `i` in slot `keccak256(p(s)) + floor(i / perSlot)` at byte offset `size * (i mod perSlot)`).
- `string`: Solidity short/long string encoding.
- "bits a..b" of a slot count from the least-significant bit (bit 0).

### 0.3 Endpoint text grammar

Validator endpoints are ASCII strings parsed with the grammar of the Rust standard library (toolchain 1.96) `FromStr` implementations:

- `SocketAddr` ("`<ip>:<port>`"): either `a.b.c.d:port` (IPv4 dotted-quad, each octet 1–3 decimal digits with value ≤ 255 and no leading zero unless the octet is exactly `0`) or `[ipv6]:port` / `[ipv6%scope]:port` (RFC 4291 text form inside brackets, with optional `::` compression and optional trailing dotted-quad; `scope` a decimal `u32`); `port` is a decimal `u16`. No hostnames, no whitespace.
- `IpAddr` ("`<ip>`"): an IPv4 dotted quad or an unbracketed IPv6 address (no scope id, no port).

For any corner case not covered by this summary, acceptance is defined by Rust 1.96 `core::net::SocketAddr::from_str` and `core::net::IpAddr::from_str`.

## 1. ValidatorConfig (V1)

Reference implementation: crates/precompiles/src/validator_config/mod.rs, crates/precompiles/src/validator_config/dispatch.rs, crates/contracts/src/precompiles/validator_config.rs, crates/precompiles/src/ip.rs.

V1 is the original validator registry. Its account, owner and initial validators come from the genesis allocation (04-state-and-genesis.md). It stays callable at every fork up to T13 and its state persists; from T2 it is the migration source for ValidatorConfigV2 (§2.7). Consensus at this protocol version does not read V1 (§2.9).

V1 emits **no events**.

### 1.1 Storage layout

| Slot | Field | Type |
|---|---|---|
| 0 | `owner` | `address` (bits 0..159) |
| 1 | `validatorsArray` | `address[]` (one element per slot) |
| 2 | `validators` | `mapping(address => Validator)` |
| 3 | `nextDkgCeremony` | `uint64` (bits 0..63) |

`Validator` record (4 slots, base `b = keccak256(p(addr) ‖ p(2))`):

| Slot | Field(s) |
|---|---|
| `b+0` | `publicKey` (`bytes32`) |
| `b+1` | `active` (`bool`, bits 0..7) · `index` (`uint64`, bits 8..71) · `validatorAddress` (`address`, bits 72..231) |
| `b+2` | `inboundAddress` (`string`) |
| `b+3` | `outboundAddress` (`string`) |

A validator "exists" at `addr` iff `validators[addr].publicKey != 0`.

### 1.2 ABI

```solidity
interface IValidatorConfig {
    struct Validator {
        bytes32 publicKey;
        bool active;
        uint64 index;
        address validatorAddress;
        string inboundAddress;
        string outboundAddress;
    }
    function getValidators() external view returns (Validator[] memory);                // 0xb7ab4db5
    function addValidator(address newValidatorAddress, bytes32 publicKey, bool active,
        string calldata inboundAddress, string calldata outboundAddress) external;         // 0xffb4822e
    function updateValidator(address newValidatorAddress, bytes32 publicKey,
        string calldata inboundAddress, string calldata outboundAddress) external;         // 0x09970c76
    function changeValidatorStatus(address validator, bool active) external;            // 0xa1b3f4a9
    function changeValidatorStatusByIndex(uint64 index, bool active) external;          // 0x5aa3d0e1 (from T1)
    function owner() external view returns (address);                                   // 0x8da5cb5b
    function changeOwner(address newOwner) external;                                    // 0xa6f9dae1
    function getNextFullDkgCeremony() external view returns (uint64);                   // 0x281a69ec
    function setNextFullDkgCeremony(uint64 epoch) external;                             // 0xc3576d46
    function validatorsArray(uint256 index) external view returns (address);            // 0x031fadbd
    function validators(address validator) external view returns (Validator memory);    // 0xfa52c7d8
    function validatorCount() external view returns (uint64);                           // 0x0f43a677

    error Unauthorized();                                                  // 0x82b42900
    error ValidatorAlreadyExists();                                        // 0x8d09a73e
    error ValidatorNotFound();                                             // 0x580e542f
    error InvalidPublicKey();                                              // 0xa2d0fee8
    error NotHostPort(string field, string input, string backtrace);       // 0xad764df2
    error NotIpPort(string field, string input, string backtrace);         // 0x89ac2be7
}
```

Before T1, `changeValidatorStatusByIndex` is not scheduled and reverts `UnknownFunctionSelector(0x5aa3d0e1)`.

### 1.3 Endpoint validation and error text

Both `inboundAddress` and `outboundAddress` MUST parse as `SocketAddr` (§0.3). (Despite the `<hostname|ip>` wording in older interface comments, hostnames are rejected.) On failure the call reverts with:

- inbound: `NotHostPort("inboundAddress", inboundAddress, detail)`
- outbound: `NotIpPort("outboundAddress", outboundAddress, detail)`

where `detail` is:

- From T2: the 39-byte ASCII string `` input was not of the form `<ip>:<port>` `` (the code span's surrounding spaces are not part of the string).
- Before T2: the string `Parse(AddrParseError(Socket))` (29 bytes; the Rust `Debug` rendering of the parse error).

Inbound is validated before outbound. Revert data length affects only callers' gas (`RETURNDATASIZE`, copy and memory costs), never state.

### 1.4 Function semantics

```python
def check_owner(sender):
    if sender != sload(0).owner: revert Unauthorized()

def owner() -> address: return owner
def validatorCount() -> uint64: return len(validatorsArray)
def getNextFullDkgCeremony() -> uint64: return nextDkgCeremony

def validatorsArray(index: uint256) -> address:
    if index >= 2**64 or index >= len(validatorsArray): revert Panic(0x32)
    return validatorsArray[index]

def validators(addr) -> Validator:
    # returns the stored record verbatim, all-zero if absent
    return validators[addr]

def getValidators() -> Validator[]:
    out = []
    for i in range(len(validatorsArray)):
        a = validatorsArray[i]
        r = validators[a]
        out.append(Validator(r.publicKey, r.active, r.index, a, r.inboundAddress, r.outboundAddress))
    return out

def addValidator(sender, newAddr, publicKey, active, inbound, outbound):
    if publicKey == 0: revert InvalidPublicKey()
    check_owner(sender)
    if validators[newAddr].publicKey != 0: revert ValidatorAlreadyExists()
    validate_endpoints(inbound, outbound)            # §1.3
    validators[newAddr] = Validator(publicKey, active, index=len(validatorsArray),
                                    validatorAddress=newAddr, inbound, outbound)
    validatorsArray.push(newAddr)

def updateValidator(sender, newAddr, publicKey, inbound, outbound):
    if publicKey == 0: revert InvalidPublicKey()
    if validators[sender].publicKey == 0: revert ValidatorNotFound()
    old = validators[sender]
    if newAddr != sender:
        if validators[newAddr].publicKey != 0: revert ValidatorAlreadyExists()
        validatorsArray[old.index] = newAddr
        delete validators[sender]                     # clears all 4 slots incl. long-string data
    validate_endpoints(inbound, outbound)            # §1.3 (after the rotation writes)
    validators[newAddr] = Validator(publicKey, old.active, old.index, newAddr, inbound, outbound)

def changeValidatorStatus(sender, addr, active):
    check_owner(sender)
    if validators[addr].publicKey == 0: revert ValidatorNotFound()
    r = validators[addr]; r.active = active
    validators[addr] = r                              # full-record write

def changeValidatorStatusByIndex(sender, index, active):   # from T1
    check_owner(sender)
    if index >= len(validatorsArray): revert ValidatorNotFound()
    a = validatorsArray[index]
    r = validators[a]; r.active = active
    validators[a] = r                                 # full-record write

def changeOwner(sender, newOwner):
    check_owner(sender); owner = newOwner             # zero allowed

def setNextFullDkgCeremony(sender, epoch):
    check_owner(sender); nextDkgCeremony = epoch
```

Notes (normative): V1 does not enforce public-key uniqueness, does not reject a zero `newValidatorAddress`, never shrinks `validatorsArray`, and `updateValidator` is authorised by the record at `msg.sender` only (the owner has no special right there). "Full-record write" stores every field of the struct in field order, as the framework's struct write defines.

## 2. ValidatorConfigV2 (TIP-1017)

Reference implementation: crates/precompiles/src/validator_config_v2/mod.rs, crates/precompiles/src/validator_config_v2/dispatch.rs, crates/contracts/src/precompiles/validator_config_v2.rs, crates/precompiles/src/ip.rs, crates/evm/src/block.rs (`deploy_precompile_at_boundary`).

### 2.1 Activation

- The address `0xCCCCCCCC00000000000000000000000000000001` is routed to the native precompile at every fork (it is listed as a Genesis system precompile), regardless of the account's code.
- Before T2: a call MUST charge the input cost (§0.1) and then return success with empty return data, without decoding the selector, reading or writing storage. (This differs from calling an empty account: the input charge applies.)
- At the start of every block from T2, before any transaction, if the account at this address has empty code (code hash `0xc5d2…a470` = `keccak256("")`, or the account does not exist), the executor MUST set its code to the single byte `0xEF`, keeping its balance and nonce (a non-existent account is created with nonce 0 and balance 0) and writing no storage. This is idempotent: after the first T2 block the condition is false. The step's position among the other pre-block steps is defined in 05-block-execution.md. Mainnet genesis contains no account at this address, so the marker is written in the first T2 block.
- From T2, calls dispatch per §2.3. The storage is all-zero at T2 activation (owner `0`, not initialized), so every function except the views, `deactivateValidator` (which finds no validators), `migrateValidator` and `initializeIfMigrated` reverts `NotInitialized()` until migration completes (§2.7).

### 2.2 Storage layout

| Slot | Field | Type |
|---|---|---|
| 0 | `config` | packed: `owner` (bits 0..159) · `isInit` (bool, bits 160..167) · `initAtHeight` (uint64, bits 168..231) · `migrationSkippedCount` (uint8, bits 232..239) · `v1ValidatorCount` (uint8, bits 240..247) |
| 1 | `validators` | `ValidatorRecord[]` (6 slots per element) |
| 2 | `addressToIndex` | `mapping(address => uint64)`, 1-based index into `validators`, 0 = none |
| 3 | `pubkeyToIndex` | `mapping(bytes32 => uint64)`, 1-based, 0 = none |
| 4 | `nextNetworkIdentityRotationEpoch` | `uint64` |
| 5 | `activeIngressIps` | `mapping(bytes32 => bool)` keyed by `ingressKey` (§2.4.3) |
| 6 | `activeIndices` | `uint64[]` (4 per slot), each a 1-based index into `validators` |

`ValidatorRecord` element `i` (base `b = keccak256(p(1)) + 6*i`):

| Slot | Field(s) |
|---|---|
| `b+0` | `publicKey` (`bytes32`) |
| `b+1` | `validatorAddress` (bits 0..159) |
| `b+2` | `ingress` (`string`) |
| `b+3` | `egress` (`string`) |
| `b+4` | `feeRecipient` (bits 0..159) · `index` (uint64, bits 160..223) |
| `b+5` | `activeIdx` (uint64, bits 0..63; 1-based position in `activeIndices`, 0 = inactive) · `addedAtHeight` (uint64, bits 64..127) · `deactivatedAtHeight` (uint64, bits 128..191; 0 = active) |

`activeIdx` is internal (not returned by any function). Invariant: a record is active iff `deactivatedAtHeight == 0` iff `activeIdx != 0`, and then `activeIndices[activeIdx-1] == index+1`.

### 2.3 ABI

```solidity
interface IValidatorConfigV2 {
    struct Validator {             // field order is normative for ABI encoding
        bytes32 publicKey;
        address validatorAddress;
        string ingress;
        string egress;
        address feeRecipient;
        uint64 index;
        uint64 addedAtHeight;
        uint64 deactivatedAtHeight;
    }
    // views
    function getActiveValidators() external view returns (Validator[] memory);                 // 0x9de70258
    function getInitializedAtHeight() external view returns (uint64);                          // 0xf926b083
    function owner() external view returns (address);                                          // 0x8da5cb5b
    function validatorCount() external view returns (uint64);                                  // 0x0f43a677
    function validatorByIndex(uint64 index) external view returns (Validator memory);          // 0xecb14a34
    function validatorByAddress(address validatorAddress) external view returns (Validator memory); // 0x1a6dda94
    function validatorByPublicKey(bytes32 publicKey) external view returns (Validator memory); // 0x1b425d5e
    function getNextNetworkIdentityRotationEpoch() external view returns (uint64);             // 0x42739f79
    function isInitialized() external view returns (bool);                                     // 0x392e53cd
    // mutators
    function addValidator(address validatorAddress, bytes32 publicKey, string calldata ingress,
        string calldata egress, address feeRecipient, bytes calldata signature)
        external returns (uint64 index);                                                       // 0x6dcf616a
    function deactivateValidator(uint64 idx) external;                                         // 0x8f289544
    function rotateValidator(uint64 idx, bytes32 publicKey, string calldata ingress,
        string calldata egress, bytes calldata signature) external;                            // 0x82f20dbe
    function setFeeRecipient(uint64 idx, address feeRecipient) external;                       // 0x572e4068
    function setIpAddresses(uint64 idx, string calldata ingress, string calldata egress) external; // 0x55f25dc6
    function transferValidatorOwnership(uint64 idx, address newAddress) external;              // 0x9e38a5f1
    function transferOwnership(address newOwner) external;                                     // 0xf2fde38b
    function setNetworkIdentityRotationEpoch(uint64 epoch) external;                           // 0xcb8425d2
    function migrateValidator(uint64 idx) external;                                            // 0xc8e73200
    function initializeIfMigrated() external;                                                  // 0x2f88bb4f
}
```

> **Resolved conflict C-VAL-01**: TIP-1017 orders the `Validator` struct `…, egress, index, addedAtHeight, deactivatedAtHeight, feeRecipient`; the code returns `…, egress, feeRecipient, index, addedAtHeight, deactivatedAtHeight`. Decided: this spec follows the implementation, and the TIP is amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939). See [conflicts](../conflicts.md#c-val-01).

> **Resolved conflict C-VAL-02**: TIP-1017 names the rotation-epoch functions `getNextFullDkgCeremony()` / `setNextFullDkgCeremony(uint64)` (selectors `0x281a69ec` / `0xc3576d46`); the code exposes only `getNextNetworkIdentityRotationEpoch()` / `setNetworkIdentityRotationEpoch(uint64)`, so the TIP selectors revert `UnknownFunctionSelector` on V2. Decided: this spec follows the implementation, and the TIP is amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939). See [conflicts](../conflicts.md#c-val-02).

Events (emitted at the V2 address; `indexed` fields are topics in declaration order after topic0):

| Event | topic0 |
|---|---|
| `ValidatorAdded(uint64 indexed index, address indexed validatorAddress, bytes32 publicKey, string ingress, string egress, address feeRecipient)` | `0x2f013b45d5e1f23545bf878cd3fd902f5a327541c96f83fc826a2d9bb25d79a1` |
| `ValidatorDeactivated(uint64 indexed index, address indexed validatorAddress)` | `0x67d2695de7744d47781e04f4e6e3c98540bd3efdf5eba283c32734701cf0d240` |
| `ValidatorRotated(uint64 indexed index, uint64 indexed deactivatedIndex, address indexed validatorAddress, bytes32 oldPublicKey, bytes32 newPublicKey, string ingress, string egress, address caller)` | `0x1068b9f6c5935b37af967e63040bf1a8540171c0bd0255180625784b00f5dd3b` |
| `FeeRecipientUpdated(uint64 indexed index, address feeRecipient, address caller)` | `0x22b6921469e5c41d4013782fda1738d3f501be71802a08377c25987f0a2a68c0` |
| `IpAddressesUpdated(uint64 indexed index, string ingress, string egress, address caller)` | `0x241dec1e5ad7db0fa5d3d80c9fb8362e665dd623a4453decff244990e5db64b4` |
| `ValidatorOwnershipTransferred(uint64 indexed index, address indexed oldAddress, address indexed newAddress, address caller)` | `0x424eaa11c8177b4916856bb34ad6fb8843c76b6c3a3ef340925dc733e3203fac` |
| `OwnershipTransferred(address indexed oldOwner, address indexed newOwner)` | `0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0` |
| `ValidatorMigrated(uint64 indexed index, address indexed validatorAddress, bytes32 publicKey)` | `0x2e1e3dd2e695e031b81bb15d615eed5ff5ccd3f3334a6181e52dc878473b859c` |
| `NetworkIdentityRotationEpochSet(uint64 indexed previousEpoch, uint64 indexed nextEpoch)` | `0x713bea732fe97c115b54c1b99ac96d7439806000ff4970322cc60f240180e3d0` |
| `Initialized(uint64 height)` | `0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2` |
| `SkippedValidatorMigration(uint64 indexed index, address indexed validatorAddress, bytes32 publicKey)` | `0xacac4fb2a24744049568d5be18ddc954871a3c8e805ee63a438e15e7490b908d` |

Errors:

| Error | Selector |
|---|---|
| `AlreadyInitialized()` | `0x0dc149f0` |
| `IngressAlreadyExists(string ingress)` | `0x8591b353` |
| `EmptyV1ValidatorSet()` | `0x77c218dd` |
| `InvalidMigrationIndex()` | `0x34e4bb70` |
| `InvalidIp(string input, string reason)` | `0xc87d8830` (only reachable from T14; never at ≤ T13) |
| `InvalidOwner()` | `0x49e27cff` |
| `InvalidPublicKey()` | `0xa2d0fee8` |
| `InvalidSignature()` | `0x8baa579f` |
| `InvalidSignatureFormat()` | `0x8529df1f` |
| `InvalidValidatorAddress()` | `0x713ce511` |
| `MigrationNotComplete()` | `0xcf45835b` |
| `NotInitialized()` | `0x87138d5c` |
| `NotIp(string input, string backtrace)` | `0xda00093e` |
| `NotIpPort(string input, string backtrace)` | `0x443ba5f5` |
| `PublicKeyAlreadyExists()` | `0xbfa96094` |
| `Unauthorized()` | `0x82b42900` |
| `AddressAlreadyHasValidator()` | `0x77a6ca7e` |
| `ValidatorAlreadyDeactivated()` | `0xfb1ba7c3` |
| `ValidatorNotFound()` | `0x580e542f` |

### 2.4 Helpers

#### 2.4.1 Guards

```python
def cfg(): return sload_config()                        # one read of slot 0
def require_init(c):      if not c.isInit: revert NotInitialized()
def require_not_init(c):  if c.isInit: revert AlreadyInitialized()
def require_owner(c, s):  if s != c.owner: revert Unauthorized()
def require_owner_or_validator(c, s, v):
    if s != v and s != c.owner: revert Unauthorized()

def get_active_validator(idx) -> ValidatorRecord:
    if idx >= len(validators): revert ValidatorNotFound()
    v = validators[idx]                                  # full-record read
    if v.deactivatedAtHeight != 0: revert ValidatorAlreadyDeactivated()
    return v

def require_new_pubkey(pk):
    if pk == 0: revert InvalidPublicKey()
    if pubkeyToIndex[pk] != 0: revert PublicKeyAlreadyExists()

def require_new_address(a):                              # deactivated addresses may be reused
    if a == 0: revert InvalidValidatorAddress()
    i1 = addressToIndex[a]
    if i1 != 0 and validators[i1-1].deactivatedAtHeight == 0: revert AddressAlreadyHasValidator()
```

#### 2.4.2 Endpoint validation

```python
def validate_endpoints(ingress, egress):
    if not parses_as_SocketAddr(ingress):                # §0.3
        revert NotIpPort(ingress, "input was not of the form `<ip>:<port>`")
    if not parses_as_IpAddr(egress):
        revert NotIp(egress, "input was not a valid IP address")
```

(From T14 additional length and IPv4-mapped checks apply; out of scope.) Any string accepted by these grammars is at most 255 bytes long, so the `uint8` length prefix of §2.4.4 never overflows at ≤ T13.

#### 2.4.3 Ingress key

```python
def ingressKey(ingress) -> bytes32:
    sa = parse_SocketAddr(ingress)       # failure: revert NotIpPort(ingress, "input was not of the form `<ip>:<port>`")
    if sa.is_v4: return keccak256(sa.ip.octets[4] ‖ be16(sa.port))
    else:        return keccak256(sa.ip.octets[16] ‖ be32(sa.scope_id) ‖ be16(sa.port))   # scope 0 if absent
```

Two textual forms of the same socket address (for example `[::1]:80` and `[0:0:0:0:0:0:0:1%0]:80`) have the same key.

#### 2.4.4 Key-ownership signature

`addValidator` and `rotateValidator` require an Ed25519 signature by the key being installed.

```python
NS_ADD    = b"TEMPO_VALIDATOR_CONFIG_V2_ADD_VALIDATOR"
NS_ROTATE = b"TEMPO_VALIDATOR_CONFIG_V2_ROTATE_VALIDATOR"

def verify_validator_signature(kind, publicKey, signature, validatorAddress, ingress, egress, feeRecipient=None):
    sig = commonware_ed25519_Signature_decode(signature)   # exactly 64 bytes, else:
    #   revert InvalidSignatureFormat()
    msg = keccak256(
        be64(chain_id)                                       # 8 bytes; mainnet 4217
        ‖ 0xCCCCCCCC00000000000000000000000000000001          # 20 bytes
        ‖ validatorAddress                                   # 20 bytes
        ‖ uint8(len(ingress)) ‖ ingress                       # exact calldata bytes
        ‖ uint8(len(egress))  ‖ egress
        ‖ (feeRecipient if kind == ADD else b""))            # 20 bytes for ADD only
    ns = NS_ADD if kind == ADD else NS_ROTATE
    pk = commonware_ed25519_PublicKey_decode(publicKey)      # else: revert InvalidPublicKey()
    if not pk.verify(ns, msg, sig): revert InvalidSignature()
```

`commonware_ed25519_*` are the commonware 2026.9.0 types `commonware_cryptography::ed25519::{PublicKey, Signature}` decoded with `commonware_codec::DecodeExt::decode` (exact length, no trailing bytes) and verified with `commonware_cryptography::Verifier::verify(&PublicKey, namespace, message, &Signature)`, whose signed payload is commonware's namespaced union of `namespace` and the 32-byte `msg`. The acceptance set of keys and signatures is exactly that of those types. The signature is decoded before the public key, so a malformed signature reports `InvalidSignatureFormat` even when the key is also undecodable. No gas is charged for decoding or verification.

### 2.5 Views

```python
def owner(): return cfg().owner
def isInitialized(): return cfg().isInit
def getInitializedAtHeight(): return cfg().initAtHeight
def validatorCount(): return len(validators)
def getNextNetworkIdentityRotationEpoch(): return nextNetworkIdentityRotationEpoch

def to_abi(r) -> Validator:
    return Validator(r.publicKey, r.validatorAddress, r.ingress, r.egress, r.feeRecipient,
                     r.index, r.addedAtHeight, r.deactivatedAtHeight)

def validatorByIndex(i):
    if i >= len(validators): revert ValidatorNotFound()
    return to_abi(validators[i])
def validatorByAddress(a):
    i1 = addressToIndex[a]
    if i1 == 0: revert ValidatorNotFound()
    return to_abi(validators[i1-1])         # may be deactivated
def validatorByPublicKey(pk):
    i1 = pubkeyToIndex[pk]
    if i1 == 0: revert ValidatorNotFound()
    return to_abi(validators[i1-1])
def getActiveValidators():
    return [to_abi(validators[activeIndices[j]-1]) for j in range(len(activeIndices))]
```

The order of `getActiveValidators()` is the `activeIndices` order, which changes on deactivation (§2.6.2); consumers MUST NOT rely on it.

### 2.6 Mutators

`block.number` is the executing block's number. All checks and writes are in the order shown.

#### 2.6.1 addValidator (owner)

```python
def addValidator(sender, validatorAddress, publicKey, ingress, egress, feeRecipient, signature) -> uint64:
    c = cfg(); require_init(c); require_owner(c, sender)
    require_new_pubkey(publicKey)
    require_new_address(validatorAddress)
    validate_endpoints(ingress, egress)
    h = ingressKey(ingress)
    if activeIngressIps[h]: revert IngressAlreadyExists(ingress)
    verify_validator_signature(ADD, publicKey, signature, validatorAddress, ingress, egress, feeRecipient)
    activeIngressIps[h] = true
    i = append_validator(validatorAddress, publicKey, ingress, egress, feeRecipient,
                         added=block.number, deactivated=0)
    emit ValidatorAdded(i, validatorAddress, publicKey, ingress, egress, feeRecipient)
    return i

def append_validator(addr, pk, ingress, egress, fee, added, deactivated) -> uint64:
    n = len(validators)
    activeIdx = 0
    if deactivated == 0:
        activeIndices.push(n + 1)            # element write, then length write
        activeIdx = len(activeIndices)
    validators.push(ValidatorRecord(pk, addr, ingress, egress, fee, index=n,
                                    activeIdx=activeIdx, added=added, deactivated=deactivated))
    pubkeyToIndex[pk] = n + 1
    addressToIndex[addr] = n + 1             # overwrites a pointer to a deactivated record
    return n
```

`feeRecipient` may be any address, including zero.

#### 2.6.2 deactivateValidator (owner or the validator; no initialization required)

```python
def deactivateValidator(sender, idx):
    v = get_active_validator(idx)
    require_owner_or_validator(cfg(), sender, v.validatorAddress)
    delete activeIngressIps[ingressKey(v.ingress)]
    validators[idx].deactivatedAtHeight = block.number
    a = v.activeIdx - 1
    last = len(activeIndices) - 1
    if a != last:                                   # swap-and-pop
        moved = activeIndices[last]
        activeIndices[a] = moved
        validators[moved - 1].activeIdx = a + 1
    activeIndices.pop()                             # zeroes the vacated element, then length -= 1
    validators[idx].activeIdx = 0
    emit ValidatorDeactivated(idx, v.validatorAddress)
```

Deactivation is permanent. The record's `publicKey` stays reserved (`pubkeyToIndex` unchanged) and `addressToIndex` keeps pointing at it until the address is reused.

#### 2.6.3 rotateValidator (owner or the validator)

```python
def rotateValidator(sender, idx, publicKey, ingress, egress, signature):
    v = get_active_validator(idx)
    c = cfg(); require_init(c); require_owner_or_validator(c, sender, v.validatorAddress)
    require_new_pubkey(publicKey)
    validate_endpoints(ingress, egress)
    if activeIngressIps[ingressKey(ingress)]: revert IngressAlreadyExists(ingress)
    #   (the validator's own current ingress counts as in use: the new ingress MUST differ, a port change suffices)
    verify_validator_signature(ROTATE, publicKey, signature, v.validatorAddress, ingress, egress)
    # update ingress tracking (keys always differ here)
    delete activeIngressIps[ingressKey(v.ingress)]
    activeIngressIps[ingressKey(ingress)] = true
    # append a deactivated snapshot of the old identity
    j = len(validators)
    validators.push(ValidatorRecord(v.publicKey, v.validatorAddress, v.ingress, v.egress, v.feeRecipient,
                                    index=j, activeIdx=0, added=v.addedAtHeight, deactivated=block.number))
    pubkeyToIndex[v.publicKey] = j + 1
    # overwrite the original slot in place
    r = validators[idx]
    r.publicKey = publicKey; r.ingress = ingress; r.egress = egress; r.addedAtHeight = block.number
    validators[idx] = r                              # full-record write
    pubkeyToIndex[publicKey] = idx + 1
    emit ValidatorRotated(idx, j, v.validatorAddress, v.publicKey, publicKey, ingress, egress, sender)
```

Rotation keeps `index`, `validatorAddress`, `feeRecipient`, `activeIdx` and the `addressToIndex` pointer of the in-place record; the active count is unchanged. The `validatorAddress` signed over is the record's current address, not `msg.sender`.

#### 2.6.4 setFeeRecipient, setIpAddresses, transferValidatorOwnership (owner or the validator)

```python
def setFeeRecipient(sender, idx, feeRecipient):
    v = get_active_validator(idx)
    c = cfg(); require_init(c); require_owner_or_validator(c, sender, v.validatorAddress)
    v.feeRecipient = feeRecipient
    validators[idx] = v                              # full-record write
    emit FeeRecipientUpdated(idx, feeRecipient, sender)

def setIpAddresses(sender, idx, ingress, egress):
    v = get_active_validator(idx)
    c = cfg(); require_init(c); require_owner_or_validator(c, sender, v.validatorAddress)
    validate_endpoints(ingress, egress)
    old = ingressKey(v.ingress); new = ingressKey(ingress)
    if old != new:
        if activeIngressIps[new]: revert IngressAlreadyExists(ingress)
        delete activeIngressIps[old]
        activeIngressIps[new] = true
    v.ingress = ingress; v.egress = egress
    validators[idx] = v                              # full-record write
    emit IpAddressesUpdated(idx, ingress, egress, sender)

def transferValidatorOwnership(sender, idx, newAddress):
    v = get_active_validator(idx)
    c = cfg(); require_init(c); require_owner_or_validator(c, sender, v.validatorAddress)
    require_new_address(newAddress)                  # the record's own address is active: AddressAlreadyHasValidator
    old = v.validatorAddress
    v.validatorAddress = newAddress
    validators[idx] = v                              # full-record write
    delete addressToIndex[old]
    addressToIndex[newAddress] = idx + 1
    emit ValidatorOwnershipTransferred(idx, old, newAddress, sender)
```

`setIpAddresses` with a different text for the same socket address (equal `ingressKey`) is accepted and stores the new strings without touching `activeIngressIps`.

#### 2.6.5 transferOwnership, setNetworkIdentityRotationEpoch (owner)

```python
def transferOwnership(sender, newOwner):
    if newOwner == 0: revert InvalidOwner()          # checked before initialization and auth
    c = cfg(); require_init(c); require_owner(c, sender)
    old = c.owner; c.owner = newOwner
    store_config(c)
    emit OwnershipTransferred(old, newOwner)

def setNetworkIdentityRotationEpoch(sender, epoch):
    c = cfg(); require_init(c); require_owner(c, sender)
    prev = nextNetworkIdentityRotationEpoch
    nextNetworkIdentityRotationEpoch = epoch
    emit NetworkIdentityRotationEpochSet(prev, epoch)
```

### 2.7 Migration from V1 and initialization

Migration copies V1 records into V2 one call at a time, in **descending** V1 index order, and then flips `isInit`. Before `isInit` is true, only views, `deactivateValidator`, `migrateValidator` and `initializeIfMigrated` can succeed.

```python
def require_migration_owner(sender) -> Config:
    c = cfg(); require_not_init(c)
    if c.owner == 0:                                  # first migration call (or V1 owner is zero)
        c.owner = V1.owner
        n1 = len(V1.validatorsArray)
        if n1 == 0: revert EmptyV1ValidatorSet()
        c.v1ValidatorCount = n1 mod 256               # truncating uint8 snapshot
        store_config(Config(owner=c.owner, isInit=False, initAtHeight=0,
                            migrationSkippedCount=0, v1ValidatorCount=c.v1ValidatorCount))
    require_owner(c, sender)                          # after the bootstrap write; a failing call reverts it
    return c

def migrateValidator(sender, idx):
    c = require_migration_owner(sender)
    n1 = c.v1ValidatorCount
    processed = len(validators) + c.migrationSkippedCount
    if processed >= n1 or idx != n1 - processed - 1: revert InvalidMigrationIndex()
    a = V1.validatorsArray(idx)                       # V1 Panic(0x32) cannot occur: V1 never shrinks
    r1 = V1.validators(a)                             # (publicKey, active, index, validatorAddress, inbound, outbound)

    def skip():
        emit SkippedValidatorMigration(idx, r1.validatorAddress, r1.publicKey)
        config.migrationSkippedCount = min(c.migrationSkippedCount + 1, 255)
        return

    if not commonware_ed25519_PublicKey_decodes(r1.publicKey): return skip()
    if not parses_as_SocketAddr(r1.outboundAddress): return skip()
    egress = canonical_ip_text(parse_SocketAddr(r1.outboundAddress).ip)
    if pubkeyToIndex[r1.publicKey] != 0: return skip()
    i1 = addressToIndex[r1.validatorAddress]
    if i1 != 0 and validators[i1-1].deactivatedAtHeight == 0:
        revert AddressAlreadyHasValidator()           # NOT a skip
    h = ingressKey(r1.inboundAddress)                 # unparsable inbound reverts NotIpPort (NOT a skip)
    if r1.active and activeIngressIps[h]: return skip()
    i = append_validator(r1.validatorAddress, r1.publicKey, r1.inboundAddress, egress,
                         feeRecipient=0, added=block.number,
                         deactivated=(0 if r1.active else block.number))
    if r1.active: activeIngressIps[h] = true
    emit ValidatorMigrated(i, r1.validatorAddress, r1.publicKey)

def initializeIfMigrated(sender):
    c = require_migration_owner(sender)
    if c.v1ValidatorCount == 0 or len(validators) + c.migrationSkippedCount < c.v1ValidatorCount:
        revert MigrationNotComplete()
    nextNetworkIdentityRotationEpoch = V1.nextDkgCeremony    # no NetworkIdentityRotationEpochSet event
    c.initAtHeight = block.number; c.isInit = True
    store_config(c)                                   # owner, skipped count and v1 count preserved
    emit Initialized(block.number)
```

`canonical_ip_text` is the Rust 1.96 `Display` form of the parsed IP: dotted decimal for IPv4; for IPv6 the RFC 5952 form (lowercase hex, longest run of two or more zero groups compressed, IPv4-mapped addresses as `::ffff:a.b.c.d`). The ingress string is copied verbatim; only egress is canonicalised (and loses its port). Inactive V1 records are migrated as born-deactivated entries (`deactivatedAtHeight = addedAtHeight = block.number`, no `activeIndices` entry, no ingress reservation). V1 is read through its storage directly (no call frame, no input charge).

> **Resolved conflict C-VAL-03**: TIP-1017 says `initializeIfMigrated` "can be called immediately when the V1 validator count is zero"; the code reverts `EmptyV1ValidatorSet()` (or `MigrationNotComplete()`) when V1 is empty. Decided: this spec follows the implementation, and the TIP is amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939). See [conflicts](../conflicts.md#c-val-03).

> **Resolved conflict C-VAL-04**: TIP-1017 says an invalid V1 entry is always "marked as processed … so global completion is not blocked"; the code reverts `AddressAlreadyHasValidator()` when the V1 address belongs to an active V2 record and reverts `NotIpPort` when the V1 inbound address does not parse, leaving that index unprocessed. Decided: this spec follows the implementation, and the TIP is amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939). See [conflicts](../conflicts.md#c-val-04).

### 2.8 Gas

Every V2 function costs exactly the input charge plus the framework cost of the storage reads, storage writes and logs listed in §2.4–§2.7, performed in that order. Signature decoding and Ed25519 verification, endpoint parsing and `ingressKey` hashing cost no gas. Pre-T2 calls cost only the input charge.

### 2.9 Consumption by consensus

Reference implementation: crates/consensus/src/validators.rs, crates/consensus/src/consensus/application/parent_state.rs, crates/consensus/src/peer_manager/actor.rs.

A validator computing or checking the DKG outcome carried by the boundary block of an epoch (07-consensus.md defines the boundary predicate, the `OnchainDkgOutcome` encoding and how proposals are compared) MUST derive two of its fields from ValidatorConfigV2 storage as follows. Let `P` be the parent of the boundary block and `S` the post-state of `P` (that is, the state after executing `P`, which is the pre-state of the boundary block). Reads are direct storage reads under the rules of `P`'s fork; they do not execute transactions or charge gas.

```python
def next_players(S) -> ordered_set[ed25519.PublicKey]:
    keys = {}
    for v in getActiveValidators() evaluated on S:
        pk = commonware_ed25519_PublicKey_decode(v.publicKey)    # failure: skip entry
        ok_ingress = parses_as_SocketAddr(v.ingress)            # failure: skip entry
        ok_egress  = parses_as_IpAddr(v.egress)                 # failure: skip entry
        if pk and ok_ingress and ok_egress: keys.add(pk)        # duplicates collapse
    return ordered_set(keys)        # commonware_utils::ordered::Set order (ascending key bytes)

def is_next_full_dkg(S, outcome_epoch) -> bool:
    return nextNetworkIdentityRotationEpoch(S) == outcome_epoch
```

where `outcome_epoch = epoch(P) + 1`. Undecodable entries are skipped silently, never rejected. Because `deactivatedAtHeight` is set to the executing block's number and `S` is the state after `P`, TIP-1017's filter `addedAtHeight < boundary && (deactivatedAtHeight == 0 || deactivatedAtHeight >= boundary)` evaluated on `S` selects exactly the active entries, so the two formulations agree. Setting the rotation epoch to a value that is not the next outcome epoch has no effect. An empty `next_players` set cannot be encoded (07-consensus.md requires 1..=65535 players), so such a boundary outcome cannot be produced.

The T12 change to DKG reveal handling (07-consensus.md) does not change these reads.

The same decoded entries (with `to_p2p_address`: ingress socket, egress IP with port 0) also feed the peer set; 08-p2p-and-sync.md specifies that use.

> **Resolved conflict C-VAL-05**: TIP-1017 says the consensus layer reads V1 while `v2.isInitialized()` is false and V2 afterwards; the code always reads V2 (no V1 fallback and no `isInitialized` check). Decided: this spec follows the implementation, and the TIP is amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939). See [conflicts](../conflicts.md#c-val-05).

The `feeRecipient` field is not consumed by block validity at or below T13 (its use as the required beneficiary starts at T14, out of scope).

## 3. CurrentCommittee (TIP-1070)

Reference implementation: crates/precompiles/src/current_committee/mod.rs, crates/precompiles/src/current_committee/dispatch.rs, crates/contracts/src/precompiles/current_committee.rs, crates/evm/src/block.rs (`apply_current_committee_system_call`), crates/evm/src/evm.rs (`SYSTEM_CALL_GAS_LIMIT`), crates/dkg-onchain-artifacts/src/lib.rs.

### 3.1 Activation

- Before T8 the address `0xC077E00000000000000000000000000000000000` is an ordinary (empty) account.
- From T8 it is routed to the native precompile, and at the start of every block from T8 the executor MUST install the `0xEF` marker exactly as in §2.1 (only if the code is empty; balance and nonce kept; no storage written). Activation does not initialise the committee: until the first boundary system call after T8, `getCommitteeMembers()` returns `(0, [])`.

### 3.2 Storage layout

| Slot | Field | Type |
|---|---|---|
| 0 | `epoch` | `uint64` (bits 0..63) |
| 1 | `publicKeys` | `bytes32[]` (length at slot 1, element `i` at `keccak256(p(1)) + i`) |

### 3.3 ABI

```solidity
interface ICurrentCommittee {
    error Unauthorized();                                                                    // 0x82b42900
    function getCommitteeMembers() external view returns (uint64 epoch, bytes32[] memory publicKeys); // 0xb2a275f9
    function setCommitteeMembers(uint64 epoch, bytes32[] calldata publicKeys) external;     // 0x229bdd9c
}
```

```python
def getCommitteeMembers(): return (epoch, publicKeys)

def setCommitteeMembers(sender, newEpoch, keys):
    if sender != 0x0000000000000000000000000000000000000000: revert Unauthorized()
    disable_tip1060_storage_credits_for_rest_of_call()     # neither mint nor consume credits
    epoch = newEpoch
    publicKeys = keys          # array assignment: shorter arrays zero the stale tail slots, then length, then elements
```

"Disable TIP-1060 storage credits" has the meaning defined in precompiles/account-keychain.md (storage credits section). The array assignment follows the framework's dynamic-array store with tail cleanup (active since T5, hence always at T8+): if the previous length exceeds the new one, the element slots `[newLen, prevLen)` are zeroed first, then the length slot is written, then elements `0..newLen-1`. No event is emitted. Any caller other than `address(0)` gets `Unauthorized()`, so in practice only the system call below can write.

### 3.4 End-of-epoch system call

From T8, in every block whose number `h` satisfies `(h + 1) mod epochLength == 0` (`epochLength` from the chain configuration, 01-chain-and-forks.md; mainnet 21600), the executor MUST, after all transactions and after the T4 incentive-section check, perform:

```python
def apply_current_committee_system_call(block):
    outcome = OnchainDkgOutcome.read(block.header.extra_data)   # 07-consensus.md encoding
    #   decoding reads a prefix of extra_data; bytes after the outcome are not examined by this step
    #   decode failure => block INVALID
    keys = [bytes32(pk) for pk in outcome.output.players]       # 32-byte ed25519 keys, set order
    calldata = abi.encodeCall(setCommitteeMembers, (outcome.epoch, keys))
    result = system_call(caller=0x0000000000000000000000000000000000000000,
                         to=0xC077E00000000000000000000000000000000000,
                         data=calldata, value=0, gas_limit=250_000_000)
    if not result.success: block INVALID                        # revert or exceptional halt
    commit(result.state)
```

Rules:

- `outcome.output.players` is the player set of the DKG `Output` (the committee for `outcome.epoch`), not `next_players`. Keys are written in `commonware_utils::ordered::Set` order, unchanged.
- The call is a system call (05-block-execution.md): it is not a transaction, produces no receipt, does not consume block gas, transfers no value and pays no fee. Its gas limit, 250,000,000 (`SYSTEM_CALL_GAS_LIMIT`), is binding: running out of gas invalidates the block.
- Ordering within block finalisation: (1) the T4 incentive-gas check, (2) selection of the post-execution EIP-7928 block-access-list index, (3) this call, (4) before T13, the inherited Ethereum post-block processing; from T13 nothing further (TIP-1119).
- Transactions in the boundary block observe the previous record; the new record is visible from the next block.

> **Resolved conflict C-VAL-06**: TIP-1070 requires the call to come "from the system address" (by EIP-4788 convention `0xfffffffffffffffffffffffffffffffffffffffe`); the code (and TIP-1119's table) uses caller `address(0)`, and the precompile reverts `Unauthorized()` for any other caller. Decided: this spec follows the implementation, and the TIP is amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939). See [conflicts](../conflicts.md#c-val-06).

## 4. Zones (TIP-1091, TIP-1096, TIP-1098)

Reference implementation: crates/precompiles/src/zone_factory/{mod.rs,portal.rs,dispatch.rs}, crates/contracts/src/precompiles/zone_factory.rs, crates/contracts/src/zones.rs, crates/contracts/src/zones/zone_portal.rs, crates/evm/src/block.rs (`deploy_zone_factory_at_boundary`, `install_zone_runtimes`, `upgrade_zone_runtimes`, `zone_runtime_fork`), crates/primitives/src/address.rs (`zone_portal_id`).

### 4.1 Addresses and constants

```python
ZONE_FACTORY_ADDRESS      = 0x5AF2000000000000000000000000000000000000   # native, T10
ZONE_PORTAL_IMPL_ADDRESS  = 0x5AD1000000000000000000000000000000000000   # EVM runtime
ZONE_VERIFIER_ADDRESS     = 0x5A56000000000000000000000000000000000000   # EVM stub T10..T12, native from T13
ZONE_MESSENGER_ADDRESS    = 0x5A4D000000000000000000000000000000000000   # EVM runtime
ZONE_PORTAL_PREFIX        = 0x5AD000000000000000000000                   # 12 bytes
INITIAL_FACTORY_OWNER     = 0xaF571FD4B3AD43a5807A5E58bFb25ea1aB327A14
ZONE_CREATION_GAS         = 15_000_000
MAX_SEQUENCERS            = 8
MAX_TOKEN_METADATA_BYTES  = 31

def portal_address(zoneId: uint32) -> address:
    return ZONE_PORTAL_PREFIX ‖ be64(zoneId)          # 20 bytes; zone 1 -> 0x5AD0…0001

def zone_portal_id(a: address) -> Optional[uint64]:
    if a[0:12] != ZONE_PORTAL_PREFIX: return None
    z = be_uint64(a[12:20])
    return z if z != 0 else None
```

Portal proxy runtime (ERC-1167, 45 bytes), written at every portal address by `createZone`:

```text
363d3d373d3d3d363d73 5ad1000000000000000000000000000000000000 5af43d82803e903d91602b57fd5bf3
keccak256 = 0x620678cab8cbffe25fab0e4d29c360ba2f7b55076bad1a7e730e80866211a795
```

### 4.2 Shared runtimes pinned by code hash

The portal implementation, messenger and (T10–T12) verifier are EVM bytecode installed by the protocol. They were compiled with solc 0.8.35 (CBOR metadata suffix `64736f6c6343 000823 0033`). Their exact bytes are normative and are reproduced in Appendix A; an implementation MUST install byte-identical code, which it can check against these hashes:

| Runtime set | Address | Length (bytes) | keccak256 (code hash) |
|---|---|---|---|
| T10 `ZONE_PORTAL_RUNTIME` | `0x5AD1…` | 23,359 | `0x109c27a83ea58d7b91efcc7bb415a04abef5a52d8fdc5a246c96de965fa47b32` |
| T10 `ZONE_VERIFIER_RUNTIME` | `0x5A56…` | 373 | `0xf3ab166b6d8637bb2f15ac5037b4546611339fc88e4b03b00b89559f7f2822a2` |
| T10 `ZONE_MESSENGER_RUNTIME` | `0x5A4D…` | 1,858 | `0x1ea2e80521c58fd7966e1fd370f84ac297261c7197f097ffc879de1890e0a1a0` |
| T13 `T13_ZONE_PORTAL_RUNTIME` | `0x5AD1…` | 23,994 | `0xbb0c0e14d5c2e15ca4aa1aaeb8d5c7bfdcf35fdadac5380ff93d38f962e4c41e` |
| T13 `T13_ZONE_VERIFIER_RUNTIME` | `0x5A56…` | 387 | `0xcf7b19d3c186e4fd235c94907d10bba5c1ce21d6e815676b00aaf298b456de14` |
| T13 `T13_ZONE_MESSENGER_RUNTIME` | `0x5A4D…` | 1,858 | `0x526c5bb045b6229e5a693d70feee066cc3848b5f91c62949ced54818045214ee` |

(The `0xEF` marker's code hash is `0x309b8896ee4c1ff7ec1966155373dee42663b6b40c3fedc70ba501684848d2a3`.) A later T15 portal runtime exists in the reference implementation and is out of scope.

### 4.3 Activation-time state changes

These steps run at the start of every block, after the Ethereum/EIP-2935 pre-block system calls and the earlier per-fork `0xEF` installs, before any transaction (05-block-execution.md fixes the global order). They write state directly (no EVM execution, no gas, no logs) and change the state root.

```python
def install_runtimes(runtimes):          # [(address, code)] in order: portal impl, verifier, messenger
    for (addr, code) in runtimes:
        acct = state.get(addr)            # may be absent
        if acct is not None and acct.code_hash == keccak256(code):
            continue
        acct = acct or Account(nonce=0, balance=0)
        acct.code = code                  # balance, nonce and storage are preserved
        state.put(addr, acct)

def pre_block_zone_steps(block):
    if T10_active(block):
        f = state.get(ZONE_FACTORY_ADDRESS)
        if f is None or f.code_hash == keccak256(b""):
            set_code_keep_balance_nonce(ZONE_FACTORY_ADDRESS, b"\xef")
            sstore(ZONE_FACTORY_ADDRESS, 0, 1 | (INITIAL_FACTORY_OWNER << 32))   # nextZoneId=1, owner
            install_runtimes([(ZONE_PORTAL_IMPL_ADDRESS, ZONE_PORTAL_RUNTIME),
                              (ZONE_VERIFIER_ADDRESS,    ZONE_VERIFIER_RUNTIME),
                              (ZONE_MESSENGER_ADDRESS,   ZONE_MESSENGER_RUNTIME)])
    if T13_active(block) and not T13_active_at(genesis.timestamp):
        install_runtimes([(ZONE_PORTAL_IMPL_ADDRESS, T13_ZONE_PORTAL_RUNTIME),
                          (ZONE_VERIFIER_ADDRESS,    T13_ZONE_VERIFIER_RUNTIME),
                          (ZONE_MESSENGER_ADDRESS,   T13_ZONE_MESSENGER_RUNTIME)])
```

- The T10 step is skipped whenever the factory already has code: on mainnet it takes effect once, in the first block at or after T10 (mainnet activation timestamp in 01-chain-and-forks.md), and the T10 runtimes are installed only together with the factory.
- The T13 step runs in every block from T13 on chains whose genesis was before T13 (mainnet). It is idempotent through the code-hash comparison. Upgrading the shared portal implementation upgrades every portal proxy; portal storage is unchanged, so the new `tokenEnablementCursorInitialized` flag (§4.5) is false for portals created before T13.
- A chain whose genesis is already at T10 or T13 carries the corresponding accounts in its genesis allocation (04-state-and-genesis.md) and skips the T13 upgrade.

### 4.4 ZoneFactory precompile

#### 4.4.1 Storage

| Slot | Field | Type |
|---|---|---|
| 0 | `nextZoneId` (bits 0..31) · `owner` (bits 32..191) | `uint32`, `address` |
| 1 | `zones` | `mapping(uint32 => ZoneInfo)` |

`ZoneInfo` record (5 slots, base `b = keccak256(p(zoneId) ‖ p(1))`):

| Slot | Field(s) |
|---|---|
| `b+0` | `zoneId` (uint32, bits 0..31) · `portal` (bits 32..191) · `accessMode` (bool, bits 192..199) · `gatewayMode` (bool, bits 200..207) |
| `b+1` | `admin` (bits 0..159) |
| `b+2` | `sequencers` (`address[]`) |
| `b+3` | `threshold` (uint8, bits 0..7) · `verifier` (bits 8..167) |
| `b+4` | `rpcUrl` (`string`) |

#### 4.4.2 ABI

```solidity
struct ZoneInfo { uint32 zoneId; address portal; bool accessMode; bool gatewayMode; address admin;
                  address[] sequencers; uint8 threshold; address verifier; string rpcUrl; }

interface IZoneFactory {
    struct CreateZoneParams {
        address initialToken; bool accessMode; bool gatewayMode;
        address[] allowedAccounts; address[] zoneGateways;
        address admin; address[] sequencers; uint8 threshold; string rpcUrl;
    }
    function owner() external view returns (address);                                       // 0x8da5cb5b
    function transferOwnership(address newOwner) external;                                  // 0xf2fde38b
    function createZone(CreateZoneParams calldata params)
        external returns (uint32 zoneId, address portal);                                   // 0x89677d9e
    function nextZoneId() external view returns (uint32);                                   // 0x266db436
    function zones(uint32 id) external view returns (ZoneInfo memory info);                 // 0x90b7f6fd
    function isZonePortal(address portal) external view returns (bool);                     // 0x01b290d3

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
        // 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0
    event ZoneCreated(uint32 indexed zoneId, address indexed portal, address initialToken, bool accessMode,
        bool gatewayMode, address admin, address[] sequencers, uint8 threshold, address verifier);
        // 0x4f2c5b8ee43ce856328b02e8d2b193126eb1c13f34475bd902ecb9a1eaa826a4

    error InvalidToken();               // 0xc1ab6dc1
    error TokenTransferPolicyNotSet();  // 0x8074d401
    error InvalidClosedLoopConfig();    // 0xa1eaf730
    error NotOwner();                   // 0x30cd7471
    error InvalidAdmin();               // 0xb5eba9f0
    error InvalidSequencerSet();        // 0x52013e33
    error AlreadyInitialized();         // 0x0dc149f0
    error TokenMetadataTooLong();       // 0x524d4f38
}
```

Portal events emitted by `createZone` (from the `ZonePortal` ABI; `enum Role { None=0, Sequencer=1, Account=2, CallbackGateway=3, PauseGuardian=4 }` ABI-encodes as `uint8`):

| Event | topic0 |
|---|---|
| `EnforcementModesUpdated(bool accessMode, bool gatewayMode)` | `0x3e5479494e0a078954a7ff8437aeca3bf7519b51a2fc06b3821251147ff9c5f7` |
| `SequencerSetUpdated(uint64 indexed nonce, uint8 threshold, address[] sequencers)` | `0x9282e5956b9751944c6e527bb3fa37aed57d3cfb67979c8962f561a194fc0bc5` |
| `LeaderUpdated(address indexed previousLeader, address indexed newLeader, uint64 indexed epoch, uint64 activationTempoBlock)` | `0x0e49bd8bbce34618e6af3bb74d587a65fa2a594df80b7cc21d690ee78c6d7a69` |
| `RoleUpdated(address indexed account, uint8 prev, uint8 next)` | `0x2359a069f5d7871f8f60ad861112ebe12dcf2ba55225c32ec04564d494afc69b` |
| `TokenEnabled(address indexed token, string name, string symbol, string currency)` | `0x4ac4dcc08b0c26c3fb6b58c64c1392b7934b1ce6b0382a5986ea5c3de795e053` |

#### 4.4.3 Views and ownership

```python
def owner(): return slot0.owner
def nextZoneId(): return slot0.nextZoneId
def zones(id): return zones[id]                    # all-zero record if never created
def isZonePortal(a):
    z = zone_portal_id(a)
    return z is not None and z < nextZoneId          # zone 0 never matches

def transferOwnership(sender, newOwner):
    prev = owner
    if sender != prev: revert NotOwner()
    owner = newOwner                                  # zero allowed (disables createZone)
    emit OwnershipTransferred(prev, newOwner)
```

#### 4.4.4 createZone

```python
def createZone(sender, p: CreateZoneParams) -> (uint32, address):
    deduct_gas(15_000_000)                            # first, before any check; insufficient gas = exceptional halt
    if sender != owner: revert NotOwner()
    if not (p.initialToken[0:12] == TIP20_PREFIX and code_hash(p.initialToken) != keccak256(b"")):
        revert InvalidToken()                         # TIP20Factory.isTIP20 (precompiles/tip20.md)
    if not tip403_token_transfer_policy_binding(p.initialToken).is_set:
        revert TokenTransferPolicyNotSet()            # explicit TIP-403 binding (precompiles/tip403.md)
    validate_closed_loop(p)
    if p.admin == 0: revert InvalidAdmin()
    validate_sequencer_set(p.sequencers, p.threshold)
    zoneId = nextZoneId
    portal = portal_address(zoneId)
    name, symbol, currency = TIP20(p.initialToken).name, .symbol, .currency   # storage reads
    if max(len(name), len(symbol), len(currency)) > 31: revert TokenMetadataTooLong()   # UTF-8 byte length
    enablement_hash = keccak256(abi.encode(bytes32(0), p.initialToken, name, symbol, currency))
    if zoneId == 2**32 - 1: revert Panic(0x11)
    nextZoneId = zoneId + 1
    initialize_portal(portal, zoneId, p, enablement_hash)          # §4.6
    zones[zoneId] = ZoneInfo(zoneId, portal, p.accessMode, p.gatewayMode, p.admin,
                             p.sequencers, p.threshold, ZONE_VERIFIER_ADDRESS, p.rpcUrl)
    emit_logs_in_order(portal, zoneId, p)              # §4.4.5
    return (zoneId, portal)

def validate_closed_loop(p):
    if ZONE_MESSENGER_ADDRESS in p.allowedAccounts: revert InvalidClosedLoopConfig()
    allv = p.allowedAccounts + p.zoneGateways + p.sequencers
    if T11_active:
        deduct_gas(20 * len(allv))                    # charged before the duplicate test
        if has_duplicates(allv): revert InvalidClosedLoopConfig()
        return
    # before T11
    if any(g in p.allowedAccounts for g in p.zoneGateways): revert InvalidClosedLoopConfig()
    if any(s in set(p.allowedAccounts) | set(p.zoneGateways) for s in p.sequencers):
        revert InvalidClosedLoopConfig()
    # duplicates inside allowedAccounts or inside zoneGateways, and zero entries there, are permitted

def validate_sequencer_set(seqs, threshold):
    if len(seqs) == 0 or len(seqs) > 8 or threshold == 0 or threshold > len(seqs):
        revert InvalidSequencerSet()
    for i, s in enumerate(seqs):
        if s == 0 or s in seqs[:i]: revert InvalidSequencerSet()
```

From T11 a sequencer repeated within `sequencers` is reported as `InvalidClosedLoopConfig()` (the global duplicate test runs first); before T11 it is reported as `InvalidSequencerSet()`. From T11, two zero-address entries anywhere in the three lists are duplicates.

> **Resolved conflict C-VAL-07**: TIP-1091 (and its reference ZoneFactory.sol) reject only addresses that appear in both `allowedAccounts` and `zoneGateways` before T11; the code also rejects, before T11, any sequencer that appears in `allowedAccounts` or `zoneGateways`. Decided: this spec follows the implementation, and the TIP is amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939). See [conflicts](../conflicts.md#c-val-07).

> **Resolved conflict C-VAL-09**: the TIP-1091 reference `ZoneFactory.sol` checks `NotOwner` before anything else (and says the owner is set "by the T9 activation"); the code deducts 15,000,000 gas before the owner check, so failing calls also consume it or halt out of gas, and the owner is installed at T10. Decided: this spec follows the implementation, and the TIP is amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939). See [conflicts](../conflicts.md#c-val-09).

Gas of a `createZone` call is exactly: the input charge; 15,000,000; the framework cost of every account read (`initialToken` code hash), storage read and write performed in §4.4.4 and §4.6 in the listed order (TIP-20 metadata strings, TIP-403 binding, factory slot 0, portal and `zones` records); from T11, `20 * (len(allowedAccounts)+len(zoneGateways)+len(sequencers))`; the code-installation charge of §4.6 step 2; and the cost of the logs of §4.4.5.

#### 4.4.5 createZone logs

After all state writes, `createZone` appends these logs to the transaction's log list in exactly this order. The first ones carry the **portal** address as their emitter even though no portal code runs:

1. portal: `EnforcementModesUpdated(p.accessMode, p.gatewayMode)`
2. portal: `SequencerSetUpdated(nonce=0, p.threshold, p.sequencers)`
3. portal: `LeaderUpdated(previousLeader=0, newLeader=p.sequencers[0], epoch=1, activationTempoBlock=block.number)`
4. portal: for each `g` in `p.zoneGateways` in order, `RoleUpdated(g, prev, CallbackGateway)`
5. portal: for each `a` in `p.allowedAccounts` in order, `RoleUpdated(a, prev, Account)`
6. portal: `TokenEnabled(p.initialToken, name, symbol, currency)`
7. factory: `ZoneCreated(zoneId, portal, p.initialToken, p.accessMode, p.gatewayMode, p.admin, p.sequencers, p.threshold, ZONE_VERIFIER_ADDRESS)`

In steps 4–5, `prev` is the role most recently emitted for that address within steps 4–5 of this call (sequencer roles are not tracked), or `None` if none was; so a repeated entry reports its previous role from this list.

### 4.5 ZonePortal storage layout

Every portal proxy executes the shared implementation by `DELEGATECALL`, so its state lives in the portal account. The layout below is that of the shared runtimes (T10 and T13 use the same layout; T13 starts using the slot-28 fields). Fields not written by `createZone` are listed for completeness because the native factory and verifier tooling address them by slot.

| Slot | Field(s) (bits) |
|---|---|
| 0 | `admin` (0..159) |
| 1 | `zoneGasRate` uint128 (0..127) · `withdrawalBatchIndex` uint64 (128..191) |
| 2 | `blockHash` bytes32 |
| 3 | `currentDepositQueueHash` bytes32 |
| 4 | `depositCount` (0..63) · `lastProcessedDepositNumber` (64..127) · `lastSyncedTempoBlockNumber` (128..191) · `bouncebackGas` (192..255), all uint64 |
| 5 | `encryptionKeys` `EncryptionKeyEntry[]` (2 slots each: `x` bytes32; `yParity` uint8 (0..7) · `activationBlock` uint64 (8..71)) |
| 6 | `tokenConfigs` `mapping(address => TokenConfig)`; `TokenConfig` = `enabled` bool (0..7) · `depositsActive` bool (8..15) |
| 7 | `enabledTokens` `address[]` |
| 8 | `refunds` `mapping(address => mapping(address => uint128))` |
| 9 | `withdrawalQueue.head` uint256 |
| 10 | `withdrawalQueue.tail` uint256 |
| 11 | `withdrawalQueue.slots` `mapping(uint256 => bytes32)` |
| 12 | `rpcUrl` string |
| 13 | `pendingAdmin` (0..159) |
| 14 | `withdrawalReentrancyStatus` uint256 |
| 15 | `zoneId` uint32 (0..31) · `messenger` (32..191) |
| 16 | `verifier` (0..159) · `initialized` bool (160..167) · `sequencerSetVersion` uint64 (168..231) · `sequencerThreshold` uint8 (232..239) |
| 17 | `zoneHeight` uint256 |
| 18 | `sequencers` `address[]` |
| 19 | reserved (zero) |
| 20 | `role` `mapping(address => uint8)` (`Role` enum) |
| 21 | `isAccessEnforced` bool (0..7) · `isGatewayEnforced` bool (8..15) · reserved (16..255) |
| 22 | `maxTempoGasRate` uint128 (0..127) |
| 23 | `leader` (0..159) · `leaderEpoch` uint64 (160..223) |
| 24 | `leaderActivationTempoBlock` (0..63) · `depositCountBlock` (64..127) · `depositsInCurrentBlock` (128..191) · `tokenEnableCountBlock` (192..255), all uint64 |
| 25 | `tokensEnabledInCurrentBlock` uint64 (0..63) · `pauseExpiry` uint64 (64..127) |
| 26 | `tokenEnablementHash` bytes32 |
| 27 | `abdicationEffectiveAt` `mapping(uint8 => uint64)` (key `Capability`: `PausePortal=0`, `AccessPolicy=1`) |
| 28 | `lastProcessedEnabledTokenCount` uint64 (0..63) · `tokenEnablementCursorInitialized` bool (64..71) · `transfersEnabled` bool (72..79; T15, always 0 at ≤ T13) |

### 4.6 Portal initialization by createZone

`createZone` initialises the portal **natively**: it writes the portal account's code and storage directly and never executes EVM code at the portal or the implementation.

> **Resolved conflict C-VAL-08**: TIP-1091 (step 5) and its reference `ZoneFactory.sol` say the factory calls the portal's factory-only initializer; the code writes portal storage and emits the portal's logs natively without any call frame (different gas, no inner call). Decided: this spec follows the implementation, and the TIP is amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939). See [conflicts](../conflicts.md#c-val-08).

```python
def initialize_portal(portal, zoneId, p, enablement_hash):
    S = storage_of(portal)
    if S[16].initialized: revert AlreadyInitialized()                       # 1
    set_code(portal, ZONE_PORTAL_PROXY_RUNTIME)                              # 2 unconditional, overwrites any code
    S.admin = p.admin                                                        # 3  slot 0
    S.tokenConfigs[p.initialToken] = TokenConfig(enabled=True, depositsActive=True)   # 4
    S.enabledTokens = [p.initialToken]                                       # 5  array assignment
    S.rpcUrl = p.rpcUrl                                                      # 6
    S.zoneId = zoneId                                                        # 7  slot 15
    S.messenger = ZONE_MESSENGER_ADDRESS                                     # 8  slot 15
    S.verifier = ZONE_VERIFIER_ADDRESS                                       # 9  slot 16
    S.initialized = True                                                     # 10 slot 16
    S.sequencerThreshold = p.threshold                                       # 11 slot 16
    S.sequencers = p.sequencers                                              # 12 array assignment
    for s in p.sequencers: S.role[s] = 1        # Sequencer                  # 13
    S.isAccessEnforced = p.accessMode                                        # 14 slot 21
    S.isGatewayEnforced = p.gatewayMode                                      # 15 slot 21
    S.leader = p.sequencers[0]                                               # 16 slot 23
    S.leaderEpoch = 1                                                        # 17 slot 23
    S.leaderActivationTempoBlock = block.number                              # 18 slot 24
    S.tokenEnableCountBlock = block.number                                   # 19 slot 24
    S.tokensEnabledInCurrentBlock = 1                                        # 20 slot 25
    S.tokenEnablementHash = enablement_hash                                              # 21 slot 26
    if T13_active: S.tokenEnablementCursorInitialized = True                 # 22 slot 28 (from T13)
    for g in p.zoneGateways:    S.role[g] = 3   # CallbackGateway            # 23
    for a in p.allowedAccounts: S.role[a] = 2   # Account                    # 24
```

- Every assignment to a packed field is a read-modify-write of its slot (framework packed-slot semantics).
- Step 2 charges the framework's code-installation cost for 45 bytes (per-byte code-deposit gas plus code-deposit state gas, and, when TIP-1016 is active and the account was empty, the CREATE charge, CREATE state gas and keccak cost for 2 words, exactly as for TIP-20 deployment; see 06-transactions-and-fees.md and precompiles/00-framework.md). The portal's nonce and balance are not changed.
- `sequencerSetVersion`, `blockHash`, `zoneGasRate`, `maxTempoGasRate`, `depositCount` and the other fields are left at zero; `lastProcessedEnabledTokenCount` stays 0.
- Before T11 an address may appear more than once in `allowedAccounts` or `zoneGateways`; later writes win (account roles last).
- New portals created from T13 have `tokenEnablementCursorInitialized = true` with `lastProcessedEnabledTokenCount = 0`, so their token cursor starts operational; portals created before T13 keep `false` until their first T13 settlement initialises it (§4.7).

### 4.7 Portal and messenger runtime behaviour (TIP-1096 limits)

All portal, messenger and (T10–T12) verifier behaviour is defined by the pinned EVM bytecode of §4.2 and Appendix A, executed under the ordinary EVM rules of 05-block-execution.md; a client needs no other description of them to validate blocks. The following summary of the T13 portal runtime (TIP-1096) is informative; where it and the bytecode differ, the bytecode governs:

- `MAX_UNPROCESSED_DEPOSITS = 230`, `WITHDRAWAL_BOUNCEBACK_RESERVE = 20`: with `unprocessed = depositCount - lastProcessedDepositNumber`, an ordinary deposit reverts once `unprocessed >= 210`, a withdrawal bounce-back once `unprocessed >= 230`, and `submitBatch` rejects `withdrawals.length > 230 - unprocessed` before processing any withdrawal.
- `MAX_UNPROCESSED_TOKEN_ENABLEMENTS = 8`: enabling a token requires `len(enabledTokens) - lastProcessedEnabledTokenCount < 8`, and reverts while `tokenEnablementCursorInitialized` is false.
- `submitBatch` and the verifier interface gain `TokenEnablementTransition(uint64 prevProcessedTokenCount, uint64 nextProcessedTokenCount)`; outside the activation batch it requires `prev == lastProcessedEnabledTokenCount <= next <= len(enabledTokens)`; on acceptance it sets `lastProcessedEnabledTokenCount = next` and, for the first settlement of an upgraded portal, `tokenEnablementCursorInitialized = true`.
- Event signatures change at T13: `BatchSubmitted` gains a trailing `uint64 lastProcessedEnabledTokenCount` (so its topic0 changes).

### 4.8 ZoneVerifier

Reference implementation: crates/precompiles/src/zone_verifier/{mod.rs,dispatch.rs,attestation.rs,pcrs.json,pcr.rs}, crates/nitro-attestation/src/{lib.rs,cbor.rs,x509.rs}, crates/contracts/src/precompiles/zone_verifier.rs.

#### 4.8.1 T10–T12: EVM stub

From T10 until T13 the address holds `ZONE_VERIFIER_RUNTIME` (Appendix A) and is not a precompile. Its behaviour, for reference: it accepts only selector `0x7106a43e` = `verify(uint32,uint64,uint64,bytes32,uint64,(bytes32,bytes32),(bytes32,bytes32,uint64,uint64),bytes32,bytes,bytes)` with zero call value, at least 448 bytes of arguments, in-range `uint32`/`uint64` words and well-formed `bytes` offsets and lengths, and then returns `abi.encode(true)`; anything else reverts with empty data. It checks no proof.

#### 4.8.2 From T13: native precompile

From T13 the address is routed to the native verifier. The code installed at T13 (`T13_ZONE_VERIFIER_RUNTIME`, an equivalent permissive stub for selector `0xebb2ddc9`) is observable through `EXTCODE*` but never executes, because native dispatch takes precedence.

```solidity
interface IZoneVerifier {
    struct BlockTransition { bytes32 prevBlockHash; bytes32 nextBlockHash; }
    struct DepositQueueTransition { bytes32 prevProcessedHash; bytes32 nextProcessedHash;
                                    uint64 prevDepositNumber; uint64 nextDepositNumber; }
    struct TokenEnablementTransition { uint64 prevProcessedTokenCount; uint64 nextProcessedTokenCount; }
    function verify(uint32 zoneId, uint64 tempoBlockNumber, uint64 anchorBlockNumber, bytes32 anchorBlockHash,
        uint64 expectedWithdrawalBatchIndex, uint256 nextZoneHeight, BlockTransition calldata blockTransition,
        DepositQueueTransition calldata depositQueueTransition,
        TokenEnablementTransition calldata tokenEnablementTransition, bytes32 withdrawalQueueHash,
        bytes calldata verifierConfig, bytes calldata proof) external view returns (bool);   // 0xebb2ddc9
}
```

Dispatch:

```python
MAX_CALLDATA_LEN = 4 + 17*32 + 2*32 + 32 + 24_576        # = 25_220

def call(calldata, msg_sender):
    charge_input_cost(calldata)                            # §0.1 (30 gas/word at T13)
    if len(calldata) > MAX_CALLDATA_LEN and calldata[0:4] == 0xebb2ddc9:
        return success(abi.encode(False))                  # before ABI decoding, no further gas
    dispatch normally (§0.1): verify is a view function; unknown selector / malformed args revert
    return abi.encode(verify(msg_sender, args))
```

`verify`:

```python
NITRO = b"\x01"; NO_PROOF = b"\x02"

def verify(caller, c) -> bool:
    if caller != portal_address(c.zoneId): return False
    if c.verifierConfig == NITRO and len(c.proof) > 0:
        pass                                                   # Nitro path
    else:
        return c.verifierConfig == NO_PROOF and len(c.proof) == 0   # temporary fallback (T13)
    if len(c.proof) > 24_576: return False                     # no base gas
    deduct_gas(40_000)
    parsed = parse_attestation(c.proof)                        # §4.8.3; failure -> return False
    if parsed is None: return False
    deduct_gas(150_000 * (len(parsed.cabundle) + 1))
    att = verify_parsed(parsed, block.timestamp, AWS_NITRO_ROOT_DER)   # §4.8.4; failure -> return False
    if att is None: return False
    for i in (0, 1, 2):                                        # PCR policy at T13, §4.8.5
        e = [x for x in att.pcrs if x.index == i]
        if not e or e[0].value != APPROVED_PCRS_T13[i]: return False
    if att.timestamp > block.timestamp * 1000 + 300_000: return False   # milliseconds, saturating
    if len(att.user_data) != 32: return False
    return att.user_data == batch_commitment(chain_id, c)      # §4.8.6
```

Every validation failure returns `false` (ABI-encoded) with the gas already charged; only out-of-gas is exceptional. Because all failures inside `parse_attestation` and `verify_parsed` yield the same result and charge nothing more, the order of the individual checks in §4.8.3–§4.8.4 is not observable.

#### 4.8.3 Document parsing

`parse_attestation(doc)` succeeds only if all of the following hold (CBOR per RFC 8949; COSE per RFC 9052; decoding of individual integers and strings is exactly that of `minicbor` 2.3.0 with `minicbor-serde` 0.7.1):

1. `len(doc) <= 24_576`. The document is one CBOR data item with no trailing bytes: optionally a single tag 18 (any other leading tag fails), then a definite-length array of exactly 4 elements `[protected, unprotected, payload, signature]`. No other tags are accepted anywhere (including inside the payload and on field names).
2. `protected` is a definite-length byte string whose content is exactly a definite-length map of one entry, key unsigned `1`, value negative `-35`, with no trailing bytes. `unprotected` is an empty map (definite or indefinite length); any entry fails. `payload` is a byte string of 1–16,384 bytes. `signature` is a byte string of exactly 96 bytes (`r ‖ s`). All byte and text strings everywhere are definite-length (chunked strings fail).
3. `payload` decodes, with no trailing bytes, as a map (definite or indefinite length) with text-string keys only. Required keys: `module_id` (non-empty text), `digest` (text equal to `SHA384`), `timestamp` (unsigned integer, nonzero, fits u64; milliseconds), `pcrs` (map), `certificate` (byte string), `cabundle` (array). Optional keys: `public_key`, `user_data`, `nonce` (byte string or CBOR null; null or absent is treated as empty). Unknown keys, duplicate keys (including duplicated optional keys, even when null), CBOR `undefined`, non-null wrong types, and non-text keys fail.
4. `pcrs`: 1 or more entries, unsigned integer keys, unique, each < 32, values byte strings of length 32, 48 or 64. `certificate`: 1–1,024 bytes. `cabundle`: 1–32 byte strings of 1–1,024 bytes each (the parser stops at the 33rd entry). A non-null `public_key` is 1–1,024 bytes; `user_data` and `nonce` are at most 512 bytes (a zero-length byte string is allowed).

The PCR entries are kept sorted by index; the exact `protected` and `payload` byte strings are kept for §4.8.4.

#### 4.8.4 Certificate chain and signature

Let `chain = cabundle + [certificate]` (index `0` is the root, index `n = len(cabundle)` the leaf; all of `cabundle` are CA certificates). `verify_parsed` succeeds only if:

1. `cabundle[0]` is byte-identical to `AWS_NITRO_ROOT_DER` (533 bytes; SHA-256 `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`, keccak256 `0x311d96fcd5c5e0ccf72ef548e2ea7d4c0cd53ad7c4cc49e67471aed41d61f185`):

```text
3082021130820196a003020102021100f93175681b90afe11d46ccb4e4e7f856300a06082a8648ce3d0403033049310b
3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b30190603
5504030c126177732e6e6974726f2d656e636c61766573301e170d3139313032383133323830355a170d343931303238
3134323830355a3049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b
0c03415753311b301906035504030c126177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106
052b8104002203620004fc0254eba608c1f36870e29ada90be46383292736e894bfff672d989444b5051e534a4b1f6db
e3c0bc581a32b7b176070ede12d69a3fea211b66e752cf7dd1dd095f6f1370f4170843d9dc100121e4cf630128096644
87c9796284304dc53ff4a3423040300f0603551d130101ff040530030101ff301d0603551d0e041604149025b50dd905
47e796c396fa729dcf99a9df4b96300e0603551d0f0101ff040403020186300a06082a8648ce3d040303036900306602
3100a37f2f91a1c9bd5ee7b8627c1698d255038e1f0343f95b63a9628c3d39809545a11ebcbf2e3b55d8aeee71b4c3d6
adf3023100a2f39b1605b27028a5dd4ba069b5016e65b4fbde8fe0061d6a53197f9cdaf5d943bc61fc2beb03cb6fee8d
2302f3dff6
```

2. Every certificate in `chain` (root included):
   - decodes as an X.509 `Certificate` (RFC 5280) and re-encodes to exactly the same bytes (strict DER; decoding as by `x509-cert` 0.2.5 / `der` 0.7.10);
   - has version v3;
   - has outer `signatureAlgorithm` and `tbsCertificate.signature` both equal to `ecdsa-with-SHA384` (OID 1.2.840.10045.4.3.3) with absent parameters;
   - is valid at the block: `notBefore <= block.timestamp <= notAfter`, comparing whole seconds since the Unix epoch;
   - has no two extensions with the same OID, and no critical extension other than basicConstraints (2.5.29.19) and keyUsage (2.5.29.15); basicConstraints and keyUsage, when present, decode;
   - if a CA (index < n): basicConstraints is present, **critical**, with `cA = TRUE`; keyUsage is present with `keyCertSign` (its criticality is not checked); its `pathLenConstraint`, if any, is recorded;
   - if the leaf: basicConstraints, if present, has `cA = FALSE` and no `pathLenConstraint`; keyUsage is present with `digitalSignature`;
   - has subjectPublicKeyInfo algorithm id-ecPublicKey (1.2.840.10045.2.1) with parameters the named curve secp384r1 (1.3.132.0.34), and a 97-byte uncompressed key (first byte `0x04`) that is a valid, non-identity P-384 point;
   - has a signature value that is a strict-DER `SEQUENCE { INTEGER r, INTEGER s }` with no trailing bytes, `r` and `s` positive with magnitudes of 1–48 bytes.
3. For `i = 1..n`: the DER encoding of `chain[i].issuer` equals that of `chain[i-1].subject`.
4. For every CA `chain[i]` (`i < n`) with `pathLenConstraint = L`: the number of certificates `chain[j]`, `i < j < n`, whose subject differs from their issuer is at most `L` (the leaf is never counted).
5. For `i = 1..n`: ECDSA P-384 verification of the DER signature of `chain[i]` over `SHA-384(DER(chain[i].tbsCertificate))` under `chain[i-1]`'s key succeeds. The root's own signature is not checked.
6. The COSE signature verifies: ECDSA P-384 over `SHA-384(Sig_structure)` under the leaf key, with the 96-byte `r ‖ s` signature, where `Sig_structure` is the CBOR encoding (definite lengths, shortest-form heads) of the array `["Signature1", protected, h'', payload]` using the exact `protected` and `payload` bytes of the document.

ECDSA verification accepts both low-s and high-s signatures. The verified result exposes `timestamp`, `pcrs`, `public_key`, `user_data` and `nonce`.

#### 4.8.5 Approved PCRs

From T13 the approved measurements are (48-byte SHA-384 values; provenance: prover image `ghcr.io/tempoxyz/tempo-zone-prover@sha256:ecac6ddca9aadc10c70b9d7f17d683b5b1d040d26785a292d27543a41fa8747c`, measured at tempoxyz/tempo commit `c60e3faa28657ac36569b43fa6bc44a9ed6929e7`):

| Register | Required value |
|---|---|
| PCR0 | `d64354677406bfda618e6f694528eec9e96c967296a4021249ad0153234f10f95861cd13509fbb7240f7a6d38ce69302` |
| PCR1 | `0cfa8adbf2c8842affa4e9d2bf3cd59ba3782c538ca5086c203d2382ed8b9945f289537c86dcbe52ac85057e8895fdbd` |
| PCR2 | `7cde50b7d313a691c03106281a84f6ae3c7bcdcffc8063bd1729d5f4969f535c508553c7102475bc1f02b97432ab56b9` |

Other PCR indices may be present and are ignored. The tuple is a fork constant (no runtime configuration; mainnet and Moderato never accept overrides).

> **Resolved conflict C-VAL-10**: TIP-1098 leaves PCR0–2 as placeholders and says the production verifier "has no approved tuple and MUST return false", and docs zones/proving.mdx says the measurements are unset so Nitro proofs are rejected; the code approves the tuple above from T13. Decided: this spec follows the implementation, and the TIP is amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939). See [conflicts](../conflicts.md#c-val-10).

#### 4.8.6 Batch commitment

```python
TYPEHASH = keccak256("NitroBatchAttestation(uint256 parentChainId,address verifier,uint32 zoneId,"
  "uint64 tempoBlockNumber,uint64 anchorBlockNumber,bytes32 anchorBlockHash,"
  "uint64 expectedWithdrawalBatchIndex,uint256 nextZoneHeight,bytes32 prevBlockHash,bytes32 nextBlockHash,"
  "bytes32 prevProcessedHash,bytes32 nextProcessedHash,uint64 prevDepositNumber,uint64 nextDepositNumber,"
  "uint64 prevProcessedTokenCount,uint64 nextProcessedTokenCount,bytes32 withdrawalQueueHash,"
  "bytes32 verifierConfigHash)")
# = 0xb6f39555cba9bf38842c669ea0c90bca6aad793881d75a0034e33352fbecb25e

def batch_commitment(chain_id, c) -> bytes32:          # EIP-712 hashStruct, no domain separator
    return keccak256(abi.encode(TYPEHASH, uint256(chain_id), ZONE_VERIFIER_ADDRESS, c.zoneId,
        c.tempoBlockNumber, c.anchorBlockNumber, c.anchorBlockHash, c.expectedWithdrawalBatchIndex,
        c.nextZoneHeight, c.blockTransition.prevBlockHash, c.blockTransition.nextBlockHash,
        c.depositQueueTransition.prevProcessedHash, c.depositQueueTransition.nextProcessedHash,
        c.depositQueueTransition.prevDepositNumber, c.depositQueueTransition.nextDepositNumber,
        c.tokenEnablementTransition.prevProcessedTokenCount,
        c.tokenEnablementTransition.nextProcessedTokenCount,
        c.withdrawalQueueHash, keccak256(c.verifierConfig)))
```

`chain_id` is the executing chain's id (4217 on mainnet).

## Appendix A. Protocol-installed runtime bytecode

Each block below is the exact runtime code (hex, wrapped at 128 characters; concatenate the lines, no `0x` prefix). The keccak256 of the decoded bytes MUST equal the listed code hash. Reference: crates/contracts/src/zones.rs at commit 37dc7833023927f49fd0aa81ae84dbd43790f70c.

### T10 ZONE_PORTAL_RUNTIME (installed at 0x5AD1000000000000000000000000000000000000 at T10)

Length 23359 bytes, keccak256 `0x109c27a83ea58d7b91efcc7bb415a04abef5a52d8fdc5a246c96de965fa47b32`.

```text
60c06040526004361015610011575f80fd5b5f60a0525f3560e01c80625d97ef14613028578062ebfdb414612f9357806303dd6f3414610d3b578063046f7da2
14612f2b57806304a3b09814612ee25780630e18b68114612e475780630e86bbdc14612dc05780630f3804b814612d4257806310cea85714612d05578063129c
824014612cce5780631950dd1114612ca95780631b32199b14612c835780631bf00ca814612c6657806321b4deee146127915780632678224714612c3c578063
27c71b5014612bab5780632b7ac3f314612b815780632c37826e14612b565780632dfdf0b514612b2e5780633488ce0d14612ab75780633557796214612a7a57
806337f981d8146129fc57806339dc015d146128c65780633a6b889b1461289b5780633cb747bf146128715780633fcf7df414610cbe57806340eedabb146128
475780634256ce3814612828578063430f8b4f1461280957806345c5d2fb146127ea5780634fdf2ec21461279657806356eb688f146127915780635c975abb14
612766578063652ef10b146125bd5780636d46e9871461259557806371649b6e14612571578063748538d91461253057806375829def146124b157806378d859
9e1461241757806378fb159b14611f615780638081a8b214611f4257806383888ecc14611f1757806383a146b314611efb5780638456cb5914611df957806384
b7112314611dda578063857e85f814611d7b57806386012b45146119e157806386829b82146111c257806386f47e55146111a35780638976248d146111765780
638d8bd5fb1461114e57806390f595981461111157806391aa3f0414610fcb57806394ce88b014610fac578063959f47c314610ed557806395a8c58d14610e60
578063996329a214610e435780639a97784b14610d965780639ecd4cc014610d5f578063b01f22e414610d3b578063b02690f214610cdb578063b1cf9e3d1461
0cbe578063b456c0dd14610c9f578063b83c755f14610c77578063be2a63ee14610c4c578063bf4c541114610b2f578063bffa55d514610a58578063c690908a
14610963578063cfaabb4d14610935578063d179978a14610910578063e09eae1014610889578063e47178491461086a578063e84abe691461083f578063ecf7
9a4e14610817578063ef10b187146105a0578063f125af6b14610575578063f22a195e14610556578063f490ca9614610532578063f60874421461049b578063
f706cfbf1461047c578063f851a44014610451578063fb2f12061461042f5763fe136c4e146103ac575f80fd5b34610429576020366003190112610429576103
c561325e565b6040516103d181613495565b60a0518152602060a05191015260018060a01b031660a05152600660205260408060a05120815190610402826134
95565b5460ff6020818316151593848152019160081c161515815282519182525115156020820152f35b60a05180fd5b346104295760a0513660031901126104
2957602060045460c01c604051908152f35b346104295760a0513660031901126104295760a051546040516001600160a01b039091168152602090f35b346104
295760a051366003190112610429576020604051620186a08152f35b34610429576020366003190112610429576104b46133b3565b60a051546001600160a01b
0316330361051f5760ff5f516020615aaa5f395f51905f52916104e06143dc565b610516821960155416838315151617918260155560405193849360081c1690
839092916020906040830194151583521515910152565b0390a160a05180f35b637bfa4b9f60e01b60a05152600460a051fd5b346104295760a0513660031901
12610429576020604051670de0b6b3a76400008152f35b346104295760a051366003190112610429576020600254604051908152f35b346104295760a0513660
031901126104295760206001600160401b0360195460401c16604051908152f35b346104295760a0366003190112610429576004356105bc61341e565b906044
3560ff811691908290036104295760a051546001600160a01b031633141580610807575b6107f4576105f083615783565b156107e1576105fe8161579d565b15
6107e15760206040519281840130815283604086015260ff8616948560608201526060815261062f6080826134b0565b51902090604051918252828201526064
356040820152608435606082015260a05160a05152608060a0519160015afa156107d45761067160a0515193826144f3565b926001600160a01b031680159081
156107c0575b506107ad576001600160401b0343166040516106a081613466565b82815260208101908482526040810190838252600554600160401b81101561
0795578060016106d29201600555613d4c565b91909161077c5760ff916001915181550192511668ffffffffffffffff008354925160081b169168ffffffffff
ffffffff1916171790556005545f198101908111610764577f854006acd102b75cc8cfe8e0fc954c82e22610d6d4b4ba4f0f19e896ed6397f29460a094604051
9485526020850152600180861b0316604084015260608301526080820152a160a05180f35b634e487b7160e01b60a051526011600452602460a051fd5b634e48
7b7160e01b60a0515260a051600452602460a051fd5b634e487b7160e01b60a051526041600452602460a051fd5b6392536faf60e01b60a05152600460a051fd
5b6001600160a01b0385161415905084610685565b6040513d60a051823e3d90fd5b632f0be49b60e11b60a05152600460a051fd5b6314f8a09f60e21b60a051
52600460a051fd5b5061081133613ee0565b156105e3565b346104295760a0513660031901126104295760206001600160801b0360015416604051908152f35b
346104295760a0513660031901126104295760206001600160401b0360045460401c16604051908152f35b346104295760a05136600319011261042957602060
0754604051908152f35b34610429576020366003190112610429576108a26132b4565b60a051546001600160a01b0316330361051f57600480546001600160c0
1b031660c083901b6001600160c01b0319161790556040516001600160401b0390911681527f66bcd750662bb66118e25a8e421ae73974634d9af2d44fb9e600
d250917fe69090602090a160a05180f35b346104295760a05136600319011261042957602063ffffffff600f5416604051908152f35b34610429576020366003
1901126104295760043560a05152600b6020526020604060a0512054604051908152f35b346104295760203660031901126104295761097c61325e565b60a051
546001600160a01b0316330361051f5760018060a01b0381168060a05152600660205260ff604060a051205416610a45576040516335ec42c960e01b81526004
81019190915260208160248161083f60921b5afa9081156107d45760a05191610a0b575b50156109f8576109f290614c13565b60a05180f35b631fcf8c4760e1
1b60a05152600460a051fd5b90506020813d602011610a3d575b81610a26602093836134b0565b8101031261042957610a37906134f5565b826109e3565b3d91
50610a19565b632909298f60e11b60a05152600460a051fd5b3461042957602036600319011261042957610a7161325e565b610a7a336155c1565b60a0805160
01600160a01b038316908190526008602081815283516040808220335f8181529185528282205493879052948452955181902084875290925293208054600160
0160801b031916905590926001600160801b0390921691610ae19183916155f2565b15610b1c576020916040518281527fffd3bbab073ab4b2d0792c27010492
4c14c285a153b9acddabae166395d2eb5c843392a3604051908152f35b63be51ced360e01b60a05152600460a051fd5b34610429576020366003190112610429
5760043560028110156104295760a051546001600160a01b0316330361051f5760195460401c6001600160401b03164210610c3957610b7d81613395565b8060
a05152601b6020526001600160401b03604060a051205416610c19577f839069134f9aac5b7c48da0389dd17d6579bb89ebdddc7fbd83bf64af2dd2ef2602061
0bd06001600160401b034216613fed565b610bd984613395565b8360a05152601b82526001600160401b03604060a05120911690816001600160401b03198254
16179055610c0c84613395565b604051908152a260a05180f35b60a05163667ccc6f60e11b9052610c2f81613395565b600452602460a051fd5b63c362a96f60
e01b60a05152600460a051fd5b346104295760a0513660031901126104295760206001600160401b0360045460801c16604051908152f35b346104295760a051
3660031901126104295760206001600160401b0360185416604051908152f35b346104295760a051366003190112610429576020601a54604051908152f35b34
6104295760a05136600319011261042957602060405160088152f35b346104295760203660031901126104295760075460043590811015610d235760a0805160
0790525160208082209092015460405160039290921b1c6001600160a01b03168152f35b634e487b7160e01b60a051526032600452602460a051fd5b34610429
576020610d57610d4e36613321565b93929092613522565b604051908152f35b346104295760203660031901126104295760406001600160401b03610d856004
35614313565b835191151582529091166020820152f35b3461042957602036600319011261042957600435604051610db681613466565b60a051815260a05160
20820152604060a051910152600554811015610e2d57610de0606091613d4c565b506001600160401b03604051610df581613466565b60ff6001845494858452
01549183604060208301928486168452019360081c1683526040519485525116602084015251166040820152f35b637f455d3760e11b60a05152600452602460
a051fd5b346104295760a051366003190112610429576020604051601f8152f35b3461042957604036600319011261042957610e7961325e565b602435906005
8210156104295760a080516001600160a01b0392909216909152601460205251604090205460ff16906005821015610ebd5760209114604051908152f35b634e
487b7160e01b60a051526021600452602460a051fd5b346104295760a0513660031901126104295760405160a051600c54610ef98161342e565b808452906001
8116908115610f885750600114610f39575b610f3583610f21818503826134b0565b6040519182916020835260208301906134d1565b0390f35b919050600c60
a051525f516020615a8a5f395f51905f529160a051905b808210610f6e57509091508101602001610f21610f11565b9192600181602092548385880101520191
01909291610f56565b60ff191660208086019190915291151560051b84019091019150610f219050610f11565b346104295760a0513660031901126104295760
20600954604051908152f35b34610429576040366003190112610429576004356001600160401b03811161042957610ffb9036906004016133ee565b90611005
33613ee0565b156107f45760195460401c6001600160401b03164210610c3957600e546110fe576001600e5561103482613f09565b9061104260405192836134
b0565b828252601f1961105184613f09565b0136602084013782602435815b6110a257505060a0515b83811061107a5760a051600e81905580f35b8061109c61
108b600193878661417a565b6110958387614166565b51906150aa565b01611068565b5f198201828111610764576110ea6110ca82846110c26110dc958a6141
66565b52888761417a565b926040519283916020830195866141ce565b03601f1981018352826134b0565b519020908015610764575f1901908161105e565b63
0b5c738160e01b60a05152600460a051fd5b346104295760403660031901126104295761112a61325e565b6111326133c2565b60a051546001600160a01b0316
330361051f576109f2916140bc565b346104295760a0513660031901126104295760206001600160801b0360165416604051908152f35b346104295760a05136
6003190112610429576020611192614097565b6001600160801b0360405191168152f35b346104295760a0513660031901126104295760206040516298968081
52f35b34610429576101803660031901126104295760043563ffffffff81168103610429576111ec613274565b60443591908215158303610429576064359283
15158403610429576084356001600160401b038111610429576112269036906004016133ee565b9160a4356001600160401b0381116104295761124690369060
04016133ee565b60c435979092906001600160a01b03891689036104295760e435916001600160a01b038316830361042957610104356001600160401b038111
610429576112919036906004016133ee565b610124356080819052909a91949060ff8116900361042957610144356001600160a01b0381169290839003610429
57610164356001600160401b038111610429576112e09036906004016132f4565b93909230615ad160901b146119ce57735af1ffffffffffffffffffffffffff
ffffffffff1933016119bb576010549260ff8460a01c166119a9578f63ffffffff600f5491640100000000600160c01b039060201b169216906001600160401b
0360c01b161717600f5560018060a01b03166bffffffffffffffffffffffff60a01b60a05154161760a05155600160a01b916affffffffffffffffffffff60a8
1b16171760105560155461ff0085151560081b169060ff851515169061ffff191617176015556001600160401b038211610795576113be600c5461342e565b60
1f8111611958575b5060a05190601f83116001146118d4579180915f516020615aaa5f395f51905f5295949360a051926118c9575b50508160011b915f199060
031b1c191617600c555b6040805191151582529115156020820152a186158080156118bf575b80156118b2575b80156118a4575b6118865760a0515b88811061
1802575060125488146117c4575b60a051806117ae575b61179c5760a0515b6012548110156114ce5780611474600192613d0b565b838060a01b039154906003
1b1c168060a051526014602052604060a0512060ff1981541690555f516020615aea5f395f51905f526040805160a0515060a0515085815260a0515060a05150
60a0516020820152a20161145e565b50889760125460a05160125580611787575b5060a0515b81811061172157506017546001600160a01b0316801515908161
1710575b506116fd5760105460ff60e81b60805160e81b169060ff60e81b1916178060105560405190826040830160ff60805116845260406020850152526060
820192859060a0515b8181106116d75750505090806001600160401b037f9282e5956b9751944c6e527bb3fa37aed57d3cfb67979c8962f561a194fc0bc59360
a81c16930390a2610d235761159661159b91614083565b614610565b60a0515b82811061165557505060a05190505b8281106115be576109f284614c13565b60
01600160a01b036115d96115d4838686614073565b614083565b16906001600160a01b0386168214610429578160a05152601460205260ff604060a051205416
6005811015610ebd576104295760a080518390526014602090815290516040808220805460ff1916600290811790915581519283529282019290925260019391
5f516020615aea5f395f51905f5291a2016115ae565b6001600160a01b0361166b6115d4838686614073565b16908160a05152601460205260ff604060a05120
54166005811015610ebd576104295760a080518390526014602090815290516040808220805460ff191660039081179091558151928352928201929092526001
93915f516020615aea5f395f51905f5291a20161159f565b909194602080600192838060a01b036116ef8a61328a565b168152019601929101611548565b63cb
d28fa360e01b60a05152600460a051fd5b61171a9150613ee0565b158a611503565b806117326115d46001938588614073565b61173b81614b4b565b60a08051
84821b85900392909216918290526014602090815290516040808220805460ff19168717905580519182529181018590525f516020615aea5f395f51905f5291
90a2016114e5565b61179690601260a05152613e8b565b896114e0565b621194ed60e51b60a05152600460a051fd5b5060ff60105460e81c1660ff6080511614
611456565b60a0515b8881106117d6575b5061144d565b6117ec6117e76115d4838c87614073565b613ee0565b156117f9576001016117c8565b5060a0516117
d0565b6001600160a01b036118186115d4838c87614073565b168015611886578060a05152601460205260ff604060a0512054166005811015610ebd57801590
8115611899575b50156104295760a0515b82811061186157505060010161143b565b816001600160a01b036118786115d4848f8a614073565b16146118865760
0101611850565b6352013e3360e01b60a05152600460a051fd5b60011490508c611846565b508760ff6080511611611433565b5060ff608051161561142c565b
5060088811611425565b013590508d806113f4565b601f19831691600c60a051525f516020615a8a5f395f51905f529260a0515b818110611940575091600193
91855f516020615aaa5f395f51905f529897969410611927575b505050811b01600c55611409565b01355f19600384901b60f8161c191690558d808061191956
5b919360206001819287870135815501950192016118f3565b828111156113c75761199990600c60a05152601f840160051c906020851061199f575b601f8291
0160051c03905f516020615a8a5f395f51905f5201613ec5565b8c6113c7565b60a051915061197b565b62dc149f60e41b60a05152600460a051fd5b63196639
1b60e11b60a05152600460a051fd5b63b25caa5160e01b60a05152600460a051fd5b34610429576040366003190112610429576004356001600160401b038111
61042957611a119036906004016133ee565b611a1961341e565b60a051546001600160a01b0316330361051f5781158015611d71575b8015611d66575b801561
1d5a575b6118865760a0515b828110611ccb5750601254821480611c90575b80611c7c575b61179c5760a0515b601254811015611adc5780611a82600192613d
0b565b838060a01b0391549060031b1c168060a051526014602052604060a0512060ff1981541690555f516020615aea5f395f51905f526040805160a0515060
a0515085815260a0515060a0515060a0516020820152a201611a6c565b509060125460a05160125580611c67575b5060a0515b818110611c0157506017546001
600160a01b03168015159081611bf0575b506116fd576010549060ff60e81b8360e81b1691611b466001600160401b038460ff60e81b198416178060105560a8
1c1661400d565b926001600160401b0360a81b8460a81b169168ffffffffffffffffff60a81b19161717601055806040519360ff604086019116855260406020
8601525260608301939060a0515b818110611bca576001600160401b0384167f9282e5956b9751944c6e527bb3fa37aed57d3cfb67979c8962f561a194fc0bc5
86880387a260a05180f35b909194602080600192838060a01b03611be28a61328a565b168152019601929101611b8d565b611bfa9150613ee0565b1584611b10
565b80611c126115d46001938588614073565b611c1b81614b4b565b60a0805184821b85900392909216918290526014602090815290516040808220805460ff
19168717905580519182529181018590525f516020615aea5f395f51905f529190a201611af2565b611c7690601260a05152613e8b565b83611aed565b5060ff
60105460e81c1660ff821614611a64565b60a0515b838110611ca2575b50611a5e565b611cb36117e76115d4838789614073565b15611cc057600101611c9456
5b505060a05184611c9c565b6001600160a01b03611ce16115d4838688614073565b168015611886578060a05152601460205260ff604060a051205416600581
1015610ebd578015908115611d4f575b50156104295760a0515b828110611d2a575050600101611a4b565b816001600160a01b03611d416115d484898b614073
565b161461188657600101611d19565b600114905086611d0f565b508160ff821611611a43565b5060ff811615611a3c565b5060088211611a35565b34610429
57604036600319011261042957611d9461325e565b611d9c613274565b9060018060a01b031660a051526008602052604060a051209060018060a01b03165f52
60205260206001600160801b0360405f205416604051908152f35b346104295760a051366003190112610429576020601254604051908152f35b346104295760
a0513660031901126104295760195460401c6001600160401b03164210610c3957611e28614440565b60a051546001600160a01b031633141580611eeb575b80
611ec3575b611eb057611e5a6001600160401b034216613fed565b67ffffffffffffffff60401b6019549160401b169067ffffffffffffffff60401b19161760
1955337f477a1104043ff48a8d2126e5d02d0d4977cb0b2ee7cd4030cb8823007db90f3660a05160a051a260a05180f35b63248ccfdb60e11b60a05152600460
a051fd5b5060a08051339052601460205251604090205460ff166005811015610ebd5760041415611e44565b50611ef533613ee0565b15611e3e565b34610429
5760a05136600319011261042957602061119261402a565b346104295760a0513660031901126104295760206001600160401b0360105460a81c166040519081
52f35b346104295760a051366003190112610429576020600a54604051908152f35b34610429576101a036600319011261042957611f7b6132b4565b611f8361
32ca565b6040366043190112610429576080366083190112610429576101043590610124356001600160401b03811161042957611fc09036906004016132f456
5b9390610144356001600160401b03811161042957611fe29036906004016132f4565b9190936101643594610184356001600160401b0381116104295761200a
9036906004016133ee565b92909161201633613ee0565b156107f4576044359160025483036122e0576001600160401b03811690816123ec5750508692600160
0160401b0388164381116123d957612056906146b0565b945b85156123d95761206781613f09565b9161207560405193846134b0565b81835260208301916005
1b810190368211610429578c888f938d8f97968b92868f97925b82841061239257505050506120ad9761473d565b1561237f576120ba613f8f565b9560045496
6001600160401b03808960401c1691161480159061235c575b8015612340575b61232d5760018060a01b036010541663ffffffff600f5416936001600160401b
038a6001549882808b60801c1699816121178c613fcf565b946040519b633883521f60e11b8d5260048d01521660248b01521660448901526064880152166084
86015260a4850152606435968760c486015260843560e486015260a4359c8d61010487015260a0515060c4356001600160401b03811680910361042957610124
87015260e4356001600160401b03811692908390036104295760209587958f6121de938896956121cb9288976101448901526101648801526101c06101848801
526101c4870191613502565b848103600319016101a486015291613502565b03915afa9081156107d45760a051916122f3575b50156122e05767ffffffffffff
ffff60801b9061220e9061400d565b60801b16906001600160401b0360801b19161760015560025567ffffffffffffffff60401b61223b613fa5565b60401b16
916001600160401b0360801b9060801b169077ffffffffffffffffffffffffffffffff0000000000000000191617176004556011557f5a66941dc92cb865480c
966eff640c02b1d00d544b74332fd67c6f1cbfccdf3960806122a083614b1d565b936001600160401b03600154831c1693600254906001600160401b03600454
60401c1691604051938452602084015260408301526060820152a360a05180f35b6309bde33960e01b60a05152600460a051fd5b90506020813d602011612325
575b8161230e602093836134b0565b810103126104295761231f906134f5565b896121f2565b3d9150612301565b633d9dffbd60e01b60a05152600460a051fd
5b50612349613fa5565b6001600160401b038089169116116120df565b50612365613fa5565b6001600160401b0380612376613f8f565b169116106120d8565b
63098017c360e01b60a05152600460a051fd5b96509650965096975050505083356001600160401b038111610429576020916123bf839236908601613f71565b
8152019301888f938f928f9796908f91928e968d94612099565b632705871360e01b60a05152600460a051fd5b6001600160401b0389959295168511156123d9
574385116123d95761241190946146b0565b94612058565b346104295760203660031901126104295761243061329e565b60a051546001600160a01b03163303
61051f576001600160801b0316670de0b6b3a7640000811161249e576020817fede0c86e4d0b914b0ba2f68c3359e9ccbcdece694913dcbdf50affe96900e1e8
926001600160801b03196016541617601655604051908152a160a05180f35b630d62f21160e11b60a05152600460a051fd5b3461042957602036600319011261
0429576124ca61325e565b60a051546001600160a01b0316903382900361051f5760018060a01b031690816bffffffffffffffffffffffff60a01b600d541617
600d557fe5cd1c804f1c9cc6d7009e4c0fb532f0e2d8863524c3323a6b3790c3f80bf25c60a05160a051a360a05180f35b346104295760203660031901126104
29576001600160a01b0361255161325e565b1660a051526006602052602060ff604060a0512054166040519015158152f35b346104295760a051366003190112
61042957602060ff601554166040519015158152f35b346104295760203660031901126104295760206125b36117e761325e565b6040519015158152f35b3461
0429576020366003190112610429576004356001600160401b038111610429576125ed9036906004016132f4565b906125f733613ee0565b156107f457600160
0160401b03821161079557612615600c5461342e565b601f8111612720575b5060a05191601f811160011461268f5760a0517ff4e00967b25e707df96d886762
43b33be84847ef27615af8ef91290b52294fc69382612684575b508160011b905f198360031b1c191617600c555b610516604051928392602084526020840191
613502565b905082013584612659565b601f19811692600c60a051525f516020615a8a5f395f51905f529060a0515b8581106127085750827ff4e00967b25e70
7df96d88676243b33be84847ef27615af8ef91290b52294fc695106126ef575b5050600181811b01600c5561266d565b8301355f19600384901b60f8161c1916
905583806126df565b909160206001819285880135815501930191016126ae565b8281111561261e5761276090600c60a05152601f840160051c906020851061
199f57601f82910160051c03905f516020615a8a5f395f51905f5201613ec5565b8261261e565b346104295760a0513660031901126104295760206125b36001
600160401b0360195460401c16421090565b6133d1565b34610429576040366003190112610429576127af61325e565b6127b76132ca565b60a0515460016001
60a01b0316331415806127da575b6107f4576109f291613def565b506127e433613ee0565b156127cd565b346104295760a05136600319011261042957602060
0354604051908152f35b346104295760a051366003190112610429576020601154604051908152f35b346104295760a051366003190112610429576020600554
604051908152f35b346104295760a051366003190112610429576017546040516001600160a01b039091168152602090f35b346104295760a051366003190112
61042957600f54604051602091821c6001600160a01b03168152f35b346104295760a0513660031901126104295760206001600160401b0360175460a01c1660
4051908152f35b34610429576020366003190112610429576128df6132b4565b600554801580156129c3575b6129a35760a051905f1981019081116107645760
01600160401b03909216915b80821061293c5760608261291e81613d4c565b509060ff600183549301541660405192835260208301526040820152f35b908082
0180821161076457600181018091116107645760011c90836001600160401b03600161296a85613d4c565b50015460081c161161297d57509061290b565b9150
5f1981019081111561290b57634e487b7160e01b60a051526011600452602460a051fd5b6001600160401b038263302c66ab60e21b60a0515216600452602460
a051fd5b5060055415610d2357600560a051526001600160401b036001602060a0512060a05150015460081c166001600160401b038316106128eb565b346104
29576020366003190112610429576001600160a01b03612a1d61325e565b1660a0515260066020526020604060a05120612a466001600160401b036019546040
1c16421090565b159081612a6e575b81612a5f575b506040519015158152f35b60ff91505460081c1682612a54565b805460ff169150612a4e565b3461042957
604036600319011261042957612a9361325e565b612a9b6133c2565b60a051546001600160a01b0316330361051f576109f291613d68565b346104295760a051
366003190112610429576005548015612b1b575f19810190811161076457612ae8606091613d4c565b5060ff6001825492015416612afd81836144f3565b6040
805193845260208401929092526001600160a01b031690820152f35b630c322fb560e31b60a05152600460a051fd5b346104295760a051366003190112610429
5760206001600160401b0360045416604051908152f35b346104295760a0513660031901126104295760206001600160401b0360015460801c16604051908152
f35b346104295760a051366003190112610429576010546040516001600160a01b039091168152602090f35b3461042957602036600319011261042957612bc4
61325e565b60a051546001600160a01b0316330361051f5760018060a01b03168060a05152600660205260ff604060a051205416156109f85760a08051829052
60066020525160408120805461ff00191690557feb225a736fbfee3f85ccb72bdf84ff0396ab358b7970e2cc351ab3e3fd92358d9080a260a05180f35b346104
295760a05136600319011261042957600d546040516001600160a01b039091168152602090f35b346104295760a05136600319011261042957602060405160e6
8152f35b346104295760a05136600319011261042957602060ff60155460081c1615604051908152f35b346104295760a05136600319011261042957602060ff
60105460e81c16604051908152f35b34610429576020366003190112610429576020612cec600435613d0b565b905460405160039290921b1c6001600160a01b
03168152f35b3461042957604036600319011261042957612d1e61325e565b612d266133c2565b60a051546001600160a01b0316330361051f576109f291613c
59565b3461042957602036600319011261042957612d5b6133b3565b60a051546001600160a01b0316330361051f5760ff5f516020615aaa5f395f51905f5291
612d876143dc565b6105166015549161ff0081151560081b1661ff00198416176015556040519384931683909291602090604083019415158352151591015256
5b3461042957602036600319011261042957612dd961329e565b60a051546001600160a01b0316330361051f576001600160801b0316670de0b6b3a764000081
1161249e576020817fc62141e607d6fcbf7d11fd2b6d8e18e5ebef6d3fff8136ca98822801abbaea38926001600160801b031960015416176001556040519081
52a160a05180f35b346104295760a05136600319011261042957600d546001600160a01b0381169081158015612ed8575b612ec55760a05180546001600160a0
1b031980821685178355909216600d556001600160a01b03909116907ff8ccb027dfcd135e000e9d45e6cc2d662578a8825d4c45b5e32e0adf67e79ec69080a3
60a05180f35b63058d9a1b60e01b60a05152600460a051fd5b5081331415612e70565b3461042957602036600319011261042957600435600281101561042957
612f0881613395565b60a05152601b60205260206001600160401b03604060a051205416604051908152f35b346104295760a0513660031901126104295760a0
51546001600160a01b0316330361051f5767ffffffffffffffff60401b1960195416601955337fd2c62538708a93d7454226ca65a098ec07211b126fc22bf2ac
cdcae6561fc2aa60a05160a051a260a05180f35b3461042957602036600319011261042957612fac61325e565b60a051546001600160a01b0316330361051f57
60018060a01b03168060a05152600660205260ff604060a051205416156109f85760a0805182905260066020525160408120805461ff0019166101001790557f
22ab73af03f04a21e91c7923327f99279b7f5d07d9551762c39bccdf051f1fe99080a260a05180f35b346131e35760c03660031901126131e35761304161325e
565b613049613274565b604435916001600160801b038316928381036131e357608435936001600160401b0385168095036131e35760a4356001600160401b03
81116131e3576130939036906004016132f4565b909330330361324f5760ff60155460081c168061323f575b61323057600f5460405163a9059cbb60e01b8152
6001600160a01b03602092831c811660048301526001600160801b039690961660248201529190941693816044815f885af19081156131d8575f916131f6575b
50156131e75760035495600f5460018060a01b038160201c1693843b156131e3575f9663ffffffff94889461317d936040519b8c9a8b998a986311da526160e0
1b8a521660048901526024880152606435604488015260018060a01b03166064870152608486015260a485015260e060c485015260e4840191613502565b0392
5af180156131d8576131c4575b5060ff6015541690816131b8575b506131a55760a05180f35b631fd6e06160e01b60a05152600460a051fd5b90506003541481
61319a565b5f6131ce916134b0565b5f60a0528161318c565b6040513d5f823e3d90fd5b5f80fd5b6312171d8360e31b5f5260045ffd5b90506020813d602011
613228575b81613211602093836134b0565b810103126131e357613222906134f5565b876130ff565b3d9150613204565b63793cd94b60e11b5f5260045ffd5b
50613249866142c1565b156130ab565b6314e1dbf760e11b5f5260045ffd5b600435906001600160a01b03821682036131e357565b602435906001600160a01b
03821682036131e357565b35906001600160a01b03821682036131e357565b600435906001600160801b03821682036131e357565b600435906001600160401b
03821682036131e357565b602435906001600160401b03821682036131e357565b35906001600160401b03821682036131e357565b9181601f840112156131e3
578235916001600160401b0383116131e357602083818601950101116131e357565b9060a06003198301126131e3576004356001600160a01b03811681036131
e357916024356001600160801b03811681036131e3579160443591606435906001600160401b0382116131e35760a09082900360031901126131e35760040190
6084356001600160a01b03811681036131e35790565b6002111561339f57565b634e487b7160e01b5f52602160045260245ffd5b6004359081151582036131e3
57565b6024359081151582036131e357565b346131e3575f3660031901126131e357602060405162278d008152f35b9181601f840112156131e3578235916001
600160401b0383116131e3576020808501948460051b0101116131e357565b6024359060ff821682036131e357565b90600182811c9216801561345c575b6020
83101461344857565b634e487b7160e01b5f52602260045260245ffd5b91607f169161343d565b606081019081106001600160401b0382111761348157604052
565b634e487b7160e01b5f52604160045260245ffd5b604081019081106001600160401b0382111761348157604052565b90601f801991011681019081106001
600160401b0382111761348157604052565b805180835260209291819084018484015e5f828201840152601f01601f1916010190565b519081151582036131e3
57565b908060209392818452848401375f828201840152601f01601f1916010190565b60195491939160401c6001600160401b03164210613c25576001600160
a01b038516948515613c165761355d9061355833615856565b6155c1565b6001600160a01b03165f8181526006602052604090205460ff811615613c07576008
1c60ff1615613bf857604051639c4bad2960e01b8152602081600481855afa9081156131d8575f91613bbe575b506040516337de09eb60e11b81526001600160
401b039190911660048201526024810186905260208160448161100f60921b5afa9081156131d8575f91613b84575b5015613b7557602082019461360a613605
8761439c565b615783565b15613b665782359061361b8261579d565b15613b66576040840191604061363184876143aa565b905003613b435761364186614313
565b5015613ac05761364f614097565b906001600160801b0361366961366361402a565b84615891565b16976001600160801b038116988910613ab157826136
86916158b1565b97604051906323b872dd60e01b825233600483015230602483015260448201526020816064815f8a5af180156131d857613a7a575b50600160
0160801b03821691826139f8575b5060405160c081018181106001600160401b038211176134815760405285815260208101923384526001600160801b036040
83019a1691828b52606081019a868c5260808201958b875260a08b3603126131e3576040519060a082018281106001600160401b038211176134815760405286
82528e3560ff811681036131e357602083015289356001600160401b0381116131e3578c61376f91369101613f71565b604083015260608c01356001600160a0
1b031981169e908f81036131e357606084015260808d0135926001600160801b03198416998a85036131e35761389194608083015260a0870191825260035492
6001600160801b03604051978896602088019a60018c52606060408a015260018060a01b03905116608089015260018060a01b0390511660a0880152511660c0
86015260018060a01b0390511660e085015251610100840152519060c0610120840152815161014084015260ff60208301511661016084015261385360408301
5160a06101808601526101e08501906134d1565b6060808401516001600160a01b0319166101a08601526080909301516001600160801b0319166101c0850152
9183015203601f1981018352826134b0565b5190209a6018546001600160401b0343166001600160401b038260401c16036139d0575b50601854986001600160
401b038a60801c169460d28610156139bc578d9b6139656001600160401b039a61395f8f967f51046223e5e0abca942f13a8f3d1c8dfd59c8b6c4f3e64fc2f5b
f453767a97ca9f9760ff988f9c600161399b9e60801b910160801b16906001600160401b0360801b19161760185560035561393e6004549e8f1661400d565b60
01600160401b0381169e8f906001600160401b031916176004555061439c565b946143aa565b9590966040519c8d5260208d015260408c015260608b01526080
8a01521660a088015261016060c0880152610160870191613502565b9660e08501526101008401526101208301526101408201528033940390a390565b6301eb
386f60e71b5f5260d260045260245ffd5b600160401b600160c01b0319164360401b67ffffffffffffffff60401b16176018555f6138b5565b5f5460405163a9
059cbb60e01b81526001600160a01b039190911660048201526001600160801b039091166024820152602081806044810103815f8a5af180156131d857156136
cd576020813d602011613a72575b81613a5a602093836134b0565b810103126131e357613a6b906134f5565b505f6136cd565b3d9150613a4d565b6020813d60
2011613aa9575b81613a93602093836134b0565b810103126131e357613aa4906134f5565b6136bb565b3d9150613a86565b636ba4a1c760e01b5f5260045ffd
5b85600554811015613b3157613ad481613d4c565b5060018201808311613b1d5760016001600160401b0381613af58294613d4c565b5094015460081c169201
5460081c169163034dff0f60e01b5f5260045260245260445260645ffd5b634e487b7160e01b5f52601160045260245ffd5b637f455d3760e11b5f5260045260
245ffd5b613b4d83866143aa565b9050632331a96360e11b5f52600452604060245260445ffd5b632f0be49b60e11b5f5260045ffd5b6354cfe65960e01b5f52
60045ffd5b90506020813d602011613bb6575b81613b9f602093836134b0565b810103126131e357613bb0906134f5565b5f6135ee565b3d9150613b92565b90
506020813d602011613bf0575b81613bd9602093836134b0565b810103126131e357613bea90614388565b5f6135ac565b3d9150613bcc565b63dec712ef60e0
1b5f5260045ffd5b631fcf8c4760e11b5f5260045ffd5b638dc30b3960e01b5f5260045ffd5b63c362a96f60e01b5f5260045ffd5b90600581101561339f5760
ff80198354169116179055565b90600582101561339f5752565b613c616143dc565b60018060a01b031690815f52601460205260ff60405f20541690805f1461
3d04576003905b600582101561339f57600583101561339f57818314613cfe5715613cf7575f5b600581101561339f5782036131e3575f516020615aea5f395f
51905f5291613cf4604092855f526014602052613cde81855f20613c34565b613cea84518094613c4c565b6020830190613c4c565ba2565b6003613ca6565b50
505050565b5f90613c86565b601254811015613d235760125f5260205f2001905f90565b634e487b7160e01b5f52603260045260245ffd5b8054821015613d23
575f5260205f2001905f90565b600554811015613d235760055f5260205f209060011b01905f90565b613d70614440565b60018060a01b031690815f52601460
205260ff60405f20541690805f14613de8576004905b600582101561339f57600583101561339f57818314613cfe5715613de157816131e3575f516020615aea
5f395f51905f5291613cf4604092855f526014602052613cde81855f20613c34565b6004613ca6565b5f90613d95565b90613df982613ee0565b15613e7c5760
17546001600160a01b0383811690821614613e77576001600160401b03809160a01c169116808203613e625750506001600160401b0360185416600160016040
1b03431614613e5357613e5190614610565b565b6324619d6960e11b5f5260045ffd5b630670c83560e21b5f5260045260245260445ffd5b505050565b63e2ab
4ae760e01b5f5260045ffd5b5f5b818110613e98575050565b5f7fbb8a6a4669ba250d26cd7a459eca9d215f8307e33aebe50379bc5a3617ec34448201556001
01613e8d565b5f5b828110613ed357505050565b5f82820155600101613ec7565b6001600160a01b03165f9081526014602052604090205460ff166005811015
61339f5760011490565b6001600160401b0381116134815760051b60200190565b6001600160401b03811161348157601f01601f191660200190565b92919261
3f4782613f20565b91613f5560405193846134b0565b8294818452818301116131e3578281602093845f960137010152565b9080601f830112156131e3578160
20613f8c93359101613f3b565b90565b60c4356001600160401b03811681036131e35790565b60e4356001600160401b03811681036131e35790565b35600160
0160401b03811681036131e35790565b6001600160401b036001911601906001600160401b038211613b1d57565b6001600160401b0362278d00911601906001
600160401b038211613b1d57565b6001600160401b03166001600160401b038114613b1d5760010190565b60045460c01c48810290808204481490151715613b
1d5764e8d4a51000810190818111613b1d5764e8d4a50fff01908111613b1d5764e8d4a510006001600160801b0391041690565b9190811015613d235760051b
0190565b356001600160a01b03811681036131e35790565b6001600160801b0360015416620186a0026001600160801b038116908103613b1d5790565b816140
c56143dc565b614149575b60018060a01b031690815f52601460205260ff60405f20541690805f14614142576002905b600582101561339f5760058310156133
9f57818314613cfe571561413b57816131e3575f516020615aea5f395f51905f5291613cf4604092855f526014602052613cde81855f20613c34565b6002613c
a6565b5f906140ef565b600f5460201c6001600160a01b03908116908216036140ca575f80fd5b8051821015613d235760209160051b010190565b9190811015
613d235760051b8101359061011e19813603018212156131e3570190565b9035601e19823603018112156131e35701602081359101916001600160401b038211
6131e35781360383136131e357565b604081529291906001600160a01b036141e68261328a565b1660408501526020810135606085015260018060a01b036142
096040830161328a565b16608085015260608101356001600160801b03811681036131e3576020916001600160801b036142bc921660a0870152608081013560
c08701526001600160401b0361425760a083016132e0565b1660e08701526001600160401b0361427160c083016132e0565b166101008701526142a961429d61
428b60e084018461419d565b610120808b01526101608a0191613502565b9161010081019061419d565b878303603f190161014089015290613502565b930152
565b6001600160a01b03165f9081526014602052604090205460ff16600581101561339f5760031490565b6001600160a01b03165f9081526014602052604090
205460ff16600581101561339f5760021490565b60055480821015614380575f198101908111613b1d5781146143785760018101809111613b1d576001600160
401b0360016143516201518093613d4c565b50015460081c1601906001600160401b038211613b1d576001600160401b03821643109190565b506001905f9056
5b50505f905f90565b51906001600160401b03821682036131e357565b3560ff811681036131e35790565b903590601e19813603018212156131e35701803590
6001600160401b0382116131e3576020019181360383136131e357565b60015f52601b6020527f9fafca4c9c0d5c2cbf85f49fd8ab8212430ce78c2a0cb75b51
e0f9c4f9ace003546001600160401b03168015159081614435575b5061442157565b63317e9b3b60e21b5f52600160045260245ffd5b90504210155f61441a56
5b5f8052601b6020527f584f46c60af19681376031579adb04a2416e54ee5505351c2a8435e3766026ea546001600160401b03168015159081614497575b5061
448457565b63317e9b3b60e21b5f525f60045260245ffd5b90504210155f61447d565b3d156144cc573d906144b382613f20565b916144c160405193846134b0
565b82523d5f602084013e565b606090565b6020815191015190602081106144e5575090565b5f199060200360031b1b1690565b5f806401000003d019600781
858181800909086040516020810191602083526020604083015260206060830152608082015263400000f4600160fe1b0360a08201526401000003d01960c082
015260c0815261455060e0826134b0565b519060055afa61455e6144a2565b9080614605575b156145d05760ff6145776002926144d1565b9316146001831615
036145b4575b60405191602083019182526040830152604082526145a46060836134b0565b905190206001600160a01b031690565b906401000003d019036401
000003d0198111613b1d5790614585565b60405162461bcd60e51b815260206004820152600d60248201526c1b5bd9195e1c0819985a5b1959609a1b60448201
52606490fd5b506020815114614565565b601754906001600160a01b031667ffffffffffffffff60a01b61464a6001600160a01b03198416831760a01c600160
0160401b0316613fcf565b60a01b168163ffffffff60e01b84161717806017557f0e49bd8bbce34618e6af3bb74d587a65fa2a594df80b7cc21d690ee78c6d7a
6960206001600160401b0380431693848219601854161760185560405194855260a01c169460018060a01b031692a4565b905f80809360405160208101918252
602081526146ce6040826134b0565b519071f90827f1c53a10cb7a02335b1753200029355afa6146ed6144a2565b9080614712575b6146fb5750565b90915060
20818051810103126131e3576020015190565b506020815110156146f4565b908160209103126131e357516001600160a01b03811681036131e35790565b9391
9590946010549360ff8560e81c16976011548711801590614b13575b8015614b07575b614af95763ffffffff600f5416976147876001600160401b0360015460
801c16613fcf565b96604051602081019060443582526064356040820152604081526147ac6060826134b0565b519020946040516020810190608435825260a4
35604082015260c4356001600160401b03811681036131e3576001600160401b0316606082015260e4356001600160401b03811681036131e357600160016040
1b031660808201526080815261481660a0826134b0565b51902096369061482592613f3b565b80519060200120976040519960208b019b7fdea0f5bce3cdcb7a
6f79e17b92916ec551d9e09aa3b08697f87bfaeb68633c928d5260408c01528260a81c6001600160401b031660608c015260808b01526001600160401b031660
a08a0152600160a01b600190031660c08901526001600160401b031660e08801526001600160401b031661010087015261012086015261014085015261016084
01526101808301526101a08201526101a081526148de6101c0826134b0565b51902060405160208101907f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b
0ffacaa9a75d522b39400f8252604081017fe17337f79206a015e0451a0d8a3f22c09d7c6d3f7966361afa60e4ddcd8cd1ff9052606081017fc89efdaa54c0f2
0c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc690524660808201523060a082015260a0815261497560c0826134b0565b51902090604051906020
82019261190160f01b845260228301526042820152604281526149a36062826134b0565b5190208251926149b284613f09565b93604051946149c190866134b0
565b808552601f19906149d190613f09565b013660208601375f5b8151811015614aee57614a1b60206149f28385614166565b51604051809381926319045a25
60e01b83528860048401526040602484015260448301906134d1565b038162051653608c1b5afa5f9181614abe575b50614a3d575050505050505f90565b6001
600160a01b038116908115908115614aad575b50614aa3575f5b828110614a76575090600191614a6f8288614166565b52016149da565b816001600160a01b03
614a89838a614166565b511614614a9857600101614a59565b505050505050505f90565b5050505050505f90565b614ab79150613ee0565b155f614a52565b61
4ae091925060203d8111614ae7575b614ad881836134b0565b81019061471e565b905f614a2e565b503d614ace565b509192505051101590565b505050505050
505050505f90565b50895160125410614762565b50888a511061475b565b8015614b4557600a5490815f52600b60205260405f205560018101808211613b1d57
600a5590565b505f1990565b601254600160401b81101561348157806001614b6c92016012556012613d37565b81546001600160a01b0393841660039290921b
91821b9390911b1916919091179055565b6020818303126131e3578051906001600160401b0382116131e3570181601f820112156131e357805190614bc38261
3f20565b92614bd160405194856134b0565b828452602083830101116131e357815f9260208093018386015e8301015290565b91908260409103126131e35761
3f8c6020614c0c846134f5565b9301614388565b6018546001600160401b0343168160c01c03615064575b506019546001600160401b03811660088110156150
505760016001600160401b03910116906001600160401b0319161760195560018060a01b03166040516306fdde0360e01b81525f81600481855afa9081156131
d8575f91615036575b506040516395d89b4160e01b81525f81600481865afa9081156131d8575f9161501c575b5060405163e5a6b10f60e01b8152915f836004
81875afa9283156131d8575f93614ff8575b50601f8151118015614fed575b8015614fe2575b614fd3576040918251614cf884826134b0565b60018152602081
0190601f198501368337805115613d235786825284516323143aff60e01b81526004810188905291858360248161100f60921b5afa928315614fc9575f93614f
a9575b508215614e9b575b505015614e8c57601a54835160208101918252868582015260a06060820152614da4816110dc614d92614d8060c08401896134d156
5b838103601f19016080850152876134d1565b828103601f190160a0840152896134d1565b519020601a558251614db581613495565b60018152602081016001
8152865f526006602052845f209151151560ff8019845416911617825551151561ff0082549160081b169061ff00191617905560075492600160401b84101561
3481577f4ac4dcc08b0c26c3fb6b58c64c1392b7934b1ce6b0382a5986ea5c3de795e05394614e7a614e8793614e40876001614e6c99016007556007613d3756
5b81549060031b908b821b9160018060a01b03901b191617905583519687966060885260608801906134d1565b9086820360208801526134d1565b9184830390
8501526134d1565b0390a2565b638074d40160e01b5f5260045ffd5b855163a783dc9960e01b8152602060048201529151602483018190529192508291604483
0191905f5b818110614f8757505050908060209203815f61100f60921b5af18015614f4e57614f58575b5082516323143aff60e01b8152600481018690528381
60248161100f60921b5afa908115614f4e575f91614f20575b505f80614d4a565b614f409150843d8611614f47575b614f3881836134b0565b810190614bf256
5b505f614f18565b503d614f2e565b84513d5f823e3d90fd5b6020813d602011614f7f575b81614f71602093836134b0565b810103126131e35751614ee9565b
3d9150614f64565b82516001600160a01b0316845285945060209384019390920191600101614ec4565b614fc1919350863d8811614f4757614f3881836134b0
565b50915f614d42565b86513d5f823e3d90fd5b630a49a9e760e31b5f5260045ffd5b50601f835111614ce5565b50601f825111614cde565b6150159193503d
805f833e61500d81836134b0565b810190614b90565b915f614cd1565b61503091503d805f833e61500d81836134b0565b5f614cac565b61504a91503d805f83
3e61500d81836134b0565b5f614c88565b6305a3146760e21b5f52600860045260245ffd5b6001600160c01b03164360c01b6001600160c01b03191617601855
6019805467ffffffffffffffff191690555f614c2a565b356001600160801b03811681036131e35790565b906009545f91815f52600b60205260405f20546040
5160208101906150d4816110dc868a866141ce565b519020036155b257815f52600b6020528060405f20551561559e575b506150fa82614083565b9160c08101
6001600160401b0361511082613fbb565b16156153cd5760a08201629896806001600160401b0361512f83613fbb565b1611615356576001600160401b036151
4682613fbb565b16615251575060205f516020615aca5f395f51905f529260609260ff60155460081c16158015615236575b8061521c575b806151f5575b1590
816151d0575b506001600160801b0361519a60408401614083565b976151a6868501615096565b90604051985060018060a01b03168852168387015215604086
015201359360018060a01b031692a3565b6151ef906151e86151e2878601615096565b91613fbb565b90896158d1565b5f615185565b50615217615205604084
01614083565b615210868501615096565b90896155f2565b61517d565b5061523161522c60408401614083565b615a6d565b615177565b5061524b6152466040
8401614083565b6142c1565b15615171565b61525d60408401614083565b61527261526c60608601615096565b92613fbb565b9061528060e08601866143aa56
5b9092303b156131e357604051625d97ef60e01b81526001600160a01b03808b16600483015290931660248401526001600160801b0394909416604483015260
2086013560648301526001600160401b0393909316608482015260c060a4820152915f91839182916152f59160c4840191613502565b038183305af190816153
29575b505f516020615aca5f395f51905f5292606092602092615322578561517d565b600161517d565b60209194509260609261534a5f5f516020615aca5f39
5f51905f52966134b0565b5f959250925092615302565b509291506060602082615387835f516020615aca5f395f51905f529501966153806151e28961509656
5b90876158d1565b6001600160801b036153a461539e60408401614083565b97615096565b604080516001600160a01b03988916815292909116848301525f90
8201529101359490931692a3565b508092506153db9150614083565b6153e361402a565b91606081016001600160801b036153f982615096565b166001600160
801b0385161161558d575b5f936001600160801b038116151580615570575b615566575b5061543884615433604093615096565b6158b1565b91019161544761
522c84614083565b8061554d575b156154be577f0f7ef08806234f85aaee43d3ba4589c3bc6d5ac3fc8edd56fc3d91cc7553bdcb92614e87906001600160a01b
039061548a90614083565b1694604051938493849160409194936001600160801b038092606086019760018060a01b0316865216602085015216910152565b60
01600160a01b0381165f9081526008602052604090207f5fea28d0adb7d877ae3259768f41ad6741aa1784c4475746dd931364f62e68a193614e879161550482
614083565b60018060a01b03165f5260205260405f206001600160801b0361552a8682845416615891565b82546001600160801b031916911617905560016001
60a01b039061548a90614083565b506155618261555b85614083565b836155f2565b61544d565b9350615438615423565b505f546155889082906001600160a0
1b0316866155f2565b61541e565b925061559883615096565b9261540a565b60018101809111613b1d576009555f6150f0565b632e1aaf2760e21b5f5260045f
fd5b6155ca81615a6d565b156155d25750565b6376ecd09f60e11b5f9081526001600160a01b0391909116600452602490fd5b60405163fbea9d6760e01b8152
6001600160a01b03831660048201529092906020816024816103f760961b5afa5f9181615762575b5061563457505050505f90565b6040805163b72b0c5960e0
1b81526001600160a01b03958616600482018190523060248301529590921660448301528160648161100f60921b5afa5f9181615719575b5061568457505050
505f90565b156157125760405163a9059cbb60e01b81526001600160a01b039290921660048301526001600160801b0316602482015290602090829060449082
905f905af15f91816156d6575b50613f8c57505f90565b9091506020813d60201161570a575b816156f2602093836134b0565b810103126131e3576157039061
34f5565b905f6156cc565b3d91506156e5565b5050505f90565b9091506040813d60401161575a575b81615735604093836134b0565b810103126131e3576003
602061574a836134f5565b92015110156131e357905f615677565b3d9150615728565b61577c91925060203d602011614ae757614ad881836134b0565b905f61
5627565b60ff1660028114908115615795575090565b600391501490565b80158015615846575b615835575f9081906401000003d01990600790829081818009
09086040516020810191602083526020604083015260206060830152608082015263800001e9600160ff1b0360a08201526401000003d01960c082015260c081
5261580b60e0826134b0565b519060055afa6158196144a2565b9015801561583a575b615835576158316001916144d1565b1490565b505f90565b5060208151
1415615822565b506401000003d0198110156157a6565b60155460ff81161561588d5760081c60ff168061587e575b61587b576155ca816142ea565b50565b50
615888816142c1565b61586e565b5050565b906001600160801b03809116911601906001600160801b038211613b1d57565b906001600160801b038091169116
03906001600160801b038211613b1d57565b916001600160401b031691604051906158e982613466565b60018060a01b03169081815260208101848152600160
0160801b03604083019416938481526001600160801b03600354916040519360208501955f875260018060a01b03905116604086015260018060a01b03905116
60608501525116608083015260a082015260a0815261595f60c0826134b0565b519020916018546001600160401b0343166001600160401b038260401c160361
5a45575b50601854916001600160401b038360801c169160e6831015615a31577fadf6f2901dd7af2f28a594f47a925894a08d4de10609dff591a80642648775
c59360609360016001600160401b0360801b910160801b16906001600160401b0360801b1916176018558460035560045490615a036001600160401b03831661
400d565b6001600160401b03811680936001600160401b031916176004555060405192835260208301526040820152a3565b6301eb386f60e71b5f5260e66004
5260245ffd5b600160401b600160c01b0319164360401b67ffffffffffffffff60401b16176018555f615983565b60ff6015541615908115615a7f575090565b
613f8c91506142ea56fedf6966c971051c3d54ec59162606531493a51404a002842f56009d7e5cf4a8c73e5479494e0a078954a7ff8437aeca3bf7519b51a2fc
06b3821251147ff9c5f765042ea6dad60c26f055e80ec401b3437c854ed586a0704d305bb4e9ea4518cf2359a069f5d7871f8f60ad861112ebe12dcf2ba55225
c32ec04564d494afc69ba26469706673582212203ede85372f6983faf7c0aa525decca4041a5f66d5585d6a6e187c8200f85973d64736f6c63430008230033
```

### T10 ZONE_VERIFIER_RUNTIME (installed at 0x5A56000000000000000000000000000000000000 at T10)

Length 373 bytes, keccak256 `0xf3ab166b6d8637bb2f15ac5037b4546611339fc88e4b03b00b89559f7f2822a2`.

```text
6080806040526004361015610012575f80fd5b5f3560e01c637106a43e14610025575f80fd5b346100c8576101c03660031901126100c85760043563ffffffff
8116036100c85761004e6100cc565b506100576100e3565b506100606100fa565b5060403660a31901126100c85760803660e31901126100c8576101843567ff
ffffffffffffff81116100c85761009a903690600401610111565b50506101a4359067ffffffffffffffff82116100c8576100c0602092369060040161011156
5b505060018152f35b5f80fd5b6024359067ffffffffffffffff821682036100c857565b6044359067ffffffffffffffff821682036100c857565b6084359067
ffffffffffffffff821682036100c857565b9181601f840112156100c85782359167ffffffffffffffff83116100c857602083818601950101116100c85756fe
a2646970667358221220671cd43a35aaf7a79d3e551ccd060893d3f3004756d7d2c69fb7baae9867a7f864736f6c63430008230033
```

### T10 ZONE_MESSENGER_RUNTIME (installed at 0x5A4D000000000000000000000000000000000000 at T10)

Length 1858 bytes, keccak256 `0x1ea2e80521c58fd7966e1fd370f84ac297261c7197f097ffc879de1890e0a1a0`.

```text
6080806040526004361015610012575f80fd5b5f3560e01c90816311da5261146100565750637b9a730114610032575f80fd5b34610052575f36600319011261
005257604051612d7960911b8152602090f35b5f80fd5b346100525760e0366003190112610052576004359063ffffffff821680920361005257602435600160
0160a01b03811690819003610052576064356001600160a01b038116939084900361005257608435916fffffffffffffffffffffffffffffffff831680930361
00525760a4359167ffffffffffffffff83168093036100525760c4359567ffffffffffffffff871161005257366023880112156100525786600401359567ffff
ffffffffffff871161005257366024888a010111610052575f546106ba5760015f9081556390b7f6fd60e01b82526004820184905281602481612d7960911b5a
fa90811561037b575f916104d3575b50602001516001600160a01b031633036104c457604051631b32199b60e01b8152602081600481335afa90811561037b57
5f9161048a575b501580610416575b6104075760405163fbea9d6760e01b8152600481018290526020816024816103f760961b5afa90811561037b575f916103
cd575b506040805163b72b0c5960e01b8152600481018690523060248201526001600160a01b0390921660448301528160648161100f60921b5afa9081156103
7b575f91610386575b50156103325760405163a9059cbb60e01b81528160048201528560248201526020816044815f885af190811561037b575f91610341575b
50156103325760e45f928760209860246040519b8c9a8b998a96630a137ff560e01b885260048801523384880152604435604488015260648701526084860152
60c060a48601528260c486015201848401378181018301859052601f01601f19168101030193f15f91816102ed575b506102c25763be51ced360e01b5f526004
5ffd5b6001600160e01b03191663f5ec800b60e01b016102de575f8055005b63be51ced360e01b5f5260045ffd5b9091506020813d60201161032a575b816103
09602093836106c9565b8101031261005257516001600160e01b0319811681036100525790826102ae565b3d91506102fc565b6312171d8360e31b5f5260045f
fd5b90506020813d602011610373575b8161035c602093836106c9565b810103126100525761036d906106ff565b8861023f565b3d915061034f565b6040513d
5f823e3d90fd5b90506040813d6040116103c5575b816103a1604093836106c9565b8101031261005257600360206103b6836106ff565b920151101561005257
88610208565b3d9150610394565b90506020813d6020116103ff575b816103e8602093836106c9565b81010312610052576103f9906106eb565b886101c2565b
3d91506103db565b63793cd94b60e11b5f5260045ffd5b506040516395a8c58d60e01b81526004810182905260036024820152602081604481335afa90811561
037b575f91610450575b501561018e565b90506020813d602011610482575b8161046b602093836106c9565b810103126100525761047c906106ff565b886104
49565b3d915061045e565b90506020813d6020116104bc575b816104a5602093836106c9565b81010312610052576104b6906106ff565b88610186565b3d9150
610498565b63efc26b5760e01b5f5260045ffd5b90503d805f833e6104e481836106c9565b8101906020818303126100525780519067ffffffffffffffff8211
610052570190610120828203126100525760405191610120830183811067ffffffffffffffff82111761068e57604052805163ffffffff811681036100525783
5261054c602082016106eb565b602084015261055d604082016106ff565b604084015261056e606082016106ff565b606084015261057f608082016106eb565b
608084015260a081015167ffffffffffffffff811161005257810182601f820112156100525780519067ffffffffffffffff821161068e578160051b60405192
6105cc60208301856106c9565b83526020808401918301019185831161005257602001905b8282106106a25750505060a084015260c081015160ff8116810361
00525760c084015261061360e082016106eb565b60e08401526101008101519067ffffffffffffffff8211610052570181601f820112156100525780519067ff
ffffffffffffff821161068e5760405192610664601f8401601f1916602001856106c9565b8284526020838301011161005257815f9260208093018386015e83
0101526101008201528861014e565b634e487b7160e01b5f52604160045260245ffd5b602080916106af846106eb565b8152019101906105e4565b6336a4d21b
60e11b5f5260045ffd5b90601f8019910116810190811067ffffffffffffffff82111761068e57604052565b51906001600160a01b038216820361005257565b
519081151582036100525756fea264697066735822122083c0307c38ab063b353a7ce57e3ca8791b9f19dd080e5e2d9657544a4d53b5ad64736f6c6343000823
0033
```

### T13 T13_ZONE_PORTAL_RUNTIME (installed at 0x5AD1000000000000000000000000000000000000 from T13)

Length 23994 bytes, keccak256 `0xbb0c0e14d5c2e15ca4aa1aaeb8d5c7bfdcf35fdadac5380ff93d38f962e4c41e`.

```text
60c06040526004361015610011575f80fd5b5f60a0525f3560e01c80625d97ef14613318578062ebfdb41461328357806303dd6f3414610dd3578063046f7da2
1461321b57806304a3b098146131d25780630e18b681146131375780630e86bbdc146130b05780630f3804b81461303257806310cea85714612ff5578063129c
824014612fbe5780631950dd1114612f995780631b32199b14612f7357806321b4deee146123eb5780632678224714612f4957806327c71b5014612eb8578063
2b7ac3f314612e8e5780632c37826e14612e635780632dfdf0b514612e3b5780633488ce0d14612dc45780633557796214612d87578063370ddf9914612d6057
806337f981d814612ce257806339dc015d14612bac5780633a6b889b14612b815780633b667e7414610d565780633cb747bf14612b5757806340eedabb14612b
2d5780634256ce3814612b0e578063430f8b4f14612aef57806345c5d2fb14612ad05780634cd6c7c7146124445780634fdf2ec2146123f057806356eb688f14
6123eb5780635c975abb146123c05780635e53dcd3146123a3578063652ef10b146121fa5780636d46e987146121d257806371649b6e146121ae578063748538
d91461216d57806375829def146120ee57806378d8599e146120545780638081a8b21461203557806383888ecc1461200a57806383a146b314611fee57806384
56cb5914611eec57806384b7112314611ecd578063857e85f814611e6e57806386012b4514611ad457806386829b82146112b557806386f47e55146112965780
638976248d146112695780638d8bd5fb1461124157806390f595981461120457806391aa3f041461106357806394ce88b014611044578063959f47c314610f6d
57806395a8c58d14610ef8578063996329a214610edb5780639a97784b14610e2e5780639ecd4cc014610df7578063b01f22e414610dd3578063b02690f21461
0d73578063b1cf9e3d14610d56578063b456c0dd14610d37578063b83c755f14610d0f578063be2a63ee14610ce4578063bf4c541114610bc7578063bffa55d5
14610af0578063c690908a146109a1578063ccd537ca14610979578063cfaabb4d1461094b578063d179978a14610926578063e09eae101461089f578063e471
784914610880578063e84abe6914610855578063ecf79a4e1461082d578063ef10b187146105b6578063f125af6b1461058b578063f22a195e1461056c578063
f490ca9614610548578063f6087442146104b1578063f706cfbf14610492578063f851a44014610467578063fb2f1206146104455763fe136c4e146103c2575f
80fd5b3461043f57602036600319011261043f576103db613558565b6040516103e78161378f565b60a0518152602060a05191015260018060a01b031660a051
52600660205260408060a051208151906104188261378f565b5460ff6020818316151593848152019160081c161515815282519182525115156020820152f35b
60a05180fd5b3461043f5760a05136600319011261043f57602060045460c01c604051908152f35b3461043f5760a05136600319011261043f5760a051546040
516001600160a01b039091168152602090f35b3461043f5760a05136600319011261043f576020604051620186a08152f35b3461043f57602036600319011261
043f576104ca6136ad565b60a051546001600160a01b031633036105355760ff5f516020615d255f395f51905f52916104f66146e6565b61052c821960155416
838315151617918260155560405193849360081c1690839092916020906040830194151583521515910152565b0390a160a05180f35b637bfa4b9f60e01b60a0
5152600460a051fd5b3461043f5760a05136600319011261043f576020604051670de0b6b3a76400008152f35b3461043f5760a05136600319011261043f5760
20600254604051908152f35b3461043f5760a05136600319011261043f5760206001600160401b0360195460401c16604051908152f35b3461043f5760a03660
0319011261043f576004356105d2613718565b9060443560ff8116919082900361043f5760a051546001600160a01b03163314158061081d575b61080a576106
0683615a65565b156107f75761061481615a7f565b156107f75760206040519281840130815283604086015260ff861694856060820152606081526106456080
826137aa565b51902090604051918252828201526064356040820152608435606082015260a05160a05152608060a0519160015afa156107ea5761068760a051
5193826147fd565b926001600160a01b031680159081156107d6575b506107c3576001600160401b0343166040516106b681613760565b828152602081019084
82526040810190838252600554600160401b8110156107ab578060016106e89201600555614008565b9190916107925760ff916001915181550192511668ffff
ffffffffffff008354925160081b169168ffffffffffffffffff1916171790556005545f19810190811161077a577f854006acd102b75cc8cfe8e0fc954c82e2
2610d6d4b4ba4f0f19e896ed6397f29460a0946040519485526020850152600180861b0316604084015260608301526080820152a160a05180f35b634e487b71
60e01b60a051526011600452602460a051fd5b634e487b7160e01b60a0515260a051600452602460a051fd5b634e487b7160e01b60a051526041600452602460
a051fd5b6392536faf60e01b60a05152600460a051fd5b6001600160a01b038516141590508461069b565b6040513d60a051823e3d90fd5b632f0be49b60e11b
60a05152600460a051fd5b6314f8a09f60e21b60a05152600460a051fd5b506108273361430b565b156105f9565b3461043f5760a05136600319011261043f57
60206001600160801b0360015416604051908152f35b3461043f5760a05136600319011261043f5760206001600160401b0360045460401c16604051908152f3
5b3461043f5760a05136600319011261043f576020600754604051908152f35b3461043f57602036600319011261043f576108b86135ae565b60a05154600160
0160a01b0316330361053557600480546001600160c01b031660c083901b6001600160c01b0319161790556040516001600160401b0390911681527f66bcd750
662bb66118e25a8e421ae73974634d9af2d44fb9e600d250917fe69090602090a160a05180f35b3461043f5760a05136600319011261043f57602063ffffffff
600f5416604051908152f35b3461043f57602036600319011261043f5760043560a05152600b6020526020604060a0512054604051908152f35b3461043f5760
a05136600319011261043f5760206001600160401b03601c5416604051908152f35b3461043f57602036600319011261043f576109ba613558565b60a0515460
01600160a01b031633036105355760018060a01b0381168060a05152600660205260ff604060a051205416610add576040516335ec42c960e01b815260048101
9190915260208160248161083f60921b5afa9081156107ea5760a05191610aa3575b5015610a9057601c5460ff8160401c1615610a7d57600754600160016040
1b0391909116810390811161077a5760081115610a6557610a5f90614f80565b60a05180f35b6305a3146760e21b60a051526008600452602460a051fd5b63a1
9cf2a960e01b60a05152600460a051fd5b631fcf8c4760e11b60a05152600460a051fd5b90506020813d602011610ad5575b81610abe602093836137aa565b81
01031261043f57610acf906137ef565b82610a21565b3d9150610ab1565b632909298f60e11b60a05152600460a051fd5b3461043f5760203660031901126104
3f57610b09613558565b610b12336158a3565b60a080516001600160a01b038316908190526008602081815283516040808220335f8181529185528282205493
8790529484529551819020848752909252932080546001600160801b031916905590926001600160801b0390921691610b799183916158d4565b15610bb45760
20916040518281527fffd3bbab073ab4b2d0792c270104924c14c285a153b9acddabae166395d2eb5c843392a3604051908152f35b63be51ced360e01b60a051
52600460a051fd5b3461043f57602036600319011261043f57600435600281101561043f5760a051546001600160a01b031633036105355760195460401c6001
600160401b03164210610cd157610c158161368f565b8060a05152601b6020526001600160401b03604060a051205416610cb1577f839069134f9aac5b7c48da
0389dd17d6579bb89ebdddc7fbd83bf64af2dd2ef26020610c686001600160401b0342166141dd565b610c718461368f565b8360a05152601b82526001600160
401b03604060a05120911690816001600160401b0319825416179055610ca48461368f565b604051908152a260a05180f35b60a05163667ccc6f60e11b905261
0cc78161368f565b600452602460a051fd5b63c362a96f60e01b60a05152600460a051fd5b3461043f5760a05136600319011261043f5760206001600160401b
0360045460801c16604051908152f35b3461043f5760a05136600319011261043f5760206001600160401b0360185416604051908152f35b3461043f5760a051
36600319011261043f576020601a54604051908152f35b3461043f5760a05136600319011261043f57602060405160088152f35b3461043f5760203660031901
1261043f5760075460043590811015610dbb5760a08051600790525160208082209092015460405160039290921b1c6001600160a01b03168152f35b634e487b
7160e01b60a051526032600452602460a051fd5b3461043f576020610def610de63661361b565b9392909261381c565b604051908152f35b3461043f57602036
600319011261043f5760406001600160401b03610e1d60043561461d565b835191151582529091166020820152f35b3461043f57602036600319011261043f57
600435604051610e4e81613760565b60a051815260a0516020820152604060a051910152600554811015610ec557610e78606091614008565b50600160016040
1b03604051610e8d81613760565b60ff600184549485845201549183604060208301928486168452019360081c16835260405194855251166020840152511660
40820152f35b637f455d3760e11b60a05152600452602460a051fd5b3461043f5760a05136600319011261043f576020604051601f8152f35b3461043f576040
36600319011261043f57610f11613558565b60243590600582101561043f5760a080516001600160a01b0392909216909152601460205251604090205460ff16
906005821015610f555760209114604051908152f35b634e487b7160e01b60a051526021600452602460a051fd5b3461043f5760a05136600319011261043f57
60405160a051600c54610f9181613728565b80845290600181169081156110205750600114610fd1575b610fcd83610fb9818503826137aa565b604051918291
6020835260208301906137cb565b0390f35b919050600c60a051525f516020615d055f395f51905f529160a051905b8082106110065750909150810160200161
0fb9610fa9565b919260018160209254838588010152019101909291610fee565b60ff191660208086019190915291151560051b84019091019150610fb99050
610fa9565b3461043f5760a05136600319011261043f576020600954604051908152f35b3461043f57604036600319011261043f576004356001600160401b03
811161043f576110939036906004016136e8565b9061109d3361430b565b1561080a5760195460401c6001600160401b03164210610cd157600e546111f15760
01600e556001600160401b036110df60045482808260401c16911661419f565b1660e681119081156111dc575b506111c4576110fa826140ab565b9061110860
405192836137aa565b828252601f19611117846140ab565b0136602084013782602435815b61116857505060a0515b8381106111405760a051600e81905580f3
5b806111626111516001938786614484565b61115b8387614470565b519061538c565b0161112e565b5f19820182811161077a576111b0611190828461118861
11a2958a614470565b528887614484565b926040519283916020830195866144d8565b03601f1981018352826137aa565b51902090801561077a575f19019081
611124565b6301eb386f60e71b60a0515260e6600452602460a051fd5b60e69081039150811161077a578211836110ec565b630b5c738160e01b60a051526004
60a051fd5b3461043f57604036600319011261043f5761121d613558565b6112256136bc565b60a051546001600160a01b0316330361053557610a5f916143c6
565b3461043f5760a05136600319011261043f5760206001600160801b0360165416604051908152f35b3461043f5760a05136600319011261043f5760206112
856143a1565b6001600160801b0360405191168152f35b3461043f5760a05136600319011261043f576020604051629896808152f35b3461043f576101803660
0319011261043f5760043563ffffffff8116810361043f576112df61356e565b6044359190821515830361043f5760643592831515840361043f576084356001
600160401b03811161043f576113199036906004016136e8565b9160a4356001600160401b03811161043f576113399036906004016136e8565b60c435979092
906001600160a01b038916890361043f5760e435916001600160a01b038316830361043f57610104356001600160401b03811161043f57611384903690600401
6136e8565b610124356080819052909a91949060ff8116900361043f57610144356001600160a01b038116929083900361043f57610164356001600160401b03
811161043f576113d39036906004016135ee565b93909230615ad160901b14611ac157735af1ffffffffffffffffffffffffffffffffffff193301611aae5760
10549260ff8460a01c16611a9c578f63ffffffff600f5491640100000000600160c01b039060201b169216906001600160401b0360c01b161717600f55600180
60a01b03166bffffffffffffffffffffffff60a01b60a05154161760a05155600160a01b916affffffffffffffffffffff60a81b16171760105560155461ff00
85151560081b169060ff851515169061ffff191617176015556001600160401b0382116107ab576114b1600c54613728565b601f8111611a4b575b5060a05190
601f83116001146119c7579180915f516020615d255f395f51905f5295949360a051926119bc575b50508160011b915f199060031b1c191617600c555b604080
5191151582529115156020820152a186158080156119b2575b80156119a5575b8015611997575b6119795760a0515b8881106118f5575060125488146118b757
5b60a051806118a1575b61188f5760a0515b6012548110156115c15780611567600192613fc7565b838060a01b0391549060031b1c168060a051526014602052
604060a0512060ff1981541690555f516020615d655f395f51905f526040805160a0515060a0515085815260a0515060a0515060a0516020820152a201611551
565b50889760125460a0516012558061187a575b5060a0515b81811061181457506017546001600160a01b03168015159081611803575b506117f05760105460
ff60e81b60805160e81b169060ff60e81b1916178060105560405190826040830160ff60805116845260406020850152526060820192859060a0515b81811061
17ca5750505090806001600160401b037f9282e5956b9751944c6e527bb3fa37aed57d3cfb67979c8962f561a194fc0bc59360a81c16930390a2610dbb576116
8961168e9161438d565b614e18565b60a0515b82811061174857505060a05190505b8281106116b157610a5f84614f80565b6001600160a01b036116cc6116c7
83868661437d565b61438d565b16906001600160a01b038616821461043f578160a05152601460205260ff604060a0512054166005811015610f555761043f57
60a080518390526014602090815290516040808220805460ff19166002908117909155815192835292820192909252600193915f516020615d655f395f51905f
5291a2016116a1565b6001600160a01b0361175e6116c783868661437d565b16908160a05152601460205260ff604060a0512054166005811015610f55576104
3f5760a080518390526014602090815290516040808220805460ff19166003908117909155815192835292820192909252600193915f516020615d655f395f51
905f5291a201611692565b909194602080600192838060a01b036117e28a613584565b16815201960192910161163b565b63cbd28fa360e01b60a05152600460
a051fd5b61180d915061430b565b158a6115f6565b806118256116c7600193858861437d565b61182e81614eb8565b60a0805184821b85900392909216918290
526014602090815290516040808220805460ff19168717905580519182529181018590525f516020615d655f395f51905f529190a2016115d8565b6118899060
1260a051526142b6565b896115d3565b621194ed60e51b60a05152600460a051fd5b5060ff60105460e81c1660ff6080511614611549565b60a0515b88811061
18c9575b50611540565b6118df6118da6116c7838c8761437d565b61430b565b156118ec576001016118bb565b5060a0516118c3565b6001600160a01b036119
0b6116c7838c8761437d565b168015611979578060a05152601460205260ff604060a0512054166005811015610f5557801590811561198c575b501561043f57
60a0515b82811061195457505060010161152e565b816001600160a01b0361196b6116c7848f8a61437d565b161461197957600101611943565b6352013e3360
e01b60a05152600460a051fd5b60011490508c611939565b508760ff6080511611611526565b5060ff608051161561151f565b5060088811611518565b013590
508d806114e7565b601f19831691600c60a051525f516020615d055f395f51905f529260a0515b818110611a3357509160019391855f516020615d255f395f51
905f529897969410611a1a575b505050811b01600c556114fc565b01355f19600384901b60f8161c191690558d8080611a0c565b919360206001819287870135
815501950192016119e6565b828111156114ba57611a8c90600c60a05152601f840160051c9060208510611a92575b601f82910160051c03905f516020615d05
5f395f51905f52016142f0565b8c6114ba565b60a0519150611a6e565b62dc149f60e41b60a05152600460a051fd5b631966391b60e11b60a05152600460a051
fd5b63b25caa5160e01b60a05152600460a051fd5b3461043f57604036600319011261043f576004356001600160401b03811161043f57611b04903690600401
6136e8565b611b0c613718565b60a051546001600160a01b031633036105355781158015611e64575b8015611e59575b8015611e4d575b6119795760a0515b82
8110611dbe5750601254821480611d83575b80611d6f575b61188f5760a0515b601254811015611bcf5780611b75600192613fc7565b838060a01b0391549060
031b1c168060a051526014602052604060a0512060ff1981541690555f516020615d655f395f51905f526040805160a0515060a0515085815260a0515060a051
5060a0516020820152a201611b5f565b509060125460a05160125580611d5a575b5060a0515b818110611cf457506017546001600160a01b0316801515908161
1ce3575b506117f0576010549060ff60e81b8360e81b1691611c396001600160401b038460ff60e81b198416178060105560a81c166141fd565b926001600160
401b0360a81b8460a81b169168ffffffffffffffffff60a81b19161717601055806040519360ff6040860191168552604060208601525260608301939060a051
5b818110611cbd576001600160401b0384167f9282e5956b9751944c6e527bb3fa37aed57d3cfb67979c8962f561a194fc0bc586880387a260a05180f35b9091
94602080600192838060a01b03611cd58a613584565b168152019601929101611c80565b611ced915061430b565b1584611c03565b80611d056116c760019385
8861437d565b611d0e81614eb8565b60a0805184821b85900392909216918290526014602090815290516040808220805460ff19168717905580519182529181
018590525f516020615d655f395f51905f529190a201611be5565b611d6990601260a051526142b6565b83611be0565b5060ff60105460e81c1660ff82161461
1b57565b60a0515b838110611d95575b50611b51565b611da66118da6116c783878961437d565b15611db357600101611d87565b505060a05184611d8f565b60
01600160a01b03611dd46116c783868861437d565b168015611979578060a05152601460205260ff604060a0512054166005811015610f55578015908115611e
42575b501561043f5760a0515b828110611e1d575050600101611b3e565b816001600160a01b03611e346116c784898b61437d565b161461197957600101611e
0c565b600114905086611e02565b508160ff821611611b36565b5060ff811615611b2f565b5060088211611b28565b3461043f57604036600319011261043f57
611e87613558565b611e8f61356e565b9060018060a01b031660a051526008602052604060a051209060018060a01b03165f5260205260206001600160801b03
60405f205416604051908152f35b3461043f5760a05136600319011261043f576020601254604051908152f35b3461043f5760a05136600319011261043f5760
195460401c6001600160401b03164210610cd157611f1b61474a565b60a051546001600160a01b031633141580611fde575b80611fb6575b611fa357611f4d60
01600160401b0342166141dd565b67ffffffffffffffff60401b6019549160401b169067ffffffffffffffff60401b191617601955337f477a1104043ff48a8d
2126e5d02d0d4977cb0b2ee7cd4030cb8823007db90f3660a05160a051a260a05180f35b63248ccfdb60e11b60a05152600460a051fd5b5060a0805133905260
1460205251604090205460ff166005811015610f555760041415611f37565b50611fe83361430b565b15611f31565b3461043f5760a05136600319011261043f
576020611285614334565b3461043f5760a05136600319011261043f5760206001600160401b0360105460a81c16604051908152f35b3461043f5760a0513660
0319011261043f576020600a54604051908152f35b3461043f57602036600319011261043f5761206d613598565b60a051546001600160a01b03163303610535
576001600160801b0316670de0b6b3a764000081116120db576020817fede0c86e4d0b914b0ba2f68c3359e9ccbcdece694913dcbdf50affe96900e1e8926001
600160801b03196016541617601655604051908152a160a05180f35b630d62f21160e11b60a05152600460a051fd5b3461043f57602036600319011261043f57
612107613558565b60a051546001600160a01b031690338290036105355760018060a01b031690816bffffffffffffffffffffffff60a01b600d541617600d55
7fe5cd1c804f1c9cc6d7009e4c0fb532f0e2d8863524c3323a6b3790c3f80bf25c60a05160a051a360a05180f35b3461043f57602036600319011261043f5760
01600160a01b0361218e613558565b1660a051526006602052602060ff604060a0512054166040519015158152f35b3461043f5760a05136600319011261043f
57602060ff601554166040519015158152f35b3461043f57602036600319011261043f5760206121f06118da613558565b6040519015158152f35b3461043f57
602036600319011261043f576004356001600160401b03811161043f5761222a9036906004016135ee565b906122343361430b565b1561080a57600160016040
1b0382116107ab57612252600c54613728565b601f811161235d575b5060a05191601f81116001146122cc5760a0517ff4e00967b25e707df96d88676243b33b
e84847ef27615af8ef91290b52294fc693826122c1575b508160011b905f198360031b1c191617600c555b61052c6040519283926020845260208401916137fc
565b905082013584612296565b601f19811692600c60a051525f516020615d055f395f51905f529060a0515b8581106123455750827ff4e00967b25e707df96d
88676243b33be84847ef27615af8ef91290b52294fc6951061232c575b5050600181811b01600c556122aa565b8301355f19600384901b60f8161c1916905583
8061231c565b909160206001819285880135815501930191016122eb565b8281111561225b5761239d90600c60a05152601f840160051c9060208510611a9257
601f82910160051c03905f516020615d055f395f51905f52016142f0565b8261225b565b3461043f5760a05136600319011261043f57602060405160e68152f3
5b3461043f5760a05136600319011261043f5760206121f06001600160401b0360195460401c16421090565b6136cb565b3461043f5760403660031901126104
3f57612409613558565b6124116135c4565b60a051546001600160a01b031633141580612434575b61080a57610a5f9161421a565b5061243e3361430b565b15
612427565b3461043f576101e036600319011261043f5761245e6135ae565b6124666135c4565b90604036604319011261043f57608036608319011261043f57
60403661010319011261043f57610164356001600160401b03811161043f576124ac9036906004016135ee565b919092610184356001600160401b0381116104
3f576124cf9036906004016135ee565b6101c4356001600160401b03811161043f576124ef9036906004016136e8565b9290916124fb3361430b565b1561080a
5760443594600254860361291c576001600160401b0381169081612aa557505085926001600160401b038716438111612a925761253b9061491a565b945b8515
612a925761254c816140ab565b9161255a60405193846137aa565b818352602083019160051b81019036821161043f5780925b828410612a6657505050506125
9390888a6101443588888c6101a4356149a7565b15612a53576125a0614131565b94600454956001600160401b03808860401c16911614801590612a30575b80
15612a14575b612a01576001600160401b036007541697601c549960a0515060ff8b60401c165f146129f9576001600160401b038b165b6001600160401b0380
61260761415d565b92169116148015906129d6575b80156129bd575b6129695760ff8b60401c1615809a819b6129a2575b8161297c575b5061296957600160a0
1b600190036010541692600f5463ffffffff1696600154988960801c6001600160401b031661266d906141bf565b916040519963ebb2ddc960e01b8b5260048b
01526001600160401b038d1660248b01526001600160401b031660448a015260648901526001600160401b031660848801526101a43560a488015260c4870152
60643560e487015260843561010487015260a43561012487015260a0515060c4356001600160401b03811680910361043f5761014487015260e4356001600160
401b0381169081900361043f57610164870152610104356001600160401b0381169081900361043f5761018487015261012435916001600160401b0383168303
61043f576020958795612781879594612794946001600160401b038897166101a4880152610144356101c48801526102206101e48801526102248701916137fc
565b84810360031901610204860152916137fc565b03915afa9081156107ea5760a0519161292f575b501561291c5767ffffffffffffffff60801b6127d06080
83901c6001600160401b03166141fd565b60801b16906001600160401b0360801b19161760015560643560025567ffffffffffffffff60401b61280061414756
5b60401b16916001600160401b0360801b9060801b169077ffffffffffffffffffffffffffffffff00000000000000001916171760045560ff8260401c169061
2903575b6128d4575b6101a43560115561285b61014435614dea565b6001600160401b0360015460801c167f2ad9ed3f2b3ff263b7a3cf97621dfc164b1d2303
160c10d0dc421f866d0d54ef60a06002546001600160401b0360045460401c166001600160401b03601c5416906040519260a435845260208401526101443560
4084015260608301526080820152a360a05180f35b600160401b906001600160401b036128ea614174565b169068ffffffffffffffffff19161717601c558061
2848565b506001600160401b03612914614174565b161515612843565b6309bde33960e01b60a05152600460a051fd5b90506020813d602011612961575b8161
294a602093836137aa565b8101031261043f5761295b906137ef565b866127a8565b3d915061293d565b630493d50f60e11b60a05152600460a051fd5b600891
5061299a6001600160401b0391612994614174565b9061419f565b16118c612636565b90506001600160401b036129b4614174565b16151590612630565b5089
6001600160401b036129cf614174565b161161261b565b506129df614174565b6001600160401b03806129f061415d565b16911610612614565b60a0516125f6
565b633d9dffbd60e01b60a05152600460a051fd5b50612a1d614147565b6001600160401b038088169116116125c5565b50612a39614147565b600160016040
1b0380612a4a614131565b169116106125be565b63098017c360e01b60a05152600460a051fd5b83356001600160401b03811161043f57602091612a87839236
908601614113565b815201930192612572565b632705871360e01b60a05152600460a051fd5b6001600160401b038895929516851115612a9257438511612a92
57612aca909461491a565b9461253d565b3461043f5760a05136600319011261043f576020600354604051908152f35b3461043f5760a0513660031901126104
3f576020601154604051908152f35b3461043f5760a05136600319011261043f576020600554604051908152f35b3461043f5760a05136600319011261043f57
6017546040516001600160a01b039091168152602090f35b3461043f5760a05136600319011261043f57600f54604051602091821c6001600160a01b03168152
f35b3461043f5760a05136600319011261043f5760206001600160401b0360175460a01c16604051908152f35b3461043f57602036600319011261043f57612b
c56135ae565b60055480158015612ca9575b612c895760a051905f19810190811161077a576001600160401b03909216915b808210612c2257606082612c0481
614008565b509060ff600183549301541660405192835260208301526040820152f35b9080820180821161077a576001810180911161077a5760011c90836001
600160401b036001612c5085614008565b50015460081c1611612c63575090612bf1565b91505f19810190811115612bf157634e487b7160e01b60a051526011
600452602460a051fd5b6001600160401b038263302c66ab60e21b60a0515216600452602460a051fd5b5060055415610dbb57600560a051526001600160401b
036001602060a0512060a05150015460081c166001600160401b03831610612bd1565b3461043f57602036600319011261043f576001600160a01b03612d0361
3558565b1660a0515260066020526020604060a05120612d2c6001600160401b0360195460401c16421090565b159081612d54575b81612d45575b5060405190
15158152f35b60ff91505460081c1682612d3a565b805460ff169150612d34565b3461043f5760a05136600319011261043f57602060ff601c5460401c166040
519015158152f35b3461043f57604036600319011261043f57612da0613558565b612da86136bc565b60a051546001600160a01b0316330361053557610a5f91
614024565b3461043f5760a05136600319011261043f576005548015612e28575f19810190811161077a57612df5606091614008565b5060ff60018254920154
16612e0a81836147fd565b6040805193845260208401929092526001600160a01b031690820152f35b630c322fb560e31b60a05152600460a051fd5b3461043f
5760a05136600319011261043f5760206001600160401b0360045416604051908152f35b3461043f5760a05136600319011261043f5760206001600160401b03
60015460801c16604051908152f35b3461043f5760a05136600319011261043f576010546040516001600160a01b039091168152602090f35b3461043f576020
36600319011261043f57612ed1613558565b60a051546001600160a01b031633036105355760018060a01b03168060a05152600660205260ff604060a0512054
1615610a905760a0805182905260066020525160408120805461ff00191690557feb225a736fbfee3f85ccb72bdf84ff0396ab358b7970e2cc351ab3e3fd9235
8d9080a260a05180f35b3461043f5760a05136600319011261043f57600d546040516001600160a01b039091168152602090f35b3461043f5760a05136600319
011261043f57602060ff60155460081c1615604051908152f35b3461043f5760a05136600319011261043f57602060ff60105460e81c16604051908152f35b34
61043f57602036600319011261043f576020612fdc600435613fc7565b905460405160039290921b1c6001600160a01b03168152f35b3461043f576040366003
19011261043f5761300e613558565b6130166136bc565b60a051546001600160a01b0316330361053557610a5f91613f15565b3461043f576020366003190112
61043f5761304b6136ad565b60a051546001600160a01b031633036105355760ff5f516020615d255f395f51905f52916130776146e6565b61052c6015549161
ff0081151560081b1661ff001984161760155560405193849316839092916020906040830194151583521515910152565b3461043f5760203660031901126104
3f576130c9613598565b60a051546001600160a01b03163303610535576001600160801b0316670de0b6b3a764000081116120db576020817fc62141e607d6fc
bf7d11fd2b6d8e18e5ebef6d3fff8136ca98822801abbaea38926001600160801b03196001541617600155604051908152a160a05180f35b3461043f5760a051
36600319011261043f57600d546001600160a01b03811690811580156131c8575b6131b55760a05180546001600160a01b031980821685178355909216600d55
6001600160a01b03909116907ff8ccb027dfcd135e000e9d45e6cc2d662578a8825d4c45b5e32e0adf67e79ec69080a360a05180f35b63058d9a1b60e01b60a0
5152600460a051fd5b5081331415613160565b3461043f57602036600319011261043f57600435600281101561043f576131f88161368f565b60a05152601b60
205260206001600160401b03604060a051205416604051908152f35b3461043f5760a05136600319011261043f5760a051546001600160a01b03163303610535
5767ffffffffffffffff60401b1960195416601955337fd2c62538708a93d7454226ca65a098ec07211b126fc22bf2accdcae6561fc2aa60a05160a051a260a0
5180f35b3461043f57602036600319011261043f5761329c613558565b60a051546001600160a01b031633036105355760018060a01b03168060a05152600660
205260ff604060a05120541615610a905760a0805182905260066020525160408120805461ff0019166101001790557f22ab73af03f04a21e91c7923327f9927
9b7f5d07d9551762c39bccdf051f1fe99080a260a05180f35b346134dd5760c03660031901126134dd57613331613558565b61333961356e565b604435916001
600160801b038316928381036134dd57608435936001600160401b0385168095036134dd5760a4356001600160401b0381116134dd5761338390369060040161
35ee565b90933033036135495760ff60155460081c1680613539575b61352a57600f5460405163a9059cbb60e01b81526001600160a01b03602092831c811660
048301526001600160801b039690961660248201529190941693816044815f885af19081156134d2575f916134f0575b50156134e157600354956002600e5560
0f5460018060a01b038160201c1693843b156134dd575f9663ffffffff948894613472936040519b8c9a8b998a986311da526160e01b8a521660048901526024
880152606435604488015260018060a01b03166064870152608486015260a485015260e060c485015260e48401916137fc565b03925af180156134d2576134be
575b506001600e5560ff6015541690816134b2575b5061349f5760a05180f35b631fd6e06160e01b60a05152600460a051fd5b90506003541481613494565b5f
6134c8916137aa565b5f60a05281613481565b6040513d5f823e3d90fd5b5f80fd5b6312171d8360e31b5f5260045ffd5b90506020813d602011613522575b81
61350b602093836137aa565b810103126134dd5761351c906137ef565b876133ef565b3d91506134fe565b63793cd94b60e11b5f5260045ffd5b506135438661
45cb565b1561339b565b6314e1dbf760e11b5f5260045ffd5b600435906001600160a01b03821682036134dd57565b602435906001600160a01b038216820361
34dd57565b35906001600160a01b03821682036134dd57565b600435906001600160801b03821682036134dd57565b600435906001600160401b038216820361
34dd57565b602435906001600160401b03821682036134dd57565b35906001600160401b03821682036134dd57565b9181601f840112156134dd578235916001
600160401b0383116134dd57602083818601950101116134dd57565b9060a06003198301126134dd576004356001600160a01b03811681036134dd5791602435
6001600160801b03811681036134dd579160443591606435906001600160401b0382116134dd5760a09082900360031901126134dd5760040190608435600160
0160a01b03811681036134dd5790565b6002111561369957565b634e487b7160e01b5f52602160045260245ffd5b6004359081151582036134dd57565b602435
9081151582036134dd57565b346134dd575f3660031901126134dd57602060405162278d008152f35b9181601f840112156134dd578235916001600160401b03
83116134dd576020808501948460051b0101116134dd57565b6024359060ff821682036134dd57565b90600182811c92168015613756575b6020831014613742
57565b634e487b7160e01b5f52602260045260245ffd5b91607f1691613737565b606081019081106001600160401b0382111761377b57604052565b634e487b
7160e01b5f52604160045260245ffd5b604081019081106001600160401b0382111761377b57604052565b90601f801991011681019081106001600160401b03
82111761377b57604052565b805180835260209291819084018484015e5f828201840152601f01601f1916010190565b519081151582036134dd57565b908060
209392818452848401375f828201840152601f01601f1916010190565b6019549394929360401c6001600160401b03164210613ee1576001600160a01b038316
928315613ed2576138589061385333615b38565b6158a3565b6001600160a01b03165f8181526006602052604090205490929060ff811615613ec35760081c60
ff1615613eb457604051639c4bad2960e01b8152602081600481875afa9081156134d2575f91613e7a575b506040516337de09eb60e11b81526001600160401b
039190911660048201526024810182905260208160448161100f60921b5afa9081156134d2575f91613e40575b5015613e315760208501946139086139038761
46a6565b615a65565b15613e225780359061391982615a7f565b15613e22576040810190604061392f83836146b4565b905003613dff5761393f8761461d565b
5015613d7c5761394d6143a1565b906001600160801b03613967613961614334565b84615b73565b16956001600160801b038116968710613d6d578261398491
615b93565b95604051906323b872dd60e01b825233600483015230602483015260448201526020816064815f8c5af180156134d257613d36575b506001600160
801b0382169182613cb4575b506040519360c085018581106001600160401b0382111761377b576040528785526020850198338a526001600160801b03604087
0198169485895260608701968888526080810199838b5260a0863603126134dd576040519860a08a018a81106001600160401b0382111761377b57604052858a
528e3560ff811681036134dd5760208b015283356001600160401b0381116134dd57613a6e9036908901614113565b60408b015260608701356001600160a01b
031981169e908f81036134dd5760608c01526080880135916001600160801b031983169b8c84036134dd576001600160401b039e613b9994608083015260a087
01918252600354926001600160801b03604051978896602088019a60018c52606060408a015260018060a01b03905116608089015260018060a01b0390511660
a0880152511660c086015260018060a01b0390511660e085015251610100840152519060c0610120840152815161014084015260ff6020830151166101608401
52613b5b604083015160a06101808601526101e08501906137cb565b6060808401516001600160a01b0319166101a08601526080909301516001600160801b03
19166101c08501529183015203601f1981018352826137aa565b5190209b60d26002600e5414613ca7575b6004549a8b9181613bc3818086169560401c168561
419f565b9116918291161015613c955750937f51046223e5e0abca942f13a8f3d1c8dfd59c8b6c4f3e64fc2f5bf453767a97ca9a989693613c3e8f9d9b999694
613c388f95613c1760ff98613c749c986003556141fd565b6001600160401b0381169e8f906001600160401b03191617600455506146a6565b946146b4565b95
90966040519c8d5260208d015260408c015260608b015260808a01521660a088015261016060c08801526101608701916137fc565b9660e08501526101008401
526101208301526101408201528033940390a390565b6301eb386f60e71b5f5260045260245ffd5b506003600e5560e6613baa565b5f5460405163a9059cbb60
e01b81526001600160a01b039190911660048201526001600160801b039091166024820152602081806044810103815f8c5af180156134d257156139cb576020
813d602011613d2e575b81613d16602093836137aa565b810103126134dd57613d27906137ef565b505f6139cb565b3d9150613d09565b6020813d602011613d
65575b81613d4f602093836137aa565b810103126134dd57613d60906137ef565b6139b9565b3d9150613d42565b636ba4a1c760e01b5f5260045ffd5b866005
54811015613ded57613d9081614008565b5060018201808311613dd95760016001600160401b0381613db18294614008565b5094015460081c1692015460081c
169163034dff0f60e01b5f5260045260245260445260645ffd5b634e487b7160e01b5f52601160045260245ffd5b637f455d3760e11b5f5260045260245ffd5b
613e0992506146b4565b9050632331a96360e11b5f52600452604060245260445ffd5b632f0be49b60e11b5f5260045ffd5b6354cfe65960e01b5f5260045ffd
5b90506020813d602011613e72575b81613e5b602093836137aa565b810103126134dd57613e6c906137ef565b5f6138ec565b3d9150613e4e565b9050602081
3d602011613eac575b81613e95602093836137aa565b810103126134dd57613ea690614692565b5f6138aa565b3d9150613e88565b63dec712ef60e01b5f5260
045ffd5b631fcf8c4760e11b5f5260045ffd5b638dc30b3960e01b5f5260045ffd5b63c362a96f60e01b5f5260045ffd5b9060058110156136995760ff801983
54169116179055565b9060058210156136995752565b613f1d6146e6565b60018060a01b031690815f52601460205260ff60405f20541690805f14613fc05760
03905b600582101561369957600583101561369957818314613fba5715613fb3575f5b60058110156136995782036134dd575f516020615d655f395f51905f52
91613fb0604092855f526014602052613f9a81855f20613ef0565b613fa684518094613f08565b6020830190613f08565ba2565b6003613f62565b5050505056
5b5f90613f42565b601254811015613fdf5760125f5260205f2001905f90565b634e487b7160e01b5f52603260045260245ffd5b8054821015613fdf575f5260
205f2001905f90565b600554811015613fdf5760055f5260205f209060011b01905f90565b61402c61474a565b60018060a01b031690815f52601460205260ff
60405f20541690805f146140a4576004905b600582101561369957600583101561369957818314613fba571561409d57816134dd575f516020615d655f395f51
905f5291613fb0604092855f526014602052613f9a81855f20613ef0565b6004613f62565b5f90614051565b6001600160401b03811161377b5760051b602001
90565b6001600160401b03811161377b57601f01601f191660200190565b9291926140e9826140c2565b916140f760405193846137aa565b8294818452818301
116134dd578281602093845f960137010152565b9080601f830112156134dd5781602061412e933591016140dd565b90565b60c4356001600160401b03811681
036134dd5790565b60e4356001600160401b03811681036134dd5790565b610104356001600160401b03811681036134dd5790565b610124356001600160401b
03811681036134dd5790565b356001600160401b03811681036134dd5790565b906001600160401b03809116911603906001600160401b038211613dd957565b
6001600160401b036001911601906001600160401b038211613dd957565b6001600160401b0362278d00911601906001600160401b038211613dd957565b6001
600160401b03166001600160401b038114613dd95760010190565b906142248261430b565b156142a7576017546001600160a01b03838116908216146142a257
6001600160401b03809160a01c16911680820361428d5750506001600160401b03601854166001600160401b0343161461427e5761427c90614e18565b565b63
24619d6960e11b5f5260045ffd5b630670c83560e21b5f5260045260245260445ffd5b505050565b63e2ab4ae760e01b5f5260045ffd5b5f5b8181106142c357
5050565b5f7fbb8a6a4669ba250d26cd7a459eca9d215f8307e33aebe50379bc5a3617ec34448201556001016142b8565b5f5b8281106142fe57505050565b5f
828201556001016142f2565b6001600160a01b03165f9081526014602052604090205460ff1660058110156136995760011490565b60045460c01c4881029080
8204481490151715613dd95764e8d4a51000810190818111613dd95764e8d4a50fff01908111613dd95764e8d4a510006001600160801b0391041690565b9190
811015613fdf5760051b0190565b356001600160a01b03811681036134dd5790565b6001600160801b0360015416620186a0026001600160801b038116908103
613dd95790565b816143cf6146e6565b614453575b60018060a01b031690815f52601460205260ff60405f20541690805f1461444c576002905b600582101561
369957600583101561369957818314613fba571561444557816134dd575f516020615d655f395f51905f5291613fb0604092855f526014602052613f9a81855f
20613ef0565b6002613f62565b5f906143f9565b600f5460201c6001600160a01b03908116908216036143d4575f80fd5b8051821015613fdf5760209160051b
010190565b9190811015613fdf5760051b8101359061011e19813603018212156134dd570190565b9035601e19823603018112156134dd570160208135910191
6001600160401b0382116134dd5781360383136134dd57565b604081529291906001600160a01b036144f082613584565b166040850152602081013560608501
5260018060a01b0361451360408301613584565b16608085015260608101356001600160801b03811681036134dd576020916001600160801b036145c6921660
a0870152608081013560c08701526001600160401b0361456160a083016135da565b1660e08701526001600160401b0361457b60c083016135da565b16610100
8701526145b36145a761459560e08401846144a7565b610120808b01526101608a01916137fc565b916101008101906144a7565b878303603f19016101408901
52906137fc565b930152565b6001600160a01b03165f9081526014602052604090205460ff1660058110156136995760031490565b6001600160a01b03165f90
81526014602052604090205460ff1660058110156136995760021490565b6005548082101561468a575f198101908111613dd957811461468257600181018091
11613dd9576001600160401b03600161465b6201518093614008565b50015460081c1601906001600160401b038211613dd9576001600160401b038216431091
90565b506001905f90565b50505f905f90565b51906001600160401b03821682036134dd57565b3560ff811681036134dd5790565b903590601e198136030182
12156134dd57018035906001600160401b0382116134dd576020019181360383136134dd57565b60015f52601b6020527f9fafca4c9c0d5c2cbf85f49fd8ab82
12430ce78c2a0cb75b51e0f9c4f9ace003546001600160401b0316801515908161473f575b5061472b57565b63317e9b3b60e21b5f52600160045260245ffd5b
90504210155f614724565b5f8052601b6020527f584f46c60af19681376031579adb04a2416e54ee5505351c2a8435e3766026ea546001600160401b03168015
1590816147a1575b5061478e57565b63317e9b3b60e21b5f525f60045260245ffd5b90504210155f614787565b3d156147d6573d906147bd826140c2565b9161
47cb60405193846137aa565b82523d5f602084013e565b606090565b6020815191015190602081106147ef575090565b5f199060200360031b1b1690565b5f80
6401000003d019600781858181800909086040516020810191602083526020604083015260206060830152608082015263400000f4600160fe1b0360a0820152
6401000003d01960c082015260c0815261485a60e0826137aa565b519060055afa6148686147ac565b908061490f575b156148da5760ff6148816002926147db
565b9316146001831615036148be575b60405191602083019182526040830152604082526148ae6060836137aa565b905190206001600160a01b031690565b90
6401000003d019036401000003d0198111613dd9579061488f565b60405162461bcd60e51b815260206004820152600d60248201526c1b5bd9195e1c0819985a
5b1959609a1b6044820152606490fd5b50602081511461486f565b905f80809360405160208101918252602081526149386040826137aa565b519071f90827f1
c53a10cb7a02335b1753200029355afa6149576147ac565b908061497c575b6149655750565b9091506020818051810103126134dd576020015190565b506020
8151101561495e565b908160209103126134dd57516001600160a01b03811681036134dd5790565b9391949590929560105460ff8160e81c1697601154871180
1590614de0575b8015614dd4575b614dc65763ffffffff600f5416976149f26001600160401b0360015460801c166141bf565b96604051602081019060443582
52606435604082015260408152614a176060826137aa565b519020936040516020810190608435825260a435604082015260c4356001600160401b0381168103
6134dd576001600160401b0316606082015260e4356001600160401b03811681036134dd576001600160401b0316608082015260808152614a8160a0826137aa
565b519020956040516020810190610104356001600160401b03811681036134dd576001600160401b03168252610124356001600160401b03811681036134dd
576001600160401b0316604082015260408152614add6060826137aa565b519020973690614aec926140dd565b80519060200120986040519a60208c019c7fb1
55d32b4b347a555165cab364d500d1c10bb3b9c50d31d54c220e98ce9202588e5260408d01528260a81c6001600160401b031660608d015260808c0152600160
0160401b031660a08b0152600160a01b600190031660c08a01526001600160401b031660e08901526001600160401b0316610100880152610120870152610140
8601526101608501526101808401526101a08301526101c08201526101c08152614bab6101e0826137aa565b51902060405160208101907f8b73c3c69bb8fe3d
512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f8252604081017fe17337f79206a015e0451a0d8a3f22c09d7c6d3f7966361afa60e4ddcd8cd1ff90
52606081017fc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc690524660808201523060a082015260a08152614c4260c0826137
aa565b5190209060405190602082019261190160f01b84526022830152604282015260428152614c706062826137aa565b519020825192614c7f846140ab565b
9360405194614c8e90866137aa565b808552601f1990614c9e906140ab565b013660208601375f5b8151811015614dbb57614ce86020614cbf8385614470565b
51604051809381926319045a2560e01b83528860048401526040602484015260448301906137cb565b038162051653608c1b5afa5f9181614d8b575b50614d0a
575050505050505f90565b6001600160a01b038116908115908115614d7a575b50614d70575f5b828110614d43575090600191614d3c8288614470565b520161
4ca7565b816001600160a01b03614d56838a614470565b511614614d6557600101614d26565b505050505050505f90565b5050505050505f90565b614d849150
61430b565b155f614d1f565b614dad91925060203d8111614db4575b614da581836137aa565b810190614988565b905f614cfb565b503d614d9b565b50919250
5051101590565b505050505050505050505f90565b508951601254106149cd565b50888a51106149c6565b8015614e1257600a5490815f52600b60205260405f
205560018101808211613dd957600a5590565b505f1990565b601754906001600160a01b031667ffffffffffffffff60a01b614e526001600160a01b03198416
831760a01c6001600160401b03166141bf565b60a01b168163ffffffff60e01b84161717806017557f0e49bd8bbce34618e6af3bb74d587a65fa2a594df80b7c
c21d690ee78c6d7a6960206001600160401b0380431693848219601854161760185560405194855260a01c169460018060a01b031692a4565b60125460016040
1b81101561377b57806001614ed992016012556012613ff3565b81546001600160a01b0393841660039290921b91821b9390911b1916919091179055565b6020
818303126134dd578051906001600160401b0382116134dd570181601f820112156134dd57805190614f30826140c2565b92614f3e60405194856137aa565b82
8452602083830101116134dd57815f9260208093018386015e8301015290565b91908260409103126134dd5761412e6020614f79846137ef565b930161469256
5b6040516306fdde0360e01b81526001600160a01b0391909116905f81600481855afa9081156134d2575f9161535e575b506040516395d89b4160e01b81525f
81600481865afa9081156134d2575f91615344575b5060405163e5a6b10f60e01b8152915f83600481875afa9283156134d2575f93615320575b50601f815111
8015615315575b801561530a575b6152fb57604091825161502084826137aa565b600181526020810190601f198501368337805115613fdf5786825284516323
143aff60e01b81526004810188905291858360248161100f60921b5afa9283156152f1575f936152d1575b5082156151c3575b5050156151b457601a54835160
208101918252868582015260a060608201526150cc816111a26150ba6150a860c08401896137cb565b838103601f19016080850152876137cb565b828103601f
190160a0840152896137cb565b519020601a5582516150dd8161378f565b600181526020810160018152865f526006602052845f209151151560ff8019845416
911617825551151561ff0082549160081b169061ff00191617905560075492600160401b84101561377b577f4ac4dcc08b0c26c3fb6b58c64c1392b7934b1ce6
b0382a5986ea5c3de795e053946151a26151af9361516887600161519499016007556007613ff3565b81549060031b908b821b9160018060a01b03901b191617
905583519687966060885260608801906137cb565b9086820360208801526137cb565b91848303908501526137cb565b0390a2565b638074d40160e01b5f5260
045ffd5b855163a783dc9960e01b81526020600482015291516024830181905291925082916044830191905f5b8181106152af57505050908060209203815f61
100f60921b5af1801561527657615280575b5082516323143aff60e01b815260048101869052838160248161100f60921b5afa908115615276575f9161524857
5b505f80615072565b6152689150843d861161526f575b61526081836137aa565b810190614f5f565b505f615240565b503d615256565b84513d5f823e3d90fd
5b6020813d6020116152a7575b81615299602093836137aa565b810103126134dd5751615211565b3d915061528c565b82516001600160a01b03168452859450
602093840193909201916001016151ec565b6152e9919350863d881161526f5761526081836137aa565b50915f61506a565b86513d5f823e3d90fd5b630a49a9
e760e31b5f5260045ffd5b50601f83511161500d565b50601f825111615006565b61533d9193503d805f833e61533581836137aa565b810190614efd565b915f
614ff9565b61535891503d805f833e61533581836137aa565b5f614fd4565b61537291503d805f833e61533581836137aa565b5f614fb0565b35600160016080
1b03811681036134dd5790565b906009545f91815f52600b60205260405f205460405160208101906153b6816111a2868a866144d8565b519020036158945781
5f52600b6020528060405f205515615880575b506153dc8261438d565b9160c081016001600160401b036153f28261418b565b16156156af5760a08201629896
806001600160401b036154118361418b565b1611615638576001600160401b036154288261418b565b16615533575060205f516020615d455f395f51905f5292
60609260ff60155460081c16158015615518575b806154fe575b806154d7575b1590816154b2575b506001600160801b0361547c6040840161438d565b976154
88868501615378565b90604051985060018060a01b03168852168387015215604086015201359360018060a01b031692a3565b6154d1906154ca6154c4878601
615378565b9161418b565b9089615bb3565b5f615467565b506154f96154e76040840161438d565b6154f2868501615378565b90896158d4565b61545f565b50
61551361550e6040840161438d565b615ce8565b615459565b5061552d6155286040840161438d565b6145cb565b15615453565b61553f6040840161438d565b
61555461554e60608601615378565b9261418b565b9061556260e08601866146b4565b9092303b156134dd57604051625d97ef60e01b81526001600160a01b03
808b16600483015290931660248401526001600160801b03949094166044830152602086013560648301526001600160401b0393909316608482015260c060a4
820152915f91839182916155d79160c48401916137fc565b038183305af1908161560b575b505f516020615d455f395f51905f52926060926020926156045785
61545f565b600161545f565b60209194509260609261562c5f5f516020615d455f395f51905f52966137aa565b5f9592509250926155e4565b50929150606060
2082615669835f516020615d455f395f51905f529501966156626154c489615378565b9087615bb3565b6001600160801b036156866156806040840161438d56
5b97615378565b604080516001600160a01b03988916815292909116848301525f908201529101359490931692a3565b508092506156bd915061438d565b6156
c5614334565b91606081016001600160801b036156db82615378565b166001600160801b0385161161586f575b5f936001600160801b03811615158061585257
5b615848575b5061571a84615715604093615378565b615b93565b91019161572961550e8461438d565b8061582f575b156157a0577f0f7ef08806234f85aaee
43d3ba4589c3bc6d5ac3fc8edd56fc3d91cc7553bdcb926151af906001600160a01b039061576c9061438d565b16946040519384938491604091949360016001
60801b038092606086019760018060a01b0316865216602085015216910152565b6001600160a01b0381165f9081526008602052604090207f5fea28d0adb7d8
77ae3259768f41ad6741aa1784c4475746dd931364f62e68a1936151af916157e68261438d565b60018060a01b03165f5260205260405f206001600160801b03
61580c8682845416615b73565b82546001600160801b03191691161790556001600160a01b039061576c9061438d565b506158438261583d8561438d565b8361
58d4565b61572f565b935061571a615705565b505f5461586a9082906001600160a01b0316866158d4565b615700565b925061587a83615378565b926156ec56
5b60018101809111613dd9576009555f6153d2565b632e1aaf2760e21b5f5260045ffd5b6158ac81615ce8565b156158b45750565b6376ecd09f60e11b5f9081
526001600160a01b0391909116600452602490fd5b60405163fbea9d6760e01b81526001600160a01b03831660048201529092906020816024816103f760961b
5afa5f9181615a44575b5061591657505050505f90565b6040805163b72b0c5960e01b81526001600160a01b0395861660048201819052306024830152959092
1660448301528160648161100f60921b5afa5f91816159fb575b5061596657505050505f90565b156159f45760405163a9059cbb60e01b81526001600160a01b
039290921660048301526001600160801b0316602482015290602090829060449082905f905af15f91816159b8575b5061412e57505f90565b9091506020813d
6020116159ec575b816159d4602093836137aa565b810103126134dd576159e5906137ef565b905f6159ae565b3d91506159c7565b5050505f90565b90915060
40813d604011615a3c575b81615a17604093836137aa565b810103126134dd5760036020615a2c836137ef565b92015110156134dd57905f615959565b3d9150
615a0a565b615a5e91925060203d602011614db457614da581836137aa565b905f615909565b60ff1660028114908115615a77575090565b600391501490565b
80158015615b28575b615b17575f9081906401000003d01990600790829081818009090860405160208101916020835260206040830152602060608301526080
82015263800001e9600160ff1b0360a08201526401000003d01960c082015260c08152615aed60e0826137aa565b519060055afa615afb6147ac565b90158015
615b1c575b615b1757615b136001916147db565b1490565b505f90565b50602081511415615b04565b506401000003d019811015615a88565b60155460ff8116
15615b6f5760081c60ff1680615b60575b615b5d576158ac816145f4565b50565b50615b6a816145cb565b615b50565b5050565b906001600160801b03809116
911601906001600160801b038211613dd957565b906001600160801b03809116911603906001600160801b038211613dd957565b90916001600160401b031691
60405191615bcc83613760565b60018060a01b031691828152602081018481526001600160801b03604083019316928381526001600160801b03600354916040
519360208501955f875260018060a01b03905116604086015260018060a01b0390511660608501525116608083015260a082015260a08152615c4260c0826137
aa565b51902091600454906001600160401b0382169160e66001600160401b03615c6e818460401c168661419f565b161015615cd4577fadf6f2901dd7af2f28
a594f47a925894a08d4de10609dff591a80642648775c593615ca6606094876003556141fd565b6001600160401b03811680936001600160401b031916176004
555060405192835260208301526040820152a3565b6301eb386f60e71b5f5260e660045260245ffd5b60ff6015541615908115615cfa575090565b61412e9150
6145f456fedf6966c971051c3d54ec59162606531493a51404a002842f56009d7e5cf4a8c73e5479494e0a078954a7ff8437aeca3bf7519b51a2fc06b3821251
147ff9c5f765042ea6dad60c26f055e80ec401b3437c854ed586a0704d305bb4e9ea4518cf2359a069f5d7871f8f60ad861112ebe12dcf2ba55225c32ec04564
d494afc69ba2646970667358221220c6db7148aedf6743ceab91ec6c136bbc2325acce751cf6299a5019b3759ec64464736f6c63430008230033
```

### T13 T13_ZONE_VERIFIER_RUNTIME (installed at 0x5A56000000000000000000000000000000000000 from T13; never executed)

Length 387 bytes, keccak256 `0xcf7b19d3c186e4fd235c94907d10bba5c1ce21d6e815676b00aaf298b456de14`.

```text
6080806040526004361015610012575f80fd5b5f3560e01c63ebb2ddc914610025575f80fd5b346100d6576102203660031901126100d65760043563ffffffff
8116036100d65761004e6100da565b506100576100f1565b50610060610108565b5060403660c31901126100d6576080366101031901126100d6576040366101
831901126100d6576101e43567ffffffffffffffff81116100d6576100a890369060040161011f565b5050610204359067ffffffffffffffff82116100d65761
00ce602092369060040161011f565b505060018152f35b5f80fd5b6024359067ffffffffffffffff821682036100d657565b6044359067ffffffffffffffff82
1682036100d657565b6084359067ffffffffffffffff821682036100d657565b9181601f840112156100d65782359167ffffffffffffffff83116100d6576020
83818601950101116100d65756fea2646970667358221220030518df9a73d0b3ed3c51d3bcf96fc84aa0a0189c0b76c44f42a3782285fc3264736f6c63430008
230033
```

### T13 T13_ZONE_MESSENGER_RUNTIME (installed at 0x5A4D000000000000000000000000000000000000 from T13)

Length 1858 bytes, keccak256 `0x526c5bb045b6229e5a693d70feee066cc3848b5f91c62949ced54818045214ee`.

```text
6080806040526004361015610012575f80fd5b5f3560e01c90816311da5261146100565750637b9a730114610032575f80fd5b34610052575f36600319011261
005257604051612d7960911b8152602090f35b5f80fd5b346100525760e0366003190112610052576004359063ffffffff821680920361005257602435600160
0160a01b03811690819003610052576064356001600160a01b038116939084900361005257608435916fffffffffffffffffffffffffffffffff831680930361
00525760a4359167ffffffffffffffff83168093036100525760c4359567ffffffffffffffff871161005257366023880112156100525786600401359567ffff
ffffffffffff871161005257366024888a010111610052575f546106ba5760015f9081556390b7f6fd60e01b82526004820184905281602481612d7960911b5a
fa90811561037b575f916104d3575b50602001516001600160a01b031633036104c457604051631b32199b60e01b8152602081600481335afa90811561037b57
5f9161048a575b501580610416575b6104075760405163fbea9d6760e01b8152600481018290526020816024816103f760961b5afa90811561037b575f916103
cd575b506040805163b72b0c5960e01b8152600481018690523060248201526001600160a01b0390921660448301528160648161100f60921b5afa9081156103
7b575f91610386575b50156103325760405163a9059cbb60e01b81528160048201528560248201526020816044815f885af190811561037b575f91610341575b
50156103325760e45f928760209860246040519b8c9a8b998a96630a137ff560e01b885260048801523384880152604435604488015260648701526084860152
60c060a48601528260c486015201848401378181018301859052601f01601f19168101030193f15f91816102ed575b506102c25763be51ced360e01b5f526004
5ffd5b6001600160e01b03191663f5ec800b60e01b016102de575f8055005b63be51ced360e01b5f5260045ffd5b9091506020813d60201161032a575b816103
09602093836106c9565b8101031261005257516001600160e01b0319811681036100525790826102ae565b3d91506102fc565b6312171d8360e31b5f5260045f
fd5b90506020813d602011610373575b8161035c602093836106c9565b810103126100525761036d906106ff565b8861023f565b3d915061034f565b6040513d
5f823e3d90fd5b90506040813d6040116103c5575b816103a1604093836106c9565b8101031261005257600360206103b6836106ff565b920151101561005257
88610208565b3d9150610394565b90506020813d6020116103ff575b816103e8602093836106c9565b81010312610052576103f9906106eb565b886101c2565b
3d91506103db565b63793cd94b60e11b5f5260045ffd5b506040516395a8c58d60e01b81526004810182905260036024820152602081604481335afa90811561
037b575f91610450575b501561018e565b90506020813d602011610482575b8161046b602093836106c9565b810103126100525761047c906106ff565b886104
49565b3d915061045e565b90506020813d6020116104bc575b816104a5602093836106c9565b81010312610052576104b6906106ff565b88610186565b3d9150
610498565b63efc26b5760e01b5f5260045ffd5b90503d805f833e6104e481836106c9565b8101906020818303126100525780519067ffffffffffffffff8211
610052570190610120828203126100525760405191610120830183811067ffffffffffffffff82111761068e57604052805163ffffffff811681036100525783
5261054c602082016106eb565b602084015261055d604082016106ff565b604084015261056e606082016106ff565b606084015261057f608082016106eb565b
608084015260a081015167ffffffffffffffff811161005257810182601f820112156100525780519067ffffffffffffffff821161068e578160051b60405192
6105cc60208301856106c9565b83526020808401918301019185831161005257602001905b8282106106a25750505060a084015260c081015160ff8116810361
00525760c084015261061360e082016106eb565b60e08401526101008101519067ffffffffffffffff8211610052570181601f820112156100525780519067ff
ffffffffffffff821161068e5760405192610664601f8401601f1916602001856106c9565b8284526020838301011161005257815f9260208093018386015e83
0101526101008201528861014e565b634e487b7160e01b5f52604160045260245ffd5b602080916106af846106eb565b8152019101906105e4565b6336a4d21b
60e11b5f5260045ffd5b90601f8019910116810190811067ffffffffffffffff82111761068e57604052565b51906001600160a01b038216820361005257565b
519081151582036100525756fea26469706673582212202ea4935f83ce9a841b312eb603e731e359cb0d89cea122e4c27f08b0ba45ce2364736f6c6343000823
0033
```

