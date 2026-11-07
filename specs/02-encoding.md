# 02 — Encoding

This chapter defines every byte-level encoding a Tempo client needs to decode, validate and hash blocks of Tempo mainnet (chain id 4217) from genesis through T13: the RLP conventions Tempo uses, the block header and its standalone and parent-relative validity rules, the block body, the transaction envelope, the Tempo transaction (type `0x76`) with its signing hashes, the key-authorization structures in every fork, the pre-T4 end-of-block system transaction, receipts, the logs bloom and the block's Merkle roots.

Signature byte formats (secp256k1, P256, WebAuthn, Keychain V1/V2, configurable account) and their verification are defined in [03-signatures.md](03-signatures.md). This chapter only fixes where those byte strings sit and how they are re-encoded for hashing ([§4.6](#46-canonical-re-encoding)). Chain ids, fork activation timestamps, the genesis header and genesis state are defined in [01-chain-and-forks.md](01-chain-and-forks.md). Execution semantics (what a transaction does, gas accounting, the content of receipts) are defined in [05-block-execution.md](05-block-execution.md) and [06-transactions-and-fees.md](06-transactions-and-fees.md).

Throughout, "fork F active" means `header.timestamp >= F.activation_time`, where `header.timestamp` is the **seconds** field of the inner header of the block being validated (see [01-chain-and-forks.md](01-chain-and-forks.md)). The millisecond part never selects a fork.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

---

## 1. Conventions

### 1.1 Notation

- `bytes` is a byte string; `b"..."` is an ASCII byte string; `0x..` is hex; `||` is concatenation.
- `uN` is an unsigned N-bit integer; `U256` is an unsigned 256-bit integer; `Address` is 20 bytes; `B256`/`bytes32` is 32 bytes; `bytes4` is 4 bytes.
- `keccak256` is Keccak-256 (Ethereum's, not SHA3-256). `sha256` is SHA-256.
- `be32(n)` is `n` as a 32-byte big-endian integer.
- `rlp(x)` is the RLP encoding of `x` ([§1.2](#12-rlp)). `[a, b, …]` inside `rlp(...)` denotes an RLP list.
- A value is **decode-invalid** when its bytes are not a valid encoding under this chapter. A block whose header or body contains a decode-invalid item is invalid.

Pseudocode is Python-like, in the style of the Ethereum execution-specs.

### 1.2 RLP

Tempo uses Ethereum RLP (Yellow Paper Appendix B; execution-specs `ethereum_rlp`) with **strict canonical decoding**. A decoder MUST reject:

1. a string or list whose length prefix uses more bytes than needed, or a long-form prefix (`0xb8..0xbf`, `0xf8..0xff`) for a payload shorter than 56 bytes;
2. a single byte `< 0x80` encoded as a one-byte string (`0x81 0x05`);
3. an integer with a leading zero byte (including the one-byte string `0x00`); integer zero is the empty string `0x80`;
4. an integer longer than its type (more than 8 bytes for `u64`, 16 for `u128`, 32 for `U256`);
5. a fixed-size byte array (`Address`, `B256`, `bytes4`, `B64`) whose string length is not exactly the array size;
6. a list where a string is required, or a string where a list is required;
7. a list whose items do not consume exactly its declared payload length;
8. a `bool` other than `0x80` (false) or `0x01` (true);
9. for `NonZeroU64` fields, the value zero (`0x80`) — except where a rule below treats `0x80` as an absent-value placeholder before decoding the field.

Encoders MUST produce canonical RLP.

### 1.3 Optional fields

Tempo structures use four distinct conventions for optional fields. Each structure in this chapter names the one it uses.

**(A) Presence-only trailing optionals** ("no gaps"). Used by the Ethereum inner header and by `TempoHeader`. Optional fields form a suffix of the list. A field is present iff list payload remains when the decoder reaches it; there is no placeholder for "absent", so an absent field can only be followed by absent fields. `0x80` at an optional position is decoded as the field's value (and is decode-invalid if the field's type cannot be the empty string).

```python
def decode_presence_optional(payload, field_type):
    if payload.remaining() == 0:
        return None
    return payload.decode(field_type)   # 0x80 is NOT a placeholder
```

**(B) Canonical trailing optionals with placeholder.** Used by `KeyAuthorization` and `TokenLimit`. Optional fields form a suffix. An absent field that is followed by at least one present field is encoded as the placeholder `0x80`. Absent fields after the last present field MUST be omitted. The decoder, for each optional field in order:

```python
def decode_canonical_optional(payload, field_type):
    if payload.remaining() == 0:
        return None                              # omitted
    if payload.peek() == 0x80 and payload.remaining() > 1:
        payload.skip(1)                          # placeholder, more fields follow
        return None
    return payload.decode(field_type)            # a final 0x80 is decoded as a value
```

None of the field types that use (B) can decode from `0x80` (`NonZeroU64` rejects zero; lists, `Address` and `B256` reject the empty string). So a `0x80` in the **last** position of the list is decode-invalid, and so is any run of placeholders that ends the list. The encoder writes `0x80` for an absent field iff some later optional field is present, and omits all trailing absent fields. The result is that every accepted encoding re-encodes to identical bytes.

**(C) Fixed-position optionals.** Used by `valid_before`, `valid_after`, `fee_token` and `fee_payer_signature` of the Tempo transaction. The field is always present in the list; `0x80` means absent. Rules are given per field in [§4.3](#43-tempo-transaction-0x76).

**(D) Type-detected optional.** Used only by `key_authorization` of the Tempo transaction: present iff the next item is an RLP list ([§4.3](#43-tempo-transaction-0x76)).

### 1.4 EIP-2718 typed envelopes

Transactions and receipts use EIP-2718. The **2718 encoding** of a typed item is `type_byte || payload`, with `type_byte` in `[0x00, 0x7f]`. A legacy transaction's 2718 encoding is its RLP list, with no type byte. Decoding 2718 bytes (`decode_2718`):

```python
def decode_2718(buf):
    if buf[0] <= 0x7f:
        return typed_decode(buf[0], buf[1:])     # 0x00 is rejected, see §4.1
    return legacy_decode(buf)                    # buf[0] >= 0xc0: RLP list
```

Inside a block body ([§3](#3-block-and-body)), transactions use the **network form**. A legacy transaction is the RLP list itself. A typed transaction is canonically `rlp_string(type_byte || payload)`, an RLP byte string whose content is the 2718 encoding. Decoders MUST also accept a typed transaction written **unwrapped** in the list, as the bare bytes `type_byte || payload` with no string header. This legacy acceptance comes from the decoder treating a first byte `< 0x80` as a one-byte string header. Both forms decode to the same transaction. Encoders MUST emit the wrapped form, and every length, hash and root in this chapter is computed from the wrapped (canonical) form.

```python
def network_decode_tx(list_payload):
    first = list_payload.peek()
    if first >= 0xc0:
        return legacy_decode(list_payload)                 # consumes one RLP list
    if first < 0x80:
        ty = list_payload.read_u8()                        # unwrapped form
        return typed_decode(ty, list_payload)              # consumes the typed payload
    s = list_payload.read_rlp_string()                     # wrapped form
    if len(s) == 0: raise DecodeError
    tx = typed_decode(s[0], s[1:])
    # typed_decode MUST consume exactly len(s) - 1 bytes
    return tx
```

### 1.5 Constants

| Name | Value | Definition |
|---|---|---|
| `EMPTY_ROOT_HASH` | `0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421` | `keccak256(0x80)`, root of an empty trie |
| `EMPTY_OMMER_ROOT_HASH` | `0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347` | `keccak256(rlp([]))` |
| `EMPTY_REQUESTS_HASH` | `0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `sha256(b"")`, EIP-7685 hash of no requests |
| `KECCAK_EMPTY` | `0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470` | `keccak256(b"")` |
| `TEMPO_TX_TYPE_ID` | `0x76` | Tempo transaction type and sender-signature domain |
| `FEE_PAYER_SIGNATURE_MAGIC_BYTE` | `0x78` | Fee-payer signature domain |
| `EIP7702_MAGIC` | `0x05` | Authorization signature domain (EIP-7702) |
| `TEMPO_MAXIMUM_EXTRA_DATA_SIZE` | `10240` | Maximum `extra_data` length in bytes |
| `MAX_RLP_BLOCK_SIZE` | `8388608` | EIP-7934 block size limit in bytes |
| `MINIMUM_GAS_LIMIT` | `5000` | Minimum block gas limit |
| `GAS_LIMIT_BOUND_DIVISOR` | `1024` | Block gas limit change bound |
| `MAXIMUM_GAS_LIMIT_BLOCK` | `2**63 - 1` | Maximum block gas limit |
| `TEMPO_SUBBLOCK_NONCE_KEY_PREFIX` | `0x5b` | Reserved most-significant byte of `nonce_key` |

---

## 2. Block header

### 2.1 TempoHeader

A Tempo block header is an RLP list of four mandatory items and one presence-only trailing optional (convention A):

```text
TempoHeader = rlp([
    general_gas_limit,      # u64
    shared_gas_limit,       # u64
    timestamp_millis_part,  # u64
    inner,                  # RLP list: the inner header, §2.2
    consensus_context?,     # RLP list: TempoConsensusContext, §2.3; omitted when absent
])
```

`inner` is a **nested** list: the whole Ethereum header is one item of the outer list, not spliced into it. `consensus_context` is present iff list payload remains after `inner`. An explicit `0x80` in that position is decode-invalid, because a `TempoConsensusContext` is a list. Any further item after `consensus_context` is decode-invalid.

The millisecond timestamp of a header is:

```python
def timestamp_millis(h):
    return h.inner.timestamp * 1000 + h.timestamp_millis_part
```

### 2.2 Inner header

`inner` uses the Ethereum header encoding with presence-only trailing optionals (convention A), in this order:

| # | Field | Type | Required value / rule on Tempo |
|---|---|---|---|
| 0 | `parent_hash` | B256 | hash of the parent `TempoHeader` ([§2.4](#24-header-hash)) |
| 1 | `ommers_hash` | B256 | MUST be `EMPTY_OMMER_ROOT_HASH` |
| 2 | `beneficiary` | Address | any value (see note) |
| 3 | `state_root` | B256 | post-state root ([05-block-execution.md](05-block-execution.md)) |
| 4 | `transactions_root` | B256 | [§7.3](#73-roots) |
| 5 | `receipts_root` | B256 | [§7.3](#73-roots) |
| 6 | `logs_bloom` | 256 bytes | [§7.2](#72-logs-bloom) |
| 7 | `difficulty` | U256 | MUST be 0 |
| 8 | `number` | u64 | MUST be `parent.number + 1` |
| 9 | `gas_limit` | u64 | [§2.5](#25-standalone-header-validity), [§2.6](#26-header-validity-against-the-parent) |
| 10 | `gas_used` | u64 | MUST be `<= gas_limit`; value fixed by execution |
| 11 | `timestamp` | u64 | seconds part of the block time |
| 12 | `extra_data` | bytes | length MUST be `<= 10240`; content defined in [07-consensus.md](07-consensus.md) |
| 13 | `mix_hash` | B256 | any value; exposed to the EVM as `PREVRANDAO` |
| 14 | `nonce` | B64 | MUST be `0x0000000000000000` |
| 15 | `base_fee_per_gas` | u64 | MUST be present; value per [§2.7](#27-base-fee) |
| 16 | `withdrawals_root` | B256 | MUST be present and equal `EMPTY_ROOT_HASH` ([§3.2](#32-body-validity)) |
| 17 | `blob_gas_used` | u64 | MUST be present and equal 0 |
| 18 | `excess_blob_gas` | u64 | MUST be present and equal 0 |
| 19 | `parent_beacon_block_root` | B256 | MUST be present; any value |
| 20 | `requests_hash` | B256 | MUST be present; value per [05-block-execution.md](05-block-execution.md) |

Every Tempo header (genesis and all later blocks) has exactly these 21 fields (Ethereum Osaka shape). The decoder is the generic Ethereum decoder, which would also accept the Amsterdam fields `block_access_list_hash` (B256) and `slot_number` (u64) after `requests_hash`. Both MUST be absent (Amsterdam is not active on Tempo). A header with fewer than 21 fields fails the presence rules in [§2.5](#25-standalone-header-validity).

Notes:

- `requests_hash`: Tempo blocks carry no execution-layer requests in any fork, so on mainnet this field has always equalled `EMPTY_REQUESTS_HASH`. The normative rule (it equals the EIP-7685 commitment of the block's requests) is in [05-block-execution.md](05-block-execution.md).
- `beneficiary`, `mix_hash` and `parent_beacon_block_root` are not constrained by header validation at any fork up to T13. Honest proposers set `beneficiary` per [07-consensus.md §12](07-consensus.md#12-validator-proposal-procedure) (build step 6) and set `mix_hash = parent_beacon_block_root = 0x00…00` (32 zero bytes).
- `blob_gas_used = excess_blob_gas = 0` follows from Ethereum's Osaka rules: no blob transactions are accepted ([§4.1](#41-envelope-types)), so the block's blob gas sum is 0, and the EIP-4844/EIP-7918 excess-blob-gas recurrence from a zero genesis value stays 0. A client MAY implement the general Osaka rule instead of the constant; the result is the same.

### 2.3 TempoConsensusContext

```text
TempoConsensusContext = rlp([
    epoch,        # u64
    view,         # u64
    parent_view,  # u64
    proposer,     # 32-byte string: Ed25519 public key
])
```

All four fields are required (no optionals). `proposer` MUST be exactly 32 bytes that decode as an Ed25519 public key under [commonware/cryptography.md §3.2](commonware/cryptography.md#32-public-key-decoding): the bytes are the compressed encoding of a curve point, with non-canonical encodings accepted per ZIP-215. A context whose `proposer` fails this check is decode-invalid, which makes the whole header decode-invalid.

Presence by fork is a header-validity rule ([§2.5](#25-standalone-header-validity) check 9). Every node checks it on every header, including a follower replaying finalized blocks:

- A header whose timestamp is before T4 MUST NOT contain `consensus_context`.
- A header whose timestamp is at or after T4 MUST contain it.

The genesis header of mainnet and Moderato has no `consensus_context`. Mainnet and Moderato history satisfy the rule: every header before T4 omits the field, and every header from T4 carries it.

Beyond presence and decoding:

- Header validation and block execution do not compare the context's contents with anything.
- A validator voting on a proposal also requires the context to equal the Context the block was **first proposed under** ([07-consensus.md §5.1](07-consensus.md#header-consensus-context)): the epoch and view of that proposal's round, the view of its parent, and that round's leader. No rule compares it with the round of the certificate that notarizes or finalizes it. A boundary block that is re-proposed ([07-consensus.md §5.3](07-consensus.md#53-epoch-scoped-instances)) keeps the header, and so the context, of its first proposal, and may be certified in a later view.

> **Resolved conflict C-FORKS-05**: TIP-1031 and t4.mdx gate `consensus_context` presence by fork (absent before T4, required from T4), but the implementation has no fork gate: the execution layer never checks presence by fork, and consensus requires it on every new proposal. Decided: this spec adopts TIP-1031's rule as a header-validity rule. The implementation does not yet enforce the gate, and that is tracked as a code issue. Mainnet and Moderato history satisfy the rule. See [conflicts](conflicts.md#c-forks-05).

### 2.4 Header hash

```python
def header_hash(h: TempoHeader) -> B256:
    return keccak256(rlp(h))   # the whole outer list, including consensus_context when present
```

This is the block hash. It is the `parent_hash` of the child and the consensus digest ([07-consensus.md](07-consensus.md)).

### 2.5 Standalone header validity

A non-genesis header `h` is valid on its own iff all of the following hold. Let `F` be the Tempo fork active at `h.inner.timestamp`.

1. `h.inner.difficulty == 0`, `h.inner.nonce == 0x0000000000000000`, `h.inner.ommers_hash == EMPTY_OMMER_ROOT_HASH`.
2. `len(h.inner.extra_data) <= 10240`.
3. `h.inner.gas_used <= h.inner.gas_limit` and `h.inner.gas_limit <= 2**63 - 1`.
4. `base_fee_per_gas`, `withdrawals_root`, `blob_gas_used`, `excess_blob_gas`, `parent_beacon_block_root` and `requests_hash` are present. `block_access_list_hash` and `slot_number` are absent.
5. `h.inner.blob_gas_used` is a multiple of 131072 (`DATA_GAS_PER_BLOB`) and does not exceed the Osaka maximum blob gas per block. Combined with [§3.2](#32-body-validity), this forces 0.
6. `h.timestamp_millis_part < 1000`.
7. `h.shared_gas_limit == expected_shared_gas_limit(F, h.inner.gas_limit)`.
8. `h.general_gas_limit == expected_general_gas_limit(F, h.inner.gas_limit, h.shared_gas_limit)`.
9. If `F < T4`, `consensus_context` is absent. If `F >= T4`, `consensus_context` is present. When present, it decodes as in [§2.3](#23-tempoconsensuscontext).

```python
def expected_shared_gas_limit(F, gas_limit):
    if F >= T4:
        return 0
    return gas_limit // 10

def expected_general_gas_limit(F, gas_limit, shared_gas_limit):
    if genesis_config.generalGasLimit is not None:      # absent on mainnet and Moderato
        return genesis_config.generalGasLimit
    if F >= T1:
        return 30_000_000                               # TEMPO_T1_GENERAL_GAS_LIMIT
    return (gas_limit - shared_gas_limit) // 2
```

For example, mainnet block 1 (pre-T1, `gas_limit = 500,000,000`) has `shared_gas_limit = 50,000,000` and `general_gas_limit = 225,000,000`.

Checks 1–5 are the Ethereum Osaka header checks for a proof-of-stake chain (execution-specs `osaka` `validate_header` and `state_transition`, with EIP-4895, EIP-4844, EIP-4788 and EIP-7685 for the presence of fields). Tempo deviates in two places: the `extra_data` limit is 10240 bytes instead of 32, and the gas-limit maximum `2**63 - 1` is an added check. Checks 6–9 are Tempo additions.

> **Resolved conflict C-ENC-04**: TIP-1010 fixes the shared gas limit at 50,000,000 (`gas_limit / 10`) with no end date, while code requires `shared_gas_limit == 0` from T4. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-enc-04).

### 2.6 Header validity against the parent

For a header `h` with parent `p`:

1. `h.inner.parent_hash == header_hash(p)` and `h.inner.number == p.inner.number + 1`.
2. Gas limit bound: let `d = abs(h.inner.gas_limit - p.inner.gas_limit)`. MUST have `d < p.inner.gas_limit // 1024` and `h.inner.gas_limit >= 5000`. The gas limit is not otherwise fixed by consensus. Mainnet genesis sets 500,000,000 and proposers keep the parent's value.
3. `h.inner.base_fee_per_gas == next_base_fee(p, h.inner.timestamp)` ([§2.7](#27-base-fee)).
4. `h.inner.excess_blob_gas` equals the Osaka (EIP-7918) excess-blob-gas computed from `p`. Under (1)–(3) of [§2.5](#25-standalone-header-validity) this is 0.
5. `timestamp_millis(h) > timestamp_millis(p)` (strict). The seconds timestamp alone is not compared, so two consecutive blocks may share `inner.timestamp` if `timestamp_millis_part` increases.

Checks 1, 2 and 4 are the Ethereum Osaka parent checks (execution-specs `osaka` `validate_header` and `check_gas_limit`, EIP-4844 and EIP-7918 for the excess blob gas). Tempo deviates in two places: the base fee rule of check 3 replaces the EIP-1559 update, and check 5 replaces Ethereum's `h.timestamp > p.timestamp` with a comparison of millisecond timestamps.

### 2.7 Base fee

The base fee rule is selected by the fork active at the **child's** timestamp:

```python
T0_BASE_FEE  = 10_000_000_000
T1_BASE_FEE  = 20_000_000_000
T7_TARGET    = 10_000_000
T7_DENOM     = 8
T7_CAP       = 12_000_000_000
T7_FLOOR     = T7_CAP // 20          # 600_000_000

def next_base_fee(parent, child_timestamp):
    F = fork_at(child_timestamp)
    if F >= T7:
        return t7_next_base_fee(parent.inner.base_fee_per_gas, parent.inner.gas_used)
    if F >= T1:
        return T1_BASE_FEE
    return T0_BASE_FEE

def t7_next_base_fee(base_fee, gas_used):
    if gas_used == T7_TARGET:
        nb = base_fee
    elif gas_used > T7_TARGET:
        nb = base_fee + max(1, base_fee * (gas_used - T7_TARGET) // (T7_TARGET * T7_DENOM))
    else:
        nb = base_fee - base_fee * (T7_TARGET - gas_used) // (T7_TARGET * T7_DENOM)
    return min(max(nb, T7_FLOOR), T7_CAP)
```

Intermediate products are computed in at least 128-bit precision. The first T7 block's parent has base fee `T1_BASE_FEE`, so the clamp yields `T7_CAP` for it. This is not a special case. Unit semantics of the base fee (attodollars) are in [06-transactions-and-fees.md](06-transactions-and-fees.md).

### 2.8 Test vector: mainnet block 1

Header fields: `general_gas_limit = 0x0d693a40`, `shared_gas_limit = 0x02faf080`, `timestamp_millis_part = 0x2c5`, no `consensus_context`. Inner: `parent_hash = 0x49d7ec70…3c54` (mainnet genesis hash, see [01-chain-and-forks.md](01-chain-and-forks.md)), `ommers_hash = EMPTY_OMMER_ROOT_HASH`, `beneficiary = 0x0`, `state_root = 0x83408974…c7f6`, `transactions_root = 0x6cbfac2d…1b44`, `receipts_root = 0xb64408da…65a0`, zero bloom, `difficulty = 0`, `number = 1`, `gas_limit = 0x1dcd6500`, `gas_used = 0`, `timestamp = 0x696aa4c7`, empty `extra_data`, zero `mix_hash`, zero `nonce`, `base_fee_per_gas = 0x2540be400`, `withdrawals_root = EMPTY_ROOT_HASH`, `blob_gas_used = 0`, `excess_blob_gas = 0`, zero `parent_beacon_block_root`, `requests_hash = EMPTY_REQUESTS_HASH`.

```text
rlp (627 bytes) =
f90270 840d693a40 8402faf080 8202c5
  f90260
    a049d7ec7085e77bf5a403d0fcb4cfc42a4084a89dfff60477579c5e09c9e03c54
    a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347
    940000000000000000000000000000000000000000
    a083408974323f63ab969b23f0fe1dba30d7ee5dc5c524a975bae38187eaa2c7f6
    a06cbfac2d2b694b71b37538fe5bcc8450fc4bdab1c3c2119a450e333a724d1b44
    a0b64408da6b8fe39ab764af88ece1e8cca1c35fd988db57806e99138c629365a0
    b90100 00…00 (256 zero bytes)
    80 01 841dcd6500 80 84696aa4c7 80
    a00000000000000000000000000000000000000000000000000000000000000000
    880000000000000000
    8502540be400
    a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
    80 80
    a00000000000000000000000000000000000000000000000000000000000000000
    a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

header_hash = 0x76e86f9739fbe17669b01b24e976ac214742c4b1bbc6ae0c083a87e43a5e9b0f
```

This is the on-chain hash of mainnet block 1. Its body is one system transaction ([§6.4](#64-test-vector)).

---

## 3. Block and body

### 3.1 Encoding

```text
Block = rlp([
    header,         # TempoHeader, §2.1
    transactions,   # list of transactions in network form, §1.4
    ommers,         # list of TempoHeader; MUST be empty
    withdrawals,    # list of EIP-4895 withdrawals; MUST be present and empty
])
```

`withdrawals` is a trailing item that is present on Tempo at every block because Shanghai is active from genesis. A body without it is invalid. Blob sidecars and execution-layer request lists are never part of a Tempo block.

### 3.2 Body validity

1. `keccak256(rlp(ommers)) == header.inner.ommers_hash`, so `ommers == []`.
2. `withdrawals` is present, and `withdrawals_root(withdrawals) == header.inner.withdrawals_root`. In every fork the withdrawals list MUST be empty, so the root is `EMPTY_ROOT_HASH`. A non-empty list is rejected before execution ("withdrawals are not permitted").
3. `transactions_root(transactions) == header.inner.transactions_root` ([§7.3](#73-roots)).
4. `header.inner.blob_gas_used` equals the sum of blob gas of the transactions, which is 0.
5. Block size (EIP-7934, active from genesis because Osaka is): `len(rlp(block)) <= 8388608`, where `rlp(block)` is the canonical re-encoding of the decoded block ([§4.6](#46-canonical-re-encoding)), with typed transactions in wrapped form.
6. System-transaction placement rules of [§6.3](#63-placement-and-validity).

Checks 1–5 are Ethereum Osaka's block-body checks (execution-specs `osaka` `state_transition`, EIP-4895, EIP-4844, EIP-7934). Tempo deviates in that the withdrawals list MUST be empty in every fork.

Ordering of user transactions and lane rules are in [05-block-execution.md](05-block-execution.md).

> **Resolved conflict C-ENC-02**: docs blockspace/overview.mdx lists "start-of-block system transaction(s)" as the first section of every block body, but code defines no start-of-block system transaction in any fork (only the pre-T4 end-of-block transaction of §6). Decided: this spec follows the implementation, and the docs are fixed in [tempoxyz/docs#1098](https://github.com/tempoxyz/docs/pull/1098). See [conflicts](conflicts.md#c-enc-02).

---

## 4. Transactions

### 4.1 Envelope types

| Type byte | Transaction | Encoding |
|---|---|---|
| none (RLP list) | Legacy, with or without EIP-155 | Ethereum, execution-specs Osaka `LegacyTransaction` |
| `0x01` | EIP-2930 | Ethereum (EIP-2930) |
| `0x02` | EIP-1559 | Ethereum (EIP-1559) |
| `0x04` | EIP-7702 | Ethereum (EIP-7702) |
| `0x76` | Tempo transaction | [§4.3](#43-tempo-transaction-0x76) |

All other type bytes are decode-invalid in every fork, including `0x03` (EIP-4844 blob transactions are not supported) and `0x00` (a legacy transaction MUST NOT carry a type byte). This set is the same at every fork from genesis through T13.

The Ethereum types are encoded, signed and hashed exactly as in execution-specs Osaka (Legacy: `keccak256(rlp([nonce, gas_price, gas, to, value, data, v, r, s]))` with EIP-155 `v = 35 + 2·chain_id + y_parity` or `27 + y_parity`; typed: `keccak256(type || rlp([...]))`). Whether a given decodable transaction is valid (chain id, signature low-s, gas caps, value transfer rules) is defined in [06-transactions-and-fees.md](06-transactions-and-fees.md).

One legacy transaction shape is reserved for the protocol: a legacy transaction whose signature is `(r = 0, s = 0, y_parity = 0)` is a **system transaction** ([§6](#6-pre-t4-end-of-block-system-transaction)).

### 4.2 Transaction hash and identifier

For every type:

```python
def tx_hash(tx) -> B256:
    return keccak256(encode_2718(tx))     # canonical re-encoding, §4.6

def unique_tx_identifier(tx, sender: Address) -> B256:
    # sender-scoped replay identifier; where it is used is defined in 06-transactions-and-fees.md
    return keccak256(encode_for_signing(tx) || sender)
```

`encode_for_signing(tx)` is the exact preimage whose keccak256 is the sender signing hash: the Ethereum signing payload for the Ethereum types, and [§4.5.1](#451-sender-signing-hash) for `0x76`. For `0x76` the identifier is also called the expiring-nonce hash. Because `encode_for_signing` of a sponsored `0x76` transaction omits `fee_token` and the fee-payer signature, the identifier does not change when the fee payer or fee token changes.

### 4.3 Tempo transaction (0x76)

2718 encoding: `0x76 || rlp(fields)`, where `fields` is the following list. Items 0–12 are always present. Item 13 is present only when a key authorization is attached. The sender signature is always last.

| # | Field | Type | Encoding |
|---|---|---|---|
| 0 | `chain_id` | u64 | integer |
| 1 | `max_priority_fee_per_gas` | u128 | integer |
| 2 | `max_fee_per_gas` | u128 | integer |
| 3 | `gas_limit` | u64 | integer |
| 4 | `calls` | list of `Call` | `[[to, value, input], …]` |
| 5 | `access_list` | EIP-2930 access list | `[[address, [storage_key, …]], …]` |
| 6 | `nonce_key` | U256 | integer |
| 7 | `nonce` | u64 | integer |
| 8 | `valid_before` | optional NonZeroU64 | convention C: `0x80` ↔ absent |
| 9 | `valid_after` | optional NonZeroU64 | convention C: `0x80` ↔ absent |
| 10 | `fee_token` | optional Address | convention C: `0x80` ↔ absent, else 20-byte string |
| 11 | `fee_payer_signature` | optional secp256k1 signature | convention C: `0x80` ↔ absent, else `[y_parity, r, s]` |
| 12 | `aa_authorization_list` | list of `TempoSignedAuthorization` | `[[chain_id, address, nonce, signature], …]` |
| 13 | `key_authorization` | optional `SignedKeyAuthorization` | convention D; [§5](#5-key-authorization) |
| last | `signature` | `TempoSignature` | RLP byte string; content per [03-signatures.md](03-signatures.md) |

Sub-structures:

- `Call = rlp([to, value, input])`. `to` is `0x80` for contract creation or a 20-byte string for a call target. `value` is a U256. `input` is a byte string. Exactly three items.
- `fee_payer_signature = rlp([y_parity, r, s])`. `y_parity` is a `bool` (`0x80` or `0x01`), `r` and `s` are U256 integers. Exactly three items. The fee-payer signature is always secp256k1. Its recovery and the low-s rule are in [03-signatures.md](03-signatures.md).
- `TempoSignedAuthorization = rlp([chain_id, address, nonce, signature])`. `chain_id` is a U256, `address` an Address, `nonce` a u64, and `signature` an RLP byte string holding a `TempoSignature` ([03-signatures.md](03-signatures.md)). Exactly four items.

Some sources call `aa_authorization_list` `tempo_authorization_list`. The two names denote the same field.

#### 4.3.1 Decoding

```python
def decode_tempo_tx(payload: bytes) -> TempoSignedTx:   # payload = bytes after the 0x76 type byte
    lst = read_rlp_list_header(payload)                  # MUST be a list
    chain_id                 = lst.decode(u64)
    max_priority_fee_per_gas = lst.decode(u128)
    max_fee_per_gas          = lst.decode(u128)
    gas_limit                = lst.decode(u64)
    calls                    = lst.decode(list_of(Call))
    access_list              = lst.decode(AccessList)
    nonce_key                = lst.decode(U256)
    nonce                    = lst.decode(u64)
    valid_before = lst.decode(u64) or None               # 0 (0x80) means absent
    valid_after  = lst.decode(u64) or None
    if lst.peek() == 0x80:
        lst.skip(1); fee_token = None
    else:
        fee_token = lst.decode(Address)                  # exactly 20 bytes
    if lst.peek() == 0x80:
        lst.skip(1); fee_payer_signature = None
    else:
        fee_payer_signature = lst.decode_list(bool, U256, U256)   # exactly 3 items
    aa_authorization_list    = lst.decode(list_of(TempoSignedAuthorization))
    if lst.remaining() > 0 and lst.peek() >= 0xc0:      # next item is a list
        key_authorization = lst.decode(SignedKeyAuthorization)   # §5
    else:
        key_authorization = None
    tx = TempoTransaction(...)
    validate_structure(tx)                               # §4.3.2; failure is decode-invalid
    sig_bytes = lst.decode(bytes)                        # MUST be an RLP string
    if lst.remaining() != 0: raise DecodeError           # no trailing items
    signature = TempoSignature.from_bytes(sig_bytes)     # 03-signatures.md; failure is decode-invalid
    return TempoSignedTx(tx, signature)
```

A reader that runs out of input where an item is expected fails to decode (for example, a list that ends right after `aa_authorization_list` lacks a signature).

#### 4.3.2 Decode-time structural validity

The decoder rejects, as decode-invalid in every fork:

1. `calls` is empty;
2. `calls[0].to` is creation and `aa_authorization_list` is non-empty;
3. any `calls[i].to` with `i >= 1` is creation;
4. both `valid_before` and `valid_after` are present and `valid_before <= valid_after`.

All other 0x76 rules (chain id, nonce modes, time window against the block, fee payer recovery, key-authorization fork gating, keychain version gating, intrinsic gas, the reserved `nonce_key` prefix in [§6.5](#65-reserved-nonce-key-prefix)) are validity rules of the transaction in a block, defined in [06-transactions-and-fees.md](06-transactions-and-fees.md). A transaction that fails one of them still has a well-defined encoding and hash.

### 4.4 Signature field

The `signature` item, the `signature` of each `TempoSignedAuthorization` and the `signature` of a `SignedKeyAuthorization` are RLP byte strings whose contents are signature byte encodings defined in [03-signatures.md](03-signatures.md). Their lengths and type bytes are: 65 bytes untyped secp256k1; `0x01` P256; `0x02` WebAuthn; `0x03` Keychain V1; `0x04` Keychain V2; `0x05` configurable account. Which of these is **valid** in which fork and position (for example V2 only from T1C, V1 only before T1C, `0x05` never valid at T13 or earlier) is defined in [03-signatures.md](03-signatures.md). This chapter only requires that they decode.

### 4.5 Signing hashes

All signing hashes are computed over the canonical re-encoding ([§4.6](#46-canonical-re-encoding)) of the decoded transaction.

#### 4.5.1 Sender signing hash

The sender signs `keccak256(encode_for_signing(tx))`:

```python
def encode_for_signing(tx) -> bytes:
    sponsored = tx.fee_payer_signature is not None
    items = [
        rlp(tx.chain_id), rlp(tx.max_priority_fee_per_gas), rlp(tx.max_fee_per_gas),
        rlp(tx.gas_limit), rlp(tx.calls), rlp(tx.access_list), rlp(tx.nonce_key), rlp(tx.nonce),
        rlp(tx.valid_before or 0),                        # 0x80 when absent
        rlp(tx.valid_after or 0),
        b"\x80" if (sponsored or tx.fee_token is None) else rlp(tx.fee_token),
        b"\x00" if sponsored else b"\x80",                # raw byte 0x00 placeholder, not RLP of an integer
        rlp(tx.aa_authorization_list),
    ]
    if tx.key_authorization is not None:
        items.append(rlp(tx.key_authorization))          # §5, canonical re-encoding
    payload = b"".join(items)
    return b"\x76" + rlp_list_header(len(payload)) + payload
```

So when a fee payer signature is present, the sender does not commit to `fee_token` (it is replaced by `0x80`), and the fee-payer slot holds the single raw byte `0x00`. The sender signature itself is never part of the preimage. `key_authorization` is included, signature and all, when present.

#### 4.5.2 Fee-payer signing hash

The fee payer signs `fee_payer_signing_hash(tx, sender)`, where `sender` is the address recovered from the sender signature ([03-signatures.md](03-signatures.md)):

```python
def fee_payer_signing_hash(tx, sender: Address) -> B256:
    items = [
        rlp(tx.chain_id), rlp(tx.max_priority_fee_per_gas), rlp(tx.max_fee_per_gas),
        rlp(tx.gas_limit), rlp(tx.calls), rlp(tx.access_list), rlp(tx.nonce_key), rlp(tx.nonce),
        rlp(tx.valid_before or 0), rlp(tx.valid_after or 0),
        b"\x80" if tx.fee_token is None else rlp(tx.fee_token),   # always committed
        rlp(sender),                                               # 0x94 || 20 bytes
        rlp(tx.aa_authorization_list),
    ]
    if tx.key_authorization is not None:
        items.append(rlp(tx.key_authorization))
    payload = b"".join(items)
    return keccak256(b"\x78" + rlp_list_header(len(payload)) + payload)
```

#### 4.5.3 Authorization-list signing hash

Each `TempoSignedAuthorization` is signed over the EIP-7702 hash `keccak256(0x05 || rlp([chain_id, address, nonce]))` (with `chain_id` as U256). Keychain-wrapped signatures transform this digest as defined in [03-signatures.md](03-signatures.md).

#### 4.5.4 Transaction hash

```python
def tempo_tx_hash(tx) -> B256:
    payload = encode_fields_with_signature(tx)   # items 0..12 as in §4.3, key_authorization?, rlp(sig_bytes)
    return keccak256(b"\x76" + rlp_list_header(len(payload)) + payload)
```

The fields are written as in §4.3: `valid_before`/`valid_after` as `0x80` when absent, `fee_token` as `0x80` or 20 bytes, `fee_payer_signature` as `0x80` or `[y_parity, r, s]`, `key_authorization` omitted entirely when absent, and the signature as an RLP string of its canonical bytes.

### 4.6 Canonical re-encoding

<a id="canonical-re-encoding"></a>

Decoding is not injective for the signature byte strings in a Tempo transaction. Every other item in this chapter round-trips byte-for-byte. Two primitive-signature encodings are malleable:

1. **secp256k1 (65 bytes, `r || s || v`).** The decoder accepts `v ∈ {0, 1, 27, 28} ∪ [35, 255]` and derives `y_parity`:
   ```python
   def parity_from_v(v):
       if v in (0, 1): return v == 1
       if v in (27, 28): return v == 28
       if v >= 35: return (v - 35) % 2 == 1
       raise DecodeError            # v in 2..26 or 29..34
   ```
   The canonical encoding writes `v = 27 + y_parity`. `r` and `s` are any 32-byte values at decode; range and low-s checks belong to verification ([03-signatures.md](03-signatures.md)).
2. **P256 (`0x01 || r || s || x || y || pre_hash`).** The decoder sets `pre_hash = (byte != 0)`. The canonical encoding writes `0x01` for true and `0x00` for false.

These rules apply to every primitive signature inside a `0x76` transaction: the sender `signature` (directly, or as the inner signature of a Keychain V1/V2 envelope), every `aa_authorization_list[i].signature` (directly or inside Keychain), and `key_authorization.signature`. WebAuthn and the Keychain envelope header (type byte and 20-byte user address) are not malleable.

Normative rule: a client MUST accept every encoding the decoder accepts, and MUST compute **every** hash, root and length over the canonical re-encoding of the decoded value, never over the received bytes. This covers the transaction hash, the sender signing hash and fee-payer signing hash (which embed `key_authorization`, and so its re-encoded signature), `unique_tx_identifier`, the transactions root ([§7.3](#73-roots)) and the block size ([§3.2](#32-body-validity)). A client that hashes the received bytes computes a different `transactions_root` for a block containing, say, a `v = 0` signature, and rejects a block the network accepts. Encoders MUST emit canonical bytes.

The Ethereum transaction types are not malleable this way: their signatures are RLP integers and the legacy `v` re-encodes from `(y_parity, chain_id)` to the same bytes.

### 4.7 Test vectors: Tempo transactions

Both vectors below were produced by the encoder that produced mainnet blocks, and each hash was recomputed independently from the rules of §4.2, §4.5 and [03-signatures.md §8.1](03-signatures.md#81-effective-digest). Every secp256k1 signature is the deterministic RFC 6979 signature of the stated key, written canonically (`v = 27 + y_parity`).

Keys (secp256k1 private keys, as 32-byte big-endian integers):

| Role | Private key | Address |
|---|---|---|
| root account (sender) | 1 | `0x7e5f4552091a69125d5dfcb7b8c2659029395bdf` |
| access key | 2 | `0x2b5ad5c4795c026514f8317c7a215e218dccd6cf` |
| fee payer (vector B only) | 3 | `0x6813eb9362372eef6200f3b1dbc3f819671cba69` |

Shared parts. The key authorization is `KeyAuthorization{chain_id = 4217, key_type = Secp256k1, key_id = access key, expiry = 1800000000, limits = [TokenLimit{token = 0x20c0…0000, limit = 1000000000, period = 0}]}`, signed by the root key. The one call is `transfer(0x…beef, 1000000)` on the TIP-20 token `0x20c0000000000000000000000000000000000000`.

```text
KeyAuthorization (digest preimage, 60 bytes) =
f83a 821079 80 942b5ad5c4795c026514f8317c7a215e218dccd6cf 846b49d200
     db da 9420c0000000000000000000000000000000000000 843b9aca00
key_authorization_digest = 0x03785f7bb7714bd3d7523ae46397f923acba6751aa6eabb581755d71b9e5a666

SignedKeyAuthorization (129 bytes) =
f87f f83a…3b9aca00 (as above)
     b841 512f817ac191fb563b836711c554a3af4e25ad204f4614697e808c6385359eae
          73b504f0ad61d830d6c5acb2f6370d3d6cacaefaf2f37778ed21e6149ca48d21 1b

calls item (96 bytes) =
f85e f85c 9420c0000000000000000000000000000000000000 80
          b844 a9059cbb 000000000000000000000000000000000000000000000000000000000000beef
                        00000000000000000000000000000000000000000000000000000000000f4240
```

The key type `Secp256k1` (0) encodes as `80`, and the `TokenLimit` with `period = 0` is the two-item list `da…`.

#### 4.7.1 Vector A: unsponsored, expiring nonce, Keychain V2

Fields: `chain_id = 4217`, `max_priority_fee_per_gas = 0`, `max_fee_per_gas = 20000000000`, `gas_limit = 1000000`, the call above, empty `access_list`, `nonce_key = 2**256 − 1`, `nonce = 0`, `valid_before = 1781013630`, no `valid_after`, no `fee_token`, no `fee_payer_signature`, empty `aa_authorization_list`, the key authorization above. The signature is a Keychain V2 signature of the access key for the root account.

```text
encode_for_signing (287 bytes) =
76 f9011b
   821079 80 8504a817c800 830f4240        # chain_id, priority fee 0, max fee, gas_limit
   f85e…0f4240                            # calls
   c0                                     # access_list
   a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff   # nonce_key
   80 846a281c7e 80                       # nonce 0, valid_before, valid_after absent
   80 80                                  # fee_token absent, fee-payer slot 0x80 (unsponsored)
   c0                                     # aa_authorization_list
   f87f…1b                                # SignedKeyAuthorization
sender_signing_hash            = 0xb741450401746f1fb6892e853995c06d8ce27e57beafc4be4caf7860bc023ba4
keychain V2 effective digest   = keccak256(04 || sender_signing_hash || 7e5f…5bdf)
                               = 0xad38c1fd8c1b45415672987337d7368d63adb0723c4418c4fe85dc3288d8104b

signature (86 bytes) =
04 7e5f4552091a69125d5dfcb7b8c2659029395bdf          # Keychain V2, user_address
   5281c2b6ab2f2d828006916c1269004f0cc860bf27f9934f2630c4860d9e46be   # inner r (access key)
   12f01c6466e4b969d156d656b81a50d2b17d26b051c092aac24010eb2254757b   # inner s
   1c                                                                  # inner v

tx (2718, 375 bytes) =
76 f90173 <the 283 payload bytes of encode_for_signing> b856 <signature>
tx_hash             = 0x07d210e402c8128344b99c6e70722806487f0228bcbd8112309d209a5ddb27e7
unique_tx_identifier (expiring-nonce replay hash from T1B)
                    = keccak256(encode_for_signing || 7e5f…5bdf)
                    = 0x3acce9d1bddd6e2136e949bb944174634f3baacc8095cc254273fb71e77896c1
```

Recovering the inner signature over the effective digest gives the access key `0x2b5a…d6cf`; the sender is `user_address` `0x7e5f…5bdf`.

#### 4.7.2 Vector B: sponsored, Keychain V2

As vector A, except `nonce_key = 0`, `nonce = 5`, no `valid_before`, `fee_token = 0x20c0000000000000000000000000000000000000`, and a fee-payer signature by the fee payer key.

```text
encode_for_signing (250 bytes) =
76 f8f7
   821079 80 8504a817c800 830f4240 f85e…0f4240 c0
   80 05 80 80                            # nonce_key 0, nonce 5, valid_before, valid_after absent
   80                                     # fee_token omitted because sponsored
   00                                     # raw fee-payer placeholder byte (sponsored)
   c0 f87f…1b
sender_signing_hash            = 0xae25a1a3af1535b6deb22f5a44dd711756529573c02fe3805a8a8d6cdcad82d5
keychain V2 effective digest   = 0xdbbf18ebb55b6a878bd10fd6a22ae0e73c8d8eadb8f33558eb6a5b1c70a1b58c

fee-payer preimage (291 bytes) =
78 f9011f
   821079 80 8504a817c800 830f4240 f85e…0f4240 c0
   80 05 80 80
   9420c0000000000000000000000000000000000000   # fee_token, always committed
   947e5f4552091a69125d5dfcb7b8c2659029395bdf   # sender (root account)
   c0 f87f…1b
fee_payer_signing_hash = 0x3cc7225f8b58dcf8a32d1a453d50253851edbd09669db6cf18dc3a4a67a8e79f

signature (86 bytes) =
04 7e5f4552091a69125d5dfcb7b8c2659029395bdf
   5e836d0a259cc2822bb7c2f90f01898a2e5d4d9c82e0b8490ce40e608126d879
   056931aa9546d65cc3b1acab1dca90f14ebc158fef9a75cc44fc93221b26bf5c
   1b

fee_payer_signature item (69 bytes) =
f843 80                                                              # y_parity 0
     a09a2196bd029ad312d59c051d697a9bb34a4498cf3e723b9a03e0590c37666ce3
     a00b2fb4aaa465dfca145b85f5d84c5aa3b2c41e328d0a57ac14937a9d08878ba0

tx (2718, 427 bytes) =
76 f901a7
   821079 80 8504a817c800 830f4240 f85e…0f4240 c0 80 05 80 80
   9420c0000000000000000000000000000000000000   # fee_token
   f843…878ba0                                  # fee_payer_signature
   c0 f87f…1b
   b856 <signature>
tx_hash = 0x91a94bcf1b45ccfd5e6026548f8d9cacc8620e5baf2e399dc8a194f7a249a305
```

The sender preimage of vector B is the same whatever the fee payer's signature and fee token are: replacing `fee_token` or the fee-payer signature changes `tx_hash` but not `sender_signing_hash`.

---

## 5. Key authorization

A `0x76` transaction MAY carry a `SignedKeyAuthorization` that provisions an access key in the AccountKeychain precompile ([precompiles/account-keychain.md](precompiles/account-keychain.md)).

### 5.1 KeyAuthorization

`KeyAuthorization` is an RLP list of three required fields followed by six optional fields under convention B ([§1.3](#13-optional-fields)):

```text
KeyAuthorization = rlp([
    chain_id,        # u64
    key_type,        # u8: 0 Secp256k1, 1 P256, 2 WebAuthn, 3 ConfigurableAccount; any other value is decode-invalid
    key_id,          # Address
    expiry?,         # NonZeroU64; absent = never expires
    limits?,         # list of TokenLimit; absent = unlimited; [] = no spending allowed
    allowed_calls?,  # list of CallScope; absent = unrestricted; [] = scoped, nothing allowed
    witness?,        # B256 (exactly 32 bytes); absent = no witness; present zero is a witness
    is_admin?,       # NonZeroU64 that MUST equal 1; absent = false
    account?,        # Address
])
```

- `key_type` 0 encodes as `0x80`. The one-byte string `0x00` is decode-invalid (leading zero).
- `is_admin`: the decoder reads a `NonZeroU64` and rejects any value other than 1 ("invalid admin key authorization marker"). The encoder writes `0x01` for true and treats false as absent.
- `expiry` cannot be zero on the wire: a final `0x80` is decode-invalid, and a middle `0x80` is the absent placeholder.

### 5.2 TokenLimit, CallScope, SelectorRule

```text
TokenLimit   = rlp([token, limit, period?])      # Address, U256, NonZeroU64 under convention B
CallScope    = rlp([target, selector_rules])     # Address, list of SelectorRule; both required
SelectorRule = rlp([selector, recipients])       # bytes4 (exactly 4 bytes), list of Address; both required
```

- `TokenLimit.period` absent means `period = 0` (a one-time limit). The canonical one-time encoding is the two-item form `[token, limit]`. The three-item form with `period` encoded as `0x80` is decode-invalid, because `0x80` in the last position is decoded as a `NonZeroU64` and zero is rejected.
- `CallScope.selector_rules` and `SelectorRule.recipients` are always present. The empty list `0xc0` means "any selector" and "any recipient" respectively.

> **Resolved conflict C-ENC-05**: TIP-1011 says `expiry`/`limits` None encode as `0x80` and that a final `0x80` for `allowed_calls` and the three-item `TokenLimit` with `period = 0` MUST be accepted; the code's canonical decoder rejects any `0x80` that ends the list. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-enc-05).

### 5.3 SignedKeyAuthorization

```text
SignedKeyAuthorization = rlp([
    rlp(KeyAuthorization),   # the complete KeyAuthorization list, nested as one item
    signature,               # RLP byte string: a primitive signature (03-signatures.md)
])
```

This is a two-item list: the authorization is a **nested** list, not spliced field by field into the outer list. In the 0x76 decoder ([§4.3.1](#431-decoding)), it is recognised by its first byte being `>= 0xc0`. The signature is an "account signature": a primitive signature (65-byte secp256k1, `0x01` P256 or `0x02` WebAuthn), or a `0x05` configurable-account signature. A Keychain envelope (`0x03`/`0x04`) in this position is decode-invalid. Validity of `0x05` here is defined in [03-signatures.md](03-signatures.md) (never valid at T13 or earlier).

> **Resolved conflict C-ENC-01**: docs spec-tempo-transaction.mdx and TIP-0001 define the signed form as the flat list `rlp([chain_id, key_type, key_id, expiry?, …, signature])`; code encodes and decodes the nested two-item list `rlp([rlp(KeyAuthorization), signature])`. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-enc-01).

### 5.4 Digest

```python
def key_authorization_digest(auth: KeyAuthorization) -> B256:
    return keccak256(rlp(auth))      # canonical encoding of the unsigned KeyAuthorization list
```

There is no domain prefix. Under convention B every accepted encoding re-encodes to identical bytes, so the digest equals keccak256 of the received inner-list bytes.

### 5.5 Fields by fork

The wire format and decoder are the same in every fork. The fields are gated by fork as **validity** rules, applied when the transaction is validated in a block. The full check order is in [06-transactions-and-fees.md](06-transactions-and-fees.md) and [precompiles/account-keychain.md](precompiles/account-keychain.md).

| Field / feature | Before T1C | T1C ≤ fork < T3 | T3 ≤ fork < T5 | T5 ≤ fork < T6 | From T6 |
|---|---|---|---|---|---|
| `chain_id == 0` | accepted as wildcard (any chain) | MUST equal the chain id | same | same | same |
| `chain_id != 0` | MUST equal the chain id | MUST equal | same | same | same |
| `TokenLimit.period != 0` | invalid ("periodic token limits are not active before T3") | invalid | allowed | allowed | allowed |
| `allowed_calls` present | invalid ("call scopes are not active before T3") | invalid | allowed | allowed | allowed |
| `witness` present | invalid | invalid | invalid ("key authorization witnesses are not active before T5") | allowed | allowed |
| `is_admin` or `account` present | invalid | invalid | invalid | invalid ("T6 key authorization fields are not active before T6") | allowed |
| `key_type == 3` (configurable account) | see [03-signatures.md](03-signatures.md): not valid at T13 or earlier | | | | |

So in practice, the encoding of a valid key authorization is:

- **T0 ≤ fork < T3:** `[chain_id, key_type, key_id, expiry?, limits?]` with every `TokenLimit = [token, limit]`.
- **T3 ≤ fork < T5:** adds `allowed_calls?` and `TokenLimit.period?`.
- **T5 ≤ fork < T6:** adds `witness?`.
- **From T6:** adds `is_admin?` and `account?`.

> **Resolved conflict C-ENC-06**: docs spec-tempo-transaction.mdx say the key-authorization `chain_id` MUST equal the executing chain and "zero is not a wildcard", and TIP-0001 says "0 = valid on any chain", neither with a fork qualifier. Code treats 0 as a wildcard before T1C and requires an exact match from T1C. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-enc-06).

### 5.6 Test vector

`KeyAuthorization{chain_id = 42170, key_type = P256, key_id = 0x…dead, expiry = 1700100000, limits = [TokenLimit{token = 0x…42, limit = 1000000, period = 86400}]}`, signed with a P256 signature `r = 0x11×32, s = 0x22×32, x = 0x33×32, y = 0x44×32, pre_hash = false`:

```text
f8c3                                   # SignedKeyAuthorization list (195-byte payload)
  f83d                                 # KeyAuthorization list (61-byte payload)
    82a4ba                             # chain_id 42170
    01                                 # key_type P256
    94000000000000000000000000000000000000dead
    84655577a0                         # expiry 1700100000
    de                                 # limits (30-byte list)
      dd 940000000000000000000000000000000000000042 830f4240 83015180   # TokenLimit (29-byte list)
  b882 01 1111…11 2222…22 3333…33 4444…44 00     # 130-byte P256 signature string
```

The inner `f83d…` list (63 bytes) is the digest preimage. The `TokenLimit` item `dd…` holds the token, `limit = 0x0f4240` and `period = 0x015180`; with `period = 0` it would be the two-item list `d9 94…42 830f4240` (25-byte payload).

---

## 6. Pre-T4 end-of-block system transaction

### 6.1 Recognition

A transaction is a **system transaction** iff it is a legacy transaction whose decoded signature is exactly `(r = 0, s = 0, y_parity = 0)`. Its sender is `0x0000000000000000000000000000000000000000` by definition. No signature recovery is performed.

A system transaction is well-formed iff `nonce == 0`, `gas_price == 0`, `gas_limit == 0`, `value == 0`, and its EIP-155 `chain_id` equals the chain id (so `v = 35 + 2·chain_id`, which is 8469 on mainnet). A system transaction without an EIP-155 chain id is not well-formed.

### 6.2 Encoding

```text
system_tx = rlp([
    0x80,                 # nonce 0
    0x80,                 # gas_price 0
    0x80,                 # gas_limit 0
    0x94 || 0x00×20,      # to = 0x0000000000000000000000000000000000000000
    0x80,                 # value 0
    rlp_string(input),
    rlp(35 + 2·chain_id), # v
    0x80,                 # r = 0
    0x80,                 # s = 0
])

input = rlp([SubBlockMetadata, …]) || be32(block.number)

SubBlockMetadata = rlp([
    version,          # u8, MUST be 1 (encoded 0x01)
    validator,        # B256
    fee_recipient,    # Address
    signature,        # bytes
])
```

The input is checked as follows:

```python
def validate_system_tx_input(input, block_number):
    if len(input) < 32: invalid
    metadata, suffix = input[:-32], input[-32:]
    if suffix != be32(block_number): invalid
    rest = metadata
    lst = decode(list_of(SubBlockMetadata), rest)   # each item exactly 4 fields; version == 1
    if rest_remaining != 0: invalid                 # no bytes after the list
```

The contents of `validator`, `fee_recipient` and `signature` are not checked.

### 6.3 Placement and validity

- **Before T4:** every block MUST contain exactly one system transaction. It MUST be the last transaction of the block, it MUST have `to = 0x0`, and it MUST be well-formed with a valid input (§6.2). A block with no transactions is therefore invalid before T4. No non-system transaction may follow a system transaction, and a second system transaction is invalid ("duplicate subblocks metadata system transaction").
- **From T4:** a block MUST NOT contain any system transaction. One with `to = 0x0` is rejected ("subblocks are disabled in T4+"), and one with any other `to` is rejected ("invalid system transaction").
- In every fork, a system transaction with `to != 0x0` is invalid.

Check order before execution: (1) every system transaction anywhere in the block MUST be well-formed; (2) before T4, the last transaction MUST be a system transaction, and from T4 the expected count is 0; (3) before T4, the last transaction's `to` MUST be `0x0`; (4) the Ethereum body checks of [§3.2](#32-body-validity). During execution, each system transaction's input is checked (§6.2) and its position and uniqueness enforced. Execution of the system transaction (a call from `0x0` that consumes no block gas, with a successful receipt) is defined in [05-block-execution.md](05-block-execution.md). Its receipt is encoded as a legacy receipt ([§7.1](#71-receipts)).

> **Resolved conflict C-ENC-03**: TIP-1046 §9 says T4 "allows blocks to omit" the empty subblocks-metadata transaction, implying an empty one stays acceptable; code rejects every system transaction from T4. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-enc-03).

### 6.4 Test vector

Mainnet block 1 (chain id 4217) contains exactly one transaction, the system transaction with an empty metadata list:

```text
input   = c0 || be32(1)
tx      = f840 80 80 80 940000000000000000000000000000000000000000 80
          a1 c00000000000000000000000000000000000000000000000000000000000000001
          822115 80 80
tx_hash = 0x6c80b11764e6020da93126a323b29596b342d2697c54ffc550645924da53e67c
transactions_root = 0x6cbfac2d2b694b71b37538fe5bcc8450fc4bdab1c3c2119a450e333a724d1b44
receipt (legacy) = rlp([0x01, 0x80, 256 zero bytes, []])     # status 1, cumulative_gas_used 0, no logs
receipts_root     = 0xb64408da6b8fe39ab764af88ece1e8cca1c35fd988db57806e99138c629365a0
```

Both roots match the block 1 header in [§2.8](#28-test-vector-mainnet-block-1).

### 6.5 Reserved nonce-key prefix

A `0x76` transaction whose `nonce_key` has most-significant byte `0x5b` (`nonce_key >> 248 == 0x5b`) is a "subblock transaction". Such a transaction is invalid in a block in every fork ("subblock transactions are not supported"). The encoding is unaffected.

---

## 7. Receipts, bloom and roots

### 7.1 Receipts

A receipt is `(tx_type, status, cumulative_gas_used, logs)`. There is no fee or gas-price field. Its 2718 encoding is:

```text
receipt_payload = rlp([status, cumulative_gas_used, logs_bloom, logs])
    status              = bool: 0x01 success, 0x80 failure
    cumulative_gas_used = u64
    logs_bloom          = 256 bytes, bloom of this receipt's logs (§7.2)
    logs                = [[address, [topic, …], data], …]

encode_2718(receipt) = receipt_payload                 if tx_type is legacy (including system transactions)
                     = tx_type || receipt_payload       otherwise (0x01, 0x02, 0x04, 0x76)
```

The values of `status`, `cumulative_gas_used` and `logs` (including protocol-emitted logs and their order) are defined in [05-block-execution.md](05-block-execution.md). Receipts are never part of the block body.

### 7.2 Logs bloom

The Ethereum 2048-bit bloom (Yellow Paper §4.3.1, execution-specs `logs_bloom`): for the log address and each topic, take `h = keccak256(item)`. For `i` in 0, 1, 2, set bit `((h[2i] << 8) | h[2i+1]) & 2047` (bit 0 is the least-significant bit of byte 255). A receipt's bloom covers its logs. The header `logs_bloom` is the bitwise OR of all receipt blooms of the block.

### 7.3 Roots

All roots are Ethereum Merkle-Patricia trie roots (execution-specs `trie_root`, non-secured, keys not hashed). The root of an empty trie is `EMPTY_ROOT_HASH`.

```python
def ordered_trie_root(values: list[bytes]) -> B256:
    return trie_root({rlp(i): values[i] for i in range(len(values))})

transactions_root = ordered_trie_root([encode_2718(tx) for tx in block.transactions])   # canonical, §4.6
receipts_root     = ordered_trie_root([encode_2718(r) for r in receipts])
withdrawals_root  = ordered_trie_root([rlp(w) for w in block.withdrawals])              # always EMPTY_ROOT_HASH
```

The trie values are the 2718 encodings (not the RLP-string-wrapped network form). For example a `0x76` transaction contributes `0x76 || rlp(fields)`. After execution, `header.inner.receipts_root`, `header.inner.logs_bloom` and `header.inner.gas_used` MUST equal the values computed from the receipts ([05-block-execution.md](05-block-execution.md)).
