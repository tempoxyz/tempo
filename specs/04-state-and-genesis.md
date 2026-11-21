# 04. State model and genesis

This chapter defines how Tempo state is represented and committed to, which addresses are reserved, and how the genesis block and genesis state of Tempo mainnet (chain ID 4217) are constructed. It also gives the expected genesis values a client MUST reproduce.

Fork names and the predicate "fork F active" are defined in [01-chain-and-forks.md](01-chain-and-forks.md#fork-model). Encodings of headers and RLP conventions are in [02-encoding.md](02-encoding.md).

## 1. State model

### 1.1 World state

Tempo state is the Ethereum world state, committed to by the Ethereum Merkle Patricia Trie exactly as in execution-specs Osaka (`ethereum/osaka/trie.py`, "secure" trie):

- The **state trie** maps `keccak256(address)` (32 bytes) to `rlp(account)`.
- Each account's **storage trie** maps `keccak256(slot)` (slot as a 32-byte big-endian word) to `rlp(value)`, where `value` is the 256-bit slot value as a minimal big-endian byte string (no leading zero bytes).
- A storage slot whose value is zero is **absent** from the storage trie. This also applies to genesis allocations: a slot listed in the genesis file with value zero MUST NOT be inserted (see §4.4).
- The empty trie root is `0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421`.
- `header.state_root` is the root of the state trie after the block's execution, including all fork-boundary state changes and system calls ([05-block-execution.md](05-block-execution.md)).

EIP-161 account-emptiness and touched-account deletion rules apply unchanged (the EVM runs at the Osaka spec in every fork, see [01-chain-and-forks.md](01-chain-and-forks.md#ethereum-baseline)).

### 1.2 Account encoding

In every fork up to and including T13, an account leaf MUST be the 4-item Ethereum account RLP:

```
rlp([nonce: uint64, balance: uint256, storage_root: bytes32, code_hash: bytes32])
```

with integers encoded as minimal big-endian strings (`0` encodes as the empty string `0x80`), `storage_root` the root of the account's storage trie and `code_hash = keccak256(code)` (`0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470` for empty code).

T14 adds an optional fifth RLP item to the account leaf, the *account extension*, which holds configurable-account commitments and is encoded only when non-empty. At or before T13:

- No state transition can produce a non-empty extension: before T14 no precompile, opcode or transaction path writes an account configuration commitment (the configurable-account constructs that write it are introduced by T14 and are rejected or absent at every fork in scope; see [03-signatures.md §9](03-signatures.md#9-configurable-account-signatures-0x05-at-or-before-t13) and [06-transactions-and-fees.md §4.2](06-transactions-and-fees.md#42-structure-checks) item 2).
- At or before T13, no reachable account leaf has a fifth item, so every account leaf is the 4-item list above. A genesis allocation MUST NOT carry an account `extension` (§4.4). No client enforces the 4-item form: the reference decodes a non-empty fifth item at any fork.

### 1.3 Code

Account code is stored by hash as in Ethereum. Tempo adds no code format of its own. The single-byte code `0xEF` is used as a **marker** for protocol accounts (§2.2). Its hash is:

```
keccak256(0xEF) = 0x309b8896ee4c1ff7ec1966155373dee42663b6b40c3fedc70ba501684848d2a3
```

Because Osaka applies EIP-3541, no CREATE/CREATE2 or creation transaction can deploy code starting with `0xEF`. Marker code is only ever written by genesis, by precompile initialization, or by the protocol at fork boundaries.

## 2. Precompiles and protocol accounts

### 2.1 Which addresses are precompiles

At fork F, an address `a` is a **Tempo precompile** iff either:

1. `a` starts with the 12-byte TIP-20 prefix `0x20C000000000000000000000` (any 8-byte suffix, whether or not a token was created there), or
2. `a` appears in the system precompile table below and F is the listed activation fork or later.

| Address | Precompile | Active from |
|---|---|---|
| `0x403C000000000000000000000000000000000000` | TIP-403 registry | Genesis |
| `0xfeEC000000000000000000000000000000000000` | Fee manager (TipFeeManager / FeeAMM) | Genesis |
| `0xDEc0000000000000000000000000000000000000` | Stablecoin DEX | Genesis |
| `0x4e4F4E4345000000000000000000000000000000` | Nonce manager | Genesis |
| `0xaAAAaaAA00000000000000000000000000000000` | Account keychain | Genesis |
| `0xCccCcCCC00000000000000000000000000000000` | Validator config (V1) | Genesis |
| `0xCCCCcCcc00000000000000000000000000000001` | Validator config V2 | Genesis (address); its ABI only from T2 |
| `0x20Fc000000000000000000000000000000000000` | TIP-20 factory | Genesis |
| `0xFDC0000000000000000000000000000000000000` | Address registry (TIP-1022) | T3 |
| `0x5165300000000000000000000000000000000000` | Signature verifier (TIP-1020) | T3 |
| `0x4D50500000000000000000000000000000000000` | TIP-20 channel reserve (TIP-1034) | T5 |
| `0xB10C000000000000000000000000000000000000` | Receive policy guard (TIP-1028) | T6 |
| `0x1060000000000000000000000000000000000000` | Storage credits (TIP-1060) | T7 |
| `0xC077E00000000000000000000000000000000000` | Current committee (TIP-1070) | T8 |
| `0x5AF2000000000000000000000000000000000000` | Zone factory (TIP-1091) | T10 |
| `0x5A56000000000000000000000000000000000000` | Zone verifier (TIP-1098) | T13 |

`0xAACC000000000000000000000000000000000000` (configurable account) is a precompile only from T14 and is an ordinary address at or before T13.

In addition, the Ethereum built-in precompiles are active:

- **Before T1C:** the Prague set (addresses `0x01` to `0x11`, with Prague's MODEXP pricing and bounds).
- **From T1C:** the Osaka set (adds P256VERIFY at `0x0100` per EIP-7951, and the EIP-7823/EIP-7883 MODEXP limits and pricing).

The Ethereum built-in precompile set active at fork F determines the EIP-2929 warm addresses at transaction start; Tempo precompile addresses are not pre-warmed ([05-block-execution.md §1.3](05-block-execution.md#13-precompiles)). Calls to every precompile address, Ethereum or Tempo, run native code. A Tempo precompile is dispatched on the call target regardless of the code stored there. A DELEGATECALL or CALLCODE to a Tempo precompile, that is any frame whose storage address differs from the call target, MUST revert with ABI data `DelegateCallNotAllowed()`, selector `keccak256("DelegateCallNotAllowed()")[0..4]`. The dispatch rules, gas and error conventions are in [precompiles/00-framework.md](precompiles/00-framework.md).

### 2.2 State representation of protocol accounts

A Tempo precompile keeps its state in its own account's storage, using the slot layouts given in each precompile chapter. Its account has nonce 0, balance 0 and, once initialized, code `0xEF` (§1.3). The marker makes the account non-empty under EIP-161 and gives `EXTCODESIZE = 1` and `EXTCODEHASH = 0x309b…d2a3`. It is never executed: dispatch is native.

The marker is written in exactly these ways:

1. **Genesis:** every precompile account in the genesis allocation has code `0xEF` (§4.5).
2. **Precompile initialization:** when a precompile instance is initialized at run time, its code is set to `0xEF`. The main case is TIP-20 token creation by the factory at `0x20C0…||id` ([precompiles/tip20.md](precompiles/tip20.md)).
3. **Fork boundaries:** in the pre-execution phase of every block in which the fork is active, the protocol writes code `0xEF` to each precompile that activated at that fork, if the account's code hash is empty. Balance, nonce and storage are left as they are. The write is idempotent, so it changes state only in the first block where the fork is active. The table:

   | Fork | Accounts that receive the 0xEF marker |
   |---|---|
   | T2 | `0xCCCCCCCC00000000000000000000000000000001` (validator config V2) |
   | T3 | `0x5165300000000000000000000000000000000000`, then `0xFDC0000000000000000000000000000000000000` |
   | T5 | `0x4D50500000000000000000000000000000000000` |
   | T6 | `0xB10C000000000000000000000000000000000000` |
   | T7 | `0x1060000000000000000000000000000000000000` |
   | T8 | `0xC077E00000000000000000000000000000000000` |
   | T10 | `0x5AF2000000000000000000000000000000000000` (with initial storage), plus zone runtime bytecode at `0x5AD1…`, `0x5A56…`, `0x5A4D…` |
   | T13 | zone runtime bytecode replaced at `0x5AD1…`, `0x5A56…`, `0x5A4D…` |

   The exact ordering relative to system calls, the T10 storage and the runtime bytecode are specified in [05-block-execution.md](05-block-execution.md) and [precompiles/validator-config-and-zones.md](precompiles/validator-config-and-zones.md).

Precompiles active from Genesis but absent from the mainnet genesis allocation are represented as non-existent accounts until something writes to them. This is the case for validator config V2 before T2. Calls to them still dispatch natively.

### 2.3 Ethereum system contracts

The mainnet and Moderato genesis allocations contain **no code** at the Ethereum system-contract addresses: EIP-2935 `0x0000F90827F1C53a10cb7A02335B175320002935`, EIP-4788 `0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02`, EIP-7002 `0x00000961Ef480Eb55e80D19ad83579A64c007002` and EIP-7251 `0x0000BBdDc7CE488642fb579F8B00f3a590007251`. No fork installs code there either. How the pre-T13 inherited Ethereum system calls and the T13 explicit system calls (TIP-1119) behave against these addresses is specified in [05-block-execution.md](05-block-execution.md).

## 3. Reserved address namespaces

| Namespace | Rule (20-byte address `a`) | Meaning | Forks |
|---|---|---|---|
| TIP-20 tokens | `a[0:12] == 0x20C000000000000000000000`. Token id = `uint64_be(a[12:20])` | Every such address is a TIP-20 precompile (§2.1). Id 0 (`0x20C0000000000000000000000000000000000000`) is pathUSD | all |
| System precompiles | table in §2.1 | Native precompiles | per table |
| Ethereum precompiles | `0x01..0x11` (Prague), plus `0x0100` from T1C | Native precompiles | per §2.1 |
| Virtual addresses (TIP-1022) | `a[4:14] == 0xFD × 10`. `masterId = a[0:4]`, `userTag = a[14:20]` | TIP-20 deposit-forwarding aliases resolved through the address registry | From T3 (resolution); [precompiles/tip403.md](precompiles/tip403.md) |
| Zone portals | `a[0:12] == 0x5AD000000000000000000000` and `zone_id = uint64_be(a[12:20]) != 0` | Protocol-managed ZonePortal proxies, one per zone | From T10; TIP-20 burn protection from T12 ([precompiles/tip20.md](precompiles/tip20.md)) |
| Zone runtimes | `0x5AD1000000000000000000000000000000000000` (portal implementation), `0x5A56000000000000000000000000000000000000` (verifier), `0x5A4D000000000000000000000000000000000000` (messenger) | Protocol-installed EVM bytecode | From T10 ([precompiles/validator-config-and-zones.md](precompiles/validator-config-and-zones.md)) |
| System transaction sender | `0x0000000000000000000000000000000000000000` | Sender and target of the pre-T4 end-of-block system transaction | Before T4 ([02-encoding.md](02-encoding.md), [05-block-execution.md](05-block-execution.md)) |

## 4. Genesis

### 4.1 Normative genesis data

The genesis state and header of each network are fully determined by a genesis JSON file in the genesis-file format that Ethereum execution clients use for custom networks (format below). These files are normative data for this specification. Each is identified by its size and hashes:

| Network | File name | Size | SHA-256 of file bytes | Keccak-256 of file bytes |
|---|---|---|---|---|
| Mainnet (4217) | [`presto.json`](genesis/presto.json) | 62,070 bytes | `00571ffc60bd49c51650839deb6379f9218167377b1b9c6e5cdfda968d330046` | `0x5501ea9d465084f486e420aaaf081edc0134f17e3799ea2480e0f16c59d3737b` |
| Moderato (42431) | [`moderato.json`](genesis/moderato.json.gz) (stored gzip-compressed; size and hashes are of the decompressed file) | 2,584,301 bytes | `fea8a8699be8582d94dcbb5960c2e163e5d58b904362ba99bd7e0b2cb2a5b160` | `0xad0ec9e17c058cd59545986f4653dfa191f2b6a6e5ebd5c32dbb51cf79686f41` |

(Any re-serialization that yields the same parsed content yields the same genesis.)

For mainnet and Moderato, a client MUST derive its genesis from this data as described below, and the resulting genesis hash MUST equal the expected value in §4.7.

The file's top-level keys are `config` (§4.2), `nonce`, `timestamp`, `extraData`, `gasLimit`, `difficulty`, `mixHash`, `coinbase`, `baseFeePerGas` and `alloc`. The mainnet file also has a top-level `craftedWithLove` object (team member names and the message "Time is money"). It MUST be ignored, because it affects neither the genesis header nor the state. Absent numeric header keys (`number`, `gasUsed`, `parentHash`, `blobGasUsed`, `excessBlobGas`) are zero.

The file is a JSON object (RFC 8259). Its values are encoded as follows:

- **Quantities** (`nonce`, `timestamp`, `gasLimit`, `difficulty`, `baseFeePerGas`, and each account's `nonce` and `balance`) are JSON numbers, or JSON strings of `0x` hex or of decimal digits, such as `"0x1dcd6500"`. Leading zeros are allowed. The top-level `nonce` is a 64-bit value. It becomes the 8-byte big-endian header `nonce`.
- **Byte strings** (`extraData` and each account's `code`) are hex strings with two digits per byte and an optional `0x` prefix.
- **Fixed-size values** are hex strings with an optional `0x` prefix and exactly their size: 20 bytes for `coinbase` and the `alloc` keys, 32 bytes for `mixHash`. Hex digits are case-insensitive, so EIP-55 mixed-case addresses are accepted.
- **Storage words** (the keys and values of an account's `storage` object) are hex strings with an optional `0x` prefix and at most 32 bytes. A shorter word is padded with zeros on the left.
- A `null` value counts as absent.
- **`config`** is a JSON object whose values are JSON numbers, booleans or hex address strings, as listed in [01-chain-and-forks.md](01-chain-and-forks.md#genesis-configuration).

A storage value is the 256-bit slot value as a big-endian word. A client MUST accept every file whose values parse under these rules. The result for other value forms is implementation-defined. For example, the reference also accepts a `0X`, `0o` or `0b` prefix and `_` in a quantity. The reference genesis generator writes only `0x` hex, so its files parse the same way in every client.

### 4.2 Genesis `config`

The `config` object holds the Ethereum fork schedule and Tempo's extension keys. Their meaning, and the mainnet and Moderato values, are specified in [01-chain-and-forks.md](01-chain-and-forks.md#genesis-configuration). The state and header construction below depend on `config` only in that every Ethereum fork through Osaka is active at genesis, so the genesis header carries all post-London/Shanghai/Cancun/Prague header fields.

### 4.3 Genesis header

The genesis block has no transactions, ommers or withdrawals, and is not executed. Its header is a `TempoHeader` ([02-encoding.md](02-encoding.md)) built as follows:

| Field | Value |
|---|---|
| `general_gas_limit` | `0` |
| `shared_gas_limit` | `0` |
| `timestamp_millis_part` | `timestamp mod 1000` (= `0` on mainnet and Moderato) |
| `consensus_context` | absent (omitted from the RLP) |
| `inner.parent_hash` | `0x00…00` (32 zero bytes) |
| `inner.ommers_hash` | `0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347` (keccak of `rlp([])`) |
| `inner.beneficiary` | `coinbase` (`0x00…00`) |
| `inner.state_root` | root of the genesis state (§4.4) |
| `inner.transactions_root` | empty trie root |
| `inner.receipts_root` | empty trie root |
| `inner.logs_bloom` | 256 zero bytes |
| `inner.difficulty` | `difficulty` (`0`) |
| `inner.number` | `0` |
| `inner.gas_limit` | `gasLimit` (`0x1dcd6500` = 500,000,000) |
| `inner.gas_used` | `0` |
| `inner.timestamp` | `timestamp` (`0`) |
| `inner.extra_data` | `extraData` bytes (§4.6) |
| `inner.mix_hash` | `mixHash` (`0x00…00`) |
| `inner.nonce` | `nonce` as 8-byte big-endian (`0x0000000000000042`) |
| `inner.base_fee_per_gas` | `baseFeePerGas` (`0x2540be400` = 10,000,000,000) |
| `inner.withdrawals_root` | empty trie root |
| `inner.blob_gas_used` | `0` |
| `inner.excess_blob_gas` | `0` |
| `inner.parent_beacon_block_root` | `0x00…00` |
| `inner.requests_hash` | `0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (sha256 of the empty string, EIP-7685 empty requests) |

`inner` has exactly the 21 Prague/Osaka header fields in Ethereum order, with no Amsterdam fields. The genesis hash is `keccak256(rlp(TempoHeader))` with the encoding of [02-encoding.md](02-encoding.md):

```
rlp([general_gas_limit, shared_gas_limit, timestamp_millis_part, rlp_list(inner_fields...)])
```

The genesis header is exempt from the per-block header rules of [05-block-execution.md](05-block-execution.md): its `general_gas_limit`, `shared_gas_limit` and base fee are not derived from the fork rules, and it carries no consensus context.

### 4.4 Genesis state from `alloc`

`alloc` maps 20-byte addresses to accounts with a required `balance` and optional `nonce`, `code` and `storage` (a map from storage word to storage word, §4.1). A client MUST reject a file with an account that has no `balance`. A missing `nonce` is 0, missing `code` is empty and missing `storage` is empty. An account MUST NOT carry an `extension` (§1.2). For each entry, the client MUST create the account with those values, and storage entries whose value is zero MUST be skipped (§1.1). The genesis state root is the state trie root over all entries (§1.1, §1.2).

This rule is consensus-critical. Mainnet's alloc lists zero-valued slots (for example slot `0x06` of pathUSD and slot `0x0f` of token `0x20c0…16c6514b53947fdc`). Inserting them would give state root `0xb1a04bd8…786c` and the wrong genesis hash `0x80da98c9…0bcc`.

### 4.5 Mainnet genesis allocation

The mainnet allocation has 14 accounts, all with balance 0:

| Address | Role | Nonce | Code | Code hash | Storage slots (non-zero) |
|---|---|---|---|---|---|
| `0x000000000022D473030F116dDEE9F6B43aC78BA3` | Permit2 (predeploy) | 1 | 9,152 bytes | `0x8b6b97803b2857cbf118d7afa6537b9a622a54a045f3ae4afd306e0eb4080f72` | 0 |
| `0x4e59b44847b379578588920cA78FbF26c0B4956C` | Arachnid deterministic CREATE2 factory (predeploy) | 1 | 69 bytes | `0x2fa86add0aed31f33a762c9d88e807c475bd51d0f52bd0955754b2608f7e4989` | 0 |
| `0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7` | Safe singleton factory (predeploy) | 1 | 69 bytes | `0x2fa86add0aed31f33a762c9d88e807c475bd51d0f52bd0955754b2608f7e4989` | 0 |
| `0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed` | CreateX (predeploy) | 1 | 11,838 bytes | `0xbd8a7ea8cfca7b4e5f5041d7d4b17bc317c5ce42cfbc42066a00cf26b43eb53f` | 0 |
| `0xcA11bde05977b3631167028862bE2a173976CA11` | Multicall3 (predeploy) | 1 | 3,808 bytes | `0xd5c15df687b16f2ff992fc8d767b4216323184a2bbc6ee2f9c398c318e770891` | 0 |
| `0x20C0000000000000000000000000000000000000` | TIP-20 pathUSD (token id 0) | 0 | `0xEF` | `0x309b…d2a3` | 8 (9 listed) |
| `0x20c00000000000000000000016c6514b53947fdc` | TIP-20 token id `0x16c6514b53947fdc`, name/symbol "DONOTUSE" | 0 | `0xEF` | `0x309b…d2a3` | 11 (15 listed) |
| `0x20Fc000000000000000000000000000000000000` | TIP-20 factory | 0 | `0xEF` | `0x309b…d2a3` | 0 |
| `0x403C000000000000000000000000000000000000` | TIP-403 registry | 0 | `0xEF` | `0x309b…d2a3` | 0 |
| `0x4e4F4E4345000000000000000000000000000000` | Nonce manager | 0 | `0xEF` | `0x309b…d2a3` | 0 |
| `0xaAAAaaAA00000000000000000000000000000000` | Account keychain | 0 | `0xEF` | `0x309b…d2a3` | 0 |
| `0xCccCcCCC00000000000000000000000000000000` | Validator config (V1) | 0 | `0xEF` | `0x309b…d2a3` | 22 |
| `0xDEc0000000000000000000000000000000000000` | Stablecoin DEX | 0 | `0xEF` | `0x309b…d2a3` | 0 |
| `0xfeEC000000000000000000000000000000000000` | Fee manager | 0 | `0xEF` | `0x309b…d2a3` | 1 |

The exact code bytes and storage words are those in `presto.json`. What each storage word means under the precompile's layout is specified in the precompile chapters. For orientation (informative):

- **pathUSD** (`0x20C0…0000`): name and symbol "pathUSD", currency "USD", supply cap `2^128−1`, and role-system entries.
- **Token `0x20c0…16c6514b53947fdc`**: name and symbol "DONOTUSE", currency "USD", quote token pathUSD, with role and policy entries.
- **Fee manager**: one mapping entry whose value is the token `0x20c0…16c6514b53947fdc`.
- **Validator config V1**: owner `0x3c50c3f02cb4394c433a22f112ec19be312d8b63`, a validator count of 4, and four validator records for validator addresses `0x…42170001` through `0x…42170004`. Each record holds a 32-byte Ed25519 public key, a packed index/active word, and inbound/outbound `host:port` strings: `40.160.24.34:30001`, `40.160.24.210:30003`, `40.160.64.50:30005` and `148.113.220.159:30007`. See [precompiles/validator-config-and-zones.md](precompiles/validator-config-and-zones.md).

Accounts **not** in the mainnet genesis: validator config V2 (`0xCCCC…0001`), every T3+ precompile, the zone accounts, and the Ethereum system contracts (§2.3). Moderato's allocation (16 accounts) has the same predeploys and system precompiles, and TIP-20 tokens with ids 0 to 3 instead of the DONOTUSE token.

### 4.6 Genesis `extraData`

The genesis `extraData` is the `OnchainDkgOutcome` ([07-consensus.md](07-consensus.md) §10.2) for epoch 0, encoded with the codec of [commonware/codec.md](commonware/codec.md); its embedded `Output` is encoded as in [commonware/dkg.md §11.1](commonware/dkg.md#111-output). It carries the initial validator set and the epoch-0 BLS12-381 (MinSig) threshold public key, the network identity (the constant term of the public polynomial, [commonware/cryptography.md §5.4](commonware/cryptography.md#54-public-polynomial-and-sharing-encoding)). Mainnet's epoch-0 identity is `0xa217bb85…05f5a193` (96 bytes). Its format and use are specified in [07-consensus.md](07-consensus.md). For genesis-hash purposes it is opaque bytes.

### 4.7 Expected genesis values

| Network | Genesis state root | Genesis block hash |
|---|---|---|
| Mainnet (4217) | `0x83408974323f63ab969b23f0fe1dba30d7ee5dc5c524a975bae38187eaa2c7f6` | `0x49d7ec7085e77bf5a403d0fcb4cfc42a4084a89dfff60477579c5e09c9e03c54` |
| Moderato (42431) | `0x3952ff0c60a3f215ab11a3a2c7698126b7911da84faf5cb66bdbcb0c605738c4` | `0xba49153e6f3996a340f3fe3d69e7c0826b717ae672cb115cf0527cada0b78e9e` |

These values were recomputed from the genesis files with the rules in §4.3 and §4.4. The mainnet hash equals the `parent_hash` of mainnet block 1 (hash `0x76e86f9739fbe17669b01b24e976ac214742c4b1bbc6ae0c083a87e43a5e9b0f`), whose `state_root` equals the genesis state root above. The Moderato hash matches the value Tempo's tooling publishes for Moderato.

A client that a user configures for mainnet or Moderato by name MUST use the genesis whose hash is the value above. A genesis file from a path defines a custom chain, whatever its chain ID: the reference does not compare its hash with these values. A node that starts from such a file with chain ID 4217 or 42431 and another genesis starts its own chain, and mainnet or Moderato peers refuse it at the Status handshake ([08-p2p-and-sync.md](08-p2p-and-sync.md)).

### 4.8 Genesis generator (informative)

The genesis files were produced by Tempo's genesis generator. It runs an in-memory EVM at fork T0. Its steps include:

- deploying the Arachnid CREATE2 factory as raw code, and Permit2 through it;
- installing Multicall3, CreateX and the Safe singleton factory as predeployed code;
- initializing the precompiles through their own initialization paths, which writes the `0xEF` marker;
- encoding the epoch-0 DKG outcome into `extraData`.

Clients MUST NOT re-run the generator to obtain genesis. The JSON files are authoritative.
