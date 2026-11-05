# 01. Chain configuration and forks

This chapter defines the Tempo networks, the genesis configuration keys, the Ethereum rule set Tempo builds on, the fork model and the activation schedule. It ends with a ledger of every consensus-relevant change made by each fork from T0 through T13, with links to the chapter that specifies each change.

Throughout this specification, "fork F is active for a block" and the shorthand "From F:" / "Before F:" are defined by the [activation predicate](#activation-predicate) below.

## Networks

| | Mainnet | Moderato (testnet) |
|---|---|---|
| Chain ID | **4217** | **42431** |
| Name in the reference implementation | `presto` (CLI name `mainnet`) | `moderato` (CLI names `moderato`, `testnet`) |
| Genesis file | `crates/chainspec/src/genesis/presto.json` | `crates/chainspec/src/genesis/moderato.json` |
| Genesis block hash | `0x49d7ec7085e77bf5a403d0fcb4cfc42a4084a89dfff60477579c5e09c9e03c54` | `0xba49153e6f3996a340f3fe3d69e7c0826b717ae672cb115cf0527cada0b78e9e` |
| Genesis timestamp | 0 | 0 |
| Epoch length (`epochLength`) | 21,600 blocks | 21,600 blocks |
| First fork in effect | T0 (at genesis) | Genesis (T0 from timestamp 1770303600) |

This specification covers mainnet from genesis. Moderato is listed for its chain ID, genesis and schedule only: its blocks before T0 (heights 0 to 3,767,358) were produced under the pre-T0 **Genesis** rule set, which is out of scope. From its T0 activation, Moderato follows the same rules as mainnet at the same fork.

How the genesis block and state are derived from the genesis file, and how the expected hashes are checked, is in [04-state-and-genesis.md](04-state-and-genesis.md). The genesis `extraData` carries the epoch-0 DKG outcome and network identity ([07-consensus.md](07-consensus.md)). Bootnodes, built-in network identities and trusted checkpoints are covered in [08-p2p-and-sync.md](08-p2p-and-sync.md).

Reference implementation: crates/chainspec/src/spec.rs (`PRESTO`, `MODERATO`, `chainspec_from_chain_id`), crates/hardfork/src/constants.rs.

## Genesis configuration

The `config` object of the genesis file is an Ethereum (geth/alloy) chain configuration extended with Tempo keys. A client MUST interpret the keys as follows and MUST ignore no key listed here.

### Ethereum keys

| Key | Mainnet | Moderato | Meaning |
|---|---|---|---|
| `chainId` | 4217 | 42431 | EIP-155 chain ID. Also the chain ID in Tempo transaction signing ([02-encoding.md](02-encoding.md)) |
| `homesteadBlock`, `eip150Block`, `eip155Block`, `eip158Block`, `byzantiumBlock`, `constantinopleBlock`, `petersburgBlock`, `istanbulBlock`, `berlinBlock`, `londonBlock`, `mergeNetsplitBlock` | 0 | 0 | Block-number Ethereum forks, all active at genesis |
| `daoForkSupport` | false | false | No DAO fork state change |
| `terminalTotalDifficulty`, `terminalTotalDifficultyPassed` | 0, true | 0, true | Paris (proof-of-stake header rules) active at genesis |
| `shanghaiTime`, `cancunTime`, `pragueTime`, `osakaTime` | 0 | 0 | Timestamp Ethereum forks, all active at genesis |
| `depositContractAddress` | `0x0000000000000000000000000000000000000000` | `0x00000000219ab540356cbb839cbe05303d7705fa` | EIP-6110 deposit contract. Used only by the Ethereum request processing that Tempo inherits before T13 ([05-block-execution.md](05-block-execution.md)) |

No other Ethereum fork key is present. `amsterdamTime`, any later Ethereum fork, any blob-parameter-only fork and `blobSchedule` are absent, so those forks are **not active** in any block covered by this specification. Blob parameters are the EIP-7840 defaults for Cancun, Prague and Osaka.

### Tempo keys

| Key | Type | Mainnet | Moderato | Meaning |
|---|---|---|---|---|
| `epochLength` | non-zero uint64 | 21600 | 21600 | Consensus epoch length L in blocks ([07-consensus.md](07-consensus.md)). It is also used by execution: the T8 end-of-epoch committee system call ([05-block-execution.md](05-block-execution.md)). It MUST be present. |
| `generalGasLimit` | uint64 | absent | absent | Optional override of the per-block general (non-payment) gas limit. When present, it replaces the fork-derived value in **every** fork ([05-block-execution.md](05-block-execution.md)). |
| `t0Time`, `t1Time`, `t1aTime`, `t1bTime`, `t1cTime`, `t2Time`, …, `t13Time` | uint64 (Unix seconds) | see [schedule](#activation-schedule) | see [schedule](#activation-schedule) | Activation timestamp of each Tempo fork. The key is the fork name in lower case followed by `Time`. An absent key means the fork is not scheduled. |

The keys `t14Time` and `t15Time` belong to forks after T13 and are absent from both networks. A client implementing this specification MUST treat a configuration that schedules T14 or later as unsupported.

A Tempo key that is present but not a valid unsigned integer (or, for `epochLength`, is zero) SHOULD be rejected. The reference implementation instead discards all Tempo keys when any of them fails to parse. This never happens for the built-in networks.

Unknown top-level genesis fields (such as mainnet's `craftedWithLove`) carry no meaning.

Reference implementation: crates/chainspec/src/spec.rs (`TempoGenesisInfo`, `TempoChainSpec::from_genesis`), crates/hardfork/src/lib.rs (`genesis_key`).

## Ethereum baseline

1. **Ethereum forks.** Every Ethereum fork from Frontier through Osaka is active from genesis. No later Ethereum fork is active at or before T13.
2. **EVM rule set.** Every Tempo fork, Genesis through T13, executes the EVM with the **Osaka** rule set (revm `SpecId::OSAKA`). No Tempo fork changes the Ethereum spec. Every Tempo change, including changes that reach Ethereum behaviour such as the precompile set, gas parameters and system calls, is a Tempo fork gate. The Ethereum reference is execution-specs `osaka` together with the EIPs it includes.
3. **Tempo overrides of Osaka.** Several Osaka behaviours are replaced or narrowed by Tempo rules. Each is specified where noted:
   - Header and base fee rules replace EIP-1559's base fee update ([05-block-execution.md](05-block-execution.md)).
   - The EIP-7825 per-transaction gas cap of 16,777,216 applies before T1A. It is 30,000,000 from T1A ([05-block-execution.md](05-block-execution.md)).
   - The Ethereum built-in precompile set is Prague's before T1C ([04-state-and-genesis.md](04-state-and-genesis.md)).
   - EIP-3529 refund limits apply before T7 ([05-block-execution.md](05-block-execution.md)).
   - EIP-4844 blob transactions do not exist (type `0x03` is invalid, [02-encoding.md](02-encoding.md)), so `blob_gas_used` and `excess_blob_gas` are always 0.
   - Ethereum's pre- and post-block system processing (EIP-2935, EIP-4788, EIP-7002, EIP-7251, EIP-6110, EIP-7685) is inherited before T13 and replaced by TIP-1119 from T13 ([05-block-execution.md](05-block-execution.md)).
   - Withdrawals MUST be empty ([05-block-execution.md](05-block-execution.md)).
4. **Tempo additions** (new transaction type `0x76`, precompiles, header fields, payment lanes) are specified in the chapters listed in [README.md](README.md).

Reference implementation: crates/hardfork/src/lib.rs (`From<TempoHardfork> for SpecId`), crates/evm/src/lib.rs (`evm_env`, `resolved_env`).

## Fork model

### Fork list

Tempo forks form a totally ordered list. Each fork includes every earlier fork's rules except where a later fork changes them:

```
FORKS = [Genesis, T0, T1, T1A, T1B, T1C, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13]
```

`Genesis` is the baseline rule set and always activates at timestamp 0. On mainnet T0 also activates at 0, so the Genesis rule set never governs a mainnet block. A rule written "From Tn" applies to every block whose fork is Tn **or any later fork**. A rule written "Before Tn" applies to every block whose fork is earlier than Tn.

### Activation predicate

```python
def activation(config, F) -> Optional[int]:
    if F == Genesis:
        return 0
    return config.get(F.name.lower() + "Time")      # None if absent

def fork_at(config, ts: int) -> Fork:
    # the latest fork in list order whose activation time has been reached
    for F in reversed(FORKS):
        a = activation(config, F)
        if a is not None and ts >= a:
            return F
    return Genesis

def is_active(config, F, ts: int) -> bool:
    return FORKS.index(fork_at(config, ts)) >= FORKS.index(F)
```

A chain configuration MUST list activation times that do not decrease in fork order, which mainnet and Moderato do. Under that condition `is_active(F, ts)` holds exactly when `activation(F)` is defined and `ts >= activation(F)`.

**The timestamp used is the header's `timestamp` field in whole seconds** (`header.inner.timestamp`). The sub-second `timestamp_millis_part` is never used to select a fork. A block activates fork F iff its seconds timestamp is ≥ `activation(F)`, even when its millisecond timestamp falls inside the activation second.

### Which block's timestamp

- **Per-block rules.** Every rule for validating and executing block B uses `fork_at(B.header.timestamp)`, including when the rule reads the parent. This covers header field checks (gas limits, base fee, extra fields), transaction validity, EVM semantics, precompile behaviour, pre- and post-execution system calls and fork-boundary state changes.
- **Next-block parameters are chosen by the child.** A value of block B that is computed from its parent P (the base fee, for example) uses B's fork, not P's:

  ```python
  def expected_base_fee(config, parent, header) -> int:
      f = fork_at(config, header.timestamp)                    # the child's fork
      if is_active_fork(f, T7):
          return tip1067_next_base_fee(parent.base_fee_per_gas, parent.gas_used)   # 05-block-execution.md
      if is_active_fork(f, T1):
          return 20_000_000_000
      return 10_000_000_000
  ```

  (`is_active_fork(f, F)` means `FORKS.index(f) >= FORKS.index(F)`.) For the first T7 block, the formula is applied to the T6 parent's base fee of 20,000,000,000, and the result is clamped to the T7 cap of 12,000,000,000.
- **Transaction pool** admission (outside this specification's scope) uses the fork of the block being built.

### Consensus-layer switches

Some consensus-layer behaviour must stay fixed for a whole epoch, so it is chosen once per epoch from the fork in effect at the **previous epoch boundary**, not per block. With epoch length L:

```python
def epoch_of(height): return height // L               # epoch e = heights [e*L, (e+1)*L - 1]

def boundary_height(epoch):                            # last block of the previous epoch
    return 0 if epoch == 0 else epoch * L - 1          # epoch 0 uses the genesis block

def consensus_fork(epoch) -> Fork:
    return fork_at(config, header_at(boundary_height(epoch)).timestamp)
```

Up to and including T13, two switches use `consensus_fork`. Both change at T12:

| Switch | Before T12 | From T12 | Specified in |
|---|---|---|---|
| Simplex leader election version ([commonware/simplex.md §6](commonware/simplex.md#6-leader-election)) | V0 | V1 | [07-consensus.md](07-consensus.md) |
| DKG reveal rules for the ceremony run during the epoch | V0 | V1 | [07-consensus.md](07-consensus.md), [commonware/dkg.md §2](commonware/dkg.md#2-fault-model-and-derived-parameters) |

As a result, T12's consensus changes take effect at the first epoch whose boundary block has a timestamp ≥ the T12 activation. That is the epoch after the one in which T12 activated for execution, unless T12 activated exactly at a boundary block. Execution rules in that epoch still switch per block.

Reference implementation: crates/consensus/src/epoch/manager/actor.rs, crates/consensus/src/dkg/manager/actor/mod.rs (`is_state_v1_activated`).

### Simultaneous activations

Several forks can share one activation time. They then activate together in the same block, and `fork_at` returns the latest of them. On mainnet, Genesis and T0 activate at 0, and T1 and T1A both activate at 1770908400, so no mainnet block is ever at T1 without T1A. On Moderato, T0 and T1 activate together, as do T1A and T1B, and blocks between 1770303600 and 1771858800 ran T1 without T1A, with the 16,777,216 transaction gas cap.

### Fork identifier (EIP-2124)

Nodes advertise an EIP-2124 fork identifier `(FORK_HASH, FORK_NEXT)` in the devp2p `eth` Status handshake ([08-p2p-and-sync.md](08-p2p-and-sync.md)). It is computed exactly as in EIP-2124, over the combined list of Ethereum and Tempo forks:

```python
def fork_id(genesis_hash, head_number, head_timestamp, config):
    h = crc32(genesis_hash)                                        # IEEE CRC-32
    block_forks = sorted(set(b for b in ethereum_block_forks(config) if b > 0))   # empty on Tempo
    time_forks  = sorted(set(t for t in ethereum_time_forks(config) + tempo_time_forks(config)
                             if t > genesis_timestamp))            # Genesis/T0 at 0 are skipped
    for b in block_forks:
        if head_number < b: return (h, b)
        h = crc32_update(h, uint64_be(b))
    for t in time_forks:
        if head_timestamp < t: return (h, t)
        h = crc32_update(h, uint64_be(t))
    return (h, 0)
```

`tempo_time_forks` are the activation times of T0 through T13 from the `tNTime` keys. Forks sharing a timestamp contribute it once. Peers MUST be accepted or rejected by the EIP-2124 validation rules. Resulting identifiers (mainnet values through T3 match those published in Tempo's RPC documentation):

| Head in fork | Mainnet FORK_HASH | Mainnet FORK_NEXT | Moderato FORK_HASH | Moderato FORK_NEXT |
|---|---|---|---|---|
| Genesis (Moderato only, before 1770303600) | n/a | n/a | 0x749c2727 | 1770303600 |
| T0 | 0xfde57c3e | 1770908400 | 0xeeaff752 | 1771858800 |
| T1 | 0x9e6fe384 | 1771858800 | 0xeeaff752 | 1771858800 |
| T1A | 0x9e6fe384 | 1771858800 | 0xc87dcf4d | 1773068400 |
| T1B | 0x73a4f670 | 1773327600 | 0xc87dcf4d | 1773068400 |
| T1C | 0x2a3ee80d | 1774965600 | 0x18851001 | 1774537200 |
| T2 | 0x471a451c | 1777298400 | 0x9df7f063 | 1776780000 |
| T3 | 0xd2087b77 | 1779112800 | 0x3d05eef5 | 1778767200 |
| T4 | 0x8ef43f21 | 1781013600 | 0x6be77007 | 1780495200 |
| T5 | 0x470001dc | 1782223200 | 0xb3233ed2 | 1781791200 |
| T6 | 0x20bb9ef5 | 1783605600 | 0x18db8179 | 1783000800 |
| T7 | 0xc1b8bff6 | 1785420000 | 0xabcdc67f | 1785160800 |
| T8 | 0x6a86ab1c | 1786024800 | 0x403e5030 | 1785938400 |
| T9 | 0x004c8bda | 1787320800 | 0xeefd0665 | 1787234400 |
| T10 | 0x70ba9898 | 1789048800 | 0x959bc6c7 | 1788962400 |
| T11 | 0x820adcc4 | 1791900000 | 0x26fff85f | 1791468000 |
| T12 | 0x118c7fce | 1793718000 | 0xc39dc3a7 | 1793286000 |
| T13 | 0x292f0850 | 0 | 0xa50b6a45 | 0 |

FORK_NEXT for a head at T13 is 0 because no later fork is scheduled at this commit.

Reference implementation: crates/chainspec/src/spec.rs (`from_genesis` adds the Tempo forks to the chain's fork list, `fork_id`), paradigmxyz/reth `ChainHardforks`/`ChainSpec::fork_id`.

## Activation schedule

Normative activation timestamps (Unix seconds, compared with `header.timestamp`). The "first block" columns give the first block at or after activation, as recorded in the reference implementation. They are informative, not needed for validation, and not recorded for T3 and later.

| Fork | Genesis key | Mainnet (4217) timestamp | Mainnet UTC | Mainnet first block | Moderato (42431) timestamp | Moderato UTC | Moderato first block |
|---|---|---|---|---|---|---|---|
| Genesis | (none) | 0 | genesis | 0 | 0 | genesis | 0 |
| T0 | `t0Time` | 0 | genesis | 0 | 1770303600 | 2026-02-05 15:00 UTC | 3,767,359 |
| T1 | `t1Time` | 1770908400 | 2026-02-12 15:00 UTC | 4,494,230 | 1770303600 | 2026-02-05 15:00 UTC | 3,767,359 |
| T1A | `t1aTime` | 1770908400 | 2026-02-12 15:00 UTC | 4,494,230 | 1771858800 | 2026-02-23 15:00 UTC | 6,033,587 |
| T1B | `t1bTime` | 1771858800 | 2026-02-23 15:00 UTC | 6,253,936 | 1771858800 | 2026-02-23 15:00 UTC | 6,033,587 |
| T1C | `t1cTime` | 1773327600 | 2026-03-12 15:00 UTC | 8,967,991 | 1773068400 | 2026-03-09 15:00 UTC | 7,768,256 |
| T2 | `t2Time` | 1774965600 | 2026-03-31 14:00 UTC | 12,286,033 | 1774537200 | 2026-03-26 15:00 UTC | 10,072,242 |
| T3 | `t3Time` | 1777298400 | 2026-04-27 14:00 UTC | not recorded | 1776780000 | 2026-04-21 14:00 UTC | not recorded |
| T4 | `t4Time` | 1779112800 | 2026-05-18 14:00 UTC | not recorded | 1778767200 | 2026-05-14 14:00 UTC | not recorded |
| T5 | `t5Time` | 1781013600 | 2026-06-09 14:00 UTC | not recorded | 1780495200 | 2026-06-03 14:00 UTC | not recorded |
| T6 | `t6Time` | 1782223200 | 2026-06-23 14:00 UTC | not recorded | 1781791200 | 2026-06-18 14:00 UTC | not recorded |
| T7 | `t7Time` | 1783605600 | 2026-07-09 14:00 UTC | not recorded | 1783000800 | 2026-07-02 14:00 UTC | not recorded |
| T8 | `t8Time` | 1785420000 | 2026-07-30 14:00 UTC | not recorded | 1785160800 | 2026-07-27 14:00 UTC | not recorded |
| T9 | `t9Time` | 1786024800 | 2026-08-06 14:00 UTC | not recorded | 1785938400 | 2026-08-05 14:00 UTC | not recorded |
| T10 | `t10Time` | 1787320800 | 2026-08-21 14:00 UTC | not recorded | 1787234400 | 2026-08-20 14:00 UTC | not recorded |
| T11 | `t11Time` | 1789048800 | 2026-09-10 14:00 UTC | not recorded | 1788962400 | 2026-09-09 14:00 UTC | not recorded |
| T12 | `t12Time` | 1791900000 | 2026-10-13 14:00 UTC | not recorded | 1791468000 | 2026-10-08 14:00 UTC | not recorded |
| T13 | `t13Time` | 1793718000 | 2026-11-03 15:00 UTC | not recorded | 1793286000 | 2026-10-29 15:00 UTC | not recorded |

Both networks schedule nothing after T13 at this commit.

Reference implementation: crates/hardfork/src/constants.rs (`mainnet`, `moderato`), crates/chainspec/src/genesis/{presto,moderato}.json.

## T0 baseline

Mainnet launched at T0, so the T0 rule set is the **complete launch protocol**. A mainnet client MUST implement it as its base and need not implement the pre-T0 Genesis rule set. The parameters below hold from genesis until the fork in the last column changes them:

| Area | T0 rule | Changed at |
|---|---|---|
| EVM | Osaka (`SpecId::OSAKA`) | never (≤ T13) |
| Ethereum built-in precompiles | Prague set (`0x01` to `0x11`) | T1C (Osaka set, adds P256VERIFY `0x0100`) |
| Tempo precompiles | Those active from Genesis ([04-state-and-genesis.md](04-state-and-genesis.md)) | T2, T3, T5, T6, T7, T8, T10, T13 |
| Opcode `0x4F` (MILLIS_TIMESTAMP) | Defined. 2 gas. Pushes `header.timestamp * 1000 + timestamp_millis_part` | T1C (undefined opcode) |
| Gas schedule | Osaka (SSTORE set 20,000; CREATE 32,000; new account 25,000; code deposit 200 per byte) | T1 (TIP-1000), T7 (TIP-1060) |
| Refunds | EIP-3529 (clearing refund 4,800; cap quotient 5) | T7 |
| Per-transaction gas cap | 16,777,216 (EIP-7825) | T1A (30,000,000) |
| Base fee | Every block's `base_fee_per_gas` = 10,000,000,000 attodollars per gas | T1 (20,000,000,000), T7 (dynamic, TIP-1067) |
| Block gas limit | Ethereum gas-limit bound rule from the genesis value 500,000,000 ([05-block-execution.md](05-block-execution.md)) | never (≤ T13) |
| `shared_gas_limit` | `gas_limit // 10` | T4 (0) |
| `general_gas_limit` | `(gas_limit - shared_gas_limit) // 2`, which is 225,000,000 for a 500,000,000 gas limit. Mainnet block 1 has `shared_gas_limit = 50,000,000` and `general_gas_limit = 225,000,000` | T1 (30,000,000) |
| End-of-block system transaction | Exactly one subblocks-metadata system transaction, last in the block ([05-block-execution.md](05-block-execution.md)) | T4 (none allowed) |
| Payment classification | v1: every call target has the TIP-20 prefix | T5 (TIP-1045 v2) |
| Nonces | Protocol nonce or 2D nonce key. 2D-key intrinsic gas is 22,100 for a new key and 5,000 for an existing key. No extra gas for protocol-nonce transactions. No expiring nonces | T1 (TIP-1000, TIP-1009), T2 |
| Keychain signatures | V1 (`0x03`) valid, V2 (`0x04`) invalid ([03-signatures.md](03-signatures.md)) | T1C |
| Key authorization | T0 field set. `chain_id = 0` is a wildcard. Intrinsic gas 27,000 + signature verification + 22,000 per spending limit. The precompile call is unmetered ([06-transactions-and-fees.md](06-transactions-and-fees.md)) | T1, T1B, T1C, T3, T4, T5, T6, T7 |
| Fee-token fallback | pathUSD | T13 (pathUSD, then OUSD) |
| Precompile dispatch | Lenient ABI decoding. Input cost 6 gas per 32-byte word. A missing selector halts. Checkpoints are no-ops. Static gas is charged after cold loads. No SSTORE refunds ([precompiles/00-framework.md](precompiles/00-framework.md)) | T1, T1C, T4, T11, T12 |
| Block system calls | Ethereum Prague/Osaka pre- and post-block processing, inherited ([05-block-execution.md](05-block-execution.md)) | T13 (TIP-1119) |
| Consensus | Epoch length 21,600. No `consensus_context` in headers. Leader elector V0. DKG reveal V0 ([07-consensus.md](07-consensus.md)) | T4, T12 |

Rules in the reference implementation that are gated on T0 are always active on mainnet. They differ from the pre-T0 Genesis rule set as follows:

| # | Change | Specified in | TIP |
|---|---|---|---|
| T0-1 | From T0 (mainnet genesis), Tempo-tx 2D-nonce intrinsic gas is included in the intrinsic-gas validation (IntrinsicGasTooLow if gas_limit < intrinsic+nonce gas); pre-T0 Genesis rules added it after validation and executed with a u64::MAX budget when it did not fit. | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-0001](../tips/tip-0001.md) |
| T0-2 | From T0, entries of tempo_authorization_list signed with a Keychain signature are skipped (not applied, no refund accounting); pre-T0 Genesis applied them. Effectively always-on for mainnet (T0 at timestamp 0). | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-0001](../tips/tip-0001.md) |
| T0-3 | From T0, authorizeKey reverts ExpiryInPast when expiry <= block timestamp (checked before key-exists/revoked checks); before, no expiry check. | [precompiles/account-keychain.md](precompiles/account-keychain.md) | none |

Reference implementation: crates/evm/src/handler.rs, crates/precompiles/src/account_keychain/mod.rs.

## Per-fork change ledger

Each table lists every consensus-relevant change the fork makes, one line each, with the chapter that specifies it normatively and the TIP that proposed it, if any. "none" in the TIP column means no TIP describes the change, and the linked chapter is the only specification. Changes that only affect the transaction pool, RPC or node operation are omitted. Selector gates are the `#[schedule(since = Tn)]` / `#[schedule(until = Tn)]` attributes in crates/precompiles/src/*/dispatch.rs. A selector "is dispatched" means the precompile recognizes the function from that fork. Before it, the call reverts `UnknownFunctionSelector(bytes4)` like any unknown selector ([precompiles/00-framework.md](precompiles/00-framework.md)).

Meta TIPs bundle the smaller changes of a fork: [TIP-1036](../tips/tip-1036.md) (T2), [TIP-1038](../tips/tip-1038.md) (T3), [TIP-1046](../tips/tip-1046.md) (T4), [TIP-1057](../tips/tip-1057.md) (T5), [TIP-1105](../tips/tip-1105.md) (T11), [TIP-1116](../tips/tip-1116.md) (T12) and [TIP-1146](../tips/tip-1146.md) (T13). T0, T1, T1A, T1B, T1C and T6 through T10 have no meta TIP. Where a TIP is still marked Draft or Approved but its fork is active, the linked chapter specifies the implemented behaviour.

### T1

Mainnet: 1770908400 (together with T1A). Scope: TIP-1000 state-creation pricing, TIP-1009 expiring nonces, TIP-1010 gas parameters.

| # | Change | Specified in | TIP |
|---|---|---|---|
| T1-1 | From T1, the EVM gas parameters change (TIP-1000): zero-to-nonzero SSTORE set cost 250,000 (Osaka 20,000); contract-creation transaction cost and CREATE/CREATE2 base cost 500,000 (Osaka 32,000); new-account cost for value transfer or SELFDESTRUCT to an empty account 250,000 (Osaka 25,000); code deposit 1,000 gas/byte (Osaka 200); EIP-7702 per-empty-account cost 12,500 (Osaka 25,000); EIP-7702 existing-authority refund 0 (Osaka 12,500). | [05-block-execution.md](05-block-execution.md) | [TIP-1000](../tips/tip-1000.md) |
| T1-2 | From T1 the next block's base fee is fixed at 20,000,000,000 (TEMPO_T1_BASE_FEE); before, fixed at 10,000,000,000 (TEMPO_T0_BASE_FEE). | [05-block-execution.md](05-block-execution.md) | [TIP-1010](../tips/tip-1010.md) |
| T1-3 | From T1, the header `general_gas_limit` (the non-payment lane limit) MUST be 30,000,000; before, it MUST be `(gas_limit - shared_gas_limit) // 2`. In both cases a genesis `generalGasLimit` replaces the value. | [05-block-execution.md](05-block-execution.md) | [TIP-1010](../tips/tip-1010.md) |
| T1-4 | From T1, non-AA transactions (legacy/2930/1559/7702) pay +NewAccountCost (250,000) intrinsic gas if tx.nonce==0 and +250,000 per EIP-7702 authorization with nonce 0; before, no such surcharge. | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-1000](../tips/tip-1000.md) |
| T1-5 | From T1, each Tempo-tx tempo_authorization_list entry with nonce==0 adds NewAccountCost (250,000) intrinsic gas; before, no surcharge. | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-1000](../tips/tip-1000.md) |
| T1-6 | From T1, Tempo-tx nonce intrinsic gas is 13,000 (2×2,100+100+3×2,900) for nonce_key==TEMPO_EXPIRING_NONCE_KEY, else 250,000 if nonce==0 (any key), else 2D-key gas (new/existing key); before, only nonzero nonce_key paid 2D-key gas (22,100 new, 5,000 existing) and protocol-nonce txs paid 0. | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-1000](../tips/tip-1000.md) |
| T1-7 | From T1, nonce_key==U256::MAX is an expiring nonce: requires valid_before (ExpiringNonceMissingValidBefore), checks/marks the replay hash in NonceManager's ring (ExpiringNonceReplay / expiry window errors) and skips nonce-overflow validation; before, it was an ordinary 2D nonce key. | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-1009](../tips/tip-1009.md) |
| T1-8 | From T1, an existing access key's stored signature type must match the keychain signature's inner type (always validated); before, the type was checked only when the tx carried a key_authorization. | [06-transactions-and-fees.md](06-transactions-and-fees.md) | none |
| T1-9 | On T1 and T1A only, the keychain authorize_key precompile call is gas-metered against the tx's remaining gas with a gas table zeroed except SstoreSetWithoutLoadCost and WarmStorageReadCost; pre-T1 and from T1B it runs with u64::MAX gas (unmetered). | [06-transactions-and-fees.md](06-transactions-and-fees.md) | none |
| T1-10 | From T1, precompile calldata shorter than a 4-byte selector reverts with empty data; before, it halts with 'Invalid input: missing function selector'. | [precompiles/00-framework.md](precompiles/00-framework.md) | none |
| T1-11 | From T1, ValidatorConfig `changeValidatorStatusByIndex` is dispatched; before, the selector is unknown and the call reverts `UnknownFunctionSelector(bytes4)`. | [precompiles/validator-config-and-zones.md](precompiles/validator-config-and-zones.md) | none |

> **Resolved conflict C-FORKS-01**: docs guide/node/network-upgrades.mdx says T1B adds keychain precompile gas metering; the code meters the key-authorization precompile call only at T1 and T1A and makes it unmetered (intrinsic gas only) from T1B. Decided: this spec follows the implementation, and the docs are fixed in [tempoxyz/docs#1098](https://github.com/tempoxyz/docs/pull/1098). See [conflicts](conflicts.md#c-forks-01).

Reference implementation: crates/chainspec/src/spec.rs, crates/evm/src/handler.rs, crates/evm/src/handler/config.rs, crates/hardfork/src/gas_params.rs, crates/hardfork/src/lib.rs, crates/precompiles/src/dispatch.rs.

### T1A

Mainnet: 1770908400 (together with T1). No TIP.

| # | Change | Specified in | TIP |
|---|---|---|---|
| T1A-1 | From T1A the per-transaction gas limit cap is 30,000,000 (TEMPO_T1_TX_GAS_LIMIT_CAP); before, MAX_TX_GAS_LIMIT_OSAKA (2^24 = 16,777,216). | [05-block-execution.md](05-block-execution.md) | [TIP-1010](../tips/tip-1010.md) |
| T1A-2 | From T1A, a system error (OOG, DB error, panic) raised while re-placing a filled flip order propagates and reverts the swap; before, every flip failure including system errors was swallowed. | [precompiles/stablecoin-dex.md](precompiles/stablecoin-dex.md) | none |

> **Resolved conflict C-FORKS-02**: TIP-1010 (protocolVersion T1) puts the 30,000,000 per-transaction gas cap at T1; the code applies it from T1A, with the EIP-7825 16,777,216 cap before. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-forks-02).

Reference implementation: crates/evm/src/lib.rs, crates/hardfork/src/lib.rs, crates/precompiles/src/stablecoin_dex/mod.rs.

### T1B

Mainnet: 1771858800. No TIP.

| # | Change | Specified in | TIP |
|---|---|---|---|
| T1B-1 | From T1B, key_authorization intrinsic gas = sig verification + (2,100+100 SLOAD) + SstoreSetWithoutLoadCost×(1+N limit slots) + 2,000 buffer (plus later-fork extras), sole accounting with an unmetered precompile; before, 27,000 + sig verification + 22,000 per spending limit. | [06-transactions-and-fees.md](06-transactions-and-fees.md) | none |
| T1B-2 | From T1B the expiring-nonce replay key is the sender-scoped unique_tx_identifier (keccak256(encode_for_signing \|\| sender)); before, the transaction hash. | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-1009](../tips/tip-1009.md) |

The T1B change to key-authorization gas is also subject to C-FORKS-01 above.

Reference implementation: crates/evm/src/handler.rs.

### T1C

Mainnet: 1773327600. No TIP. Keychain V2 signatures, Osaka precompile set, removal of opcode 0x4F, precompile checkpoints.

| # | Change | Specified in | TIP |
|---|---|---|---|
| T1C-1 | From T1C legacy (V1) Keychain signatures (tx and authorization list) are rejected with LegacyPostT1C; before, V2 Keychain signatures were rejected with V2BeforeActivation. | [03-signatures.md](03-signatures.md) | none |
| T1C-2 | From T1C the Ethereum built-in precompile set follows the configured spec (OSAKA, all Tempo forks map to OSAKA); before, it was the PRAGUE set. | [04-state-and-genesis.md](04-state-and-genesis.md) | none |
| T1C-3 | From T1C opcode 0x4F (MILLIS_TIMESTAMP, 2 gas, pushes block timestamp in ms) is undefined (OpcodeNotFound); before, it executes. | [05-block-execution.md](05-block-execution.md) | none |
| T1C-4 | From T1C key_authorization.chain_id must equal the chain ID exactly; before, chain_id 0 was accepted as a wildcard. | [06-transactions-and-fees.md](06-transactions-and-fees.md) | none |
| T1C-5 | From T1C, precompile checkpoint guards create journal checkpoints so uncommitted state changes are rolled back on failure; before, checkpoints are no-ops. | [precompiles/00-framework.md](precompiles/00-framework.md) | none |
| T1C-6 | From T1C, transfer_fee_post_tx refunds a nonzero unused fee refund to the payer's AccountKeychain spending limit (refund_spending_limit) before reward accounting; before, the spending limit was not refunded. | [precompiles/tip20.md](precompiles/tip20.md) | [TIP-1036](../tips/tip-1036.md) (listed under T2, see C-FORKS-04) |
| T1C-7 | From T1C, collect_fee_pre_tx reserves the direct-route amount_out in transient pending_fee_swap_reservation, and rebalance_swap/burn revert InsufficientLiquidity if they would leave reserve_validator_token below the reservation; before, no reservation or check. | [precompiles/fee-manager.md](precompiles/fee-manager.md) | [TIP-1036](../tips/tip-1036.md) (listed under T2, see C-FORKS-04) |
| T1C-8 | From T1C, place_flip writes next_order_id = order_id+1 directly (one SLOAD fewer, gas-only change); before, it called increment_next_order_id, re-reading the counter. | [precompiles/stablecoin-dex.md](precompiles/stablecoin-dex.md) | none |

> **Resolved conflict C-FORKS-04**: TIP-1036 (T2 meta TIP) lists the FeeAMM reserved-liquidity check (§12) and the fee-refund spending-limit restore (§10) as T2 changes; the code gates both at T1C. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-forks-04).

Reference implementation: crates/evm/src/handler.rs, crates/evm/src/handler/config.rs, crates/evm/src/instructions.rs, crates/hardfork/src/lib.rs, crates/precompiles/src/lib.rs, crates/precompiles/src/stablecoin_dex/mod.rs, crates/precompiles/src/storage/thread_local.rs, crates/precompiles/src/tip20/mod.rs, crates/precompiles/src/tip_fee_manager/amm.rs, crates/precompiles/src/tip_fee_manager/mod.rs.

### T2

Mainnet: 1774965600. Scope: [TIP-1004](../tips/tip-1004.md), [TIP-1015](../tips/tip-1015.md), [TIP-1017](../tips/tip-1017.md), meta [TIP-1036](../tips/tip-1036.md).

| # | Change | Specified in | TIP |
|---|---|---|---|
| T2-1 | From T2, at block start 0xEF marker code is installed at VALIDATOR_CONFIG_V2_ADDRESS if it has empty code; before, no marker. | [05-block-execution.md](05-block-execution.md) | [TIP-1017](../tips/tip-1017.md) |
| T2-2 | From T2, a Tempo tx whose fee_payer_signature recovers to the sender is rejected with SelfSponsoredFeePayer; before, it was accepted. | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-1036](../tips/tip-1036.md) |
| T2-3 | From T2, 2D nonce key gas adds 2×WARM_SLOAD: existing key 5,200 (was 5,000) and new key 22,300 (was 22,100). | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-1036](../tips/tip-1036.md) |
| T2-4 | From T2, TIP-20 `permit`, `nonces` and `DOMAIN_SEPARATOR` are dispatched; before, the selector is unknown and the call reverts `UnknownFunctionSelector(bytes4)`. | [precompiles/tip20.md](precompiles/tip20.md) | [TIP-1004](../tips/tip-1004.md) |
| T2-5 | From T2, sender()/recipient()/mint_recipient() map to directional Sender/Recipient/MintRecipient roles; before, all map to Transfer (sender and recipient both checked on the same account). | [precompiles/tip403.md](precompiles/tip403.md) | [TIP-1015](../tips/tip-1015.md) |
| T2-6 | From T2, transfer authorization (TIP-20 is_transfer_authorized and compound Transfer role) short-circuits to false when sender auth fails without evaluating the recipient policy; before, both were always evaluated. | [precompiles/tip403.md](precompiles/tip403.md) | [TIP-1015](../tips/tip-1015.md) |
| T2-7 | From T2, a stored COMPOUND policy type decodes successfully and an undecodable type reverts InvalidPolicyType; before, COMPOUND or invalid types reverted Panic(UnderOverflow), and is_policy_lookup_error matches InvalidPolicyType/PolicyNotFound instead of UnderOverflow. | [precompiles/tip403.md](precompiles/tip403.md) | [TIP-1036](../tips/tip-1036.md) |
| T2-8 | From T2, createPolicy(WithAccounts) with COMPOUND or invalid policyType reverts IncompatiblePolicyType; before, the type was stored as 255 (__Invalid). | [precompiles/tip403.md](precompiles/tip403.md) | [TIP-1015](../tips/tip-1015.md) |
| T2-9 | From T2, policyData for built-in IDs 0/1 returns WHITELIST/BLACKLIST with zero admin without storage reads; before, it checked policy_exists (else PolicyNotFound) and returned stored default data. | [precompiles/tip403.md](precompiles/tip403.md) | [TIP-1036](../tips/tip-1036.md) |
| T2-10 | From T2, get_policy_data reverts PolicyNotFound when stored data is default and policy_id >= policy_id_counter (counter read only for default data); before, nonexistent IDs silently returned default data. | [precompiles/tip403.md](precompiles/tip403.md) | [TIP-1036](../tips/tip-1036.md) |
| T2-11 | From T2, TIP-403 `isAuthorizedSender`, `isAuthorizedRecipient`, `isAuthorizedMintRecipient`, `compoundPolicyData` and `createCompoundPolicy` are dispatched; before, the selector is unknown and the call reverts `UnknownFunctionSelector(bytes4)`. | [precompiles/tip403.md](precompiles/tip403.md) | [TIP-1015](../tips/tip-1015.md) |
| T2-12 | From T2, tickToPrice and priceToTick revert InvalidTick when the tick is not a multiple of TICK_SPACING; before, unaligned ticks were accepted. | [precompiles/stablecoin-dex.md](precompiles/stablecoin-dex.md) | [TIP-1036](../tips/tip-1036.md) |
| T2-13 | From T2, getRemainingLimit returns the effective limit (zero for missing or revoked keys); before, it returns the raw stored remaining value. | [precompiles/account-keychain.md](precompiles/account-keychain.md) | [TIP-1036](../tips/tip-1036.md) |
| T2-14 | From T2, admin operations additionally revert UnauthorizedCaller unless tx.origin is seeded and equals msg.sender; before, no tx.origin check. | [precompiles/account-keychain.md](precompiles/account-keychain.md) | [TIP-1036](../tips/tip-1036.md) |
| T2-15 | From T2, addValidator/updateValidator NotHostPort/NotIpPort error strings use Display formatting of the parse error; before, Debug formatting (revert data differs). | [precompiles/validator-config-and-zones.md](precompiles/validator-config-and-zones.md) | none |
| T2-16 | From T2, ValidatorConfigV2 dispatches its ABI; before, any call (after input-cost charge) succeeds with empty output like an empty account. | [precompiles/validator-config-and-zones.md](precompiles/validator-config-and-zones.md) | [TIP-1017](../tips/tip-1017.md) |

Reference implementation: crates/evm/src/block.rs, crates/evm/src/handler.rs, crates/hardfork/src/lib.rs, crates/precompiles/src/account_keychain/mod.rs, crates/precompiles/src/stablecoin_dex/mod.rs, crates/precompiles/src/tip20/mod.rs, crates/precompiles/src/tip403_registry/mod.rs, crates/precompiles/src/validator_config/mod.rs, crates/precompiles/src/validator_config_v2/dispatch.rs.

### T3

Mainnet: 1777298400. Scope: [TIP-1011](../tips/tip-1011.md), [TIP-1020](../tips/tip-1020.md), [TIP-1022](../tips/tip-1022.md), meta [TIP-1038](../tips/tip-1038.md).

| # | Change | Specified in | TIP |
|---|---|---|---|
| T3-1 | TIP-1038 §3 (zero-valued `expiry`, `valid_before`, `valid_after` unrepresentable) changes no block-validity rule: on the wire, zero has always decoded as absent. | [02-encoding.md](02-encoding.md) | [TIP-1038](../tips/tip-1038.md) |
| T3-2 | From T3 ADDRESS_REGISTRY (TIP-1022) and SIGNATURE_VERIFIER (TIP-1020) are live precompiles and get 0xEF marker code at block start if empty; before, they are ordinary empty accounts. | [04-state-and-genesis.md](04-state-and-genesis.md) | [TIP-1020](../tips/tip-1020.md) |
| T3-3 | From T3 key authorizations may carry periodic limits and call scopes; before, KeychainValidationFailed ('periodic token limits/call scopes are not active before T3'). | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-1011](../tips/tip-1011.md) |
| T3-4 | From T3, a same-tx authorize-and-use whose key_type differs from the keychain signature type fails KeychainValidationFailed; before, not checked. | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-1011](../tips/tip-1011.md) |
| T3-5 | From T3, a Keychain-signed Tempo tx whose first call is CREATE is rejected (CallsValidation 'access-key transactions cannot use CREATE as the first call'); before, allowed. | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-1011](../tips/tip-1011.md) |
| T3-6 | From T3, for access-key txs every call is pre-validated against the key's call scopes (metered against remaining gas) before the first call executes, failing the batch; before, no scope check. | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-1011](../tips/tip-1011.md) |
| T3-7 | From T3 key_authorization gas counts 2 SSTOREs per spending limit and adds call-scope storage rows (1+3/target+3/selector+1/constrained selector+2/recipient); before, 1 SSTORE per limit and no scope rows. | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-1011](../tips/tip-1011.md) |
| T3-8 | From T3, mint/mintWithMemo, burn/burnWithMemo and burnBlocked revert Paused when the token is paused (checked before the role check), and mint also validates the resolved recipient; before, these ignored pause state. | [precompiles/tip20.md](precompiles/tip20.md) | [TIP-1038](../tips/tip-1038.md) |
| T3-9 | From T3, setRewardRecipient reverts InvalidRecipient for a TIP-1022 virtual address; before, virtual addresses were accepted. | [precompiles/tip20.md](precompiles/tip20.md) | [TIP-1022](../tips/tip-1022.md) |
| T3-10 | From T3, TIP-20 recipients that are TIP-1022 virtual addresses resolve to their registered master, reverting VirtualAddressUnregistered if unregistered; before, recipients are used unchanged (registry precompile enabled at T3). | [precompiles/tip403.md](precompiles/tip403.md) | [TIP-1022](../tips/tip-1022.md) |
| T3-11 | From T3, createPolicyWithAccounts and modifyPolicyWhitelist/Blacklist revert VirtualAddressNotAllowed for virtual addresses (modify checks this first); before, virtual addresses were accepted. | [precompiles/tip403.md](precompiles/tip403.md) | [TIP-1022](../tips/tip-1022.md) |
| T3-12 | From T3, setUserToken returns without writing storage or emitting UserTokenSet when the token equals the current value; before, it always wrote and emitted. | [precompiles/fee-manager.md](precompiles/fee-manager.md) | [TIP-1038](../tips/tip-1038.md) |
| T3-13 | From T3, swap route validation reverts Paused if any hop's token_in is paused (internal-balance swaps bypass TIP-20 pause checks); before, no pause check on route. | [precompiles/stablecoin-dex.md](precompiles/stablecoin-dex.md) | [TIP-1038](../tips/tip-1038.md) §4 ([TIP-1036](../tips/tip-1036.md) §3 says T2, see C-FORKS-03) |
| T3-14 | From T3, the legacy authorizeKey(keyId,signatureType,expiry,enforceLimits,limits) selector errors with LegacyAuthorizeKeySelectorChanged(selector); before, it is accepted and mapped to period=0 limits, allowAnyCalls=true, allowedCalls=[]. | [precompiles/account-keychain.md](precompiles/account-keychain.md) | [TIP-1011](../tips/tip-1011.md) |
| T3-15 | From T3, authorizeKey rejects duplicate tokens (when enforceLimits) with InvalidSpendingLimit, accepts periodic limits and call scopes, and stores remaining, max (amount > u128::MAX -> InvalidSpendingLimit), period, period_end=now+period and the scope tree; before, any period!=0 -> InvalidSpendingLimit, allowAnyCalls=false or nonempty allowedCalls -> InvalidCallScope, and only remaining is stored. | [precompiles/account-keychain.md](precompiles/account-keychain.md) | [TIP-1011](../tips/tip-1011.md) |
| T3-16 | From T3, updateSpendingLimit sets both remaining and max to newLimit (newLimit > u128::MAX -> InvalidSpendingLimit) keeping period and period_end; before, only remaining is written. | [precompiles/account-keychain.md](precompiles/account-keychain.md) | [TIP-1011](../tips/tip-1011.md) |
| T3-17 | From T3, transactions signed by a scoped access key must match its call-scope tree (CREATE or unlisted target/selector/recipient -> CallNotAllowed); before, no call-scope enforcement. | [precompiles/account-keychain.md](precompiles/account-keychain.md) | [TIP-1011](../tips/tip-1011.md) |
| T3-18 | From T3, effective remaining-limit reads for key_id == 0 return (0, 0) without reading storage; before, the stored values for the zero key are read. | [precompiles/account-keychain.md](precompiles/account-keychain.md) | [TIP-1011](../tips/tip-1011.md) |
| T3-19 | From T3, effective-limit reads return (0,0) for expired keys and, for periodic limits past period_end, return (max, next period end); before, they return raw stored remaining with periodEnd 0. | [precompiles/account-keychain.md](precompiles/account-keychain.md) | [TIP-1011](../tips/tip-1011.md) |
| T3-20 | From T3, spending deduction rolls periodic limits over (remaining=max, period_end advanced) before checking, writes the full limit row and emits AccessKeySpend; before, it only checks and decrements remaining with no event. | [precompiles/account-keychain.md](precompiles/account-keychain.md) | [TIP-1011](../tips/tip-1011.md) |
| T3-21 | From T3, fee-refund restoration of an access-key limit is clamped to max when max != 0; before, remaining is increased with saturating add and no clamp. | [precompiles/account-keychain.md](precompiles/account-keychain.md) | [TIP-1038](../tips/tip-1038.md) |
| T3-22 | From T3, AccountKeychain `authorizeKey` (TIP-1011 overload), `setAllowedCalls`, `removeAllowedCalls`, `getRemainingLimitWithPeriod` and `getAllowedCalls` are dispatched, and `getRemainingLimit` becomes an unknown selector; before, the reverse. | [precompiles/account-keychain.md](precompiles/account-keychain.md) | [TIP-1011](../tips/tip-1011.md) |

> **Resolved conflict C-FORKS-03**: TIP-1036 §3 says the StablecoinDEX internal-balance swap pause check is gated at T2; the code gates it at T3 (matching TIP-1038 §4), and the placement and internal-debit pause checks at T4. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-forks-03).

Reference implementation: crates/contracts/src/precompiles/mod.rs, crates/evm/src/block.rs, crates/evm/src/handler.rs, crates/precompiles/src/account_keychain/dispatch.rs, crates/precompiles/src/account_keychain/mod.rs, crates/precompiles/src/address_registry/mod.rs, crates/precompiles/src/stablecoin_dex/mod.rs, crates/precompiles/src/tip20/mod.rs, crates/precompiles/src/tip20/rewards.rs, crates/precompiles/src/tip403_registry/mod.rs, crates/precompiles/src/tip_fee_manager/mod.rs.

### T4

Mainnet: 1779112800. Scope: [TIP-1031](../tips/tip-1031.md), meta [TIP-1046](../tips/tip-1046.md).

| # | Change | Specified in | TIP |
|---|---|---|---|
| T4-1 | From T4, block headers carry the trailing `consensus_context` field `[epoch, view, parent_view, proposer]`, set by the proposer. C-FORKS-05 covers how its presence is gated. | [02-encoding.md](02-encoding.md) | [TIP-1031](../tips/tip-1031.md) |
| T4-2 | From T4 blocks must contain zero end-of-block system txs (MissingEndOfBlockSystemTxs otherwise) and a subblocks-metadata system tx (to=0x0) is rejected ('subblocks are disabled in T4+'); before, exactly SYSTEM_TX_COUNT=1 such tx was required last. | [05-block-execution.md](05-block-execution.md) | [TIP-1046](../tips/tip-1046.md) |
| T4-3 | From T4 shared_gas_limit is 0 and any incentive-section gas fails the block ('incentive gas limit exceeded'); before, shared gas limit was block_gas_limit/10. | [05-block-execution.md](05-block-execution.md) | [TIP-1046](../tips/tip-1046.md) |
| T4-4 | From T4 key_authorization gas counts only storage-creating scope rows (1+2/target+1+2/selector+1/non-empty selector set+1/constrained selector+2/recipient) and adds 5,000+7,000/target+7,000/selector+5,000/recipient scope surcharge; before, T3 row counting and no surcharge. | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-1046](../tips/tip-1046.md) |
| T4-5 | From T4, precompile SLOAD, SSTORE and account loads deduct static gas (WarmStorageReadCost / SstoreStatic) before access and skip the cold load if remaining gas < cold additional cost; before, static gas is deducted after the (possibly cold) load. | [precompiles/00-framework.md](precompiles/00-framework.md) | [TIP-1046](../tips/tip-1046.md) |
| T4-6 | From T4, precompile SSTOREs add the standard SSTORE refund to the refund counter; before, precompile storage writes produce no refund. | [precompiles/00-framework.md](precompiles/00-framework.md) | none |
| T4-7 | From T4 a struct store starts each packed slot group from zero instead of SLOADing the existing slot (one fewer SLOAD's gas; unowned padding bits cleared); before, it loaded and merged into the current slot value. | [precompiles/00-framework.md](precompiles/00-framework.md) | [TIP-1046](../tips/tip-1046.md) |
| T4-8 | From T4, an error (e.g. OutOfGas) in the TIP-20 is_initialized check is propagated; before, it is treated as uninitialized and reverts Uninitialized. | [precompiles/tip20.md](precompiles/tip20.md) | [TIP-1046](../tips/tip-1046.md) |
| T4-9 | From T4, order and flip placement revert Paused if the non-escrow token is paused, and internal-balance escrow debits (fully covered or flip internal_balance_only) check the escrow token's pause; before, these paths skipped pause checks. | [precompiles/stablecoin-dex.md](precompiles/stablecoin-dex.md) | [TIP-1046](../tips/tip-1046.md) |
| T4-10 | From T4, cancelStaleOrder treats a maker as authorized only if also recipient-authorized on the payout token (bid=base, ask=quote); before, only sender auth on the escrow token was checked. | [precompiles/stablecoin-dex.md](precompiles/stablecoin-dex.md) | [TIP-1046](../tips/tip-1046.md) |
| T4-11 | From T4, all call scopes in a batch are validated (zero target, selector rules) before any scope is written; before, only target duplicates are checked up front and each scope is validated inline just before its write. | [precompiles/account-keychain.md](precompiles/account-keychain.md) | [TIP-1046](../tips/tip-1046.md) |
| T4-12 | From T4, a selector rule with empty recipients no longer issues a delete() of the nested recipients set; before, the redundant delete touches storage (affects gas/warmness only). | [precompiles/account-keychain.md](precompiles/account-keychain.md) | [TIP-1046](../tips/tip-1046.md) |
| T4-13 | From T4, recipient-constrained selector rules require only that target has the TIP-20 address prefix; before, target must be an initialized TIP-20 per TIP20Factory.isTIP20 (storage read). | [precompiles/account-keychain.md](precompiles/account-keychain.md) | [TIP-1046](../tips/tip-1046.md) |

> **Open conflict C-FORKS-05**: TIP-1031 and docs upgrades/t4.mdx require consensus_context exactly from T4 and absent before; the code applies no fork gate to its presence (proposers always set it, consensus verification always requires it, execution never checks it by fork). See [conflicts](conflicts.md#c-forks-05).

Reference implementation: crates/evm/src/block.rs, crates/evm/src/consensus/mod.rs, crates/evm/src/handler.rs, crates/hardfork/src/lib.rs, crates/precompiles-macros/src/storable.rs, crates/precompiles/src/account_keychain/mod.rs, crates/precompiles/src/stablecoin_dex/mod.rs, crates/precompiles/src/storage/evm.rs, crates/precompiles/src/tip20/dispatch.rs.

### T5

Mainnet: 1781013600. Scope: [TIP-1026](../tips/tip-1026.md), [TIP-1030](../tips/tip-1030.md), [TIP-1033](../tips/tip-1033.md), [TIP-1034](../tips/tip-1034.md), [TIP-1035](../tips/tip-1035.md), [TIP-1045](../tips/tip-1045.md), [TIP-1053](../tips/tip-1053.md), [TIP-1056](../tips/tip-1056.md), meta [TIP-1057](../tips/tip-1057.md).

| # | Change | Specified in | TIP |
|---|---|---|---|
| T5-1 | From T5 TIP20_CHANNEL_RESERVE is a live precompile and gets 0xEF marker code at block start if empty; before, empty account. | [04-state-and-genesis.md](04-state-and-genesis.md) | [TIP-1034](../tips/tip-1034.md) |
| T5-2 | From T5 the payment lane uses TIP-1045 is_payment_v2 (allow-listed TIP-20 selector with exact ABI length, empty access/authorization lists, bounded key_authorization, non-empty calls); before, is_payment_v1 (every call target has the TIP-20 0x20c0 prefix). | [05-block-execution.md](05-block-execution.md) | [TIP-1045](../tips/tip-1045.md) |
| T5-3 | From T5 key authorizations may carry a witness (charging an extra 2,200 SLOAD+1,500 event gas); before, KeychainValidationFailed ('key authorization witnesses are not active before T5'). | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-1053](../tips/tip-1053.md) |
| T5-4 | From T5, overwriting a Vec/String/Bytes with a shorter value zeroes stale tail slots (one extra SLOAD of the length/base slot unless skip_tail_cleanup); before, tail slots are left populated. | [precompiles/00-framework.md](precompiles/00-framework.md) | [TIP-1057](../tips/tip-1057.md) |
| T5-5 | TIP-1057 §1 (fixed-size array packing) changes no state: no precompile storage uses an affected array type. The fixed packing rule applies at every fork. | [precompiles/00-framework.md](precompiles/00-framework.md) | [TIP-1057](../tips/tip-1057.md) |
| T5-6 | From T5, TIP-20 system_transfer_from reverts Unauthorized unless caller is in the implicit approval list {TipFeeManager, StablecoinDEX, TIP20ChannelReserve}; before, the list is empty and caller is unchecked. | [precompiles/tip20.md](precompiles/tip20.md) | [TIP-1035](../tips/tip-1035.md) |
| T5-7 | From T5, the TIP-20 channel reserve address, and the token's own address, are protected from burnBlocked/burnAt (ProtectedAddress); before, only FeeManager and StablecoinDEX were protected. | [precompiles/tip20.md](precompiles/tip20.md) | [TIP-1034](../tips/tip-1034.md) |
| T5-8 | From T5, AddressRegistry `isImplicitlyApproved`, TIP-20 `logoURI`/`setLogoURI` and TIP20Factory `createToken` with logo URI are dispatched; before, the selector is unknown and the call reverts `UnknownFunctionSelector(bytes4)`. | [precompiles/tip20.md](precompiles/tip20.md) | [TIP-1026](../tips/tip-1026.md), [TIP-1035](../tips/tip-1035.md) |
| T5-9 | From T5, when the direct pool lacks liquidity, fee routing falls back to a two-hop route via userToken.quoteToken(), reserving liquidity in both pools; before, it returned no route (InsufficientLiquidity). | [precompiles/fee-manager.md](precompiles/fee-manager.md) | [TIP-1033](../tips/tip-1033.md) |
| T5-10 | From T5, DEX pulls tokens from users via TIP-20 system_transfer_from (no allowance); before, via transferFrom requiring the user's allowance to the DEX. | [precompiles/stablecoin-dex.md](precompiles/stablecoin-dex.md) | [TIP-1035](../tips/tip-1035.md) |
| T5-11 | From T5, flip orders may have flip_tick == tick (bids flip_tick >= tick, asks <= tick); before, equality reverted InvalidFlipTick. | [precompiles/stablecoin-dex.md](precompiles/stablecoin-dex.md) | [TIP-1030](../tips/tip-1030.md) |
| T5-12 | From T5, a fully filled flip order is flipped in place keeping its orderId (record kept on success, deleted on failure) and a failed flip emits FlipFailed(orderId, maker, selector); before, a new order was placed via place_flip and the filled record always deleted, no event. | [precompiles/stablecoin-dex.md](precompiles/stablecoin-dex.md) | [TIP-1056](../tips/tip-1056.md) |
| T5-13 | From T5, authorizeKey with allowAnyCalls=true and a nonempty allowedCalls reverts InvalidCallScope; before, allowedCalls is ignored. | [precompiles/account-keychain.md](precompiles/account-keychain.md) | none |
| T5-14 | From T5, AccountKeychain `authorizeKey` (witness overload), `burnKeyAuthorizationWitness` and `isKeyAuthorizationWitnessBurned` are dispatched; before, the selector is unknown and the call reverts `UnknownFunctionSelector(bytes4)`. | [precompiles/account-keychain.md](precompiles/account-keychain.md) | [TIP-1053](../tips/tip-1053.md) |

Reference implementation: crates/contracts/src/precompiles/mod.rs, crates/evm/src/block.rs, crates/evm/src/handler.rs, crates/precompiles/src/account_keychain/mod.rs, crates/precompiles/src/address_registry/mod.rs, crates/precompiles/src/stablecoin_dex/mod.rs, crates/precompiles/src/stablecoin_dex/order/mod.rs, crates/precompiles/src/storage/types/bytes_like.rs, crates/precompiles/src/storage/types/vec.rs, crates/precompiles/src/tip20/mod.rs, crates/precompiles/src/tip_fee_manager/amm.rs.

### T6

Mainnet: 1782223200. Scope: [TIP-1028](../tips/tip-1028.md), [TIP-1049](../tips/tip-1049.md).

| # | Change | Specified in | TIP |
|---|---|---|---|
| T6-1 | From T6 RECEIVE_POLICY_GUARD is a live precompile and gets 0xEF marker code at block start if empty; before, empty account. | [04-state-and-genesis.md](04-state-and-genesis.md) | [TIP-1028](../tips/tip-1028.md) |
| T6-2 | From T6 key authorizations may set is_admin/account and an access key may authorize another key if it is an active admin key whose type matches the sidecar signature (else KeyAuthorizationNotSignedByRoot/KeychainValidationFailed); before, such fields failed, non-root signers failed KeyAuthorizationNotSignedByRoot, and access keys failed AccessKeyCannotAuthorizeOtherKeys. | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-1049](../tips/tip-1049.md) |
| T6-3 | From T6 admin key authorizations add 1,500 intrinsic gas for the extra event; before, n/a. | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-1049](../tips/tip-1049.md) |
| T6-4 | From T6, inbound transfers/mints check the recipient's address-level receive policy: the guard address as target reverts AddressReserved, blocked inbounds are diverted to the guard (or revert PolicyForbids where configured); before, no receive-policy check. | [precompiles/tip20.md](precompiles/tip20.md) | [TIP-1028](../tips/tip-1028.md) |
| T6-5 | From T6, the RECEIVE_POLICY_GUARD address is protected from burnBlocked/burnAt and always authorized by every TIP-403 policy; before, it had no special status. | [precompiles/tip403.md](precompiles/tip403.md) | [TIP-1028](../tips/tip-1028.md) |
| T6-6 | From T6, admin operations may be signed by an active admin access key of msg.sender; before, any non-zero transaction key reverts UnauthorizedCaller. | [precompiles/account-keychain.md](precompiles/account-keychain.md) | [TIP-1049](../tips/tip-1049.md) |
| T6-7 | From T6, AccountKeychain `authorizeAdminKey`/`isAdminKey`, SignatureVerifier `verifyKeychain`/`verifyKeychainAdmin` and TIP-403 `receivePolicy`/`validateReceivePolicy`/`setReceivePolicy` are dispatched; before, the selector is unknown and the call reverts `UnknownFunctionSelector(bytes4)`. | [precompiles/account-keychain.md](precompiles/account-keychain.md) | [TIP-1049](../tips/tip-1049.md), [TIP-1028](../tips/tip-1028.md) |

Reference implementation: crates/contracts/src/precompiles/mod.rs, crates/evm/src/block.rs, crates/evm/src/handler.rs, crates/precompiles/src/account_keychain/mod.rs, crates/precompiles/src/tip20/mod.rs, crates/precompiles/src/tip403_registry/mod.rs.

### T7

Mainnet: 1783605600. Scope: [TIP-1060](../tips/tip-1060.md), [TIP-1064](../tips/tip-1064.md), [TIP-1067](../tips/tip-1067.md), [TIP-1075](../tips/tip-1075.md). The upgrade page also cites a TIP-1066 for channel storage credits, which does not exist in `tips/`. That behaviour is row T7-7, specified in [precompiles/tip20.md](precompiles/tip20.md).

| # | Change | Specified in | TIP |
|---|---|---|---|
| T7-1 | From T7 STORAGE_CREDITS is a live precompile and gets 0xEF marker code at block start if empty; before, empty account. | [04-state-and-genesis.md](04-state-and-genesis.md) | [TIP-1060](../tips/tip-1060.md) |
| T7-2 | From T7 (TIP-1060), zero-to-nonzero SSTORE set cost is 5,000 in the gas table, with the remaining 245,000 charged by the storage-credit hook; the SSTORE set refund is 5,000 (Osaka 19,900); the clearing refund is 0 (EIP-3529 4,800); and the refund cap quotient is 1 (EIP-3529 5), so refunds are uncapped up to gas used. | [05-block-execution.md](05-block-execution.md) | [TIP-1060](../tips/tip-1060.md) |
| T7-3 | From T7 SSTORE runs the TIP-1060 storage-credit hook (charging 245,000 for fresh 0→x creations unless covered by a credit, minting credits on clears); successful txs then settle pending refunds from STORAGE_CREDITS transient storage as refund credits×245,000, and fee-payer fee-token slots are non-creditable; before, plain SSTORE. | [05-block-execution.md](05-block-execution.md) | [TIP-1060](../tips/tip-1060.md) |
| T7-4 | From T7 base fee is dynamic: EIP-1559 update (denominator 8, elasticity 1) against a fixed 10,000,000 gas target on parent gas_used, clamped to [600,000,000, 12,000,000,000]; before, fixed 20,000,000,000. | [05-block-execution.md](05-block-execution.md) | [TIP-1067](../tips/tip-1067.md) |
| T7-5 | From T7 key_authorization SSTORE cost adds STORAGE_CREDIT_VALUE (245,000) to SstoreSetWithoutLoadCost per row (net 250,000 as in T1); before, the gas-table value alone. | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-1060](../tips/tip-1060.md) |
| T7-6 | From T7 distributeReward calldata no longer triggers TIP-20 fee-token inference (only transfer/transferWithMemo); before, it also did. | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-1075](../tips/tip-1075.md) |
| T7-7 | From T7, opening a channel spends the payer's channel_storage_credits (counter deleted, budget applied to the channel-state write); before, the channel state was written without spending credits. | [precompiles/tip20.md](precompiles/tip20.md) | [TIP-1060](../tips/tip-1060.md) |
| T7-8 | From T7, distributeReward and setRewardRecipient are no-ops returning success with no checks, transfers or events; before, they executed fully. | [precompiles/tip20.md](precompiles/tip20.md) | [TIP-1075](../tips/tip-1075.md) |
| T7-9 | From T7, deleting order slots credits the maker's dex_storage_credits (initializing the counter spends one credit) and user placements spend those credits when writing the new order record; before, no DEX storage credits were recorded or spent. | [precompiles/stablecoin-dex.md](precompiles/stablecoin-dex.md) | [TIP-1064](../tips/tip-1064.md) |
| T7-10 | From T7, StablecoinDEX `storageCredits` and TIP20ChannelReserve `storageCredits` are dispatched; before, the selector is unknown and the call reverts `UnknownFunctionSelector(bytes4)`. | [precompiles/stablecoin-dex.md](precompiles/stablecoin-dex.md) | [TIP-1064](../tips/tip-1064.md), [TIP-1060](../tips/tip-1060.md) |
| T7-11 | From T7, a periodic limit whose remaining hits zero is stored as sentinel U256::MAX (decoded as zero by reads, spends and refunds) so the slot is never cleared; before, zero is stored. | [precompiles/account-keychain.md](precompiles/account-keychain.md) | [TIP-1060](../tips/tip-1060.md) |
| T7-12 | From T7, precompile SSTOREs run the TIP-1060 storage-credit policy, preserve_storage_credits sets the owner's mode to Preserve, and track_minted_credits/with_budget measure credit deltas; before, all are no-ops. | [precompiles/account-keychain.md](precompiles/account-keychain.md) | [TIP-1060](../tips/tip-1060.md) |

Reference implementation: crates/chainspec/src/spec.rs, crates/contracts/src/precompiles/mod.rs, crates/evm/src/block.rs, crates/evm/src/common.rs, crates/evm/src/handler.rs, crates/evm/src/handler/config.rs, crates/evm/src/instructions.rs, crates/hardfork/src/gas_params.rs, crates/precompiles/src/account_keychain/mod.rs, crates/precompiles/src/dispatch.rs, crates/precompiles/src/stablecoin_dex/mod.rs, crates/precompiles/src/storage/evm.rs, crates/precompiles/src/storage_credits/mod.rs, crates/precompiles/src/tip20/rewards.rs, crates/precompiles/src/tip20_channel_reserve/mod.rs.

### T8

Mainnet: 1785420000. Scope: [TIP-1042](../tips/tip-1042.md), [TIP-1062](../tips/tip-1062.md), [TIP-1070](../tips/tip-1070.md), [TIP-1075](../tips/tip-1075.md), [TIP-1087](../tips/tip-1087.md).

| # | Change | Specified in | TIP |
|---|---|---|---|
| T8-1 | From T8 CURRENT_COMMITTEE is a live precompile and gets 0xEF marker code at block start if empty; before, empty account. | [04-state-and-genesis.md](04-state-and-genesis.md) | [TIP-1070](../tips/tip-1070.md) |
| T8-2 | From T8 the last block of each epoch ((number+1)%epoch_length==0) ends with a system call from 0x0 to CURRENT_COMMITTEE setCommitteeMembers(epoch, players) decoded from extra_data's DKG outcome; decode failure or a failed call invalidates the block; before, no call. | [05-block-execution.md](05-block-execution.md) | [TIP-1070](../tips/tip-1070.md) |
| T8-3 | From T8, update_rewards is a no-op returning zero address and getPendingRewards returns only the stored reward_balance; before, rewards accrued on balance changes and pending included unaccrued rewards. | [precompiles/tip20.md](precompiles/tip20.md) | [TIP-1075](../tips/tip-1075.md) |
| T8-4 | From T8, _transfer debits the sender with a delta decrement (InsufficientBalance on underflow) after the rewards hook; before, it read (SLOAD) and checked the balance (InsufficientBalance) before the rewards hook, then wrote the new balance. | [precompiles/tip20.md](precompiles/tip20.md) | none |
| T8-5 | From T8, collect_fee_pre_tx checks only fee_payer sender authorization (FeeManager recipient exempt); before, full fee_payer→FeeManager transfer authorization. | [precompiles/fee-manager.md](precompiles/fee-manager.md) | [TIP-1042](../tips/tip-1042.md) |
| T8-6 | From T8, mint checks user-token sender auth for msg_sender and recipient auth for FeeManager and to, plus validator-token recipient auth for to; burn checks msg_sender sender auth on both tokens; before, no such pre-checks. | [precompiles/fee-manager.md](precompiles/fee-manager.md) | [TIP-1042](../tips/tip-1042.md) |
| T8-7 | From T8, order storage is versioned: reads detect Legacy/V1/V2 from slot0 and writes use compact layouts; before, orders always used the legacy layout without reading a version. | [precompiles/stablecoin-dex.md](precompiles/stablecoin-dex.md) | [TIP-1062](../tips/tip-1062.md) |
| T8-8 | From T8, createPair assigns the book index book_keys.len() (Orderbook::new_with_index); before, books were created without an index. | [precompiles/stablecoin-dex.md](precompiles/stablecoin-dex.md) | [TIP-1087](../tips/tip-1087.md) |
| T8-9 | From T8, appending an order writes only the previous tail's next field; before, the previous tail order was fully read and rewritten. | [precompiles/stablecoin-dex.md](precompiles/stablecoin-dex.md) | [TIP-1062](../tips/tip-1062.md) |
| T8-10 | From T8, a taker-triggered flip rewrite credits the maker with storage credits minted by the rewrite without spending maker credits; before (T7), non-charged writes were plain writes. | [precompiles/stablecoin-dex.md](precompiles/stablecoin-dex.md) | [TIP-1064](../tips/tip-1064.md) |
| T8-11 | From T8, StablecoinDEX `bookIndexForKey`, `bookKeyForIndex` and `setBookIndex` are dispatched; before, the selector is unknown and the call reverts `UnknownFunctionSelector(bytes4)`. | [precompiles/stablecoin-dex.md](precompiles/stablecoin-dex.md) | [TIP-1087](../tips/tip-1087.md) |

Reference implementation: crates/contracts/src/precompiles/mod.rs, crates/evm/src/block.rs, crates/precompiles/src/stablecoin_dex/mod.rs, crates/precompiles/src/stablecoin_dex/order/storage.rs, crates/precompiles/src/tip20/mod.rs, crates/precompiles/src/tip20/rewards.rs, crates/precompiles/src/tip_fee_manager/amm.rs, crates/precompiles/src/tip_fee_manager/mod.rs.

### T9

Mainnet: 1786024800. Scope: [TIP-1092](../tips/tip-1092.md).

| # | Change | Specified in | TIP |
|---|---|---|---|
| T9-1 | From T9, a token's transfer policy ID is stored and read in the TIP-403 registry (initialize/changeTransferPolicyId write there; reads prefer it over the legacy slot); before, it lived only in the TIP-20 slot. | [precompiles/tip20.md](precompiles/tip20.md) | [TIP-1092](../tips/tip-1092.md) |
| T9-2 | From T9, TIP-403 `tokenTransferPolicyId` and `migrateTransferPolicyIds` are dispatched; before, the selector is unknown and the call reverts `UnknownFunctionSelector(bytes4)`. | [precompiles/tip403.md](precompiles/tip403.md) | [TIP-1092](../tips/tip-1092.md) |

Reference implementation: crates/precompiles/src/tip20/mod.rs.

### T10

Mainnet: 1787320800. Scope: [TIP-1091](../tips/tip-1091.md).

| # | Change | Specified in | TIP |
|---|---|---|---|
| T10-1 | From T10 ZONE_FACTORY is a live precompile; at block start, if its code is empty, the factory marker with initial TIP-1091 storage plus portal/verifier/messenger runtimes are installed; before, absent. | [04-state-and-genesis.md](04-state-and-genesis.md) | [TIP-1091](../tips/tip-1091.md) |

Reference implementation: crates/contracts/src/precompiles/mod.rs, crates/evm/src/block.rs.

### T11

Mainnet: 1789048800. Scope: [TIP-1093](../tips/tip-1093.md), [TIP-1100](../tips/tip-1100.md), meta [TIP-1105](../tips/tip-1105.md).

| # | Change | Specified in | TIP |
|---|---|---|---|
| T11-1 | From T11 the expiring-nonce ring capacity is 3,000,000 and max valid_before window 300 s; before, 300,000 and 30 s. | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-1093](../tips/tip-1093.md) |
| T11-2 | From T11, precompile calldata is ABI-decoded strictly (non-canonical encoding, out-of-range values, bad padding/offsets fail decoding); before, lenient decoding. | [precompiles/00-framework.md](precompiles/00-framework.md) | [TIP-1105](../tips/tip-1105.md) |
| T11-3 | From T11 precompile calldata decoding costs 30 gas per 32-byte word (was 6) and duplicate validation charges 20 gas per item (was 0). | [precompiles/00-framework.md](precompiles/00-framework.md) | [TIP-1100](../tips/tip-1100.md) |
| T11-4 | From T11 (until T14), authorizeKey/authorizeAdminKey calldata whose signatureType head word equals 3 (ConfigurableAccount) reverts with empty data before dispatch; before T11 it decodes and later fails with InvalidSignatureType. | [precompiles/account-keychain.md](precompiles/account-keychain.md) | [TIP-1105](../tips/tip-1105.md) |
| T11-5 | From T11, duplicate checks for scope targets, selectors and ZoneFactory closed-loop accounts/gateways/sequencers use metered sort-and-scan, with all target duplicates checked before per-scope validation; before, unmetered incremental HashSet checks interleaved with validation. | [precompiles/account-keychain.md](precompiles/account-keychain.md) | [TIP-1105](../tips/tip-1105.md) |

Reference implementation: crates/hardfork/src/lib.rs, crates/precompiles/src/account_keychain/dispatch.rs, crates/precompiles/src/account_keychain/mod.rs, crates/precompiles/src/dispatch.rs, crates/precompiles/src/lib.rs, crates/precompiles/src/zone_factory/mod.rs.

### T12

Mainnet: 1791900000. Scope: [TIP-1006](../tips/tip-1006.md), [TIP-1088](../tips/tip-1088.md), [TIP-1095](../tips/tip-1095.md), [TIP-1106](../tips/tip-1106.md), meta [TIP-1116](../tips/tip-1116.md). The two consensus rows switch per epoch (see [Consensus-layer switches](#consensus-layer-switches)).

| # | Change | Specified in | TIP |
|---|---|---|---|
| T12-1 | From T12 an expiring-nonce tx may carry any nonce (opaque discriminator); before, a nonzero nonce failed ExpiringNonceNonceNotZero. | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-1106](../tips/tip-1106.md) |
| T12-2 | For epochs whose starting boundary block has T12 active, leader election uses version V1 of the Random elector (hashes the seed first); before, V0. | [07-consensus.md](07-consensus.md), [commonware/simplex.md §6](commonware/simplex.md#6-leader-election) | [TIP-1116](../tips/tip-1116.md) §5 |
| T12-3 | For an epoch whose boundary block (see [Consensus-layer switches](#consensus-layer-switches)) is in T12 or later, the DKG ceremony uses the V1 reveal rules; before, V0. | [07-consensus.md](07-consensus.md), [commonware/dkg.md §2](commonware/dkg.md#2-fault-model-and-derived-parameters) | [TIP-1116](../tips/tip-1116.md) §4 |
| T12-4 | From T12, strict ABI validation permits trailing bytes after the encoded arguments; at T11 trailing bytes fail decoding. | [precompiles/00-framework.md](precompiles/00-framework.md) | [TIP-1116](../tips/tip-1116.md) |
| T12-5 | From T12, a mutating precompile call in a static context is a frame-local exceptional halt; before, it reverts with StaticCallNotAllowed() ABI data. | [precompiles/00-framework.md](precompiles/00-framework.md) | [TIP-1116](../tips/tip-1116.md) |
| T12-6 | From T12, a precompile SSTORE fails OutOfGas when remaining frame gas <= CallStipend (2300), per EIP-2200; before, no stipend sentry. | [precompiles/00-framework.md](precompiles/00-framework.md) | [TIP-1116](../tips/tip-1116.md) |
| T12-7 | From T12, any address with the Zone portal prefix 0x5AD000000000000000000000 is protected from burnBlocked/burnAt (ProtectedAddress); before, not protected. | [precompiles/tip20.md](precompiles/tip20.md) | [TIP-1006](../tips/tip-1006.md) |
| T12-8 | From T12, open/topUp check payer→payee transfer and receive-policy authorization and move deposits via channel_reserve_transfer, marking new channels to use the payer as receive-policy sender; before, only payee recipient auth then system_transfer_from. | [precompiles/tip20.md](precompiles/tip20.md) | [TIP-1095](../tips/tip-1095.md) |
| T12-9 | From T12, settle/close/withdraw check payer→payee authorization, deliver via policy-aware channel_reserve_transfer, and commit/delete channel state only after deliveries succeed; before, sender auth only, state written or deleted first, then plain transfers. | [precompiles/tip20.md](precompiles/tip20.md) | [TIP-1095](../tips/tip-1095.md) |
| T12-10 | From T12, TIP-20 `BURN_AT_ROLE` and `burnAt` are dispatched; before, the selector is unknown and the call reverts `UnknownFunctionSelector(bytes4)`. | [precompiles/tip20.md](precompiles/tip20.md) | [TIP-1006](../tips/tip-1006.md) |
| T12-11 | From T12, tick levels store only the links slot: total_liquidity is no longer maintained on place/fill/cancel (cancel writes the level only for head/tail), and getPriceLevel sums order remainings; before, the two-slot aggregate was updated on every change. | [precompiles/stablecoin-dex.md](precompiles/stablecoin-dex.md) | [TIP-1088](../tips/tip-1088.md) |
| T12-12 | From T12, quoteSwapExactAmountIn/Out walk the book order-by-order using swap step arithmetic; before, legacy per-tick quotes over total_liquidity rounding once per tick. | [precompiles/stablecoin-dex.md](precompiles/stablecoin-dex.md) | [TIP-1088](../tips/tip-1088.md) |

Reference implementation: crates/consensus/src/epoch/manager/actor.rs, crates/evm/src/handler.rs, crates/precompiles/src/dispatch.rs, crates/precompiles/src/stablecoin_dex/mod.rs, crates/precompiles/src/stablecoin_dex/orderbook.rs, crates/precompiles/src/storage/evm.rs, crates/precompiles/src/tip20/mod.rs, crates/precompiles/src/tip20_channel_reserve/mod.rs.

### T13

Mainnet: 1793718000. Scope: [TIP-1096](../tips/tip-1096.md), [TIP-1098](../tips/tip-1098.md), [TIP-1115](../tips/tip-1115.md), [TIP-1119](../tips/tip-1119.md), meta [TIP-1146](../tips/tip-1146.md). TIP-1146 §1 (recipient policy for bridged TIP-20 credits) changes zone-chain execution, not Tempo L1 block validity. The L1 parts of TIP-1096 and TIP-1098 are the T13 zone runtime bytecode and the zone verifier precompile (rows below).

| # | Change | Specified in | TIP |
|---|---|---|---|
| T13-1 | From T13 ZONE_VERIFIER is a live precompile and, unless genesis was already at T13+, the T13 ZonePortal/ZoneVerifier/ZoneMessenger runtime code is installed at block start (storage kept, skipped when code hash equal); before, T10 runtimes. | [04-state-and-genesis.md](04-state-and-genesis.md) | [TIP-1098](../tips/tip-1098.md) |
| T13-2 | From T13 pre-execution performs only the EIP-2935 parent-hash system call (Prague active, not genesis) and post-execution skips Ethereum's finish (no execution-request calls, empty requests); before, the inherited Ethereum pre/post-block calls incl. EIP-4788 beacon root ran. | [05-block-execution.md](05-block-execution.md) | [TIP-1119](../tips/tip-1119.md) |
| T13-3 | From T13, when fee-token resolution falls back and max_fee>0, it picks the first of [pathUSD, OUSD] whose fee-payer balance >= max_fee, else fails insufficient balance on the richest; before, always pathUSD (DEFAULT_FEE_TOKEN). | [06-transactions-and-fees.md](06-transactions-and-fees.md) | [TIP-1115](../tips/tip-1115.md) |
| T13-4 | From T13, portal initialization also writes token_enablement_cursor_initialized=true; before, the flag is left unset. | [precompiles/validator-config-and-zones.md](precompiles/validator-config-and-zones.md) | [TIP-1096](../tips/tip-1096.md) |

Reference implementation: crates/contracts/src/precompiles/mod.rs, crates/evm/src/block.rs, crates/evm/src/fee_manager.rs, crates/hardfork/src/lib.rs, crates/precompiles/src/zone_factory/portal.rs.

## Forks after T13

The reference implementation defines T14 and T15, but neither network schedules them at this commit, and they are outside this specification. Code paths gated on T14 or T15 behave as their pre-T14 branch in every block covered here. For example, a non-empty account extension is invalid ([04-state-and-genesis.md](04-state-and-genesis.md)), configurable-account signatures (type `0x05`) are invalid ([03-signatures.md](03-signatures.md)), and `0xAACC…` is not a precompile.
