# Open conflicts

Each entry is a place where Tempo's docs or TIPs disagree with the implementation at commit `37dc7833023927f49fd0aa81ae84dbd43790f70c`. Each chapter marks the conflict inline with an **Open conflict** marker. The chapters describe what the implementation does until a decision is recorded here. Every TIP conflict except C-FORKS-05 is decided: the spec follows the implementation, and [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939) amends the TIPs. The rest are open: C-FORKS-05 and the conflicts that touch only docs.tempo.xyz pages (tempoxyz/docs).

Groups:

- **A. Affects block validity, gas or state (67).** Mainnet blocks were produced by the implementation, so a spec that follows the doc would reject or mis-execute real blocks. The only open question is how to fix the TIP or doc.
- **B. Doc-only (18).** The doc is stale, incomplete or out of scope, and block validity is not affected.
- **C. Needs a decision (1).**

## C. Needs a decision

### C-FORKS-05 (also C-CONS-01)
<a id="c-forks-05"></a><a id="c-cons-01"></a>

TIP-1031 and docs upgrades/t4.mdx require consensus_context exactly from T4 and absent before; the code applies no fork gate to its presence (proposers always set it, consensus verification always requires it, execution never checks it by fork).

- Where: [01-chain-and-forks.md:420](01-chain-and-forks.md#L420), [02-encoding.md:207](02-encoding.md#L207), [07-consensus.md:115](07-consensus.md#L115)
- Recommendation: Mainnet blocks before T4 carry no consensus_context and blocks from T4 do, which matches TIP-1031, but the code enforces no fork gate. Recommended: the spec adopts TIP-1031's rule (absent before T4, required from T4), and the missing gate is filed as a code issue.
- Decision: _open_

## A. Affects block validity, gas or state

### C-FORKS-01
<a id="c-forks-01"></a>

docs guide/node/network-upgrades.mdx says T1B adds keychain precompile gas metering; the code meters the key-authorization precompile call only at T1 and T1A and makes it unmetered (intrinsic gas only) from T1B.

- Where: [01-chain-and-forks.md:293](01-chain-and-forks.md#L293)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: _open_

### C-FORKS-02 (also C-TXF-03, C-EXEC-03)
<a id="c-forks-02"></a><a id="c-txf-03"></a><a id="c-exec-03"></a>

TIP-1010 (protocolVersion T1) puts the 30,000,000 per-transaction gas cap at T1; the code applies it from T1A, with the EIP-7825 16,777,216 cap before.

- Where: [01-chain-and-forks.md:306](01-chain-and-forks.md#L306), [06-transactions-and-fees.md:66](06-transactions-and-fees.md#L66), [05-block-execution.md:209](05-block-execution.md#L209)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-FORKS-04
<a id="c-forks-04"></a>

TIP-1036 (T2 meta TIP) lists the FeeAMM reserved-liquidity check (§12) and the fee-refund spending-limit restore (§10) as T2 changes; the code gates both at T1C.

- Where: [01-chain-and-forks.md:338](01-chain-and-forks.md#L338), [precompiles/fee-manager.md:472](precompiles/fee-manager.md#L472), [precompiles/fee-manager.md:512](precompiles/fee-manager.md#L512), [precompiles/tip20.md:1006](precompiles/tip20.md#L1006)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-FORKS-03
<a id="c-forks-03"></a>

TIP-1036 §3 says the StablecoinDEX internal-balance swap pause check is gated at T2; the code gates it at T3 (matching TIP-1038 §4), and the placement and internal-debit pause checks at T4.

- Where: [01-chain-and-forks.md:396](01-chain-and-forks.md#L396), [precompiles/stablecoin-dex.md:743](precompiles/stablecoin-dex.md#L743)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-ENC-04
<a id="c-enc-04"></a>

TIP-1010 fixes the shared gas limit at 50,000,000 (`gas_limit / 10`) with no end date, while code requires `shared_gas_limit == 0` from T4.

- Where: [02-encoding.md:250](02-encoding.md#L250)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-ENC-05
<a id="c-enc-05"></a>

TIP-1011 says `expiry`/`limits` None encode as `0x80` and that a final `0x80` for `allowed_calls` and the three-item `TokenLimit` with `period = 0` MUST be accepted; the code's canonical decoder rejects any `0x80` that ends the list.

- Where: [02-encoding.md:611](02-encoding.md#L611)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-ENC-01
<a id="c-enc-01"></a>

docs spec-tempo-transaction.mdx and TIP-0001 define the signed form as the flat list `rlp([chain_id, key_type, key_id, expiry?, …, signature])`; code encodes and decodes the nested two-item list `rlp([rlp(KeyAuthorization), signature])`.

- Where: [02-encoding.md:624](02-encoding.md#L624)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-ENC-06
<a id="c-enc-06"></a>

docs spec-tempo-transaction.mdx say the key-authorization `chain_id` MUST equal the executing chain and "zero is not a wildcard", and TIP-0001 says "0 = valid on any chain", neither with a fork qualifier. Code treats 0 as a wildcard before T1C and requires an exact match from T1C.

- Where: [02-encoding.md:656](02-encoding.md#L656)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-ENC-03
<a id="c-enc-03"></a>

TIP-1046 §9 says T4 "allows blocks to omit" the empty subblocks-metadata transaction, implying an empty one stays acceptable; code rejects every system transaction from T4.

- Where: [02-encoding.md:735](02-encoding.md#L735)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-SIG-02
<a id="c-sig-02"></a>

docs and TIP-0001 say the WebAuthn challenge is the Base64URL "tx_hash"; the code compares it with the signing digest.

- Where: [03-signatures.md:257](03-signatures.md#L257)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-SIG-03
<a id="c-sig-03"></a>

TIP-0001 requires the UP flag and allows AT with CBOR parsing; the code accepts UP or UV and rejects AT and ED.

- Where: [03-signatures.md:259](03-signatures.md#L259)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-SIG-04
<a id="c-sig-04"></a>

TIP-0001 checks clientDataJSON by substring search; the code parses it as JSON with the rules above.

- Where: [03-signatures.md:283](03-signatures.md#L283)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-SIG-01 (also C-TXF-01)
<a id="c-sig-01"></a><a id="c-txf-01"></a>

docs and TIP-0001 charge WebAuthn calldata gas for clientDataJSON only; the code charges all of webauthn_data.

- Where: [03-signatures.md:588](03-signatures.md#L588), [06-transactions-and-fees.md:290](06-transactions-and-fees.md#L290)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-EXEC-05 (also C-PFW-03)
<a id="c-exec-05"></a><a id="c-pfw-03"></a>

TIP-1000 states a cold zero-to-nonzero SSTORE costs 252,100 gas at T1; the code charges 252,200 (100 static + 250,000 + 2,100 cold).

- Where: [05-block-execution.md:166](05-block-execution.md#L166), [precompiles/00-framework.md:616](precompiles/00-framework.md#L616)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-EXEC-06
<a id="c-exec-06"></a>

TIP-1060 states the T7 clean-creation residual is 5,000 gas in total (4,900 dynamic + 100 warm) and the 0→Y→0 restore refund is 4,900; the code charges 100 + 5,000 dynamic and refunds 5,000.

- Where: [05-block-execution.md:168](05-block-execution.md#L168)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-EXEC-04
<a id="c-exec-04"></a>

TIP-1000 says the nonzero→zero SSTORE clearing refund stays 15,000 gas; the code uses 4,800 (EIP-3529) at T0–T6 and 0 from T7.

- Where: [05-block-execution.md:196](05-block-execution.md#L196)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-EXEC-02
<a id="c-exec-02"></a>

TIP-1010 (and the fee specification's parameter table) give the block gas limit as a fixed 500,000,000; the code enforces only the Ethereum ±1/1024 per-block bound above.

- Where: [05-block-execution.md:298](05-block-execution.md#L298)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-EXEC-07
<a id="c-exec-07"></a>

TIP-1045 requires static-only payment calldata to satisfy the ABI encoding constraints of its signature and classifies malformed encodings as general; the code checks only the selector and exact length (e.g. an `address` word with non-zero high bytes still classifies as a payment).

- Where: [05-block-execution.md:663](05-block-execution.md#L663)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-EXEC-01
<a id="c-exec-01"></a>

TIP-1010 (invariant 5) and the payment-lane specification state that a block is invalid when non-payment gas exceeds `general_gas_limit` (or proposer-lane gas exceeds the non-shared limit, or subblock gas exceeds `shared_gas_limit`), and the payment-lane specification bounds post-lane inclusion by the shared budget; before T4 the code instead moves the overflowing transaction and all later ones into an unbounded `GasIncentive` section and accepts the block.

- Where: [05-block-execution.md:716](05-block-execution.md#L716)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-EXEC-08 (also C-VAL-06)
<a id="c-exec-08"></a><a id="c-val-06"></a>

TIP-1070 requires the committee update to be called "from the system address" following the EIP-4788 convention (conventionally `0xff…fe`); the code (and TIP-1119) call it from `0x0000…0000`, and the precompile rejects any other caller.

- Where: [05-block-execution.md:798](05-block-execution.md#L798), [precompiles/validator-config-and-zones.md:726](precompiles/validator-config-and-zones.md#L726)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-TXF-02
<a id="c-txf-02"></a>

TIP-1000 also charges +250,000 for each EIP-7702 authorization that moves an account from no delegation to delegation; the code charges no such amount (for type 4 and for 0x76 authorizations alike).

- Where: [06-transactions-and-fees.md:124](06-transactions-and-fees.md#L124)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-TXF-04
<a id="c-txf-04"></a>

TIP-1011 gives the scope slot count `1 + 3S + 3K + C + 2W` and frames the rounded overhead as optional and scope-only; from T4 the code uses `1 + 2S + 1 + 2K + P + C + 2W` and always adds the 5,000 base, also when `allowed_calls` is absent.

- Where: [06-transactions-and-fees.md:337](06-transactions-and-fees.md#L337)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-TXF-08
<a id="c-txf-08"></a>

TIP-1000 charges the 250,000 account-creation gas to Tempo transactions "with any `nonce_key` and `nonce == 0`"; the code charges an expiring-nonce transaction (`nonce_key == uint256.max`) only `EXPIRING_NONCE_GAS`.

- Where: [06-transactions-and-fees.md:356](06-transactions-and-fees.md#L356)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-TXF-05 (also C-KEY-08)
<a id="c-txf-05"></a><a id="c-key-08"></a>

TIP-1009 keys replay protection on the transaction hash (invariant E1: "a transaction hash can never be executed twice"); from T1B the code keys it on `keccak256(encode_for_signing || sender)`, and TIP-1009 was not amended.

- Where: [06-transactions-and-fees.md:434](06-transactions-and-fees.md#L434), [precompiles/account-keychain.md:1192](precompiles/account-keychain.md#L1192)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-TXF-07
<a id="c-txf-07"></a>

the fee specification gives the refund as `(gas_limit - gas_used) * gas_price`; the code refunds `ceil(gas_limit*price/10^12) - ceil(gas_used*price/10^12)`, which can differ by one base unit.

- Where: [06-transactions-and-fees.md:735](06-transactions-and-fees.md#L735)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: _open_

### C-CONS-02 (also C-VAL-05)
<a id="c-cons-02"></a><a id="c-val-05"></a>

TIP-1017 says the consensus layer reads ValidatorConfig V1 until ValidatorConfigV2 is initialized, but the implementation always reads ValidatorConfigV2.

- Where: [07-consensus.md:484](07-consensus.md#L484), [precompiles/validator-config-and-zones.md:659](precompiles/validator-config-and-zones.md#L659)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-PFW-01
<a id="c-pfw-01"></a>

TIP-1100 (and docs upgrades/t11) require the input charge on *every* Tempo precompile call; the code reverts DELEGATECALL/CALLCODE with no input charge.

- Where: [precompiles/00-framework.md:171](precompiles/00-framework.md#L171)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-PFW-02
<a id="c-pfw-02"></a>

TIP-1046 §8 says T4 removes the SLOAD for "the first packed slot" of a packed-struct store; the code removes it for every packed slot run of the struct.

- Where: [precompiles/00-framework.md:420](precompiles/00-framework.md#L420)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-PFW-04
<a id="c-pfw-04"></a>

TIP-1000 (invariant 4) requires storage clearing to keep its refund for every SSTORE, including precompile-created state; the code records no refund for native-precompile SSTOREs before T4.

- Where: [precompiles/00-framework.md:642](precompiles/00-framework.md#L642)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-KEY-04
<a id="c-key-04"></a>

TIP-1011 stores periodic-limit metadata in a separate `spending_limit_period_state` mapping; the code extends the `spending_limits` row (`s1`).

- Where: [precompiles/account-keychain.md:302](precompiles/account-keychain.md#L302)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-KEY-06
<a id="c-key-06"></a>

TIP-1011 specifies a flat 7-argument `authorizeKey` (selector `0x203e2736`) and a `getRemainingLimit` that returns `(uint256, uint64)`; the code uses the `KeyRestrictions` tuple form (`0x980a6025`), removes `getRemainingLimit` at T3 and adds `getRemainingLimitWithPeriod`.

- Where: [precompiles/account-keychain.md:350](precompiles/account-keychain.md#L350)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-KEY-02
<a id="c-key-02"></a>

AccountKeychain.mdx says an unsupported `signatureType` reverts with `InvalidSignatureType`; from T11 the code reverts with empty data for 3 and for values of 4 or more.

- Where: [precompiles/account-keychain.md:413](precompiles/account-keychain.md#L413)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: _open_

### C-KEY-03
<a id="c-key-03"></a>

AccountKeychain.mdx says recipient-constrained selector rules are validated before any state is written; the code writes the key word (and the scope-tree reset) before validating scopes, and before T4 validates each scope while inserting it.

- Where: [precompiles/account-keychain.md:557](precompiles/account-keychain.md#L557)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: _open_

### C-KEY-07
<a id="c-key-07"></a>

TIP-1053 says access keys MUST NOT burn witnesses; from T6 the code lets an admin access key burn them (as do the docs).

- Where: [precompiles/account-keychain.md:590](precompiles/account-keychain.md#L590)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-KEY-05
<a id="c-key-05"></a>

TIP-1011 says `removeAllowedCalls` only disables the target scope and that prior selector rows may remain in state; the code removes the target from the set and deletes every selector and recipient row under it.

- Where: [precompiles/account-keychain.md:767](precompiles/account-keychain.md#L767)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-KEY-09
<a id="c-key-09"></a>

TIP-1009 stores `ptr + 1` unbounded and indexes with `ptr % CAPACITY`; the code stores the wrapped pointer (as TIP-1093 states).

- Where: [precompiles/account-keychain.md:1190](precompiles/account-keychain.md#L1190)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-KEY-11
<a id="c-key-11"></a>

TIP-1060 describes the balance as `mapping(address => uint256 packed_state)`; the code stores it at slot `uint256(bytes32(account))` with no mapping hash.

- Where: [precompiles/account-keychain.md:1345](precompiles/account-keychain.md#L1345)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-KEY-12
<a id="c-key-12"></a>

TIP-1060 describes the transient state as a mapping of a struct `{uint64 budget; uint8 mode; uint64 pending_refunds}`; the code uses the direct slot and the bit layout above.

- Where: [precompiles/account-keychain.md:1361](precompiles/account-keychain.md#L1361)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-FEE-06
<a id="c-fee-06"></a>

TIP-1042 reads both tokens' policy ids before evaluating any authorization; code finishes the userToken checks before reading the validatorToken policy.

- Where: [precompiles/fee-manager.md:261](precompiles/fee-manager.md#L261)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-FEE-07
<a id="c-fee-07"></a>

docs say the payout-side checks apply to each nonzero payout; code performs both transfers, and their checks, even for a zero amount.

- Where: [precompiles/fee-manager.md:304](precompiles/fee-manager.md#L304)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: _open_

### C-FEE-03
<a id="c-fee-03"></a>

the Fee AMM doc says pre-collection checks liquidity before collecting; code collects first, then checks.

- Where: [precompiles/fee-manager.md:414](precompiles/fee-manager.md#L414)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: _open_

### C-FEE-01
<a id="c-fee-01"></a>

spec-fee.mdx says the pre-collection reserves max_fee of liquidity; code reserves floor(maxAmount × 0.997) validator-token units (nested floor on leg 2), and only from T1C.

- Where: [precompiles/fee-manager.md:470](precompiles/fee-manager.md#L470)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: _open_

### C-DEX-01
<a id="c-dex-01"></a>

docs exchange/spec.mdx says `pairKey` is order-independent; the implementation hashes `tokenA || tokenB` in argument order and keys all book storage by `keccak256(base || quote)`.

- Where: [precompiles/stablecoin-dex.md:180](precompiles/stablecoin-dex.md#L180)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: _open_

### C-DEX-04
<a id="c-dex-04"></a>

TIP-1087 requires a V0/V1→V2 flip rewrite to assert `bookKeys[bookKeyIdx-1] == bookKey` (and a V2 rewrite to preserve the stored `bookIndex`); the implementation takes `bookIndex` from the owning orderbook's `bookId` with no assertion and no extra read.

- Where: [precompiles/stablecoin-dex.md:392](precompiles/stablecoin-dex.md#L392)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-DEX-05
<a id="c-dex-05"></a>

TIP-1062 says a version-1 flip order that flips MUST remain version 1; the implementation rewrites it as version 2 once its book has an index (as TIP-1087 specifies).

- Where: [precompiles/stablecoin-dex.md:394](precompiles/stablecoin-dex.md#L394)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-DEX-03
<a id="c-dex-03"></a>

TIP-1056 requires a flip rewrite to write only the order-record slots whose contents change (under a "TIP-1055" layout that does not exist); at T5–T7 the implementation stores all six legacy slots, including unchanged ones.

- Where: [precompiles/stablecoin-dex.md:948](precompiles/stablecoin-dex.md#L948)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-T20-06
<a id="c-t20-06"></a>

TIP-1004 orders the nonce increment before signature validation; the step order above (validation first) is what produced mainnet gas.

- Where: [precompiles/tip20.md:609](precompiles/tip20.md#L609)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-T20-05
<a id="c-t20-05"></a>

the TIP-20 docs and TIP-1035 describe `system_transfer_from(from, to, amount)`; the hook takes no recipient and always credits the calling precompile.

- Where: [precompiles/tip20.md:978](precompiles/tip20.md#L978)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-T20-09
<a id="c-t20-09"></a>

TIP-1034 requires an interface identical to its reference file and on-chain storage of only `ChannelState`; from T7 the code adds the `storageCredits` view and the per-payer credit mapping (§11.3, §11.9).

- Where: [precompiles/tip20.md:1251](precompiles/tip20.md#L1251)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-T20-08
<a id="c-t20-08"></a>

TIP-1034 declares bits 224..255 of the packed state reserved and always zero; from T12 byte 28 holds the logical-receive-policy-sender flag.

- Where: [precompiles/tip20.md:1286](precompiles/tip20.md#L1286)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-T20-10
<a id="c-t20-10"></a>

TIP-1095 says its behaviour activates for channels opened at or after T12; the code applies the T12 authorization and delivery path to all channels from T12 and keeps only the receive-policy sender per channel.

- Where: [precompiles/tip20.md:1499](precompiles/tip20.md#L1499)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-T403-01
<a id="c-t403-01"></a>

TIP-1028 specifies two mappings (`addressReceiveConfig`, `addressRecoveryAuthority`) and a bit-level config packing that differ from this layout.

- Where: [precompiles/tip403.md:176](precompiles/tip403.md#L176)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-T403-04
<a id="c-t403-04"></a>

the docs state that policy 0 rejects every address and TIP-1015 that unknown ids revert, but from T6 the guard address is authorized by every policy.

- Where: [precompiles/tip403.md:262](precompiles/tip403.md#L262)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-T403-09
<a id="c-t403-09"></a>

TIP-1015's pseudo-code and cost claim ("1 keccak + 2 SLOADs") do not match the storage-access sequence above.

- Where: [precompiles/tip403.md:264](precompiles/tip403.md#L264)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-T403-06
<a id="c-t403-06"></a>

the docs list `PolicyCreated` and `PolicyAdminUpdated` before the membership events.

- Where: [precompiles/tip403.md:373](precompiles/tip403.md#L373)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: _open_

### C-T403-10
<a id="c-t403-10"></a>

the docs say "precompile" recovery addresses must be rejected; the code's set excludes Ethereum precompiles.

- Where: [precompiles/tip403.md:483](precompiles/tip403.md#L483)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: _open_

### C-T403-02
<a id="c-t403-02"></a>

TIP-1028 declares `uint64 public nonce = 1` (initialized to 1).

- Where: [precompiles/tip403.md:612](precompiles/tip403.md#L612)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-T403-07
<a id="c-t403-07"></a>

TIP-1028 says a reroute to an unresolvable virtual `to` reverts `InvalidClaimAddress()`; the code reverts `VirtualAddressUnregistered()`.

- Where: [precompiles/tip403.md:747](precompiles/tip403.md#L747)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-T403-08
<a id="c-t403-08"></a>

TIP-1028 says the release emits `Transfer(GUARD, to)` followed by `ReceiptClaimed`; for a virtual `to` a second-hop `Transfer` sits between them.

- Where: [precompiles/tip403.md:749](precompiles/tip403.md#L749)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-T403-03
<a id="c-t403-03"></a>

TIP-1022 gives the slot as `keccak256(abi.encode(masterId, REGISTRY_SLOT))`, which right-pads the `bytes4` key; the code left-pads it (precompiles/00-framework.md §6.5).

- Where: [precompiles/tip403.md:825](precompiles/tip403.md#L825)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-VAL-01
<a id="c-val-01"></a>

TIP-1017 orders the `Validator` struct `…, egress, index, addedAtHeight, deactivatedAtHeight, feeRecipient`; the code returns `…, egress, feeRecipient, index, addedAtHeight, deactivatedAtHeight`.

- Where: [precompiles/validator-config-and-zones.md:278](precompiles/validator-config-and-zones.md#L278)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-VAL-02
<a id="c-val-02"></a>

TIP-1017 names the rotation-epoch functions `getNextFullDkgCeremony()` / `setNextFullDkgCeremony(uint64)` (selectors `0x281a69ec` / `0xc3576d46`); the code exposes only `getNextNetworkIdentityRotationEpoch()` / `setNetworkIdentityRotationEpoch(uint64)`, so the TIP selectors revert `UnknownFunctionSelector` on V2.

- Where: [precompiles/validator-config-and-zones.md:280](precompiles/validator-config-and-zones.md#L280)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-VAL-03
<a id="c-val-03"></a>

TIP-1017 says `initializeIfMigrated` "can be called immediately when the V1 validator count is zero"; the code reverts `EmptyV1ValidatorSet()` (or `MigrationNotComplete()`) when V1 is empty.

- Where: [precompiles/validator-config-and-zones.md:625](precompiles/validator-config-and-zones.md#L625)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-VAL-04
<a id="c-val-04"></a>

TIP-1017 says an invalid V1 entry is always "marked as processed … so global completion is not blocked"; the code reverts `AddressAlreadyHasValidator()` when the V1 address belongs to an active V2 record and reverts `NotIpPort` when the V1 inbound address does not parse, leaving that index unprocessed.

- Where: [precompiles/validator-config-and-zones.md:627](precompiles/validator-config-and-zones.md#L627)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-VAL-07
<a id="c-val-07"></a>

TIP-1091 (and its reference ZoneFactory.sol) reject only addresses that appear in both `allowedAccounts` and `zoneGateways` before T11; the code also rejects, before T11, any sequencer that appears in `allowedAccounts` or `zoneGateways`.

- Where: [precompiles/validator-config-and-zones.md:940](precompiles/validator-config-and-zones.md#L940)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-VAL-09
<a id="c-val-09"></a>

the TIP-1091 reference `ZoneFactory.sol` checks `NotOwner` before anything else (and says the owner is set "by the T9 activation"); the code deducts 15,000,000 gas before the owner check, so failing calls also consume it or halt out of gas, and the owner is installed at T10.

- Where: [precompiles/validator-config-and-zones.md:942](precompiles/validator-config-and-zones.md#L942)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-VAL-08
<a id="c-val-08"></a>

TIP-1091 (step 5) and its reference `ZoneFactory.sol` say the factory calls the portal's factory-only initializer; the code writes portal storage and emits the portal's logs natively without any call frame (different gas, no inner call).

- Where: [precompiles/validator-config-and-zones.md:1000](precompiles/validator-config-and-zones.md#L1000)
- Recommendation: Follow the implementation (it produced mainnet's blocks); amend the TIP or doc.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

## B. Doc-only

### C-ENC-02
<a id="c-enc-02"></a>

docs blockspace/overview.mdx lists "start-of-block system transaction(s)" as the first section of every block body, but code defines no start-of-block system transaction in any fork (only the pre-T4 end-of-block transaction of §6).

- Where: [02-encoding.md:357](02-encoding.md#L357)
- Recommendation: Follow the implementation; fix the doc. No effect on block validity.
- Decision: _open_

### C-TXF-06
<a id="c-txf-06"></a>

TIP-1106 is marked `status: Draft` with `protocolVersion: TBD`, but the code activates it at T12.

- Where: [06-transactions-and-fees.md:436](06-transactions-and-fees.md#L436)
- Recommendation: Follow the implementation; fix the doc. No effect on block validity.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-CONS-03
<a id="c-cons-03"></a>

the docs say blocks come about every 600 ms from a 500 ms builder loop, but the implementation uses an adaptive estimator targeting 550 ms with a 50 ms network budget.

- Where: [07-consensus.md:506](07-consensus.md#L506)
- Recommendation: Follow the implementation; fix the doc. No effect on block validity.
- Decision: _open_

### C-CONS-04
<a id="c-cons-04"></a>

the consensus docs page links commonware-consensus 0.0.65, but the implementation and this chapter use commonware 2026.9.0.

- Where: [07-consensus.md:564](07-consensus.md#L564)
- Recommendation: Follow the implementation; fix the doc. No effect on block validity.
- Decision: _open_

### C-P2P-01
<a id="c-p2p-01"></a>

TIP-1017 says the ed25519 key is used for signing all consensus p2p messages; the code uses it only for transport authentication and DKG artifacts, while votes and certificates carry BLS threshold signatures.

- Where: [08-p2p-and-sync.md:69](08-p2p-and-sync.md#L69), [08-p2p-and-sync.md:829](08-p2p-and-sync.md#L829)
- Recommendation: Follow the implementation; fix the doc. No effect on block validity.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).

### C-P2P-02
<a id="c-p2p-02"></a>

docs protocol/rpc/index.mdx says `consensus_subscribe` emits notarized, finalized and nullified events and `consensus_getLatest` returns the latest notarized block; the code emits only finalized events and always returns `notarized: null`.

- Where: [08-p2p-and-sync.md:601](08-p2p-and-sync.md#L601), [08-p2p-and-sync.md:831](08-p2p-and-sync.md#L831)
- Recommendation: Follow the implementation; fix the doc. No effect on block validity.
- Decision: _open_

### C-KEY-01
<a id="c-key-01"></a>

AccountKeychain.mdx puts `transactionKey` in transient slot 0; the code uses transient slot 4 (and slot 5 for `tx_origin`).

- Where: [precompiles/account-keychain.md:219](precompiles/account-keychain.md#L219)
- Recommendation: Follow the implementation; fix the doc. No effect on block validity.
- Decision: _open_

### C-KEY-10
<a id="c-key-10"></a>

spec-tempo-transaction.mdx gives the 2D nonce storage key as `keccak256(abi.encode(account_address, nonce_key))`; the code uses the nested mapping at slot 0 above.

- Where: [precompiles/account-keychain.md:1111](precompiles/account-keychain.md#L1111)
- Recommendation: Follow the implementation; fix the doc. No effect on block validity.
- Decision: _open_

### C-FEE-05
<a id="c-fee-05"></a>

docs state the unchanged-token no-op unconditionally; code applies it only from T3.

- Where: [precompiles/fee-manager.md:196](precompiles/fee-manager.md#L196)
- Recommendation: Follow the implementation; fix the doc. No effect on block validity.
- Decision: _open_

### C-FEE-04
<a id="c-fee-04"></a>

docs state the T8 mint/burn/pre-collection authorization rules unconditionally; code applies them only from T8.

- Where: [precompiles/fee-manager.md:259](precompiles/fee-manager.md#L259), [precompiles/fee-manager.md:410](precompiles/fee-manager.md#L410)
- Recommendation: Follow the implementation; fix the doc. No effect on block validity.
- Decision: _open_

### C-DEX-06
<a id="c-dex-06"></a>

docs exchange/spec.mdx states T2/T4/T5/T12 behaviour (tick spacing in `tickToPrice`/`priceToTick`, the recipient check in `cancelStaleOrder`, same-id flips with `OrderFlipped`/`FlipFailed` and `flipTick == tick`, quote/swap parity and a traversed `totalLiquidity`) as unconditional rules; the implementation applies each only from its fork.

- Where: [precompiles/stablecoin-dex.md:44](precompiles/stablecoin-dex.md#L44)
- Recommendation: Follow the implementation; fix the doc. No effect on block validity.
- Decision: _open_

### C-T20-01
<a id="c-t20-01"></a>

the TIP-20 docs' factory section writes TIP20_PREFIX as a 13-byte value.

- Where: [precompiles/tip20.md:69](precompiles/tip20.md#L69)
- Recommendation: Follow the implementation; fix the doc. No effect on block validity.
- Decision: _open_

### C-T20-04
<a id="c-t20-04"></a>

the TIP-20 docs present an interface without the reward functions and events that the code dispatches at every fork.

- Where: [precompiles/tip20.md:283](precompiles/tip20.md#L283)
- Recommendation: Follow the implementation; fix the doc. No effect on block validity.
- Decision: _open_

### C-T20-03
<a id="c-t20-03"></a>

the TIP-20 docs' factory interface omits `AddressNotReserved` and `TokenAlreadyExists`.

- Where: [precompiles/tip20.md:1079](precompiles/tip20.md#L1079)
- Recommendation: Follow the implementation; fix the doc. No effect on block validity.
- Decision: _open_

### C-T20-02
<a id="c-t20-02"></a>

the docs' `AddressReserved` comment says "lowerBytes < 1000"; the reserved range is ids `< 1024`.

- Where: [precompiles/tip20.md:1097](precompiles/tip20.md#L1097)
- Recommendation: Follow the implementation; fix the doc. No effect on block validity.
- Decision: _open_

### C-T403-05
<a id="c-t403-05"></a>

docs say an unknown policy id reverts with `PolicyNotFound`, without the T2 boundary.

- Where: [precompiles/tip403.md:327](precompiles/tip403.md#L327)
- Recommendation: Follow the implementation; fix the doc. No effect on block validity.
- Decision: _open_

### C-T403-11
<a id="c-t403-11"></a>

the docs describe token creation as registering a TIP-403 binding without saying this starts at T9.

- Where: [precompiles/tip403.md:529](precompiles/tip403.md#L529)
- Recommendation: Follow the implementation; fix the doc. No effect on block validity.
- Decision: _open_

### C-VAL-10
<a id="c-val-10"></a>

TIP-1098 leaves PCR0–2 as placeholders and says the production verifier "has no approved tuple and MUST return false", and docs zones/proving.mdx says the measurements are unset so Nitro proofs are rejected; the code approves the tuple above from T13.

- Where: [precompiles/validator-config-and-zones.md:1174](precompiles/validator-config-and-zones.md#L1174)
- Recommendation: Follow the implementation; fix the doc. No effect on block validity.
- Decision: follow the implementation; TIP amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939).
