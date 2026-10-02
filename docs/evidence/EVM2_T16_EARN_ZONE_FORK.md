# T16 native Earn and Zone fork smoke test

The [checked record](evm2-t16-native-earn-zone-smoke.json) captures one disposable
Tempo L1 and Zone devnet. Tempo source `2ed378214` used the binary SHA-256 in
the record; Zones source `c494eca38` used the separately recorded binary. The
L1 began with T15 at Unix time `1790921148` and T16 at `1790922288`. Its
pre-fork EarnVault had 1,000,000 EarnShare and 1,000,000 pathUSD of venue
backing. A pre-fork Zone deposit held another 100,000 pathUSD in its L1 portal,
with 100,000 private supply. The Zone was created before L1 T16 and kept the
same datadir and genesis block across the L1 boundary.

The legacy EarnFactory does not index all deployed vaults. For this devnet,
the stack was reconciled at L1 block 439 using
[`build-native-earn-manifest.py`](../../scripts/native-payments/build-native-earn-manifest.py).
Its [EIP-1186 account and storage proofs](evm2-t16-native-earn-manifest-proof.json)
were verified against that block's state root, including the manifest's code
hashes, vault/fee bindings, and the vault's EarnShare issuer role. The six
account proofs and nine storage proofs bind that role to the same manifest
vault. The generated `nativeEarnManifest` was inserted
into the local genesis configuration and the node restarted before T16. This
configuration step is a devnet procedure; a production activation needs a
published, fixed manifest and commitment before the fork. These are state
proofs, not a cryptographic Zone execution proof.

At L1 block 1171 the EarnVault still had its legacy proxy code hash. Block
1172, timestamp `1790922288`, replaced the vault and EarnFees clone code with
the pinned dispatcher hash while retaining both accounts' storage. EarnShare
supply, vault assets, venue assets, and portal backing were identical at
blocks 1171 and 1172. A restarted Zone batch submitter initially failed
because its older Tempo SDK could not parse the L1's new `T16` label.
[The Zones fix](https://github.com/tempoxyz/zones/pull/1637) reads T13 activation
from the fork schedule and resumed queued batches on the same datadir. The
Zone's own T15 was then scheduled for Unix time `1790922875`, after which
signed private transfers succeeded.

The isolated post-fork Earn transactions were:

| Call | L1 block | Receipt | Payment gas | General gas | Accounting result |
| --- | ---: | --- | ---: | ---: | --- |
| `spendFromEarn(400000, …)` | 1193 | success | 222,094 | 0 | shares and venue assets 1,000,000 → 600,000; recipient +400,000 |
| `deposit(200000, 200000)` | 1230 | success | 262,432 | 0 | shares and venue assets 600,000 → 800,000 |
| venue yield transfer of 100,000 | 1250 | success | 39,942 | 0 | assets 800,000 → 900,000; shares stay 800,000 |
| `redeem(100000, 112500)` | 1267 | success | 218,144 | 0 | shares 800,000 → 700,000; assets 900,000 → 787,500 |
| `redeem(10000, 1000000)` | 1285 | revert | 457,558 | 0 | shares and custody unchanged |

The spend trace contains a native vault delegate frame, a nested native
EarnFees delegate frame, TIP-20 burn/transfer calls, and the engine and venue
exit. The metric samples in the record match each single-transaction block by
timestamp and exact receipt gas. A post-fork Zone private transfer in L2 block
1418 moved another 10,000 units: the sender held 80,000, the recipient 20,000,
private supply remained 100,000, and L1 portal backing remained 100,000. The
batch covering that transfer settled in L1 block 2554 with 98,842 payment gas
and zero general gas. It used explicit NoProof mode; this run does **not**
demonstrate Nitro execution-proof validity or sustained mixed-workload
throughput.

A separate contract at `0x8464135c8F25Da09e49BC8782676a84730C318bC` had
the exact dispatcher runtime hash but no system registration. Its
`spendFromEarn` call reverted with no child calls in L1 block 3981. That block
also included a real Earn redemption: the matched metric charged 1,000,000
general gas to the forged call and 218,120 payment gas to the registered
payment. Matching bytecode and selector alone therefore did not grant payment
capacity in this run.

The [30-minute mixed-load record](evm2-t16-mixed-load-summary.json) checks
[all 450 cycle receipts](evm2-t16-mixed-load-30m.jsonl.gz) against both chains:
900 Earn deposits/redemptions and 450 private Zone transfers completed in
1,800 seconds. Eighteen custody checkpoints and the final state held 700,000
EarnShare, 787,500 vault/venue assets, and 100,000 portal backing. The
[sampled L1 lane counters](evm2-t16-mixed-load-lane-metrics.jsonl.gz) match all
900 Earn blocks. In 898 blocks, general gas was zero. Two blocks also contained
separate general-lane transactions: a forged-dispatcher deployment and its
rejected call. Their payment gas exactly covered the Earn receipt gas, with
no payment deficit. The last private transfer was in Zone block 4353; the
sequencer submitted the batch through block 4360 to L1, where settlement
receipt `0x21baa9efd6ac2817bf2f659cca8c659e282b1ac3cb29d55e8ea1454f04576038`
succeeded in L1 block 5434 with 98,842 gas. This is a serial workload at
0.25 mixed cycles per second, not a capacity benchmark. Settlement used
NoProof mode, so it does not establish cryptographic execution-proof validity.

The raw load and metric files are gzip-compressed JSONL. Recheck their
receipts, custody, and lane samples while this devnet is available with:

```bash
python3 scripts/native-payments/summarize-t16-mixed-load.py \
  --load docs/evidence/evm2-t16-mixed-load-30m.jsonl.gz \
  --metrics docs/evidence/evm2-t16-mixed-load-lane-metrics.jsonl.gz \
  --output /tmp/evm2-t16-mixed-load-rechecked.json
```

After review added live issuer-role checks and charged registry hashing, the
L1 was copied and unwound to the common pre-fork block 1171. The
[reviewed-binary record](evm2-t16-reviewed-fork.json) pins the new binary hash
and the unchanged block 1171 hash. The reviewed binary activated T16 in its
new block 1172: vault and fee code became the dispatcher, with 1,000,000
EarnShare and venue/vault assets unchanged. On that branch, Earn deposit,
redemption, and spending, plus a new Zone portal deposit and its settlement,
all had matched payment-gas samples with zero general gas. The private Zone
transfer moved 1,000 of 10,000 private pathUSD from sender to recipient;
portal backing and private supply remained 10,000. The batch containing it
settled on L1 in receipt
`0x90a55796e214a661fc65d07df519e5ae52650ae77013703d09ad48b0fd88fd80`.
This branch also uses NoProof settlement. With the reviewed L1 and Zone nodes
available, `python3 scripts/native-payments/check-t16-reviewed.py` rechecks
the fork, receipts, custody, and lane samples. Set the two disposable
`EVM2_ZONE_*_KEY` variables to include authenticated private balances and
supply; that full check passed on this run.

The Zone binary was then rebuilt against Tempo revision
`746d98bfe35e7e965509b6d7772d23dc41dc7993` and restarted on the same
Zone datadir. It resumed L1 ingestion and settlement. A recipient with 1,000
private units attempted to send all 1,000; the transaction reverted with
`InsufficientBalance()` after its 1-unit private fee, and no transfer occurred.
Sending the remaining 998 succeeded, leaving 10,000 with the sender and zero
with the recipient while private supply and portal backing stayed 10,000. The
batch through Zone block 2200 settled on L1 in receipt
`0x4bfe04db2f936fed8b7249e1986d8e70e236ec9f4ec699a6187917e0916e7b8a`.
The reviewed record and checker include both receipts, the revert data,
authenticated balances, and that settlement.

While these isolated devnets are available, rerun the public receipt and state
checker from the Tempo checkout:

```bash
python3 scripts/native-payments/check-t16-combined.py
cargo run --quiet -p tempo-evm --example verify_native_earn_proofs -- \
  docs/evidence/evm2-t16-native-earn-manifest-proof.json
```

For private Zone balance verification, set `EVM2_ZONE_SENDER_KEY` and
`EVM2_ZONE_RECIPIENT_KEY` to the two disposable devnet signers before running
the checker. It derives short-lived authenticated RPC tokens locally and reads
the historical L2 state at block 1418. The checked run verified 12 L1
accounting snapshots, six Earn receipts, the fork code transition, two Zone
private transfers, portal backing, and the zero-general-lane settlement sample.
