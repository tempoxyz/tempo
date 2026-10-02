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
hashes and vault/fee bindings. The generated `nativeEarnManifest` was inserted
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
