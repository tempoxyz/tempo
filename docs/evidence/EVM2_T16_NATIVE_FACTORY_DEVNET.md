# T16 native Earn factory devnet

A fresh Tempo chain activated T16 at timestamp `1790936016`, between blocks
`0x6e` and `0x6f`. The [saved genesis](evm2-t16-native-factory-genesis.json.gz)
has hash `0x03df7ae1df1c861973b6fdced2e5d05e73b9c6d58bf09c26349e4d2193e9f993`.
It preloads the exact factory, vault and fee implementations, engine, and
ERC-4626 venue code; the venue starts with zero supply and the engine is
unbound. The scheduled factory identity and one engine approval were verified
at the fork. The registry was empty in block `0x6e` and had its `0xef` system
marker and seven factory configuration slots in block `0x6f`.

The Tempo release binary has SHA-256
`b94e5b484548e0062448a95fd3f94d9c45fc005534cc9bb54768bb84955d765e`
and was built from branch revision `e12c38fc5c0a2a4920c35a8e93648355335529d5`.
Its version string still embeds the earlier build metadata `5bb038c`; use the
binary hash and source revision to identify the tested executable. The node
used a one-second dev block interval and chain ID 1337.

After activation, a real transaction called the scheduled
`NativeEarnFactory.deploy` using the [exact calldata](evm2-t16-native-factory-deploy-calldata.txt).
It created EarnShare `0x20c0000000000000000000008add4f9444dc5350`, vault
`0xdc17c27ae8be831af07cc38c02930007060020f4`, and fee account
`0xb8eebbf3c9b44ffb0b010d57916044eaf82de1e4`. Both accounts received
dispatcher code hash `0x502aeca502056d259b30dcce44d73a0bfbbcca8fd0aaec28647e53978c2ee1b4`;
the vault has the live EarnShare issuer role. Engine binding was a separate
successful transaction. Factory deployment used the general lane as an
administrative transaction; subsequent registered vault payments were admitted
to the payment lane.

| Operation | Block | Receipt | Payment gas | General gas |
| --- | ---: | --- | ---: | ---: |
| Deposit 1,000,000 assets | `0xbd` | success | 1,758,836 | 0 |
| Spend 200,000 shares | `0x113` | success | 474,932 | 0 |
| Redeem 100,000 shares | `0x152` | success | 221,526 | 0 |
| Redeem with impossible minimum | `0x17c` | revert | 460,940 | 0 |

Each table entry has a receipt, a single-transaction block whose gas used
equals the receipt, and 8–9 saved payload metric samples matching that gas
exactly. A separate successful 300,000-share redemption occurred in block
`0x122`; its lane metric was not sampled. The raw samples and all ten receipts
are in the [evidence bundle](evm2-t16-native-factory-devnet.json). Approvals,
engine binding, and factory creation are accounted for separately.

The initial deposit left venue supply, venue assets, engine assets, and
EarnShare supply at 1,000,000. A 100,000-asset venue donation raised active NAV
to 1,100,000 without minting shares. Spending 200,000 shares paid 220,000
assets to the recipient. After both redemptions, EarnShare supply was 400,000
and vault backing was 440,000; `isAccountingAligned()` returned true. The
failed redemption left supply, backing, and recipient balance identical on
the blocks before and after it.

At block `0x327`, `eth_getProof` returned [six account and 38 storage
proofs](evm2-t16-native-factory-proofs.json.gz) under state root
`0x9c03245ade39347d1839baff004faaf4baedeafbe68be17ea382ed3217ccd6eb`.
The verifier checks Merkle inclusion, registry identities and engine approval,
vault/fee bindings, dispatcher code hashes, and the EarnShare issuer role.
Changing the saved issuer-role value causes proof verification to fail.

The same binary also replayed the original legacy Earn chain from pre-fork
block `1171` (hash `0x49df419c51bdcbb02d31b7a452e609ab4ff392f253ed34b5ab95947bfc79393b`).
At block `1172`, T16 replaced the proxy runtime, added its engine approval,
and retained 1,000,000 EarnShare and 1,000,000 venue-backed assets. A later
100,000-asset deposit raised both to 1,100,000. Its receipt used 263,614
payment gas and zero general gas in eight saved metric samples. The [legacy
replay record](evm2-t16-native-factory-legacy-replay.json) includes the fork
hashes, receipt, and before/after values. This exercises the new approval
check against an existing funded vault as well as the fresh factory path.

Governor revocation was also exercised against the funded factory vault in a
separate [record](evm2-t16-native-factory-revocation.json). The engine approval
slot changed from the pinned code hash to zero at block `0x7a8`. A valid
`deposit(1000,900)` reverted at block `0x7b0`; EarnShare supply and backing
stayed at 402,727 and 443,000. Reapproval restored the pinned hash at block
`0x7b8`. The identical call then succeeded at block `0x7bc`, minting 909
EarnShare against 1,000 assets. Fifteen [captured metric
samples](evm2-t16-native-factory-revocation-lanes.json.gz) for that successful
transaction charged its 265,890 gas to the payment lane and zero to general.
The revoked attempt exhausted its 3,000,000 gas limit and was not admitted as
a verified Earn payment. This tests suspension and restoration; it does not
establish a zero-general-gas claim for invalid or revoked calls.

A fresh chain using the same genesis and Tempo revision `c82e6f741` exercised
the registration event added after the original run. Its release binary SHA-256
is `55009b21d8fe970e9330b1b972e6b5e5df9d302677ca4c377fc41110e98dd89b`.
T16 activated in block `0x1` because its scheduled timestamp had passed when
this chain started. The factory deployed a stack in block `0x26`; the
[receipt](evm2-t16-native-registration-event.json) contains one
`NativeEarnRegistered` log from the registry, with the vault, asset, EarnShare,
fees, engine, and pinned engine code hash. After engine binding and approval,
a 1,000,000-asset deposit succeeded in block `0x6e`. EarnShare supply and vault
backing both reached 1,000,000. Sixteen [metric
samples](evm2-t16-native-registration-event-lanes.json.gz) charged all
1,758,836 gas to payment and zero to general. The checker validates the saved
receipt, log topics and data, dispatcher code, balances, and live archived
blocks when `--event-rpc-url` is supplied.

The evidence can be checked offline, then against the still-running devnet:

```sh
python3 scripts/native-payments/check-t16-factory-devnet.py
python3 scripts/native-payments/check-t16-factory-devnet.py --rpc-url http://127.0.0.1:56545 --legacy-rpc-url http://127.0.0.1:58545
python3 scripts/native-payments/check-t16-factory-devnet.py --event-rpc-url http://127.0.0.1:55545 --event-binary target/release/tempo
gzip -dc docs/evidence/evm2-t16-native-factory-proofs.json.gz | cargo run --quiet -p tempo-evm --example verify_native_earn_factory_proofs -- - docs/evidence/evm2-t16-native-factory-devnet.json
```

## Settlement-forwarder admission check

Tempo revision `d6700be7e` fixed native runtime copying from a contract already
persisted in the database. Its release binary SHA-256 is
`ad7d6e360aba8347f54feb74fc08342dbf2f8c3b44b4f77665b9ab2ff9058f78`.
The [saved run](evm2-t16-native-settlement-forwarder-mock.json) uses the same
T16 chain and genesis as the registration-event run above. A deployed 65-byte
mock solver at `0xdc64a140aa3e981100a9beca4e685f962f0cf6c9` exposes an
engine getter, returns true for caller authorization, and writes a marker and
the observed caller during `solveAndForward`. The governor registered it in
block `0xbba`; the receipt emitted `NativeEarnSettlementRegistered`. The
original deployed runtime was copied to the deterministic snapshot at
`0x5aec000117109dbf537fec8bc79cda3fb6db7c8c`, and the solver address
received the native dispatcher.

A canonical one-request forwarding transaction succeeded in block `0xbd3`,
used 613,338 gas, wrote marker `42` and the original EOA caller to solver
storage, and left vault assets and EarnShare supply aligned at 1,000,000.
Seventeen [captured metric samples](evm2-t16-native-settlement-forwarder-mock-lanes.json.gz)
matched that receipt gas in the payment lane with zero general gas. The
[checker](../../scripts/native-payments/check-t16-settlement-forwarder-mock.py)
replays receipt, code, storage, accounting, and lane assertions offline or
against the devnet:

```sh
python3 scripts/native-payments/check-t16-settlement-forwarder-mock.py --rpc-url http://127.0.0.1:55545 --tempo-binary target/release/tempo
```

This mock exercises registration, persisted-code copying, and paid native
delegatecall. It does **not** execute the Veda solver, engine payout, or vault
finalization; the run below exercises those stages with local Veda periphery.

## Veda queued settlement on T16

The [local Veda settlement run](evm2-t16-native-veda-settlement.json) closes
that execution gap for the repository's local Veda periphery. On the same T16
chain, Earn revision `a86e91a` deployed `LocalVedaVault`, Accountant, Teller,
tracking Queue, and stock-solver fixture, plus the production `VedaEngine` and
`VedaForwardingSolver`. The governor approved the engine's deployed code hash.
The existing native factory created a second Earn stack bound to that engine,
and the registrar snapshotted and registered the deployed production forwarder.
The saved [20 receipts](evm2-t16-native-veda-settlement-receipts.json.gz)
cover the deployment and binding sequence, asset and EarnShare approvals,
deposit, queued request, and solve.

A 1,000,000-asset deposit minted 999,999 EarnShare under the local Teller's
conservative quote. The vault then requested redemption of 100,000 EarnShare;
both the tracking Queue and vault emitted request ID
`0x4c89102dc9ad0c2cdad9ff6a047660377e4290e7878df6235990d8dfb324db7f`.
The registered forwarder submitted a canonical one-request
`solveAndForward` transaction in block `0xec7`. Its 593,576 gas was observed
in the payment lane with zero general gas in 15 [captured
samples](evm2-t16-native-veda-settlement-lanes.json.gz). The local stock solver
paid 100,000 assets to the engine; `VedaEngine.forwardSolved` finalized the
vault claim in the same transaction. The recipient gained exactly 100,000
assets; vault and engine open-claim counts moved from one to zero, the Queue
request became inactive, `settled(asset)` remained zero, and EarnShare supply
and vault assets both remained 899,999. Replaying the same request reverted
without changing those balances or claim counters.

At block `0xf57`, [nine account and nine storage
proofs](evm2-t16-native-veda-settlement-proofs.json.gz) verify against state
root `0x24701fbc3e13d9875fb0385433c8297aec4fdf0702ec9a7562e57a7491a7a6d9`.
They cover the native registry, vault, fees, EarnShare, engine, Queue,
forwarder, snapshot, and asset, including dispatcher code hashes and the
vault/fee/forwarder binding slots. The saved run can be checked offline and
against the running devnet:

```sh
python3 scripts/native-payments/check-t16-veda-settlement.py --rpc-url http://127.0.0.1:55545 --tempo-binary target/release/tempo
gzip -dc docs/evidence/evm2-t16-native-veda-settlement-proofs.json.gz | cargo run --quiet -p tempo-evm --example verify_native_earn_veda_proofs -- - docs/evidence/evm2-t16-native-veda-settlement.json
```

The stock solver, Queue, Teller, Vault, and Accountant in this run are local
test fixtures; `VedaEngine`, `VedaForwardingSolver`, Earn vault/fees, and Tempo
native execution are the production code. This establishes a real on-chain
queued payout and finalization using the local Veda interfaces. Vendor Veda
contracts and hosted solver authorities remain a separate integration gate.

## Sustained Earn payment-lane burst

The [80-second burst](evm2-t16-native-earn-sustained-summary.json) on the same
T16 node submitted 20 cycles of 100 registered vault deposits followed by
100 redemptions. All 4,000 payments succeeded, with 100 transactions in each
of 40 blocks (50.36 transactions per elapsed second, limited by the one-second
block schedule and two-phase client). The 4,000 saved
[receipts and metric samples](evm2-t16-native-earn-sustained-raw.json.gz)
total 974,784,000 paid gas. Each block's receipt gas equals its block gas;
586 captured samples match the block payment gas with zero general gas. At
every deposit block EarnShare supply and vault assets were 1,100,000, and at
every redemption block both returned to 1,000,000. The first attempted
redemption burst, before EarnShare approval, reverted 100 times and was
excluded from the successful workload; a share approval corrected the setup.

```sh
python3 scripts/native-payments/check-t16-earn-sustained.py --rpc-url http://127.0.0.1:55545 --tempo-binary target/release/tempo
```

This measures registered Earn payments in one node. The mixed-capacity runs
below exercised Earn and Zone on the same T16 L1.

## Same-chain Earn and private Zone capacity

The [40-second mixed run](evm2-t16-native-combined-capacity-summary.json)
submitted 2,000 registered Earn payments and 1,000 private Zone transfers.
The Zone was newly provisioned on this T16 L1, credited by a 1,000,000-asset
encrypted portal deposit, and activated at T15 after its pre-fork balance was
checked. All workload receipts succeeded. Eleven Zone batches settled on L1
through the NoProof devnet path. The checker verifies per-block receipts,
private balances through authenticated RPC, portal custody, Earn accounting,
settlement calldata and events, and captured payment-lane samples:

```sh
python3 scripts/native-payments/check-t16-combined-capacity.py --l1-rpc-url http://127.0.0.1:55545 --zone-rpc-url http://127.0.0.1:57545 --zone-private-rpc-url http://127.0.0.1:57544 --tempo-binary target/release/tempo --zones-binary /path/to/tempo-zone
```

The [240-second continuation](evm2-t16-native-combined-sustained-summary.json)
ran 60 cycles of 100 Earn deposits, 100 private Zone transfers, and 100 Earn
redemptions: 18,000 successful workload transactions across 180 workload
blocks, or 74.97 transactions per elapsed second. The 12,000 Earn receipts
used 2,897,952,200 gas and the 6,000 Zone transfer receipts used 729,432,000
gas. Twenty-four Earn blocks also included a Zone settlement, so the checker
accounts for Earn receipt gas separately from full L1 block gas. All 120 Earn
blocks had captured payment-lane samples with zero general-lane gas; 1,708
samples matched the full L1 block gas. Twenty-six NoProof Zone settlements
succeeded during the window, with two matching zero-general-lane samples.
The final settled Zone block follows the last transfer. The private sender
lost exactly 6,000 units, the recipient gained 6,000, and Zone supply equals
portal custody at 1,000,000. EarnShare supply equals vault assets at 1,000,000.
The [raw receipts](evm2-t16-native-combined-sustained-raw.json.gz),
[metric samples](evm2-t16-native-combined-sustained-metrics.json.gz), and
[settlement receipts](evm2-t16-native-combined-sustained-settlements.json.gz)
are saved with the checker:

```sh
python3 scripts/native-payments/check-t16-combined-sustained.py --l1-rpc-url http://127.0.0.1:55545 --zone-rpc-url http://127.0.0.1:57545 --zone-private-rpc-url http://127.0.0.1:57544 --tempo-binary target/release/tempo --zones-binary /path/to/tempo-zone
```

Authenticated private balance checks additionally require
`EVM2_ZONE_SENDER_KEY` and `EVM2_ZONE_RECIPIENT_KEY` for the two local dev
accounts. The run used a single client, a one-second L1 block schedule, and
local NoProof settlement. It does not measure saturation throughput or
Nitro-attested batch proving.

This run exercises new-stack registration and synchronous accounting on a
fresh fork. The earlier [combined fork run](EVM2_T16_EARN_ZONE_FORK.md) covers
legacy Earn and Zone migration and the mixed serial workload. Vendor Veda
settlement and real Nitro-attested Zone settlement remain open.
