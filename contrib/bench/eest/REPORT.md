# Benchmarkoor → Tempo execution report

Date: 2026-08-19

## Outcome

The working integration regenerates Ethereum Execution Spec Tests (EEST) on a
published Tempo node, exports the canonical blocks, and replays them through
Benchmarkoor's Engine API interface:

```text
EEST benchmark definition
  -> execute remote with Tempo funding/deployment adapter
  -> canonical Tempo setup + workload blocks
  -> tempo-engine-suite/v1 (RLP + BAL + provenance)
  -> Benchmarkoor reth_newPayload / reth_forkchoiceUpdated replay
  -> JSON, suite statistics, HTML UI
```

All instruction, precompile, and scenario files in the Prague compute benchmark
tree were attempted. The adapter produced **925 unique transaction-bearing
tests from 1,137 cases (81.35%)**. Every exported test passed EEST post-state
validation and then passed Benchmarkoor replay on a fresh published Tempo
container: **925 passed, 0 Engine API replay failures**.

Coverage by source family:

| Family | Verified | Selected | Coverage |
| --- | ---: | ---: | ---: |
| EVM instructions | 693 | 773 | 89.65% |
| Precompiles | 223 | 228 | 97.81% |
| Scenarios | 9 | 136 | 6.62% |
| **Total** | **925** | **1,137** | **81.35%** |

Inputs:

- EEST revision: `ce0509a90bdf7bdff68a90ba00b4ce956144e450`
- Tempo image: `docker.io/tempoxyz/tempo:latest`
- Image digest: `sha256:99f2b51e2400b7aceb9c31c944cad8777d170092c3a6b62013c4a63d3c53e680`
- Tempo version: `tempo/v1.13.0-f557cbb/aarch64-unknown-linux-gnu`
- Fork/gas parameter: Prague / 10M

Verified batch results (correctness and integration evidence; not a stable
performance baseline):

| Suite | Run | Hash | Passed | Failed | Measured gas | Server execution |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| arithmetic | `1787168923_87b4c1a6_tempo` | `a35bccd89405b3ef` | 61 | 0 | 610M | 1.051s |
| bitwise/context/control | `1787169116_ada5e8ae_tempo` | `edae01448fd670be` | 38 | 0 | 380M | 275.727ms |
| stack/memory | `1787169556_078fd5b5_tempo` | `4e66abe132f36885` | 195 | 0 | 1.950B | 1.504s |
| account/transaction context¹ | `1787170139_bba9f34f_tempo` | `266a34deb877e4ac` | 34 | 0 | 340M | 203.893ms |
| comparison | `1787171598_05e40b17_tempo` | `1e8c56d330a1bffa` | 6 | 0 | 60M | 43.725ms |
| Keccak | `1787171974_2b4fb4fe_tempo` | `8ea58bef17053123` | 35 | 0 | 350M | 645.348ms |
| precompiles except MODEXP | `1787170409_40284a39_tempo` | `79d03cee9a398ec1` | 104 | 0 | 1.033B | 5.427s |
| MODEXP | `1787170698_66830f25_tempo` | `6050d02132249483` | 119 | 0 | 1.190B | 3.501s |
| call context | `1787171041_00e2850f_tempo` | `1a6f32ec44ca47fc` | 142 | 0 | 1.420B | 786.018ms |
| LOG | `1787171372_a613e307_tempo` | `1f864f8ba4c657d5` | 140 | 0 | 1.400B | 210.529ms |
| storage | `1787171475_00ea6769_tempo` | `f11919671e7c586a` | 24 | 0 | 239.954M | 96.259ms |
| system | `1787171564_467220a4_tempo` | `d4ca813713245e30` | 18 | 0 | 179.996M | 105.910ms |
| mixed-operation scenarios | `1787171645_a95b756f_tempo` | `c9883a0a5b6e910e` | 9 | 0 | 90M | 18.558ms |
| **De-duplicated total** | | | **925** | **0** | **9.243B** | **13.869s** |

¹ The original 68-test core run also contains 34 Keccak cases. They are excluded
from this row and replaced by the complete isolated 35-test Keccak run, so the
total does not double-count them.

The aggregate execution rate was 666.45 MGas/s. Run at least five repetitions
on an idle host before treating throughput as a baseline, and compare only
identical suite hashes and image digests.

## Full corpus repetition

A fresh repetition of every production suite completed on the same published
image after the initial conversion run. It executed 962 suite entries across
13 EEST-derived suites and three Tempo-native TIP-20 suites: **962 passed, 0
failed**. De-duplicating the 34 Keccak cases shared by the core and isolated
Keccak suites gives **928 unique tests, 9.252B gas, 14.331s server execution,
and 645.62 MGas/s**.

| Family | Fresh run IDs | Passed | Failed |
| --- | --- | ---: | ---: |
| arithmetic / bitwise / stack-memory | `1787172533_13fe9a40_tempo`, `1787172541_2858a1f3_tempo`, `1787172551_2cacf1b9_tempo` | 294 | 0 |
| core / comparison / Keccak | `1787172579_e76196af_tempo`, `1787172591_1a898832_tempo`, `1787172596_8deb4621_tempo` | 109 | 0 |
| call / LOG / storage / system | `1787172605_f28dedcc_tempo`, `1787172625_aa200bda_tempo`, `1787172646_4d9af0c7_tempo`, `1787172653_dcc72b6b_tempo` | 324 | 0 |
| precompiles | `1787172661_db4088c5_tempo`, `1787172682_94d5c8a1_tempo` | 223 | 0 |
| scenarios | `1787172702_9207aced_tempo` | 9 | 0 |
| TIP-20 | `1787172709_71fcf87d_tempo`, `1787172713_873b5270_tempo`, `1787172717_8f2f3c65_tempo` | 3 | 0 |
| **Raw suite executions** | | **962** | **0** |

The one-case ADD debugging artifact and the obsolete 903-case structural import
were not rerun. ADD is already contained in the arithmetic suite; the structural
import is deliberately non-executable because its signed Ethereum transactions
use a base fee that cannot be rewritten for Tempo without invalidating them.

## Single merged-suite run

The 16 production manifests were also combined into one boundary-aware
`tempo-engine-suite/v1` manifest. Benchmarkoor preserved sequential state inside
each original suite and recreated a fresh published Tempo container at exactly
15 suite transitions.

| Run | Suite entries | Passed | Failed | Gas | Server execution | MGas/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `1787173140_0395b56c_tempo` | 962 | 962 | 0 | 9.592B | 13.808s | 694.68 |

The merged run intentionally retains 34 namespaced Keccak cases from both their
original core segment and the later complete Keccak segment. Its unique semantic
coverage remains 928 tests after de-duplication.

## Precompile coverage

All ten precompile source files were found and attempted; none were overlooked.

| Precompile | Verified | Selected | Result |
| --- | ---: | ---: | --- |
| alt_bn128 | 36 | 36 | complete |
| BLAKE2f | 9 | 9 | complete |
| BLS12-381 | 28 | 29 | 1 upstream skip |
| ecrecover | 1 | 1 | complete |
| identity | 8 | 8 | complete |
| MODEXP | 119 | 119 | complete |
| P-256 verify | 0 | 4 | 4 upstream Prague skips |
| point evaluation | 2 | 2 | complete |
| RIPEMD-160 | 10 | 10 | complete |
| SHA-256 | 10 | 10 | complete |
| **Total** | **223** | **228** | **97.81%** |

The 223 exported precompile cases all passed Engine API replay. P-256 is not
active for the selected Prague fork in this EEST revision; its four parameters
were reported as skips by EEST, not failures by Tempo.

## Compatibility findings and skipped cases

The 212 non-exported cases were retained as explicit compatibility findings:

- Instructions: 80/773 were skipped or failed during live generation. These
  include six truncated-PUSH fixtures passed as raw `bytes` to an execute-mode
  allocator, 13 memory deployments with native balance, eight account balance/
  value cases, two upstream transaction-context skips, three call-value cases,
  seven cold-storage cases whose ~102.7M transaction gas limit exceeds Tempo's
  30M cap, and 41 system cases dominated by native-value setup and the resulting
  nonce replacement cascade.
- Precompiles: 5/228 were upstream skips (four P-256 and one BLS12-381); 223
  exported and replayed successfully.
- Scenarios: all nine mixed-operation cases passed. Seven unchunkified-bytecode
  variants were upstream Prague skips. The 120 transaction-type cases are not a
  useful direct Tempo benchmark: 119 fail admission because Ethereum's 21K
  transfer gas, native value, EIP-7702 authorization, or creation assumptions do
  not match Tempo; the remaining pytest case produced no transaction-bearing
  block. Deeper translation was intentionally skipped.
- Future-fork EIP-7928 block-access-list and stateful bloatnet/predeploy suites
  were not included in the 1,137-case Prague compute denominator. They require a
  different fork or preloaded state and should be separate integrations.

Other interface observations:

1. Tempo disables the standard `engine_newPayload*` flow for these blocks and
   uses `reth_newPayload` with Tempo raw block RLP and an optional block access
   list, followed by `reth_forkchoiceUpdated`.
2. Re-encoding an Ethereum payload header is insufficient. The existing 100M
   corpus uses a 7-wei base fee while Tempo requires its own base-fee schedule;
   signed transactions cannot be fee-rewritten without invalidating signatures.
3. EEST's live runner initially failed with `value transfer not allowed` because
   Tempo has no native currency. Generated benchmark senders must receive a
   TIP-20 fee token instead of native ETH.
4. New EOAs without a user fee-token preference pay a legacy transaction from
   pathUSD, while the pre-funded dev seed has BetaUSD configured. The adapter
   transfers pathUSD to generated EOAs; the seed pays setup fees in BetaUSD.
5. EEST's Ethereum deployment estimate was too low for Tempo state-gas/storage-
   credit accounting. Setup deployment uses a 30M ceiling; the measured workload
   transaction remains the EEST-generated 10M legacy transaction.

## Existing Tempo-specific TIP-20 smoke suites

All three canonical TIP-20 suites passed on the same published image digest:

| Suite | Gas | Server execution | Throughput | Result |
| --- | ---: | ---: | ---: | --- |
| existing recipients | 417,300 | 1.369ms | 304.82 MGas/s | passed |
| new recipients | 5,410,300 | 1.820ms | 2,972.69 MGas/s | passed |
| shared existing recipient | 3,168,760 | 1.696ms | 1,868.37 MGas/s | passed |

These remain Tempo-native suites. EEST-derived suites add Ethereum-compatible
opcode/precompile/scenario coverage; new Tempo suites should independently add
AA, fee-token, nonce, DEX, storage-credit, subblock, transition, and invalid-
payload dimensions.

## Scaling rules

- Run related EEST files serially on one fresh source chain with
  `run-batch.sh`. The capture hook retains each pytest node ID and block range.
- Keep every canonical block before the last transaction-bearing block for a
  passing case in `setup`; time only that final workload block in `test`.
- Preserve blocks produced by failed cases as setup for the next passing case;
  omitting them breaks parent hashes and state roots.
- Use 10M or another Tempo-valid gas target, not the upstream 100M default.
- Preserve the EEST revision, EOA seed, fork, test path/filter, gas target,
  Tempo image digest, and resulting suite hash.
- Classify unsupported tests instead of silently weakening them. EIP-7702 EOA
  delegation/storage, stateful predeploys, blob transactions, and non-linear
  block graphs need explicit adapters.
- Generate Tempo-specific suites through native transaction producers, then
  export them into the same format so the report layer can compare both
  families without conflating their provenance.
