# Owner funding qualification

This document records the owner-funding release checks for node maintainers. The scope is signed `requireFunds` transactions using the native DEX at T13. Earn vaults and access key funding are separate releases.

## Reproduce the payment and gas measurements

```sh
cargo run -p tempo-e2e --example owner_funding --locked
cargo test -p tempo-e2e owner_funding_finalization_and_gas --locked -- --nocapture
cargo test -p tempo-node --test it funding:: --locked
```

The example starts four local validators with consensus and execution running inside the existing E2E runtime. It uses disposable test identities and the test genesis. It does not connect to a deployed network or launch production binaries.

The example seeds the recipient with one pathUSD to avoid charging only the baseline for a new recipient balance. It creates two USD TIP-20 inputs and liquid tick-zero DEX books. An owner with no output tokens signs a sponsored requirement for 50 pathUSD, using at most 30 units of the first input and the second input for the remainder.

The example discovers native DEX candidates through RPC and uses the second candidate's request data in the signed payment. The example's encoder signs both the sender and sponsor payloads and submits raw transaction bytes over HTTP RPC.

Each scenario waits for all four validators to finalize the receipt's height. It compares the block hash, state root, complete receipt, historical token balances, DEX input credits, and absent source/DEX allowances. Failures must leave no funding events or input consumption. Normal fees and nonce consumption still apply.

`FUNDING_GAS_RESULTS` contains machine-readable gas, transaction hash, finalized block hash, and state root for each scenario. Gas includes the application transfer, funding, and normal transaction overhead; setup transactions are excluded. Absolute gas depends on order-book shape, storage state, and the number of quote probes.

## Measured gas

Measured with Rust 1.95.0 on the T13 fixture above. The four-validator E2E test measured all seven scenarios using discovered request data. Transactions run in the listed order, so these are reproducible scenario measurements, not isolated estimates for arbitrary liquidity or storage state.

| Scenario | Total gas | Additional gas versus subsequent direct transfer |
| --- | ---: | ---: |
| First owner transaction, direct transfer | 290,954 | 250,000 |
| Subsequent direct transfer | 40,954 | 0 |
| Requirement already covered | 44,137 | 3,183 |
| One source, 50 units, omitted slippage | 621,183 | 580,229 |
| Two sources, 30 + 20 units, 100 bps | 766,341 | 725,387 |
| Funding succeeds, payment reverts | 507,985 | — |
| First source supplies 30, requirement remains unmet | 435,130 | — |

The first transaction's 250,000-gas nonce-initialization charge is unrelated to funding. Both failure rows retain normal fees while reverting source inputs, DEX credits, output transfers, and funding events. These numbers do not establish worst-case gas bounds for fragmented books.

## Security and compatibility checks

| Area | Evidence | Constraint |
| --- | --- | --- |
| Authorization | Native permission, callback, and owner state-machine tests; signed node rejection of access keys. | Only the transaction handler initiates funding. The owner trusts the selected source and its declared input valuation; signatures authorize source addresses and data. |
| Input authority | TIP-20/DEX tests for wrong assets, existing allowances, cumulative caps, refunds, nested reverts, and cleanup. | Temporary authority belongs to one account/source callback and cannot survive it. |
| Public quotes | Native DEX/EVM and RPC tests for ceilings, cost and input caps, account balances, liquidity, and rejected direct funding. | Quotes are read-only estimates with no input authority. Execution obtains its own quote and rechecks availability. |
| Shared cost | Arithmetic/property tests and multi-source DEX integration. | One budget uses the initial shortfall; actual gross inputs consume it. Currency metadata is not an oracle. |
| Delivery and rollback | Owner integration, signed node RPC, and four-validator scenarios. | Funding and application calls share rollback. Every required balance is rechecked before calls. |
| Activation and addresses | T12 rejection/T13 execution tests and the fixed system-address table. | The proposed `0x1120…0000` and `0x1120…0001` assignments still need protocol review. No network fork dates are assigned here. |
| Signing and compatibility | Fixed RLP vectors, sender/sponsor mutation tests, legacy/empty-extension compatibility. | Both signatures cover funding. Access key funding remains disabled. |
| RPC and scheduling | Signed RPC simulation, estimation, tracing, address-filter tests, payment classification tests. | Funding uses the general gas lane and cannot use payment replay shortcuts. |
| Resource use | Intrinsic/floor-byte tests, metered native reads/writes, callback gas and out-of-gas tests. | Partial sizing performs at most 129 quote probes during each of quoting and execution. Transaction gas bounds execution; fragmented books need separate load qualification. |

The E2E module is included by the existing `tempo-e2e` CI job. The signed RPC module is included by the ordinary node integration job. Neither suite requires a new workflow or test exclusion.

## Release gate

Local qualification does not establish production readiness. Before activation, require green CI for the exact stack revision, independent protocol/security review, acceptance of the fixed addresses, and a network-approved T13 schedule. Load qualification should include fragmented books and maximum-size signed funding arrays. Delegated funding and non-parity pricing must remain unavailable until their own implementations and release checks are complete.
