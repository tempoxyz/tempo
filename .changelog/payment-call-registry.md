---
tempo-hardfork: minor
tempo-contracts: minor
tempo-precompiles: minor
tempo-primitives: minor
tempo-evm: minor
tempo-payload-builder: minor
tempo-transaction-pool: minor
---

Added the `T17` hardfork with no public-network activation and the TIP-1180 payment call registry precompile at `0x1180000000000000000000000000000000000000`. From T17, transactions whose every call targets an active registered instance with a listed selector, exact calldata length and gas limit within the selectors' gas caps are registered payments, bounded by a registered payment gas limit of half the block gas limit. During execution every frame must run registered code (including templates with no payment selectors) or a precompile; otherwise the transaction's gas counts against the general lane. The builder admits registered payments by gas used, bounds the work it discards when one fails that check, and demotes only the failing instance with a back-off; the pool caches classification per block and registry version. The prototype genesis `paymentLaneCalls` list is removed.
