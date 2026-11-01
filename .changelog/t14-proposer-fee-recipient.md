---
tempo-evm: minor
tempo-payload-builder: patch
---

Added `TempoEvm::proposer_fee_recipient`. From T14, block execution rejects blocks whose beneficiary differs from the proposer's `ValidatorConfigV2` fee recipient, and blocks whose proposer has no `ValidatorConfigV2` entry, so a proposer's consensus key alone can no longer redirect fees.
