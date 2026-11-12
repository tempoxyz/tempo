---
tempo-contracts: minor
---

Added dormancy to the TIP-1169 card records interface: an activity clock that card issuance starts and holds and card authorizations move, `markDormant`, `reactivate`, `touch`, `escheat` paying an Escheat authority directly or through a facility, `payoutOf` and the `PayoutRecorded` event.
