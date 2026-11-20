---
tempo-contracts: minor
---

Added account records to the TIP-1169 card records interface (`ICards`): an account status that every hold checks, closure that sweeps the available balance to a payout address after debts (`closeAccount`, `sweep`), an authorities registry the validator config owner keeps (`setAuthority`, `authorityOf`), estates an Estate authority hands to an executor (`setEstate`, `settleEstate`), `getAccount`, and the `AccountStatusSet`, `AccountSwept` and `AuthoritySet` events with `AccountInactive`, `AccountStateInvalid` and `HoldsOpen`.
