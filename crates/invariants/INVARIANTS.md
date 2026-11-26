# Tempo invariants

Generated from each check's metadata by `the_catalog_lists_every_check`.

| ID | Severity | Since | Until | Spec | Covers | Invariant |
|---|---|---|---|---|---|---|
| `TEMPO-TIP20-SUPPLY-CAP` |  |  |  |  |  | A token's total supply never exceeds its supply cap. |
| `TEMPO-TIP20-BALANCE-SUM` |  |  |  |  |  | The observed holders' balances sum to at most the total supply. |
| `TEMPO-TIP20-TRANSFER-EVENTS` |  |  |  |  |  | Each observed balance moves by exactly the step's `Transfer` events into and out of it, and the supply by its mints and burns. |
| `TEMPO-TIP20-ROLE-AUTHZ` |  |  |  |  |  | Only an account holding a token's role calls the token directly for what the role gates: mint, pause, unpause, burnBlocked and burnAt. |
| `TEMPO-FEE5` |  |  |  |  |  | The fee manager holds, of each token, at least its pools' reserves of it plus the fees it collected in it. |
| `TEMPO-AMM30` |  |  |  |  |  | A pool is uninitialized (no LP supply, reserves or LP) or has at least the locked minimum LP supply. |
| `TEMPO-AMM14` |  |  |  |  |  | An initialized pool's LP holders hold at most its LP supply less the locked minimum. |
| `TEMPO-FEE5-STEP` |  |  |  |  |  | The fee manager's holdings of each token never fall by more than what it owes in it. |
| `TEMPO-AMM2` |  |  |  |  |  | The LP supply grows by exactly the minted liquidity, plus `MIN_LIQUIDITY` on a pool's first mint. |
| `TEMPO-AMM3` |  |  |  |  |  | The recipient's LP balance grows by exactly the liquidity minted to it. |
| `TEMPO-AMM4` |  |  |  |  |  | The validator reserve grows by exactly the validator tokens deposited. |
| `TEMPO-AMM5` |  |  |  |  |  | A burn pays `liquidity * reserve / totalSupply` of each token, rounded down. |
| `TEMPO-AMM-EXIT` |  |  |  |  |  | An LP holder burning its whole position never halts or panics. |
| `TEMPO-DEX10` |  |  |  |  |  | The DEX holds, of each token, at least its users' internal balances of it plus its live orders' escrow in it. |
| `TEMPO-DEX10-STEP` |  |  |  |  |  | The DEX's holdings of each token never fall by more than what it owes in it. |
| `TEMPO-ACCOUNT-COMMITMENT-KEPT` |  |  |  | TIP-1107 |  | A commitment is never cleared. |
| `TEMPO-ACCOUNT-COMMITMENT-BY-SELF` |  |  |  | TIP-1107 |  | Only registration, the account's own owner update or its migration changes its commitment. |
| `TEMPO-ACCOUNT-COMMITMENT-EVENT` |  |  |  | TIP-1107 |  | A changed commitment is announced, registration included. |
| `TEMPO-ACCOUNT-COMMITMENT-HASH` |  |  |  | TIP-1107 |  | The commitment is the hash of the configuration that wrote it. |
| `TEMPO-ACCOUNT-CONFIG-RULES` |  |  |  | TIP-1107 |  | Every carried or announced configuration passes the configuration rules. |
| `TEMPO-ACCOUNT-SIGNER-REGISTERED` |  |  |  | TIP-1107 |  | Every configurable signer has a commitment afterwards. |
| `TEMPO-ACCOUNT-QUORUM-COMMITMENT` |  |  |  | TIP-1107 |  | A quorum matches its account's commitment, or derives its address. |
| `TEMPO-ACCOUNT-SENDER-QUORUM` |  |  |  | TIP-1107 |  | The transaction's own configurable signature names its sender. |
| `TEMPO-ACCOUNT-QUORUM-WEIGHT` |  |  |  | TIP-1107 |  | Approvals are ascending owners that reach the threshold and fall below it without any one. |
| `TEMPO-ACCOUNT-APPROVAL-BOUNDS` |  |  |  | TIP-1107 |  | 1 to 8 approvals, each at most 2,049 bytes. |
| `TEMPO-ACCOUNT-UPDATE-QUORUM` |  |  |  | TIP-1107 |  | Owner updates are signed directly by the account's quorum. |
| `TEMPO-ACCOUNT-UPDATE-VERSION` |  |  |  | TIP-1107 |  | Each owner update keeps the salt and bumps the version by one. |
| `TEMPO-ACCOUNT-UPGRADE-ROOT` |  |  |  | TIP-1113 |  | Migration is signed by the sender's own original key, without an authorization list. |
| `TEMPO-ACCOUNT-UPGRADE-FRESH` |  |  |  | TIP-1113 |  | Only an account without a commitment migrates. |
| `TEMPO-ACCOUNT-UPGRADE-CONFIG` |  |  |  | TIP-1113 |  | Migration stores the version-1 configuration's hash under the upgrade salt. |
| `TEMPO-ACCOUNT-ROOT-KEY-RETIRED` |  | T14 |  | TIP-1113 |  | An ordinary signature is never authority for an account with a commitment. |
| `TEMPO-ACCOUNT-FORK-GATED` |  |  | T14 | TIP-1111 |  | Before T14, no configurable signatures or key-type-3 grants. |
| `TEMPO-ACCOUNT-FAILED-ROLLBACK` |  |  |  | TIP-1107 |  | A failed transaction keeps no owner update or migration, only registration. |
| `TEMPO-ACCOUNT-DERIVED-ADDRESS` |  |  |  | TIP-1107 |  | A registering account's address is outside the reserved address spaces. |
| `TEMPO-ACCOUNT-GRANT-SIGNER` |  | T14 |  | TIP-1111 |  | An inline grant is signed by its parent's own key or quorum, or by an admin key the parent already had that also signs the transaction. |
| `TEMPO-ACCOUNT-GRANT-TYPE` |  | T14 |  | TIP-1111 |  | An access key using a grant made in the same transaction signs as the grant's key type. |
| `TEMPO-ACCOUNT-ACCESS-KEY-TYPE` |  | T14 |  | TIP-1111 |  | An access key signs as the key type its grant stores, except that a configurable signature may use an ordinary grant whose key ID already has a commitment. |
| `TEMPO-ACCOUNT-GRANT-AUTHORITY` |  | T14 |  | TIP-1111 |  | Grants change only in the parent's own transactions, by its key or quorum, and never as an admin key. |
| `TEMPO-ACCOUNT-MARKER` |  |  |  | TIP-1107 |  | An account with a commitment has the 0xef marker as code. |
| `TEMPO-ACCOUNT-MARKER-INSTALL` |  |  |  | TIP-1107 |  | Only registration and migration install the marker. |
| `TEMPO-ACCOUNT-GRANT-DELEGATE` |  |  |  | TIP-1111 |  | A key-type-3 grant names a delegate other than the parent, outside the reserved spaces, without other code. |
| `TEMPO-ACCOUNT-MARKER-KEPT` |  |  |  | TIP-1107 |  | Nothing changes or clears the marker. |
| `TEMPO-KEYCHAIN-REVOKED-KEY-SPENDS` |  |  |  |  |  | A revoked access key never spends. |
| `TEMPO-KEYCHAIN-EXPIRED-KEY-SPENDS` |  |  |  |  |  | An access key never spends at or past its expiry. |
| `TEMPO-KEYCHAIN-SPEND-LIMIT` |  |  |  |  |  | An access key with enforced limits never spends more than its remaining limit. |
| `TEMPO-RECEIVE-POLICY-CLAIM-AUTHORITY` |  |  |  |  |  | Blocked value claimed to a third party is claimed under a recovery authority the receiver's root or an admin key set. |
| `TEMPO-BLOCK-GAS-MONOTONIC` |  |  |  |  |  | A block's receipts never lower its cumulative gas used. |
