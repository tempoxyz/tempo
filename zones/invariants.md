# Zone Invariants

This document lists the core protocol invariants for Tempo Zones. It is intended
for auditors, invariant/fuzz test authors, and production monitoring.

## Criticality

| Criticality | Meaning |
|-------------|---------|
| 🔴 **CRIT** | Direct loss of funds, invalid state transition, or unrecoverable queue corruption if violated |
| 🟡 **HIGH** | Governance/access-control breakage, privacy breakage, fund lock, replay, or proof soundness issue |
| 🟢 **MED** | Structural inconsistency, operational DoS, accounting drift, or monitoring-relevant degradation |

## Invariants

### Zone Registry and Deployment

| ID | Assertion | Crit | Impact |
|---|---|---|---|
| `TEMPO-ZONE-CHAIN-ID-UNIQUE` | Each live zone uses the chain ID derived from its zone ID, and no two live zones share a chain ID | 🟡 | Cross-zone replay protection fails; signed transactions may be valid on more than one zone |
| `TEMPO-ZONE-PORTAL-PAIRING` | A `ZoneFactory` registry entry maps one zone ID to exactly one portal, and that portal uses the factory's shared messenger | 🟡 | Deposits, withdrawals, callbacks, and config reads can target different trust domains |
| `TEMPO-ZONE-GENESIS-BINDING` | Portal `blockHash` starts at zero, and the first proof starts with the canonical genesis block derived from `zoneId` before transitioning through at least one non-genesis block | 🔴 | The zone may bootstrap from an attacker-chosen genesis state |
| `TEMPO-ZONE-FIRST-TEMPO-ANCHOR` | The first proof contains at least two blocks, and its first non-genesis block imports Tempo and proves the portal's `sequencer` slot is non-zero at that block | 🔴 | The zone may settle an unanchored bootstrap state or anchor to Tempo state from before its portal existed |
| `TEMPO-ZONE-PREDEPLOY-ADDRESSES` | `TempoState`, `ZoneInbox`, `ZoneOutbox`, and `TempoStateReader` exist at their fixed addresses | 🔴 | System calls can be redirected or missing, invalidating mint/burn, proofs, and Tempo reads |

### Access Control and Configuration

| ID | Assertion | Crit | Impact |
|---|---|---|---|
| `TEMPO-ZONE-ADMIN-NONZERO` | Portal `admin != address(0)` for every zone | 🟡 | Token governance can become permanently unavailable |
| `TEMPO-ZONE-ADMIN-ONLY-GOVERNANCE` | Only `admin` can govern tokens and access modes or set `zoneGasRate`, `maxTempoGasRate`, and `bouncebackGas` | 🟡 | A sequencer or user can enable malicious assets, reopen paused deposits, alter access policy, or exceed governance fee bounds |
| `TEMPO-ZONE-SEQUENCER-ONLY-OPS` | Only a registered sequencer can set `tempoGasRate`, set RPC URL, submit batches, and process withdrawals; the portal admin or a registered sequencer can set encryption keys | 🟡 | Unauthorized operators can censor, misprice, settle, or drain queued work |
| `TEMPO-ZONE-GAS-RATE-BOUNDED` | `zoneGasRate` and `maxTempoGasRate` never exceed `MAX_GAS_FEE_RATE`, and `tempoGasRate` never exceeds the finalized `maxTempoGasRate` | 🟢 | Deposit or withdrawal fee math may overflow or become economically unusable |

### Token Registry and Supply

| ID | Assertion | Crit | Impact |
|---|---|---|---|
| `TEMPO-ZONE-TOKEN-ENABLEMENT-APPEND-ONLY` | Once enabled, a token remains enabled and remains in the append-only enabled token list | 🔴 | Withdrawals can be disabled after deposits, breaking the non-custodial bridge guarantee |
| `TEMPO-ZONE-TOKEN-ENABLEMENT-BINDING` | Every non-genesis `advanceTempo` hashes the exact ordered token-address and metadata delta from `ZoneInbox.processedTokenEnablementHash`, requires equality with `ZonePortal.tokenEnablementHash` at the final imported Tempo state, and initializes all entries before processing deposits | 🔴 | A sequencer can omit or alter an irreversible enablement, causing enabled-token deposits to bounce permanently and locking the asset out of the zone |
| `TEMPO-ZONE-TOKEN-DEPOSIT-PAUSE-ONLY` | Pausing a token only disables new deposits; withdrawals for enabled tokens remain requestable and processable | 🔴 | Admin can lock users inside the zone by pausing deposits |
| `TEMPO-ZONE-MESSENGER-AUTH` | The shared messenger only relays when `msg.sender == ZoneFactory.zones(zoneId).portal` | 🟡 | A caller can spoof a source zone or invoke receiver callbacks outside the portal-controlled withdrawal path |
| `TEMPO-ZONE-SUPPLY-SOLVENCY` | For each token, zone-side total supply equals accepted deposits plus withdrawal bounce-backs minus requested withdrawals minus deposit bounce-backs | 🔴 | The zone can mint unbacked tokens or burn user funds without matching L1 release |
| `TEMPO-ZONE-PORTAL-SOLVENCY` | Portal token balance plus paid-out/parked refunds is sufficient for all unwithdrawn zone supply and pending withdrawals | 🔴 | Portal cannot honor exits, causing direct loss or insolvency |
| `TEMPO-ZONE-MINT-BURN-AUTHORITY` | Only `ZoneInbox` can mint zone tokens and only `ZoneOutbox` can burn zone tokens | 🔴 | Unauthorized mint or burn breaks bridge accounting and can steal or destroy funds |

### Deposits

| ID | Assertion | Crit | Impact |
|---|---|---|---|
| `TEMPO-ZONE-DEPOSIT-ENABLED-ACTIVE` | User deposits only enter the queue when the token is enabled and deposits are active | 🟡 | Users can deposit unsupported or paused assets that the zone may not process |
| `TEMPO-ZONE-DEPOSIT-FEE-SNAPSHOT` | Deposit queue entries store `amount - FIXED_DEPOSIT_GAS * zoneGasRate`, and the fee is paid to the admin at enqueue time | 🟢 | Fee changes can retroactively change user value or underpay processing costs |
| `TEMPO-ZONE-DEPOSIT-ALIASES` | `deposit` and `depositEncrypted` accept the same encrypted arguments and produce identical validation, accounting, queue entries, and events | 🟡 | Callers can receive different bridge semantics depending on the selected entrypoint |
| `TEMPO-ZONE-DEPOSIT-MIN-AMOUNT` | Both deposit entrypoints revert (`DepositTooSmall`) unless `amount >= depositFee + currentBouncebackFee` | 🔴 | Dust deposits can enter the queue that cannot fund their own Tempo-side refund, stranding funds |
| `TEMPO-ZONE-DEPOSIT-BOUNCEBACK-NONZERO` | Every user-initiated deposit has a non-zero, TIP-403-authorized `tempoRefundRecipient` | 🔴 | Failed deposits can permanently block or strand funds without a refund target |
| `TEMPO-ZONE-DEPOSIT-QUEUE-HASH` | Portal deposit queue hash updates as `keccak256(abi.encode(depositType, depositData, previousHash))` for every encrypted user deposit or internal withdrawal bounce-back | 🔴 | The zone may process a different deposit sequence than the portal accepted |
| `TEMPO-ZONE-DEPOSIT-NUMBER-MONOTONIC` | `depositCount` and `processedDepositNumber` are monotonic and match the number of queue entries enqueued or proven processed | 🟢 | User deposit status can be wrong and deposits may be skipped or double-counted |
| `TEMPO-ZONE-DEPOSIT-PROCESSED-PREFIX` | The inbox processes only a prefix of the portal queue, oldest first, and never skips, reorders, or duplicates deposits | 🔴 | Users receive wrong mints/refunds or deposits become unprovable |
| `TEMPO-ZONE-DEPOSIT-FAIL-BOUNCEBACK` | Any rejected deposit, invalid encryption, or failed mint enqueues exactly one deposit bounce-back withdrawal | 🔴 | Failed deposits can be lost, duplicated, or stuck |
| `TEMPO-ZONE-DEPOSIT-REJECTION-NO-MINT` | A rejected user deposit never mints zone tokens and still advances the deposit queue | 🔴 | Sequencer rejection can create unbacked mints or stall deposits |

### Deposit Encryption and Keys

| ID | Assertion | Crit | Impact |
|---|---|---|---|
| `TEMPO-ZONE-ENCRYPTION-KEY-APPEND-ONLY` | Sequencer encryption keys are appended with valid secp256k1 points and proof of possession; historical entries never mutate | 🟡 | Sequencer can register unusable keys or rewrite history, causing undecryptable deposits |
| `TEMPO-ZONE-ENCRYPTION-KEY-GRACE` | Non-current encryption keys are accepted only until the next key activation block plus `ENCRYPTION_KEY_GRACE_PERIOD`; the current key does not expire | 🟢 | Users can enqueue deposits to expired keys or have current-key deposits rejected |
| `TEMPO-ZONE-ENCRYPTED-PAYLOAD-SHAPE` | Deposits require valid ephemeral public key parity/X coordinate and exactly 64 bytes of ciphertext | 🟢 | Oversized or invalid payloads can DoS zone-side decryption or make proofs impossible |
| `TEMPO-ZONE-DECRYPTION-ORDER` | Decryption data is consumed one-for-one, in order, for accepted encrypted deposits only | 🔴 | A sequencer can apply a proof to the wrong ciphertext or desynchronize processing |
| `TEMPO-ZONE-CHAUM-PEDERSEN-BINDING` | Accepted encrypted deposits only decrypt using a valid Chaum-Pedersen proof tied to the stored sequencer key for `keyIndex` | 🔴 | Sequencer can substitute keys or fabricate plaintext, redirecting deposits |
| `TEMPO-ZONE-AES-GCM-AUTHENTICITY` | If AES-GCM authentication or plaintext length validation fails, no mint is attempted and the deposit bounces back | 🔴 | Invalid ciphertext can mint to attacker-chosen or malformed recipients |

### Withdrawals

| ID | Assertion | Crit | Impact |
|---|---|---|---|
| `TEMPO-ZONE-WITHDRAWAL-TOKEN-ENABLED` | Withdrawals can only be requested for enabled tokens | 🔴 | Users can burn unsupported assets with no corresponding portal escrow |
| `TEMPO-ZONE-WITHDRAWAL-FALLBACK-NONZERO` | Every user withdrawal has a non-zero `zoneFallbackRecipient` | 🔴 | Failed Tempo-side withdrawals cannot return funds to the zone |
| `TEMPO-ZONE-WITHDRAWAL-FEE-SNAPSHOT` | Withdrawal fee equals `(WITHDRAWAL_BASE_GAS + gasLimit) * tempoGasRate` at request time, with the rate bounded by the finalized admin maximum, and is burned with the amount | 🟢 | Fee changes retroactively alter user economics or underfund processing |
| `TEMPO-ZONE-WITHDRAWAL-BURN-BEFORE-QUEUE` | `requestWithdrawal` burns `amount + fee` before appending the pending withdrawal | 🔴 | Portal can release funds without removing zone supply |
| `TEMPO-ZONE-WITHDRAWAL-CALLBACK-BOUNDS` | `gasLimit <= MAX_WITHDRAWAL_GAS_LIMIT`, callback data is bounded, and over-limit legacy withdrawals bounce back after dequeue | 🟡 | A withdrawal can exceed block gas limits or permanently block the FIFO queue |
| `TEMPO-ZONE-WITHDRAWAL-CALLBACK-RETURNDATA-BOUND` | Realized delivery cost of a callback withdrawal stays within its `gasLimit` plus a fixed overhead: `relayMessage` bounds its return and revert data for any callback target, and enabled tokens are native TIP-20s with constant-size errors | 🟡 | A callback can charge unbounded quadratic memory gas to the delivery frame, exhausting a `processWithdrawals` batch and permanently blocking the FIFO queue |
| `TEMPO-ZONE-SENDER-TAG-BINDING` | `senderTag == keccak256(abi.encodePacked(sender, txHash, fallbackNonce))`, where `txHash` is the current withdrawal request transaction hash and `fallbackNonce` uniquely identifies the withdrawal | 🟡 | Authenticated withdrawals can reveal, link, or misattribute the sender |
| `TEMPO-ZONE-ENCRYPTED-SENDER-SHAPE` | If `revealTo` is set, `encryptedSender` is present and exactly 113 bytes; otherwise it is empty | 🟢 | Selective reveal consumers cannot authenticate sender metadata reliably |
| `TEMPO-ZONE-WITHDRAWAL-BATCH-INDEX` | `finalizeWithdrawalBatch` advances `withdrawalBatchIndex` exactly once per submitted batch, including zero-withdrawal batches | 🔴 | Sequencer can omit or replay batches containing withdrawals |
| `TEMPO-ZONE-WITHDRAWAL-HASH-LIFO-FIFO` | Outbox builds each withdrawal hash chain LIFO so the portal processes user withdrawals FIFO | 🔴 | Withdrawal order can be reversed, skipped, or duplicated |
| `TEMPO-ZONE-WITHDRAWAL-QUEUE-FIFO` | Portal withdrawal queue uses monotonically increasing logical indices with `tail >= head`; slots in `[head, tail)` contain non-zero hash chains, consumed slots are cleared to zero, and backlog size cannot block batch submission | 🔴 | Queue capacity or stale entries can block batch submission, lose withdrawals, or permit replay |
| `TEMPO-ZONE-WITHDRAWAL-DEQUEUE-AUTH` | `processWithdrawals` only dequeues when `keccak256(abi.encode(withdrawal, remainingQueue))` matches the current head slot | 🔴 | Sequencer can process arbitrary withdrawals or steal portal escrow |
| `TEMPO-ZONE-WITHDRAWAL-POP-ONCE` | Each processed withdrawal is popped exactly once, whether transfer/callback succeeds or bounces back | 🔴 | Failed withdrawals can block the queue or successful withdrawals can be replayed |
| `TEMPO-ZONE-WITHDRAWAL-FAIL-BOUNCEBACK` | Any failed user-facing transfer or callback enqueues exactly one withdrawal bounce-back deposit for `amount`, excluding fee | 🔴 | Failed withdrawals can lose funds or duplicate refunds |
| `TEMPO-ZONE-WITHDRAWAL-FEE-LOCAL` | User withdrawal data does not include the fee, and `processWithdrawals` never pays a user withdrawal fee from portal escrow | 🔴 | A compromised sequencer can encode or redeem arbitrary fees from protected escrow |
| `TEMPO-ZONE-DEPOSIT-BOUNCEBACK-FEE-CAP` | Deposit bounce-back fee is computed from the configured `bouncebackGas` at processing time and capped at the bounced amount | 🟢 | Refund accounting can underflow or overpay the admin |
| `TEMPO-ZONE-DEPOSIT-BOUNCEBACK-FEE-NONBLOCKING` | A failed deposit-bounce-back fee transfer never reverts `processWithdrawal`; processing completes and the admin keeps the fee only when its transfer succeeds | 🟡 | A fee-transfer failure can stall the withdrawal queue or block exits |
| `TEMPO-ZONE-BOUNCEBACK-FUNDS-PRESERVED` | When a bounce-back's final transfer/mint reverts, funds are credited to `_refunds[token][recipient]` (portal-side for deposit bounce-backs, `ZoneInbox`-side for withdrawal bounce-backs) and `claimRefund` zeroes the balance before paying | 🔴 | Funds whose bounce-back fails can be lost, double-claimed, or stuck |
| `TEMPO-ZONE-BOUNCEBACK-TERMINAL` | Internal withdrawal bounce-backs are the only `DepositType.WithdrawalBounceBack` entries; their canonical payload contains only `token`, the encoded fallback nonce in `to`, and `amount`. Rejected or malformed bounce-back entries revert, and a failed bounce-back routes to the refund registry instead of re-bouncing | 🔴 | A bounce-back can re-bounce indefinitely, looping the deposit/withdrawal queues or stalling processing |

### Batch Submission and Proofs

| ID | Assertion | Crit | Impact |
|---|---|---|---|
| `TEMPO-ZONE-BATCH-PREV-HASH` | Submitted `blockTransition.prevBlockHash` equals the portal's current `blockHash` | 🔴 | A batch can fork from an uncommitted zone state |
| `TEMPO-ZONE-BATCH-NEXT-HASH` | Accepted proof output commits to the full next zone block hash, including state, transactions, receipts, number, timestamp, beneficiary, and protocol version | 🔴 | Proof can validate a different state transition than the portal records |
| `TEMPO-ZONE-BATCH-DEPOSIT-TRANSITION` | Deposit transition starts from the inbox's previous processed hash/number and ends at the post-batch processed hash/number | 🔴 | Deposits can be skipped, replayed, or falsely marked processed |
| `TEMPO-ZONE-BATCH-WITHDRAWAL-COMMITMENT` | Submitted `withdrawalQueueHash` equals `ZoneOutbox.lastBatch.withdrawalQueueHash` from the proven post-state | 🔴 | Portal can enqueue withdrawals that the zone never finalized |
| `TEMPO-ZONE-BATCH-ANCHOR-BLOCK` | Anchor block number/hash passed to the verifier matches either the direct Tempo binding or a valid ancestry chain to a recent Tempo block; when non-zero, `recentTempoBlockNumber > tempoBlockNumber` | 🔴 | Proof can rely on a stale or forged Tempo view |
| `TEMPO-ZONE-BATCH-SEQUENCER-BENEFICIARY` | Every non-genesis proven zone block has `beneficiary == portal.sequencer`; the genesis block matches the canonical header in full | 🟡 | A non-sequencer can produce blocks or collect block-level authority |
| `TEMPO-ZONE-BATCH-FINALIZE-LAST` | Intermediate blocks do not finalize withdrawals; the final block executes `finalizeWithdrawalBatch` last | 🔴 | Withdrawals can be omitted from the committed state or finalized before later user transactions |
| `TEMPO-ZONE-PROOF-MISSING-READS` | Any zone-state or Tempo-state read missing from the witness causes proof failure; missing reads never default silently | 🔴 | Prover can omit non-zero state and prove an invalid transition |

### Tempo State Reads and TIP-403

| ID | Assertion | Crit | Impact |
|---|---|---|---|
| `TEMPO-ZONE-TEMPO-HEADER-CONTINUITY` | `TempoState.finalizeTempo` only accepts headers whose parent hash and block number continue from the previous finalized Tempo header | 🔴 | Zone reads can bind to a forged or discontinuous Tempo history |
| `TEMPO-ZONE-TEMPO-READ-METERING` | Native Tempo storage reads charge 2,100 gas on the first transaction-local access to an account/slot and 100 gas on subsequent accesses; EVM-overlay reads use ordinary cold/warm SLOAD pricing and are not charged twice | 🔴 | Unpriced native read loops or double-charged overlay reads can cause resource exhaustion or inconsistent gas accounting |
| `TEMPO-ZONE-TEMPO-READ-ROOT` | Every Tempo storage read is proven against the `tempoStateRoot` bound at the block where the read occurs | 🔴 | Configuration, token, policy, or queue reads can be forged |
| `TEMPO-ZONE-TIP403-INHERITANCE` | Zone token transfer, mint, and withdrawal paths enforce the TIP-403 policy inherited from the current finalized Tempo view | 🔴 | Blacklisted or unauthorized accounts can move, receive, mint, or withdraw funds |
| `TEMPO-ZONE-TIP403-READONLY` | Zone-side TIP-403 registry/proxy cannot mutate policy state | 🟡 | A zone user or sequencer can diverge policy from Tempo |

### Zone Execution and Privacy

| ID | Assertion | Crit | Impact |
|---|---|---|---|
| `TEMPO-ZONE-ADVANCE-TEMPO-FIRST` | When present, `advanceTempo` is the first transaction in a zone block | 🟡 | User transactions can execute against the wrong Tempo binding or stale config |
| `TEMPO-ZONE-CONTRACT-CREATION-DISABLED` | User `CREATE` and `CREATE2` always revert on zones | 🟡 | Users can deploy contracts that bypass privacy and system-token assumptions |
| `TEMPO-ZONE-BALANCE-ALLOWANCE-PRIVACY` | `balanceOf(account)` reveals values only to `account`; `allowance(owner, spender)` reveals values only to `owner` or `spender` | 🟡 | Account balances and approvals leak through token precompiles |
| `TEMPO-ZONE-ACCOUNT-GETTER-PRIVACY` | Account-indexed `NonceManager` and `AccountKeychain` getters reveal values only when their immediate caller owns the queried account | 🟡 | Forwarding contracts or ordinary users can expose another account's nonce activity, keys, limits, call scopes, or authorization metadata |
| `TEMPO-ZONE-REFUND-READ-PRIVACY` | `ZoneInbox.refunds(token, owner)` reveals a value only when its immediate caller is `owner` or an active sequencer | 🟡 | Forwarding contracts can expose another account's pending refund balance |
| `TEMPO-ZONE-FIXED-TOKEN-GAS` | TIP-20 transfer and approve operations charge fixed gas independent of account storage layout | 🟢 | Gas timing leaks whether addresses have prior token activity |
| `TEMPO-ZONE-BLOCK-TIMESTAMP-MONOTONIC` | Zone block timestamps are non-decreasing and block numbers increment by one | 🟢 | Time-dependent application logic and proof replay assumptions can break |

### Redacted RPC

| ID | Assertion | Crit | Impact |
|---|---|---|---|
| `TEMPO-ZONE-RPC-TOKEN-DOMAIN` | Authorization tokens bind to `TempoZoneRPC`, version, zone ID or wildcard zero, chain ID, `issuedAt`, and `expiresAt` | 🟡 | Tokens can be replayed across zones, chains, or protocol versions |
| `TEMPO-ZONE-RPC-TOKEN-LIFETIME` | Tokens expire, are not valid too far in the future, and never exceed the 30-day maximum validity window | 🟡 | Long-lived or future-dated tokens can preserve unauthorized access |
| `TEMPO-ZONE-RPC-SENDER-SCOPING` | `eth_sendRawTransaction`, `eth_call`, and `eth_estimateGas` require the authenticated account to match the transaction or call sender | 🟡 | Users can simulate or submit transactions as other accounts |
| `TEMPO-ZONE-RPC-ACCOUNT-QUERY-SCOPING` | `eth_getBalance`/`eth_getTransactionCount` return `0x0` for non-self queries and `eth_getTransactionByHash`/`eth_getTransactionReceipt` return `null` when the caller is not the sender | 🟡 | Users can read other accounts' balances, nonces, or transactions, or probe account existence |
| `TEMPO-ZONE-RPC-RAW-STATE-SEQUENCER-ONLY` | Raw state, full transaction/block, debug/admin/txpool, proof, and pending-transaction methods are unavailable to non-sequencers | 🟡 | Private transaction, storage, and mempool data leaks |
| `TEMPO-ZONE-RPC-BLOCK-REDACTION` | Non-sequencer block responses have empty `transactions` and zeroed `logsBloom` | 🟡 | Users can infer other users' activity from block payloads or bloom probes |
| `TEMPO-ZONE-RPC-LOG-SCOPING` | Log queries and subscriptions only return TIP-20 events where the authenticated account is a relevant party | 🟡 | Users can observe other users' transfers, approvals, mints, or burns |
| `TEMPO-ZONE-RPC-TIMING-FLOOR` | Scoped data-fetching methods enforce the minimum response time before returning negative results | 🟢 | Timing differences leak transaction or log existence |
| `TEMPO-ZONE-RPC-KEYCHAIN-REVOCATION` | Keychain-authenticated WebSocket connections terminate within one second of importing a revocation block | 🟡 | Revoked session keys can keep observing private zone activity |
