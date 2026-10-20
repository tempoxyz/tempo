# Zone forced exits: technical design

A user requests withdrawal of the full liquid balance of one token from a Zone account through the encrypted L1 inbox. This requires a live sequencer that is submitting proofs. Partial withdrawals, arbitrary forced transactions and exits after operator failure are out of scope.

The four steps below describe admission, execution, proof/settlement, and delivery. The STF (state transition function) executes in Step 2 and is replayed by the prover in Step 3 (i.e. these are the same transition rules in both steps)

## Overview

1. **Request on L1:** The user signs and encrypts an exit authorization, and the portal collects and pays the fixed 0.1-token fee to its L1 admin and queues the request.
2. **Process on Zone:** The sequencer decrypts and validates the request through the STF, which burns the account's full liquid token balance at processing time and creates a withdrawal, or records an empty or rejected outcome.
3. **Prove and settle:** The prover replays the same STF, and L1 settlement verifies the proof and authenticates the outcomes and resulting withdrawals.
4. **Deliver on L1:** The sequencer processes the withdrawal through the normal queue, paying the recipient or bouncing the principal back to the Zone account if payment fails.

## Step 1: Request on L1

The client signs the authorization, encrypts it together with the signature using the Zone's published encryption key, and submits the encrypted request to the portal.

```solidity
uint128 constant FORCED_EXIT_COMPENSATION = 100_000;

struct ForcedExitAuthorization {
    address account;
    uint256 zoneChainId;
    address token;
    address recipient;
    uint256 nonce;
    uint64 admitBefore;      // Exclusive L1 admission deadline; not an execution deadline
}

function requestForcedExit(
    address token,
    uint256 keyIndex,
    DepositPayload calldata encrypted
) external returns (uint64 requestId, uint64 depositNumber);

struct ForcedExit {
    uint64 requestId;
    address token;
    uint256 keyIndex;
    DepositPayload encrypted;
    address feePayer;
    uint64 requestedAtBlock;
    uint64 requestedAtTime;
}
```

EIP-712 domain: name `TempoZoneForcedExit`, version `1`, L1 chain ID, verifying contract equal to the portal. The canonical signed type is `ForcedExitAuthorization(address account,uint256 zoneChainId,address token,address recipient,uint256 nonce,uint64 admitBefore)`.

### Encryption

This is the current live-sequencer design. Use the existing `DepositPayload` ABI unchanged: `ephemeralPubkeyX`, `ephemeralPubkeyYParity`, `ciphertext`, `nonce`, and `tag`. As with `Deposit`, `keyIndex` belongs to the outer queued struct, not the encryption envelope. 

Client plaintext is `abi.encode(uint8(1), authorization, signature)`, with strict canonical decoding and a bounded signature envelope. Use a fresh ephemeral key and GCM nonce for every encryption. Reuse secp256k1 ECDH, the existing HKDF salt and context `(portal, keyIndex, ephemeralPubkeyX, sender)`, AES-256-GCM, and empty AAD. Here `sender` is the fee payer (`msg.sender`), captured by the portal; a client using a relayer must encrypt for that relayer address. The forced-exit EIP-712 domain and versioned plaintext distinguish this operation from deposits; the forced plaintext cannot pass the existing 64-byte deposit decoder.

The deposit plaintext is fixed at 64 bytes. Forced authorization plus signature is larger: share the envelope and cryptographic helpers, but add a separate bounded forced-exit codec and ciphertext-length validation. Do not change the existing deposit encoding or its 64-byte rule. Pin maximum ciphertext/signature sizes for the enabled signature schemes before activation; arbitrary unbounded ciphertext is not admissible. The minimum encodable plaintext length and ABI alignment are checked at admission, and exact canonical encoding is checked after decryption.

### L1 admission

`requestId` is portal-local, monotonic, nonzero and distinct from the global deposit number. Append `DepositType.ForcedExit = 2`, preserving existing discriminants and encodings.

The portal validates the public enabled token, ciphertext envelope/size, ephemeral-point validity, encryption key using the existing deposit key-validity and rotation-grace rules, and queue capacity. It collects exactly `FORCED_EXIT_COMPENSATION` from `msg.sender` and immediately transfers it to the portal’s `admin` on L1, assigns request/deposit IDs and admission block/time, and commits the entire entry with `keccak256(abi.encode(DepositType.ForcedExit, entry, previousHash))`. Emit the complete reconstructible encrypted entry using the existing L1 event ingestion/backfill pattern. Fee collection, payment to `admin` and all admission changes are atomic.

Compensation is a protocol constant, not a user-selected amount or a configurable sequencer fee. Follow the existing deposit fee-payment pattern: call `transferFrom(msg.sender, portal, FORCED_EXIT_COMPENSATION)`, then `transfer(admin, FORCED_EXIT_COMPENSATION)` in the request token under native token-transfer policies. Either transfer failing reverts the entire admission, including both transfers, ID allocation and queue changes. The recipient is the portal’s current `admin`, exactly as for deposit fees; it need not be the sequencer leader. Payment is complete at admission, so no compensation recipient or amount is stored in the queued entry or signed authorization. Only supported six-decimal tokens are admissible: `100_000` base units is 0.1 token, not a guaranteed USD amount.

The portal implementation of `requestForcedExit` uses the same `whenNotPaused` gate as ordinary encrypted deposits. Admission while paused reverts before collecting compensation, allocating IDs or changing the queue. L1 delivery follows the existing `processWithdrawals` pause gate, leaving withdrawals queued until delivery is unpaused.

Apply the existing depositor-access check to the fee payer (`msg.sender`), including its existing callback-gateway exception when gateway enforcement is enabled. The token must be enabled and supported, and both fee transfers must satisfy native token pause and TIP-403 rules. The token's `depositsActive` flag does not gate forced requests: it controls incoming principal deposits, whereas a forced request collects only compensation. The hidden exiting account need not be a portal member. Recipient membership and gateway eligibility are checked after decryption as specified in Step 2, then checked again at L1 delivery.

Keep token public because compensation is collected in the selected token, just as deposit token accounting is public. There is no public withdrawal amount at admission: execution determines the full balance. Account, recipient, authorization nonce, admission deadline, and signature remain encrypted. L1 cannot check recipient policy, the signed admission deadline, or authorization-digest deduplication at admission. Check these inside Zone execution. Do not publish the plaintext authorization digest merely for deduplication; use the Zone-local consumed authorization nonce map. Ciphertext duplication does not replace authorization replay protection.

A forced withdrawal request has no deposit-refund recipient or admission-principal refund path. A withdrawal created by successful Zone execution has the normal withdrawal bounce-back path described below. If admission reverts, fee collection, payment and queue changes revert atomically. Once admitted, the fee has already been paid to `admin`, even if the request is later rejected, empty, delayed or never processed. Zone execution failure does not undo this L1 payment, and a later withdrawal bounce-back does not refund it.

### Capacity

Forced requests share the same public admission capacity and outstanding-entry accounting as ordinary encrypted deposits; each consumes one queue entry. Preserve the existing reserve for withdrawal-generated entries, including bounce-backs. Size the shared admission limit using worst-case signature verification, authenticated balance/policy reads, ciphertext decryption, outcome storage and settlement calldata/gas, accounting for token initialization within the same execution budget. The entire imported queue head must fit the execution budget; a lower processing cap must not silently skip a suffix.

## Step 2: Process on Zone

Process this variant in canonical inbox order and read the historical encryption key from authenticated L1 storage using `keyIndex`, just as deposits do. Key rotation after admission must not prevent processing an accepted request using its historical key. Reuse `DecryptionData` and Chaum-Pedersen verification to establish the correct ECDH shared secret, then derive the key and decrypt inside shared Zone/SPF execution.

A portal pause after admission does not prevent inbox processing or produce a terminal rejection; token-level restrictions still apply. The forced-exit inbox helper must not inherit the portal-pause check from the ordinary outbox request helper. The admitted request may create a withdrawal while paused, but its L1 delivery waits for the portal to be unpaused.

An absent or invalid Chaum-Pedersen proof invalidates processing; it must never produce a terminal rejected exit. Only after verifying the correct shared secret may an invalid GCM tag or malformed plaintext produce a deterministic invalid-request outcome. A validly decrypted but unauthorized request also produces a deterministic rejection. Never trust `QueuedDeposit.rejected` for this variant. Malformed authenticated outer protocol data and missing witnesses remain fatal execution errors. 

After decryption, verify the signed domain/Zone, public token equality, admission deadline, root-key authorization and nonce. Evaluate token and recipient policy failures separately from authorization, using the failure semantics below. Require nonzero account/recipient. The account’s own root key must sign the authorization: verify the signature over the canonical EIP-712 digest and require the recovered or derived signer address to equal `account`. Access keys and delegated keychain signatures cannot authorize a forced exit, even if active or otherwise permitted to spend from the account. Require authenticated L1 `requestedAtTime < admitBefore`; equality is expired and zero grants no unlimited-deadline exception. This is an admission deadline, not an execution deadline: a request admitted in time may execute later, subject to the processing-time authorization and policy checks above, and withdraw the full liquid balance then present, including funds received after admission. Passing `admitBefore` does not cancel an admitted request. Invalid requests still pay the fixed admission processing fee.

Signature envelopes must use explicitly supported Tempo-compatible schemes with strict canonical decoding, including rejection of trailing data and unsupported versions. V1 excludes arbitrary ERC-1271 callbacks and counterfactual accounts. Accept only supported primitive root-signature envelopes and reject access-key/keychain envelopes. There is no signing-key selector in the authorization; derive the signer identity from the verified signature. The outer `keyIndex` still selects the Zone encryption key and does not select the account signing key. Pin cross-language type-hash and signature vectors.

For a fresh authorized nonzero-balance request, evaluate execution policies against authenticated state at the imported L1 anchor: require the token to be enabled, require the signed recipient to hold `Role.Account` when portal access enforcement is enabled, and reject a recipient with `Role.CallbackGateway` when gateway enforcement is enabled because this is a plain withdrawal. Require the native token pause and TIP-403 checks used by the debit path, including the debited account's sender eligibility; do not bypass them when bypassing the allowance requirement. The exiting account's portal membership and the token's `depositsActive` flag are not execution requirements. Apply the recipient checks to the L1 destination; do not require it to hold a Zone balance or have a Zone signing key. L1 delivery independently rechecks its current recipient resolution, portal membership/gateway rules and TIP-403 receive policy for `portal → recipient`, and performs the native token transfer. A later delivery failure follows the ordinary bounce-back path.

The sequencer must supply valid decryption material and execute every imported forced entry to produce a valid accepted transition. Reuse the existing authenticated queue and proof pipeline. This does not itself force checkpoint import or continued block production: the guarantee is conditional on live execution and enforced inclusion. Do not describe queue correctness alone as a deadline or operator-failure guarantee.

Each forced exit consumes exactly one `DecryptionData` in the mixed inbox stream, just like an encrypted deposit; bounce-backs consume none. Missing or extra entries invalidate processing.

For a successfully authenticated request, the shared STF derives its outcome as follows; requests rejected during decryption or authorization skip this sequence and go directly to the common terminal finalization below:

1. Checks the dedicated Zone-local `(account, nonce)` replay map. After successful authorization, consumes the nonce even for an empty balance or deterministic policy failure; invalid authorization cannot consume another account's nonce.
2. Reads the liquid balance `B` through authenticated state witnesses.
3. Rejects unsupported `uint128` overflow without truncation, otherwise produces `Empty` for zero balance, otherwise checks applicable token and recipient policies. An applicable policy failure produces a deterministic `Rejected(reason)`. These outcomes do not debit principal.
4. Otherwise burns exactly `B` using an inbox-only outbox helper, without a preexisting user allowance or ordinary withdrawal fee. Token accounting/reward/policy hooks remain atomic with the debit.
5. Enqueues a normal plain withdrawal to the signed recipient and derives `Exited(B)` and the exact withdrawal hash for terminal finalization. Allocate a nonzero fallback nonce from the existing outbox counter and map it to the signed `account` in Zone state, so failed L1 delivery returns principal to the account that was debited. Principal debit, reward hooks, fallback registration and withdrawal enqueue are one atomic attempt. Record `Exited(B)` only when that attempt succeeds; the failure table below defines rejection and fatal rollback boundaries. Use request-ID-based public attribution, not the plaintext authorization digest.

All terminal paths converge on a common finalization step: record exactly one outcome and consume the inbox entry. This includes invalid ciphertext after a valid decryption proof, invalid authorization, replay, policy rejection, empty balance and successful withdrawal creation. No terminal rejection may return before this finalization. Fatal errors bypass terminal finalization and abort the enclosing transition, rolling back all Zone effects, including any earlier requests' effects in that transition.

The debit helper must reuse upstream TIP-20 supply, rewards and policy hooks, not raw balance-slot writes or an unrestricted arbitrary-account burn API. Reuse the existing `Withdrawal` encoding: set plain withdrawal callback data empty, gas limit zero, memo zero and encrypted sender empty. Set `senderTag` to `keccak256(abi.encode("TempoZoneForcedExit", portal, requestId))` for public request attribution without revealing the account. Bind the exact withdrawal, including its fallback nonce, to the outcome; no `forcedExitId` field or new withdrawal encoding is required.

L1 admission enforces collection and immediate payment of the fixed fee. Authenticated inclusion in the portal queue establishes that these admission rules succeeded; the STF does not pay, mint, credit or refund compensation. There is no Zone compensation ledger or claim function. No user transaction interleaves within inbox processing. Later requests see the resulting balance. Requests do not freeze funds at admission.

### Processing outcomes and failure semantics

The table describes committed Zone effects for one admitted request. Every terminal outcome consumes that inbox entry. In every row, the fee was already paid on L1 at admission and is unchanged by Zone execution, including an aborted transition. Consuming an inbox entry is distinct from consuming the signed `(account, nonce)`: an invalid request must not reserve another account's authorization nonce. “No change” below means no change attributable to this request.

| Condition | Processing result | Authorization nonce | Principal and withdrawal |
| --- | --- | --- | --- |
| Missing/extra decryption data, invalid Chaum-Pedersen proof, missing state witness, or malformed authenticated outer entry | Abort transition; no terminal outcome | Roll back | Roll back all effects |
| Correctly proven shared secret, but invalid GCM tag or noncanonical/malformed plaintext | Terminal `Rejected(reason)` | No change | No change; no withdrawal |
| Invalid/unsupported signature, wrong domain/Zone or public token, zero account/recipient, or admission deadline not met | Terminal `Rejected(reason)` | No change | No change; no withdrawal |
| Signature is valid for a different account, or uses an access-key/keychain envelope | Terminal `Rejected(reason)` | No change | No change; no withdrawal |
| Otherwise authorized request reuses a consumed nonce | Terminal `Rejected(reason)` | Already consumed; no change | No change; no withdrawal |
| Fresh authorized request has a balance exceeding the supported `uint128` range | Terminal `Rejected(reason)` | Consume | No change; no withdrawal |
| Fresh authorized request has zero balance | Terminal `Empty` | Consume | No change; no withdrawal |
| Fresh authorized request has a deterministic token/recipient policy failure, including a classified policy revert during the debit attempt | Terminal `Rejected(reason)` | Consume | Roll back the entire debit attempt, including reward hooks, fallback registration and withdrawal enqueue |
| Fresh authorized request successfully debits the full balance and enqueues its withdrawal | Terminal `Exited(B)` | Consume | Debit exactly `B` and enqueue one withdrawal atomically |
| Out of gas, execution-capacity exhaustion, internal invariant failure, or an unclassified execution error, including after debit | Abort transition; no terminal outcome | Roll back | Roll back all effects |

Apply checks in canonical order: decryption proof, ciphertext/codec, signed fields and authorization, replay, balance overflow, zero balance, applicable token/recipient policies, then the debit attempt. A valid zero-balance request produces `Empty` before token/recipient policy evaluation. Pin the order of checks within each category and the versioned public reason codes so the host cannot choose among rejection reasons. Fatal witness or execution errors encountered at any stage take precedence over a terminal outcome.

Use a nested storage checkpoint for the debit attempt. Catch only explicitly classified deterministic policy errors: roll back that checkpoint, then record `Rejected(reason)` and nonce consumption outside it through common terminal finalization. On success, commit the attempt and record `Exited(B)`. The enclosing transition still commits or rolls back the attempt, nonce, outcome and inbox cursor together. Never turn an arbitrary error into a user rejection, and never preserve a successful outcome from an aborted transition. The L1 admission transaction is separate: its completed fee payment to `admin` is unaffected when Zone execution aborts.

Temporary outbox limits must not cause terminal rejection or nonce consumption. Ensure the outbox limits can accommodate withdrawals produced by the admitted inbox workload within the shared execution budget; exhaustion is an execution failure to resolve before producing an accepted transition, not grounds to skip a queue suffix.

### Request rejection and withdrawal bounce-back

Reuse deposit encryption and queue infrastructure, but do not route forced requests through the ordinary deposit refund handler. A rejected or empty forced request creates no principal withdrawal, refund, or `WithdrawalBounceBack` entry; the account principal remains unchanged. A request whose debit attempt fails must roll back the attempt and follow the rejection or fatal-error rules above; it must not create a bounce-back to compensate for partially applied Zone execution. Missing witnesses or invalid decryption proofs still invalidate processing rather than consuming the request as a rejection.

After successful execution and settlement, the resulting withdrawal follows ordinary L1 delivery and withdrawal bounce-back behavior. Failed L1 delivery enqueues a `WithdrawalBounceBack` entry returning the principal to the signed Zone account through its fallback nonce. This is distinct from rejecting a request before a withdrawal exists.

Existing deposit refunds and withdrawal bounce-backs, including those from forced withdrawals, may coexist in the same inbox. A forced exit processes after any preceding entries, so funds credited by an earlier bounce-back contribute to its processing-time balance. Funds credited by a later bounce-back are not included in an already processed exit. The original authorization nonce remains consumed; a later forced withdrawal requires a new authorized request and processing compensation, or the user may request an ordinary withdrawal under its normal rules.

## Step 3: Prover and the STF

The prover replays the same STF used in Step 2 against authenticated Zone and L1 witnesses. It verifies the queue commitment/order, historical encryption key and decryption proof, the account’s root signature, signed authorization fields and nonce, exact full-balance debit, fallback-nonce registration to the debited account, and resulting withdrawal/outcome. Fee payment is enforced by authenticated L1 admission, not replayed as a Zone state change. Missing witnesses or a forged decryption proof invalidate the transition; the host cannot choose a rejection reason.

The batch includes an ordered public outcome array:

```solidity
struct ForcedExitOutcome {
    uint64 requestId;
    uint64 depositNumber;
    address token;
    address recipient;       // Zero unless Exited
    uint8 status;            // Exited, Empty, Rejected
    uint16 reason;           // Versioned code; zero on success
    uint128 amount;          // Zero unless Exited
    bytes32 withdrawalHash; // Zero unless Exited
}
```

For an `Exited` outcome, define `withdrawalHash = keccak256(abi.encode(withdrawal))`, using the complete existing Solidity `Withdrawal` struct in its declared field order, including `senderTag`, `fallbackNonce` and the empty dynamic fields. Use standard ABI encoding, not packed encoding. This hashes the individual withdrawal without a queue suffix. The existing queue link remains `keccak256(abi.encode(withdrawal, remainingQueue))`; the proof must bind the exact same withdrawal to both its outcome hash and that batch's withdrawal queue commitment. `Empty` and `Rejected` outcomes have `withdrawalHash = bytes32(0)`. Pin Solidity/Rust vectors for both encodings.

Bound the outcome array by the measured execution and settlement budget. Commit `keccak256(abi.encode(outcomes))`, including the canonical empty array, in batch output, proof/attestation inputs, settlement quorum digest and verifier inputs, together with the existing chain/portal, L1 anchor, parent/next Zone transition, deposit queue, token transition and withdrawal commitments. Every consumed forced request must have exactly one outcome; a successful exit must enter that batch's withdrawal commitment. Checkpoint-only blocks cannot count as processing an exit.

The sequencer submits the batch and matching proof to L1. An enforcing verifier must reject forged, empty, wrong-image/version, stale-parent or mismatched-input proofs. For Nitro, the attestation must bind the approved image, AWS attestation trust checks and exact execution digest. 

After verification, the portal checks request/deposit identity and token against admission metadata, rejects unknown requests, omitted/duplicate/reordered outcomes and status regressions, and authenticates each successful withdrawal once for normal queue delivery. The proof binds the recipient to the decrypted authorization; L1 cannot read that recipient at admission. Failed outcomes have zero recipient, amount and withdrawal hash.

`Exited` records successful Zone debit and withdrawal creation, not successful L1 payment. Later delivery or bounce-back does not rewrite that processing outcome. Status tooling reports delivery and bounce-back progress separately using the existing withdrawal and inbox events.

This proves correct processing of imported requests. It does not independently compel checkpoint import or continued production, so this version makes no bounded-time inclusion or operator-failure guarantee.

## Step 4: Withdrawal on L1

After the proven batch settles, the sequencer calls the existing `processWithdrawals` to deliver the forced withdrawal in normal FIFO order. Funds go to the authenticated recipient. 

Use the existing withdrawal encoding, queue hashes and fallback-nonce semantics. The authenticated outcome binds the request to its exact withdrawal. Delivery uses the existing sequencer authorization, portal pause gate, token/recipient policy checks, deposit-capacity preflight and reentrancy protection.

Process the withdrawal exactly like a normal plain withdrawal. On successful transfer, consume it through normal queue accounting so it cannot be paid again. If delivery fails, consume the withdrawal and enqueue one `WithdrawalBounceBack` entry with the same token, full principal amount and fallback nonce. Continue processing later withdrawals under the existing rules; a blocked recipient does not retain the failed withdrawal at the queue head. A transaction-level revert, including a pause or capacity failure, rolls back these effects under the existing behavior.

The Zone processes the bounce-back through the existing inbox handler: consume the fallback mapping once and attempt to mint the principal back to the signed account under current token policy. If minting is blocked, record the amount in the existing pending withdrawal-bounce-back credit ledger for later claim through its policy-aware claim path. No new recovery ledger or delivery path is needed. Neither the bounce-back nor claiming its pending credit re-executes the original forced request or charges its processing compensation again. The original nonce remains consumed and compensation remains earned; another forced withdrawal requires a new authorization and fee.

Encryption hides account, recipient and authorization at request time from public L1 observers. The public request still exposes fee payer, token, compensation, key index, timing and ciphertext length. Successful settlement reveals recipient and withdrawn amount; no account or plaintext authorization/digest is required for delivery. This is deposit-style request privacy, not settlement balance privacy or unlinkability, and the sequencer and authorized readers of execution/decryption material can decrypt the request. Public failure reasons must be bounded protocol codes, never decrypted payloads.

### Accounting invariants

For each token, admission collects the fixed fee and transfers the same amount to `admin` on L1, leaving portal principal backing and Zone account balances unchanged. The fee creates no pending liability or Zone credit. Processing converts the Zone principal into a pending withdrawal. Settlement authenticates that withdrawal without changing escrow balance. Successful delivery reduces backing and the single withdrawal liability by the same amount. Failed delivery leaves backing unchanged and replaces the withdrawal liability with one queued bounce-back liability. Zone bounce-back processing replaces that liability with either reminted principal or an existing pending bounce-back credit; claiming a credit replaces it with minted principal. These are alternative states of one backed liability, never simultaneous claims to the same principal. The outcome is a processing record, not an additional liability. Preserve ordinary deposit, refund and withdrawal backing throughout, including token supply/reward hooks.

## Activation requirements and open parameters

V1 fixes `FORCED_EXIT_COMPENSATION` at `100_000` base units. Changing it requires a versioned portal admission change and an updated signed authorization domain version so existing signatures cannot authorize requests at the new fee. Already-admitted requests have paid their fee and are neither charged again nor refunded when processing crosses an upgrade boundary. Keep the STF and proof verifier compatible with each admitted authorization version; there is no processing-time compensation amount to migrate.

Portal storage includes feature/config version, request counter, encrypted-entry identity/token/deposit metadata and outcomes. Zone storage includes authorization nonces and pending outcomes, and reuses the existing fallback-recipient mapping and pending withdrawal-bounce-back credits. Append storage without reordering existing slots; update Solidity layouts and Rust witness/storage views together and regenerate ABI/layout/runtime artifacts through repository tooling.

Keep pure codecs, authorization digests and validation helpers in `exithatch`; stateful execution remains in existing inbox/outbox precompiles. Propagate the typed entry through L1 event ingestion, canonical reconstruction and restart/backfill; propagate outcomes through builder, executor, SPF, proof/quorum inputs and settlement. Checker and CLI tooling must support backing/outcome inspection and sign/encrypt/request/status operations.


### Notes: Validations and Tests

- Round-trip vectors using the existing envelope, HKDF context, historical keys, and `DecryptionData`; wrong portal/sender/key and tampered ciphertext cases.
- Mixed deposits, forced exits, and bounce-backs preserve queue hashes and exact decryption ordering; existing deposit vectors remain unchanged.
- Missing or forged decryption proof cannot consume a forced request; correctly proven invalid ciphertext produces a deterministic failure.
- Authorization replay, signed/public token mismatch, admission deadline boundaries (before/equal/after, including zero), execution after the admission deadline with later-received funds, wrong-account signatures, rejection of access-key/keychain envelopes, and atomic full-balance processing.
- Public settlement recipient/token/amount cannot be substituted; plaintext authorization is absent from L1 admission calldata/events.
- Enforcing settlement rejects forged/empty/mismatched proofs and omitted outcomes; checkpoint-only blocks cannot satisfy requests.
- Sequencer `processWithdrawals` uses the existing plain-withdrawal encoding and behavior: each withdrawal is consumed once by payment or bounce-back enqueue, failed transfers do not block the suffix, and transaction-level reverts preserve atomic payment/bounce-back/cursor accounting.
- Rejected/empty forced requests create no principal refund or bounce-back. Failed L1 delivery creates exactly one normal bounce-back for the full principal, with the authenticated fallback nonce resolving only to the debited Zone account; replay cannot pay or remint twice.
- Bounce-back processing remints to the debited account or records an existing pending bounce-back credit when policy blocks minting. Later claims remain policy-aware and cannot duplicate principal. The original authorization nonce remains consumed, compensation is not refunded or charged again for recovery, and a new forced request requires a new authorization and fee.
- Bounce-backs before and after a forced request affect only the appropriate processing-time balance; existing deposit refunds and ordinary withdrawal bounce-backs remain unchanged. Processing outcomes remain stable while tooling tracks payment, bounce-back and pending-credit progress separately.

- Exercise every row of the failure-semantics table, including replay versus inbox consumption, canonical failure precedence, policy failure after burn, and fatal failure after an earlier request in the same transition. Verify the specified nonce, principal, reward, fallback, outcome and cursor effects or rollback; completed L1 admission payments remain unaffected.
- Full-balance zero/dust/max/overflow, admin address equal to the exiting account (fee payment changes only its L1 balance), withdrawal-capacity exhaustion, and supply/backing reconciliation.
- Admission collects exactly `FORCED_EXIT_COMPENSATION` and immediately pays the same amount to the current portal `admin` on L1, matching deposit fee handling. Failure of either transfer, including a blocked admin or paused token, rolls back the entire admission. Later admin/leader changes do not trigger another payment.
- Paused admission matches encrypted deposits: no fee collection, ID allocation or queue mutation. Requests admitted before a portal pause can still process through the inbox without a pause-induced rejection; L1 delivery remains queued while paused and resumes under the normal rules after unpausing.
- Deposits and forced requests consume the same public admission capacity, reject when that shared capacity is full, and cannot consume the existing withdrawal-processing reserve; there is no separate forced-request allowance.
- Admission applies the existing fee-payer depositor-access rules; an enabled token with `depositsActive = false` still admits a forced request if both fee transfers are permitted. A nonmember exiting account may withdraw to an eligible recipient, but native token restrictions remain enforced. Check recipient membership/gateway changes at execution and delivery separately.
- Every terminal path, including invalid ciphertext and invalid signatures, reaches common outcome/cursor finalization; fatal errors roll back all Zone effects of the enclosing transition without undoing the earlier L1 fee payment.
- Processing, rejection, empty outcomes, execution retries and bounce-back recovery neither pay nor mint compensation; no Zone compensation ledger or claim API is introduced.
- Individual withdrawal hashes match standard Solidity/Rust ABI vectors, exclude the queue suffix and bind every withdrawal field; substituting a field or a suffix-dependent queue hash cannot satisfy the outcome commitment.
- Admission fee-transfer failure, membership/token policy behavior, no recharging of admitted requests across upgrades and signed-domain version separation, and maximum mixed execution/settlement budgets.
- Restart/backfill and finality handling, coordinated activation with pending legacy deposits/withdrawals, storage/ABI compatibility, and reentrancy attempts during delivery.
