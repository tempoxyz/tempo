# Tempo Invariants

## Stablecoin DEX

### Order Management

- **TEMPO-DEX1**: Newly created order ID matches next order ID and increments monotonically.
- **TEMPO-DEX2**: Placing an order escrows the correct amount - bids escrow quote tokens (rounded up), asks escrow base tokens.
- **TEMPO-DEX3**: Cancelling an active order refunds the escrowed amount to the maker's internal balance.

### Swap Invariants

- **TEMPO-DEX4**: `amountOut >= minAmountOut` when executing `swapExactAmountIn`.
- **TEMPO-DEX5**: `amountIn <= maxAmountIn` when executing `swapExactAmountOut`.
- **TEMPO-DEX14**: Swapper total balance (external + internal) changes correctly - loses exact `amountIn` of tokenIn and gains exact `amountOut` of tokenOut. Skipped when swapper has active orders (self-trade makes accounting complex).
- **TEMPO-DEX16**: Quote functions (`quoteSwapExactAmountIn/Out`) return values matching actual swap execution.
- **TEMPO-DEX18**: Dust invariant - each swap can at maximum increase the dust in the DEX by the number of orders filled.
- **TEMPO-DEX19**: Post-swap dust bounded - maximum dust accumulation in the protocol is bounded and tracked via `_maxDust`.

### Balance Invariants

- **TEMPO-DEX6**: DEX token balance >= sum of all internal user balances (the difference accounts for escrowed order amounts).

### Orderbook Structure Invariants

- **TEMPO-DEX7**: Total liquidity at a tick level equals the sum of remaining amounts of all orders at that tick. If liquidity > 0, head and tail must be non-zero.
- **TEMPO-DEX8**: Best bid tick points to the highest tick with non-empty bid liquidity, or `type(int16).min` if no bids exist.
- **TEMPO-DEX9**: Best ask tick points to the lowest tick with non-empty ask liquidity, or `type(int16).max` if no asks exist.
- **TEMPO-DEX10**: Order linked list is consistent - `prev.next == current` and `next.prev == current`. If head is zero, tail must also be zero.
- **TEMPO-DEX11**: Tick bitmap accurately reflects which ticks have liquidity (bit set iff tick has orders).
- **TEMPO-DEX17**: Linked list head/tail is terminal - `head.prev == None` and `tail.next == None`

### Flip Order Invariants

- **TEMPO-DEX12**: Flip orders have valid tick constraints - for bids `flipTick > tick`, for asks `flipTick < tick`.

### Blacklist Invariants

- **TEMPO-DEX13**: Anyone can cancel a stale order from a blacklisted maker via `cancelStaleOrder`. The escrowed funds are refunded to the blacklisted maker's internal balance.

## FeeAMM

The FeeAMM is a constant-rate AMM used for converting user fee tokens to validator fee tokens. It operates with two fixed rates:

- **Fee Swap Rate (M)**: 0.9970 (0.30% fee) - Used when swapping user tokens to validator tokens during fee collection
- **Rebalance Rate (N)**: 0.9985 (0.15% fee) - Used when liquidity providers rebalance pools

### Liquidity Management Invariants

- **TEMPO-AMM1**: Minting LP tokens always produces a positive liquidity amount when the deposit is valid.
- **TEMPO-AMM2**: Total LP supply increases correctly on mint - by `liquidity + MIN_LIQUIDITY` for first mint, by `liquidity` for subsequent mints.
- **TEMPO-AMM3**: Actor's LP balance increases by exactly the minted liquidity amount.
- **TEMPO-AMM4**: Validator token reserve increases by exactly the deposited amount on mint.

### Burn Invariants

- **TEMPO-AMM5**: Burn returns pro-rata amounts - `amountToken = (liquidity * reserve) / totalSupply` for both user and validator tokens.
- **TEMPO-AMM6**: Total LP supply decreases by exactly the burned liquidity amount.
- **TEMPO-AMM7**: Actor's LP balance decreases by exactly the burned liquidity amount.
- **TEMPO-AMM8**: Actor receives the exact calculated token amounts on burn.
- **TEMPO-AMM9**: Pool reserves decrease by exactly the returned token amounts on burn.

### Rebalance Swap Invariants

- **TEMPO-AMM10**: Rebalance swap `amountIn` follows the formula: `amountIn = (amountOut * N / SCALE) + 1` (rounds up).
- **TEMPO-AMM11**: Pool reserves update correctly - user reserve decreases by `amountOut`, validator reserve increases by `amountIn`.
- **TEMPO-AMM12**: Actor balances update correctly - pays `amountIn` validator tokens, receives `amountOut` user tokens.

### Fee Swap Invariants

- **TEMPO-AMM25**: Fee swap `amountOut` follows the formula: `amountOut = (amountIn * M / SCALE)` (rounds down). Output never exceeds input.
- **TEMPO-AMM26**: Fee swap reserves update correctly - user reserve increases by `amountIn`, validator reserve decreases by `amountOut`. Verified via ghost variable tracking in `simulateFeeCollection`.

### Global Invariants

- **TEMPO-AMM13**: Pool solvency - AMM token balances are always >= sum of pool reserves for that token.
- **TEMPO-AMM14**: LP token accounting - Total supply equals sum of all user LP balances + MIN_LIQUIDITY (locked on first mint).
- **TEMPO-AMM15**: MIN_LIQUIDITY is permanently locked - once a pool is initialized, total supply is always >= MIN_LIQUIDITY.
- **TEMPO-AMM16**: Fee rates are constant - M = 9970, N = 9985, SCALE = 10000.
- **TEMPO-AMM27**: Pool ID uniqueness - `getPoolId(A, B) != getPoolId(B, A)` for directional pool separation.
- **TEMPO-AMM28**: No LP when uninitialized - if `totalSupply == 0`, no actor holds LP tokens for that pool.
- **TEMPO-AMM29**: Fee conservation - `collectedFees + distributed <= totalFeesIn` (fees cannot be created from nothing).
- **TEMPO-AMM30**: Pool initialization shape - a pool is either completely uninitialized (totalSupply=0, reserves=0) OR properly initialized with totalSupply >= MIN_LIQUIDITY. No partial/bricked states allowed.
- **TEMPO-AMM31**: Fee double-count prevention - fees accumulate via `+=` (not overwrite), and `distributeFees` zeros the balance before transfer, preventing the same fees from being distributed twice.

### Rounding & Exploitation Invariants

- **TEMPO-AMM17**: Mint/burn cycle should not profit the actor - prevents rounding exploitation.
- **TEMPO-AMM18**: Small swaps should still pay >= theoretical rate.
- **TEMPO-AMM19**: Must pay at least 1 for any swap - prevents zero-cost extraction.
- **TEMPO-AMM20**: Reserves are always bounded by uint128.
- **TEMPO-AMM21**: Spread between fee swap (M) and rebalance (N) prevents arbitrage - M < N with 15 bps spread.
- **TEMPO-AMM22**: Rebalance swap rounding always favors the pool - the +1 in the formula ensures pool never loses to rounding, even when `(amountOut * N) % SCALE == 0` (exact division case).

- **TEMPO-AMM23**: Burn rounding dust accumulates in pool - integer division rounds down, so users receive <= theoretical amount.
- **TEMPO-AMM24**: All participants can exit with solvency guaranteed. After distributing all fees and burning all LP positions:

  - **Solvency**: AMM balance >= tracked reserves (LPs cannot extract more than exists)
  - **No value creation**: AMM balance does not exceed reserves by more than tracked dust sources
  - **MIN_LIQUIDITY preserved**: Even if all LP holders burn their entire balances pro-rata, MIN_LIQUIDITY worth of reserves remains permanently locked. This is guaranteed by the combination of:
    1. First mint locks MIN_LIQUIDITY in totalSupply but assigns it to no one (TEMPO-AMM15)
    2. Pro-rata burn formula `(liquidity * reserve) / totalSupply` can only extract `userLiquidity / totalSupply` fraction
    3. Since `sum(userBalances) = totalSupply - MIN_LIQUIDITY`, full exit leaves `(MIN_LIQUIDITY / totalSupply) * reserves` in the pool

  Note: Fee swap dust (0.30% fee) and rebalance +1 rounding go INTO reserves and are distributed pro-rata to LPs when they burn. This is the intended fee mechanism - LPs earn revenue from fee swaps. The invariant verifies no value is created (balance ≤ reserves + tracked dust) rather than requiring dust to remain, since dust legitimately flows to LPs.

### TIP-403 Blacklist Invariants

Blacklist testing uses a simple approach: `toggleBlacklist` randomly adds/removes actors from token blacklists, and existing handlers (mint, burn, rebalanceSwap, distributeFees) naturally encounter blacklisted actors and verify `PolicyForbids` behavior.

- **TEMPO-AMM32**: Blacklisted actors cannot receive tokens from AMM operations. Operations that would transfer tokens to a blacklisted recipient (burn, rebalanceSwap, distributeFees) revert with `PolicyForbids`. Frozen fees/LP remain intact and are not lost.
- **TEMPO-AMM33**: Blacklisted actors cannot deposit tokens into the AMM. Mint operations from blacklisted actors revert with `PolicyForbids`.
- **TEMPO-AMM34**: Blacklist recovery - after being removed from blacklist, validators can claim their frozen fees and LPs can burn their positions. Blacklisting is a temporary freeze, not permanent loss. Verified in the two-phase exit check: Phase 1 exits with blacklisted actors frozen, Phase 2 unblacklists all actors and verifies complete recovery.

## FeeManager

The FeeManager extends FeeAMM and handles fee token preferences and distribution for validators and users.

### Token Preference Invariants

- **TEMPO-FEE1**: `setValidatorToken` correctly stores the validator's token preference.
- **TEMPO-FEE2**: `setUserToken` correctly stores the user's token preference.

### Fee Distribution Invariants

- **TEMPO-FEE3**: After `distributeFees`, collected fees for that validator/token pair are zeroed.
- **TEMPO-FEE4**: Validator receives exactly the previously collected fee amount on distribution.

### Fee Collection Invariants

- **TEMPO-FEE5**: Collected fees should not exceed AMM token balance for any token.
- **TEMPO-FEE6**: Fee swap rate M is correctly applied - fee output should always be <= fee input.

## TIP-1000: State Creation Cost (Gas Pricing)

TIP-1000 defines Tempo's gas pricing for state creation operations, charging 250,000 gas for each new state element to account for long-term storage costs.

### State Creation Invariants (GasPricing.t.sol)

Tested via `vmExec.executeTransaction()` - executes real transactions and verifies gas requirements:

- **TEMPO-GAS1**: SSTORE to new slot costs exactly 250,000 gas.
  - Handler executes SSTORE with insufficient gas (100k) and sufficient gas (350k)
  - Invariant: insufficient gas must fail, sufficient must succeed

- **TEMPO-GAS5**: Contract creation cost = (code_size × 1,000) + 500,000 + 250,000 (account creation).
  - Handler deploys contracts with insufficient and sufficient gas
  - Invariant: deployment must fail below threshold, succeed above

- **TEMPO-GAS8**: Multiple new state elements charge 250k each independently.
  - Handler writes N slots (2-5) with gas for only 1 slot vs gas for N slots
  - Invariant: all N slots must not be written with gas for only 1

### Protocol-Level Invariants (Rust)

The following are enforced at the protocol level and tested in Rust:

- **TEMPO-GAS2**: Account creation intrinsic gas (250k) → `crates/revm/src/handler.rs`
- **TEMPO-GAS3**: SSTORE reset cost (5k) → `crates/revm/`
- **TEMPO-GAS4**: Storage clear refund (15k) → `crates/revm/`
- **TEMPO-GAS6**: Transaction gas cap (30M) → `crates/transaction-pool/src/validator.rs`
- **TEMPO-GAS7**: First tx minimum gas (271k) → `crates/transaction-pool/src/validator.rs`
- **TEMPO-GAS9-14**: Various protocol-level gas rules → `crates/revm/`

## TIP-1010: Mainnet Gas Parameters (Block Limits)

TIP-1010 defines Tempo's mainnet block gas parameters, including a 500M total block gas limit with a 30M general lane and 470M payment lane allocation.

### Block Gas Invariants (BlockGasLimits.t.sol)

Tested via `vmExec.executeTransaction()` and constant assertions:

- **TEMPO-BLOCK1**: Block total gas limit = 500,000,000. (constant assertion)
- **TEMPO-BLOCK2**: General lane gas limit = 30,000,000. (constant assertion)
- **TEMPO-BLOCK3**: Transaction gas cap = 30,000,000.
  - Handler submits tx at cap (30M) and over cap (30M+)
  - Invariant: over-cap transactions must be rejected

- **TEMPO-BLOCK4**: Base fee = 20 gwei (T1), 10 gwei (T0). (constant assertion)
- **TEMPO-BLOCK5**: Payment lane minimum = 470M. (constant assertion)
- **TEMPO-BLOCK6**: Max contract deployment (24KB) fits within tx gas cap.
  - Handler deploys contracts at 50-100% of max size
  - Invariant: max size deployment must succeed within tx cap

- **TEMPO-BLOCK10**: shared_gas_limit = 50M. (constant assertion)

### Protocol-Level Invariants (Rust)

The following are enforced in the block builder and tested in Rust:

- **TEMPO-BLOCK7**: Block validity rejects over-limit blocks → `crates/payload/builder/src/lib.rs`
- **TEMPO-BLOCK8-9**: Hardfork activation rules → `crates/chainspec/`
- **TEMPO-BLOCK11**: Constant base fee within epoch → `crates/chainspec/`
- **TEMPO-BLOCK12**: General lane enforcement (30M cap) → `crates/payload/builder/src/lib.rs`

## Nonce

The Nonce precompile manages 2D nonces for accounts, enabling multiple independent nonce sequences per account identified by a nonce key.

### Nonce Increment Invariants

- **TEMPO-NON1**: Monotonic increment - nonces only ever increase by exactly 1 per increment operation.
- **TEMPO-NON2**: Ghost state consistency - actual nonce values always match tracked ghost state.
- **TEMPO-NON3**: Read consistency - `getNonce` returns the correct value after any number of increments.

### Protocol Nonce Invariants

- **TEMPO-NON4**: Protocol nonce rejection - nonce key 0 is reserved for protocol nonces and reverts with `ProtocolNonceNotSupported` when accessed through the precompile.

### Independence Invariants

- **TEMPO-NON5**: Account independence - incrementing one account's nonce does not affect any other account's nonces.
- **TEMPO-NON6**: Key independence - incrementing one nonce key does not affect any other nonce key for the same account.

### Edge Case Invariants

- **TEMPO-NON7**: Large nonce key support - `type(uint256).max - 1` works correctly as a nonce key. Note: `type(uint256).max` is reserved for `TEMPO_EXPIRING_NONCE_KEY`.
- **TEMPO-NON8**: Strict monotonicity - multiple sequential increments produce strictly increasing values with no gaps.

### Overflow Invariants

- **TEMPO-NON9**: Nonce overflow protection - incrementing a nonce at `u64::MAX` reverts with `NonceOverflow`. Rust uses `checked_add(1)` which returns an error on overflow.
- **TEMPO-NON10**: Invalid key increment rejection - `increment_nonce(key=0)` reverts with `InvalidNonceKey` (distinct from `ProtocolNonceNotSupported` used for reads).

### Reserved Key Invariants

- **TEMPO-NON11**: Reserved expiring nonce key - `type(uint256).max` is reserved for `TEMPO_EXPIRING_NONCE_KEY`. Reading it returns 0 for uninitialized accounts (readable but reserved for special use).

## TIP20Factory

The TIP20Factory is the factory contract for creating TIP-20 compliant tokens with deterministic addresses.

### Token Creation Invariants

- **TEMPO-FAC1**: Deterministic addresses - `createToken` deploys to the exact address returned by `getTokenAddress` for the same sender/salt combination.
- **TEMPO-FAC2**: TIP20 recognition - all tokens created by the factory are recognized as TIP-20 by `isTIP20()`.
- **TEMPO-FAC3**: Address uniqueness - attempting to create a token at an existing address reverts with `TokenAlreadyExists`.
- **TEMPO-FAC4**: Quote token validation - `createToken` reverts with `InvalidQuoteToken` if the quote token is not a valid TIP-20.
- **TEMPO-FAC5**: Reserved address enforcement - addresses in the reserved range (lower 64 bits < 1024) revert with `AddressReserved`.
- **TEMPO-FAC6**: Token properties - created tokens have correct name, symbol, and currency as specified.
- **TEMPO-FAC7**: Currency consistency - USD tokens must have USD quote tokens; non-USD tokens can have any valid quote token.

### Address Prediction Invariants

- **TEMPO-FAC8**: isTIP20 consistency - created tokens return true, non-TIP20 addresses return false.
- **TEMPO-FAC9**: Address determinism - `getTokenAddress(sender, salt)` always returns the same address for the same inputs.
- **TEMPO-FAC10**: Sender differentiation - different senders with the same salt produce different token addresses.

### Global Invariants

- **TEMPO-FAC11**: Address format - all created tokens have addresses with the correct TIP-20 prefix (`0x20C0...`).
- **TEMPO-FAC12**: Salt-to-token consistency - ghost mappings `saltToToken` and `tokenToSalt` match factory's `getTokenAddress` for all tracked sender/salt combinations.

## TIP403Registry

The TIP403Registry manages transfer policies (whitelists and blacklists) that control which addresses can send or receive tokens.

### Global Invariants

These are checked after every fuzz run:

- **TEMPO-REG13**: Special policy existence - policies 0 and 1 always exist (return true for `policyExists`).
- **TEMPO-REG15**: Counter monotonicity - `policyIdCounter` only increases and equals `2 + totalPoliciesCreated`.
- **TEMPO-REG16**: Policy type immutability - a policy's type cannot change after creation.
- **TEMPO-REG19**: Policy membership consistency - ghost policy membership state matches registry `isAuthorized` for all tracked accounts, respecting whitelist/blacklist semantics.

### Per-Handler Assertions

These verify correct behavior when the specific function is called:

#### Policy Creation

- **TEMPO-REG1**: Policy ID assignment - newly created policy ID equals `policyIdCounter` before creation.
- **TEMPO-REG2**: Counter increment - `policyIdCounter` increments by 1 after each policy creation.
- **TEMPO-REG3**: Policy existence - all created policies return true for `policyExists()`.
- **TEMPO-REG4**: Policy data accuracy - `policyData()` returns the correct type and admin as specified during creation.
- **TEMPO-REG5**: Bulk creation - `createPolicyWithAccounts` correctly initializes all provided accounts in the policy.

#### Admin Management

- **TEMPO-REG6**: Admin transfer - `setPolicyAdmin` correctly updates the policy admin.
- **TEMPO-REG7**: Admin-only enforcement - non-admins cannot modify policy admin (reverts with `Unauthorized`).

#### Policy Modification

- **TEMPO-REG8**: Whitelist modification - adding an account to a whitelist makes `isAuthorized` return true for that account.
- **TEMPO-REG9**: Blacklist modification - adding an account to a blacklist makes `isAuthorized` return false for that account.
- **TEMPO-REG10**: Policy type enforcement - `modifyPolicyWhitelist` on a blacklist (or vice versa) reverts with `IncompatiblePolicyType`.

#### Special Policies

- **TEMPO-REG11**: Always-reject policy - policy ID 0 returns false for all `isAuthorized` checks.
- **TEMPO-REG12**: Always-allow policy - policy ID 1 returns true for all `isAuthorized` checks.
- **TEMPO-REG14**: Non-existent policies - policy IDs >= `policyIdCounter` return false for `policyExists()`.
- **TEMPO-REG17**: Special policy immutability - policies 0 and 1 cannot be modified via `modifyPolicyWhitelist` or `modifyPolicyBlacklist`.
- **TEMPO-REG18**: Special policy admin immutability - the admin of policies 0 and 1 cannot be changed (attempts revert with `Unauthorized` since admin is `address(0)`).


## ValidatorConfig

The ValidatorConfig precompile manages the set of validators that participate in consensus, including their public keys, addresses, and active status.

### Owner Authorization Invariants

- **TEMPO-VAL1**: Owner-only add - only the owner can add new validators (non-owners revert with `Unauthorized`).
- **TEMPO-VAL7**: Owner transfer - `changeOwner` correctly updates the owner address.
- **TEMPO-VAL8**: New owner authority - only the current owner can transfer ownership.

### Validator Index Invariants

- **TEMPO-VAL2**: Index assignment - new validators receive sequential indices starting from 0; indices are unique and within bounds.

### Validator Update Invariants

- **TEMPO-VAL3**: Validator self-update - validators can update their own public key, inbound address, and outbound address.
- **TEMPO-VAL4**: Update restriction - only the validator themselves can call `updateValidator` (owner cannot update validators).

### Status Management Invariants

- **TEMPO-VAL5**: Owner-only status change - only the owner can change validator active status (validators cannot change their own status).
- **TEMPO-VAL6**: Status toggle - `changeValidatorStatus` correctly updates the validator's active flag.

### Validator Creation Invariants

- **TEMPO-VAL9**: Duplicate rejection - adding a validator that already exists reverts with `ValidatorAlreadyExists`.
- **TEMPO-VAL10**: Zero public key rejection - adding a validator with zero public key reverts with `InvalidPublicKey`.

### Validator Rotation Invariants

- **TEMPO-VAL11**: Address rotation - validators can rotate to a new address while preserving their index and active status.

### DKG Ceremony Invariants

- **TEMPO-VAL12**: DKG epoch setting - `setNextFullDkgCeremony` correctly stores the epoch value.
- **TEMPO-VAL13**: Owner-only DKG - only the owner can set the DKG ceremony epoch.

### Global Invariants

- **TEMPO-VAL14**: Owner consistency - contract owner always matches ghost state.
- **TEMPO-VAL15**: Validator data consistency - all validator data (active status, public key, index) matches ghost state.
- **TEMPO-VAL16**: Index consistency - each validator's index matches the ghost-tracked index assigned at creation.

## TIP20

TIP20 is the Tempo token standard that extends ERC-20 with transfer policies, memo support, pause functionality, and reward distribution.

### Transfer Invariants

- **TEMPO-TIP1**: Balance conservation - sender balance decreases by exactly `amount`, recipient balance increases by exactly `amount`. Transfer returns `true` on success.
- **TEMPO-TIP2**: Total supply unchanged after transfer - transfers only move tokens between accounts.
- **TEMPO-TIP3**: Allowance consumption - `transferFrom` decreases allowance by exactly `amount` transferred.
- **TEMPO-TIP4**: Infinite allowance preserved - `type(uint256).max` allowance remains infinite after `transferFrom`.
- **TEMPO-TIP9**: Memo transfers behave identically to regular transfers for balance accounting.

### Approval Invariants

- **TEMPO-TIP5**: Allowance setting - `approve` sets exact allowance amount, returns `true`.

### Mint/Burn Invariants

- **TEMPO-TIP6**: Minting increases total supply and recipient balance by exactly `amount`.
- **TEMPO-TIP7**: Supply cap enforcement - minting reverts if `totalSupply + amount > supplyCap`.
- **TEMPO-TIP8**: Burning decreases total supply and burner balance by exactly `amount`.
- **TEMPO-TIP23**: Burn blocked - `burnBlocked` decreases target balance and total supply by exactly `amount` when target is blacklisted.

### Reward Distribution Invariants

- **TEMPO-TIP10**: Reward recipient setting - `setRewardRecipient` updates the stored recipient correctly.
- **TEMPO-TIP11**: Opted-in supply tracking - `optedInSupply` increases when opting in (by holder's balance) and decreases when opting out.
- **TEMPO-TIP25**: Reward delegation - users can delegate their rewards to another address via `setRewardRecipient`.
- **TEMPO-TIP12**: Global reward per token updates - `distributeReward` increases `globalRewardPerToken` by `(amount * ACC_PRECISION) / optedInSupply`.
- **TEMPO-TIP13**: Reward token custody - distributed rewards are transferred to the token contract.
- **TEMPO-TIP14**: Reward claiming - `claimRewards` transfers owed amount from contract to caller, updates balances correctly.
- **TEMPO-TIP15**: Claim bounded by available - claimed amount cannot exceed contract's token balance.

### Policy Invariants

- **TEMPO-TIP16**: Blacklist enforcement - transfers to/from blacklisted addresses revert with `PolicyForbids`.
- **TEMPO-TIP17**: Pause enforcement - transfers revert with `ContractPaused` when paused.

### Global Invariants

- **TEMPO-TIP18**: Supply conservation - `totalSupply = initialSupply + totalMints - totalBurns`.
- **TEMPO-TIP19**: Opted-in supply bounded - `optedInSupply <= totalSupply`.
- **TEMPO-TIP20**: Balance sum equals supply - sum of all holder balances equals `totalSupply`.
- **TEMPO-TIP21**: Decimals constant - `decimals()` always returns 6.
- **TEMPO-TIP22**: Supply cap enforced - `totalSupply <= supplyCap` always holds.

### Protected Address Invariants

- **TEMPO-TIP24**: Protected address enforcement - `burnBlocked` cannot be called on FeeManager or DEX addresses (reverts with `ProtectedAddress`).

### Access Control Invariants

- **TEMPO-TIP26**: Issuer-only minting - only accounts with `ISSUER_ROLE` can call `mint` (non-issuers revert with `Unauthorized`).
- **TEMPO-TIP27**: Pause-role enforcement - only accounts with `PAUSE_ROLE` can call `pause` (non-role holders revert with `Unauthorized`).
- **TEMPO-TIP28**: Unpause-role enforcement - only accounts with `UNPAUSE_ROLE` can call `unpause` (non-role holders revert with `Unauthorized`).
- **TEMPO-TIP29**: Burn-blocked-role enforcement - only accounts with `BURN_BLOCKED_ROLE` can call `burnBlocked` (non-role holders revert with `Unauthorized`).
