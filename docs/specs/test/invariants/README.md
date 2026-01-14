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
- **TEMPO-DEX18**: Dust invariant - each swap can at maximum increase the dust in the DEX by 1.

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
- **TEMPO-AMM22**: Rebalance swap rounding always favors the pool - the +1 in the formula ensures pool never loses to rounding.
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

### Reward Distribution Invariants

- **TEMPO-TIP10**: Reward recipient setting - `setRewardRecipient` updates the stored recipient correctly.
- **TEMPO-TIP11**: Opted-in supply tracking - `optedInSupply` increases when opting in (by holder's balance) and decreases when opting out.
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

## TIP403Registry

The TIP403Registry manages transfer policies (whitelists and blacklists) that control which addresses can send or receive tokens.

### Policy Creation Invariants

- **TEMPO-REG1**: Policy ID assignment - newly created policy ID equals `policyIdCounter` before creation.
- **TEMPO-REG2**: Counter increment - `policyIdCounter` increments by 1 after each policy creation.
- **TEMPO-REG3**: Policy existence - all created policies return true for `policyExists()`.
- **TEMPO-REG4**: Policy data accuracy - `policyData()` returns the correct type and admin as specified during creation.
- **TEMPO-REG5**: Bulk creation - `createPolicyWithAccounts` correctly initializes all provided accounts in the policy.

### Admin Management Invariants

- **TEMPO-REG6**: Admin transfer - `setPolicyAdmin` correctly updates the policy admin.
- **TEMPO-REG7**: Admin-only enforcement - non-admins cannot modify policy admin (reverts with `Unauthorized`).

### Policy Modification Invariants

- **TEMPO-REG8**: Whitelist modification - adding an account to a whitelist makes `isAuthorized` return true for that account.
- **TEMPO-REG9**: Blacklist modification - adding an account to a blacklist makes `isAuthorized` return false for that account.
- **TEMPO-REG10**: Policy type enforcement - `modifyPolicyWhitelist` on a blacklist (or vice versa) reverts with `IncompatiblePolicyType`.

### Special Policy Invariants

- **TEMPO-REG11**: Always-reject policy - policy ID 0 returns false for all `isAuthorized` checks.
- **TEMPO-REG12**: Always-allow policy - policy ID 1 returns true for all `isAuthorized` checks.
- **TEMPO-REG13**: Special policy existence - policies 0 and 1 always exist (return true for `policyExists`).
- **TEMPO-REG14**: Non-existent policies - policy IDs >= `policyIdCounter` return false for `policyExists()`.

### Global Invariants

- **TEMPO-REG15**: Counter monotonicity - `policyIdCounter` only increases and equals `2 + totalPoliciesCreated`.
- **TEMPO-REG16**: Policy type immutability - a policy's type cannot change after creation.
