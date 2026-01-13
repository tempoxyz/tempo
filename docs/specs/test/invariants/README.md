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

### Global Invariants

- **TEMPO-AMM13**: Pool solvency - AMM token balances are always >= sum of pool reserves for that token.
- **TEMPO-AMM14**: LP token accounting - Total supply equals sum of all user LP balances + MIN_LIQUIDITY (locked on first mint).
- **TEMPO-AMM15**: MIN_LIQUIDITY is permanently locked - once a pool is initialized, total supply is always >= MIN_LIQUIDITY.
- **TEMPO-AMM16**: Fee rates are constant - M = 9970, N = 9985, SCALE = 10000.

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
