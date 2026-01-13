# Tempo Invariants

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

## Running Invariant Tests

```bash
# Run all invariant tests
forge test --match-contract "InvariantTest" -vvv

# Run FeeAMM invariant tests specifically
forge test --match-contract "FeeAMMInvariantTest" -vvv

# Run with more depth (CI profile)
FOUNDRY_PROFILE=ci forge test --match-contract "InvariantTest" -vvv
```
