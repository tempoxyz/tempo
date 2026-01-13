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

## FeeManager

The FeeManager extends FeeAMM and handles fee token preferences and distribution for validators and users.

### Token Preference Invariants

- **TEMPO-FEE1**: `setValidatorToken` correctly stores the validator's token preference.
- **TEMPO-FEE2**: `setUserToken` correctly stores the user's token preference.

### Fee Distribution Invariants

- **TEMPO-FEE3**: After `distributeFees`, collected fees for that validator/token pair are zeroed.
- **TEMPO-FEE4**: Validator receives exactly the previously collected fee amount on distribution.

### Fee Collection Invariants (Protocol-Level)

These invariants apply during transaction fee collection (called by the protocol):

- **TEMPO-FEE5**: Pre-tx fee collection transfers max fee amount to the FeeManager.
- **TEMPO-FEE6**: Pre-tx fee collection checks sufficient liquidity when user token ≠ validator token.
- **TEMPO-FEE7**: Post-tx fee collection refunds unused gas to the user.
- **TEMPO-FEE8**: Post-tx fee collection executes swap immediately when user token ≠ validator token.
- **TEMPO-FEE9**: Fee swap output follows formula: `amountOut = amountIn * M / SCALE` (0.30% fee).
- **TEMPO-FEE10**: Collected fees accumulate correctly for the validator in their preferred token.

## Running Invariant Tests

```bash
# Run all invariant tests
forge test --match-contract "InvariantTest" -vvv

# Run FeeAMM invariant tests specifically
forge test --match-contract "FeeAMMInvariantTest" -vvv

# Run with more depth (CI profile)
FOUNDRY_PROFILE=ci forge test --match-contract "InvariantTest" -vvv
```
