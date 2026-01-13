## Actors

| Actor | Description |
|-------|-------------|
| **User** | End-user paying transaction fees; sets preferred `userToken` via `setUserToken()` |
| **Validator** | Block producer (`block.coinbase`); sets preferred `validatorToken`; receives collected fees |
| **LP (Liquidity Provider)** | Provides single-sided liquidity (validatorToken); earns spread from swap imbalance |
| **Rebalancer/Arbitrageur** | Swaps validatorToken→userToken at 0.15% worse rate to extract accumulated userTokens |
| **Protocol** | Calls `collectFeePreTx`/`collectFeePostTx` (enforced via `msg.sender == address(0)`) |

---

## Actions

### FeeManager

| Function | Actor | Effect |
|----------|-------|--------|
| `setUserToken(token)` | User | Configure preferred fee token (direct call only) |
| `setValidatorToken(token)` | Validator | Configure preferred payout token (direct call only, not during own block) |
| `collectFeePreTx(user, userToken, maxAmount)` | Protocol | Lock max fee from user, check liquidity for cross-token swap |
| `collectFeePostTx(user, maxAmount, actualUsed, userToken)` | Protocol | Refund unused fees, execute swap if needed, accumulate fees for validator |
| `distributeFees(validator, token)` | Anyone | Transfer accumulated fees to validator |

### FeeAMM

| Function | Actor | Effect |
|----------|-------|--------|
| `mint(userToken, validatorToken, amount, to)` | LP | Deposit validatorToken, receive LP tokens (single-sided) |
| `burn(userToken, validatorToken, liquidity, to)` | LP | Redeem LP tokens for pro-rata share of both reserves |
| `rebalanceSwap(userToken, validatorToken, amountOut, to)` | Rebalancer | Swap validatorToken→userToken at rate N/SCALE (0.9985) |

---

## Swap Rates

| Swap Type | Rate | Direction |
|-----------|------|-----------|
| Fee Swap | M = 0.9970 (0.30% fee) | userToken → validatorToken |
| Rebalance Swap | N = 0.9985 (0.15% fee) | validatorToken → userToken |
| **Spread** | 15 basis points | LP profit margin |

---

## Security Risk Scenarios

### Critical Risks

| Risk | Description | Mitigation | Unit Tests |
|------|-------------|------------|------------|
| **Rounding exploitation** | Repeated small swaps accumulate rounding errors in attacker's favor | Invariants A7, A8, I2; round against user | `RoundingExploit.t.sol` |
| **LP share inflation attack** | First depositor manipulates reserves to dilute subsequent LPs | MIN_LIQUIDITY (1000) permanently locked on first mint | `RoundingExploit.t.sol` |
| **Reserve insolvency** | Token balance < sum of reserves across all pools | Invariant A3, I3: `balance ≥ sum(reserves)` | `ReserveInsolvency.t.sol` |

### Medium Risks

| Risk | Description | Mitigation | Unit Tests |
|------|-------------|------------|------------|
| **Pool ID collision** | Different token pairs mapping to same poolId | Invariant A4: poolId unique per ordered pair | `FeeAMMInvariant.t.sol` |
| **Cross-token arbitrage** | Exploit spread between fee swap (M) and rebalance swap (N) | Invariants I1, I2, I8 ensure 15 bps spread maintained | `CrossTokenArbitrage.t.sol` |
| **Fee double-counting** | Distributed fees exceed collected fees | Invariants F3, F4, I5 enforce conservation | `FeeDoubleCount.t.sol` |
| **Validator token manipulation** | Validator changes token mid-block to steal fees | `CANNOT_CHANGE_WITHIN_BLOCK` check | - |

### Lower Risks

| Risk | Description | Mitigation | Unit Tests |
|------|-------------|------------|------------|
| **LP rug via burn** | Burning more LP tokens than ever minted | Invariant A7: `burned ≤ minted` | `RoundingExploit.t.sol` |
| **Directional pool confusion** | Mixing up Pool(A,B) vs Pool(B,A) logic | Invariant I6: pools are directional and separate | `CrossTokenArbitrage.t.sol` |
| **uint128 overflow** | Reserve updates exceed uint128 max | `_requireU128()` checks on all reserve modifications | `FeeAMMOverflow.t.sol` |
| **Uninitialized pool LP** | LP tokens exist for pool with zero supply | Invariant A5: `supply == 0 ⇒ all balances == 0` | `FeeAMMInvariant.t.sol` |

---

# Invariants Tested

## FeeAMM Invariants (A1-A11)

- **A1: Pool Initialization Shape** - A pool is either completely uninitialized (all zeros) or properly initialized with MIN_LIQUIDITY locked
- **A2: LP Supply Accounting** - Total LP supply equals sum of all actor balances plus locked MIN_LIQUIDITY
- **A3: Token Balance Covers Reserves** - AMM's token balance must be at least the sum of reserves across all pools
- **A4: Pool IDs Unique** - Every tracked poolId corresponds to exactly one ordered token pair
- **A5: No LP When Uninitialized** - If totalSupply is zero, no actor may hold LP tokens for that pool
- **A6: Each Pool Individually Backed** - For every pool, AMM holds at least that pool's reserves in each token
- **A7: Tracked Pool IDs Seen** - All tracked poolIds are marked as seen in the handler
- **A8: No Free Value** - Users cannot extract more LP tokens than minted (no value creation from rounding)
- **A9: Rebalance Swap Rate** - Rebalance swap input must be >= (output * N / SCALE) + 1
- **A10: Fee Swap Rate** - Fee swap output must be exactly (input * M / SCALE) with rounding down
- **A11: Reserves Bounded** - Pool reserves must always fit in uint128

## FeeManager Invariants (F1-F5)

- **F1: Fees Bounded** - Total collected fees cannot exceed total fees input
- **F2: Fee Conservation** - fees_in = fees_collected + refunds (for same token scenarios)
- **F3: Distribution Bounded** - Cannot distribute more fees than collected
- **F4: Fees Cleared on Distribute** - Undistributed fees equal sum of all validator pending fees
- **F5: Non-Zero Accumulation** - Fees can only be collected when actualUsed > 0

## Integration Invariants (I1-I8)

- **I1: Cross-Token Fee Rate** - Cross-token fees collected at rate M/SCALE (0.997) within rounding bounds
- **I2: No Arbitrage** - Fee swap -> rebalance sequence results in net loss for arbitrageur
- **I3: System Solvency** - System always has enough tokens to cover all pool reserves
- **I4: LP Accounting Integration** - LP token accounting correct across fee collection and AMM operations
- **I5: Fee Conservation Integration** - collected + refunds <= totalIn across all fee types
- **I6: Directional Pool Separation** - Pool(A,B) and Pool(B,A) are separate pools with independent reserves
- **I7: LP Value Preserved** - LP tokens represent at least their share of reserves
- **I8: Swap Spread Positive** - Spread between fee swap (M=9970) and rebalance (N=9985) ensures LP profitability
