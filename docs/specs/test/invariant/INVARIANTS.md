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
