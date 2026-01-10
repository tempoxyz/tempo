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

### Balance Invariants

- **TEMPO-DEX6**: DEX token balance >= sum of all internal user balances (the difference accounts for escrowed order amounts).

### Orderbook Structure Invariants

- **TEMPO-DEX7**: Total liquidity at a tick level equals the sum of remaining amounts of all orders at that tick. If liquidity > 0, head must be non-zero.
- **TEMPO-DEX8**: Best bid tick points to the highest tick with non-empty bid liquidity, or `type(int16).min` if no bids exist.
- **TEMPO-DEX9**: Best ask tick points to the lowest tick with non-empty ask liquidity, or `type(int16).max` if no asks exist.
- **TEMPO-DEX10**: Order linked list is consistent - `prev.next == current` and `next.prev == current`. If head is zero, tail must also be zero.
- **TEMPO-DEX11**: Tick bitmap accurately reflects which ticks have liquidity (bit set iff tick has orders).

### Flip Order Invariants

- **TEMPO-DEX12**: Flip orders have valid tick constraints - for bids `flipTick > tick`, for asks `flipTick < tick`.

### Blacklist Invariants

- **TEMPO-DEX13**: Anyone can cancel a stale order from a blacklisted maker via `cancelStaleOrder`. The escrowed funds are refunded to the blacklisted maker's internal balance.
