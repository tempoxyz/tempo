# Stablecoin DEX Orderbook Query Guide

DEX precompile address: `0xDEc0000000000000000000000000000000000000`

All commands use `cast call`. Set these env vars first:

```bash
export RPC_URL="<your-tempo-rpc-url>"
export DEX="0xDEc0000000000000000000000000000000000000"
export BASE_TOKEN="<base-token-address>"  # e.g. USDC TIP-20 address
```

## Step 1: Get the pair key

```bash
cast call $DEX "pairKey(address,address)(bytes32)" $BASE_TOKEN 0x0000000000000000000000000000000000000000 --rpc-url $RPC_URL
```

> Quote token is always pathUSD (`address(0)` or the actual pathUSD address). Try both if one reverts.

## Step 2: Get the orderbook state (best bid/ask)

```bash
PAIR_KEY="<output from step 1>"
cast call $DEX "books(bytes32)(address,address,int16,int16)" $PAIR_KEY --rpc-url $RPC_URL
```

Returns: `base, quote, bestBidTick, bestAskTick`

## Step 3: Get tick level at best bid

```bash
BEST_BID_TICK=<from step 2>
cast call $DEX "getTickLevel(address,int16,bool)(uint128,uint128,uint128)" $BASE_TOKEN $BEST_BID_TICK true --rpc-url $RPC_URL
```

Returns: `head, tail, totalLiquidity`

## Step 4: Get tick level at best ask

```bash
BEST_ASK_TICK=<from step 2>
cast call $DEX "getTickLevel(address,int16,bool)(uint128,uint128,uint128)" $BASE_TOKEN $BEST_ASK_TICK false --rpc-url $RPC_URL
```

Returns: `head, tail, totalLiquidity`

## Step 5: Walk orders at a tick level

Starting from `head` returned in step 3 or 4:

```bash
ORDER_ID=<head from getTickLevel>
cast call $DEX "getOrder(uint128)(uint128,address,bytes32,bool,int16,uint128,uint128,uint128,uint128,bool,int16)" $ORDER_ID --rpc-url $RPC_URL
```

Returns (in order):
- `orderId` (uint128)
- `maker` (address)
- `bookKey` (bytes32)
- `isBid` (bool)
- `tick` (int16)
- `amount` (uint128) — original size
- `remaining` (uint128) — unfilled size
- `prev` (uint128)
- `next` (uint128) — **next order in queue at this tick**
- `isFlip` (bool)
- `flipTick` (int16)

**Loop**: if `next != 0`, call `getOrder(next)`. Repeat until `next == 0`.

## Step 6: Convert ticks to prices

```bash
cast call $DEX "tickToPrice(int16)(uint32)" $TICK --rpc-url $RPC_URL
```

Price is scaled by `PRICE_SCALE`:
```bash
cast call $DEX "PRICE_SCALE()(uint32)" --rpc-url $RPC_URL
```

Actual price = `tickToPrice(tick) / PRICE_SCALE`

## Step 7: Walk deeper into the book

There's no view to get "next tick with liquidity." To walk beyond best bid/ask:
- Decrement tick by `TICK_SPACING` for bids, increment for asks
- Call `getTickLevel` at each tick — if `totalLiquidity > 0`, there are orders
- Get tick spacing: `cast call $DEX "TICK_SPACING()(int16)" --rpc-url $RPC_URL`
- Bounds: `MIN_TICK` to `MAX_TICK`

```bash
cast call $DEX "TICK_SPACING()(int16)" --rpc-url $RPC_URL
cast call $DEX "MIN_TICK()(int16)" --rpc-url $RPC_URL
cast call $DEX "MAX_TICK()(int16)" --rpc-url $RPC_URL
```

## Summary: Minimal full book snapshot

```
1. pairKey(base, quote) → key
2. books(key) → bestBidTick, bestAskTick
3. For bids: tick = bestBidTick; while tick >= MIN_TICK; tick -= TICK_SPACING:
     getTickLevel(base, tick, true) → if totalLiquidity > 0, walk orders
4. For asks: tick = bestAskTick; while tick <= MAX_TICK; tick += TICK_SPACING:
     getTickLevel(base, tick, false) → if totalLiquidity > 0, walk orders
5. For each order: getOrder(head) → follow .next chain
6. tickToPrice(tick) / PRICE_SCALE for human-readable prices
```

## Useful extras

```bash
# Total orders ever placed
cast call $DEX "nextOrderId()(uint128)" --rpc-url $RPC_URL

# Check a user's claimable balance (from filled orders)
cast call $DEX "balanceOf(address,address)(uint128)" $USER_ADDRESS $TOKEN --rpc-url $RPC_URL

# Quote a swap without executing
cast call $DEX "quoteSwapExactAmountIn(address,address,uint128)(uint128)" $TOKEN_IN $TOKEN_OUT $AMOUNT --rpc-url $RPC_URL
```
