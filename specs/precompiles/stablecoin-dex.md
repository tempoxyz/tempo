# Stablecoin DEX

The Stablecoin DEX is a native precompile at `0xdec0000000000000000000000000000000000000`. It holds an on-chain central limit order book for every pair of a USD TIP-20 token (the *base*) and its quote token. It keeps internal per-user balances, places and cancels limit and flip orders, executes exact-in and exact-out swaps (multi-hop through pathUSD), and quotes them.

This chapter specifies every rule of the DEX that affects the validity or post-state of a Tempo mainnet block from genesis through T13: storage layout, arithmetic, check order, events, errors and the exact sequence of storage accesses (which fixes gas). General precompile mechanics (dispatch, ABI decoding, input-cost charging, storage gas, struct packing, revert encoding, checkpoints) are defined in [00-framework.md](00-framework.md). TIP-20 operations the DEX calls are defined in [tip20.md](tip20.md), TIP-403 authorization in [tip403.md](tip403.md), and the TIP-1060 storage-credit machinery in [account-keychain.md](account-keychain.md) (storage credits section).

Fork predicates ("From T*n*", "Before T*n*", `fork(Tn)`) are defined in [../01-chain-and-forks.md](../01-chain-and-forks.md): `fork(Tn)` is true iff the executing block's `header.timestamp >= ` Tn's activation time.

Reference implementation: crates/precompiles/src/stablecoin_dex/ (mod.rs, orderbook.rs, order/mod.rs, order/storage.rs, dispatch.rs), crates/contracts/src/precompiles/stablecoin_dex.rs.

## 1. Constants

| Name | Value | Notes |
|---|---|---|
| `STABLECOIN_DEX_ADDRESS` | `0xdec0000000000000000000000000000000000000` | Active from genesis. Genesis account: nonce 0, balance 0, code `0xef`, no storage ([../04-state-and-genesis.md](../04-state-and-genesis.md)). |
| `PATH_USD` | TIP-20 id 0, `0x20c0000000000000000000000000000000000000` | Root of the quote-token tree; its quote token is the zero address. |
| `PRICE_SCALE` | `100_000` (uint32) | Price of tick `t` is `PRICE_SCALE + t`. |
| `MIN_TICK` / `MAX_TICK` | `-2000` / `2000` (int16) | Inclusive bounds for order ticks. |
| `MIN_PRICE` / `MAX_PRICE` | `98_000` / `102_000` (uint32) | `PRICE_SCALE + MIN_TICK`, `PRICE_SCALE + MAX_TICK`. |
| `TICK_SPACING` | `10` (int16) | Order and flip ticks MUST be multiples of 10. |
| `MIN_ORDER_AMOUNT` | `100_000_000` (uint128) | Minimum order `amount` in base units. |
| `NO_BID` | `-32768` (`int16.min`) | `bestBidTick` sentinel: no bids. |
| `NO_ASK` | `32767` (`int16.max`) | `bestAskTick` sentinel: no asks. |
| `ORDER_VERSION_V1` / `ORDER_VERSION_V2` | `1` / `2` | Order record versions (T8+). Legacy records are version `0`. |

## 2. Per-fork summary

| Fork | DEX change (normative text is in the referenced section) |
|---|---|
| Genesis/T0 | Base behaviour: legacy 6-slot order records, aggregate `totalLiquidity` per tick, per-tick quotes, flip orders re-placed under a new order id (§11.7), `transferFrom` with allowance for pulls (§7, §8.2). All errors raised by an automatic flip placement are swallowed. |
| T1A | A *system error* raised by an automatic flip placement propagates and reverts the swap (§11.7). |
| T1C | Precompile checkpoints become real, so `placeFlip` / flip placement is atomic (§15). `placeFlip` writes `nextOrderId` without re-reading it (§9.2). |
| T2 | `tickToPrice` / `priceToTick` enforce `TICK_SPACING` (§14). TIP-403 lookup-failure classification used by `cancelStaleOrder` changes (§12.2). |
| T3 | Swap routes reject a paused input token on every hop (§11.2). |
| T4 | Order placement rejects a paused non-escrow token and a paused escrow token when internal balance alone covers the escrow (§9). `cancelStaleOrder` also cancels when the maker is not an authorized *recipient* of the payout token (§12.2). Struct writes stop pre-reading packed slots ([00-framework.md](00-framework.md)). |
| T5 | Flip orders flip in place under the same order id, emit `OrderFlipped` / `FlipFailed` (TIP-1056); `flipTick == tick` allowed (TIP-1030); pulls use `systemTransferFrom` without allowance (TIP-1035). |
| T6 | No DEX code change. TIP-403 always-authorized addresses and TIP-20 receive policies change the outcome of the TIP-20/TIP-403 calls the DEX makes ([tip403.md](tip403.md), [tip20.md](tip20.md)). |
| T7 | Maker storage credits (TIP-1064): `dex_storage_credits`, `storageCredits(address)`, credit attribution and spending (§10). Every mutating entrypoint first sets the DEX's TIP-1060 mode to Preserve (§4). |
| T8 | Versioned order records V1/V2 (TIP-1062, TIP-1087), per-book `bookId`, `bookIndexForKey` / `bookKeyForIndex` / `setBookIndex`; appending writes only the predecessor's `next` field; flip rewrites credit freed slots to the maker (§6.5, §9.3). |
| T9-T11 | No DEX change. |
| T12 | Quotes walk the book order by order with the swap arithmetic (TIP-1088); `TickLevel.totalLiquidity` is no longer read, written or cleared; `getTickLevel` sums the queue; a cancel writes the tick level only if it removed the head or tail (§6.3, §12.1, §13). Static calls to mutating functions halt instead of reverting ([00-framework.md](00-framework.md)). |
| T13 | No DEX change. |

> **Open conflict C-DEX-06**: docs exchange/spec.mdx states T2/T4/T5/T12 behaviour (tick spacing in `tickToPrice`/`priceToTick`, the recipient check in `cancelStaleOrder`, same-id flips with `OrderFlipped`/`FlipFailed` and `flipTick == tick`, quote/swap parity and a traversed `totalLiquidity`) as unconditional rules; the implementation applies each only from its fork. See [conflicts](../conflicts.md#c-dex-06).

## 3. ABI

All functions, events and errors use the Solidity ABI. Selectors and topics are `keccak256` of the canonical signature.

### 3.1 Structs

```solidity
struct Order {            // getOrder return value
    uint128 orderId; address maker; bytes32 bookKey; bool isBid; int16 tick;
    uint128 amount; uint128 remaining; uint128 prev; uint128 next; bool isFlip; int16 flipTick;
}
struct Orderbook {        // books return value
    address base; address quote; int16 bestBidTick; int16 bestAskTick;
}
```

### 3.2 Functions

| Selector | Signature | Kind | Available |
|---|---|---|---|
| `0x9ccb0744` | `createPair(address base) returns (bytes32 key)` | mutate | all |
| `0x63813125` | `place(address token, uint128 amount, bool isBid, int16 tick) returns (uint128 orderId)` | mutate | all |
| `0x922828f1` | `placeFlip(address token, uint128 amount, bool isBid, int16 tick, int16 flipTick) returns (uint128 orderId)` | mutate | all |
| `0x81649d06` | `cancel(uint128 orderId)` | mutate | all |
| `0x928b0e7f` | `cancelStaleOrder(uint128 orderId)` | mutate | all |
| `0xf8856c0f` | `swapExactAmountIn(address tokenIn, address tokenOut, uint128 amountIn, uint128 minAmountOut) returns (uint128 amountOut)` | mutate | all |
| `0xf0122b75` | `swapExactAmountOut(address tokenIn, address tokenOut, uint128 amountOut, uint128 maxAmountIn) returns (uint128 amountIn)` | mutate | all |
| `0x08fab167` | `withdraw(address token, uint128 amount)` | mutate | all |
| `0xaecbd005` | `setBookIndex(uint32 index)` | mutate | from T8 |
| `0xe7c98f1a` | `quoteSwapExactAmountIn(address tokenIn, address tokenOut, uint128 amountIn) returns (uint128 amountOut)` | view | all |
| `0x1576fa0e` | `quoteSwapExactAmountOut(address tokenIn, address tokenOut, uint128 amountOut) returns (uint128 amountIn)` | view | all |
| `0xf7888aec` | `balanceOf(address user, address token) returns (uint128)` | view | all |
| `0x117d4128` | `getOrder(uint128 orderId) returns (Order)` | view | all |
| `0x949bc662` | `getTickLevel(address base, int16 tick, bool isBid) returns (uint128 head, uint128 tail, uint128 totalLiquidity)` | view | all |
| `0xcd27ca82` | `pairKey(address tokenA, address tokenB) returns (bytes32)` | view | all |
| `0x2a58b330` | `nextOrderId() returns (uint128)` | view | all |
| `0x0c0dee70` | `books(bytes32 pairKey) returns (Orderbook)` | view | all |
| `0x4d65338b` | `storageCredits(address user) returns (uint64 credits)` | view | from T7 |
| `0x61285475` | `bookIndexForKey(bytes32 bookKey) returns (bool set, uint32 index)` | view | from T8 |
| `0x3c047a7a` | `bookKeyForIndex(uint32 index) returns (bytes32 bookKey)` | view | from T8 |
| `0xa1634b14` | `MIN_TICK() returns (int16)` → `-2000` | view | all |
| `0x6882a888` | `MAX_TICK() returns (int16)` → `2000` | view | all |
| `0x46ca626b` | `TICK_SPACING() returns (int16)` → `10` | view | all |
| `0xc33f59d3` | `PRICE_SCALE() returns (uint32)` → `100000` | view | all |
| `0x40bf2aa4` | `MIN_ORDER_AMOUNT() returns (uint128)` → `100000000` | view | all |
| `0xad9f20a6` | `MIN_PRICE() returns (uint32)` → `98000` | view | all |
| `0x01c11d96` | `MAX_PRICE() returns (uint32)` → `102000` | view | all |
| `0x269a311d` | `tickToPrice(int16 tick) returns (uint32 price)` | view | all |
| `0x87b4e352` | `priceToTick(uint32 price) returns (int16 tick)` | view | all |

Before its "Available" fork, a selector MUST be treated as unknown (the framework's `UnknownFunctionSelector` path).

### 3.3 Events

All events are emitted with the DEX address as the log address.

| topic0 | Signature (indexed fields marked) |
|---|---|
| `0xaff90cfc97c741e6d1ffffa62656c16a763f41dc773055d7b0c36950a823babf` | `PairCreated(bytes32 indexed key, address indexed base, address indexed quote)` |
| `0xc200d837816d02c5ee9bf081cba1a32ab1482de7a738b41c0b357186b0b998cd` | `OrderPlaced(uint128 indexed orderId, address indexed maker, address indexed token, uint128 amount, bool isBid, int16 tick, bool isFlipOrder, int16 flipTick)` |
| `0x16c08f8f2c17b3c8879b3e3cf5efdbdcdfdbd0fcb3890f9d3086f470cd601ddd` | `OrderFilled(uint128 indexed orderId, address indexed maker, address indexed taker, uint128 amountFilled, bool partialFill)` |
| `0x37a42d10bbce3e94e109a6a44e4479f0ee45dd6ecc6ca902168ea58e01ba32fe` | `OrderFlipped(uint128 indexed orderId, address indexed maker, address indexed token, uint128 amount, bool isBid, int16 tick, int16 flipTick)` (emitted from T5) |
| `0x51fbc4e39b03172adeae05359178834eaf629c3fd6a8a081daa4bd36885c0dad` | `FlipFailed(uint128 indexed orderId, address indexed maker, bytes4 reason)` (emitted from T5) |
| `0x06ff08ed6b6987bb7df963009d8b54dc03988f4e465c009924929bb010fe03e7` | `OrderCancelled(uint128 indexed orderId)` |

### 3.4 Errors

DEX errors (`StablecoinDEX` error namespace):

| Selector | Error |
|---|---|
| `0x82b42900` | `Unauthorized()` |
| `0xc5fc4bf4` | `PairDoesNotExist()` |
| `0xc9bb25eb` | `PairAlreadyExists()` |
| `0x5dcaf2d7` | `OrderDoesNotExist()` |
| `0x5c6d7b73` | `IdenticalTokens()` |
| `0xc1ab6dc1` | `InvalidToken()` |
| `0xb549f7dd` | `TickOutOfBounds(int16 tick)` |
| `0xce8ef7fc` | `InvalidTick()` |
| `0xf88aeb80` | `InvalidFlipTick()` |
| `0xf4d678b8` | `InsufficientBalance()` |
| `0xbb55fd27` | `InsufficientLiquidity()` |
| `0xbb2875c3` | `InsufficientOutput()` |
| `0xde9d3c88` | `MaxInputExceeded()` |
| `0x46628371` | `BelowMinimumOrderSize(uint128 amount)` |
| `0x0e442a4a` | `InvalidBaseToken()` |
| `0x68496923` | `OrderNotStale()` |
| `0x1918c05d` | `IndexAlreadySet()` |

Errors from other precompiles that DEX calls can return unchanged (non-exhaustive; see the called function's chapter): TIP-20 `InvalidToken()` (`0xc1ab6dc1`, same signature as the DEX error) when an address lacks the TIP-20 prefix, TIP-20 `PolicyForbids()` (`0x54cfe659`), TIP-20 `ContractPaused()` (`0xab35696f`), TIP-20 `InvalidCurrency()` (`0xf5993428`), TIP-20 balance/allowance errors from transfers, and `Panic(uint256)` (`0x4e487b71`) with code `0x11` for arithmetic over/underflow. In pseudocode, `Panic(0x11)` denotes that panic, and `Fatal` denotes the framework's non-ABI fatal error (a system error).

## 4. Dispatch

For every call, the DEX MUST first charge the framework input cost for the calldata, then decode the selector and arguments as defined in [00-framework.md](00-framework.md) (missing selector, unknown selector, malformed ABI and static-call rules live there).

- *view* functions run in any context and never write persistent or transient storage.
- *mutate* functions are rejected in a static context per the framework. From T7, before running its body, every mutating function MUST set the TIP-1060 credit mode of the DEX address to **Preserve** (budget 0, `pending_refunds` unchanged), exactly as `StorageCredits.setMode(Preserve)` called by the DEX would ([account-keychain.md](account-keychain.md)): one TLOAD and one TSTORE of the DEX's transient credit-state word. Before T7 no mode is set.
- `msg.sender` of the precompile call is `sender` below. `createPair`, `cancelStaleOrder` and `setBookIndex` ignore it.

Calls the DEX makes into TIP-20 tokens, the TIP-20 factory, the TIP-403 registry and StorageCredits are native function invocations in the same execution context (not EVM `CALL` frames). Their storage accesses are metered against the same gas, their events are logged in order with the DEX's own, and the DEX is the caller (`msg.sender`) for any TIP-20 transfer it performs.

Reference implementation: crates/precompiles/src/stablecoin_dex/dispatch.rs, crates/precompiles/src/dispatch.rs (`preserve_storage_credits`).

## 5. Pricing, book keys and rounding

### 5.1 Ticks and prices

```python
def tick_to_price(tick: int16) -> uint32:
    return PRICE_SCALE + tick          # any int16; no bounds or spacing check here

def base_to_quote(base: uint128, tick: int16, up: bool) -> uint128 | OVERFLOW:
    n = base * tick_to_price(tick)                         # 256-bit, cannot overflow
    q = ceil_div(n, PRICE_SCALE) if up else n // PRICE_SCALE
    return OVERFLOW if q >= 2**128 else q

def quote_to_base(quote: uint128, tick: int16, up: bool) -> uint128 | OVERFLOW:
    n = quote * PRICE_SCALE
    p = tick_to_price(tick)
    b = ceil_div(n, p) if up else n // p
    return OVERFLOW if b >= 2**128 else b
```

`ceil_div(a, b) = (a + b - 1) // b` for `b > 0`. How `OVERFLOW` is turned into an error is stated at each use: `InsufficientBalance` when computing a bid escrow, `Panic(0x11)` everywhere else.

### 5.2 Book key

```python
def book_key(base: address, quote: address) -> bytes32:
    return keccak256(base[20 bytes] || quote[20 bytes])   # abi.encodePacked(base, quote); order-dependent
```

The key of a pair is always `book_key(base, base.quoteToken())`. `pairKey(tokenA, tokenB)` returns `book_key(tokenA, tokenB)` with no validation, so `pairKey(a, b) != pairKey(b, a)` in general. Computing the key (and every mapping slot in §6) charges no keccak gas.

> **Open conflict C-DEX-01**: docs exchange/spec.mdx says `pairKey` is order-independent; the implementation hashes `tokenA || tokenB` in argument order and keys all book storage by `keccak256(base || quote)`. See [conflicts](../conflicts.md#c-dex-01).

### 5.3 Rounding rules

All amounts are integers in token base units. "Up" is ceiling division, "down" is floor division. `p = tick_to_price(order.tick)`.

| Quantity | Formula |
|---|---|
| Bid escrow at placement / flip (quote locked) | `base_to_quote(amount, tick, up)`; overflow → `InsufficientBalance` |
| Ask escrow (base locked) | `amount` |
| Bid refund on cancel | `base_to_quote(remaining, tick, up)` |
| Ask refund on cancel | `remaining` |
| Maker of a bid, per fill of `f` base | credited `f` base |
| Maker of an ask, per fill of `f` base | credited `base_to_quote(f, tick, up)` quote |
| Taker selling base into a bid, fill `f` | receives `base_to_quote(f, tick, down)` quote, except a terminating partial fill in an exact-out trade, where the taker is owed exactly the remaining requested output (at most that amount) (§11.4) |
| Taker buying base from an ask, fill `f` | receives `f` base; pays `base_to_quote(f, tick, up)` quote, except a terminating partial fill in an exact-in trade, which consumes all remaining input (§11.4) |

Rounding residues (escrow above what makers are paid, the part of an exact-in input above the maker's credit on a terminating partial fill) stay in the DEX's TIP-20 balances and are credited to nobody.

Reference implementation: crates/precompiles/src/stablecoin_dex/orderbook.rs (`base_to_quote`, `quote_to_base`, `compute_book_key`, `tick_to_price`).

## 6. Storage layout

All DEX state is ordinary account storage of `STABLECOIN_DEX_ADDRESS`. Slot derivation and packing follow [00-framework.md](00-framework.md), restated here where the DEX depends on them:

- `map_slot(key, s) = keccak256(pad32(key) || uint256(s))` where `pad32` **left-pads the key's own big-endian bytes with zero bytes** to 32 bytes. For `address`, `uint128`, `bytes32` this equals Solidity. For `int16` keys (ticks and bitmap word indices) the 2-byte two's-complement value is zero-extended, **not** sign-extended: tick `-10` (`0xfff6`) has key `0x00…00fff6`. Solidity's `abi.encode` would give `0xff…fff6`; implementations MUST use the zero-extended form.
- Within a slot, a field at byte offset `o` with size `n` occupies bits `[8o, 8(o+n))` counted from the least-significant bit (Solidity packing). Signed integers are stored as `n`-byte two's complement.
- Writing one packed field is a read-modify-write of its slot (one SLOAD, one SSTORE). A field that is alone in its slot (`nextOrderId`, mapping values) is written with one SSTORE. Whole-struct reads load each slot the struct occupies (mappings inside a struct occupy a slot but are not read). Whole-struct writes store each non-mapping slot; before T4 each packed slot group is first loaded, from T4 it is composed from zero ([00-framework.md](00-framework.md)).

### 6.1 Top-level slots

| Slot | Field | Type |
|---|---|---|
| 0 | `books` | `mapping(bytes32 bookKey => Orderbook)` |
| 1 | `orders` | `mapping(uint128 orderId => order record)` (versioned, §6.5) |
| 2 | `balances` | `mapping(address user => mapping(address token => uint128))` |
| 3 | `nextOrderId` | `uint128` at offset 0 (alone in the slot) |
| 4 | `bookKeys` | `bytes32[]`: length at slot 4, element `i` at `uint256(keccak256(pad32(4))) + i` |
| 5 | `dex_storage_credits` | `mapping(address user => uint64)` (used from T7) |

- `balances[user][token]` is at `map_slot(token, map_slot(user, 2))`, a full-slot `uint128`.
- `dex_storage_credits[user]` is at `map_slot(user, 5)`, a full-slot `uint64`.
- The logical next order id is `max(sload(3), 1)`: a stored 0 reads as 1, so the first order id is 1.

### 6.2 Orderbook record

Base slot `B = map_slot(bookKey, 0)`:

| Slot | Content |
|---|---|
| `B+0` | `base` address, offset 0 |
| `B+1` | `quote` address, offset 0 |
| `B+2` | `bids`: `mapping(int16 tick => TickLevel)` (never read or written itself) |
| `B+3` | `asks`: `mapping(int16 tick => TickLevel)` |
| `B+4` | `bestBidTick` int16 @0, `bestAskTick` int16 @2, `bookId` uint32 @4 |
| `B+5` | `bidBitmap`: `mapping(int16 word => uint256)` |
| `B+6` | `askBitmap`: `mapping(int16 word => uint256)` |

A book is *initialized* iff `base != 0`. `read_orderbook(key)` loads `B+0`, `B+1`, `B+4` (three SLOADs). `write_orderbook(...)` stores those three slots. `field_write(bestBidTick | bestAskTick | bookId, v)` is a packed read-modify-write of `B+4`. `bookId` is 1-based: `0` means no index; otherwise the book's index in `bookKeys` is `bookId - 1`. Books created before T8 have `bookId = 0` until `setBookIndex` sets it (§14). A new book has `bestBidTick = NO_BID`, `bestAskTick = NO_ASK`.

### 6.3 TickLevel

`level(book, tick, side)` has base slot `L = map_slot(tick, B+2)` for bids, `map_slot(tick, B+3)` for asks:

| Slot | Content |
|---|---|
| `L+0` | `head` uint128 @0, `tail` uint128 @16 (order ids, 0 = none) |
| `L+1` | `totalLiquidity` uint128 @0 |

Access rules (`read_level`, `write_level`, `delete_level` in the pseudocode):

- **Before T12**: read = load `L+0` and `L+1`; write = store both; delete = zero both. `totalLiquidity` equals the sum of `remaining` of the orders in the queue and every operation maintains it with checked arithmetic (over/underflow → `Panic(0x11)`).
- **From T12**: read = load `L+0` only (`totalLiquidity` is taken as 0 in memory); write = store `L+0` only; delete = zero `L+0` only. `L+1` is never accessed again and keeps whatever value it had at T12 activation (stale). Implementations MUST NOT clear or update it.

### 6.4 Tick bitmaps

Each side has a bitmap of initialized ticks. For tick `t` (MUST satisfy `MIN_TICK <= t <= MAX_TICK`, else `InvalidTick`):

```python
word(t) = t >> 8          # arithmetic shift: floor(t / 256); range -8 .. 7
bit(t)  = t & 0xFF        # low 8 bits of the two's complement: 0 .. 255
slot    = map_slot(word(t), B+5 if bid else B+6)   # int16 key, zero-extended
```

A tick is initialized on a side iff its bit is set. `set_tick_bit` / `clear_tick_bit` check the tick bounds (`InvalidTick`), then do one SLOAD and one SSTORE of the word (even if the bit already had that value).

```python
def next_initialized_tick(book, tick, is_bid) -> (int16, bool):
    return next_bid_tick(book, tick) if is_bid else next_ask_tick(book, tick)

def next_ask_tick(book, tick):            # smallest initialized ask tick > tick
    if tick >= MAX_TICK: return (MAX_TICK, False)
    t = tick + 1
    max_w = MAX_TICK >> 8                 # 7
    while True:
        w = t >> 8
        if w > max_w: return (t, False)
        b = t & 0xFF
        word = sload(askBitmap[w])
        masked = word & (ALL_ONES << b)
        if masked != 0:
            found = (w << 8) | lowest_set_bit(masked)
            return (found, found <= MAX_TICK)
        if w + 1 > max_w: return ((w + 1) << 8, False)
        t = (w + 1) << 8

def next_bid_tick(book, tick):            # largest initialized bid tick < tick
    if tick <= MIN_TICK: return (MIN_TICK, False)
    t = tick - 1
    min_w = MIN_TICK >> 8                 # -8
    while True:
        w = t >> 8
        if w < min_w: return (t, False)
        b = t & 0xFF
        word = sload(bidBitmap[w])
        masked = word & (ALL_ONES >> (255 - b))
        if masked != 0:
            found = (w << 8) | highest_set_bit(masked)
            return (found, found >= MIN_TICK)
        if w - 1 < min_w: return (((w - 1) << 8) | 0xFF, False)
        t = ((w - 1) << 8) | 0xFF
```

Only the boolean is consumed by callers; the returned tick is meaningful only when it is `True`. The number of words loaded is part of the gas of every caller.

### 6.5 Order records

The order with id `id` has base slot `O = map_slot(id, 1)`. Three physical layouts exist.

**Legacy (version 0)**, written before T8 (6 slots):

| Slot | Content |
|---|---|
| `O+0` | `orderId` uint128 @0 |
| `O+1` | `maker` address @0 |
| `O+2` | `bookKey` bytes32 |
| `O+3` | `isBid` bool @0, `tick` int16 @1, `amount` uint128 @3 |
| `O+4` | `remaining` uint128 @0, `prev` uint128 @16 |
| `O+5` | `next` uint128 @0, `isFlip` bool @16, `flipTick` int16 @17 |

**V1 (version 1)**, written from T8 when the book has no index (4 slots):

| Slot | Content |
|---|---|
| `O+0` | `maker` @0 (20 bytes), `metadata` uint8 @20, `tick` int16 @21, `flipTick` int16 @23, zero @25..30, `version = 1` uint8 @31 |
| `O+1` | `amount` uint128 @0, `remaining` uint128 @16 |
| `O+2` | `prev` uint128 @0, `next` uint128 @16 |
| `O+3` | `bookKey` bytes32 |

**V2 (version 2)**, written from T8 when the book has an index (3 slots):

| Slot | Content |
|---|---|
| `O+0` | `maker` @0, `metadata` @20, `tick` @21, `flipTick` @23, `bookIndex` uint32 @25, zero @29..30, `version = 2` @31 |
| `O+1` | `amount` @0, `remaining` @16 |
| `O+2` | `prev` @0, `next` @16 |

`metadata` = `(isBid ? 1 : 0) | (isFlip ? 2 : 0)`; other bits are written as 0 and ignored on read. In V1/V2 the logical `orderId` is the mapping key. In V2 the logical `bookKey` is `bookKeys[bookIndex]` (or the key of the book the caller already knows, see below).

A slot containing only zero bits is "empty"; a record is *absent* iff its decoded `maker` is zero.

#### 6.5.1 Version detection

```python
def version(id):
    if not fork(T8): return 0                     # no access
    v = sload(O+0) >> 248                         # byte 31
    if v == 0: return 0
    if v == 1: return 1
    if v == 2: return 2
    raise Fatal                                   # unknown version (system error)
```

Byte 31 of a legacy `O+0` is always 0 because it holds only a `uint128`. From T8, **every** access to an order record begins with this SLOAD of `O+0` (repeated for each access; no caching), including field accesses and deletes.

#### 6.5.2 Record operations

```python
def order_read(id, known_book_key=None) -> Order:
    v = version(id)
    if v == 0: o = load legacy slots O+0..O+5                 # orderId from O+0
    if v == 1: o = load O+0..O+3 ; o.orderId = id
    if v == 2:
        o = load O+0..O+2 ; o.orderId = id
        o.bookKey = known_book_key if known_book_key is not None
                    else bookKeys_at(o.bookIndex)              # §14: length SLOAD, element SLOAD,
                                                               # PairDoesNotExist if out of range
    return o
```

From T8 the full-layout load re-reads `O+0` after the version SLOAD. `read_in_book(id, key)` means `order_read(id, key)`; it is used whenever the caller already knows the order's book. Plain `order_read(id)` (no known key) is used only by `cancel`, `cancelStaleOrder` and `getOrder`.

```python
def order_write(o: Order, book_id: uint32):       # book_id = the owning Orderbook.bookId
    if not fork(T8):
        store all six legacy slots from o          # struct store, see §6 packing note
        return
    old_v = version(o.orderId)                     # SLOAD O+0 (value s0)
    old_slots = {0: 6, 1: 4, 2: 3}[old_v]
    if book_id != 0:
        store V2 record (bookIndex = book_id - 1)  # 3 SSTOREs
        new_slots = 3
    else:
        store V1 record                            # 4 SSTOREs
        new_slots = 4
    if s0 != 0:                                    # existing record
        for k in range(new_slots, old_slots):
            sstore(O+k, 0)
```

A fresh id has `s0 == 0`, so nothing is cleared (it decodes as legacy, `old_slots = 6`, but no clearing runs). Upgrades clear: legacy→V2 clears `O+3..O+5`; legacy→V1 clears `O+4, O+5`; V1→V2 clears `O+3`. The record version written depends only on the owning book's `bookId` at the time of the write; the existing record's `bookIndex` is not consulted and no consistency check against `bookKeys` is performed.

> **Open conflict C-DEX-04**: TIP-1087 requires a V0/V1→V2 flip rewrite to assert `bookKeys[bookKeyIdx-1] == bookKey` (and a V2 rewrite to preserve the stored `bookIndex`); the implementation takes `bookIndex` from the owning orderbook's `bookId` with no assertion and no extra read. See [conflicts](../conflicts.md#c-dex-04).

> **Open conflict C-DEX-05**: TIP-1062 says a version-1 flip order that flips MUST remain version 1; the implementation rewrites it as version 2 once its book has an index (as TIP-1087 specifies). See [conflicts](../conflicts.md#c-dex-05).

```python
def order_delete(id):
    n = {0: 6, 1: 4, 2: 3}[version(id)]
    for k in range(n): sstore(O+k, 0)

def order_maker(id) -> address:
    v = version(id)                  # from T8: SLOAD O+0 (value s0)
    if v in (1, 2): return s0 & (2**160 - 1)      # reuse the loaded word
    return sload(O+1) & (2**160 - 1)              # legacy

# Field handles for remaining / prev / next. Location by version:
#   legacy: remaining = (O+4, @0), prev = (O+4, @16), next = (O+5, @0)
#   V1/V2:  remaining = (O+1, @16), prev = (O+2, @0), next = (O+2, @16)
def field_write(id, name, value):    # version(id), then packed read-modify-write of that slot
def field_clear(id, name):           # same as field_write(id, name, 0)
```

Neighbour pointer updates MUST use the neighbour's own version: mixed-version linked lists are normal.

Reference implementation: crates/precompiles/src/stablecoin_dex/order/storage.rs, crates/precompiles/src/stablecoin_dex/orderbook.rs (`Orderbook`, `TickLevel`, `TickLevelHandler`), crates/precompiles/tests/storage_tests/solidity/testdata/stablecoin_dex.sol.

## 7. TIP-20 and TIP-403 operations used

The DEX uses these operations, defined in [tip20.md](tip20.md) and [tip403.md](tip403.md):

| Name here | Meaning |
|---|---|
| `tip20(a)` | Fails with TIP-20 `InvalidToken()` if `a` lacks the 12-byte TIP-20 prefix `0x20C000000000000000000000`; no storage access. |
| `has_tip20_prefix(a)` | The prefix test alone (no error). |
| `quote_token(a)` | SLOAD of token `a`'s `quoteToken` field (zero for pathUSD and for undeployed addresses). |
| `is_paused(a)` / `check_not_paused(a)` | Read token `a`'s `paused` flag; `check_not_paused` fails with `ContractPaused()` if set. |
| `ensure_transfer_authorized(a, from, to)` | Token `a`'s TIP-403 transfer authorization of `from → to`; fails with `PolicyForbids()` if not authorized. |
| `transfer_policy_id(a)` | Read token `a`'s `transferPolicyId`. |
| `is_authorized_as(policy, user, role)` | TIP-403 registry check of `user` for `role` (sender or recipient). |
| `is_policy_lookup_error(e)` | Before T2: `e == Panic(0x11)`. From T2: `e` is TIP-403 `InvalidPolicyType()` or `PolicyNotFound()`. |
| `validate_usd_currency(a)` | `tip20(a)`, then read `currency`; fails with TIP-20 `InvalidCurrency()` unless it equals `"USD"`. |
| `factory_is_tip20(a)` | TIP20Factory's `isTIP20(a)`: prefix test, then the account of `a` has non-empty code. |
| `tip20_transfer(a, to, amt)` | Token `a`'s `transfer(to, amt)` executed with the DEX as `msg.sender`. |
| `tip20_pull(a, from, amt)` | Before T5: token `a`'s `transferFrom(from, DEX, amt)` with the DEX as spender (requires allowance). From T5: token `a`'s `systemTransferFrom(DEX, from, amt)` (TIP-1035 implicit approval, no allowance). |

```python
def is_authorized_for_token(token, user, role) -> bool:
    policy = transfer_policy_id(token)
    try:
        return is_authorized_as(policy, user, role)
    except e if is_policy_lookup_error(e):
        return False
```

## 8. Internal balances

### 8.1 Balance helpers

```python
def bal(user, token) -> uint128: return sload(balances[user][token])
def set_bal(user, token, v):     sstore(balances[user][token], v)
def inc_bal(user, token, x):     set_bal(user, token, checked_add(bal(user, token), x))   # Panic(0x11)
def sub_bal(user, token, x):     set_bal(user, token, checked_sub(bal(user, token), x))   # Panic(0x11)
```

Note that `inc_bal` and `sub_bal` re-read the balance even when the caller has just read it.

### 8.2 Debit from internal balance or wallet

```python
def debit(sender, token, amount, check_pause: bool):
    tip20(token)
    ensure_transfer_authorized(token, sender, DEX)
    b = bal(sender, token)
    if b >= amount:
        if check_pause and fork(T4):
            check_not_paused(token)
        sub_bal(sender, token, amount)
    else:
        tip20_pull(token, sender, amount - b)
        set_bal(sender, token, 0)
```

Order placement passes `check_pause = True`; swaps pass `False` (they check pause in route validation from T3).

### 8.3 Withdraw

```python
def withdraw(sender, token, amount):
    if bal(sender, token) < amount: raise InsufficientBalance
    sub_bal(sender, token, amount)
    tip20(token); tip20_transfer(token, sender, amount)
```

Reference implementation: crates/precompiles/src/stablecoin_dex/mod.rs (`decrement_balance_or_transfer_from`, `transfer_from`, `withdraw`).

## 9. Pairs and order placement

### 9.1 createPair

```python
def create_pair(base) -> bytes32:
    if not factory_is_tip20(base): raise InvalidBaseToken
    quote = quote_token(base)                 # after tip20(base)
    validate_usd_currency(base)
    validate_usd_currency(quote)              # pathUSD's quote is 0 → TIP-20 InvalidToken
    key = book_key(base, quote)
    ob = read_orderbook(key)
    if ob.base != 0: raise PairAlreadyExists
    book_id = (len(bookKeys) + 1) if fork(T8) else 0      # len = SLOAD slot 4
    write_orderbook(key, base, quote, NO_BID, NO_ASK, book_id)
    bookKeys.push(key)                         # element at keccak(pad32(4)) + len, length := len + 1
    emit PairCreated(key, base, quote)
    return key
```

`bookKeys` is append-only; its order is pair-creation order. Every initialized book has exactly one entry.

### 9.2 place and placeFlip

`place` and `placeFlip` (user entrypoint, `internal_only = False`) and the pre-T5 automatic flip (`internal_only = True`, §11.7) share these steps. Check order is normative.

```python
def place(sender, token, amount, is_bid, tick) -> uint128:
    tip20(token)
    quote = quote_token(token)
    key = book_key(token, quote)
    ob = read_orderbook(key)
    if ob.base == 0: create_pair(token)        # auto-create BEFORE validation; emits PairCreated
    if not (MIN_TICK <= tick <= MAX_TICK): raise TickOutOfBounds(tick)
    if tick % 10 != 0: raise InvalidTick       # truncated remainder; any non-multiple of 10
    if amount < MIN_ORDER_AMOUNT: raise BelowMinimumOrderSize(amount)
    escrow_token, escrow_amt, other = escrow(is_bid, token, quote, amount, tick)
    ensure_transfer_authorized(other, DEX, sender)       # tip20(other) first
    if fork(T4): check_not_paused(other)
    debit(sender, escrow_token, escrow_amt, check_pause=True)
    id = max(sload(3), 1)
    sstore(3, max(sload(3), 1) + 1)            # place always re-reads nextOrderId
    o = Order(id, sender, key, is_bid, tick, amount, remaining=amount, prev=0, next=0,
              is_flip=False, flip_tick=0)
    commit_order_to_book(o, charge_credits=True)
    emit OrderPlaced(id, sender, token, amount, is_bid, tick, False, 0)
    return id

def escrow(is_bid, base, quote, amount, tick):
    if is_bid:
        q = base_to_quote(amount, tick, up=True)
        if q is OVERFLOW: raise InsufficientBalance
        return (quote, q, base)
    return (base, amount, quote)
```

```python
def place_flip(sender, token, amount, is_bid, tick, flip_tick, internal_only) -> uint128:
    tip20(token)
    quote = quote_token(token)
    key = book_key(token, quote)
    cp = checkpoint()                          # real from T1C; no-op before (§15)
    ob = read_orderbook(key)
    if ob.base == 0: create_pair(token)
    if not (MIN_TICK <= tick <= MAX_TICK): raise TickOutOfBounds(tick)
    if tick % 10 != 0: raise InvalidTick
    if not (MIN_TICK <= flip_tick <= MAX_TICK): raise TickOutOfBounds(flip_tick)
    if flip_tick % 10 != 0: raise InvalidFlipTick
    if (flip_tick == tick and not fork(T5)) \
       or (is_bid and flip_tick < tick) or (not is_bid and flip_tick > tick):
        raise InvalidFlipTick
    if amount < MIN_ORDER_AMOUNT: raise BelowMinimumOrderSize(amount)
    escrow_token, escrow_amt, other = escrow(is_bid, token, quote, amount, tick)
    ensure_transfer_authorized(other, DEX, sender)
    if fork(T4): check_not_paused(other)
    if internal_only:
        ensure_transfer_authorized(escrow_token, sender, DEX)
        if fork(T4): check_not_paused(escrow_token)
        if bal(sender, escrow_token) < escrow_amt: raise InsufficientBalance
        sub_bal(sender, escrow_token, escrow_amt)
    else:
        debit(sender, escrow_token, escrow_amt, check_pause=True)
    id = max(sload(3), 1)
    if fork(T1C): sstore(3, id + 1)
    else:         sstore(3, max(sload(3), 1) + 1)
    o = Order(id, sender, key, is_bid, tick, amount, amount, 0, 0, is_flip=True, flip_tick=flip_tick)
    commit_order_to_book(o, charge_credits=True)
    emit OrderPlaced(id, sender, token, amount, is_bid, tick, True, flip_tick)
    cp.commit()
    return id
```

Flip-tick rule summary: before T5 a bid flip needs `flipTick > tick` and an ask flip `flipTick < tick`; from T5 (TIP-1030) `flipTick >= tick` for bids and `flipTick <= tick` for asks.

### 9.3 Committing an order to the book

```python
def commit_order_to_book(o, charge_credits):
    ob = read_orderbook(o.bookKey)
    lv = read_level(o.bookKey, o.tick, o.isBid)           # §6.3
    prev_tail = lv.tail
    if prev_tail == 0:
        lv.head = lv.tail = o.orderId
        set_tick_bit(o.bookKey, o.tick, o.isBid)
        if o.isBid:
            if o.tick > ob.bestBidTick: field_write(bestBidTick, o.tick)   # packed RMW of B+4
        elif o.tick < ob.bestAskTick: field_write(bestAskTick, o.tick)
    else:
        if fork(T8):
            field_write(prev_tail, "next", o.orderId)        # version(prev_tail) + RMW
        else:
            p = read_in_book(prev_tail, o.bookKey)             # full legacy load
            p.next = o.orderId
            order_write(p, ob.bookId)                          # full legacy store (6 slots)
        o.prev = prev_tail
        lv.tail = o.orderId
    if not fork(T12):
        lv.totalLiquidity = checked_add(lv.totalLiquidity, o.remaining)    # Panic(0x11)
    write_level(o.bookKey, o.tick, o.isBid, lv)
    if charge_credits and fork(T7):
        write_order_spending_credits(o, ob.bookId)             # §10.3
    elif not charge_credits and fork(T8):
        minted = track_minted(lambda: order_write(o, ob.bookId))
        credit_dex_storage_slots(o.maker, minted)              # §10.2, immediate
    else:
        order_write(o, ob.bookId)
```

The new order is appended at the tail of its tick queue (price-time priority: FIFO within a tick). Crossed and locked books are permitted: placement never matches against the opposite side. `charge_credits` is `True` for user placements (`place`, `placeFlip`, and the pre-T5 automatic flip placement, which runs before T7 so no credits exist) and `False` for T5+ in-place flips.

Reference implementation: crates/precompiles/src/stablecoin_dex/mod.rs (`create_pair`, `place`, `place_flip`, `commit_order_to_book`).

## 10. Maker storage credits (T7+)

### 10.1 Model (TIP-1064)

From T7 every clear of a non-zero DEX slot mints one TIP-1060 storage credit owned by the DEX address, and the DEX's mode on entry is Preserve (§4), so creations pay full storage gas unless a Direct budget is set ([account-keychain.md](account-keychain.md)). On top of this, the DEX keeps a per-maker counter `dex_storage_credits[maker]` (uint64, saturating):

- Credits minted by clearing slots of an **order record** are attributed to that order's maker.
- Credits minted by clearing any other DEX slot (tick levels, bitmap words, balances, orderbook fields, `nextOrderId`, `bookKeys`) are not attributed to anyone.
- When a maker places an order (`place`, `placeFlip`), the creation of that order record's slots may spend the maker's credits (§10.3). Writes to another maker's record (the predecessor's `next` pointer) never spend credits.
- One of a maker's credits is "stored" in the counter slot itself: creating the counter (0 → non-zero) spends one DEX credit, clearing it mints one back.

Before T7 none of this exists: `track_minted` and `with_budget` run their body and return 0, and `credit_dex_storage_slots` does nothing.

### 10.2 Primitives

`SC.balance(a)` is the persistent TIP-1060 credit balance of `a`: one SLOAD at `STORAGE_CREDITS_ADDRESS`, slot `uint256(bytes32(a))` ([account-keychain.md](account-keychain.md)). `SC.state(a)` is the transient word `{mode, budget, pending_refunds}` at the same address and slot.

```python
def track_minted(f) -> uint64:                   # owner is always DEX
    if not fork(T7): f(); return 0
    before = SC.balance(DEX)
    f()                                          # an error propagates immediately
    after = SC.balance(DEX)
    if after < before: raise Fatal
    return after - before

def with_budget(limit, f) -> int:                # owner is always DEX; limit > 0 at every DEX call site
    if not fork(T7): f(); return 0
    s = SC.state(DEX)                            # TLOAD
    SC.set_state(DEX, mode=Direct, budget=limit, pending_refunds=s.pending_refunds)   # TSTORE
    before = SC.balance(DEX)
    r = run f() capturing any error
    after = SC.balance(DEX)
    s = SC.state(DEX)                            # TLOAD
    SC.set_state(DEX, mode=Preserve, budget=0, pending_refunds=s.pending_refunds)     # TSTORE
    if r is an error: raise r
    return after - before                        # signed

def credit_dex_storage_slots(user, slots):
    if slots == 0 or not fork(T7): return
    cur = sload(dex_storage_credits[user])
    upd = min(cur + slots, 2**64 - 1)
    if cur != 0:
        sstore(dex_storage_credits[user], upd)
        return
    delta = with_budget(1, lambda: sstore(dex_storage_credits[user], upd))
    if delta != -1: raise Fatal
```

### 10.3 Spending on placement

```python
def write_order_spending_credits(o, book_id):
    c = sload(dex_storage_credits[o.maker])
    if c == 0:
        order_write(o, book_id); return
    sstore(dex_storage_credits[o.maker], 0)              # mints 1 DEX credit (counter cleared)
    delta = with_budget(c, lambda: order_write(o, book_id))
    spent = -delta if delta < 0 else 0
    credit_dex_storage_slots(o.maker, saturating_sub(c, spent))   # re-creates the counter if > 0
```

Net effect: each order-record slot the placement creates (0 → non-zero) consumes one of the maker's credits until they run out; the rest pay full creation gas. The tick level, bitmap and `nextOrderId` writes in `commit_order_to_book` happen before this and always run in Preserve mode.

### 10.4 Deferred credits in swaps

Swaps collect credits in a per-call map `deltas: address → uint64` (saturating add per address). A full fill adds the minted count of the filled order's deletion to its maker, and the minted count of clearing the next order's `prev` field to the next order's maker (§11.6). After the output transfer, the swap flushes `deltas` in **ascending address order** (byte-wise on the 20-byte address), calling `credit_dex_storage_slots(user, n)` for each entry. Credits from a T8+ in-place flip rewrite (§9.3) and from cancels (§12.1) are credited immediately, not deferred.

Reference implementation: crates/precompiles/src/stablecoin_dex/mod.rs (`credit_dex_storage_slots`, `write_order_spending_dex_storage_credits`, `delete_order`, `rewrite_order`, `unlink_neighbor_and_credit_maker`), crates/precompiles/src/storage_credits/mod.rs (`track_minted_credits`, `with_budget`, `StorageCreditDeltas`).

## 11. Swaps

### 11.1 Route finding

Each USD TIP-20 token has exactly one quote token, and quote links form a tree rooted at pathUSD (the factory guarantees acyclicity, [tip20.md](tip20.md)). A swap route is the unique tree path between `tokenIn` and `tokenOut`; every hop is one book.

```python
def find_trade_path(token_in, token_out) -> list[(bytes32 key, bool is_bid)]:
    if token_in == token_out: raise IdenticalTokens
    if not has_tip20_prefix(token_in) or not has_tip20_prefix(token_out): raise InvalidToken   # DEX error
    in_q  = quote_token(token_in)
    out_q = quote_token(token_out)
    if in_q == token_out or out_q == token_in:
        return validate_route([token_in, token_out])
    path_in  = path_to_root(token_in)
    path_out = path_to_root(token_out)
    lca = first element of path_in that is also in path_out, else raise PairDoesNotExist
    path = path_in[: index(lca) + 1] + reversed(path_out[: index_in_path_out(lca)])
    return validate_route(path)

def path_to_root(t) -> list[address]:
    path = [t]
    while t != PATH_USD:
        tip20(t)                     # an address without the prefix (e.g. a zero quote) → TIP-20 InvalidToken
        t = quote_token(t)
        path.append(t)
    return path
```

Examples: if `A` and `B` are both quoted in pathUSD, `A → B` routes `[A, pathUSD, B]`. If `C` is quoted in `B` and `B` in pathUSD, `pathUSD → C` routes `[pathUSD, B, C]`.

### 11.2 Route validation

```python
def validate_route(path) -> list[(bytes32, bool)]:
    route = []
    for (a, b) in consecutive pairs of path:
        tip20(a)
        if fork(T3): check_not_paused(a)           # input token of every hop; ContractPaused
        if quote_token(a) == b:
            base, quote = a, b
        else:
            tip20(b)
            if quote_token(b) == a: base, quote = b, a
            else: raise PairDoesNotExist
        key = book_key(base, quote)
        ob = read_orderbook(key)
        if ob.base == 0: raise PairDoesNotExist
        route.append((key, a == base))           # is_bid: the taker sells base into bids
    return route
```

`is_bid == True` for a hop means the taker gives base and receives quote, walking bids from the best (highest) tick down. `is_bid == False` means the taker gives quote and receives base, walking asks from the best (lowest) tick up. The final `tokenOut` is not pause-checked here (its TIP-20 transfer to the taker checks it). TIP-403 policy is enforced only on the taker's input pull and output transfer, not on intermediate tokens, which never leave the DEX.

> **Open conflict C-FORKS-03**: TIP-1036 (T2 meta) dates the StablecoinDEX internal-balance swap pause check at T2; the implementation applies the swap-route check from T3 (as TIP-1038 says) and the internal-balance placement checks from T4. See [conflicts](../conflicts.md#c-forks-03).

### 11.3 Swap entrypoints

```python
def swap_exact_amount_in(sender, token_in, token_out, amount_in, min_out) -> uint128:
    route = find_trade_path(token_in, token_out)
    debit(sender, token_in, amount_in, check_pause=False)
    deltas = {}
    amt = amount_in
    for (key, is_bid) in route:                    # forward
        amt = fill_orders(key, is_bid, amt, sender, exact_in=True, deltas)
    if amt < min_out: raise InsufficientOutput
    tip20(token_out); tip20_transfer(token_out, sender, amt)
    flush(deltas)                                  # §10.4
    return amt

def swap_exact_amount_out(sender, token_in, token_out, amount_out, max_in) -> uint128:
    route = find_trade_path(token_in, token_out)
    deltas = {}
    amt = amount_out
    for (key, is_bid) in reversed(route):          # last hop first
        amt = fill_orders(key, is_bid, amt, sender, exact_in=False, deltas)
    if amt > max_in: raise MaxInputExceeded
    debit(sender, token_in, amt, check_pause=False)
    tip20(token_out); tip20_transfer(token_out, sender, amount_out)
    flush(deltas)
    return amt
```

Intermediate amounts are not transferred: the output of one hop is the input of the next, inside the DEX's own TIP-20 balances. Exact-in debits the full `amountIn` before any fill; exact-out fills every hop (in reverse) before debiting the computed input. The taker (`sender`) is the `taker` in every `OrderFilled`.

### 11.4 Per-order step arithmetic

The swap and the T12+ quote use the same pure step functions. `amt` is the remaining input (exact-in) or remaining output (exact-out) of the current hop; `side` is the route's `is_bid`; `o` is the resting order.

```python
def taker_output(fill, tick, order_is_bid) -> uint128:
    return base_to_quote(fill, tick, up=False) if order_is_bid else fill

def step_exact_in(amt, o, side) -> (fill, accumulate, next_amt):
    r, t = o.remaining, o.tick
    if side:                                     # selling base
        fill, next_amt = min(amt, r), saturating_sub(amt, r)
    else:                                        # buying base with quote
        base_out = quote_to_base(amt, t, up=False)
        if base_out > r:
            next_amt = checked_sub(amt, base_to_quote(r, t, up=True))
        else:
            next_amt = 0
        fill = min(base_out, r)
    accumulate = taker_output(fill, t, o.isBid)  # taker output
    return (fill, accumulate, next_amt)

def step_exact_out(amt, o, side) -> (fill, accumulate, next_amt):
    r, t = o.remaining, o.tick
    if side:                                     # receiving quote
        base_needed = quote_to_base(amt, t, up=True)
        fill = min(base_needed, r); accumulate = fill; demand = base_needed
    else:                                        # receiving base
        fill = min(amt, r); accumulate = base_to_quote(fill, t, up=True); demand = amt
    if demand > r:
        next_amt = checked_sub(amt, taker_output(r, t, o.isBid))
    else:
        next_amt = 0
    return (fill, accumulate, next_amt)
```

Any `OVERFLOW` or failed `checked_sub` inside a step raises `Panic(0x11)` before the order is touched. The fill amount uses the route's `side` while the taker payout uses the order's own `isBid`; in a consistent book they are equal, and implementations MUST compute them this way.

### 11.5 Walking the book

```python
def fill_orders(key, is_bid, amt, taker, exact_in, deltas) -> uint128:
    lv = best_level(key, is_bid)
    o = read_in_book(lv.head, key)
    step = step_exact_in if exact_in else step_exact_out
    return walk(o, amt, is_bid, step, settle=lambda o, kind: settle(key, taker, lv, o, kind, deltas))

def best_level(key, is_bid) -> TickLevel:
    ob = read_orderbook(key)
    t = ob.bestBidTick if is_bid else ob.bestAskTick
    if (is_bid and t == NO_BID) or (not is_bid and t == NO_ASK): raise InsufficientLiquidity
    return read_level(key, t, is_bid)

def walk(o, amt, side, step, settle) -> uint128:
    total = 0
    while amt > 0:
        r = o.remaining
        (fill, acc, next_amt) = step(amt, o, side)        # Panic(0x11) on overflow
        if fill < r:
            settle(o, PARTIAL(fill))
            total = checked_add(total, acc)                # after settling
            break
        nxt = settle(o, FULL)
        total = checked_add(total, acc)
        if nxt is None:
            if next_amt > 0: raise InsufficientLiquidity
            break
        o = nxt
        amt = next_amt
    return total
```

`walk` returns the taker output (exact-in) or the taker input (exact-out) of the hop. A partial fill always ends the hop. A full fill with `next_amt == 0` ends it after settling. An amount of 0 settles nothing, but `best_level` still runs, so an empty side raises `InsufficientLiquidity` even for a zero amount. A partial fill of 0 base (possible in exact-in when the remaining quote buys less than one base unit) still runs the partial-fill settlement below with `fill = 0`.

### 11.6 Fill settlement

`settle(key, taker, lv, o, kind, deltas)` dispatches: `PARTIAL(f)` → `partial_fill(o, lv, f, taker)` and returns `None`; `FULL` → `full_fill(...)`, updating the walker's `lv` to the returned level and returning the next order (or `None`).

```python
def partial_fill(o, lv, f, taker):
    ob = read_orderbook(o.bookKey)
    field_write(o.orderId, "remaining", o.remaining - f)
    o.remaining -= f
    if o.isBid: inc_bal(o.maker, ob.base, f)
    else:       inc_bal(o.maker, ob.quote, base_to_quote(f, o.tick, up=True))   # Panic(0x11)
    if not fork(T12):
        lv.totalLiquidity = checked_sub(lv.totalLiquidity, f)
        write_level(o.bookKey, o.tick, o.isBid, lv)
    emit OrderFilled(o.orderId, o.maker, taker, f, True)

def full_fill(key, o, lv, taker, deltas) -> (TickLevel, Order) | None:
    ob = read_orderbook(key)
    f = o.remaining
    if o.isBid: inc_bal(o.maker, ob.base, f)
    else:       inc_bal(o.maker, ob.quote, base_to_quote(f, o.tick, up=True))
    emit OrderFilled(o.orderId, o.maker, taker, f, False)
    if o.isFlip:
        handle_flip(o, ob, deltas)                        # §11.7
    else:
        deltas[o.maker] += track_minted(lambda: order_delete(o.orderId))
    # o below is the in-memory copy read before the fill: its next/tick/isBid are unchanged
    if o.next == 0:
        delete_level(key, o.tick, o.isBid)                # §6.3
        clear_tick_bit(key, o.tick, o.isBid)
        (t, ok) = next_initialized_tick(key, o.tick, o.isBid)
        if o.isBid: field_write(bestBidTick, t if ok else NO_BID)
        else:       field_write(bestAskTick, t if ok else NO_ASK)
        if not ok: return None
        nlv = read_level(key, t, o.isBid)
        return (nlv, read_in_book(nlv.head, key))
    lv.head = o.next
    minted = track_minted(lambda: field_clear(o.next, "prev"))
    if not fork(T12):
        lv.totalLiquidity = checked_sub(lv.totalLiquidity, f)
    write_level(key, o.tick, o.isBid, lv)
    n = read_in_book(o.next, key)
    deltas[n.maker] += minted                              # saturating; only if minted > 0
    return (lv, n)
```

The best tick is always rewritten when a tick empties during a swap, even if unchanged. The filled order's record keeps its stale `next` only if it was rewritten by a flip; otherwise it is deleted. Maker transfer policy is not checked at fill time (makers that become unauthorized can be removed with `cancelStaleOrder`).

### 11.7 Flip orders on full fill

A fully filled flip order (`isFlip`) is handled after its `OrderFilled` event and before the tick-level advance above:

```python
def handle_flip(o, ob, deltas):
    try:
        if fork(T5):
            flip_in_place(o, ob.base, ob.quote)
        else:
            place_flip(o.maker, ob.base, o.amount, not o.isBid,
                       tick=o.flipTick, flip_tick=o.tick, internal_only=True)   # §9.2
        ok = True
    except e:
        if fork(T1A) and is_system_error(e): raise e      # reverts the whole swap
        if fork(T5): emit FlipFailed(o.orderId, o.maker, selector(e))
        ok = False
    if not (fork(T5) and ok):
        deltas[o.maker] += track_minted(lambda: order_delete(o.orderId))
```

- *System errors* are: out of gas, database errors, static-call violations, `Fatal`, `Panic` (including `Panic(0x11)`), and storage-delta underflow. All other errors (DEX, TIP-20, TIP-403 and other precompile ABI errors) are *business errors*. Before T1A every error is swallowed, system errors included.
- `selector(e)` is the 4-byte ABI selector of the error; `Panic` and storage-delta underflow map to `0x4e487b71`; errors with no ABI encoding map to `0x00000000`.
- Before T5 a successful flip creates a **new** order with a new id (`nextOrderId` advances) and emits `OrderPlaced(newId, maker, base, amount, !isBid, oldFlipTick, true, oldTick)`; the filled record is always deleted. Its escrow comes only from the maker's internal balance.

```python
def flip_in_place(o, base, quote):                       # from T5 (TIP-1056)
    cp = checkpoint()
    f = Order(o.orderId, o.maker, o.bookKey, isBid=not o.isBid, tick=o.flipTick,
              amount=o.amount, remaining=o.amount, prev=0, next=0, isFlip=True, flipTick=o.tick)
    if f.isBid:
        q = base_to_quote(f.amount, f.tick, up=True)
        if q is OVERFLOW: raise InsufficientBalance
        escrow_token, escrow_amt, other = quote, q, base
    else:
        escrow_token, escrow_amt, other = base, f.amount, quote
    if bal(f.maker, escrow_token) < escrow_amt: raise InsufficientBalance
    check_not_paused(escrow_token)
    ensure_transfer_authorized(escrow_token, f.maker, DEX)
    check_not_paused(other)
    ensure_transfer_authorized(other, DEX, f.maker)
    sub_bal(f.maker, escrow_token, escrow_amt)
    commit_order_to_book(f, charge_credits=False)          # same orderId, tail of the new level
    emit OrderFlipped(f.orderId, f.maker, base, f.amount, f.isBid, f.tick, f.flipTick)
    cp.commit()
```

A flip never pulls tokens from the maker's wallet; the flipped order gets fresh time priority at its destination level, which is on the opposite side and so is never the level being walked. When the flip fails (business error), the checkpoint reverts the flip's writes, `FlipFailed` is emitted, and the record is deleted with its credits deferred to the maker.

At T5–T7 the flip rewrite stores the full six-slot legacy record (§6.5.2). From T8 it goes through `order_write`, upgrading legacy/V1 records to the book's current layout and clearing the slots the old layout no longer uses; the credits minted by those clears go to the maker immediately (§9.3).

> **Open conflict C-DEX-03**: TIP-1056 requires a flip rewrite to write only the order-record slots whose contents change (under a "TIP-1055" layout that does not exist); at T5–T7 the implementation stores all six legacy slots, including unchanged ones. See [conflicts](../conflicts.md#c-dex-03).

Reference implementation: crates/precompiles/src/stablecoin_dex/mod.rs (`find_trade_path`, `validate_and_build_route`, `find_path_to_root`, `swap_exact_amount_in`, `swap_exact_amount_out`, `fill_orders_exact_in`, `fill_orders_exact_out`, `settle_fill`, `partial_fill_order`, `fill_order`, `flip_in_place`), crates/precompiles/src/stablecoin_dex/orderbook.rs (`walk_resting_orders`, `step_exact_in`, `step_exact_out`, `taker_output`), crates/precompiles/src/error.rs (`is_system_error`, `selector`).

## 12. Cancellation

### 12.1 cancel

```python
def cancel(sender, id):
    o = order_read(id)                       # no known book key (V2 resolves via bookKeys)
    if o.maker == 0: raise OrderDoesNotExist
    if o.maker != sender: raise Unauthorized
    if o.remaining == 0: raise OrderDoesNotExist
    cancel_active_order(o)

def cancel_active_order(o):
    key = o.bookKey
    lv = read_level(key, o.tick, o.isBid)
    if o.prev != 0:
        unlink_neighbor(o.prev, lambda: field_write(o.prev, "next", o.next))
    else:
        lv.head = o.next
    if o.next != 0:
        unlink_neighbor(o.next, lambda: field_write(o.next, "prev", o.prev))
    else:
        lv.tail = o.prev
    if fork(T12):
        level_changed = (o.prev == 0 or o.next == 0)
    else:
        lv.totalLiquidity = checked_sub(lv.totalLiquidity, o.remaining)    # Panic(0x11)
        level_changed = True
    if lv.head == 0:
        clear_tick_bit(key, o.tick, o.isBid)
        ob = read_orderbook(key)
        best = ob.bestBidTick if o.isBid else ob.bestAskTick
        if best == o.tick:
            (t, ok) = next_initialized_tick(key, o.tick, o.isBid)
            if o.isBid: field_write(bestBidTick, t if ok else NO_BID)
            else:       field_write(bestAskTick, t if ok else NO_ASK)
    if level_changed:
        write_level(key, o.tick, o.isBid, lv)     # an emptied level is written as zeros, not deleted
    ob = read_orderbook(key)
    if o.isBid:
        inc_bal(o.maker, ob.quote, base_to_quote(o.remaining, o.tick, up=True))   # Panic(0x11)
    else:
        inc_bal(o.maker, ob.base, o.remaining)
    minted = track_minted(lambda: order_delete(o.orderId))
    credit_dex_storage_slots(o.maker, minted)       # immediate
    emit OrderCancelled(o.orderId)

def unlink_neighbor(nid, update):
    minted = track_minted(update)
    if minted == 0: return
    credit_dex_storage_slots(order_maker(nid), minted)     # the neighbour's maker, immediate
```

The refund goes to the maker's internal balance; no tokens leave the DEX. A pointer update can empty a neighbour's slot (for example, the V1/V2 `prev|next` slot of an order that becomes the only one at its tick), which credits that neighbour's maker.

### 12.2 cancelStaleOrder

Anyone may cancel an order whose maker is no longer authorized:

```python
def cancel_stale_order(id):
    o = order_read(id)
    if o.maker == 0: raise OrderDoesNotExist
    if maker_authorized(o): raise OrderNotStale
    cancel_active_order(o)

def maker_authorized(o) -> bool:
    ob = read_orderbook(o.bookKey)
    escrow_token, payout_token = (ob.quote, ob.base) if o.isBid else (ob.base, ob.quote)
    tip20(escrow_token)
    if not is_authorized_for_token(escrow_token, o.maker, SENDER): return False
    if fork(T4):
        tip20(payout_token)
        return is_authorized_for_token(payout_token, o.maker, RECIPIENT)
    return True
```

Before T4 only the sender role on the escrow token is checked. `cancelStaleOrder` does not check `remaining`. A TIP-403 lookup failure (`is_policy_lookup_error`, §7) counts as unauthorized; any other error propagates.

Reference implementation: crates/precompiles/src/stablecoin_dex/mod.rs (`cancel`, `cancel_active_order`, `cancel_stale_order`, `is_maker_authorized`, `is_authorized_for_token`).

## 13. Quotes

`quoteSwapExactAmountIn` and `quoteSwapExactAmountOut` are views. Both call `find_trade_path` (§11.1, including the T3+ pause checks and the `PairDoesNotExist` checks) and then evaluate each hop without writing state: exact-in forward through the route, exact-out over the reversed route, feeding each hop's result into the next.

```python
def quote_hop_exact_in(key, amt, is_bid):  return per_order(key, amt, is_bid, step_exact_in)  if fork(T12) else per_tick_in(key, amt, is_bid)
def quote_hop_exact_out(key, amt, is_bid): return per_order(key, amt, is_bid, step_exact_out) if fork(T12) else per_tick_out(key, amt, is_bid)
```

### 13.1 From T12: per-order quotes (TIP-1088)

```python
def per_order(key, amt, is_bid, step) -> uint128:
    lv = best_level(key, is_bid)                         # InsufficientLiquidity if the side is empty
    o = read_in_book(lv.head, key)
    return walk(o, amt, is_bid, step, settle=lambda o, kind:
                None if kind is PARTIAL else next_order_after(key, o, is_bid))

def next_order_after(key, o, is_bid) -> Order | None:
    if o.next != 0: return read_in_book(o.next, key)
    (t, ok) = next_initialized_tick(key, o.tick, is_bid)
    if not ok: return None
    nlv = read_level(key, t, is_bid)
    return read_in_book(nlv.head, key)
```

Same traversal and arithmetic as the swap (§11.4, §11.5), so for the same state a T12+ quote equals the amount the swap's fills produce, and it raises `InsufficientLiquidity` for exactly the same inputs. A quote does not model flips, transfers or policy checks.

### 13.2 Before T12: per-tick quotes

These use the stored `totalLiquidity` aggregate and round once per tick. They can differ from the swap result, and that difference is historical behaviour that MUST be reproduced.

```python
def per_tick_in(key, amount_in, is_bid) -> uint128:
    rem, out = amount_in, 0
    ob = read_orderbook(key)
    t = ob.bestBidTick if is_bid else ob.bestAskTick
    if t == NO_BID or t == NO_ASK: raise InsufficientLiquidity     # either sentinel, either side
    while rem > 0:
        lv = read_level(key, t, is_bid)                            # both slots
        if lv.totalLiquidity == 0:
            (t2, ok) = next_initialized_tick(key, t, is_bid)
            if not ok: raise InsufficientLiquidity
            t = t2; continue
        if is_bid:
            fill = min(rem, lv.totalLiquidity)
            got = base_to_quote(fill, t, up=False)                 # Panic(0x11)
            used = fill
        else:
            fill = min(quote_to_base(rem, t, up=False), lv.totalLiquidity)
            used = base_to_quote(fill, t, up=True)
            got = fill
        rem = checked_sub(rem, used); out = checked_add(out, got)
        if fill == lv.totalLiquidity:
            (t2, ok) = next_initialized_tick(key, t, is_bid)
            if not ok and rem > 0: raise InsufficientLiquidity
            t = t2
        else:
            break
    return out

def per_tick_out(key, amount_out, is_bid) -> uint128:
    rem, cost = amount_out, 0
    ob = read_orderbook(key)
    t = ob.bestBidTick if is_bid else ob.bestAskTick
    if t == NO_BID or t == NO_ASK: raise InsufficientLiquidity
    while rem > 0:
        lv = read_level(key, t, is_bid)
        if lv.totalLiquidity == 0:
            (t2, ok) = next_initialized_tick(key, t, is_bid)
            if not ok: raise InsufficientLiquidity
            t = t2; continue
        if is_bid:
            fill = min(quote_to_base(rem, t, up=True), lv.totalLiquidity)
            paid = fill
            got = min(base_to_quote(fill, t, up=False), rem)
        else:
            fill = min(rem, lv.totalLiquidity)
            paid = base_to_quote(fill, t, up=True)
            got = fill
        rem = saturating_sub(rem, got); cost = checked_add(cost, paid)
        if fill == lv.totalLiquidity:
            (t2, ok) = next_initialized_tick(key, t, is_bid)
            if not ok and rem > 0: raise InsufficientLiquidity
            t = t2
        else:
            break
    return cost
```

All conversions raise `Panic(0x11)` on `OVERFLOW`. Note that after exhausting a level the next tick is searched even when nothing remains.

Reference implementation: crates/precompiles/src/stablecoin_dex/mod.rs (`quote_swap_exact_amount_in`, `quote_swap_exact_amount_out`, `quote_exact_in`, `quote_exact_out`, `quote_per_order`, `next_order_after`, `quote_exact_in_per_tick`, `quote_exact_out_per_tick`).

## 14. Views, price conversion and book indexes

```python
def balanceOf(user, token):  return bal(user, token)
def nextOrderId():           return max(sload(3), 1)
def pairKey(a, b):           return book_key(a, b)
def books(key):              ob = read_orderbook(key); return (ob.base, ob.quote, ob.bestBidTick, ob.bestAskTick)
                             # an uninitialized key returns all zeros (ticks 0, not the sentinels)
def storageCredits(user):    return sload(dex_storage_credits[user])                 # from T7

def getOrder(id):
    o = order_read(id)
    if o.maker != 0 and o.orderId < max(sload(3), 1): return o     # ABI Order (§3.1)
    raise OrderDoesNotExist

def getTickLevel(base, tick, is_bid):          # any int16 tick; no bounds check
    tip20(base)
    key = book_key(base, quote_token(base))
    lv = read_level(key, tick, is_bid)          # before T12: stored head, tail, totalLiquidity
    if fork(T12):
        total, id = 0, lv.head
        while id != 0:
            o = read_in_book(id, key)
            total = checked_add(total, o.remaining)       # Panic(0x11)
            id = o.next
        lv.totalLiquidity = total
    return (lv.head, lv.tail, lv.totalLiquidity)

def tickToPrice(tick):
    if fork(T2) and tick % 10 != 0: raise InvalidTick
    return PRICE_SCALE + tick                    # no bounds check: 2010 → 102010, -32768 → 67232

def priceToTick(price):
    if not (MIN_PRICE <= price <= MAX_PRICE):
        raise TickOutOfBounds(int16_wrap(price - PRICE_SCALE))   # low 16 bits, two's complement
    tick = price - PRICE_SCALE
    if fork(T2) and tick % 10 != 0: raise InvalidTick
    return tick
```

`MIN_TICK()`, `MAX_TICK()`, `TICK_SPACING()`, `PRICE_SCALE()`, `MIN_ORDER_AMOUNT()`, `MIN_PRICE()`, `MAX_PRICE()` return the constants of §1 with no storage access.

Book-index functions (from T8, TIP-1087):

```python
def bookKeys_at(i) -> bytes32:               # also used by order_read for V2 records
    if i >= sload(4): raise PairDoesNotExist
    return sload(uint256(keccak256(pad32(4))) + i)

def book_key_index(key) -> uint32 | None:
    ob = read_orderbook(key)
    if ob.base == 0: raise PairDoesNotExist
    return None if ob.bookId == 0 else ob.bookId - 1

def bookKeyForIndex(i):  return bookKeys_at(i)
def bookIndexForKey(key):
    idx = book_key_index(key)
    return (False, 0) if idx is None else (True, idx)

def setBookIndex(i):                          # mutate; callable by anyone
    key = bookKeys_at(i)
    cur = book_key_index(key)
    if cur is not None:
        if cur == i: return                   # idempotent, no write
        raise IndexAlreadySet
    field_write(books[key].bookId, i + 1)     # packed RMW of B+4
```

From T8, `createPair` sets `bookId = len(bookKeys) + 1` for new books (§9.1), so only books created before T8 need `setBookIndex`. Once `bookId != 0`, every later order write for that book (placements and flip rewrites) uses V2.

Reference implementation: crates/precompiles/src/stablecoin_dex/mod.rs (`get_order`, `get_price_level`, `tick_to_price`, `price_to_tick`, `book_key_index`, `book_key_for_index`, `set_book_index`), crates/precompiles/src/stablecoin_dex/dispatch.rs.

## 15. Atomicity and checkpoints

A DEX call that returns an error reverts all of its state changes (persistent, transient and logs), like any reverting call frame ([00-framework.md](00-framework.md)). That includes an auto-created pair and every fill of a swap that later fails (`InsufficientOutput`, `MaxInputExceeded`, `InsufficientLiquidity`, a failed transfer).

Inside a call, `placeFlip` and the flip paths open a checkpoint so that a swallowed flip failure leaves no partial writes:

- **From T1C** the checkpoint is real: a failure inside `place_flip` / `flip_in_place` reverts that function's writes and logs before the error is swallowed or propagated.
- **Before T1C** the checkpoint is a no-op. A swallowed failure of the pre-T5 automatic flip keeps whatever that `place_flip` call had written before failing. The business-error checks in `place_flip` all run before its first write, so only a failure after its balance debit (an arithmetic panic or other system error in `commit_order_to_book`, swallowed only before T1A) can leave partial state.

## 16. Event order per entrypoint

Events are listed in emission order. TIP-20 events come from the token calls at the point shown ([tip20.md](tip20.md)).

| Entrypoint | Events |
|---|---|
| `createPair` | `PairCreated` |
| `place` | [`PairCreated` if auto-created] → [TIP-20 events of the pull, if internal balance did not cover the escrow] → `OrderPlaced(isFlipOrder=false, flipTick=0)` |
| `placeFlip` | same as `place`, ending with `OrderPlaced(isFlipOrder=true, flipTick)` |
| `swapExactAmountIn` | [TIP-20 pull events] → per fill, hop by hop in route order: `OrderFilled` then, for a fully filled flip order, one of `OrderPlaced` (before T5, success), `OrderFlipped` (T5+, success), `FlipFailed` (T5+, business error), nothing (before T5, failure) → TIP-20 output transfer events |
| `swapExactAmountOut` | per fill, hops in **reverse** route order, as above → [TIP-20 pull events] → TIP-20 output transfer events |
| `cancel`, `cancelStaleOrder` | `OrderCancelled` |
| `withdraw` | TIP-20 transfer events |
| `setBookIndex` | none |

## 17. Gas

The DEX defines no fixed per-function gas. A call costs the framework's input cost plus the metered cost of exactly the storage reads/writes, transient reads/writes, account accesses and logs its algorithm performs, including those inside the TIP-20, TIP-403, factory and StorageCredits operations it invokes ([00-framework.md](00-framework.md); TIP-1060 creation pricing and credit spending in [account-keychain.md](account-keychain.md)). The pseudocode in this chapter is normative for that access sequence: an implementation MUST perform the same reads and writes, including the redundant ones, such as:

- `inc_bal` / `sub_bal` re-reading a balance just read, `place` reading `nextOrderId` twice (and `placeFlip` before T1C), Orderbook re-reads in every fill and cancel;
- from T8, the version SLOAD before every order-record access, and the re-load of slot `O+0` in full reads;
- before T8, the full six-slot rewrite of the predecessor when appending, and from T8 the single `next`-field write;
- before T12, every `totalLiquidity` write; from T12, none, and only slot `L+0` of a tick level;
- the T7+ StorageCredits balance SLOADs around every tracked delete/rewrite, and the TLOAD/TSTORE pairs of the mode/budget switches;
- bitmap words loaded by `next_initialized_tick`, including the search after the last needed level.

On a failing call, the gas consumed is that of the accesses performed before the failing check, so check order matters too.
