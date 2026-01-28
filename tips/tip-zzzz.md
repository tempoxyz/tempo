---
id: TIP-ZZZZ
title: Dynamic State Creation Pricing
description: State creation costs adjust dynamically based on recent usage via exponentially decaying average, keeping prices low when usage is below target and raising them when approaching capacity.
authors: Dankrad Feist @dankrad
status: Draft
related: TIP-1000, TIP-1010
protocolVersion: TBD
---

# TIP-ZZZZ: Dynamic State Creation Pricing

## Abstract

State creation operations are priced dynamically based on recent usage measured via an exponentially decaying average with a 1-hour half-life. When no state is being created, prices are at pre-TIP-1000 levels (25,000 gas). As usage approaches the target rate of 10 billion state elements per year, prices increase exponentially to TIP-1000 levels (250,000 gas). This provides economic back-pressure against state growth while keeping costs low for normal usage.

## Motivation

TIP-1000 set fixed high prices for state creation (250,000 gas per element) to protect against state growth attacks. However:

1. **Overpricing during low usage**: When state growth is minimal, high prices unnecessarily burden users
2. **No market signal**: Fixed pricing doesn't signal network capacity or provide economic feedback
3. **Inefficient resource allocation**: Users pay high costs even when the network has plenty of state capacity

Dynamic pricing solves this by:
- Keeping costs low when state capacity is available
- Automatically raising prices as usage approaches sustainability limits
- Providing market signals about network state capacity
- Efficiently allocating the scarce resource (persistent state)

### Design Goals

1. **Sustainability**: Cap long-term state growth at a sustainable rate (10B elements/year)
2. **Responsiveness**: React to usage patterns within hours via exponential decay
3. **Economic efficiency**: Price low when capacity available, high when scarce
4. **Simplicity**: Single pricing formula applies to all state creation operations

---

# Specification

## Target State Growth

The protocol targets a maximum sustainable state growth rate:

```
TARGET_ELEMENTS_PER_YEAR = 10,000,000,000  (10 billion elements)
TARGET_RATE = 10B / 31,557,600 seconds ≈ 316.88 elements/second
```

**Contract code conversion**: 1 byte of contract code = 1/100th of a state element
- 100 bytes of contract code = 1 state element equivalent
- At target rate: 31,688 bytes/second of contract code

## Exponentially Decaying Average

The protocol tracks recent state creation using an exponentially weighted moving average (EWMA):

```
HALF_LIFE = 3600 seconds (1 hour)
DECAY_FACTOR = 0.5^(time_delta / HALF_LIFE)

// Updated per block
current_rate = previous_rate × DECAY_FACTOR + new_elements_this_block / block_time
```

Where:
- `previous_rate`: State creation rate from previous block (elements/second)
- `DECAY_FACTOR`: Decay applied based on time since last block
- `new_elements_this_block`: State elements created in current block
- `block_time`: Time elapsed since previous block

**State element counting:**
- New storage slot (SSTORE zero → non-zero): 1 element
- Account creation: 1 element
- Contract code: 1 element per 100 bytes
- Contract metadata (keccak + nonce): 1 element

## Dynamic Pricing Formula

State creation gas costs are calculated based on the current rate:

```
ratio = current_rate / TARGET_RATE

base_price = 25,000     (pre-TIP-1000 price)
target_price = 250,000  (TIP-1000 price)

price = base_price × 10^ratio
      = 25,000 × 10^(current_rate / TARGET_RATE)
```

**Pricing examples:**

| Usage vs Target | Ratio | Price per Element | vs TIP-1000 |
|----------------|-------|-------------------|-------------|
| 0% (idle) | 0.0 | 25,000 | 10% |
| 10% | 0.1 | 31,498 | 13% |
| 25% | 0.25 | 44,543 | 18% |
| 50% | 0.5 | 79,057 | 32% |
| 75% | 0.75 | 140,538 | 56% |
| 100% (target) | 1.0 | 250,000 | 100% |
| 150% | 1.5 | 790,569 | 316% |
| 200% | 2.0 | 2,500,000 | 1000% |

## Gas Cost Calculation

All state creation operations use the dynamic price:

```
// Per-element costs
new_storage_slot_gas = price
account_creation_gas = price
contract_metadata_gas = price

// Contract code (per 100 bytes = 1 element)
contract_code_gas_per_100_bytes = price
contract_code_gas_per_byte = price / 100
```

**Example for 24KB contract at different usage levels:**

| Usage | Price/Element | Contract Code (24KB) | Account | Metadata | Total |
|-------|---------------|---------------------|---------|----------|-------|
| 0% (idle) | 25,000 | 6,144,000 | 25,000 | 25,000 | 6,194,000 |
| 50% | 79,057 | 19,438,605 | 79,057 | 79,057 | 19,596,719 |
| 100% (target) | 250,000 | 61,440,000 | 250,000 | 250,000 | 61,940,000 |
| 150% | 790,569 | 194,380,134 | 790,569 | 790,569 | 195,961,272 |

**Note**: At target usage (100%), costs match TIP-1000. Below target, costs are lower. Above target, costs increase exponentially to discourage overuse.

## Protocol State

The protocol maintains the following state variables:

```solidity
// Stored in consensus state
uint256 current_rate;          // elements per second (fixed-point)
uint256 last_update_timestamp; // timestamp of last update
uint256 last_update_block;     // block number of last update
```

These values are updated at the beginning of each block:

```python
def update_state_creation_rate(block):
    time_delta = block.timestamp - last_update_timestamp
    decay_factor = 0.5 ** (time_delta / HALF_LIFE)

    # Decay previous rate
    decayed_rate = current_rate * decay_factor

    # Add new elements from previous block
    elements_in_block = count_state_elements(previous_block)
    new_rate = elements_in_block / time_delta

    # Update EWMA
    current_rate = decayed_rate + new_rate
    last_update_timestamp = block.timestamp
    last_update_block = block.number

    return calculate_price(current_rate)
```

## Examples

### Idle Network (0% usage)
- `current_rate = 0`
- `price = 25,000 × 10^0 = 25,000 gas`
- TIP-20 transfer to new account: ~46,000 gas total
- 24KB contract: ~6.2M gas

### Normal Usage (25% of target)
- `current_rate = 79.22 elements/second`
- `price = 25,000 × 10^0.25 = 44,543 gas`
- TIP-20 transfer to new account: ~65,543 gas total
- 24KB contract: ~11M gas

### Target Usage (100%)
- `current_rate = 316.88 elements/second`
- `price = 25,000 × 10^1 = 250,000 gas`
- TIP-20 transfer to new account: ~271,000 gas total
- 24KB contract: ~62M gas (same as TIP-1000)

### Overuse (200% of target)
- `current_rate = 633.76 elements/second`
- `price = 25,000 × 10^2 = 2,500,000 gas`
- TIP-20 transfer to new account: ~2,521,000 gas total
- 24KB contract: ~619M gas (prevents spam)

---

# Invariants

1. **Price Bounds**: State creation price MUST be at least 25,000 gas (at 0% usage) and increases exponentially with usage
2. **Target Price**: At exactly target usage rate, price MUST equal 250,000 gas per element
3. **Rate Tracking**: `current_rate` MUST be updated every block using exponential decay with 1-hour half-life
4. **Element Counting**: State elements MUST be counted consistently:
   - 1 element per new storage slot
   - 1 element per account creation
   - 1 element per 100 bytes of contract code
   - 1 element for contract metadata
5. **Monotonic Within Block**: Price MUST remain constant within a block (updated at block start)
6. **Decay Function**: Rate MUST decay by factor of 0.5 every 3600 seconds when no new state is created

---

# Key Benefits

1. **Low costs during low usage**: Prices drop to 25,000 gas when network is idle (10x cheaper than TIP-1000)
2. **Automatic back-pressure**: Prices rise exponentially as usage approaches target, discouraging overuse
3. **Market efficiency**: Scarce resource (persistent state) priced according to demand
4. **Fast response**: 1-hour half-life means prices adjust within hours of usage changes
5. **Attack resistance**: Sustained spam attacks face exponentially increasing costs (200% usage = 10x price)
6. **Sustainable long-term**: Targets 10B elements/year, manageable state growth
7. **No breaking changes**: Same transaction format, just dynamic pricing

## Economic Impact

At typical usage levels (25-50% of target):

| Operation | TIP-1000 Cost | TIP-ZZZZ Cost (25% usage) | Savings |
|-----------|---------------|---------------------------|---------|
| TIP-20 transfer (new) | 271,000 gas | 65,543 gas | 76% |
| Account creation | 250,000 gas | 44,543 gas | 82% |
| 1KB contract | 3.25M gas | 577k gas | 82% |
| 24KB contract | 62M gas | 11M gas | 82% |

During idle periods (0% usage), costs are 90% lower than TIP-1000.

During sustained heavy usage (100%+ of target), costs match or exceed TIP-1000, providing economic protection.

---

# Implementation Notes

## Fixed-Point Arithmetic

The `current_rate` should use fixed-point arithmetic for precision:

```solidity
uint256 constant PRECISION = 1e18;
uint256 current_rate;  // elements per second × PRECISION
```

## Exponential Calculation

The price formula `25,000 × 10^ratio` can be computed using logarithms:

```solidity
price = 25_000 * exp10(ratio)
      = 25_000 * exp(ratio * ln(10))
      = 25_000 * exp(ratio * 2.302585)
```

Use fixed-point exponential libraries (e.g., PRBMath) for precision.

## Decay Calculation

The decay factor `0.5^(time_delta / HALF_LIFE)` can be precomputed for common time deltas or computed using:

```solidity
decay_factor = exp(-(time_delta / HALF_LIFE) * ln(2))
             = exp(-time_delta * 0.000192367)  // for HALF_LIFE=3600
```

## Gas Overhead

Updating the EWMA and calculating dynamic price adds minimal overhead:
- One exponential calculation per block (decay)
- One exponential calculation per state operation (price)
- ~5,000-10,000 gas overhead per block

---

# Security Considerations

## Price Manipulation

**Risk**: Could an attacker manipulate the price by creating/not creating state?

**Mitigation**:
- Exponential pricing means sustained attacks become prohibitively expensive
- At 200% usage, price is 10x higher (2.5M gas per element)
- Attack to raise prices costs attacker same increased prices
- 1-hour half-life limits impact of short-term manipulation

## State Bloat

**Risk**: Could someone spam state before prices rise?

**Mitigation**:
- Exponential curve rises quickly (50% usage → 3.2x higher, 100% → 10x higher)
- Creating enough state to matter requires paying exponentially increasing costs
- Target of 10B elements/year provides sustainable long-term growth

## Calculation Precision

**Risk**: Could rounding errors accumulate in EWMA?

**Mitigation**:
- Use high-precision fixed-point arithmetic (1e18)
- Decay and price calculations use well-tested math libraries
- Rounding always rounds up for safety (never underprices)

## Block Timing Attacks

**Risk**: Could manipulating block times affect pricing?

**Mitigation**:
- Block timestamps are consensus-validated
- Large timestamp manipulation would be obvious and rejected
- Decay based on actual time elapsed, not block numbers

---

# Comparison with Alternatives

## vs TIP-1000 (Fixed High Pricing)
- **TIP-ZZZZ**: Dynamic pricing, low cost at low usage, high cost at high usage
- **TIP-1000**: Fixed high cost always
- **Trade-off**: TIP-ZZZZ is more efficient but adds complexity

## vs TIP-YYYY (Exempt from Limits)
- **TIP-ZZZZ**: Uses dynamic pricing to manage state growth
- **TIP-YYYY**: Uses gas limit exemption to enable high pricing without block limit impact
- **Compatible**: Could combine both approaches (dynamic pricing + exemption from limits)

## vs Storage Rent
- **TIP-ZZZZ**: One-time dynamic cost based on current usage
- **Storage Rent**: Recurring cost over time
- **Trade-off**: TIP-ZZZZ simpler UX, rent provides ongoing revenue

---

# Future Extensions

## Combining with TIP-YYYY

This TIP could be combined with TIP-YYYY's approach:
- Dynamic pricing for cost calculation
- Gas limit exemption for protocol constraints
- Best of both: responsive pricing + flexible limits

## Multiple Resource Dimensions

Could extend to track multiple resources independently:
- Storage elements (this TIP)
- Compute time (separate EWMA)
- Bandwidth (separate EWMA)

## Adjustable Target

The target rate (10B/year) could be made adjustable via governance as network capacity grows.
