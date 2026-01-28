---
id: TIP-ZZZZ
title: Dynamic State Creation Pricing
description: State creation costs adjust dynamically based on exponentially decaying usage average, keeping prices low at low usage while providing economic back-pressure at high usage.
authors: Dankrad Feist @dankrad
status: Draft
related: TIP-1000, TIP-1010
protocolVersion: TBD
---

# TIP-ZZZZ: Dynamic State Creation Pricing

## Abstract

State creation is priced dynamically using an exponentially decaying average (1-hour half-life) tracking recent usage. At 0% of target usage, price is 25,000 gas. At 100% of target, price is 250,000 gas (matching TIP-1000). Pricing follows `25,000 × 10^(usage_ratio)` curve.

Target: 33 billion state elements per year (1 element = 1 storage slot, 1 account, or 100 bytes contract code).

## Motivation

TIP-1000's fixed 250,000 gas pricing overcharges during normal operation while providing no market signal about capacity. Dynamic pricing keeps costs low when capacity available while automatically raising prices as usage approaches sustainability limits.

---

# Specification

## Constants

```
TARGET_RATE = 33_000_000_000 / 31_557_600 = 1045.7 elements/second
HALF_LIFE = 3600 seconds
PRECISION = 10^18 (fixed-point precision)
BASE_PRICE = 25_000 gas
TARGET_PRICE = 250_000 gas
```

## State Variables

```
uint256 current_rate_fp;     // elements/second × PRECISION
uint256 last_update_time;    // timestamp of last update
```

## State Element Counting

Per transaction:
- SSTORE zero → non-zero: 1 element
- Account creation: 1 element
- Contract code: 1 element per 100 bytes (rounded up)
- Contract metadata: 1 element

## Rate Update (Per Block)

```
time_delta = block.timestamp - last_update_time
elements = count_state_elements(previous_block)

// Exponential decay: decay_factor = 2^(-time_delta / HALF_LIFE)
// Using integer math: decay_factor_fp = 2^((-time_delta × PRECISION) / HALF_LIFE)
decay_factor_fp = exp2((-time_delta × PRECISION) / HALF_LIFE)

// Apply decay and add new rate
decayed_rate_fp = (current_rate_fp × decay_factor_fp) / PRECISION
new_rate_fp = (elements × PRECISION) / time_delta

current_rate_fp = decayed_rate_fp + new_rate_fp
last_update_time = block.timestamp
```

## Price Calculation

```
ratio_fp = (current_rate_fp × PRECISION) / (TARGET_RATE × PRECISION)

// price = 25_000 × 10^ratio = 25_000 × e^(ratio × ln(10))
ln_10_fp = 2_302585092994045684  // ln(10) × PRECISION
exponent_fp = (ratio_fp × ln_10_fp) / PRECISION
price = (BASE_PRICE × exp(exponent_fp)) / PRECISION
```

All arithmetic uses fixed-point with PRECISION = 10^18.

## Pricing Table

| Usage | Ratio | Price | vs TIP-1000 |
|-------|-------|-------|-------------|
| 0% | 0 | 25,000 | 10% |
| 25% | 0.25 | 44,543 | 18% |
| 50% | 0.5 | 79,057 | 32% |
| 100% | 1.0 | 250,000 | 100% |
| 200% | 2.0 | 2,500,000 | 1000% |

## Gas Costs

All state creation operations use the dynamic price:
- New storage slot: `price` gas
- Account creation: `price` gas
- Contract metadata: `price` gas
- Contract code: `price / 100` gas per byte

---

# Examples

## 24KB Contract Deployment

| Usage | Price/Element | Total Gas |
|-------|---------------|-----------|
| 0% idle | 25,000 | ~6.2M |
| 25% normal | 44,543 | ~11M |
| 100% target | 250,000 | ~62M |
| 200% spam | 2,500,000 | ~619M |

## TIP-20 Transfer to New Account

| Usage | Price | Total Gas |
|-------|-------|-----------|
| 0% | 25,000 | ~46k |
| 25% | 44,543 | ~66k |
| 100% | 250,000 | ~271k |

---

# Key Properties

1. **Price bounds**: Minimum 25,000 gas (at 0%), exponentially increasing
2. **Target convergence**: At target rate, price equals 250,000 gas
3. **Fast response**: 1-hour half-life responds within hours
4. **Attack resistance**: Sustained spam faces 10x+ cost increase (200% → 2.5M gas)
5. **Sustainable growth**: Caps long-term state growth at 33B elements/year

---

# Trade-offs

**vs TIP-1000**: More efficient (82-90% cheaper at normal usage) but adds complexity (EWMA tracking, exponential math)

**vs TIP-YYYY**: Different approach (pricing vs limits); could be combined

**Implementation cost**: ~5-10k gas per block for EWMA update + price calculation per state operation
