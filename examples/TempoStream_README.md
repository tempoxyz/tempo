# TempoStream: Real-Time Payment Protocol

## The Problem
Traditional payments are discrete. You pay a salary once a month. You pay a subscription once a year. This creates cashflow gaps and requires manual transactions for every single payment event.

## The Solution
**TempoStream** leverages Tempo's high-throughput architecture to enable **Continuous Money Streaming**.

Instead of sending $3,000 at the end of the month, a business opens a stream. The employee earns ~$0.0011 every second. They can withdraw their vested earnings instantly, at any time.

## Architecture
- **Deposit:** Sender locks funds in the contract.
- **Flow Rate:** Sender defines the `wei/second` rate.
- **Settlement:** The contract calculates `(block.timestamp - startTime) * rate` to determine the vest.
- **Pull Payment:** The recipient calls `withdraw()` to claim only what has vested so far.

## Why Tempo?
This protocol relies on cheap transactions and predictable gas, making it uniquely suited for the Tempo "Payment Lanes" architecture.
