# TempoVault: The "Dead Man's Switch"

## The Problem
"Not your keys, not your coins." But what happens if you lose your keys, or get incapacitated? Currently, billions in crypto are lost forever because owners cannot pass them on.

## The Solution
**TempoVault** is a "Heartbeat Protocol."
1. **Lock:** User deposits funds and sets a `beneficiary` (e.g., a backup wallet or family member).
2. **Ping:** User must call `ping()` periodically (e.g., once a month) to prove they are active.
3. **Inherit:** If the user stops pinging (Block Time > Threshold), the `beneficiary` can claim the funds trustlessly.

## Use Cases
- **Trustless Inheritance:** Estate planning without lawyers.
- **Key Recovery:** Set your *own* secondary hardware wallet as the beneficiary. If you lose your main key, just wait 30 days and claim from the backup.
