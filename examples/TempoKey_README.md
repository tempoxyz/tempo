# TempoKey: The Smart Lease Protocol

## The Problem
Real Estate tokenization (Propy, etc.) handles the *deed*, but not the *door*.
If a tenant stops paying, the landlord still has to go through a manual, legal eviction process. There is a disconnect between the **Payment** and the **Utility**.

## The Solution
**TempoKey** bridges Finance and IoT. It is a programmable lease.
1. **The Tenant** streams money into the contract (Deposit).
2. **The Contract** calculates `Time Remaining = Deposit / Rate`.
3. **The Door** (IoT Lock) queries the contract: `hasAccess(Tenant)?`
   - If **Yes**: Door opens.
   - If **No**: Door remains locked.

## Use Cases
- **Airbnb/Hotels:** Pay-per-second stays. Checkout happens automatically when you stop paying.
- **Co-working Spaces:** Unlocking meeting rooms only while the stream is active.
- **EV Charging:** The charger only dispenses electricity while funds are detected.
