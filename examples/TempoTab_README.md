# TempoTab: The "Invisible Payment" Protocol

## The Problem
Crypto payments currently have too much friction. To buy a coffee, a user must:
1. Unlock phone
2. Scan QR
3. Approve transaction
4. Wait for block confirmation

This "Push" model works for large transfers but fails for daily retail. Uber and Amazon won because payments are **invisible** (Auth/Capture).

## The Solution
**TempoTab** brings the "Credit Card Experience" to Tempo.

1. **Open Tab:** User authorizes a merchant (e.g., Starbucks) to spend up to a **Strict Limit** (e.g., $20/day).
2. **Invisible Pay:** When buying coffee, the merchant simply calls `chargeTab()`. The user does nothing.
3. **Safety Firewall:** The contract enforces the limit. If a merchant tries to pull more than the authorized amount, the transaction reverts instantly.

## Use Cases
- **Subscription Services:** Netflix-style billing without recurring approval.
- **Metered Billing:** Pay-per-minute for WiFi or EV charging.
- **Zero-Click Retail:** "Just Walk Out" grocery experience.

## Security
This is **NOT** an unlimited allowance.
- **Hard Limits:** Users define the max risk (e.g., 50 USDC).
- **Auto-Reset:** Limits reset securely based on block timestamp (Daily/Weekly).
- **Non-Custodial:** Users can `closeTab()` and recover funds at any time.
