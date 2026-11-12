---
tempo-contracts: minor
---

Added cardholder spend windows and merchant mandates to TIP-1169: calendar-month limits on an issuer's card holds (`setSpendWindow`, `spendWindow`), per-merchant limits and revocation (`setMerchantMandate`, `merchantMandate`), `holdCardForMerchant` on `IReservations`, and the `MerchantRevoked` and `WindowLimitExceeded` errors.
