---
tempo-primitives: minor
---

Added `ConfigurableAccountSignature::approving_owners`, which verifies the owner quorum like `verify_approvals` and returns the recovered approving owners. The verification cache now keeps those owners with the verified digest, so they are never recovered twice.
