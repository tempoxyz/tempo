---
"tempo": patch
---

Fixed vacuous C5 invariant check for CREATE address verification. The verifier previously iterated sequential indices 0..N which did not match the actual protocol nonces used during CREATE operations, causing the check to silently skip all entries. Added `ghost_createNonces` array to track actual nonces used and updated both verifier functions to iterate over recorded nonces instead of sequential indices.
