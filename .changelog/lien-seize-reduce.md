---
tempo-contracts: minor
tempo-precompiles: minor
tempo-transaction-pool: patch
---

TIP-1153 adds `seizeLien`, with which a lien's authority pays up to the lien from the owner to an account it names, and `reduceLien`, which lowers a lien in one call; an owner can also grow its own pledge by calling `pledge` again with a larger amount.
