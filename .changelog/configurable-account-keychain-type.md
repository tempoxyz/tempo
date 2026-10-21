---
tempo-contracts: minor
tempo-precompiles: minor
---

Added the `ConfigurableAccount` account keychain signature type (value 3). From T14, the T3+ `authorizeKey` overloads and `authorizeAdminKey` accept it for a code-free delegate other than the granting account. Earlier forks keep reverting exactly as for an unknown signature type.
