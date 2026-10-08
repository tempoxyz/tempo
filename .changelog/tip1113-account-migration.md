---
tempo-chainspec: minor
tempo-contracts: minor
---

Add TIP-1113 in-place account migration with a default-off `accountMigrationTime` genesis gate. `upgradeAccount` installs configurable ownership at the existing address and retires primitive-root authority while preserving access-key grants.
