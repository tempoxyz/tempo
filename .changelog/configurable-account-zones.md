---
zone-precompiles: minor
zone-spf: patch
zone-evm: patch
tempo-evm: minor
---

Zones expose the configurable account precompile from T14: `deriveAccount` and `getConfigCommitment` work, while `updateConfig` and `upgradeAccount` revert with `UnauthorizedConfigurableAccountCaller`. The zone genesis generator installs the configurable account marker when T14 is active at the anchor, and witness account leaves with a malformed configuration commitment fail to decode. Zones that activate T14 after genesis install the marker in their first T14 block, using the new `tempo_evm::precompile_deployment_state` shared with Tempo block execution.
